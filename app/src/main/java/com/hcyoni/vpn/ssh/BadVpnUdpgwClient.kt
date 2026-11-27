package com.hcyoni.vpn.ssh

import com.hcyoni.vpn.model.LogLevel
import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet6Address
import java.net.InetAddress
import java.net.SocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class BadVpnUdpgwClient(
    private val sessionProvider: () -> Session?,
    private val udpgwPort: Int,
    private val onBytesTx: (Long) -> Unit,
    private val onBytesRx: (Long) -> Unit,
    private val onLog: (String, LogLevel) -> Unit
) {
    private data class FlowKey(
        val clientAddr: SocketAddress,
        val dstIpKey: String,
        val dstPort: Int
    )

    private data class FlowEntry(
        val conid: Int,
        val atyp: Int,
        val udpSocket: DatagramSocket,
        val clientAddr: SocketAddress,
        val socksAddrHeader: ByteArray
    )

    private val lock = Any()
    private val writeLock = Any()
    private val workerExecutor = Executors.newCachedThreadPool()

    private val flowsByConId = ConcurrentHashMap<Int, FlowEntry>()
    private val conidByKey = ConcurrentHashMap<FlowKey, Int>()
    private val nextConId = AtomicInteger(1)

    @Volatile
    private var closed = false
    @Volatile
    private var channel: ChannelDirectTCPIP? = null
    @Volatile
    private var outputStream: OutputStream? = null

    private val loggedConnected = AtomicBoolean(false)
    private val loggedFirstReply = AtomicBoolean(false)
    private val lastFailureMs = AtomicLong(0L)

    fun prewarmAsync() {
        workerExecutor.execute {
            if (!closed) {
                ensureConnected(silentIfFail = true)
            }
        }
    }

    fun sendUdpPacket(
        udpSocket: DatagramSocket,
        clientAddr: SocketAddress,
        atyp: Int,
        dstAddress: InetAddress,
        dstPort: Int,
        socksAddrHeader: ByteArray,
        payload: ByteArray
    ) {
        if (closed || payload.isEmpty()) return

        val ipKey = dstAddress.hostAddress ?: return
        val key = FlowKey(clientAddr, ipKey, dstPort)
        val conid = conidByKey[key] ?: allocateFlow(key, atyp, udpSocket, clientAddr, socksAddrHeader)

        if (!ensureConnected(silentIfFail = false)) return

        val isIpv6 = dstAddress is Inet6Address
        val addrBytes = dstAddress.address
        val addrLen = addrBytes.size + 2
        val innerLen = 3 + addrLen + payload.size
        if (innerLen > 32_760) return

        val frame = ByteArray(2 + innerLen)
        frame[0] = (innerLen and 0xFF).toByte()
        frame[1] = ((innerLen ushr 8) and 0xFF).toByte()
        frame[2] = (if (isIpv6) FLAG_IPV6 else 0).toByte()
        frame[3] = (conid and 0xFF).toByte()
        frame[4] = ((conid ushr 8) and 0xFF).toByte()
        System.arraycopy(addrBytes, 0, frame, 5, addrBytes.size)
        val portOffset = 5 + addrBytes.size
        frame[portOffset] = ((dstPort ushr 8) and 0xFF).toByte()
        frame[portOffset + 1] = (dstPort and 0xFF).toByte()
        System.arraycopy(payload, 0, frame, portOffset + 2, payload.size)

        try {
            synchronized(writeLock) {
                val out = outputStream ?: return
                out.write(frame)
                out.flush()
            }
            onBytesTx(payload.size.toLong())
        } catch (_: IOException) {
            resetConnection()
        }
    }

    fun unregisterSocket(udpSocket: DatagramSocket) {
        val toRemove = flowsByConId.values.filter { it.udpSocket == udpSocket }
        for (entry in toRemove) {
            flowsByConId.remove(entry.conid)
        }
        val keysToRemove = conidByKey.entries
            .filter { flowsByConId[it.value] == null }
            .map { it.key }
        for (k in keysToRemove) {
            conidByKey.remove(k)
        }
    }

    fun close() {
        closed = true
        resetConnection()
        flowsByConId.clear()
        conidByKey.clear()
        try {
            workerExecutor.shutdownNow()
        } catch (_: Exception) {
        }
    }

    private fun allocateFlow(
        key: FlowKey,
        atyp: Int,
        udpSocket: DatagramSocket,
        clientAddr: SocketAddress,
        socksAddrHeader: ByteArray
    ): Int {
        synchronized(flowsByConId) {
            conidByKey[key]?.let { return it }
            repeat(65_000) {
                val id = (Math.floorMod(nextConId.getAndIncrement(), 65_534)) + 1
                if (!flowsByConId.containsKey(id)) {
                    flowsByConId[id] = FlowEntry(id, atyp, udpSocket, clientAddr, socksAddrHeader)
                    conidByKey[key] = id
                    return id
                }
            }
            val fallback = (Math.floorMod(nextConId.getAndIncrement(), 65_534)) + 1
            flowsByConId[fallback] = FlowEntry(fallback, atyp, udpSocket, clientAddr, socksAddrHeader)
            conidByKey[key] = fallback
            return fallback
        }
    }

    private fun ensureConnected(silentIfFail: Boolean): Boolean {
        val current = channel
        if (current != null && current.isConnected && !current.isClosed && outputStream != null) {
            return true
        }

        val now = System.currentTimeMillis()
        if (now - lastFailureMs.get() < 8_000L) {
            return false
        }

        synchronized(lock) {
            val again = channel
            if (again != null && again.isConnected && !again.isClosed && outputStream != null) {
                return true
            }
            if (closed) return false

            val session = sessionProvider()
            if (session == null || !session.isConnected) return false

            var ch: ChannelDirectTCPIP? = null
            try {
                ch = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
                ch.setHost("127.0.0.1")
                ch.setPort(udpgwPort)
                ch.setOrgIPAddress("127.0.0.1")
                ch.setOrgPort(udpgwPort)

                val chIn = DataInputStream(ch.inputStream)
                val chOut = ch.outputStream
                ch.connect(5_000)

                channel = ch
                outputStream = chOut

                if (loggedConnected.compareAndSet(false, true)) {
                    onLog("Motor Juegos / UDP listo (BadVPN UDPGW puerto $udpgwPort)", LogLevel.SUCCESS)
                }

                startReaderAndKeepalive(ch, chIn)
                return true
            } catch (e: Exception) {
                val prev = lastFailureMs.getAndSet(System.currentTimeMillis())
                if (!silentIfFail && prev == 0L) {
                    onLog(
                        "UDPGW puerto $udpgwPort no disponible en esta VPS (${e.message ?: "cerrado"})",
                        LogLevel.WARN
                    )
                }
                try {
                    ch?.disconnect()
                } catch (_: Exception) {
                }
                channel = null
                outputStream = null
                return false
            }
        }
    }

    private fun startReaderAndKeepalive(activeChannel: ChannelDirectTCPIP, input: DataInputStream) {
        workerExecutor.execute {
            try {
                while (!closed && activeChannel.isConnected && !activeChannel.isClosed) {
                    val b0 = input.read()
                    if (b0 == -1) break
                    val b1 = input.read()
                    if (b1 == -1) break
                    val frameLen = (b0 and 0xFF) or ((b1 and 0xFF) shl 8)
                    if (frameLen <= 0 || frameLen > 32_768) break

                    val frame = ByteArray(frameLen)
                    input.readFully(frame)
                    if (frameLen < 3) continue

                    val flags = frame[0].toInt() and 0xFF
                    if ((flags and FLAG_KEEPALIVE) != 0) continue

                    val conid = (frame[1].toInt() and 0xFF) or ((frame[2].toInt() and 0xFF) shl 8)
                    val isReplyIpv6 = (flags and FLAG_IPV6) != 0
                    val addrSize = if (isReplyIpv6) 18 else 6
                    val payloadOffset = 3 + addrSize
                    if (frameLen <= payloadOffset) continue

                    val entry = flowsByConId[conid] ?: continue
                    if (entry.udpSocket.isClosed) {
                        unregisterSocket(entry.udpSocket)
                        continue
                    }

                    val udpPayloadSize = frameLen - payloadOffset
                    onBytesRx(udpPayloadSize.toLong())

                    // Si el cliente usó IPv4 directa, reenviamos la IP/puerto reales de respuesta (Fullcone NAT)
                    val headerBytes = if (entry.atyp == 0x01 && !isReplyIpv6) {
                        byteArrayOf(
                            0x01,
                            frame[3], frame[4], frame[5], frame[6],
                            frame[7], frame[8]
                        )
                    } else {
                        entry.socksAddrHeader
                    }

                    val outPacket = ByteArray(3 + headerBytes.size + udpPayloadSize)
                    outPacket[0] = 0
                    outPacket[1] = 0
                    outPacket[2] = 0
                    System.arraycopy(headerBytes, 0, outPacket, 3, headerBytes.size)
                    System.arraycopy(frame, payloadOffset, outPacket, 3 + headerBytes.size, udpPayloadSize)

                    if (loggedFirstReply.compareAndSet(false, true)) {
                        onLog("Paquetes UDP de juegos recibiéndose correctamente", LogLevel.SUCCESS)
                    }

                    try {
                        entry.udpSocket.send(
                            DatagramPacket(outPacket, outPacket.size, entry.clientAddr)
                        )
                    } catch (_: IOException) {
                        unregisterSocket(entry.udpSocket)
                    }
                }
            } catch (_: EOFException) {
            } catch (_: IOException) {
            } finally {
                if (channel == activeChannel) {
                    resetConnection()
                }
            }
        }

        workerExecutor.execute {
            val keepAliveFrame = byteArrayOf(0x03, 0x00, FLAG_KEEPALIVE.toByte(), 0x00, 0x00)
            try {
                while (!closed && activeChannel.isConnected && !activeChannel.isClosed) {
                    Thread.sleep(15_000)
                    if (closed || channel != activeChannel) break
                    synchronized(writeLock) {
                        outputStream?.write(keepAliveFrame)
                        outputStream?.flush()
                    }
                }
            } catch (_: InterruptedException) {
            } catch (_: Exception) {
            }
        }
    }

    private fun resetConnection() {
        synchronized(lock) {
            outputStream = null
            try {
                channel?.disconnect()
            } catch (_: Exception) {
            }
            channel = null
        }
    }

    companion object {
        private const val FLAG_KEEPALIVE = 1 shl 0
        private const val FLAG_IPV6 = 1 shl 3
    }
}
