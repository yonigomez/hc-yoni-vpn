package com.hcyoni.vpn.ssh

import com.hcyoni.vpn.model.LogLevel
import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.Closeable
import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class LocalSocks5Server(
    private val sessionProvider: () -> Session?,
    private val dnsPrimary: String,
    private val dnsSecondary: String,
    private val enableIpv6: Boolean,
    private val onLog: (String, LogLevel) -> Unit
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val activeSockets = ConcurrentHashMap.newKeySet<Closeable>()
    private val activeChannels = ConcurrentHashMap.newKeySet<ChannelDirectTCPIP>()

    private var serverSocket: ServerSocket? = null
    private var acceptJob: Job? = null

    val txBytes = AtomicLong(0L)
    val rxBytes = AtomicLong(0L)

    @Volatile
    var listeningPort: Int = 0
        private set

    fun start(): Int {
        val server = ServerSocket(0, 128, InetAddress.getByName("127.0.0.1"))
        serverSocket = server
        listeningPort = server.localPort

        acceptJob = scope.launch {
            while (isActive && !server.isClosed) {
                try {
                    val client = server.accept()
                    client.tcpNoDelay = true
                    activeSockets.add(client)
                    launch { handleClient(client) }
                } catch (_: IOException) {
                    break
                }
            }
        }
        return listeningPort
    }

    fun stop() {
        try {
            serverSocket?.close()
        } catch (_: Exception) {
        }
        serverSocket = null
        listeningPort = 0

        activeChannels.forEach { ch ->
            try {
                ch.disconnect()
            } catch (_: Exception) {
            }
        }
        activeChannels.clear()

        activeSockets.forEach { sock ->
            try {
                sock.close()
            } catch (_: Exception) {
            }
        }
        activeSockets.clear()

        acceptJob?.cancel()
        scope.cancel()
    }

    private suspend fun handleClient(client: Socket) {
        try {
            val input = DataInputStream(client.getInputStream())
            val output = client.getOutputStream()

            // 1. Handshake SOCKS5 (RFC 1928)
            val ver = input.readUnsignedByte()
            if (ver != 0x05) return
            val nMethods = input.readUnsignedByte()
            val methods = ByteArray(nMethods)
            input.readFully(methods)

            if (!methods.contains(0x00.toByte())) {
                output.write(byteArrayOf(0x05, 0xFF.toByte()))
                output.flush()
                return
            }
            output.write(byteArrayOf(0x05, 0x00))
            output.flush()

            // 2. Solicitud SOCKS5
            val reqVer = input.readUnsignedByte()
            val cmd = input.readUnsignedByte()
            input.readUnsignedByte() // RSV
            val atyp = input.readUnsignedByte()
            if (reqVer != 0x05) return

            val destHost = when (atyp) {
                0x01 -> {
                    val addr = ByteArray(4)
                    input.readFully(addr)
                    InetAddress.getByAddress(addr).hostAddress ?: "0.0.0.0"
                }
                0x03 -> {
                    val len = input.readUnsignedByte()
                    val domain = ByteArray(len)
                    input.readFully(domain)
                    String(domain, Charsets.UTF_8)
                }
                0x04 -> {
                    val addr = ByteArray(16)
                    input.readFully(addr)
                    InetAddress.getByAddress(addr).hostAddress ?: "::"
                }
                else -> {
                    sendSocksReply(output, 0x08)
                    return
                }
            }
            val destPort = input.readUnsignedShort()

            when (cmd) {
                0x01 -> handleTcpConnect(client, input, output, atyp, destHost, destPort)
                0x03 -> handleUdpAssociate(client, input, output)
                else -> sendSocksReply(output, 0x07)
            }
        } catch (_: Exception) {
        } finally {
            activeSockets.remove(client)
            try {
                client.close()
            } catch (_: Exception) {
            }
        }
    }

    private suspend fun handleTcpConnect(
        client: Socket,
        clientIn: InputStream,
        clientOut: OutputStream,
        atyp: Int,
        destHost: String,
        destPort: Int
    ) {
        if (atyp == 0x04 && !enableIpv6) {
            sendSocksReply(clientOut, 0x04)
            return
        }

        val session = sessionProvider()
        if (session == null || !session.isConnected) {
            sendSocksReply(clientOut, 0x01)
            return
        }

        var channel: ChannelDirectTCPIP? = null
        try {
            channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
            channel.setHost(destHost)
            channel.setPort(destPort)
            channel.setOrgIPAddress("127.0.0.1")
            channel.setOrgPort(client.port)

            val sshIn = channel.inputStream
            val sshOut = channel.outputStream
            channel.connect(12_000)
            activeChannels.add(channel)

            sendSocksReply(clientOut, 0x00)

            coroutineScope {
                val up = launch {
                    copyStream(clientIn, sshOut) { bytes ->
                        txBytes.addAndGet(bytes)
                    }
                    try {
                        sshOut.close()
                    } catch (_: Exception) {
                    }
                }
                val down = launch {
                    copyStream(sshIn, clientOut) { bytes ->
                        rxBytes.addAndGet(bytes)
                    }
                    try {
                        client.shutdownOutput()
                    } catch (_: Exception) {
                    }
                }
                up.join()
                down.join()
            }
        } catch (_: Exception) {
            try {
                sendSocksReply(clientOut, 0x05)
            } catch (_: Exception) {
            }
        } finally {
            if (channel != null) {
                activeChannels.remove(channel)
                try {
                    channel.disconnect()
                } catch (_: Exception) {
                }
            }
        }
    }

    private suspend fun handleUdpAssociate(
        controlSocket: Socket,
        controlIn: InputStream,
        controlOut: OutputStream
    ) {
        val udpSocket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        activeSockets.add(udpSocket)
        val udpPort = udpSocket.localPort

        // Responder con dirección local de enlace UDP (127.0.0.1:udpPort)
        controlOut.write(
            byteArrayOf(
                0x05, 0x00, 0x00, 0x01,
                127, 0, 0, 1,
                ((udpPort ushr 8) and 0xFF).toByte(),
                (udpPort and 0xFF).toByte()
            )
        )
        controlOut.flush()

        coroutineScope {
            val udpJob = launch {
                val buf = ByteArray(4096)
                while (isActive && !udpSocket.isClosed) {
                    try {
                        val packet = DatagramPacket(buf, buf.size)
                        udpSocket.receive(packet)
                        val data = packet.data.copyOf(packet.length)
                        val senderAddr = packet.socketAddress
                        launch { processUdpPacket(udpSocket, senderAddr, data) }
                    } catch (_: IOException) {
                        break
                    }
                }
            }

            // Según RFC 1928, el socket UDP vive mientras siga abierto el control TCP
            val sink = ByteArray(64)
            while (isActive) {
                val n = try {
                    controlIn.read(sink)
                } catch (_: IOException) {
                    -1
                }
                if (n <= 0) break
            }
            udpJob.cancel()
            activeSockets.remove(udpSocket)
            try {
                udpSocket.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun processUdpPacket(
        udpSocket: DatagramSocket,
        clientAddr: SocketAddress,
        data: ByteArray
    ) {
        if (data.size < 10) return
        if (data[2].toInt() != 0) return // No soportamos datagramas UDP fragmentados

        val atyp = data[3].toInt() and 0xFF
        val addrEnd = when (atyp) {
            0x01 -> 4 + 4
            0x03 -> {
                val dLen = data[4].toInt() and 0xFF
                4 + 1 + dLen
            }
            0x04 -> 4 + 16
            else -> return
        }
        val headerEnd = addrEnd + 2
        if (data.size <= headerEnd) return

        val dstPort = ((data[addrEnd].toInt() and 0xFF) shl 8) or (data[addrEnd + 1].toInt() and 0xFF)
        if (dstPort != 53) {
            // El servidor SSH estándar solo reenvía TCP; las consultas DNS (53) se convierten a TCP
            return
        }

        val dnsQuery = data.copyOfRange(headerEnd, data.size)
        txBytes.addAndGet(dnsQuery.size.toLong())

        val dnsResponse = resolveDnsOverSshTcp(dnsQuery) ?: return
        rxBytes.addAndGet(dnsResponse.size.toLong())

        val headerSlice = data.copyOfRange(0, headerEnd)
        headerSlice[0] = 0
        headerSlice[1] = 0
        headerSlice[2] = 0

        val outPacket = ByteArray(headerSlice.size + dnsResponse.size)
        System.arraycopy(headerSlice, 0, outPacket, 0, headerSlice.size)
        System.arraycopy(dnsResponse, 0, outPacket, headerSlice.size, dnsResponse.size)

        try {
            if (!udpSocket.isClosed) {
                udpSocket.send(DatagramPacket(outPacket, outPacket.size, clientAddr))
            }
        } catch (_: IOException) {
        }
    }

    private fun resolveDnsOverSshTcp(query: ByteArray): ByteArray? {
        val session = sessionProvider() ?: return null
        if (!session.isConnected) return null

        val targets = listOf(dnsPrimary, dnsSecondary)
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinct()

        for (dnsHost in targets) {
            var ch: ChannelDirectTCPIP? = null
            try {
                ch = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
                ch.setHost(dnsHost)
                ch.setPort(53)
                ch.setOrgIPAddress("127.0.0.1")
                ch.setOrgPort(53)

                val chIn = DataInputStream(ch.inputStream)
                val chOut = ch.outputStream
                ch.connect(8_000)
                activeChannels.add(ch)

                val framed = ByteArray(2 + query.size)
                framed[0] = ((query.size ushr 8) and 0xFF).toByte()
                framed[1] = (query.size and 0xFF).toByte()
                System.arraycopy(query, 0, framed, 2, query.size)
                chOut.write(framed)
                chOut.flush()

                val respLen = chIn.readUnsignedShort()
                if (respLen <= 0 || respLen > 8192) continue
                val resp = ByteArray(respLen)
                chIn.readFully(resp)
                return resp
            } catch (_: EOFException) {
            } catch (_: Exception) {
            } finally {
                if (ch != null) {
                    activeChannels.remove(ch)
                    try {
                        ch.disconnect()
                    } catch (_: Exception) {
                    }
                }
            }
        }
        return null
    }

    private fun copyStream(
        input: InputStream,
        output: OutputStream,
        onBytes: (Long) -> Unit
    ) {
        val buffer = ByteArray(16_384)
        try {
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                output.write(buffer, 0, read)
                output.flush()
                onBytes(read.toLong())
            }
        } catch (_: IOException) {
        }
    }

    private fun sendSocksReply(out: OutputStream, rep: Int) {
        out.write(byteArrayOf(0x05, rep.toByte(), 0x00, 0x01, 0, 0, 0, 0, 0, 0))
        out.flush()
    }
}
