package com.hcyoni.vpn.ssh

import com.hcyoni.vpn.model.LogLevel
import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.ByteArrayOutputStream
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
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class LocalSocks5Server(
    private val sessionProvider: () -> Session?,
    private val dnsPrimary: String,
    private val dnsSecondary: String,
    private val enableIpv6: Boolean,
    private val udpgwEnabled: Boolean,
    private val udpgwPort: Int,
    private val hideServerDetails: Boolean,
    private val onLog: (String, LogLevel) -> Unit
) {
    private data class CachedDnsReply(
        val responseBytes: ByteArray,
        val expiresAtMs: Long
    )

    private val executor = Executors.newCachedThreadPool()
    private val dispatcher = executor.asCoroutineDispatcher()
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)

    private val activeSockets = ConcurrentHashMap.newKeySet<Closeable>()
    private val activeChannels = ConcurrentHashMap.newKeySet<ChannelDirectTCPIP>()
    private val dnsWireCache = ConcurrentHashMap<String, CachedDnsReply>()

    private var serverSocket: ServerSocket? = null
    private var acceptJob: Job? = null

    private val loggedFirstSuccess = AtomicBoolean(false)
    private val loggedUdpgwReady = AtomicBoolean(false)
    private val loggedUdpgwFallback = AtomicBoolean(false)
    private val lastErrorLogMs = AtomicLong(0L)
    private val tcp53BlockedUntilMs = AtomicLong(0L)

    val txBytes = AtomicLong(0L)
    val rxBytes = AtomicLong(0L)

    @Volatile
    var listeningPort: Int = 0
        private set

    fun start(): Int {
        val server = ServerSocket(0, 256, InetAddress.getByName("127.0.0.1"))
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
        dnsWireCache.clear()

        acceptJob?.cancel()
        scope.cancel()
        try {
            executor.shutdownNow()
        } catch (_: Exception) {
        }
    }

    private suspend fun handleClient(client: Socket) {
        try {
            val input = DataInputStream(client.getInputStream())
            val output = client.getOutputStream()

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

            val reqVer = input.readUnsignedByte()
            val cmd = input.readUnsignedByte()
            input.readUnsignedByte()
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

        if (destPort == 853) {
            sendSocksReply(clientOut, 0x05)
            return
        }

        val session = sessionProvider()
        if (session == null || !session.isConnected) {
            sendSocksReply(clientOut, 0x01)
            return
        }

        val isUdpgwControl = udpgwEnabled && destHost == "127.0.0.1" && destPort == udpgwPort

        var channel: ChannelDirectTCPIP? = null
        try {
            channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
            channel.setHost(destHost)
            channel.setPort(destPort)
            channel.setOrgIPAddress("127.0.0.1")
            channel.setOrgPort(client.port)

            val sshIn = channel.inputStream
            val sshOut = channel.outputStream
            channel.connect(if (isUdpgwControl) 5_000 else 8_000)
            activeChannels.add(channel)

            sendSocksReply(clientOut, 0x00)

            if (isUdpgwControl) {
                try {
                    client.trafficClass = 0x10
                    client.sendBufferSize = 131_072
                    client.receiveBufferSize = 131_072
                } catch (_: Exception) {
                }
                if (loggedUdpgwReady.compareAndSet(false, true)) {
                    onLog("Juegos / UDP nativo conectado directo a UDPGW ($udpgwPort)", LogLevel.SUCCESS)
                }
            } else if (loggedFirstSuccess.compareAndSet(false, true)) {
                val targetLabel = if (hideServerDetails) "destino remoto" else "$destHost:$destPort"
                onLog("Primer enlace TCP activo hacia $targetLabel", LogLevel.SUCCESS)
            }

            val upBuf = if (isUdpgwControl) 65_536 else 8_192
            val downBuf = if (isUdpgwControl) 65_536 else 32_768

            coroutineScope {
                val up = launch {
                    try {
                        Thread.currentThread().priority =
                            if (isUdpgwControl) Thread.MAX_PRIORITY else (Thread.NORM_PRIORITY - 1)
                    } catch (_: Exception) {
                    }
                    copyStream(clientIn, sshOut, upBuf) { bytes -> txBytes.addAndGet(bytes) }
                    try {
                        sshOut.close()
                    } catch (_: Exception) {
                    }
                }
                val down = launch {
                    try {
                        Thread.currentThread().priority =
                            if (isUdpgwControl) Thread.MAX_PRIORITY else (Thread.NORM_PRIORITY + 1)
                    } catch (_: Exception) {
                    }
                    // Drenar sshIn rápido evita llenar el PipedInputStream interno de JSch
                    copyStream(sshIn, clientOut, downBuf) { bytes -> rxBytes.addAndGet(bytes) }
                    try {
                        client.shutdownOutput()
                    } catch (_: Exception) {
                    }
                    try {
                        client.close()
                    } catch (_: Exception) {
                    }
                }
                up.join()
                down.join()
            }
        } catch (e: Exception) {
            if (isUdpgwControl) {
                try {
                    channel?.disconnect()
                } catch (_: Exception) {
                }
                channel = null
                if (loggedUdpgwFallback.compareAndSet(false, true)) {
                    onLog(
                        "Puerto $udpgwPort no activo en esta VPS; activando puente DNS interno",
                        LogLevel.WARN
                    )
                }
                sendSocksReply(clientOut, 0x00)
                runLocalDnsUdpgwFallback(clientIn, clientOut)
                return
            }

            if (destPort != 80) {
                logRateLimited("Enlace TCP rechazado ($destPort): ${e.message ?: "cerrado"}")
            }
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

    private suspend fun runLocalDnsUdpgwFallback(clientIn: InputStream, clientOut: OutputStream) {
        val dataIn = DataInputStream(clientIn)
        val writeLock = Any()
        coroutineScope {
            try {
                while (isActive) {
                    val b0 = dataIn.read()
                    if (b0 == -1) break
                    val b1 = dataIn.read()
                    if (b1 == -1) break
                    val frameLen = (b0 and 0xFF) or ((b1 and 0xFF) shl 8)
                    if (frameLen <= 0 || frameLen > 32_768) break

                    val frame = ByteArray(frameLen)
                    dataIn.readFully(frame)
                    if (frameLen < 3) continue

                    val flags = frame[0].toInt() and 0xFF
                    if ((flags and 0x01) != 0) continue

                    val isIpv6 = (flags and 0x08) != 0
                    val addrSize = if (isIpv6) 18 else 6
                    val payloadOffset = 3 + addrSize
                    if (frameLen <= payloadOffset) continue

                    val dstPort = if (!isIpv6) {
                        ((frame[7].toInt() and 0xFF) shl 8) or (frame[8].toInt() and 0xFF)
                    } else {
                        ((frame[19].toInt() and 0xFF) shl 8) or (frame[20].toInt() and 0xFF)
                    }

                    val isDns = ((flags and 0x04) != 0) || (dstPort == 53)
                    if (!isDns) continue

                    val headerCopy = frame.copyOfRange(0, payloadOffset)
                    val dnsQuery = frame.copyOfRange(payloadOffset, frameLen)

                    launch {
                        txBytes.addAndGet(dnsQuery.size.toLong())
                        val resp = resolveDnsWithCache(dnsQuery) ?: return@launch
                        rxBytes.addAndGet(resp.size.toLong())

                        val innerLen = headerCopy.size + resp.size
                        val outFrame = ByteArray(2 + innerLen)
                        outFrame[0] = (innerLen and 0xFF).toByte()
                        outFrame[1] = ((innerLen ushr 8) and 0xFF).toByte()
                        System.arraycopy(headerCopy, 0, outFrame, 2, headerCopy.size)
                        System.arraycopy(resp, 0, outFrame, 2 + headerCopy.size, resp.size)

                        synchronized(writeLock) {
                            try {
                                clientOut.write(outFrame)
                                clientOut.flush()
                            } catch (_: IOException) {
                            }
                        }
                    }
                }
            } catch (_: EOFException) {
            } catch (_: IOException) {
            }
        }
    }

    private suspend fun handleUdpAssociate(
        controlSocket: Socket,
        controlIn: InputStream,
        controlOut: OutputStream
    ) {
        val udpSocket = try {
            DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        } catch (_: Exception) {
            return
        }
        activeSockets.add(udpSocket)
        val udpPort = udpSocket.localPort
        var dnsOnlySession = false

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
                        if (data.size < 10 || data[2].toInt() != 0) continue

                        val atyp = data[3].toInt() and 0xFF
                        val addrEnd = when (atyp) {
                            0x01 -> 8
                            0x03 -> 5 + (data[4].toInt() and 0xFF)
                            0x04 -> 20
                            else -> continue
                        }
                        val headerEnd = addrEnd + 2
                        if (data.size <= headerEnd) continue
                        val dstPort = ((data[addrEnd].toInt() and 0xFF) shl 8) or (data[addrEnd + 1].toInt() and 0xFF)
                        if (dstPort != 53) continue

                        if (!dnsOnlySession) {
                            dnsOnlySession = true
                            try {
                                controlSocket.soTimeout = 2_000
                            } catch (_: Exception) {
                            }
                        }

                        val dnsQuery = data.copyOfRange(headerEnd, data.size)
                        launch {
                            txBytes.addAndGet(dnsQuery.size.toLong())
                            val resp = resolveDnsWithCache(dnsQuery) ?: return@launch
                            rxBytes.addAndGet(resp.size.toLong())

                            val hdr = data.copyOfRange(0, headerEnd)
                            hdr[0] = 0
                            hdr[1] = 0
                            hdr[2] = 0
                            val outPacket = ByteArray(hdr.size + resp.size)
                            System.arraycopy(hdr, 0, outPacket, 0, hdr.size)
                            System.arraycopy(resp, 0, outPacket, hdr.size, resp.size)
                            try {
                                if (!udpSocket.isClosed) {
                                    udpSocket.send(DatagramPacket(outPacket, outPacket.size, senderAddr))
                                }
                            } catch (_: IOException) {
                            }
                        }
                    } catch (_: IOException) {
                        break
                    }
                }
            }

            val sink = ByteArray(64)
            while (isActive && !controlSocket.isClosed) {
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

    private fun resolveDnsWithCache(query: ByteArray): ByteArray? {
        if (query.size <= 4) return null
        val keyBytes = query.copyOfRange(2, query.size)
        val cacheKey = Base64.getEncoder().encodeToString(keyBytes)
        val now = System.currentTimeMillis()

        val cached = dnsWireCache[cacheKey]
        if (cached != null && now < cached.expiresAtMs && cached.responseBytes.size >= 2) {
            val clone = cached.responseBytes.clone()
            clone[0] = query[0]
            clone[1] = query[1]
            return clone
        }

        val resp = resolveDnsUncached(query) ?: return null
        if (dnsWireCache.size > 1500) {
            dnsWireCache.clear()
        }
        dnsWireCache[cacheKey] = CachedDnsReply(resp.clone(), now + 90_000L)
        return resp
    }

    private fun resolveDnsUncached(query: ByteArray): ByteArray? {
        val now = System.currentTimeMillis()
        if (now >= tcp53BlockedUntilMs.get()) {
            val tcpResp = resolveDnsOverSshTcp(query)
            if (tcpResp != null) return tcpResp
            tcp53BlockedUntilMs.set(now + 120_000L)
        }
        return resolveDnsOverHttps443(query)
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
                ch.connect(2_500)
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

    private fun resolveDnsOverHttps443(query: ByteArray): ByteArray? {
        val session = sessionProvider() ?: return null
        if (!session.isConnected) return null

        val endpoints = listOf("1.1.1.1" to "cloudflare-dns.com", "8.8.8.8" to "dns.google")
        for ((ip, hostHeader) in endpoints) {
            var ch: ChannelDirectTCPIP? = null
            var tlsSock: SSLSocket? = null
            try {
                ch = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
                ch.setHost(ip)
                ch.setPort(443)
                ch.setOrgIPAddress("127.0.0.1")
                ch.setOrgPort(443)
                val chIn = ch.inputStream
                val chOut = ch.outputStream
                ch.connect(4_500)
                activeChannels.add(ch)

                val adapter = ChannelSocketAdapter(ch, chIn, chOut)
                val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
                tlsSock = factory.createSocket(adapter, hostHeader, 443, true) as SSLSocket
                tlsSock.soTimeout = 4_500
                tlsSock.startHandshake()

                val reqHeaders = "POST /dns-query HTTP/1.1\r\n" +
                    "Host: $hostHeader\r\n" +
                    "Content-Type: application/dns-message\r\n" +
                    "Accept: application/dns-message\r\n" +
                    "Content-Length: ${query.size}\r\n" +
                    "Connection: close\r\n\r\n"

                val out = tlsSock.outputStream
                out.write(reqHeaders.toByteArray(Charsets.ISO_8859_1))
                out.write(query)
                out.flush()

                val respStream = tlsSock.inputStream
                val rawAll = ByteArrayOutputStream()
                val buf = ByteArray(4096)
                while (true) {
                    val n = respStream.read(buf)
                    if (n <= 0) break
                    rawAll.write(buf, 0, n)
                    if (rawAll.size() > 16_384) break
                }

                val bytes = rawAll.toByteArray()
                val splitIdx = findHeaderEnd(bytes)
                if (splitIdx > 0 && splitIdx < bytes.size) {
                    val headerText = String(bytes, 0, splitIdx, Charsets.ISO_8859_1)
                    if (headerText.contains(" 200 ")) {
                        return bytes.copyOfRange(splitIdx, bytes.size)
                    }
                }
            } catch (_: Exception) {
            } finally {
                try {
                    tlsSock?.close()
                } catch (_: Exception) {
                }
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

    private fun findHeaderEnd(bytes: ByteArray): Int {
        for (i in 0 until bytes.size - 3) {
            if (bytes[i] == '\r'.code.toByte() &&
                bytes[i + 1] == '\n'.code.toByte() &&
                bytes[i + 2] == '\r'.code.toByte() &&
                bytes[i + 3] == '\n'.code.toByte()
            ) {
                return i + 4
            }
        }
        return -1
    }

    private fun copyStream(
        input: InputStream,
        output: OutputStream,
        bufSize: Int,
        onBytes: (Long) -> Unit
    ) {
        val buffer = ByteArray(bufSize)
        try {
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                output.write(buffer, 0, read)
                output.flush()
                onBytes(read.toLong())
            }
        } catch (_: EOFException) {
        } catch (_: IOException) {
        }
    }

    private fun sendSocksReply(out: OutputStream, rep: Int) {
        out.write(byteArrayOf(0x05, rep.toByte(), 0x00, 0x01, 0, 0, 0, 0, 0, 0))
        out.flush()
    }

    private fun logRateLimited(msg: String) {
        val now = System.currentTimeMillis()
        val prev = lastErrorLogMs.get()
        if (now - prev >= 15_000 && lastErrorLogMs.compareAndSet(prev, now)) {
            onLog(msg, LogLevel.WARN)
        }
    }

    private class ChannelSocketAdapter(
        private val channel: ChannelDirectTCPIP,
        private val input: InputStream,
        private val output: OutputStream
    ) : Socket() {
        @Volatile
        private var closedFlag = false
        private var timeoutMs = 0

        override fun getInputStream(): InputStream = input
        override fun getOutputStream(): OutputStream = output
        override fun isConnected(): Boolean = channel.isConnected && !closedFlag
        override fun isClosed(): Boolean = closedFlag || channel.isClosed
        override fun setSoTimeout(timeout: Int) {
            timeoutMs = timeout
        }

        override fun getSoTimeout(): Int = timeoutMs
        override fun close() {
            closedFlag = true
            try {
                channel.disconnect()
            } catch (_: Exception) {
            }
        }
    }
}
