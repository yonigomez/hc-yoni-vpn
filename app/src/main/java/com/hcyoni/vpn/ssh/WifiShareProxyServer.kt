package com.hcyoni.vpn.ssh

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
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

class WifiShareProxyServer(
    private val sessionProvider: () -> Session?,
    private val listenPort: Int,
    private val onBytesTx: (Long) -> Unit,
    private val onBytesRx: (Long) -> Unit
) {
    private val executor = Executors.newCachedThreadPool()
    private val scope = CoroutineScope(SupervisorJob() + executor.asCoroutineDispatcher())

    private val activeSockets = ConcurrentHashMap.newKeySet<Closeable>()
    private val activeChannels = ConcurrentHashMap.newKeySet<ChannelDirectTCPIP>()

    private var serverSocket: ServerSocket? = null
    private var acceptJob: Job? = null

    fun start(): Int {
        val server = ServerSocket(listenPort, 128, InetAddress.getByName("0.0.0.0"))
        serverSocket = server
        val boundPort = server.localPort

        acceptJob = scope.launch {
            while (isActive && !server.isClosed) {
                try {
                    val client = server.accept()
                    client.tcpNoDelay = true
                    activeSockets.add(client)
                    launch { handleProxyClient(client) }
                } catch (_: IOException) {
                    break
                }
            }
        }
        return boundPort
    }

    fun stop() {
        try {
            serverSocket?.close()
        } catch (_: Exception) {
        }
        serverSocket = null

        activeChannels.forEach {
            try {
                it.disconnect()
            } catch (_: Exception) {
            }
        }
        activeChannels.clear()

        activeSockets.forEach {
            try {
                it.close()
            } catch (_: Exception) {
            }
        }
        activeSockets.clear()

        acceptJob?.cancel()
        scope.cancel()
        try {
            executor.shutdownNow()
        } catch (_: Exception) {
        }
    }

    private suspend fun handleProxyClient(client: Socket) {
        var channel: ChannelDirectTCPIP? = null
        try {
            client.soTimeout = 15_000
            val clientIn = client.getInputStream()
            val clientOut = client.getOutputStream()

            val headerLines = readHttpHeaders(clientIn)
            if (headerLines.isEmpty()) return

            val requestLine = headerLines[0].trim()
            val parts = requestLine.split(" ")
            if (parts.size < 3) return

            val method = parts[0].uppercase()
            val targetRaw = parts[1]
            val version = parts[2]

            val session = sessionProvider()
            if (session == null || !session.isConnected) {
                clientOut.write("HTTP/1.1 503 Service Unavailable\r\n\r\n".toByteArray())
                clientOut.flush()
                return
            }

            client.soTimeout = 0

            val destHost: String
            val destPort: Int
            var forwardRequestBytes: ByteArray? = null

            if (method == "CONNECT") {
                val hp = targetRaw.split(":")
                destHost = hp[0].trim()
                destPort = hp.getOrNull(1)?.toIntOrNull() ?: 443
            } else {
                val uri = try {
                    URI(targetRaw)
                } catch (_: Exception) {
                    null
                }
                if (uri != null && !uri.host.isNullOrBlank()) {
                    destHost = uri.host
                    destPort = if (uri.port > 0) uri.port else 80
                    val path = buildString {
                        append(uri.rawPath?.ifEmpty { "/" } ?: "/")
                        if (!uri.rawQuery.isNullOrEmpty()) append("?").append(uri.rawQuery)
                    }
                    forwardRequestBytes = rebuildHttpHeader(method, path, version, headerLines)
                } else {
                    val hostHdr = headerLines.drop(1)
                        .firstOrNull { it.startsWith("Host:", ignoreCase = true) }
                        ?.substringAfter(':')?.trim().orEmpty()
                    if (hostHdr.isBlank()) return
                    val hp = hostHdr.split(":")
                    destHost = hp[0].trim()
                    destPort = hp.getOrNull(1)?.toIntOrNull() ?: 80
                    forwardRequestBytes = rebuildHttpHeader(method, targetRaw, version, headerLines)
                }
            }

            if (destHost.isBlank()) return

            channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
            channel.setHost(destHost)
            channel.setPort(destPort)
            channel.setOrgIPAddress("127.0.0.1")
            channel.setOrgPort(client.port)

            val sshIn = channel.inputStream
            val sshOut = channel.outputStream
            channel.connect(10_000)
            activeChannels.add(channel)

            if (method == "CONNECT") {
                clientOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
                clientOut.flush()
            } else if (forwardRequestBytes != null) {
                sshOut.write(forwardRequestBytes)
                sshOut.flush()
            }

            coroutineScope {
                val up = launch {
                    pump(clientIn, sshOut) { onBytesTx(it) }
                    try {
                        sshOut.close()
                    } catch (_: Exception) {
                    }
                }
                val down = launch {
                    pump(sshIn, clientOut) { onBytesRx(it) }
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
        } catch (_: Exception) {
        } finally {
            if (channel != null) {
                activeChannels.remove(channel)
                try {
                    channel.disconnect()
                } catch (_: Exception) {
                }
            }
            activeSockets.remove(client)
            try {
                client.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun readHttpHeaders(input: InputStream): List<String> {
        val lines = mutableListOf<String>()
        val buf = ByteArrayOutputStream(256)
        while (lines.size < 64) {
            buf.reset()
            while (true) {
                val b = input.read()
                if (b == -1) return lines
                if (b == '\n'.code) break
                if (b != '\r'.code && buf.size() < 8192) buf.write(b)
            }
            val line = buf.toString(Charsets.ISO_8859_1.name())
            if (line.isEmpty()) break
            lines.add(line)
        }
        return lines
    }

    private fun rebuildHttpHeader(
        method: String,
        path: String,
        version: String,
        originalLines: List<String>
    ): ByteArray {
        val sb = StringBuilder()
        sb.append(method).append(' ').append(path).append(' ').append(version).append("\r\n")
        for (i in 1 until originalLines.size) {
            val l = originalLines[i]
            if (l.startsWith("Proxy-Connection:", ignoreCase = true)) continue
            sb.append(l).append("\r\n")
        }
        sb.append("\r\n")
        return sb.toString().toByteArray(Charsets.ISO_8859_1)
    }

    private fun pump(input: InputStream, output: OutputStream, onBytes: (Long) -> Unit) {
        val buf = ByteArray(16_384)
        try {
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                output.write(buf, 0, n)
                output.flush()
                onBytes(n.toLong())
            }
        } catch (_: EOFException) {
        } catch (_: IOException) {
        }
    }

    companion object {
        fun detectHotspotIpAddress(): String {
            var fallbackLan: String? = null
            try {
                val interfaces = NetworkInterface.getNetworkInterfaces()
                while (interfaces.hasMoreElements()) {
                    val nif = interfaces.nextElement()
                    if (!nif.isUp || nif.isLoopback) continue
                    val name = nif.name.lowercase()
                    val addrs = nif.inetAddresses
                    while (addrs.hasMoreElements()) {
                        val addr = addrs.nextElement()
                        if (addr is Inet4Address && !addr.isLoopbackAddress) {
                            val ip = addr.hostAddress ?: continue
                            if (name.contains("ap") || name.contains("swlan") || name.contains("rndis") ||
                                ip.startsWith("192.168.43.") || ip.startsWith("192.168.137.") || ip.startsWith("192.168.42.")
                            ) {
                                return ip
                            }
                            if (ip.startsWith("192.168.") || ip.startsWith("10.")) {
                                fallbackLan = ip
                            }
                        }
                    }
                }
            } catch (_: Exception) {
            }
            return fallbackLan ?: "192.168.43.1"
        }
    }
}
