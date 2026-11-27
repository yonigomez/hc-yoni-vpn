package com.hcyoni.vpn.ssh

import com.hcyoni.vpn.model.LogLevel
import com.hcyoni.vpn.model.VpnConfig
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketTimeoutException
import java.util.regex.Pattern
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

object PayloadInjector {

    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val RESPONSE_PEEK_TIMEOUT_MS = 6_000
    private const val DEFAULT_USER_AGENT =
        "Mozilla/5.0 (Linux; Android 15; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36"

    private val SPLIT_PATTERN = Pattern.compile(
        "(\\[delay_split\\]|\\[split_delay\\]|\\[instant_split\\]|\\[split\\])",
        Pattern.CASE_INSENSITIVE
    )

    fun connectAndInject(
        config: VpnConfig,
        socketProtector: (Socket) -> Unit,
        onLog: (String, LogLevel) -> Unit
    ): Socket {
        val useProxy = config.proxyHost.isNotBlank()
        val connectHost = if (useProxy) config.proxyHost.trim() else config.sshHost.trim()
        val connectPort = if (useProxy) config.proxyPort else config.sshPort

        if (connectHost.isBlank()) {
            throw IOException("El host SSH no puede estar vacío")
        }

        val rawSocket = Socket(Proxy.NO_PROXY)
        try {
            rawSocket.tcpNoDelay = true
            rawSocket.keepAlive = true
            socketProtector(rawSocket)

            onLog("Conectando TCP a $connectHost:$connectPort...", LogLevel.INFO)
            rawSocket.connect(InetSocketAddress(connectHost, connectPort), CONNECT_TIMEOUT_MS)
            onLog("Socket TCP conectado ($connectHost:$connectPort)", LogLevel.INFO)

            var activeSocket: Socket = rawSocket

            if (config.useTls) {
                val sni = config.sniHost.ifBlank { config.sshHost }.trim()
                onLog("Iniciando handshake SSL/TLS (SNI: ${sni.ifBlank { "ninguno" }})...", LogLevel.INFO)
                val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
                val sslSocket = sslFactory.createSocket(
                    rawSocket,
                    sni.ifBlank { connectHost },
                    connectPort,
                    true
                ) as SSLSocket

                if (sni.isNotBlank() && !isIpLiteral(sni)) {
                    val params = sslSocket.sslParameters
                    params.serverNames = listOf(SNIHostName(sni))
                    sslSocket.sslParameters = params
                }
                sslSocket.soTimeout = CONNECT_TIMEOUT_MS
                sslSocket.startHandshake()
                onLog(
                    "TLS activo: ${sslSocket.session.protocol} (${sslSocket.session.cipherSuite})",
                    LogLevel.SUCCESS
                )
                activeSocket = sslSocket
            }

            val rawPayload = config.payload.trim()
            if (rawPayload.isBlank()) {
                onLog("Sin payload: conectando SSH directo...", LogLevel.INFO)
                activeSocket.soTimeout = 0
                return activeSocket
            }

            val expanded = expandPayloadTags(rawPayload, config)
            sendPayloadWithSplits(activeSocket.getOutputStream(), expanded, onLog)

            val pushbackIn = PushbackInputStream(activeSocket.getInputStream(), 8192)
            consumeOptionalHttpHandshake(activeSocket, pushbackIn, onLog)

            activeSocket.soTimeout = 0
            return WrappedInputSocket(activeSocket, pushbackIn)
        } catch (t: Throwable) {
            try {
                rawSocket.close()
            } catch (_: Exception) {
            }
            throw if (t is IOException) t else IOException(t.message ?: "Error al inyectar payload", t)
        }
    }

    fun expandPayloadTags(template: String, config: VpnConfig): String {
        val hostPort = "${config.sshHost.trim()}:${config.sshPort}"
        val sniOrHost = config.sniHost.ifBlank { config.sshHost }.trim()

        var normalized = template
            .replace("\r\n", "\n")
            .replace("\n", "[crlf]")

        normalized = replaceCaseInsensitive(normalized, "[crlf]", "\r\n")
        normalized = replaceCaseInsensitive(normalized, "[lfcr]", "\n\r")
        normalized = replaceCaseInsensitive(normalized, "[cr]", "\r")
        normalized = replaceCaseInsensitive(normalized, "[lf]", "\n")
        normalized = replaceCaseInsensitive(normalized, "[host_port]", hostPort)
        normalized = replaceCaseInsensitive(normalized, "[ssh]", hostPort)
        normalized = replaceCaseInsensitive(normalized, "[host]", sniOrHost)
        normalized = replaceCaseInsensitive(normalized, "[sni]", sniOrHost)
        normalized = replaceCaseInsensitive(normalized, "[port]", config.sshPort.toString())
        normalized = replaceCaseInsensitive(normalized, "[protocol]", "HTTP/1.1")
        normalized = replaceCaseInsensitive(normalized, "[ua]", DEFAULT_USER_AGENT)
        normalized = replaceCaseInsensitive(normalized, "[netdata]", "CONNECT $hostPort HTTP/1.1")
        normalized = replaceCaseInsensitive(normalized, "[raw]", "")
        return normalized
    }

    private fun replaceCaseInsensitive(input: String, target: String, replacement: String): String {
        return Pattern.compile(Pattern.quote(target), Pattern.CASE_INSENSITIVE)
            .matcher(input)
            .replaceAll(java.util.regex.Matcher.quoteReplacement(replacement))
    }

    private fun sendPayloadWithSplits(
        out: OutputStream,
        expanded: String,
        onLog: (String, LogLevel) -> Unit
    ) {
        val matcher = SPLIT_PATTERN.matcher(expanded)
        var lastEnd = 0
        var chunkIndex = 0

        while (matcher.find()) {
            val chunk = expanded.substring(lastEnd, matcher.start())
            if (chunk.isNotEmpty()) {
                chunkIndex++
                out.write(chunk.toByteArray(Charsets.ISO_8859_1))
                out.flush()
            }
            val tag = matcher.group(1)?.lowercase() ?: ""
            val delayMs = when {
                tag.contains("delay") -> 200L
                tag.contains("instant") -> 0L
                else -> 30L
            }
            if (delayMs > 0) {
                onLog("Split #$chunkIndex aplicado (${delayMs}ms)", LogLevel.INFO)
                Thread.sleep(delayMs)
            }
            lastEnd = matcher.end()
        }

        val tail = expanded.substring(lastEnd)
        if (tail.isNotEmpty()) {
            out.write(tail.toByteArray(Charsets.ISO_8859_1))
            out.flush()
        }

        val firstLine = expanded.lineSequence().firstOrNull()?.take(90) ?: "Payload enviado"
        onLog("Payload enviado: $firstLine", LogLevel.INFO)
    }

    private fun consumeOptionalHttpHandshake(
        socket: Socket,
        pushbackIn: PushbackInputStream,
        onLog: (String, LogLevel) -> Unit
    ) {
        val previousTimeout = socket.soTimeout
        socket.soTimeout = RESPONSE_PEEK_TIMEOUT_MS
        try {
            val probe = ByteArray(16)
            val firstRead = pushbackIn.read(probe)
            if (firstRead <= 0) {
                throw IOException("El servidor cerró la conexión tras enviar el payload")
            }

            val prefix = String(probe, 0, firstRead, Charsets.ISO_8859_1)
            if (prefix.startsWith("SSH-", ignoreCase = false)) {
                pushbackIn.unread(probe, 0, firstRead)
                onLog("Banner SSH recibido directamente", LogLevel.INFO)
                return
            }

            if (!prefix.startsWith("HTTP/", ignoreCase = true)) {
                pushbackIn.unread(probe, 0, firstRead)
                onLog("Respuesta directa detectada, continuando con SSH...", LogLevel.INFO)
                return
            }

            val buffer = ByteArrayOutputStream()
            buffer.write(probe, 0, firstRead)
            val tmp = ByteArray(1024)
            var headerEnd = findHeaderEnd(buffer.toByteArray())

            while (headerEnd < 0 && buffer.size() < 8192) {
                val n = pushbackIn.read(tmp)
                if (n <= 0) break
                buffer.write(tmp, 0, n)
                headerEnd = findHeaderEnd(buffer.toByteArray())
            }

            val allBytes = buffer.toByteArray()
            if (headerEnd < 0) {
                val preview = String(allBytes, Charsets.ISO_8859_1).lineSequence().firstOrNull().orEmpty()
                throw IOException("Respuesta HTTP incompleta del servidor: $preview")
            }

            val headerStr = String(allBytes, 0, headerEnd, Charsets.ISO_8859_1)
            val statusLine = headerStr.lineSequence().firstOrNull()?.trim().orEmpty()
            val statusCode = statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: 0

            if (allBytes.size > headerEnd) {
                pushbackIn.unread(allBytes, headerEnd, allBytes.size - headerEnd)
            }

            if (statusCode in listOf(101, 200)) {
                onLog("Respuesta Payload: $statusLine", LogLevel.SUCCESS)
            } else {
                onLog("Respuesta HTTP inesperada: $statusLine", LogLevel.WARN)
                throw IOException("El servidor/proxy rechazó el payload: $statusLine")
            }
        } catch (_: SocketTimeoutException) {
            onLog("Sin cabecera HTTP previa; iniciando negociación SSH...", LogLevel.INFO)
        } finally {
            try {
                socket.soTimeout = previousTimeout
            } catch (_: Exception) {
            }
        }
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

    private fun isIpLiteral(host: String): Boolean {
        val ipv4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
        return ipv4.matches(host) || host.contains(":")
    }

    private class WrappedInputSocket(
        private val delegate: Socket,
        private val customInputStream: InputStream
    ) : Socket() {
        override fun getInputStream(): InputStream = customInputStream
        override fun getOutputStream(): OutputStream = delegate.getOutputStream()
        override fun close() = delegate.close()
        override fun isClosed(): Boolean = delegate.isClosed
        override fun isConnected(): Boolean = delegate.isConnected
        override fun getSoTimeout(): Int = delegate.soTimeout
        override fun setSoTimeout(timeout: Int) {
            delegate.soTimeout = timeout
        }

        override fun setTcpNoDelay(on: Boolean) {
            delegate.tcpNoDelay = on
        }

        override fun getTcpNoDelay(): Boolean = delegate.tcpNoDelay
        override fun setKeepAlive(on: Boolean) {
            delegate.keepAlive = on
        }

        override fun getKeepAlive(): Boolean = delegate.keepAlive
        override fun getInetAddress(): InetAddress = delegate.inetAddress
        override fun getPort(): Int = delegate.port
        override fun getRemoteSocketAddress(): SocketAddress = delegate.remoteSocketAddress
        override fun getLocalAddress(): InetAddress = delegate.localAddress
        override fun getLocalPort(): Int = delegate.localPort
        override fun getLocalSocketAddress(): SocketAddress = delegate.localSocketAddress
        override fun shutdownInput() = delegate.shutdownInput()
        override fun shutdownOutput() = delegate.shutdownOutput()
        override fun isInputShutdown(): Boolean = delegate.isInputShutdown
        override fun isOutputShutdown(): Boolean = delegate.isOutputShutdown
    }
}
