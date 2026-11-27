package com.hcyoni.vpn.ssh

import android.annotation.SuppressLint
import android.util.Base64
import com.hcyoni.vpn.model.LogLevel
import com.hcyoni.vpn.model.VpnConfig
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.SequenceInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicInteger
import java.util.regex.Matcher
import java.util.regex.Pattern
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.random.Random

object PayloadInjector {

    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val RESPONSE_TIMEOUT_MS = 10_000
    private const val DEFAULT_USER_AGENT =
        "Mozilla/5.0 (Linux; Android 15; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36"

    private val rotationCounter = AtomicInteger(0)

    private val SPLIT_PATTERN = Pattern.compile(
        "(\\[delay_split\\]|\\[split_delay\\]|\\[instant_split\\]|\\[x-split\\]|\\[splitNoDelay\\]|\\[split\\])",
        Pattern.CASE_INSENSITIVE
    )

    private val CRLF_MULT_PATTERN = Pattern.compile(
        "\\[crlf\\*(\\d+)\\]",
        Pattern.CASE_INSENSITIVE
    )

    private val ROTATE_PATTERN = Pattern.compile(
        "\\[rotate=([^\\]]+)\\]",
        Pattern.CASE_INSENSITIVE
    )

    private val RANDOM_PATTERN = Pattern.compile(
        "\\[random=([^\\]]+)\\]",
        Pattern.CASE_INSENSITIVE
    )

    fun connectAndInject(
        config: VpnConfig,
        socketProtector: (Socket) -> Unit,
        onLog: (String, LogLevel) -> Unit
    ): Socket {
        val hideServer = config.lockServerAndProxy
        val hidePayload = config.lockPayload

        val rotIdx = rotationCounter.getAndIncrement()
        val effectiveSshHost = pickRotatedValue(config.sshHost, rotIdx)
        val effectiveProxyHost = pickRotatedValue(config.proxyHost, rotIdx)
        val effectiveSniHost = pickRotatedValue(config.sniHost, rotIdx)

        val effectiveConfig = config.copy(
            sshHost = effectiveSshHost,
            proxyHost = effectiveProxyHost,
            sniHost = effectiveSniHost
        )

        val useProxy = effectiveProxyHost.isNotBlank()
        val connectHost = if (useProxy) effectiveProxyHost else effectiveSshHost
        val connectPort = if (useProxy) effectiveConfig.proxyPort else effectiveConfig.sshPort

        if (connectHost.isBlank()) {
            throw IOException("El host SSH no puede estar vacío")
        }

        val rawSocket = Socket(Proxy.NO_PROXY)
        try {
            rawSocket.tcpNoDelay = true
            rawSocket.keepAlive = true
            socketProtector(rawSocket)

            onLog(
                if (hideServer) "Conectando TCP al servidor protegido..." else "Conectando TCP a $connectHost:$connectPort...",
                LogLevel.INFO
            )
            rawSocket.connect(InetSocketAddress(connectHost, connectPort), CONNECT_TIMEOUT_MS)
            onLog(
                if (hideServer) "Socket TCP conectado (servidor protegido)" else "Socket TCP conectado ($connectHost:$connectPort)",
                LogLevel.INFO
            )

            var activeSocket: Socket = rawSocket

            if (effectiveConfig.useTls) {
                val sni = effectiveConfig.sniHost.ifBlank { effectiveConfig.sshHost }.trim()
                onLog(
                    if (hideServer) "Iniciando SSL/TLS (SNI protegido)..." else "Iniciando SSL/TLS (SNI: ${sni.ifBlank { "ninguno" }})...",
                    LogLevel.INFO
                )
                val sslFactory = createTrustAllSslSocketFactory()
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
                onLog("TLS activo (${sslSocket.session.protocol})", LogLevel.SUCCESS)
                activeSocket = sslSocket
            }

            val rawPayload = effectiveConfig.payload.trim()
            if (rawPayload.isBlank()) {
                onLog("Conectando SSH directo...", LogLevel.INFO)
                activeSocket.soTimeout = 0
                return activeSocket
            }

            val expandedWithSplits = expandPayloadTags(rawPayload, effectiveConfig, rotIdx)
            val expectedRequests = countHttpRequests(expandedWithSplits)
            val sentHostHeader = extractHostHeader(expandedWithSplits)

            sendPayloadWithSplits(activeSocket.getOutputStream(), expandedWithSplits, hidePayload, onLog)

            val wrapped = awaitTunnelReady(
                socket = activeSocket,
                expectedRequests = expectedRequests,
                sentHostHeader = sentHostHeader,
                hidePayload = hidePayload,
                onLog = onLog
            )

            wrapped.soTimeout = 0
            return wrapped
        } catch (t: Throwable) {
            try {
                rawSocket.close()
            } catch (_: Exception) {
            }
            throw if (t is IOException) t else IOException(t.message ?: "Error al inyectar payload", t)
        }
    }

    fun expandPayloadTags(template: String, config: VpnConfig, rotIdx: Int = 0): String {
        val sshHost = config.sshHost.trim()
        val hostPort = "$sshHost:${config.sshPort}"
        val sniHost = config.sniHost.ifBlank { sshHost }.trim()
        val proxyHost = config.proxyHost.trim()
        val proxyAddr = if (proxyHost.isNotBlank()) "$proxyHost:${config.proxyPort}" else hostPort

        var normalized = template
            .replace("\r\n", "\n")
            .trimEnd('\r', '\n', ' ', '\t')

        normalized = Pattern.compile(
            "(\\[(?:crlf(?:\\*\\d+)?|lfcr|cr|lf)\\])\\n",
            Pattern.CASE_INSENSITIVE
        ).matcher(normalized).replaceAll("$1")

        normalized = replaceRotateTags(normalized, rotIdx)
        normalized = replaceRandomTags(normalized)
        normalized = replaceCrlfMultipliers(normalized)

        normalized = replaceCaseInsensitive(normalized, "[crlf]", "\r\n")
        normalized = replaceCaseInsensitive(normalized, "[lfcr]", "\n\r")
        normalized = replaceCaseInsensitive(normalized, "[cr]", "\r")
        normalized = replaceCaseInsensitive(normalized, "[lf]", "\n")

        normalized = replaceCaseInsensitive(normalized, "[host_port]", hostPort)
        normalized = replaceCaseInsensitive(normalized, "[ssh]", hostPort)
        normalized = replaceCaseInsensitive(normalized, "[ssh_host]", sshHost)
        normalized = replaceCaseInsensitive(normalized, "[host]", sshHost)
        normalized = replaceCaseInsensitive(normalized, "[ssh_port]", config.sshPort.toString())
        normalized = replaceCaseInsensitive(normalized, "[port]", config.sshPort.toString())
        normalized = replaceCaseInsensitive(normalized, "[sni]", sniHost)
        normalized = replaceCaseInsensitive(normalized, "[bug]", sniHost)
        normalized = replaceCaseInsensitive(normalized, "[proxy]", proxyAddr)
        normalized = replaceCaseInsensitive(normalized, "[proxy_host]", proxyHost.ifBlank { sshHost })
        normalized = replaceCaseInsensitive(
            normalized,
            "[proxy_port]",
            if (proxyHost.isNotBlank()) config.proxyPort.toString() else config.sshPort.toString()
        )
        normalized = replaceCaseInsensitive(normalized, "[method]", "CONNECT")
        normalized = replaceCaseInsensitive(normalized, "[protocol]", "HTTP/1.1")
        normalized = replaceCaseInsensitive(normalized, "[ua]", DEFAULT_USER_AGENT)
        normalized = replaceCaseInsensitive(normalized, "[netdata]", "CONNECT $hostPort HTTP/1.1")
        normalized = replaceCaseInsensitive(normalized, "[real_raw]", "CONNECT $hostPort HTTP/1.1\r\n")
        normalized = replaceCaseInsensitive(normalized, "[raw]", "CONNECT $hostPort HTTP/1.1\r\n")
        normalized = replaceCaseInsensitive(normalized, "[auth]", "")
        normalized = replaceWsKeys(normalized)

        val sb = StringBuilder(normalized.length + 16)
        for (i in normalized.indices) {
            val ch = normalized[i]
            if (ch == '\n' && (i == 0 || normalized[i - 1] != '\r')) {
                sb.append("\r\n")
            } else {
                sb.append(ch)
            }
        }
        var result = sb.toString()

        val withoutSplits = SPLIT_PATTERN.matcher(result).replaceAll("")
        if (withoutSplits.isNotBlank() && !result.endsWith("\r\n\r\n")) {
            result += if (result.endsWith("\r\n")) "\r\n" else "\r\n\r\n"
        }
        return result
    }

    private fun sendPayloadWithSplits(
        out: OutputStream,
        expanded: String,
        hidePayload: Boolean,
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
                tag.contains("instant") || tag.contains("nodelay") -> 0L
                else -> 40L
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

        if (hidePayload) {
            onLog("Payload protegido enviado", LogLevel.INFO)
        } else {
            val cleanPreview = SPLIT_PATTERN.matcher(expanded).replaceAll("")
            val firstLine = cleanPreview.lineSequence().firstOrNull()?.take(90) ?: "Payload enviado"
            val sentHost = extractHostHeader(expanded)
            val hostInfo = if (sentHost.isNotBlank()) " (Host: $sentHost)" else ""
            onLog("Payload enviado: $firstLine$hostInfo", LogLevel.INFO)
        }
    }

    private fun awaitTunnelReady(
        socket: Socket,
        expectedRequests: Int,
        sentHostHeader: String,
        hidePayload: Boolean,
        onLog: (String, LogLevel) -> Unit
    ): Socket {
        val rawIn = socket.getInputStream()
        socket.soTimeout = RESPONSE_TIMEOUT_MS

        var responsesRead = 0
        while (responsesRead < 5) {
            val peek = ByteArray(5)
            val peekLen = try {
                rawIn.read(peek)
            } catch (_: SocketTimeoutException) {
                if (responsesRead == 0) {
                    onLog("Iniciando negociación SSH...", LogLevel.INFO)
                    return socket
                }
                throw IOException("Tiempo de espera agotado tras respuesta HTTP #$responsesRead")
            }

            if (peekLen <= 0) {
                throw IOException("El servidor cerró la conexión tras enviar el payload")
            }

            val prefix = String(peek, 0, peekLen, Charsets.ISO_8859_1)
            if (prefix.startsWith("SSH-")) {
                onLog("Banner SSH recibido correctamente", LogLevel.INFO)
                return wrapWithPrefix(socket, peek.copyOf(peekLen), rawIn)
            }

            if (!prefix.startsWith("HTTP/", ignoreCase = true)) {
                onLog("Flujo directo detectado, iniciando SSH...", LogLevel.INFO)
                return wrapWithPrefix(socket, peek.copyOf(peekLen), rawIn)
            }

            val firstLineRest = readLineCrlf(rawIn) ?: throw IOException("Cabecera HTTP incompleta")
            val statusLine = (prefix + firstLineRest).trim()
            val statusCode = statusLine.split(Regex("\\s+")).getOrNull(1)?.toIntOrNull() ?: 0

            val headers = mutableMapOf<String, String>()
            while (true) {
                val hLine = readLineCrlf(rawIn) ?: break
                if (hLine.isEmpty()) break
                val colon = hLine.indexOf(':')
                if (colon > 0) {
                    val key = hLine.substring(0, colon).trim().lowercase()
                    val value = hLine.substring(colon + 1).trim()
                    headers[key] = value
                }
            }

            responsesRead++
            val contentLength = headers["content-length"]?.toLongOrNull() ?: -1L
            val isChunked = headers["transfer-encoding"]?.contains("chunked", ignoreCase = true) == true
            val connectionClose = headers["connection"]?.contains("close", ignoreCase = true) == true

            if (statusCode == 101) {
                onLog("Respuesta Payload: $statusLine", LogLevel.SUCCESS)
                return socket
            }

            if (statusCode == 200) {
                if (responsesRead < expectedRequests && (contentLength > 0 || isChunked)) {
                    drainHttpBody(rawIn, contentLength, isChunked)
                    onLog("Respuesta intermedia #$responsesRead ($statusLine) drenada; esperando túnel...", LogLevel.INFO)
                    continue
                }
                onLog("Respuesta Payload: $statusLine", LogLevel.SUCCESS)
                return socket
            }

            onLog("Respuesta HTTP #$responsesRead: $statusLine", LogLevel.WARN)

            if (contentLength > 0 || isChunked) {
                drainHttpBody(rawIn, contentLength, isChunked)
            }

            if (!connectionClose && responsesRead < expectedRequests) {
                onLog("Esperando respuesta #${responsesRead + 1}...", LogLevel.INFO)
                continue
            }

            if (!connectionClose) {
                val prevTimeout = socket.soTimeout
                socket.soTimeout = 600
                try {
                    val probe = ByteArray(5)
                    val n = rawIn.read(probe)
                    if (n > 0) {
                        val nextPrefix = String(probe, 0, n, Charsets.ISO_8859_1)
                        if (nextPrefix.startsWith("SSH-")) {
                            onLog("Túnel SSH detectado tras respuesta HTTP", LogLevel.SUCCESS)
                            return wrapWithPrefix(socket, probe.copyOf(n), rawIn)
                        }
                        if (nextPrefix.startsWith("HTTP/", ignoreCase = true)) {
                            return awaitRemainingAfterPrefix(
                                socket, probe.copyOf(n), rawIn, expectedRequests, sentHostHeader, hidePayload, onLog, responsesRead
                            )
                        }
                    }
                } catch (_: SocketTimeoutException) {
                } finally {
                    try {
                        socket.soTimeout = prevTimeout
                    } catch (_: Exception) {
                    }
                }
            }

            if (statusCode == 530 && !hidePayload) {
                val hostHint = if (sentHostHeader.isNotBlank()) " (Host enviado: '$sentHostHeader')" else ""
                throw IOException("El servidor rechazó el payload con '$statusLine'$hostHint")
            }
            throw IOException("El servidor/proxy rechazó el payload: $statusLine")
        }

        throw IOException("Demasiadas respuestas HTTP sin establecer el túnel (101/200)")
    }

    private fun awaitRemainingAfterPrefix(
        socket: Socket,
        initialPrefix: ByteArray,
        rawIn: InputStream,
        expectedRequests: Int,
        sentHostHeader: String,
        hidePayload: Boolean,
        onLog: (String, LogLevel) -> Unit,
        alreadyRead: Int
    ): Socket {
        val combined = SequenceInputStream(ByteArrayInputStream(initialPrefix), rawIn)
        val wrapped = wrapWithStream(socket, combined)
        return awaitTunnelReady(wrapped, (expectedRequests - alreadyRead).coerceAtLeast(1), sentHostHeader, hidePayload, onLog)
    }

    private fun readLineCrlf(input: InputStream): String? {
        val buf = ByteArrayOutputStream(128)
        while (true) {
            val b = input.read()
            if (b == -1) {
                return if (buf.size() == 0) null else buf.toString(Charsets.ISO_8859_1.name())
            }
            if (b == '\n'.code) {
                val bytes = buf.toByteArray()
                val len = if (bytes.isNotEmpty() && bytes[bytes.size - 1] == '\r'.code.toByte()) {
                    bytes.size - 1
                } else {
                    bytes.size
                }
                return String(bytes, 0, len, Charsets.ISO_8859_1)
            }
            if (buf.size() < 16_384) {
                buf.write(b)
            }
        }
    }

    private fun drainHttpBody(input: InputStream, contentLength: Long, isChunked: Boolean) {
        if (isChunked) {
            while (true) {
                val sizeLine = readLineCrlf(input) ?: return
                val hexPart = sizeLine.substringBefore(';').trim()
                val chunkSize = hexPart.toIntOrNull(16) ?: return
                if (chunkSize == 0) {
                    while (true) {
                        val trailer = readLineCrlf(input) ?: break
                        if (trailer.isEmpty()) break
                    }
                    return
                }
                skipExact(input, chunkSize.toLong())
                readLineCrlf(input)
            }
        } else if (contentLength > 0) {
            skipExact(input, contentLength)
        }
    }

    private fun skipExact(input: InputStream, count: Long) {
        var remaining = count
        val trash = ByteArray(4096)
        while (remaining > 0) {
            val toRead = minOf(remaining, trash.size.toLong()).toInt()
            val n = input.read(trash, 0, toRead)
            if (n <= 0) throw EOFException("Fin inesperado al leer cuerpo HTTP")
            remaining -= n
        }
    }

    private fun countHttpRequests(expandedWithSplits: String): Int {
        val clean = SPLIT_PATTERN.matcher(expandedWithSplits).replaceAll("")
        val blocks = clean.split("\r\n\r\n")
            .map { it.trim() }
            .filter {
                it.isNotEmpty() && (
                    it.contains("HTTP/", ignoreCase = true) ||
                        it.startsWith("GET ") || it.startsWith("POST ") ||
                        it.startsWith("HEAD ") || it.startsWith("CONNECT ") ||
                        it.startsWith("PUT ") || it.startsWith("PATCH ")
                    )
            }
        return blocks.size.coerceAtLeast(1)
    }

    private fun extractHostHeader(expandedPayload: String): String {
        val clean = SPLIT_PATTERN.matcher(expandedPayload).replaceAll("")
        for (line in clean.split("\r\n")) {
            if (line.startsWith("Host:", ignoreCase = true)) {
                return line.substringAfter(':').trim()
            }
        }
        return ""
    }

    private fun pickRotatedValue(raw: String, rotIdx: Int): String {
        val trimmed = raw.trim()
        if (!trimmed.contains(";")) return trimmed
        val parts = trimmed.split(";").map { it.trim() }.filter { it.isNotEmpty() }
        if (parts.isEmpty()) return trimmed
        return parts[Math.floorMod(rotIdx, parts.size)]
    }

    private fun replaceRotateTags(input: String, rotIdx: Int): String {
        val matcher = ROTATE_PATTERN.matcher(input)
        val sb = StringBuffer()
        while (matcher.find()) {
            val choices = matcher.group(1).orEmpty().split(";").map { it.trim() }.filter { it.isNotEmpty() }
            val chosen = if (choices.isNotEmpty()) choices[Math.floorMod(rotIdx, choices.size)] else ""
            matcher.appendReplacement(sb, Matcher.quoteReplacement(chosen))
        }
        matcher.appendTail(sb)
        return sb.toString()
    }

    private fun replaceRandomTags(input: String): String {
        val matcher = RANDOM_PATTERN.matcher(input)
        val sb = StringBuffer()
        while (matcher.find()) {
            val choices = matcher.group(1).orEmpty().split(";").map { it.trim() }.filter { it.isNotEmpty() }
            val chosen = if (choices.isNotEmpty()) choices[Random.nextInt(choices.size)] else ""
            matcher.appendReplacement(sb, Matcher.quoteReplacement(chosen))
        }
        matcher.appendTail(sb)
        return sb.toString()
    }

    private fun replaceCrlfMultipliers(input: String): String {
        val matcher = CRLF_MULT_PATTERN.matcher(input)
        val sb = StringBuffer()
        while (matcher.find()) {
            val count = (matcher.group(1)?.toIntOrNull() ?: 1).coerceIn(1, 10)
            matcher.appendReplacement(sb, Matcher.quoteReplacement("\r\n".repeat(count)))
        }
        matcher.appendTail(sb)
        return sb.toString()
    }

    private fun replaceWsKeys(input: String): String {
        val p = Pattern.compile(Pattern.quote("[ws_key]"), Pattern.CASE_INSENSITIVE)
        val m = p.matcher(input)
        val sb = StringBuffer()
        while (m.find()) {
            val keyBytes = ByteArray(16)
            SecureRandom().nextBytes(keyBytes)
            val key = Base64.encodeToString(keyBytes, Base64.NO_WRAP)
            m.appendReplacement(sb, Matcher.quoteReplacement(key))
        }
        m.appendTail(sb)
        return sb.toString()
    }

    private fun replaceCaseInsensitive(input: String, target: String, replacement: String): String {
        return Pattern.compile(Pattern.quote(target), Pattern.CASE_INSENSITIVE)
            .matcher(input)
            .replaceAll(Matcher.quoteReplacement(replacement))
    }

    private fun isIpLiteral(host: String): Boolean {
        val ipv4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
        return ipv4.matches(host) || host.contains(":")
    }

    @SuppressLint("CustomX509TrustManager", "TrustAllX509TrustManager")
    private fun createTrustAllSslSocketFactory(): SSLSocketFactory {
        val trustAll = arrayOf<TrustManager>(
            object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
        )
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, trustAll, SecureRandom())
        return ctx.socketFactory
    }

    private fun wrapWithPrefix(delegate: Socket, prefix: ByteArray, rawIn: InputStream): Socket {
        val combined = SequenceInputStream(ByteArrayInputStream(prefix), rawIn)
        return wrapWithStream(delegate, combined)
    }

    private fun wrapWithStream(delegate: Socket, customIn: InputStream): Socket {
        return WrappedInputSocket(delegate, customIn)
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
