package com.hcyoni.vpn.ssh

import com.hcyoni.vpn.data.VpnStateBus
import com.hcyoni.vpn.model.LogLevel
import com.hcyoni.vpn.model.VpnConfig
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Logger
import com.jcraft.jsch.Session
import com.jcraft.jsch.SocketFactory
import com.jcraft.jsch.UIKeyboardInteractive
import com.jcraft.jsch.UserInfo
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket

class SshTunnelManager {

    @Volatile
    var session: Session? = null
        private set

    fun connect(
        config: VpnConfig,
        deviceHwid: String,
        socketProtector: (Socket) -> Unit
    ): Session {
        disconnect()
        VpnStateBus.setServerBanner(null)

        JSch.setLogger(object : Logger {
            override fun isEnabled(level: Int): Boolean = level >= Logger.WARN
            override fun log(level: Int, message: String?) {
                if (!message.isNullOrBlank()) {
                    val mapped = if (level >= Logger.ERROR) LogLevel.ERROR else LogLevel.WARN
                    VpnStateBus.log("SSH", message, mapped)
                }
            }
        })

        val usingHwidAuto = config.useHwidWhenEmpty &&
            config.username.isBlank() &&
            config.password.isBlank() &&
            config.privateKey.isBlank()

        val effectiveUsername = if (usingHwidAuto) deviceHwid else config.username.trim()
        val effectivePassword = if (usingHwidAuto) deviceHwid else config.password

        if (effectiveUsername.isBlank()) {
            throw IllegalStateException("Falta el usuario SSH (o activa autologin por HWID)")
        }

        if (usingHwidAuto) {
            VpnStateBus.log(
                "SSH",
                "Usuario y clave vacíos: conectando con identificador HWID '$deviceHwid'",
                LogLevel.INFO
            )
        }

        val jsch = JSch()
        if (config.privateKey.isNotBlank()) {
            val passphrase = config.password.takeIf { it.isNotEmpty() }?.toByteArray(Charsets.UTF_8)
            jsch.addIdentity(
                "hcyoni_key",
                config.privateKey.trim().toByteArray(Charsets.UTF_8),
                null,
                passphrase
            )
        }

        val newSession = jsch.getSession(effectiveUsername, config.sshHost.trim(), config.sshPort)
        if (effectivePassword.isNotEmpty() && config.privateKey.isBlank()) {
            newSession.setPassword(effectivePassword)
        }

        newSession.setConfig("StrictHostKeyChecking", "no")
        newSession.setConfig("Compression", "no")
        newSession.setConfig(
            "PreferredAuthentications",
            if (config.privateKey.isNotBlank()) {
                "publickey,password,keyboard-interactive"
            } else {
                "password,keyboard-interactive,publickey"
            }
        )

        newSession.userInfo = object : UserInfo, UIKeyboardInteractive {
            override fun getPassphrase(): String = effectivePassword
            override fun getPassword(): String = effectivePassword
            override fun promptPassword(message: String?): Boolean = true
            override fun promptPassphrase(message: String?): Boolean = true
            override fun promptYesNo(message: String?): Boolean = true
            override fun showMessage(message: String?) {
                val clean = message?.trim().orEmpty()
                if (clean.isNotEmpty() && !config.hideServerBanner) {
                    VpnStateBus.setServerBanner(clean)
                    VpnStateBus.log("Banner VPS", clean, LogLevel.SUCCESS)
                }
            }

            override fun promptKeyboardInteractive(
                destination: String?,
                name: String?,
                instruction: String?,
                prompt: Array<out String>?,
                echo: BooleanArray?
            ): Array<String> {
                val count = prompt?.size ?: 0
                return Array(count) { effectivePassword }
            }
        }

        newSession.setSocketFactory(object : SocketFactory {
            override fun createSocket(host: String, port: Int): Socket {
                return PayloadInjector.connectAndInject(
                    config = config,
                    socketProtector = socketProtector,
                    onLog = { msg, level -> VpnStateBus.log("Payload", msg, level) }
                )
            }

            override fun getInputStream(socket: Socket): InputStream = socket.getInputStream()
            override fun getOutputStream(socket: Socket): OutputStream = socket.getOutputStream()
        })

        newSession.serverAliveInterval = config.keepAliveIntervalSec * 1000
        newSession.serverAliveCountMax = 3

        VpnStateBus.log(
            "SSH",
            "Autenticando usuario '$effectiveUsername' en ${config.sshHost}:${config.sshPort}...",
            LogLevel.INFO
        )
        newSession.connect(20_000)

        VpnStateBus.log(
            "SSH",
            "Túnel SSH establecido (${newSession.serverVersion})",
            LogLevel.SUCCESS
        )
        session = newSession
        return newSession
    }

    fun isConnected(): Boolean = session?.isConnected == true

    fun disconnect() {
        val current = session
        session = null
        try {
            current?.disconnect()
        } catch (_: Exception) {
        }
    }
}
