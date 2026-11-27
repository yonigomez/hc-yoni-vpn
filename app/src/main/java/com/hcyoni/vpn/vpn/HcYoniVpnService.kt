package com.hcyoni.vpn.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.hcyoni.vpn.R
import com.hcyoni.vpn.data.ConfigStore
import com.hcyoni.vpn.data.VpnStateBus
import com.hcyoni.vpn.model.LogLevel
import com.hcyoni.vpn.model.TrafficStats
import com.hcyoni.vpn.model.VpnConfig
import com.hcyoni.vpn.model.VpnState
import com.hcyoni.vpn.ssh.LocalSocks5Server
import com.hcyoni.vpn.ssh.SshTunnelManager
import com.hcyoni.vpn.ssh.WifiShareProxyServer
import com.hcyoni.vpn.util.SecurityAndDeviceHelper
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File
import java.io.IOException
import java.net.Socket
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

class HcYoniVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val sshManager = SshTunnelManager()

    private var socksServer: LocalSocks5Server? = null
    private var wifiShareServer: WifiShareProxyServer? = null
    private var tunInterface: ParcelFileDescriptor? = null
    private var tun2socksProcess: Process? = null
    private var tunLocalServer: LocalServerSocket? = null
    private var tunBindSocket: LocalSocket? = null
    private var fdServerJob: Job? = null

    private var engineJob: Job? = null
    private var statsJob: Job? = null

    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null

    @Volatile
    private var shouldRun = false

    @Volatile
    private var underlyingNetwork: Network? = null
    private var networkCallbackRegistered = false

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            underlyingNetwork = network
            try {
                setUnderlyingNetworks(arrayOf(network))
            } catch (_: Exception) {
            }
        }

        override fun onLost(network: Network) {
            if (underlyingNetwork == network) {
                underlyingNetwork = null
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
        registerNetworkTracking()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ensureNotificationChannel()
        startForegroundCompat(buildNotification("Preparando túnel SSH..."))

        if (intent?.action == ACTION_DISCONNECT) {
            stopVpnCompletely(userInitiated = true)
            return START_NOT_STICKY
        }

        if (intent?.action == ACTION_REFRESH_WIFI_SHARE) {
            if (!shouldRun) {
                stopForegroundAndSelf()
                return START_NOT_STICKY
            }
            val cfg = ConfigStore.loadConfig(this)
            serviceScope.launch { applyWifiShareState(cfg) }
            return START_STICKY
        }

        val config = ConfigStore.loadConfig(this)
        val validationError = validateSecurityConstraints(config)
        if (validationError != null) {
            VpnStateBus.log("Seguridad", validationError, LogLevel.ERROR)
            VpnStateBus.updateState(VpnState.ERROR, validationError)
            stopVpnCompletely(userInitiated = true)
            return START_NOT_STICKY
        }

        if (!shouldRun || engineJob?.isActive != true) {
            shouldRun = true
            ConfigStore.setLastConnected(this, true)
            acquireLocks()
            startEngine(config)
        }
        return START_STICKY
    }

    override fun onRevoke() {
        VpnStateBus.log("VPN", "Permiso VPN revocado por el sistema o usuario", LogLevel.WARN)
        stopVpnCompletely(userInitiated = true)
        super.onRevoke()
    }

    override fun onDestroy() {
        shouldRun = false
        unregisterNetworkTracking()
        teardownPipeline()
        releaseLocks()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun visibleServerLabel(config: VpnConfig): String {
        return if (config.lockServerAndProxy) {
            config.profileName.ifBlank { "Servidor protegido" }
        } else {
            "${config.sshHost}:${config.sshPort}"
        }
    }

    private fun validateSecurityConstraints(config: VpnConfig): String? {
        if (config.sshHost.isBlank()) {
            return "Configura tu servidor SSH primero"
        }
        if (config.expiryDateMillis > 0L && System.currentTimeMillis() > config.expiryDateMillis) {
            val fmt = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.getDefault())
            return "Configuración expirada el ${fmt.format(Date(config.expiryDateMillis))}"
        }
        if (config.blockRoot && SecurityAndDeviceHelper.isDeviceRooted()) {
            return "Conexión bloqueada: dispositivo con Root detectado"
        }
        if (config.lockedHwid.isNotBlank()) {
            val myHwid = SecurityAndDeviceHelper.getDeviceHwid(this)
            if (!config.lockedHwid.equals(myHwid, ignoreCase = true)) {
                return "Archivo restringido a otro dispositivo (HWID no coincide)"
            }
        }
        if (config.mobileDataOnly && !SecurityAndDeviceHelper.isUsingMobileData(this)) {
            return "Este servidor solo permite Datos Móviles (apaga el Wi-Fi)"
        }
        return null
    }

    private fun startEngine(initialConfig: VpnConfig) {
        engineJob?.cancel()
        engineJob = serviceScope.launch {
            var attempt = 0
            while (isActive && shouldRun) {
                val cfg = ConfigStore.loadConfig(this@HcYoniVpnService).takeIf { it.sshHost.isNotBlank() }
                    ?: initialConfig

                val secError = validateSecurityConstraints(cfg)
                if (secError != null) {
                    VpnStateBus.log("Seguridad", secError, LogLevel.ERROR)
                    VpnStateBus.updateState(VpnState.ERROR, secError)
                    stopVpnCompletely(userInitiated = true)
                    break
                }

                attempt++
                val serverLabel = visibleServerLabel(cfg)
                val stateLabel = if (attempt == 1) VpnState.CONNECTING else VpnState.RECONNECTING
                val statusText = if (attempt == 1) {
                    "Conectando a $serverLabel..."
                } else {
                    "Reconectando túnel (intento #$attempt)..."
                }
                VpnStateBus.updateState(stateLabel, statusText)
                updateNotification(statusText)

                try {
                    runSingleSession(cfg)
                    if (!shouldRun || !cfg.autoReconnect) break
                    VpnStateBus.log("VPN", "Conexión interrumpida; reintentando en 3s...", LogLevel.WARN)
                    delay(3_000)
                } catch (ce: CancellationException) {
                    throw ce
                } catch (t: Throwable) {
                    teardownPipeline()
                    val errMsg = t.message ?: "Error de conexión"
                    VpnStateBus.log("VPN", errMsg, LogLevel.ERROR)

                    if (!shouldRun || !cfg.autoReconnect) {
                        VpnStateBus.updateState(VpnState.ERROR, errMsg)
                        stopForegroundAndSelf()
                        break
                    }
                    VpnStateBus.updateState(VpnState.RECONNECTING, "Reintentando: $errMsg")
                    updateNotification("Reconectando en 3.5s...")
                    delay(3_500)
                }
            }
        }
    }

    private suspend fun runSingleSession(config: VpnConfig) {
        teardownPipeline()

        val protector: (Socket) -> Unit = { socket ->
            protect(socket)
            try {
                socket.tcpNoDelay = true
                socket.trafficClass = 0x10
                socket.sendBufferSize = 65_536
                socket.receiveBufferSize = 131_584
            } catch (_: Exception) {
            }
            try {
                underlyingNetwork?.bindSocket(socket)
            } catch (_: Exception) {
            }
        }

        val myHwid = SecurityAndDeviceHelper.getDeviceHwid(this)
        sshManager.connect(config, myHwid, protector)

        val socks = LocalSocks5Server(
            sessionProvider = { sshManager.session },
            dnsPrimary = config.dnsServer,
            dnsSecondary = config.secondaryDns,
            enableIpv6 = config.enableIpv6,
            udpgwEnabled = config.udpgwEnabled,
            udpgwPort = config.udpgwPort,
            hideServerDetails = config.lockServerAndProxy,
            onLog = { msg, level -> VpnStateBus.log("SOCKS5", msg, level) }
        )
        val socksPort = socks.start()
        socksServer = socks
        VpnStateBus.log(
            "SOCKS5",
            "Proxy local activo (Juegos UDPGW: ${if (config.udpgwEnabled) config.udpgwPort else "Desactivado"})",
            LogLevel.INFO
        )

        applyWifiShareState(config)

        val tun = establishTunInterface(config)
        tunInterface = tun

        val proc = launchBadVpnTun2Socks(socksPort, tun, config)
        delay(400)
        if (!proc.isAlive) {
            throw IllegalStateException("El motor nativo badvpn-tun2socks se detuvo al iniciar")
        }

        val connectedAt = System.currentTimeMillis()
        val label = visibleServerLabel(config)
        VpnStateBus.updateState(VpnState.CONNECTED, "Conectado • $label")
        VpnStateBus.log("VPN", "Motor badvpn-tun2socks activo — Navegación y Juegos listos", LogLevel.SUCCESS)
        updateNotification("Conectado (0h 00m) • $label")

        startStatsLoop(socks, connectedAt)

        while (shouldRun && sshManager.isConnected() && proc.isAlive) {
            delay(1_500)
        }

        if (shouldRun) {
            val sshAlive = sshManager.isConnected()
            val tunAlive = proc.isAlive
            VpnStateBus.log("VPN", "Sesión finalizada (SSH=$sshAlive, TUN=$tunAlive)", LogLevel.WARN)
        }

        statsJob?.cancel()
        teardownPipeline()
    }

    private fun launchBadVpnTun2Socks(
        socksPort: Int,
        tun: ParcelFileDescriptor,
        config: VpnConfig
    ): Process {
        val bin = File(applicationInfo.nativeLibraryDir, "libtun2socks.so")
        if (!bin.exists()) {
            throw IllegalStateException("Falta el binario nativo libtun2socks.so en el APK")
        }

        val sockFile = File(filesDir, "tun_sock")
        try {
            if (sockFile.exists()) sockFile.delete()
        } catch (_: Exception) {
        }
        val sockPath = sockFile.absolutePath

        val bindSock = LocalSocket()
        bindSock.bind(LocalSocketAddress(sockPath, LocalSocketAddress.Namespace.FILESYSTEM))
        val localServer = LocalServerSocket(bindSock.fileDescriptor)
        tunBindSocket = bindSock
        tunLocalServer = localServer

        fdServerJob?.cancel()
        fdServerJob = serviceScope.launch {
            try {
                while (isActive && shouldRun && tunLocalServer == localServer) {
                    val client = localServer.accept()
                    try {
                        client.setFileDescriptorsForSend(arrayOf(tun.fileDescriptor))
                        client.outputStream.write(0)
                        client.outputStream.flush()
                    } finally {
                        try {
                            client.close()
                        } catch (_: Exception) {
                        }
                    }
                }
            } catch (_: IOException) {
            }
        }

        val cmd = mutableListOf(
            bin.absolutePath,
            "--netif-ipaddr", "198.18.0.2",
            "--netif-netmask", "255.255.255.0",
            "--socks-server-addr", "127.0.0.1:$socksPort",
            "--tunmtu", "1500",
            "--sock-path", sockPath,
            "--loglevel", "2"
        )
        if (config.enableIpv6) {
            cmd.addAll(listOf("--netif-ip6addr", "fc00::2"))
        }
        if (config.udpgwEnabled) {
            cmd.addAll(
                listOf(
                    "--udpgw-remote-server-addr", "127.0.0.1:${config.udpgwPort}",
                    "--udpgw-transparent-dns"
                )
            )
        } else {
            cmd.add("--enable-udprelay")
        }

        val process = ProcessBuilder(cmd)
            .directory(filesDir)
            .redirectErrorStream(true)
            .start()
        tun2socksProcess = process

        serviceScope.launch {
            try {
                process.inputStream.bufferedReader().forEachLine { line ->
                    val t = line.trim()
                    if (t.isNotEmpty() && (t.contains("ERROR", ignoreCase = true) || t.contains("exit", ignoreCase = true))) {
                        VpnStateBus.log("TUN2SOCKS", t.take(160), LogLevel.WARN)
                    }
                }
            } catch (_: Exception) {
            }
        }
        return process
    }

    private fun applyWifiShareState(config: VpnConfig) {
        try {
            wifiShareServer?.stop()
        } catch (_: Exception) {
        }
        wifiShareServer = null

        val socks = socksServer ?: return
        if (!sshManager.isConnected()) return

        if (!config.wifiShareEnabled) return
        if (!config.allowWifiShare) {
            VpnStateBus.log("Pasar Wi-Fi", "Deshabilitado: el creador del servidor bloqueó compartir Wi-Fi", LogLevel.WARN)
            return
        }

        try {
            val share = WifiShareProxyServer(
                sessionProvider = { sshManager.session },
                listenPort = config.wifiSharePort,
                onBytesTx = { socks.txBytes.addAndGet(it) },
                onBytesRx = { socks.rxBytes.addAndGet(it) }
            )
            val boundPort = share.start()
            wifiShareServer = share
            val lanIp = WifiShareProxyServer.detectHotspotIpAddress()
            VpnStateBus.log("Pasar Wi-Fi", "Proxy Wi-Fi activo en $lanIp:$boundPort", LogLevel.SUCCESS)
        } catch (e: Exception) {
            VpnStateBus.log("Pasar Wi-Fi", "No se pudo abrir proxy Wi-Fi: ${e.message}", LogLevel.WARN)
        }
    }

    private fun establishTunInterface(config: VpnConfig): ParcelFileDescriptor {
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(1500)
            .addAddress("198.18.0.1", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(config.dnsServer.ifBlank { "8.8.8.8" })

        if (config.secondaryDns.isNotBlank()) {
            builder.addDnsServer(config.secondaryDns)
        }

        if (config.enableIpv6) {
            builder.addAddress("fc00::1", 64)
            builder.addRoute("::", 0)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        underlyingNetwork?.let { net ->
            try {
                builder.setUnderlyingNetworks(arrayOf(net))
            } catch (_: Exception) {
            }
        }

        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
        }

        for (pkg in config.excludedApps) {
            if (pkg != packageName) {
                try {
                    builder.addDisallowedApplication(pkg)
                } catch (_: Exception) {
                }
            }
        }

        return builder.establish()
            ?: throw IllegalStateException("Android denegó la creación de la interfaz TUN")
    }

    private fun startStatsLoop(socks: LocalSocks5Server, connectedSinceMs: Long) {
        statsJob?.cancel()
        statsJob = serviceScope.launch {
            var lastTx = 0L
            var lastRx = 0L
            while (isActive && shouldRun) {
                val tx = socks.txBytes.get()
                val rx = socks.rxBytes.get()
                val txRate = (tx - lastTx).coerceAtLeast(0L)
                val rxRate = (rx - lastRx).coerceAtLeast(0L)
                lastTx = tx
                lastRx = rx

                VpnStateBus.updateStats(
                    TrafficStats(
                        txBytes = tx,
                        rxBytes = rx,
                        txRateBps = txRate,
                        rxRateBps = rxRate,
                        connectedSinceMs = connectedSinceMs
                    )
                )

                val elapsedSec = ((System.currentTimeMillis() - connectedSinceMs) / 1000L).coerceAtLeast(0L)
                val hrs = elapsedSec / 3600L
                val mins = (elapsedSec % 3600L) / 60L
                updateNotification(
                    String.format(
                        Locale.US,
                        "Conectado (%dh %02dm) • ↓ %s  ↑ %s",
                        hrs,
                        mins,
                        formatRate(rxRate),
                        formatRate(txRate)
                    )
                )
                delay(1_000)
            }
        }
    }

    private fun stopVpnCompletely(userInitiated: Boolean) {
        shouldRun = false
        if (userInitiated) {
            ConfigStore.setLastConnected(this, false)
        }
        engineJob?.cancel()
        statsJob?.cancel()
        teardownPipeline()
        releaseLocks()
        VpnStateBus.resetStats()
        VpnStateBus.updateState(VpnState.DISCONNECTED, "Desconectado")
        VpnStateBus.log("VPN", "Túnel desconectado correctamente", LogLevel.INFO)
        stopForegroundAndSelf()
    }

    private fun stopForegroundAndSelf() {
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun teardownPipeline() {
        try {
            wifiShareServer?.stop()
        } catch (_: Exception) {
        }
        wifiShareServer = null

        fdServerJob?.cancel()
        fdServerJob = null

        try {
            tun2socksProcess?.destroy()
            tun2socksProcess?.waitFor(300, TimeUnit.MILLISECONDS)
            tun2socksProcess?.destroyForcibly()
        } catch (_: Exception) {
        }
        tun2socksProcess = null

        try {
            tunLocalServer?.close()
        } catch (_: Exception) {
        }
        tunLocalServer = null

        try {
            tunBindSocket?.close()
        } catch (_: Exception) {
        }
        tunBindSocket = null

        try {
            tunInterface?.close()
        } catch (_: Exception) {
        }
        tunInterface = null

        try {
            socksServer?.stop()
        } catch (_: Exception) {
        }
        socksServer = null

        sshManager.disconnect()
    }

    private fun registerNetworkTracking() {
        if (networkCallbackRegistered) return
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        underlyingNetwork = cm.allNetworks.firstOrNull { net ->
            val caps = cm.getNetworkCapabilities(net)
            caps != null &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        }
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        try {
            cm.registerNetworkCallback(request, networkCallback)
            networkCallbackRegistered = true
        } catch (_: Exception) {
        }
    }

    private fun unregisterNetworkTracking() {
        if (!networkCallbackRegistered) return
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        try {
            cm.unregisterNetworkCallback(networkCallback)
        } catch (_: Exception) {
        }
        networkCallbackRegistered = false
    }

    private fun acquireLocks() {
        try {
            if (wakeLock == null) {
                val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "HCYoni::TunnelWakeLock")
                    .apply { setReferenceCounted(false) }
            }
            if (wakeLock?.isHeld == false) {
                wakeLock?.acquire()
            }
        } catch (_: Exception) {
        }

        try {
            if (wifiLock == null) {
                val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
                val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                } else {
                    @Suppress("DEPRECATION")
                    WifiManager.WIFI_MODE_FULL_HIGH_PERF
                }
                wifiLock = wm.createWifiLock(mode, "HCYoni::WifiLock")
                    .apply { setReferenceCounted(false) }
            }
            if (wifiLock?.isHeld == false) {
                wifiLock?.acquire()
            }
        } catch (_: Exception) {
        }
    }

    private fun releaseLocks() {
        try {
            if (wakeLock?.isHeld == true) wakeLock?.release()
        } catch (_: Exception) {
        }
        try {
            if (wifiLock?.isHeld == true) wifiLock?.release()
        } catch (_: Exception) {
        }
    }

    private fun ensureNotificationChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.vpn_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.vpn_channel_desc)
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }

    private fun startForegroundCompat(notification: Notification) {
        val fgsType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, fgsType)
    }

    private fun updateNotification(contentText: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, buildNotification(contentText))
    }

    private fun buildNotification(contentText: String): Notification {
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)?.apply {
            addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        val contentPi = PendingIntent.getActivity(
            this,
            0,
            launchIntent ?: Intent(),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val disconnectIntent = Intent(this, HcYoniVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val disconnectPi = PendingIntent.getService(
            this,
            1,
            disconnectIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_notification)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(contentText)
            .setContentIntent(contentPi)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .addAction(0, getString(R.string.notif_disconnect), disconnectPi)
            .build()
    }

    private fun formatRate(bps: Long): String {
        return when {
            bps < 1024 -> "$bps B/s"
            bps < 1024 * 1024 -> String.format(Locale.US, "%.1f KB/s", bps / 1024.0)
            else -> String.format(Locale.US, "%.2f MB/s", bps / (1024.0 * 1024.0))
        }
    }

    companion object {
        const val ACTION_CONNECT = "com.hcyoni.vpn.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "com.hcyoni.vpn.ACTION_DISCONNECT"
        const val ACTION_REFRESH_WIFI_SHARE = "com.hcyoni.vpn.ACTION_REFRESH_WIFI_SHARE"
        private const val CHANNEL_ID = "hc_yoni_vpn_channel"
        private const val NOTIFICATION_ID = 1001
    }
}
