package com.hcyoni.vpn.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
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
import hev.htproxy.TProxyService
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
import java.net.Socket
import java.util.Locale

class HcYoniVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val sshManager = SshTunnelManager()

    private var socksServer: LocalSocks5Server? = null
    private var tunInterface: ParcelFileDescriptor? = null
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

        val config = ConfigStore.loadConfig(this)
        if (config.sshHost.isBlank()) {
            VpnStateBus.log("VPN", "Falta configurar el servidor SSH (Host)", LogLevel.ERROR)
            VpnStateBus.updateState(VpnState.ERROR, "Configura tu servidor SSH primero")
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

    private fun startEngine(initialConfig: VpnConfig) {
        engineJob?.cancel()
        engineJob = serviceScope.launch {
            var attempt = 0
            while (isActive && shouldRun) {
                val cfg = ConfigStore.loadConfig(this@HcYoniVpnService).takeIf { it.sshHost.isNotBlank() }
                    ?: initialConfig
                attempt++

                val stateLabel = if (attempt == 1) VpnState.CONNECTING else VpnState.RECONNECTING
                val statusText = if (attempt == 1) {
                    "Conectando a ${cfg.sshHost}:${cfg.sshPort}..."
                } else {
                    "Reconectando túnel (intento #$attempt)..."
                }
                VpnStateBus.updateState(stateLabel, statusText)
                updateNotification(statusText)

                try {
                    runSingleSession(cfg)
                    if (!shouldRun || !cfg.autoReconnect) break
                    VpnStateBus.log("VPN", "Conexión interrumpida; reintentando en 2.5s...", LogLevel.WARN)
                    delay(2_500)
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
                    updateNotification("Reconectando en 3s...")
                    delay(3_000)
                }
            }
        }
    }

    private suspend fun runSingleSession(config: VpnConfig) {
        teardownPipeline()

        val protector: (Socket) -> Unit = { socket ->
            protect(socket)
            try {
                underlyingNetwork?.bindSocket(socket)
            } catch (_: Exception) {
            }
        }

        // 1. Conectar TCP + Payload + SSH2
        sshManager.connect(config, protector)

        // 2. Iniciar servidor SOCKS5 local conectado al túnel SSH
        val socks = LocalSocks5Server(
            sessionProvider = { sshManager.session },
            dnsPrimary = config.dnsServer,
            dnsSecondary = config.secondaryDns,
            enableIpv6 = config.enableIpv6,
            onLog = { msg, level -> VpnStateBus.log("SOCKS5", msg, level) }
        )
        val socksPort = socks.start()
        socksServer = socks
        VpnStateBus.log("SOCKS5", "Proxy local activo en 127.0.0.1:$socksPort", LogLevel.INFO)

        // 3. Crear interfaz TUN de Android
        val tun = establishTunInterface(config)
        tunInterface = tun

        // 4. Iniciar motor nativo hev-socks5-tunnel (16KB page aligned)
        val yamlFile = writeHevConfigFile(socksPort)
        val started = TProxyService.TProxyStartService(yamlFile.absolutePath, tun.fd)
        if (!started) {
            throw IllegalStateException("No se pudo iniciar el núcleo nativo hev-socks5-tunnel")
        }

        val connectedAt = System.currentTimeMillis()
        VpnStateBus.updateState(
            VpnState.CONNECTED,
            "Conectado • ${config.sshHost}:${config.sshPort}"
        )
        VpnStateBus.log("VPN", "Túnel TUN activo — Todo el tráfico protegido", LogLevel.SUCCESS)
        updateNotification("Conectado • ${config.sshHost}")

        startStatsLoop(socks, connectedAt)

        // 5. Supervisar sesión hasta que caiga o el usuario desconecte
        while (shouldRun && sshManager.isConnected() && TProxyService.TProxyIsRunning()) {
            delay(1_500)
        }

        statsJob?.cancel()
        teardownPipeline()
    }

    private fun establishTunInterface(config: VpnConfig): ParcelFileDescriptor {
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(1500)
            .addAddress("198.18.0.1", 32)
            .addRoute("0.0.0.0", 0)
            .addAddress("fc00::1", 128)
            .addRoute("::", 0)
            .addDnsServer(config.dnsServer.ifBlank { "8.8.8.8" })

        if (config.secondaryDns.isNotBlank()) {
            builder.addDnsServer(config.secondaryDns)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
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

    private fun writeHevConfigFile(socksPort: Int): File {
        val yaml = """
            tunnel:
              mtu: 1500
              ipv4: 198.18.0.1
              ipv6: 'fc00::1'
            socks5:
              port: $socksPort
              address: 127.0.0.1
              udp: 'udp'
            misc:
              task-stack-size: 81920
              connect-timeout: 10000
              tcp-read-write-timeout: 300000
              udp-read-write-timeout: 60000
              log-level: error
        """.trimIndent()
        val file = File(filesDir, "hev-socks5-tunnel.yaml")
        file.writeText(yaml)
        return file
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
                updateNotification("Conectado • ↓ ${formatRate(rxRate)}  ↑ ${formatRate(txRate)}")
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
            if (TProxyService.TProxyIsRunning()) {
                TProxyService.TProxyStopService()
            }
        } catch (_: Throwable) {
        }
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
        underlyingNetwork = cm.activeNetwork
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
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
        private const val CHANNEL_ID = "hc_yoni_vpn_channel"
        private const val NOTIFICATION_ID = 1001
    }
}
