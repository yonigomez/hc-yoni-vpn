package com.hcyoni.vpn.ui

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.text.Editable
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.TextWatcher
import android.text.style.ForegroundColorSpan
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.GravityCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.chip.Chip
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.tabs.TabLayoutMediator
import com.hcyoni.vpn.R
import com.hcyoni.vpn.data.ConfigStore
import com.hcyoni.vpn.data.VpnStateBus
import com.hcyoni.vpn.databinding.ActivityMainBinding
import com.hcyoni.vpn.databinding.PageConnectionBinding
import com.hcyoni.vpn.databinding.PageLogsBinding
import com.hcyoni.vpn.databinding.PagePayloadBinding
import com.hcyoni.vpn.model.LogEntry
import com.hcyoni.vpn.model.LogLevel
import com.hcyoni.vpn.model.TrafficStats
import com.hcyoni.vpn.model.VpnConfig
import com.hcyoni.vpn.model.VpnState
import com.hcyoni.vpn.util.BatteryAndSystemHelper
import com.hcyoni.vpn.util.SecurityAndDeviceHelper
import com.hcyoni.vpn.vpn.HcYoniVpnService
import kotlinx.coroutines.launch
import java.util.Locale

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var connBinding: PageConnectionBinding
    private lateinit var payloadBinding: PagePayloadBinding
    private lateinit var logsBinding: PageLogsBinding

    private var activeConfig: VpnConfig = VpnConfig()
    private var myHwid: String = ""
    private var bannerHidden = false
    private var lastBannerTitle = ""
    private var lastBannerContent = ""

    private var pendingExportConfig: VpnConfig? = null
    private var pendingExportPassword: String = ""

    private val vpnPermLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        if (res.resultCode == RESULT_OK) startVpnService()
        else showMsg("Debes aceptar el permiso VPN para conectar")
    }

    private val notifPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ ->
        prepareAndStartVpn()
    }

    private val importLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@registerForActivityResult
        val raw = try {
            contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }.orEmpty()
        } catch (e: Exception) {
            showMsg("Error al leer el archivo: ${e.message}")
            return@registerForActivityResult
        }
        if (SecurityAndDeviceHelper.requiresPassword(raw)) {
            SaveAndDialogsHelper.showImportPasswordPrompt(this) { pass ->
                processImportedRaw(raw, pass)
            }
        } else {
            processImportedRaw(raw, "")
        }
    }

    private val exportLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        val cfg = pendingExportConfig ?: return@registerForActivityResult
        if (uri == null) return@registerForActivityResult
        try {
            val encrypted = SecurityAndDeviceHelper.encryptYoniConfig(cfg, pendingExportPassword)
            contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { it.write(encrypted) }
            showMsg("Archivo .yoni encriptado guardado")
        } catch (e: Exception) {
            showMsg("Error al exportar: ${e.message}")
        } finally {
            pendingExportConfig = null
            pendingExportPassword = ""
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        binding = ActivityMainBinding.inflate(layoutInflater)
        connBinding = PageConnectionBinding.inflate(layoutInflater)
        payloadBinding = PagePayloadBinding.inflate(layoutInflater)
        logsBinding = PageLogsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        myHwid = SecurityAndDeviceHelper.getDeviceHwid(this)
        SaveAndDialogsHelper.configureBannerWebView(binding.webBannerPreview, this)

        applyInsets()
        initSwipePages()
        initPayloadControls()
        initHostAutoParser()
        initClickEvents()

        applyConfigToUi(ConfigStore.loadConfig(this))
        subscribeVpnFlows()
    }

    override fun onResume() {
        super.onResume()
        val ok = BatteryAndSystemHelper.isIgnoringBatteryOptimizations(this)
        binding.btnDrawerBattery.text = if (ok) "No Suspender App (Activo)" else "No Suspender App (Activar)"
    }

    override fun onDestroy() {
        binding.webBannerPreview.stopLoading()
        super.onDestroy()
    }

    private fun applyInsets() {
        ViewCompat.setOnApplyWindowInsetsListener(binding.rootContainer) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.ime())
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        ViewCompat.setOnApplyWindowInsetsListener(binding.drawerPanel) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(bars.left, bars.top, 0, bars.bottom)
            insets
        }
    }

    private fun initSwipePages() {
        val pages = listOf(connBinding.root, payloadBinding.root, logsBinding.root)
        binding.viewPager.adapter = object : RecyclerView.Adapter<RecyclerView.ViewHolder>() {
            override fun getItemCount(): Int = pages.size
            override fun getItemViewType(position: Int): Int = position
            override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
                val page = pages[viewType]
                (page.parent as? ViewGroup)?.removeView(page)
                page.layoutParams = ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT
                )
                return object : RecyclerView.ViewHolder(page) {}
            }

            override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {}
        }
        binding.viewPager.offscreenPageLimit = 2
        TabLayoutMediator(binding.tabLayout, binding.viewPager) { tab, pos ->
            tab.text = when (pos) {
                0 -> "Conexión"
                1 -> "Payload"
                else -> "Registro"
            }
        }.attach()
    }

    private fun initPayloadControls() {
        val tags = listOf(
            "[crlf]", "[crlf*2]", "[host]", "[ssh_host]", "[host_port]",
            "[sni]", "[port]", "[split]", "[delay_split]", "[instant_split]",
            "[ua]", "[ws_key]", "[rotate=a;b]", "[netdata]", "[protocol]"
        )
        val bg = ContextCompat.getColor(this, R.color.bg_card)
        val stroke = ContextCompat.getColor(this, R.color.stroke_subtle)
        val cyan = ContextCompat.getColor(this, R.color.accent_cyan)

        tags.forEach { tag ->
            val chip = Chip(this).apply {
                text = tag
                isCheckable = false
                setTextColor(cyan)
                chipBackgroundColor = ColorStateList.valueOf(bg)
                chipStrokeColor = ColorStateList.valueOf(stroke)
                chipStrokeWidth = resources.displayMetrics.density
                setOnClickListener {
                    if (activeConfig.lockPayload) return@setOnClickListener
                    val ed = payloadBinding.etPayload.text ?: return@setOnClickListener
                    val s = payloadBinding.etPayload.selectionStart.coerceAtLeast(0)
                    val e = payloadBinding.etPayload.selectionEnd.coerceAtLeast(0)
                    ed.replace(minOf(s, e), maxOf(s, e), tag)
                    payloadBinding.etPayload.requestFocus()
                }
            }
            payloadBinding.chipGroupTags.addView(chip)
        }

        payloadBinding.chipPresetWs.setOnClickListener {
            if (!activeConfig.lockPayload) {
                payloadBinding.etPayload.setText("GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]")
            }
        }
        payloadBinding.chipPresetDirectSplit.setOnClickListener {
            if (!activeConfig.lockPayload) {
                payloadBinding.etPayload.setText("GET / HTTP/1.1[crlf]Host: [sni][crlf][crlf][split]GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]")
            }
        }
        payloadBinding.chipPresetSslWs.setOnClickListener {
            if (!activeConfig.lockPayload) {
                if (!activeConfig.lockServerAndProxy) connBinding.switchUseTls.isChecked = true
                payloadBinding.etPayload.setText("GET wss://[host]/ HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]")
            }
        }
        payloadBinding.chipPresetProxyConnect.setOnClickListener {
            if (!activeConfig.lockPayload) {
                payloadBinding.etPayload.setText("CONNECT [host_port] HTTP/1.1[crlf]Host: [host_port][crlf]Proxy-Connection: Keep-Alive[crlf][crlf]")
            }
        }
    }

    private fun initHostAutoParser() {
        connBinding.etSshHost.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                if (activeConfig.lockServerAndProxy) return
                val raw = s?.toString()?.trim().orEmpty()
                if (!raw.contains("@")) return
                val idx = raw.indexOf('@')
                val left = raw.substring(0, idx).trim()
                val right = raw.substring(idx + 1).trim()
                val hostParts = left.split(":")
                val host = hostParts[0].trim()
                val port = hostParts.getOrNull(1)?.trim()?.toIntOrNull()
                val credParts = right.split(":", limit = 2)
                if (host.isNotBlank()) {
                    connBinding.etSshHost.removeTextChangedListener(this)
                    connBinding.etSshHost.setText(host)
                    connBinding.etSshHost.setSelection(host.length)
                    connBinding.etSshHost.addTextChangedListener(this)
                    if (port != null && port in 1..65535) connBinding.etSshPort.setText(port.toString())
                    if (!activeConfig.lockCredentials) {
                        credParts.getOrNull(0)?.trim()?.takeIf { it.isNotEmpty() }?.let { connBinding.etUsername.setText(it) }
                        credParts.getOrNull(1)?.trim()?.takeIf { it.isNotEmpty() }?.let { connBinding.etPassword.setText(it) }
                    }
                    showMsg("Cuenta SSH separada automáticamente")
                }
            }
        })
    }

    private fun initClickEvents() {
        binding.tvDrawerHwid.text = myHwid
        binding.btnOpenDrawer.setOnClickListener { binding.drawerLayout.openDrawer(GravityCompat.START) }
        binding.btnImportConfig.setOnClickListener { importLauncher.launch(arrayOf("*/*")) }
        binding.btnExportConfig.setOnClickListener { openSaveDialog() }
        binding.btnClearConfig.setOnClickListener { askClearConfig() }

        binding.btnDrawerCopyHwid.setOnClickListener {
            copyClipboard("HWID HC YONI", myHwid, "HWID copiado: $myHwid")
        }
        binding.btnDrawerWifiShare.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            val current = collectConfigFromUi()
            SaveAndDialogsHelper.showWifiShareDialog(
                this,
                current,
                onCopyProxyAddr = { addr -> copyClipboard("Proxy Wi-Fi HC YONI", addr, "Copiado: $addr") },
                onSave = { enabled, port ->
                    val updated = current.copy(wifiShareEnabled = enabled, wifiSharePort = port)
                    ConfigStore.saveConfig(this, updated)
                    applyConfigToUi(updated)
                    if (VpnStateBus.state.value == VpnState.CONNECTED) {
                        startService(
                            Intent(this, HcYoniVpnService::class.java).apply {
                                action = HcYoniVpnService.ACTION_REFRESH_WIFI_SHARE
                            }
                        )
                    }
                    showMsg(if (enabled) "Pasar Wi-Fi activado (puerto $port)" else "Pasar Wi-Fi apagado")
                }
            )
        }
        binding.btnDrawerSettings.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            val current = collectConfigFromUi()
            SaveAndDialogsHelper.showFullSettingsDialog(this, current) { updated ->
                ConfigStore.saveConfig(this, updated)
                applyConfigToUi(updated)
                showMsg("Ajustes guardados")
            }
        }
        binding.btnDrawerExcludedApps.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            SaveAndDialogsHelper.showExcludedAppsPicker(this, activeConfig.excludedApps) { chosen ->
                val updated = collectConfigFromUi().copy(excludedApps = chosen)
                ConfigStore.saveConfig(this, updated)
                applyConfigToUi(updated)
                showMsg("Aplicaciones actualizadas (${chosen.size})")
            }
        }
        binding.btnDrawerSaveEncrypted.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            openSaveDialog()
        }
        binding.btnDrawerImport.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            importLauncher.launch(arrayOf("*/*"))
        }
        binding.btnDrawerBattery.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            SaveAndDialogsHelper.showBatteryProtectionDialog(this)
        }
        binding.btnDrawerUsageNotice.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            SaveAndDialogsHelper.showUsageCreditsDialog(this, myHwid) {
                copyClipboard("WhatsApp", "3873063499", "Número 3873063499 copiado")
            }
        }
        binding.btnDrawerContact.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            launchWhatsApp()
        }
        binding.btnDrawerClearConfig.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            askClearConfig()
        }

        binding.btnExpandBanner.setOnClickListener {
            if (lastBannerContent.isNotBlank()) {
                SaveAndDialogsHelper.showFullBannerDialog(this, lastBannerTitle, lastBannerContent)
            }
        }
        binding.btnHideBanner.setOnClickListener {
            bannerHidden = true
            updateBannerDisplay(VpnStateBus.serverBanner.value)
        }
        binding.btnShowBannerPill.setOnClickListener {
            bannerHidden = false
            updateBannerDisplay(VpnStateBus.serverBanner.value)
        }

        connBinding.switchUseTls.setOnCheckedChangeListener { _, checked ->
            connBinding.tilSniHost.visibility = if (checked) View.VISIBLE else View.GONE
        }

        binding.btnConnectToggle.setOnClickListener {
            val st = VpnStateBus.state.value
            if (st == VpnState.CONNECTED || st == VpnState.CONNECTING || st == VpnState.RECONNECTING) {
                startService(Intent(this, HcYoniVpnService::class.java).apply { action = HcYoniVpnService.ACTION_DISCONNECT })
            } else {
                startConnectionFlow()
            }
        }

        payloadBinding.btnClearPayload.setOnClickListener {
            if (!activeConfig.lockPayload) payloadBinding.etPayload.setText("")
        }
        payloadBinding.btnSaveConfig.setOnClickListener {
            val cfg = collectConfigFromUi()
            ConfigStore.saveConfig(this, cfg)
            applyConfigToUi(cfg)
            showMsg("Configuración guardada")
        }
        logsBinding.btnCopyLogs.setOnClickListener {
            copyClipboard("HC YONI Logs", logsBinding.tvLogs.text?.toString().orEmpty(), "Registro copiado")
        }
        logsBinding.btnClearLogs.setOnClickListener { VpnStateBus.clearLogs() }
    }

    private fun openSaveDialog() {
        val current = collectConfigFromUi()
        ConfigStore.saveConfig(this, current)
        SaveAndDialogsHelper.showEncryptedSaveDialog(this, current, myHwid) { filename, secured, pass ->
            pendingExportConfig = secured
            pendingExportPassword = pass
            exportLauncher.launch(filename)
        }
    }

    private fun processImportedRaw(raw: String, pass: String) {
        try {
            val imported = SecurityAndDeviceHelper.decryptYoniConfig(raw, pass)
            bannerHidden = false
            VpnStateBus.setServerBanner(null)
            ConfigStore.saveConfig(this, imported)
            applyConfigToUi(imported)
            VpnStateBus.log("Config", "Archivo '${imported.profileName}' importado", LogLevel.SUCCESS)
            showMsg("Configuración importada")
        } catch (e: Exception) {
            showMsg("Error al abrir archivo: ${e.message}")
        }
    }

    private fun askClearConfig() {
        MaterialAlertDialogBuilder(this)
            .setTitle("Borrar configuración actual")
            .setMessage("¿Deseas borrar el servidor, payload y candados actuales para empezar de cero?")
            .setPositiveButton("Sí, borrar") { _, _ ->
                if (VpnStateBus.state.value != VpnState.DISCONNECTED) {
                    startService(Intent(this, HcYoniVpnService::class.java).apply { action = HcYoniVpnService.ACTION_DISCONNECT })
                }
                bannerHidden = false
                VpnStateBus.setServerBanner(null)
                val blank = VpnConfig()
                ConfigStore.saveConfig(this, blank)
                applyConfigToUi(blank)
                showMsg("Configuración borrada")
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    private fun startConnectionFlow() {
        val cfg = collectConfigFromUi()
        if (cfg.sshHost.isBlank()) {
            showMsg("Ingresa el Host o IP del servidor SSH")
            binding.viewPager.setCurrentItem(0, true)
            return
        }
        if (cfg.username.isBlank() && !cfg.useHwidWhenEmpty) {
            showMsg("Ingresa el Usuario SSH o activa autologin por HWID en Ajustes")
            binding.viewPager.setCurrentItem(0, true)
            return
        }
        ConfigStore.saveConfig(this, cfg)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            return
        }
        prepareAndStartVpn()
    }

    private fun prepareAndStartVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) vpnPermLauncher.launch(intent) else startVpnService()
    }

    private fun startVpnService() {
        ContextCompat.startForegroundService(
            this,
            Intent(this, HcYoniVpnService::class.java).apply { action = HcYoniVpnService.ACTION_CONNECT }
        )
    }

    private fun applyConfigToUi(config: VpnConfig) {
        activeConfig = config
        binding.tvLockedBadge.visibility = if (config.hasAnyLock()) View.VISIBLE else View.GONE
        connBinding.tvLockNoticeSsh.visibility =
            if (config.lockServerAndProxy || config.lockCredentials) View.VISIBLE else View.GONE
        payloadBinding.tvPayloadLockedBanner.visibility = if (config.lockPayload) View.VISIBLE else View.GONE

        connBinding.etProfileName.setText(config.profileName)

        if (config.lockServerAndProxy) {
            connBinding.etSshHost.setText("🔒 Servidor protegido")
            connBinding.etSshPort.setText("***")
            connBinding.etProxyHost.setText("🔒 Protegido")
            connBinding.etProxyPort.setText("***")
            connBinding.etSniHost.setText("🔒 Protegido")
        } else {
            connBinding.etSshHost.setText(config.sshHost)
            connBinding.etSshPort.setText(config.sshPort.toString())
            connBinding.etProxyHost.setText(config.proxyHost)
            connBinding.etProxyPort.setText(config.proxyPort.toString())
            connBinding.etSniHost.setText(config.sniHost)
        }
        val srvEditable = !config.lockServerAndProxy
        connBinding.etSshHost.isEnabled = srvEditable
        connBinding.etSshPort.isEnabled = srvEditable
        connBinding.etProxyHost.isEnabled = srvEditable
        connBinding.etProxyPort.isEnabled = srvEditable
        connBinding.etSniHost.isEnabled = srvEditable
        connBinding.switchUseTls.isEnabled = srvEditable
        connBinding.switchUseTls.isChecked = config.useTls
        connBinding.tilSniHost.visibility = if (config.useTls) View.VISIBLE else View.GONE

        if (config.lockCredentials) {
            connBinding.etUsername.setText("🔒 Protegido")
            connBinding.etPassword.setText("")
            connBinding.etPrivateKey.setText("")
        } else {
            connBinding.etUsername.setText(config.username)
            connBinding.etPassword.setText(config.password)
            connBinding.etPrivateKey.setText(config.privateKey)
        }
        val credEditable = !config.lockCredentials
        connBinding.etUsername.isEnabled = credEditable
        connBinding.etPassword.isEnabled = credEditable
        connBinding.etPrivateKey.isEnabled = credEditable

        binding.btnDrawerExcludedApps.text = "Aplicaciones excluidas (${config.excludedApps.size})"
        binding.btnDrawerWifiShare.text = when {
            !config.allowWifiShare -> "Pasar Wi-Fi (🔒 Bloqueado)"
            config.wifiShareEnabled -> "Pasar Wi-Fi (Activo :${config.wifiSharePort})"
            else -> "Pasar Wi-Fi (Apagado)"
        }

        if (config.lockPayload) {
            payloadBinding.etPayload.setText("🔒 Payload encriptado y bloqueado por el creador")
        } else {
            payloadBinding.etPayload.setText(config.payload)
        }
        val payEditable = !config.lockPayload
        payloadBinding.etPayload.isEnabled = payEditable
        payloadBinding.btnClearPayload.isEnabled = payEditable
        payloadBinding.chipPresetWs.isEnabled = payEditable
        payloadBinding.chipPresetDirectSplit.isEnabled = payEditable
        payloadBinding.chipPresetSslWs.isEnabled = payEditable
        payloadBinding.chipPresetProxyConnect.isEnabled = payEditable

        updateBannerDisplay(VpnStateBus.serverBanner.value)
    }

    private fun collectConfigFromUi(): VpnConfig {
        val srvLocked = activeConfig.lockServerAndProxy
        val credLocked = activeConfig.lockCredentials
        val payLocked = activeConfig.lockPayload

        val rawHost = if (srvLocked) activeConfig.sshHost else connBinding.etSshHost.text?.toString()?.trim().orEmpty()
        var cleanHost = rawHost
        var portFromHost: Int? = null
        if (!srvLocked && rawHost.contains(":") && !rawHost.contains(";") && rawHost.count { it == ':' } == 1) {
            val parts = rawHost.split(":")
            val p = parts[1].trim().toIntOrNull()
            if (p != null && p in 1..65535) {
                cleanHost = parts[0].trim()
                portFromHost = p
            }
        }

        val sshPort = if (srvLocked) activeConfig.sshPort else (portFromHost ?: connBinding.etSshPort.text?.toString()?.toIntOrNull()?.coerceIn(1, 65535) ?: 22)
        val proxyHost = if (srvLocked) activeConfig.proxyHost else connBinding.etProxyHost.text?.toString()?.trim().orEmpty()
        val proxyPort = if (srvLocked) activeConfig.proxyPort else (connBinding.etProxyPort.text?.toString()?.toIntOrNull()?.coerceIn(1, 65535) ?: 80)

        return activeConfig.copy(
            profileName = connBinding.etProfileName.text?.toString()?.trim().orEmpty().ifBlank { "Servidor HC YONI" },
            sshHost = cleanHost,
            sshPort = sshPort,
            proxyHost = proxyHost,
            proxyPort = proxyPort,
            useTls = if (srvLocked) activeConfig.useTls else connBinding.switchUseTls.isChecked,
            sniHost = if (srvLocked) activeConfig.sniHost else connBinding.etSniHost.text?.toString()?.trim().orEmpty(),
            username = if (credLocked) activeConfig.username else connBinding.etUsername.text?.toString()?.trim().orEmpty(),
            password = if (credLocked) activeConfig.password else connBinding.etPassword.text?.toString().orEmpty(),
            privateKey = if (credLocked) activeConfig.privateKey else connBinding.etPrivateKey.text?.toString().orEmpty(),
            payload = if (payLocked) activeConfig.payload else payloadBinding.etPayload.text?.toString().orEmpty()
        )
    }

    private fun subscribeVpnFlows() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch { VpnStateBus.state.collect { drawState(it, VpnStateBus.statusMessage.value) } }
                launch { VpnStateBus.statusMessage.collect { drawState(VpnStateBus.state.value, it) } }
                launch { VpnStateBus.stats.collect { drawStats(it) } }
                launch { VpnStateBus.logs.collect { drawLogs(it) } }
                launch {
                    VpnStateBus.serverBanner.collect { banner ->
                        if (!banner.isNullOrBlank()) bannerHidden = false
                        updateBannerDisplay(banner)
                    }
                }
            }
        }
    }

    private fun updateBannerDisplay(vpsBanner: String?) {
        val note = activeConfig.configNote.trim()
        val vps = if (activeConfig.hideServerBanner) "" else vpsBanner?.trim().orEmpty()

        val (title, body) = when {
            note.isNotEmpty() && vps.isNotEmpty() -> "📢 AVISO DEL ARCHIVO Y VPS" to "$note<hr>$vps"
            note.isNotEmpty() -> "📢 AVISO DEL ARCHIVO" to note
            vps.isNotEmpty() -> "🖥️ BANNER DE LA VPS" to vps
            else -> "" to ""
        }

        if (body.isEmpty()) {
            lastBannerTitle = ""
            lastBannerContent = ""
            binding.cardBanner.visibility = View.GONE
            binding.btnShowBannerPill.visibility = View.GONE
            return
        }

        lastBannerTitle = title
        lastBannerContent = body

        if (bannerHidden) {
            binding.cardBanner.visibility = View.GONE
            binding.btnShowBannerPill.visibility = View.VISIBLE
            return
        }

        binding.btnShowBannerPill.visibility = View.GONE
        binding.tvBannerTitle.text = title
        SaveAndDialogsHelper.renderHtmlIntoWebView(binding.webBannerPreview, body)
        binding.cardBanner.visibility = View.VISIBLE
    }

    private fun drawState(state: VpnState, message: String) {
        binding.tvConnectionSubtitle.text = message
        val cyan = ContextCompat.getColor(this, R.color.accent_cyan)
        val green = ContextCompat.getColor(this, R.color.accent_green)
        val amber = ContextCompat.getColor(this, R.color.accent_amber)
        val red = ContextCompat.getColor(this, R.color.accent_red)
        val gray = ContextCompat.getColor(this, R.color.text_secondary)

        when (state) {
            VpnState.DISCONNECTED -> {
                binding.badgeStatus.text = getString(R.string.status_disconnected)
                binding.badgeStatus.setTextColor(gray)
                binding.btnConnectToggle.text = getString(R.string.btn_connect)
                binding.btnConnectToggle.backgroundTintList = ColorStateList.valueOf(cyan)
                binding.tvDuration.text = "⏱ 0h 00m 00s"
                binding.tvDuration.setTextColor(gray)
            }
            VpnState.CONNECTING -> {
                binding.badgeStatus.text = getString(R.string.status_connecting)
                binding.badgeStatus.setTextColor(amber)
                binding.btnConnectToggle.text = "CANCELAR"
                binding.btnConnectToggle.backgroundTintList = ColorStateList.valueOf(amber)
            }
            VpnState.RECONNECTING -> {
                binding.badgeStatus.text = "RECONECTANDO"
                binding.badgeStatus.setTextColor(amber)
                binding.btnConnectToggle.text = getString(R.string.btn_disconnect)
                binding.btnConnectToggle.backgroundTintList = ColorStateList.valueOf(amber)
            }
            VpnState.CONNECTED -> {
                binding.badgeStatus.text = getString(R.string.status_connected)
                binding.badgeStatus.setTextColor(green)
                binding.btnConnectToggle.text = getString(R.string.btn_disconnect)
                binding.btnConnectToggle.backgroundTintList = ColorStateList.valueOf(red)
                binding.tvDuration.setTextColor(green)
            }
            VpnState.ERROR -> {
                binding.badgeStatus.text = "ERROR"
                binding.badgeStatus.setTextColor(red)
                binding.btnConnectToggle.text = getString(R.string.btn_connect)
                binding.btnConnectToggle.backgroundTintList = ColorStateList.valueOf(cyan)
                binding.tvDuration.text = "⏱ 0h 00m 00s"
                binding.tvDuration.setTextColor(gray)
            }
        }
    }

    private fun drawStats(stats: TrafficStats) {
        binding.tvDownSpeed.text = "↓ ${formatSize(stats.rxRateBps)}/s"
        binding.tvUpSpeed.text = "↑ ${formatSize(stats.txRateBps)}/s"
        binding.tvTotalTraffic.text = "Total: ${formatSize(stats.rxBytes + stats.txBytes)}"
        if (stats.connectedSinceMs > 0L && VpnStateBus.state.value == VpnState.CONNECTED) {
            val sec = ((System.currentTimeMillis() - stats.connectedSinceMs) / 1000L).coerceAtLeast(0L)
            binding.tvDuration.text = String.format(
                Locale.US,
                "⏱ %dh %02dm %02ds",
                sec / 3600L,
                (sec % 3600L) / 60L,
                sec % 60L
            )
            binding.tvDuration.setTextColor(ContextCompat.getColor(this, R.color.accent_green))
        }
    }

    private fun drawLogs(entries: List<LogEntry>) {
        if (entries.isEmpty()) {
            logsBinding.tvLogs.text = "Sin registros aún. Toca CONECTAR para ver el túnel."
            return
        }
        val green = ContextCompat.getColor(this, R.color.accent_green)
        val amber = ContextCompat.getColor(this, R.color.accent_amber)
        val red = ContextCompat.getColor(this, R.color.accent_red)
        val cyan = ContextCompat.getColor(this, R.color.accent_cyan)
        val light = ContextCompat.getColor(this, R.color.text_primary)

        val sb = SpannableStringBuilder()
        entries.forEachIndexed { idx, e ->
            val start = sb.length
            sb.append("[${e.timestamp}] [${e.tag}] ${e.message}")
            val col = when (e.level) {
                LogLevel.SUCCESS -> green
                LogLevel.WARN -> amber
                LogLevel.ERROR -> red
                LogLevel.INFO -> if (e.tag == "Payload") cyan else light
            }
            sb.setSpan(ForegroundColorSpan(col), start, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            if (idx < entries.lastIndex) sb.append('\n')
        }
        logsBinding.tvLogs.text = sb
        logsBinding.scrollLogs.post { logsBinding.scrollLogs.fullScroll(View.FOCUS_DOWN) }
    }

    private fun launchWhatsApp() {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://wa.me/5493873063499")))
        } catch (_: Exception) {
            copyClipboard("WhatsApp", "3873063499", "Número 3873063499 copiado")
        }
    }

    private fun copyClipboard(label: String, text: String, feedback: String) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(label, text))
        showMsg(feedback)
    }

    private fun showMsg(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    private fun formatSize(bytes: Long): String = when {
        bytes < 1024L -> "$bytes B"
        bytes < 1024L * 1024L -> String.format(Locale.US, "%.1f KB", bytes / 1024.0)
        bytes < 1024L * 1024L * 1024L -> String.format(Locale.US, "%.2f MB", bytes / (1024.0 * 1024.0))
        else -> String.format(Locale.US, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
    }
}
