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
import com.google.android.material.chip.Chip
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.tabs.TabLayout
import com.hcyoni.vpn.R
import com.hcyoni.vpn.data.ConfigStore
import com.hcyoni.vpn.data.VpnStateBus
import com.hcyoni.vpn.databinding.ActivityMainBinding
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
    private var activeConfig: VpnConfig = VpnConfig()
    private var myHwid: String = ""
    private var bannerDismissed = false
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
        setContentView(binding.root)

        myHwid = SecurityAndDeviceHelper.getDeviceHwid(this)
        SaveAndDialogsHelper.configureBannerWebView(binding.webBannerPreview, this)

        applyInsets()
        initTabs()
        initPayloadControls()
        initHostAutoParser()
        initClickEvents()

        applyConfigToUi(ConfigStore.loadConfig(this))
        subscribeVpnFlows()
    }

    override fun onResume() {
        super.onResume()
        val ok = BatteryAndSystemHelper.isIgnoringBatteryOptimizations(this)
        binding.btnDrawerBattery.text = if (ok) "Sin Suspensión (Activo)" else "Sin Suspensión (Activar)"
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

    private fun initTabs() {
        binding.tabLayout.addTab(binding.tabLayout.newTab().setText("Conexión"))
        binding.tabLayout.addTab(binding.tabLayout.newTab().setText("Payload"))
        binding.tabLayout.addTab(binding.tabLayout.newTab().setText("Registro"))
        binding.tabLayout.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) {
                binding.panelConnection.visibility = if (tab.position == 0) View.VISIBLE else View.GONE
                binding.panelPayload.visibility = if (tab.position == 1) View.VISIBLE else View.GONE
                binding.panelLogs.visibility = if (tab.position == 2) View.VISIBLE else View.GONE
            }
            override fun onTabUnselected(tab: TabLayout.Tab) {}
            override fun onTabReselected(tab: TabLayout.Tab) {}
        })
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
                    val ed = binding.etPayload.text ?: return@setOnClickListener
                    val s = binding.etPayload.selectionStart.coerceAtLeast(0)
                    val e = binding.etPayload.selectionEnd.coerceAtLeast(0)
                    ed.replace(minOf(s, e), maxOf(s, e), tag)
                    binding.etPayload.requestFocus()
                }
            }
            binding.chipGroupTags.addView(chip)
        }

        binding.chipPresetWs.setOnClickListener {
            if (!activeConfig.lockPayload) {
                binding.etPayload.setText("GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]")
            }
        }
        binding.chipPresetDirectSplit.setOnClickListener {
            if (!activeConfig.lockPayload) {
                binding.etPayload.setText("GET / HTTP/1.1[crlf]Host: [sni][crlf][crlf][split]GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]")
            }
        }
        binding.chipPresetSslWs.setOnClickListener {
            if (!activeConfig.lockPayload) {
                if (!activeConfig.lockServerAndProxy) binding.switchUseTls.isChecked = true
                binding.etPayload.setText("GET wss://[host]/ HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]")
            }
        }
        binding.chipPresetProxyConnect.setOnClickListener {
            if (!activeConfig.lockPayload) {
                binding.etPayload.setText("CONNECT [host_port] HTTP/1.1[crlf]Host: [host_port][crlf]Proxy-Connection: Keep-Alive[crlf][crlf]")
            }
        }
    }

    private fun initHostAutoParser() {
        binding.etSshHost.addTextChangedListener(object : TextWatcher {
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
                    binding.etSshHost.removeTextChangedListener(this)
                    binding.etSshHost.setText(host)
                    binding.etSshHost.setSelection(host.length)
                    binding.etSshHost.addTextChangedListener(this)
                    if (port != null && port in 1..65535) binding.etSshPort.setText(port.toString())
                    if (!activeConfig.lockCredentials) {
                        credParts.getOrNull(0)?.trim()?.takeIf { it.isNotEmpty() }?.let { binding.etUsername.setText(it) }
                        credParts.getOrNull(1)?.trim()?.takeIf { it.isNotEmpty() }?.let { binding.etPassword.setText(it) }
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
        binding.btnDrawerGameDnsSettings.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            val current = collectConfigFromUi()
            SaveAndDialogsHelper.showGameAndDnsDialog(this, current) { updated ->
                ConfigStore.saveConfig(this, updated)
                applyConfigToUi(updated)
                showMsg("Ajustes guardados (Juegos: ${updated.udpgwPort})")
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
            openBatteryDialog()
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
        binding.btnDismissBanner.setOnClickListener {
            bannerDismissed = true
            binding.cardBanner.visibility = View.GONE
        }

        binding.switchUseTls.setOnCheckedChangeListener { _, checked ->
            binding.tilSniHost.visibility = if (checked) View.VISIBLE else View.GONE
        }

        binding.btnConnectToggle.setOnClickListener {
            val st = VpnStateBus.state.value
            if (st == VpnState.CONNECTED || st == VpnState.CONNECTING || st == VpnState.RECONNECTING) {
                startService(Intent(this, HcYoniVpnService::class.java).apply { action = HcYoniVpnService.ACTION_DISCONNECT })
            } else {
                startConnectionFlow()
            }
        }

        binding.btnClearPayload.setOnClickListener {
            if (!activeConfig.lockPayload) binding.etPayload.setText("")
        }
        binding.btnSaveConfig.setOnClickListener {
            val cfg = collectConfigFromUi()
            ConfigStore.saveConfig(this, cfg)
            applyConfigToUi(cfg)
            showMsg("Configuración guardada")
        }
        binding.btnCopyLogs.setOnClickListener {
            copyClipboard("HC YONI Logs", binding.tvLogs.text?.toString().orEmpty(), "Registro copiado")
        }
        binding.btnClearLogs.setOnClickListener { VpnStateBus.clearLogs() }
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
            bannerDismissed = false
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
                bannerDismissed = false
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
            binding.tabLayout.getTabAt(0)?.select()
            return
        }
        if (cfg.username.isBlank() && !cfg.useHwidWhenEmpty) {
            showMsg("Ingresa el Usuario SSH o activa autologin por HWID en el Menú")
            binding.tabLayout.getTabAt(0)?.select()
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
        binding.tvLockNoticeSsh.visibility =
            if (config.lockServerAndProxy || config.lockCredentials) View.VISIBLE else View.GONE
        binding.tvPayloadLockedBanner.visibility = if (config.lockPayload) View.VISIBLE else View.GONE

        binding.etProfileName.setText(config.profileName)

        if (config.lockServerAndProxy) {
            binding.etSshHost.setText("🔒 Servidor protegido")
            binding.etSshPort.setText("***")
            binding.etProxyHost.setText("🔒 Protegido")
            binding.etProxyPort.setText("***")
            binding.etSniHost.setText("🔒 Protegido")
        } else {
            binding.etSshHost.setText(config.sshHost)
            binding.etSshPort.setText(config.sshPort.toString())
            binding.etProxyHost.setText(config.proxyHost)
            binding.etProxyPort.setText(config.proxyPort.toString())
            binding.etSniHost.setText(config.sniHost)
        }
        val srvEditable = !config.lockServerAndProxy
        binding.etSshHost.isEnabled = srvEditable
        binding.etSshPort.isEnabled = srvEditable
        binding.etProxyHost.isEnabled = srvEditable
        binding.etProxyPort.isEnabled = srvEditable
        binding.etSniHost.isEnabled = srvEditable
        binding.switchUseTls.isEnabled = srvEditable
        binding.switchUseTls.isChecked = config.useTls
        binding.tilSniHost.visibility = if (config.useTls) View.VISIBLE else View.GONE

        if (config.lockCredentials) {
            binding.etUsername.setText("🔒 Protegido")
            binding.etPassword.setText("")
            binding.etPrivateKey.setText("")
        } else {
            binding.etUsername.setText(config.username)
            binding.etPassword.setText(config.password)
            binding.etPrivateKey.setText(config.privateKey)
        }
        val credEditable = !config.lockCredentials
        binding.etUsername.isEnabled = credEditable
        binding.etPassword.isEnabled = credEditable
        binding.etPrivateKey.isEnabled = credEditable

        binding.btnDrawerExcludedApps.text = "Aplicaciones excluidas (${config.excludedApps.size})"

        if (config.lockPayload) {
            binding.etPayload.setText("🔒 Payload encriptado y bloqueado por el creador")
        } else {
            binding.etPayload.setText(config.payload)
        }
        val payEditable = !config.lockPayload
        binding.etPayload.isEnabled = payEditable
        binding.btnClearPayload.isEnabled = payEditable
        binding.chipPresetWs.isEnabled = payEditable
        binding.chipPresetDirectSplit.isEnabled = payEditable
        binding.chipPresetSslWs.isEnabled = payEditable
        binding.chipPresetProxyConnect.isEnabled = payEditable

        updateBannerDisplay(VpnStateBus.serverBanner.value)
    }

    private fun collectConfigFromUi(): VpnConfig {
        val srvLocked = activeConfig.lockServerAndProxy
        val credLocked = activeConfig.lockCredentials
        val payLocked = activeConfig.lockPayload

        val rawHost = if (srvLocked) activeConfig.sshHost else binding.etSshHost.text?.toString()?.trim().orEmpty()
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

        val sshPort = if (srvLocked) activeConfig.sshPort else (portFromHost ?: binding.etSshPort.text?.toString()?.toIntOrNull()?.coerceIn(1, 65535) ?: 22)
        val proxyHost = if (srvLocked) activeConfig.proxyHost else binding.etProxyHost.text?.toString()?.trim().orEmpty()
        val proxyPort = if (srvLocked) activeConfig.proxyPort else (binding.etProxyPort.text?.toString()?.toIntOrNull()?.coerceIn(1, 65535) ?: 80)

        return activeConfig.copy(
            profileName = binding.etProfileName.text?.toString()?.trim().orEmpty().ifBlank { "Servidor HC YONI" },
            sshHost = cleanHost,
            sshPort = sshPort,
            proxyHost = proxyHost,
            proxyPort = proxyPort,
            useTls = if (srvLocked) activeConfig.useTls else binding.switchUseTls.isChecked,
            sniHost = if (srvLocked) activeConfig.sniHost else binding.etSniHost.text?.toString()?.trim().orEmpty(),
            username = if (credLocked) activeConfig.username else binding.etUsername.text?.toString()?.trim().orEmpty(),
            password = if (credLocked) activeConfig.password else binding.etPassword.text?.toString().orEmpty(),
            privateKey = if (credLocked) activeConfig.privateKey else binding.etPrivateKey.text?.toString().orEmpty(),
            payload = if (payLocked) activeConfig.payload else binding.etPayload.text?.toString().orEmpty()
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
                        if (!banner.isNullOrBlank()) bannerDismissed = false
                        updateBannerDisplay(banner)
                    }
                }
            }
        }
    }

    private fun updateBannerDisplay(vpsBanner: String?) {
        if (bannerDismissed) {
            binding.cardBanner.visibility = View.GONE
            return
        }
        val note = activeConfig.configNote.trim()
        val vps = if (activeConfig.hideServerBanner) "" else vpsBanner?.trim().orEmpty()

        val (title, body) = when {
            note.isNotEmpty() && vps.isNotEmpty() -> "📢 AVISO DEL ARCHIVO Y VPS" to "$note<hr>$vps"
            note.isNotEmpty() -> "📢 AVISO DEL ARCHIVO" to note
            vps.isNotEmpty() -> "🖥️ BANNER DEL SERVIDOR" to vps
            else -> "" to ""
        }

        if (body.isEmpty()) {
            lastBannerTitle = ""
            lastBannerContent = ""
            binding.cardBanner.visibility = View.GONE
            return
        }

        lastBannerTitle = title
        lastBannerContent = body
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
            binding.tvLogs.text = "Sin registros aún. Toca CONECTAR para ver el túnel."
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
        binding.tvLogs.text = sb
        binding.scrollLogs.post { binding.scrollLogs.fullScroll(View.FOCUS_DOWN) }
    }

    private fun openBatteryDialog() {
        MaterialAlertDialogBuilder(this)
            .setTitle("Protección Sin Suspensión")
            .setMessage(BatteryAndSystemHelper.getBackgroundProtectionGuide())
            .setPositiveButton("Sin restricciones") { _, _ -> BatteryAndSystemHelper.requestIgnoreBatteryOptimization(this) }
            .setNeutralButton("VPN siempre activa") { _, _ -> BatteryAndSystemHelper.openVpnSystemSettings(this) }
            .setNegativeButton("Ajustes app") { _, _ -> BatteryAndSystemHelper.openAppBatterySettings(this) }
            .show()
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
