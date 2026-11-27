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

    private var pendingExportConfig: VpnConfig? = null
    private var pendingExportPassword: String = ""

    private val vpnPermLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        if (res.resultCode == RESULT_OK) startVpnService()
        else toast("Debes aceptar el permiso VPN para conectar")
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
            toast("No se pudo leer el archivo: ${e.message}")
            return@registerForActivityResult
        }
        if (SecurityAndDeviceHelper.requiresPassword(raw)) {
            SaveAndDialogsHelper.showImportPasswordPrompt(this) { pass ->
                finishImportWithContent(raw, pass)
            }
        } else {
            finishImportWithContent(raw, "")
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
            toast("Archivo .yoni encriptado guardado")
        } catch (e: Exception) {
            toast("Error al exportar: ${e.message}")
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
        setupInsets()
        setupTabs()
        setupPayloadChips()
        setupHostAutoSplit()
        setupButtons()

        applyConfigToUi(ConfigStore.loadConfig(this))
        observeState()
    }

    override fun onResume() {
        super.onResume()
        refreshBatteryStatus()
    }

    private fun setupInsets() {
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

    private fun setupTabs() {
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

    private fun setupPayloadChips() {
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

    private fun setupHostAutoSplit() {
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
                    toast("Cuenta SSH separada automáticamente")
                }
            }
        })
    }

    private fun setupButtons() {
        binding.tvDrawerHwid.text = myHwid
        binding.btnCopyHwidInline.text = "Mi HWID: $myHwid (Copiar)"

        binding.btnOpenDrawer.setOnClickListener { binding.drawerLayout.openDrawer(GravityCompat.START) }
        binding.btnBatteryShield.setOnClickListener { showBatteryDialog() }
        binding.btnBackgroundProtection.setOnClickListener { showBatteryDialog() }
        binding.btnImportConfig.setOnClickListener { importLauncher.launch(arrayOf("*/*")) }
        binding.btnExportConfig.setOnClickListener { launchEncryptedSave() }
        binding.btnClearConfig.setOnClickListener { confirmClearConfig() }

        binding.btnCopyHwidInline.setOnClickListener { copyText("HWID hc Yoni", myHwid, "HWID copiado: $myHwid") }
        binding.btnDrawerCopyHwid.setOnClickListener { copyText("HWID hc Yoni", myHwid, "HWID copiado: $myHwid") }

        binding.btnDrawerSaveEncrypted.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            launchEncryptedSave()
        }
        binding.btnDrawerImport.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            importLauncher.launch(arrayOf("*/*"))
        }
        binding.btnDrawerBattery.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            showBatteryDialog()
        }
        binding.btnDrawerClearConfig.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            confirmClearConfig()
        }
        binding.btnDrawerUsageNotice.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            SaveAndDialogsHelper.showUsageCreditsDialog(this, myHwid) {
                copyText("WhatsApp Soporte", "3873063499", "Número 3873063499 copiado")
            }
        }
        binding.btnDrawerContact.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            openWhatsAppContact()
        }
        binding.btnDrawerGameDnsSettings.setOnClickListener {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            val current = readConfigFromUi()
            SaveAndDialogsHelper.showGameAndDnsDialog(this, current) { udpOn, udpPort, dnsOn, d1, d2 ->
                val updated = current.copy(
                    udpgwEnabled = udpOn,
                    udpgwPort = udpPort,
                    useCustomDns = dnsOn,
                    dnsServer = d1,
                    secondaryDns = d2
                )
                ConfigStore.saveConfig(this, updated)
                applyConfigToUi(updated)
                toast("Ajustes de Juegos ($udpPort) y DNS guardados")
            }
        }

        binding.btnDismissBanner.setOnClickListener {
            bannerDismissed = true
            binding.cardBanner.visibility = View.GONE
        }

        binding.switchUseTls.setOnCheckedChangeListener { _, checked ->
            binding.tilSniHost.visibility = if (checked) View.VISIBLE else View.GONE
        }

        binding.btnExcludedApps.setOnClickListener {
            SaveAndDialogsHelper.showExcludedAppsPicker(this, activeConfig.excludedApps) { updatedSet ->
                activeConfig = activeConfig.copy(excludedApps = updatedSet)
                val cfg = readConfigFromUi()
                ConfigStore.saveConfig(this, cfg)
                binding.btnExcludedApps.text = "Aplicaciones excluidas (${updatedSet.size})"
            }
        }

        binding.btnConnectToggle.setOnClickListener {
            val st = VpnStateBus.state.value
            if (st == VpnState.CONNECTED || st == VpnState.CONNECTING || st == VpnState.RECONNECTING) {
                startService(Intent(this, HcYoniVpnService::class.java).apply { action = HcYoniVpnService.ACTION_DISCONNECT })
            } else {
                connectWithChecks()
            }
        }

        binding.btnClearPayload.setOnClickListener {
            if (!activeConfig.lockPayload) binding.etPayload.setText("")
        }
        binding.btnSaveConfig.setOnClickListener {
            val cfg = readConfigFromUi()
            ConfigStore.saveConfig(this, cfg)
            applyConfigToUi(cfg)
            toast("Configuración guardada")
        }
        binding.btnCopyLogs.setOnClickListener {
            copyText("hc Yoni Logs", binding.tvLogs.text?.toString().orEmpty(), "Registro copiado")
        }
        binding.btnClearLogs.setOnClickListener { VpnStateBus.clearLogs() }
    }

    private fun launchEncryptedSave() {
        val current = readConfigFromUi()
        ConfigStore.saveConfig(this, current)
        SaveAndDialogsHelper.showEncryptedSaveDialog(this, current, myHwid) { filename, secured, pass ->
            pendingExportConfig = secured
            pendingExportPassword = pass
            exportLauncher.launch(filename)
        }
    }

    private fun finishImportWithContent(raw: String, pass: String) {
        try {
            val imported = SecurityAndDeviceHelper.decryptYoniConfig(raw, pass)
            bannerDismissed = false
            VpnStateBus.setServerBanner(null)
            ConfigStore.saveConfig(this, imported)
            applyConfigToUi(imported)
            VpnStateBus.log("Config", "Archivo '${imported.profileName}' importado correctamente", LogLevel.SUCCESS)
            toast("Configuración importada")
        } catch (e: Exception) {
            toast("No se pudo abrir el archivo: ${e.message}")
        }
    }

    private fun confirmClearConfig() {
        MaterialAlertDialogBuilder(this)
            .setTitle("Borrar configuración actual")
            .setMessage("¿Deseas borrar el servidor, payload y candados actuales para empezar de cero?")
            .setPositiveButton("Sí, borrar") { _, _ ->
                val st = VpnStateBus.state.value
                if (st != VpnState.DISCONNECTED) {
                    startService(Intent(this, HcYoniVpnService::class.java).apply { action = HcYoniVpnService.ACTION_DISCONNECT })
                }
                bannerDismissed = false
                VpnStateBus.setServerBanner(null)
                val clean = VpnConfig()
                ConfigStore.saveConfig(this, clean)
                applyConfigToUi(clean)
                toast("Configuración borrada")
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    private fun connectWithChecks() {
        val cfg = readConfigFromUi()
        if (cfg.sshHost.isBlank()) {
            toast("Ingresa el Host o IP del servidor SSH")
            binding.tabLayout.getTabAt(0)?.select()
            return
        }
        if (cfg.username.isBlank() && !cfg.useHwidWhenEmpty) {
            toast("Ingresa el Usuario SSH o activa el autologin con HWID")
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
        val intent = Intent(this, HcYoniVpnService::class.java).apply { action = HcYoniVpnService.ACTION_CONNECT }
        ContextCompat.startForegroundService(this, intent)
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
        val srvEdit = !config.lockServerAndProxy
        binding.etSshHost.isEnabled = srvEdit
        binding.etSshPort.isEnabled = srvEdit
        binding.etProxyHost.isEnabled = srvEdit
        binding.etProxyPort.isEnabled = srvEdit
        binding.etSniHost.isEnabled = srvEdit
        binding.switchUseTls.isEnabled = srvEdit
        binding.switchUseTls.isChecked = config.useTls
        binding.tilSniHost.visibility = if (config.useTls) View.VISIBLE else View.GONE

        if (config.lockCredentials) {
            binding.etUsername.setText("🔒 Credenciales protegidas")
            binding.etPassword.setText("")
            binding.etPrivateKey.setText("")
        } else {
            binding.etUsername.setText(config.username)
            binding.etPassword.setText(config.password)
            binding.etPrivateKey.setText(config.privateKey)
        }
        val credEdit = !config.lockCredentials
        binding.etUsername.isEnabled = credEdit
        binding.etPassword.isEnabled = credEdit
        binding.etPrivateKey.isEnabled = credEdit
        binding.switchHwidAutoLogin.isEnabled = credEdit
        binding.switchHwidAutoLogin.isChecked = config.useHwidWhenEmpty

        binding.switchUdpgw.isChecked = config.udpgwEnabled
        binding.etUdpgwPort.setText(config.udpgwPort.toString())
        binding.switchCustomDns.isChecked = config.useCustomDns
        binding.etDnsPrimary.setText(config.dnsServer)
        binding.etDnsSecondary.setText(config.secondaryDns)
        binding.etKeepAlive.setText(config.keepAliveIntervalSec.toString())
        binding.switchAutoReconnect.isChecked = config.autoReconnect
        binding.switchAutoStart.isChecked = config.autoStartOnBoot
        binding.switchEnableIpv6.isChecked = config.enableIpv6
        binding.btnExcludedApps.text = "Aplicaciones excluidas (${config.excludedApps.size})"

        if (config.lockPayload) {
            binding.etPayload.setText("🔒 Payload encriptado y bloqueado por el creador")
        } else {
            binding.etPayload.setText(config.payload)
        }
        val payEdit = !config.lockPayload
        binding.etPayload.isEnabled = payEdit
        binding.btnClearPayload.isEnabled = payEdit
        binding.chipPresetWs.isEnabled = payEdit
        binding.chipPresetDirectSplit.isEnabled = payEdit
        binding.chipPresetSslWs.isEnabled = payEdit
        binding.chipPresetProxyConnect.isEnabled = payEdit

        refreshBannerUi(VpnStateBus.serverBanner.value)
    }

    private fun readConfigFromUi(): VpnConfig {
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
            profileName = binding.etProfileName.text?.toString()?.trim().orEmpty().ifBlank { "Servidor hc Yoni" },
            sshHost = cleanHost,
            sshPort = sshPort,
            proxyHost = proxyHost,
            proxyPort = proxyPort,
            useTls = if (srvLocked) activeConfig.useTls else binding.switchUseTls.isChecked,
            sniHost = if (srvLocked) activeConfig.sniHost else binding.etSniHost.text?.toString()?.trim().orEmpty(),
            username = if (credLocked) activeConfig.username else binding.etUsername.text?.toString()?.trim().orEmpty(),
            password = if (credLocked) activeConfig.password else binding.etPassword.text?.toString().orEmpty(),
            privateKey = if (credLocked) activeConfig.privateKey else binding.etPrivateKey.text?.toString().orEmpty(),
            useHwidWhenEmpty = if (credLocked) activeConfig.useHwidWhenEmpty else binding.switchHwidAutoLogin.isChecked,
            payload = if (payLocked) activeConfig.payload else binding.etPayload.text?.toString().orEmpty(),
            udpgwEnabled = binding.switchUdpgw.isChecked,
            udpgwPort = binding.etUdpgwPort.text?.toString()?.toIntOrNull()?.coerceIn(1, 65535) ?: 7300,
            useCustomDns = binding.switchCustomDns.isChecked,
            dnsServer = binding.etDnsPrimary.text?.toString()?.trim().orEmpty().ifBlank { "8.8.8.8" },
            secondaryDns = binding.etDnsSecondary.text?.toString()?.trim().orEmpty().ifBlank { "1.1.1.1" },
            keepAliveIntervalSec = binding.etKeepAlive.text?.toString()?.toIntOrNull()?.coerceIn(5, 120) ?: 25,
            autoReconnect = binding.switchAutoReconnect.isChecked,
            autoStartOnBoot = binding.switchAutoStart.isChecked,
            enableIpv6 = binding.switchEnableIpv6.isChecked
        )
    }

    private fun observeState() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch { VpnStateBus.state.collect { renderState(it, VpnStateBus.statusMessage.value) } }
                launch { VpnStateBus.statusMessage.collect { renderState(VpnStateBus.state.value, it) } }
                launch { VpnStateBus.stats.collect { renderStats(it) } }
                launch { VpnStateBus.logs.collect { renderLogs(it) } }
                launch {
                    VpnStateBus.serverBanner.collect { banner ->
                        if (!banner.isNullOrBlank()) bannerDismissed = false
                        refreshBannerUi(banner)
                    }
                }
            }
        }
    }

    private fun refreshBannerUi(vpsBanner: String?) {
        if (bannerDismissed) {
            binding.cardBanner.visibility = View.GONE
            return
        }
        val note = activeConfig.configNote.trim()
        val vps = if (activeConfig.hideServerBanner) "" else vpsBanner?.trim().orEmpty()

        when {
            note.isNotEmpty() && vps.isNotEmpty() -> {
                binding.tvBannerTitle.text = "📢 AVISO DEL ARCHIVO Y SERVIDOR VPS"
                binding.tvBannerBody.text = "$note\n\n— Servidor VPS —\n$vps"
                binding.cardBanner.visibility = View.VISIBLE
            }
            note.isNotEmpty() -> {
                binding.tvBannerTitle.text = "📢 AVISO DEL ARCHIVO"
                binding.tvBannerBody.text = note
                binding.cardBanner.visibility = View.VISIBLE
            }
            vps.isNotEmpty() -> {
                binding.tvBannerTitle.text = "🖥️ BANNER DEL SERVIDOR VPS"
                binding.tvBannerBody.text = vps
                binding.cardBanner.visibility = View.VISIBLE
            }
            else -> binding.cardBanner.visibility = View.GONE
        }
    }

    private fun renderState(state: VpnState, message: String) {
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
                binding.tvDuration.text = "00:00:00"
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
            }
            VpnState.ERROR -> {
                binding.badgeStatus.text = "ERROR"
                binding.badgeStatus.setTextColor(red)
                binding.btnConnectToggle.text = getString(R.string.btn_connect)
                binding.btnConnectToggle.backgroundTintList = ColorStateList.valueOf(cyan)
            }
        }
    }

    private fun renderStats(stats: TrafficStats) {
        binding.tvDownSpeed.text = "↓ ${formatBytes(stats.rxRateBps)}/s"
        binding.tvUpSpeed.text = "↑ ${formatBytes(stats.txRateBps)}/s"
        binding.tvTotalTraffic.text = "Total: ${formatBytes(stats.rxBytes + stats.txBytes)}"
        if (stats.connectedSinceMs > 0L && VpnStateBus.state.value == VpnState.CONNECTED) {
            val sec = ((System.currentTimeMillis() - stats.connectedSinceMs) / 1000L).coerceAtLeast(0L)
            binding.tvDuration.text = String.format(Locale.US, "%02d:%02d:%02d", sec / 3600, (sec % 3600) / 60, sec % 60)
        }
    }

    private fun renderLogs(entries: List<LogEntry>) {
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

    private fun refreshBatteryStatus() {
        val ok = BatteryAndSystemHelper.isIgnoringBatteryOptimizations(this)
        binding.tvBatteryStatus.text = if (ok) "✅ Sin restricciones de batería activo" else "⚠️ Optimización activa: toca arriba para evitar cierres"
        binding.tvBatteryStatus.setTextColor(ContextCompat.getColor(this, if (ok) R.color.accent_green else R.color.accent_amber))
    }

    private fun showBatteryDialog() {
        MaterialAlertDialogBuilder(this)
            .setTitle("Protección Sin Suspensión")
            .setMessage(BatteryAndSystemHelper.getBackgroundProtectionGuide())
            .setPositiveButton("Sin restricciones") { _, _ -> BatteryAndSystemHelper.requestIgnoreBatteryOptimization(this) }
            .setNeutralButton("VPN siempre activa") { _, _ -> BatteryAndSystemHelper.openVpnSystemSettings(this) }
            .setNegativeButton("Ajustes app") { _, _ -> BatteryAndSystemHelper.openAppBatterySettings(this) }
            .show()
    }

    private fun openWhatsAppContact() {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://wa.me/5493873063499")))
        } catch (_: Exception) {
            copyText("WhatsApp", "3873063499", "Número 3873063499 copiado al portapapeles")
        }
    }

    private fun copyText(label: String, text: String, msg: String) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(label, text))
        toast(msg)
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    private fun formatBytes(bytes: Long): String = when {
        bytes < 1024L -> "$bytes B"
        bytes < 1024L * 1024L -> String.format(Locale.US, "%.1f KB", bytes / 1024.0)
        bytes < 1024L * 1024L * 1024L -> String.format(Locale.US, "%.2f MB", bytes / (1024.0 * 1024.0))
        else -> String.format(Locale.US, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
    }
}
