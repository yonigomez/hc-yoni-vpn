package com.hcyoni.vpn.ui

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.text.Editable
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.TextWatcher
import android.text.style.ForegroundColorSpan
import android.view.View
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
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
import com.hcyoni.vpn.vpn.HcYoniVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Locale

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var currentExcludedApps: Set<String> = emptySet()
    private var pendingExportIncludeSecrets = true

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        } else {
            Toast.makeText(this, "Debes aceptar el permiso VPN para conectar", Toast.LENGTH_LONG).show()
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ ->
        prepareAndStartVpn()
    }

    private val importLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@registerForActivityResult
        try {
            val content = contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
                ?: throw IllegalStateException("No se pudo leer el archivo")
            val imported = VpnConfig.fromJson(content)
            ConfigStore.saveConfig(this, imported)
            applyConfigToUi(imported)
            VpnStateBus.log("Config", "Configuración '${imported.profileName}' importada", LogLevel.SUCCESS)
            Toast.makeText(this, "Configuración importada correctamente", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Archivo .yoni inválido: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private val exportLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        if (uri == null) return@registerForActivityResult
        try {
            val config = readConfigFromUi()
            ConfigStore.saveConfig(this, config)
            val json = config.toJson(includeSecrets = pendingExportIncludeSecrets)
            contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { it.write(json) }
            Toast.makeText(this, "Archivo exportado correctamente", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Error al exportar: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        ViewCompat.setOnApplyWindowInsetsListener(binding.rootContainer) { view, insets ->
            val sysAndIme = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.ime()
            )
            view.setPadding(sysAndIme.left, sysAndIme.top, sysAndIme.right, sysAndIme.bottom)
            insets
        }

        setupTabs()
        setupPayloadTools()
        setupClickListeners()

        val saved = ConfigStore.loadConfig(this)
        applyConfigToUi(saved)
        observeVpnState()
    }

    override fun onResume() {
        super.onResume()
        refreshBatteryStatusLabel()
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

    private fun setupPayloadTools() {
        val tags = listOf(
            "[crlf]",
            "[host]",
            "[host_port]",
            "[sni]",
            "[port]",
            "[split]",
            "[delay_split]",
            "[instant_split]",
            "[ua]",
            "[netdata]",
            "[protocol]"
        )

        val bgColor = ContextCompat.getColor(this, R.color.bg_card)
        val strokeColor = ContextCompat.getColor(this, R.color.stroke_subtle)
        val textColor = ContextCompat.getColor(this, R.color.accent_cyan)

        tags.forEach { tag ->
            val chip = Chip(this).apply {
                text = tag
                isCheckable = false
                setTextColor(textColor)
                chipBackgroundColor = ColorStateList.valueOf(bgColor)
                chipStrokeColor = ColorStateList.valueOf(strokeColor)
                chipStrokeWidth = resources.displayMetrics.density
                setOnClickListener { insertTagAtCursor(tag) }
            }
            binding.chipGroupTags.addView(chip)
        }

        binding.chipPresetWs.setOnClickListener {
            binding.etPayload.setText(
                "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
            )
            Toast.makeText(this, "Plantilla WebSocket cargada", Toast.LENGTH_SHORT).show()
        }

        binding.chipPresetDirectSplit.setOnClickListener {
            binding.etPayload.setText(
                "GET / HTTP/1.1[crlf]Host: [host][crlf][split]User-Agent: [ua][crlf]Connection: Keep-Alive[crlf][crlf]"
            )
            Toast.makeText(this, "Plantilla Directo + Split cargada", Toast.LENGTH_SHORT).show()
        }

        binding.chipPresetSslWs.setOnClickListener {
            binding.switchUseTls.isChecked = true
            binding.etPayload.setText(
                "GET wss://[sni]/ HTTP/1.1[crlf]Host: [sni][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
            )
            Toast.makeText(this, "Plantilla SSL + WebSocket cargada", Toast.LENGTH_SHORT).show()
        }

        binding.chipPresetProxyConnect.setOnClickListener {
            binding.etPayload.setText(
                "CONNECT [host_port] HTTP/1.1[crlf]Host: [host_port][crlf]Proxy-Connection: Keep-Alive[crlf][crlf]"
            )
            Toast.makeText(this, "Plantilla Proxy CONNECT cargada", Toast.LENGTH_SHORT).show()
        }
    }

    private fun setupClickListeners() {
        binding.btnConnectToggle.setOnClickListener {
            val currentState = VpnStateBus.state.value
            if (currentState == VpnState.CONNECTED ||
                currentState == VpnState.CONNECTING ||
                currentState == VpnState.RECONNECTING
            ) {
                disconnectVpnService()
            } else {
                connectWithValidation()
            }
        }

        binding.switchUseTls.setOnCheckedChangeListener { _, isChecked ->
            binding.tilSniHost.visibility = if (isChecked) View.VISIBLE else View.GONE
        }

        binding.btnBatteryShield.setOnClickListener { showBackgroundProtectionDialog() }
        binding.btnBackgroundProtection.setOnClickListener { showBackgroundProtectionDialog() }

        binding.btnExcludedApps.setOnClickListener { showExcludedAppsDialog() }

        binding.btnImportConfig.setOnClickListener {
            importLauncher.launch(arrayOf("*/*"))
        }

        binding.btnExportConfig.setOnClickListener {
            MaterialAlertDialogBuilder(this)
                .setTitle("Exportar configuración .yoni")
                .setMessage("¿Deseas incluir usuario y contraseña en el archivo exportado?")
                .setPositiveButton("Completo (con clave)") { _, _ ->
                    pendingExportIncludeSecrets = true
                    val safeName = binding.etProfileName.text?.toString().orEmpty()
                        .ifBlank { "hc-yoni" }
                        .replace(Regex("[^a-zA-Z0-9_-]"), "_")
                    exportLauncher.launch("$safeName.yoni")
                }
                .setNegativeButton("Sin usuario ni clave") { _, _ ->
                    pendingExportIncludeSecrets = false
                    val safeName = binding.etProfileName.text?.toString().orEmpty()
                        .ifBlank { "hc-yoni" }
                        .replace(Regex("[^a-zA-Z0-9_-]"), "_")
                    exportLauncher.launch("$safeName-public.yoni")
                }
                .setNeutralButton("Cancelar", null)
                .show()
        }

        binding.btnClearPayload.setOnClickListener {
            binding.etPayload.setText("")
        }

        binding.btnSaveConfig.setOnClickListener {
            val cfg = readConfigFromUi()
            ConfigStore.saveConfig(this, cfg)
            Toast.makeText(this, "Configuración guardada", Toast.LENGTH_SHORT).show()
        }

        binding.btnCopyLogs.setOnClickListener {
            val text = binding.tvLogs.text?.toString().orEmpty()
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("hc Yoni Logs", text))
            Toast.makeText(this, "Registros copiados", Toast.LENGTH_SHORT).show()
        }

        binding.btnClearLogs.setOnClickListener {
            VpnStateBus.clearLogs()
        }
    }

    private fun observeVpnState() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    VpnStateBus.state.collect { state ->
                        renderStateUi(state, VpnStateBus.statusMessage.value)
                    }
                }
                launch {
                    VpnStateBus.statusMessage.collect { msg ->
                        renderStateUi(VpnStateBus.state.value, msg)
                    }
                }
                launch {
                    VpnStateBus.stats.collect { stats ->
                        renderStatsUi(stats)
                    }
                }
                launch {
                    VpnStateBus.logs.collect { entries ->
                        renderLogsUi(entries)
                    }
                }
            }
        }
    }

    private fun renderStateUi(state: VpnState, message: String) {
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

    private fun renderStatsUi(stats: TrafficStats) {
        binding.tvDownSpeed.text = "↓ ${formatBytes(stats.rxRateBps)}/s"
        binding.tvUpSpeed.text = "↑ ${formatBytes(stats.txRateBps)}/s"
        binding.tvTotalTraffic.text = "Total: ${formatBytes(stats.rxBytes + stats.txBytes)}"

        if (stats.connectedSinceMs > 0L && VpnStateBus.state.value == VpnState.CONNECTED) {
            val elapsedSec = ((System.currentTimeMillis() - stats.connectedSinceMs) / 1000L).coerceAtLeast(0L)
            val hrs = elapsedSec / 3600L
            val mins = (elapsedSec % 3600L) / 60L
            val secs = elapsedSec % 60L
            binding.tvDuration.text = String.format(Locale.US, "%02d:%02d:%02d", hrs, mins, secs)
        }
    }

    private fun renderLogsUi(entries: List<LogEntry>) {
        if (entries.isEmpty()) {
            binding.tvLogs.text = "Sin registros aún. Toca CONECTAR para ver la negociación SSH y Payload."
            return
        }

        val green = ContextCompat.getColor(this, R.color.accent_green)
        val amber = ContextCompat.getColor(this, R.color.accent_amber)
        val red = ContextCompat.getColor(this, R.color.accent_red)
        val cyan = ContextCompat.getColor(this, R.color.accent_cyan)
        val light = ContextCompat.getColor(this, R.color.text_primary)

        val sb = SpannableStringBuilder()
        entries.forEachIndexed { index, entry ->
            val line = "[${entry.timestamp}] [${entry.tag}] ${entry.message}"
            val start = sb.length
            sb.append(line)
            val color = when (entry.level) {
                LogLevel.SUCCESS -> green
                LogLevel.WARN -> amber
                LogLevel.ERROR -> red
                LogLevel.INFO -> if (entry.tag == "Payload") cyan else light
            }
            sb.setSpan(
                ForegroundColorSpan(color),
                start,
                sb.length,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )
            if (index < entries.lastIndex) {
                sb.append('\n')
            }
        }
        binding.tvLogs.text = sb
        binding.scrollLogs.post {
            binding.scrollLogs.fullScroll(View.FOCUS_DOWN)
        }
    }

    private fun connectWithValidation() {
        val cfg = readConfigFromUi()
        if (cfg.sshHost.isBlank()) {
            Toast.makeText(this, "Ingresa el Host o IP del servidor SSH", Toast.LENGTH_SHORT).show()
            binding.tabLayout.getTabAt(0)?.select()
            binding.etSshHost.requestFocus()
            return
        }
        if (cfg.username.isBlank()) {
            Toast.makeText(this, "Ingresa el Usuario SSH", Toast.LENGTH_SHORT).show()
            binding.tabLayout.getTabAt(0)?.select()
            binding.etUsername.requestFocus()
            return
        }

        ConfigStore.saveConfig(this, cfg)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            return
        }

        prepareAndStartVpn()
    }

    private fun prepareAndStartVpn() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, HcYoniVpnService::class.java).apply {
            action = HcYoniVpnService.ACTION_CONNECT
        }
        ContextCompat.startForegroundService(this, intent)
    }

    private fun disconnectVpnService() {
        val intent = Intent(this, HcYoniVpnService::class.java).apply {
            action = HcYoniVpnService.ACTION_DISCONNECT
        }
        startService(intent)
    }

    private fun applyConfigToUi(config: VpnConfig) {
        binding.etProfileName.setText(config.profileName)
        binding.etSshHost.setText(config.sshHost)
        binding.etSshPort.setText(config.sshPort.toString())
        binding.etUsername.setText(config.username)
        binding.etPassword.setText(config.password)
        binding.etPrivateKey.setText(config.privateKey)
        binding.switchUseTls.isChecked = config.useTls
        binding.tilSniHost.visibility = if (config.useTls) View.VISIBLE else View.GONE
        binding.etSniHost.setText(config.sniHost)
        binding.etProxyHost.setText(config.proxyHost)
        binding.etProxyPort.setText(config.proxyPort.toString())
        binding.etDnsPrimary.setText(config.dnsServer)
        binding.etDnsSecondary.setText(config.secondaryDns)
        binding.etKeepAlive.setText(config.keepAliveIntervalSec.toString())
        binding.switchAutoReconnect.isChecked = config.autoReconnect
        binding.switchAutoStart.isChecked = config.autoStartOnBoot
        binding.switchEnableIpv6.isChecked = config.enableIpv6
        binding.etPayload.setText(config.payload)

        currentExcludedApps = config.excludedApps
        updateExcludedAppsButtonLabel()
    }

    private fun readConfigFromUi(): VpnConfig {
        val sshPort = binding.etSshPort.text?.toString()?.toIntOrNull()?.coerceIn(1, 65535) ?: 22
        val proxyPort = binding.etProxyPort.text?.toString()?.toIntOrNull()?.coerceIn(1, 65535) ?: 80
        val keepAlive = binding.etKeepAlive.text?.toString()?.toIntOrNull()?.coerceIn(5, 120) ?: 25

        return VpnConfig(
            profileName = binding.etProfileName.text?.toString()?.trim().orEmpty()
                .ifBlank { "Servidor hc Yoni" },
            sshHost = binding.etSshHost.text?.toString()?.trim().orEmpty(),
            sshPort = sshPort,
            username = binding.etUsername.text?.toString()?.trim().orEmpty(),
            password = binding.etPassword.text?.toString().orEmpty(),
            privateKey = binding.etPrivateKey.text?.toString().orEmpty(),
            proxyHost = binding.etProxyHost.text?.toString()?.trim().orEmpty(),
            proxyPort = proxyPort,
            payload = binding.etPayload.text?.toString().orEmpty(),
            sniHost = binding.etSniHost.text?.toString()?.trim().orEmpty(),
            useTls = binding.switchUseTls.isChecked,
            dnsServer = binding.etDnsPrimary.text?.toString()?.trim().orEmpty().ifBlank { "8.8.8.8" },
            secondaryDns = binding.etDnsSecondary.text?.toString()?.trim().orEmpty().ifBlank { "1.1.1.1" },
            enableIpv6 = binding.switchEnableIpv6.isChecked,
            autoReconnect = binding.switchAutoReconnect.isChecked,
            autoStartOnBoot = binding.switchAutoStart.isChecked,
            keepAliveIntervalSec = keepAlive,
            excludedApps = currentExcludedApps
        )
    }

    private fun insertTagAtCursor(tag: String) {
        val editable = binding.etPayload.text ?: return
        val start = binding.etPayload.selectionStart.coerceAtLeast(0)
        val end = binding.etPayload.selectionEnd.coerceAtLeast(0)
        editable.replace(minOf(start, end), maxOf(start, end), tag)
        binding.etPayload.requestFocus()
    }

    private fun refreshBatteryStatusLabel() {
        val unrestricted = BatteryAndSystemHelper.isIgnoringBatteryOptimizations(this)
        if (unrestricted) {
            binding.tvBatteryStatus.text = "✅ Sin restricciones de batería activo (protegido contra Doze)"
            binding.tvBatteryStatus.setTextColor(ContextCompat.getColor(this, R.color.accent_green))
        } else {
            binding.tvBatteryStatus.text = "⚠️ Optimización activa: toca arriba para evitar cierre en segundo plano"
            binding.tvBatteryStatus.setTextColor(ContextCompat.getColor(this, R.color.accent_amber))
        }
    }

    private fun showBackgroundProtectionDialog() {
        val unrestricted = BatteryAndSystemHelper.isIgnoringBatteryOptimizations(this)
        val statusLine = if (unrestricted) {
            "Estado actual: ✅ Sin restricciones de batería\n\n"
        } else {
            "Estado actual: ⚠️ Restringido (Android/Samsung podría suspender la VPN)\n\n"
        }
        val guide = statusLine + BatteryAndSystemHelper.getBackgroundProtectionGuide()

        MaterialAlertDialogBuilder(this)
            .setTitle("Protección Anti-Cierre / Sin Suspensión")
            .setMessage(guide)
            .setPositiveButton("Sin restricciones") { _, _ ->
                BatteryAndSystemHelper.requestIgnoreBatteryOptimization(this)
            }
            .setNeutralButton("VPN siempre activa") { _, _ ->
                BatteryAndSystemHelper.openVpnSystemSettings(this)
            }
            .setNegativeButton("Ajustes de app") { _, _ ->
                BatteryAndSystemHelper.openAppBatterySettings(this)
            }
            .show()
    }

    private fun showExcludedAppsDialog() {
        Toast.makeText(this, "Cargando aplicaciones...", Toast.LENGTH_SHORT).show()
        lifecycleScope.launch {
            val installed = withContext(Dispatchers.IO) {
                val pm = packageManager
                val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
                apps.asSequence()
                    .filter { it.packageName != packageName }
                    .filter { (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 || pm.getLaunchIntentForPackage(it.packageName) != null }
                    .map { app ->
                        val label = app.loadLabel(pm).toString()
                        label to app.packageName
                    }
                    .sortedBy { it.first.lowercase(Locale.getDefault()) }
                    .toList()
            }

            if (isFinishing || isDestroyed) return@launch

            val selected = currentExcludedApps.toMutableSet()
            var filtered = installed

            val container = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(40, 20, 40, 10)
            }

            val searchBox = EditText(this@MainActivity).apply {
                hint = "Buscar aplicación..."
            }
            val listView = ListView(this@MainActivity).apply {
                choiceMode = ListView.CHOICE_MODE_MULTIPLE
            }

            fun refreshList() {
                val labels = filtered.map { "${it.first}\n${it.second}" }
                listView.adapter = ArrayAdapter(
                    this@MainActivity,
                    android.R.layout.simple_list_item_multiple_choice,
                    labels
                )
                filtered.forEachIndexed { idx, pair ->
                    listView.setItemChecked(idx, selected.contains(pair.second))
                }
            }

            listView.setOnItemClickListener { _, _, position, _ ->
                val pkg = filtered[position].second
                if (listView.isItemChecked(position)) {
                    selected.add(pkg)
                } else {
                    selected.remove(pkg)
                }
            }

            searchBox.addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: Editable?) {
                    val q = s?.toString()?.trim()?.lowercase(Locale.getDefault()).orEmpty()
                    filtered = if (q.isEmpty()) {
                        installed
                    } else {
                        installed.filter {
                            it.first.lowercase(Locale.getDefault()).contains(q) ||
                                it.second.lowercase(Locale.getDefault()).contains(q)
                        }
                    }
                    refreshList()
                }
            })

            refreshList()
            container.addView(searchBox)
            container.addView(
                listView,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    (resources.displayMetrics.heightPixels * 0.45).toInt()
                )
            )

            MaterialAlertDialogBuilder(this@MainActivity)
                .setTitle("Apps que no pasarán por la VPN")
                .setView(container)
                .setPositiveButton("Guardar") { _, _ ->
                    currentExcludedApps = selected.toSet()
                    updateExcludedAppsButtonLabel()
                    val cfg = readConfigFromUi()
                    ConfigStore.saveConfig(this@MainActivity, cfg)
                }
                .setNegativeButton("Cancelar", null)
                .show()
        }
    }

    private fun updateExcludedAppsButtonLabel() {
        binding.btnExcludedApps.text = "Aplicaciones excluidas (${currentExcludedApps.size})"
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024L -> "$bytes B"
            bytes < 1024L * 1024L -> String.format(Locale.US, "%.1f KB", bytes / 1024.0)
            bytes < 1024L * 1024L * 1024L -> String.format(Locale.US, "%.2f MB", bytes / (1024.0 * 1024.0))
            else -> String.format(Locale.US, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
        }
    }
}
