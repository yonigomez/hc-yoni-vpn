package com.hcyoni.vpn.ui

import android.annotation.SuppressLint
import android.app.DatePickerDialog
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Color
import android.text.Editable
import android.text.InputType
import android.text.TextUtils
import android.text.TextWatcher
import android.view.View
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.ArrayAdapter
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.materialswitch.MaterialSwitch
import com.hcyoni.vpn.databinding.DialogSaveConfigBinding
import com.hcyoni.vpn.model.VpnConfig
import com.hcyoni.vpn.ssh.WifiShareProxyServer
import com.hcyoni.vpn.util.BatteryAndSystemHelper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

object SaveAndDialogsHelper {

    @SuppressLint("SetJavaScriptEnabled")
    fun configureBannerWebView(webView: WebView, context: Context) {
        webView.setBackgroundColor(Color.TRANSPARENT)
        webView.settings.apply {
            javaScriptEnabled = false
            allowFileAccess = false
            allowContentAccess = false
            loadsImagesAutomatically = false
        }
        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                val uri = request?.url ?: return false
                val scheme = uri.scheme?.lowercase(Locale.US).orEmpty()
                if (scheme == "http" || scheme == "https" || scheme == "whatsapp" || scheme == "tg") {
                    try {
                        val intent = Intent(Intent.ACTION_VIEW, uri).apply {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        context.startActivity(intent)
                    } catch (_: Exception) {
                        Toast.makeText(context, "No se encontró aplicación para abrir el enlace", Toast.LENGTH_SHORT).show()
                    }
                }
                return true
            }
        }
    }

    fun renderHtmlIntoWebView(webView: WebView, rawContent: String) {
        val bodyHtml = if (rawContent.contains("<") && rawContent.contains(">")) {
            rawContent
        } else {
            val escaped = TextUtils.htmlEncode(rawContent).replace("\n", "<br>")
            val linked = escaped.replace(Regex("(https?://[^\\s<]+)"), "<a href=\"$1\">$1</a>")
            "<p align=\"center\">$linked</p>"
        }

        val doc = """
            <!DOCTYPE html>
            <html>
            <head>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
              body {
                margin: 0;
                padding: 8px 6px;
                background: transparent;
                color: #F1F5F9;
                font-family: sans-serif;
                font-size: 13px;
                line-height: 1.45;
                word-wrap: break-word;
              }
              hr {
                border: none;
                border-top: 1px solid #28354E;
                margin: 10px 0;
              }
              a {
                color: #00E5FF;
                text-decoration: none;
              }
            </style>
            </head>
            <body>$bodyHtml</body>
            </html>
        """.trimIndent()

        webView.loadDataWithBaseURL(null, doc, "text/html", "UTF-8", null)
    }

    fun showFullBannerDialog(context: Context, title: String, htmlOrText: String) {
        val wv = WebView(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (context.resources.displayMetrics.heightPixels * 0.60).toInt()
            )
        }
        configureBannerWebView(wv, context)
        renderHtmlIntoWebView(wv, htmlOrText)

        val container = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#0B111E"))
            setPadding(16, 12, 16, 8)
            addView(wv)
        }

        MaterialAlertDialogBuilder(context)
            .setTitle(title)
            .setView(container)
            .setPositiveButton("Cerrar", null)
            .show()
    }

    fun showEncryptedSaveDialog(
        activity: AppCompatActivity,
        baseConfig: VpnConfig,
        myHwid: String,
        onReadyToExport: (filename: String, configToSave: VpnConfig, filePassword: String) -> Unit
    ) {
        if (baseConfig.hasAnyLock()) {
            MaterialAlertDialogBuilder(activity)
                .setTitle("Archivo protegido")
                .setMessage("Esta configuración fue bloqueada por su creador y no se puede re-exportar. Usa el botón Borrar Configuración para crear una nueva desde cero.")
                .setPositiveButton("Entendido", null)
                .show()
            return
        }

        val dlg = DialogSaveConfigBinding.inflate(activity.layoutInflater)
        val defaultName = baseConfig.profileName
            .ifBlank { "hc-yoni-server" }
            .replace(Regex("[^a-zA-Z0-9_-]"), "_")
        dlg.etSaveFilename.setText(defaultName)

        var chosenExpiryMs = 0L
        val dateFmt = SimpleDateFormat("dd/MM/yyyy", Locale.getDefault())

        dlg.cbLockAll.setOnCheckedChangeListener { _, checked ->
            if (checked) dlg.cbLockPayloadOnly.isChecked = false
        }
        dlg.cbLockPayloadOnly.setOnCheckedChangeListener { _, checked ->
            if (checked) dlg.cbLockAll.isChecked = false
        }

        dlg.cbLockHwid.setOnCheckedChangeListener { _, checked ->
            dlg.tilSaveTargetHwid.visibility = if (checked) View.VISIBLE else View.GONE
            if (checked && dlg.etSaveTargetHwid.text.isNullOrBlank()) {
                dlg.etSaveTargetHwid.setText(myHwid)
            }
        }

        dlg.cbLockExpired.setOnCheckedChangeListener { _, checked ->
            dlg.btnPickExpiryDate.visibility = if (checked) View.VISIBLE else View.GONE
            if (!checked) {
                chosenExpiryMs = 0L
                dlg.btnPickExpiryDate.text = "Elegir fecha de vencimiento"
            }
        }

        dlg.btnPickExpiryDate.setOnClickListener {
            val cal = Calendar.getInstance().apply { add(Calendar.DAY_OF_MONTH, 7) }
            DatePickerDialog(
                activity,
                { _, year, month, day ->
                    val picked = Calendar.getInstance().apply {
                        set(year, month, day, 23, 59, 59)
                    }
                    chosenExpiryMs = picked.timeInMillis
                    dlg.btnPickExpiryDate.text = "Expira: ${dateFmt.format(Date(chosenExpiryMs))}"
                },
                cal.get(Calendar.YEAR),
                cal.get(Calendar.MONTH),
                cal.get(Calendar.DAY_OF_MONTH)
            ).apply {
                datePicker.minDate = System.currentTimeMillis()
            }.show()
        }

        dlg.cbUseFilePassword.setOnCheckedChangeListener { _, checked ->
            dlg.tilSaveFilePassword.visibility = if (checked) View.VISIBLE else View.GONE
        }

        dlg.cbShowNote.setOnCheckedChangeListener { _, checked ->
            dlg.tilSaveNote.visibility = if (checked) View.VISIBLE else View.GONE
        }

        MaterialAlertDialogBuilder(activity)
            .setTitle("Guardar Archivo Encriptado (.yoni)")
            .setView(dlg.root)
            .setPositiveButton("Guardar") { _, _ ->
                val rawName = dlg.etSaveFilename.text?.toString()?.trim().orEmpty().ifBlank { "hc-yoni" }
                val cleanName = if (rawName.endsWith(".yoni", ignoreCase = true)) rawName else "$rawName.yoni"

                val lockPayload = dlg.cbLockAll.isChecked || dlg.cbLockPayloadOnly.isChecked
                val lockServer = dlg.cbLockAll.isChecked && !dlg.cbUnlockProxy.isChecked
                val lockCreds = dlg.cbLockAll.isChecked && !dlg.cbUnlockUserPass.isChecked
                val allowWifi = dlg.cbAllowWifiShare.isChecked

                val targetHwid = if (dlg.cbLockHwid.isChecked) {
                    dlg.etSaveTargetHwid.text?.toString()?.trim().orEmpty()
                } else {
                    ""
                }

                val expiry = if (dlg.cbLockExpired.isChecked) {
                    if (chosenExpiryMs > 0L) chosenExpiryMs else (System.currentTimeMillis() + 7L * 86_400_000L)
                } else {
                    0L
                }

                val filePass = if (dlg.cbUseFilePassword.isChecked) {
                    dlg.etSaveFilePassword.text?.toString().orEmpty()
                } else {
                    ""
                }

                val note = if (dlg.cbShowNote.isChecked) {
                    dlg.etSaveNote.text?.toString()?.trim().orEmpty()
                } else {
                    ""
                }

                val secured = baseConfig.copy(
                    allowWifiShare = allowWifi,
                    wifiShareEnabled = if (allowWifi) baseConfig.wifiShareEnabled else false,
                    lockPayload = lockPayload,
                    lockServerAndProxy = lockServer,
                    lockCredentials = lockCreds,
                    mobileDataOnly = dlg.cbMobileDataOnly.isChecked,
                    blockRoot = dlg.cbBlockRoot.isChecked,
                    lockedHwid = targetHwid,
                    expiryDateMillis = expiry,
                    configNote = note,
                    hideServerBanner = dlg.cbHideServerBanner.isChecked
                )
                onReadyToExport(cleanName, secured, filePass)
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    fun showWifiShareDialog(
        context: Context,
        current: VpnConfig,
        onCopyProxyAddr: (String) -> Unit,
        onSave: (enabled: Boolean, port: Int) -> Unit
    ) {
        if (!current.allowWifiShare) {
            MaterialAlertDialogBuilder(context)
                .setTitle("Pasar Wi-Fi (Hotspot)")
                .setMessage("🔒 Esta función fue bloqueada por el creador del servidor al exportar el archivo.")
                .setPositiveButton("Entendido", null)
                .show()
            return
        }

        val lanIp = WifiShareProxyServer.detectHotspotIpAddress()
        val box = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 12)
        }

        val swEnable = MaterialSwitch(context).apply {
            text = "Activar Proxy para Pasar Wi-Fi"
            isChecked = current.wifiShareEnabled
        }
        val etPort = EditText(context).apply {
            hint = "Puerto del proxy (8080)"
            inputType = InputType.TYPE_CLASS_NUMBER
            setText(current.wifiSharePort.toString())
        }
        val tvGuide = TextView(context).apply {
            setPadding(0, 18, 0, 0)
            textSize = 12.5f
            text = """
                IP detectada en tu Zona Wi-Fi: $lanIp
                Puerto: ${current.wifiSharePort}

                Cómo conectar otro celular o PC:
                1. Activa aquí el Proxy y enciende tu Zona Wi-Fi (Hotspot).
                2. En el otro dispositivo, conéctate a tu Wi-Fi y entra en Ajustes de red → Proxy → Manual.
                3. Escribe Servidor: $lanIp y Puerto: ${etPort.text} y guarda.
            """.trimIndent()
        }

        box.addView(swEnable)
        box.addView(etPort)
        box.addView(tvGuide)

        MaterialAlertDialogBuilder(context)
            .setTitle("Pasar Wi-Fi (Sin Root)")
            .setView(box)
            .setPositiveButton("Aplicar") { _, _ ->
                val p = etPort.text?.toString()?.toIntOrNull()?.coerceIn(1024, 65535) ?: 8080
                onSave(swEnable.isChecked, p)
            }
            .setNeutralButton("Copiar IP:Puerto") { _, _ ->
                val p = etPort.text?.toString()?.toIntOrNull()?.coerceIn(1024, 65535) ?: 8080
                onCopyProxyAddr("$lanIp:$p")
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    fun showFullSettingsDialog(
        context: Context,
        current: VpnConfig,
        onApply: (VpnConfig) -> Unit
    ) {
        val scroll = ScrollView(context)
        val box = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 20, 48, 12)
        }

        val swUdpgw = CheckBox(context).apply {
            text = "Modo Juegos / UDP (BadVPN UDPGW)"
            isChecked = current.udpgwEnabled
        }
        val etPort = EditText(context).apply {
            hint = "Puerto UDPGW (por defecto 7300)"
            inputType = InputType.TYPE_CLASS_NUMBER
            setText(current.udpgwPort.toString())
        }
        val swDns = MaterialSwitch(context).apply {
            text = "Usar DNS personalizado (apagado = automático VPS)"
            isChecked = current.useCustomDns
        }
        val etDns1 = EditText(context).apply {
            hint = "DNS 1 (ej: 8.8.8.8)"
            setText(current.dnsServer)
        }
        val etDns2 = EditText(context).apply {
            hint = "DNS 2 (ej: 1.1.1.1)"
            setText(current.secondaryDns)
        }
        val etKeepAlive = EditText(context).apply {
            hint = "Intervalo Ping SSH en segundos (25)"
            inputType = InputType.TYPE_CLASS_NUMBER
            setText(current.keepAliveIntervalSec.toString())
        }
        val swHwidAuto = MaterialSwitch(context).apply {
            text = "Autologin con HWID si usuario y clave están vacíos"
            isChecked = current.useHwidWhenEmpty
            isEnabled = !current.lockCredentials
        }
        val swReconnect = MaterialSwitch(context).apply {
            text = "Reconexión automática ante caídas"
            isChecked = current.autoReconnect
        }
        val swBoot = MaterialSwitch(context).apply {
            text = "Iniciar automáticamente al encender el celular"
            isChecked = current.autoStartOnBoot
        }
        val swIpv6 = MaterialSwitch(context).apply {
            text = "Permitir reenvío IPv6 en el túnel"
            isChecked = current.enableIpv6
        }

        val batteryOk = BatteryAndSystemHelper.isIgnoringBatteryOptimizations(context)
        val btnBattery = MaterialButton(context).apply {
            text = if (batteryOk) "✅ No suspender aplicación (Activo)" else "⚠️ Activar: No suspender aplicación"
            setOnClickListener { showBatteryProtectionDialog(context) }
        }
        val btnAlwaysVpn = MaterialButton(context).apply {
            text = "Configurar VPN siempre activa (Sistema)"
            setOnClickListener { BatteryAndSystemHelper.openVpnSystemSettings(context) }
        }

        listOf(
            swUdpgw, etPort, swDns, etDns1, etDns2, etKeepAlive,
            swHwidAuto, swReconnect, swBoot, swIpv6, btnBattery, btnAlwaysVpn
        ).forEach { box.addView(it) }
        scroll.addView(box)

        MaterialAlertDialogBuilder(context)
            .setTitle("Ajustes de HC YONI")
            .setView(scroll)
            .setPositiveButton("Guardar") { _, _ ->
                val port = etPort.text?.toString()?.toIntOrNull()?.coerceIn(1, 65535) ?: 7300
                val d1 = etDns1.text?.toString()?.trim().orEmpty().ifBlank { "8.8.8.8" }
                val d2 = etDns2.text?.toString()?.trim().orEmpty().ifBlank { "1.1.1.1" }
                val ping = etKeepAlive.text?.toString()?.toIntOrNull()?.coerceIn(5, 120) ?: 25
                onApply(
                    current.copy(
                        udpgwEnabled = swUdpgw.isChecked,
                        udpgwPort = port,
                        useCustomDns = swDns.isChecked,
                        dnsServer = d1,
                        secondaryDns = d2,
                        keepAliveIntervalSec = ping,
                        useHwidWhenEmpty = if (current.lockCredentials) current.useHwidWhenEmpty else swHwidAuto.isChecked,
                        autoReconnect = swReconnect.isChecked,
                        autoStartOnBoot = swBoot.isChecked,
                        enableIpv6 = swIpv6.isChecked
                    )
                )
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    fun showBatteryProtectionDialog(context: Context) {
        MaterialAlertDialogBuilder(context)
            .setTitle("Protección Sin Suspensión")
            .setMessage(BatteryAndSystemHelper.getBackgroundProtectionGuide())
            .setPositiveButton("Sin restricciones") { _, _ -> BatteryAndSystemHelper.requestIgnoreBatteryOptimization(context) }
            .setNeutralButton("VPN siempre activa") { _, _ -> BatteryAndSystemHelper.openVpnSystemSettings(context) }
            .setNegativeButton("Ajustes app") { _, _ -> BatteryAndSystemHelper.openAppBatterySettings(context) }
            .show()
    }

    fun showImportPasswordPrompt(
        context: Context,
        onPasswordEntered: (String) -> Unit
    ) {
        val input = EditText(context).apply {
            hint = "Ingresa la contraseña del archivo"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val box = LinearLayout(context).apply {
            setPadding(48, 24, 48, 8)
            addView(input)
        }
        MaterialAlertDialogBuilder(context)
            .setTitle("Archivo protegido con clave")
            .setView(box)
            .setPositiveButton("Abrir") { _, _ ->
                onPasswordEntered(input.text?.toString().orEmpty())
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    fun showUsageCreditsDialog(context: Context, myHwid: String, onCopyPhone: () -> Unit) {
        val msg = """
            Aplicación: HC YONI VPN
            Creador: Jonathan Gastón Gómez
            WhatsApp / Soporte: +54 9 3873 063499
            
            Tu HWID único:
            $myHwid
            
            Funciones principales:
            • Juegos UDPGW activo por defecto en puerto 7300 (optimizado sin QUIC).
            • Si dejas Usuario y Contraseña vacíos, autentica con tu HWID automáticamente.
            • Pasar Wi-Fi integrado en puerto 8080 (sin Root).
            • Archivos .yoni encriptados AES-256 con soporte de Banners HTML.
            • Para que no se cierre en Samsung o Xiaomi, configura "No Suspender App" desde Ajustes o el Menú.
        """.trimIndent()

        MaterialAlertDialogBuilder(context)
            .setTitle("Avisos de Uso y Créditos")
            .setMessage(msg)
            .setPositiveButton("Cerrar", null)
            .setNeutralButton("Copiar número") { _, _ -> onCopyPhone() }
            .show()
    }

    fun showExcludedAppsPicker(
        activity: AppCompatActivity,
        currentExcluded: Set<String>,
        onSaved: (Set<String>) -> Unit
    ) {
        Toast.makeText(activity, "Cargando aplicaciones...", Toast.LENGTH_SHORT).show()
        activity.lifecycleScope.launch {
            val installed = withContext(Dispatchers.IO) {
                val pm = activity.packageManager
                pm.getInstalledApplications(PackageManager.GET_META_DATA)
                    .asSequence()
                    .filter { it.packageName != activity.packageName }
                    .filter {
                        (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 ||
                            pm.getLaunchIntentForPackage(it.packageName) != null
                    }
                    .map { it.loadLabel(pm).toString() to it.packageName }
                    .sortedBy { it.first.lowercase(Locale.getDefault()) }
                    .toList()
            }
            if (activity.isFinishing || activity.isDestroyed) return@launch

            val selected = currentExcluded.toMutableSet()
            var filtered = installed

            val box = LinearLayout(activity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(40, 20, 40, 10)
            }
            val search = EditText(activity).apply { hint = "Buscar aplicación..." }
            val list = ListView(activity).apply { choiceMode = ListView.CHOICE_MODE_MULTIPLE }

            fun refresh() {
                list.adapter = ArrayAdapter(
                    activity,
                    android.R.layout.simple_list_item_multiple_choice,
                    filtered.map { "${it.first}\n${it.second}" }
                )
                filtered.forEachIndexed { idx, pair ->
                    list.setItemChecked(idx, selected.contains(pair.second))
                }
            }

            list.setOnItemClickListener { _, _, pos, _ ->
                val pkg = filtered[pos].second
                if (list.isItemChecked(pos)) selected.add(pkg) else selected.remove(pkg)
            }

            search.addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: Editable?) {
                    val q = s?.toString()?.trim()?.lowercase(Locale.getDefault()).orEmpty()
                    filtered = if (q.isEmpty()) installed else installed.filter {
                        it.first.lowercase(Locale.getDefault()).contains(q) ||
                            it.second.lowercase(Locale.getDefault()).contains(q)
                    }
                    refresh()
                }
            })

            refresh()
            box.addView(search)
            box.addView(
                list,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    (activity.resources.displayMetrics.heightPixels * 0.45).toInt()
                )
            )

            MaterialAlertDialogBuilder(activity)
                .setTitle("Apps fuera del túnel VPN")
                .setView(box)
                .setPositiveButton("Guardar") { _, _ -> onSaved(selected.toSet()) }
                .setNegativeButton("Cancelar", null)
                .show()
        }
    }
}
