package com.hcyoni.vpn.ui

import android.app.DatePickerDialog
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.View
import android.widget.ArrayAdapter
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.materialswitch.MaterialSwitch
import com.hcyoni.vpn.databinding.DialogSaveConfigBinding
import com.hcyoni.vpn.model.VpnConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

object SaveAndDialogsHelper {

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

    fun showGameAndDnsDialog(
        context: Context,
        current: VpnConfig,
        onApply: (udpgwOn: Boolean, udpgwPort: Int, customDnsOn: Boolean, dns1: String, dns2: String) -> Unit
    ) {
        val box = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 12)
        }

        val swUdpgw = CheckBox(context).apply {
            text = "Activar Juegos / UDP (BadVPN UDPGW)"
            isChecked = current.udpgwEnabled
        }
        val etPort = EditText(context).apply {
            hint = "Puerto UDPGW (por defecto 7300)"
            inputType = InputType.TYPE_CLASS_NUMBER
            setText(current.udpgwPort.toString())
        }
        val swDns = MaterialSwitch(context).apply {
            text = "Usar DNS personalizado (apagado = DNS automático VPS)"
            isChecked = current.useCustomDns
        }
        val etDns1 = EditText(context).apply {
            hint = "DNS Primario (ej: 8.8.8.8)"
            setText(current.dnsServer)
        }
        val etDns2 = EditText(context).apply {
            hint = "DNS Secundario (ej: 1.1.1.1)"
            setText(current.secondaryDns)
        }

        box.addView(swUdpgw)
        box.addView(etPort)
        box.addView(swDns)
        box.addView(etDns1)
        box.addView(etDns2)

        MaterialAlertDialogBuilder(context)
            .setTitle("Ajustes de Juegos (7300) y DNS")
            .setView(box)
            .setPositiveButton("Guardar") { _, _ ->
                val port = etPort.text?.toString()?.toIntOrNull()?.coerceIn(1, 65535) ?: 7300
                val d1 = etDns1.text?.toString()?.trim().orEmpty().ifBlank { "8.8.8.8" }
                val d2 = etDns2.text?.toString()?.trim().orEmpty().ifBlank { "1.1.1.1" }
                onApply(swUdpgw.isChecked, port, swDns.isChecked, d1, d2)
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    fun showUsageCreditsDialog(context: Context, myHwid: String, onCopyPhone: () -> Unit) {
        val msg = """
            Aplicación: hc Yoni VPN
            Creador: Jonathan Gastón Gómez
            WhatsApp / Soporte: +54 9 3873 063499
            
            Tu HWID único:
            $myHwid
            
            Avisos de uso:
            • Modo Juegos activado por defecto en puerto 7300 (BadVPN UDPGW).
            • Si dejas Usuario y Contraseña vacíos, hc Yoni intentará autenticar automáticamente usando tu HWID.
            • Los archivos .yoni se guardan encriptados con AES-256 para abrirse únicamente dentro de hc Yoni.
            • Para evitar cierres en segundo plano en Samsung o Xiaomi, activa "Sin restricciones" en el ícono del escudo verde.
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
