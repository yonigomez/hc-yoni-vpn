package com.hcyoni.vpn.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import com.hcyoni.vpn.data.ConfigStore

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != "android.intent.action.QUICKBOOT_POWERON"
        ) {
            return
        }

        val config = ConfigStore.loadConfig(context)
        if (!config.autoStartOnBoot || config.sshHost.isBlank()) return
        if (!ConfigStore.wasLastConnected(context)) return
        if (VpnService.prepare(context) != null) return

        val serviceIntent = Intent(context, HcYoniVpnService::class.java).apply {
            this.action = HcYoniVpnService.ACTION_CONNECT
        }
        try {
            ContextCompat.startForegroundService(context, serviceIntent)
        } catch (_: Throwable) {
            // En Android 15/16, activar "VPN siempre activa" o "Sin restricciones de batería"
            // garantiza el inicio automático tras reiniciar sin bloqueos del sistema.
        }
    }
}
