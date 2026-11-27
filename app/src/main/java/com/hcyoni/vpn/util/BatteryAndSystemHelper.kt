package com.hcyoni.vpn.util

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings

object BatteryAndSystemHelper {

    fun isIgnoringBatteryOptimizations(context: Context): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        return pm.isIgnoringBatteryOptimizations(context.packageName)
    }

    @SuppressLint("BatteryLife")
    fun requestIgnoreBatteryOptimization(context: Context) {
        val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
            data = Uri.parse("package:${context.packageName}")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        try {
            context.startActivity(intent)
        } catch (_: Exception) {
            openAppBatterySettings(context)
        }
    }

    fun openAppBatterySettings(context: Context) {
        val appDetails = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.parse("package:${context.packageName}")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        try {
            context.startActivity(appDetails)
        } catch (_: Exception) {
            val fallback = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            try {
                context.startActivity(fallback)
            } catch (_: Exception) {
            }
        }
    }

    fun openVpnSystemSettings(context: Context) {
        val intent = Intent(Settings.ACTION_VPN_SETTINGS).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        try {
            context.startActivity(intent)
        } catch (_: Exception) {
            openAppBatterySettings(context)
        }
    }

    fun isSamsungDevice(): Boolean {
        return Build.MANUFACTURER.equals("samsung", ignoreCase = true)
    }

    fun getBackgroundProtectionGuide(): String {
        return when {
            isSamsungDevice() ->
                "En Samsung: 1) Toca 'Sin restricciones de batería'. 2) En Ajustes > Cuidado dispositivo > Batería > Límites de uso en segundo plano > 'Aplicaciones nunca suspendidas', añade 'hc Yoni'. 3) Activa 'VPN siempre activa' en Ajustes VPN."
            Build.MANUFACTURER.equals("xiaomi", ignoreCase = true) ||
                Build.MANUFACTURER.equals("redmi", ignoreCase = true) ||
                Build.MANUFACTURER.equals("poco", ignoreCase = true) ->
                "En Xiaomi/MIUI/HyperOS: 1) Pon Batería en 'Sin restricciones'. 2) Activa 'Inicio automático'. 3) Pon candado a hc Yoni en aplicaciones recientes."
            else ->
                "1) Toca 'Sin restricciones de batería' para evitar que Doze cierre el túnel. 2) Opcional: en Ajustes VPN activa 'VPN siempre activa' para hc Yoni."
        }
    }
}
