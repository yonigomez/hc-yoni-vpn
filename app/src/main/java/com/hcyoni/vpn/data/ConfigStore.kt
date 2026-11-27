package com.hcyoni.vpn.data

import android.content.Context
import com.hcyoni.vpn.model.VpnConfig

object ConfigStore {
    private const val PREFS_NAME = "hc_yoni_prefs"
    private const val KEY_CONFIG_JSON = "active_config_json"
    private const val KEY_WAS_CONNECTED = "was_connected"

    fun saveConfig(context: Context, config: VpnConfig) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_CONFIG_JSON, config.toJson(includeSecrets = true))
            .apply()
    }

    fun loadConfig(context: Context): VpnConfig {
        val raw = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(KEY_CONFIG_JSON, null) ?: return VpnConfig()
        return try {
            VpnConfig.fromJson(raw)
        } catch (_: Exception) {
            VpnConfig()
        }
    }

    fun setLastConnected(context: Context, connected: Boolean) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_WAS_CONNECTED, connected)
            .apply()
    }

    fun wasLastConnected(context: Context): Boolean {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_WAS_CONNECTED, false)
    }
}
