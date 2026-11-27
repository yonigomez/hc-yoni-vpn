package com.hcyoni.vpn.util

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import android.util.Base64
import com.hcyoni.vpn.model.VpnConfig
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object SecurityAndDeviceHelper {

    private const val APP_MASTER_SECRET = "HC_YONI_JONATHAN_GASTON_GOMEZ_3873063499_AES256_V2"
    private const val PREFIX_NO_PASS = "HCYONI2:N:"
    private const val PREFIX_WITH_PASS = "HCYONI2:P:"

    @SuppressLint("HardwareIds")
    fun getDeviceHwid(context: Context): String {
        val androidId = try {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) ?: "unknown"
        } catch (_: Exception) {
            "unknown"
        }
        val seed = "$androidId|${Build.MANUFACTURER}|${Build.MODEL}|${Build.BOARD}|hc_yoni"
        val digest = MessageDigest.getInstance("SHA-256").digest(seed.toByteArray(Charsets.UTF_8))
        val hex = digest.joinToString("") { "%02X".format(it) }.take(12)
        return "HCY-${hex.substring(0, 4)}-${hex.substring(4, 8)}-${hex.substring(8, 12)}"
    }

    fun isDeviceRooted(): Boolean {
        val buildTags = Build.TAGS
        if (buildTags != null && buildTags.contains("test-keys")) return true

        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/system/xbin/daemonsu"
        )
        return paths.any {
            try {
                File(it).exists()
            } catch (_: Exception) {
                false
            }
        }
    }

    fun isUsingMobileData(context: Context): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val active = cm.activeNetwork
        val activeCaps = if (active != null) cm.getNetworkCapabilities(active) else null
        if (activeCaps != null && activeCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
            return activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) &&
                !activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        }
        // Si la VPN está activa, inspeccionamos las redes físicas subyacentes
        var hasCell = false
        var hasWifi = false
        for (net in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(net) ?: continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) hasCell = true
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) hasWifi = true
        }
        return hasCell && !hasWifi
    }

    fun encryptYoniConfig(config: VpnConfig, filePassword: String = ""): String {
        val json = config.toJson(includeSecrets = true).toByteArray(Charsets.UTF_8)
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val key = deriveAesKey(filePassword)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val encrypted = cipher.doFinal(json)

        val combined = ByteArray(iv.size + encrypted.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encrypted, 0, combined, iv.size, encrypted.size)

        val b64 = Base64.encodeToString(combined, Base64.NO_WRAP)
        return if (filePassword.isNotEmpty()) {
            "$PREFIX_WITH_PASS$b64"
        } else {
            "$PREFIX_NO_PASS$b64"
        }
    }

    fun requiresPassword(rawContent: String): Boolean {
        return rawContent.trim().startsWith(PREFIX_WITH_PASS)
    }

    fun decryptYoniConfig(rawContent: String, filePassword: String = ""): VpnConfig {
        val trimmed = rawContent.trim()
        return when {
            trimmed.startsWith(PREFIX_NO_PASS) -> {
                val payload = trimmed.removePrefix(PREFIX_NO_PASS)
                val json = decryptBytes(payload, "")
                VpnConfig.fromJson(json)
            }
            trimmed.startsWith(PREFIX_WITH_PASS) -> {
                if (filePassword.isEmpty()) {
                    throw IllegalArgumentException("Este archivo requiere contraseña")
                }
                val payload = trimmed.removePrefix(PREFIX_WITH_PASS)
                val json = decryptBytes(payload, filePassword)
                VpnConfig.fromJson(json)
            }
            trimmed.startsWith("{") -> {
                // Compatibilidad con configuraciones .yoni antiguas sin cifrar
                VpnConfig.fromJson(trimmed)
            }
            else -> {
                throw IllegalArgumentException("El archivo no pertenece a hc Yoni o está dañado")
            }
        }
    }

    private fun decryptBytes(base64Data: String, filePassword: String): String {
        val combined = Base64.decode(base64Data, Base64.DEFAULT)
        if (combined.size <= 12) throw IllegalArgumentException("Datos cifrados inválidos")
        val iv = combined.copyOfRange(0, 12)
        val ciphertext = combined.copyOfRange(12, combined.size)

        val key = deriveAesKey(filePassword)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        val plain = cipher.doFinal(ciphertext)
        return String(plain, Charsets.UTF_8)
    }

    private fun deriveAesKey(filePassword: String): SecretKeySpec {
        val material = "$APP_MASTER_SECRET|$filePassword"
        val hash = MessageDigest.getInstance("SHA-256").digest(material.toByteArray(Charsets.UTF_8))
        return SecretKeySpec(hash, "AES")
    }
}
