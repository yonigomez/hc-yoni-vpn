package com.hcyoni.vpn.model

import org.json.JSONArray
import org.json.JSONObject

enum class VpnState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    RECONNECTING,
    ERROR
}

enum class LogLevel {
    INFO,
    SUCCESS,
    WARN,
    ERROR
}

data class LogEntry(
    val timestamp: String,
    val tag: String,
    val message: String,
    val level: LogLevel = LogLevel.INFO
)

data class TrafficStats(
    val txBytes: Long = 0L,
    val rxBytes: Long = 0L,
    val txRateBps: Long = 0L,
    val rxRateBps: Long = 0L,
    val connectedSinceMs: Long = 0L
)

data class VpnConfig(
    val profileName: String = "Servidor HC YONI",
    val sshHost: String = "",
    val sshPort: Int = 22,
    val username: String = "",
    val password: String = "",
    val privateKey: String = "",
    val proxyHost: String = "",
    val proxyPort: Int = 80,
    val payload: String = DEFAULT_PAYLOAD,
    val sniHost: String = "",
    val useTls: Boolean = false,
    val dnsServer: String = "8.8.8.8",
    val secondaryDns: String = "1.1.1.1",
    val useCustomDns: Boolean = false,
    val enableIpv6: Boolean = false,
    val autoReconnect: Boolean = true,
    val autoStartOnBoot: Boolean = false,
    val keepAliveIntervalSec: Int = 25,
    val udpgwEnabled: Boolean = true,
    val udpgwPort: Int = 7300,
    val useHwidWhenEmpty: Boolean = true,
    val wifiShareEnabled: Boolean = false,
    val wifiSharePort: Int = 8080,
    val allowWifiShare: Boolean = true,
    val excludedApps: Set<String> = emptySet(),
    // Bloqueos y seguridad de archivos .yoni
    val lockPayload: Boolean = false,
    val lockServerAndProxy: Boolean = false,
    val lockCredentials: Boolean = false,
    val mobileDataOnly: Boolean = false,
    val blockRoot: Boolean = false,
    val lockedHwid: String = "",
    val expiryDateMillis: Long = 0L,
    val configNote: String = "",
    val hideServerBanner: Boolean = false
) {
    fun hasAnyLock(): Boolean {
        return lockPayload || lockServerAndProxy || lockCredentials ||
            mobileDataOnly || blockRoot || lockedHwid.isNotBlank() ||
            expiryDateMillis > 0L || !allowWifiShare
    }

    fun toJson(includeSecrets: Boolean = true): String {
        val obj = JSONObject()
        obj.put("profileName", profileName)
        obj.put("sshHost", sshHost)
        obj.put("sshPort", sshPort)
        obj.put("username", if (includeSecrets) username else "")
        obj.put("password", if (includeSecrets) password else "")
        obj.put("privateKey", if (includeSecrets) privateKey else "")
        obj.put("proxyHost", proxyHost)
        obj.put("proxyPort", proxyPort)
        obj.put("payload", payload)
        obj.put("sniHost", sniHost)
        obj.put("useTls", useTls)
        obj.put("dnsServer", dnsServer)
        obj.put("secondaryDns", secondaryDns)
        obj.put("useCustomDns", useCustomDns)
        obj.put("enableIpv6", enableIpv6)
        obj.put("autoReconnect", autoReconnect)
        obj.put("autoStartOnBoot", autoStartOnBoot)
        obj.put("keepAliveIntervalSec", keepAliveIntervalSec)
        obj.put("udpgwEnabled", udpgwEnabled)
        obj.put("udpgwPort", udpgwPort)
        obj.put("useHwidWhenEmpty", useHwidWhenEmpty)
        obj.put("wifiShareEnabled", wifiShareEnabled)
        obj.put("wifiSharePort", wifiSharePort)
        obj.put("allowWifiShare", allowWifiShare)
        obj.put("lockPayload", lockPayload)
        obj.put("lockServerAndProxy", lockServerAndProxy)
        obj.put("lockCredentials", lockCredentials)
        obj.put("mobileDataOnly", mobileDataOnly)
        obj.put("blockRoot", blockRoot)
        obj.put("lockedHwid", lockedHwid)
        obj.put("expiryDateMillis", expiryDateMillis)
        obj.put("configNote", configNote)
        obj.put("hideServerBanner", hideServerBanner)

        val arr = JSONArray()
        excludedApps.sorted().forEach { arr.put(it) }
        obj.put("excludedApps", arr)
        return obj.toString(2)
    }

    companion object {
        const val DEFAULT_PAYLOAD =
            "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"

        fun fromJson(raw: String): VpnConfig {
            val obj = JSONObject(raw)
            val excluded = mutableSetOf<String>()
            val arr = obj.optJSONArray("excludedApps")
            if (arr != null) {
                for (i in 0 until arr.length()) {
                    val pkg = arr.optString(i, "").trim()
                    if (pkg.isNotEmpty()) excluded.add(pkg)
                }
            }
            return VpnConfig(
                profileName = obj.optString("profileName", "Servidor HC YONI"),
                sshHost = obj.optString("sshHost", "").trim(),
                sshPort = obj.optInt("sshPort", 22).coerceIn(1, 65535),
                username = obj.optString("username", "").trim(),
                password = obj.optString("password", ""),
                privateKey = obj.optString("privateKey", ""),
                proxyHost = obj.optString("proxyHost", "").trim(),
                proxyPort = obj.optInt("proxyPort", 80).coerceIn(1, 65535),
                payload = obj.optString("payload", DEFAULT_PAYLOAD),
                sniHost = obj.optString("sniHost", "").trim(),
                useTls = obj.optBoolean("useTls", false),
                dnsServer = obj.optString("dnsServer", "8.8.8.8").ifBlank { "8.8.8.8" },
                secondaryDns = obj.optString("secondaryDns", "1.1.1.1").ifBlank { "1.1.1.1" },
                useCustomDns = obj.optBoolean("useCustomDns", false),
                enableIpv6 = obj.optBoolean("enableIpv6", false),
                autoReconnect = obj.optBoolean("autoReconnect", true),
                autoStartOnBoot = obj.optBoolean("autoStartOnBoot", false),
                keepAliveIntervalSec = obj.optInt("keepAliveIntervalSec", 25).coerceIn(5, 120),
                udpgwEnabled = obj.optBoolean("udpgwEnabled", true),
                udpgwPort = obj.optInt("udpgwPort", 7300).coerceIn(1, 65535),
                useHwidWhenEmpty = obj.optBoolean("useHwidWhenEmpty", true),
                wifiShareEnabled = obj.optBoolean("wifiShareEnabled", false),
                wifiSharePort = obj.optInt("wifiSharePort", 8080).coerceIn(1024, 65535),
                allowWifiShare = obj.optBoolean("allowWifiShare", true),
                excludedApps = excluded,
                lockPayload = obj.optBoolean("lockPayload", false),
                lockServerAndProxy = obj.optBoolean("lockServerAndProxy", false),
                lockCredentials = obj.optBoolean("lockCredentials", false),
                mobileDataOnly = obj.optBoolean("mobileDataOnly", false),
                blockRoot = obj.optBoolean("blockRoot", false),
                lockedHwid = obj.optString("lockedHwid", "").trim(),
                expiryDateMillis = obj.optLong("expiryDateMillis", 0L),
                configNote = obj.optString("configNote", ""),
                hideServerBanner = obj.optBoolean("hideServerBanner", false)
            )
        }
    }
}
