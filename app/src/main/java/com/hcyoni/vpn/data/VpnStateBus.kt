package com.hcyoni.vpn.data

import com.hcyoni.vpn.model.LogEntry
import com.hcyoni.vpn.model.LogLevel
import com.hcyoni.vpn.model.TrafficStats
import com.hcyoni.vpn.model.VpnState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object VpnStateBus {
    private const val MAX_LOGS = 250
    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    private val _state = MutableStateFlow(VpnState.DISCONNECTED)
    val state: StateFlow<VpnState> = _state.asStateFlow()

    private val _statusMessage = MutableStateFlow("Listo para conectar")
    val statusMessage: StateFlow<String> = _statusMessage.asStateFlow()

    private val _stats = MutableStateFlow(TrafficStats())
    val stats: StateFlow<TrafficStats> = _stats.asStateFlow()

    private val _logs = MutableStateFlow<List<LogEntry>>(emptyList())
    val logs: StateFlow<List<LogEntry>> = _logs.asStateFlow()

    fun updateState(newState: VpnState, message: String) {
        _state.value = newState
        _statusMessage.value = message
    }

    fun updateStats(newStats: TrafficStats) {
        _stats.value = newStats
    }

    fun resetStats() {
        _stats.value = TrafficStats()
    }

    @Synchronized
    fun log(tag: String, message: String, level: LogLevel = LogLevel.INFO) {
        val now = synchronized(timeFormat) { timeFormat.format(Date()) }
        val entry = LogEntry(timestamp = now, tag = tag, message = message, level = level)
        val current = _logs.value
        val updated = if (current.size >= MAX_LOGS) {
            current.drop(current.size - MAX_LOGS + 1) + entry
        } else {
            current + entry
        }
        _logs.value = updated
    }

    @Synchronized
    fun clearLogs() {
        _logs.value = emptyList()
    }
}
