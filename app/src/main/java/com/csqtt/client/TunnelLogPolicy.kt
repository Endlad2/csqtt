// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

object TunnelLogPolicy {
    fun shouldSurfacePathHealth(
        missed: Long,
        sendErrors: Long,
        unresponsive: Long,
    ): Boolean = missed > 0L || sendErrors > 0L || unresponsive > 0L

    fun isInternalRecovery(line: String): Boolean {
        if (line.contains("FATAL_AUTH", ignoreCase = true)) return false
        return line.contains("GETCONF", ignoreCase = true) ||
            line.contains("[TURN][RETRY]", ignoreCase = true) ||
            line.contains("[СЕТЬ][RETRY]", ignoreCase = true) ||
            line.contains("PEER_LIVENESS_TIMEOUT", ignoreCase = true)
    }

    fun isTurnStreamFailure(line: String): Boolean {
        return line.contains("[TURN][DOWN]", ignoreCase = true) ||
            (
                line.contains("[ВОРКЕР", ignoreCase = true) &&
                    line.contains("[TURN]", ignoreCase = true) &&
                    (
                        line.contains("ошибка", ignoreCase = true) ||
                            line.contains("failed", ignoreCase = true) ||
                            line.contains("exhausted", ignoreCase = true)
                        )
                )
    }
}
