// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelLogPolicyTest {
    @Test
    fun hidesHealthyPathChecksAndSurfacesFailures() {
        assertFalse(TunnelLogPolicy.shouldSurfacePathHealth(0, 0, 0))
        assertTrue(TunnelLogPolicy.shouldSurfacePathHealth(1, 0, 0))
        assertTrue(TunnelLogPolicy.shouldSurfacePathHealth(0, 1, 0))
        assertTrue(TunnelLogPolicy.shouldSurfacePathHealth(0, 0, 1))
    }

    @Test
    fun removesStatusStickersFromVisibleLogs() {
        assertEquals(
            "VPN TUN: разрешение Android VPN было отозвано",
            withoutLogStickers("❌ VPN TUN: разрешение Android VPN было отозвано"),
        )
        assertEquals("Поток готов ✓", withoutLogStickers("Поток готов ✓"))
        assertEquals("✗ Ошибка VPN", withoutLogStickers("✗ Ошибка VPN"))
        assertEquals("Сервис запущен", withoutLogStickers("[✅] Сервис запущен"))
        assertEquals("[СЕТЬ] Переподключение", withoutLogStickers("[СЕТЬ] ⚠ Переподключение"))
    }

    @Test
    fun hidesEveryGetconfDiagnostic() {
        assertTrue(TunnelLogPolicy.isInternalRecovery("[GETCONF] Sending 72 bytes"))
        assertTrue(TunnelLogPolicy.isInternalRecovery("[ВОРКЕР #8] GETCONF timeout 750ms"))
        assertTrue(TunnelLogPolicy.isInternalRecovery("GETCONF чтение ответа конфига: timeout"))
        assertFalse(
            TunnelLogPolicy.isInternalRecovery(
                "GETCONF: FATAL_AUTH: неверный пароль подключения"
            )
        )
    }

    @Test
    fun hidesTurnRetriesThatKeepTheStreamAlive() {
        assertTrue(
            TunnelLogPolicy.isInternalRecovery(
                "[TURN][RETRY] Ошибка обновления permission: timeout"
            )
        )
        assertTrue(
            TunnelLogPolicy.isInternalRecovery(
                "[TURN][RETRY] Ошибка транзакции ChannelBind: timeout"
            )
        )
        assertFalse(
            TunnelLogPolicy.isInternalRecovery(
                "[TURN][DOWN] Permission истекает, переподнимаем поток"
            )
        )
        assertTrue(
            TunnelLogPolicy.isInternalRecovery(
                "[ВОРКЕР #17] PEER_LIVENESS_TIMEOUT: 8s без валидных пакетов"
            )
        )
        assertTrue(
            TunnelLogPolicy.isInternalRecovery(
                "[ВОРКЕР #2] [TURN][RETRY] Попытка 46: TURN liveness probe failed"
            )
        )
        assertTrue(
            TunnelLogPolicy.isInternalRecovery(
                "[ВОРКЕР #2] [СЕТЬ][RETRY] Временная ошибка сокета"
            )
        )
    }

    @Test
    fun surfacesOnlyTurnFailuresThatEndAStream() {
        assertTrue(
            TunnelLogPolicy.isTurnStreamFailure(
                "[TURN][DOWN] Allocation истекает, переподнимаем поток"
            )
        )
        assertTrue(
            TunnelLogPolicy.isTurnStreamFailure(
                "[ВОРКЕР #4] [TURN] Ошибка allocation/кредов: socket closed"
            )
        )
        assertFalse(
            TunnelLogPolicy.isTurnStreamFailure(
                "[ГРУППА #1] [TURN] Креды обновлены, TURN urls=3"
            )
        )
    }
}
