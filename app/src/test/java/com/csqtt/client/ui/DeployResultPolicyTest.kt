// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DeployResultPolicyTest {
    @Test
    fun exactMarkerAndZeroExitAreRequired() {
        assertTrue(isSuccessfulDeployResult(0, "done\nCSQTT_DEPLOY_OK\n"))
        assertFalse(isSuccessfulDeployResult(1, "CSQTT_DEPLOY_OK"))
        assertFalse(isSuccessfulDeployResult(0, "service is active"))
        assertFalse(isSuccessfulDeployResult(0, "prefix CSQTT_DEPLOY_OK suffix"))
    }

    @Test
    fun authFailureHasActionableMessage() {
        assertEquals(
            "SSH-аутентификация отклонена: проверьте логин, пароль и разрешение PasswordAuthentication на VPS",
            friendlyDeployError("Auth fail for methods 'publickey,password'"),
        )
    }

    @Test
    fun publicKeyFailureHasKeySpecificMessage() {
        assertTrue(
            friendlyDeployError("Auth fail (public key): rejected")
                .contains("authorized_keys"),
        )
    }

    @Test
    fun timeoutHasShortMessage() {
        assertEquals("Истекло время ожидания SSH/SFTP", friendlyDeployError("connect timeout"))
    }

    @Test
    fun serverSuccessLineBecomesCleanOkLog() {
        assertEquals(
            DeployOutputLine("csqtt установлен", DeployOutputLevel.OK),
            parseDeployOutputLine("✓ csqtt установлен"),
        )
    }

    @Test
    fun serverStepHasNoEmojiOrStatusSticker() {
        assertEquals(
            DeployOutputLine("Установка csqtt...", DeployOutputLevel.LOG),
            parseDeployOutputLine("📦 Установка csqtt..."),
        )
        assertEquals(
            DeployOutputLine("Проверка зависимостей", DeployOutputLevel.LOG),
            parseDeployOutputLine("[►] Проверка зависимостей"),
        )
    }

    @Test
    fun serverFailureBecomesErrorLog() {
        assertEquals(
            DeployOutputLine("Сервис csqtt не запустился", DeployOutputLevel.ERR),
            parseDeployOutputLine("[✗] Сервис csqtt не запустился"),
        )
    }

    @Test
    fun protocolAndDecorationLinesAreHidden() {
        assertNull(parseDeployOutputLine("CSQTT_PROGRESS|0.6|Бинарник..."))
        assertNull(parseDeployOutputLine("════════════════════════════"))
        assertNull(parseDeployOutputLine("CSQTT_DEPLOY_OK"))
    }

    @Test
    fun dockerModeUsesRawEnvironmentValues() {
        assertEquals("docker", deployMode(true))
        assertEquals("systemd", deployMode(false))
        assertEquals("a b#$\"\\c  d", deployEnvironmentValue("a b#$\"\\c\r\nd", true))
        assertEquals("\"a b#$\\\"\\\\c  d\"", deployEnvironmentValue("a b#$\"\\c\r\nd", false))
    }
}
