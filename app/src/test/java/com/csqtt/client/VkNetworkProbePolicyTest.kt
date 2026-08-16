// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VkNetworkProbePolicyTest {
    @Test
    fun retryDelayStartsFastAndRemainsBounded() {
        repeat(15) { failure ->
            assertEquals(1_000L, vkProbeRetryDelayMs(failure + 1))
        }
        assertEquals(2_000L, vkProbeRetryDelayMs(16))
        assertEquals(15_000L, vkProbeRetryDelayMs(Int.MAX_VALUE))
    }

    @Test
    fun anyHttpResponseProvesVkDnsTcpAndTlsReachability() {
        assertTrue(isVkProbeHttpResponse(200))
        assertTrue(isVkProbeHttpResponse(403))
        assertTrue(isVkProbeHttpResponse(503))
        assertFalse(isVkProbeHttpResponse(0))
        assertFalse(isVkProbeHttpResponse(600))
    }
}
