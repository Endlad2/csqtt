// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class WorkerCountPolicyTest {

    @Test
    fun runtimeThreadBudgetScalesWithoutFollowingCpuCoreCount() {
        for (workers in listOf(9, 18, 27, 36)) {
            assertEquals(2, WorkerCountPolicy.runtimeThreadsForWorkers(workers))
        }
        for (workers in listOf(45, 54, 81, 108)) {
            assertEquals(3, WorkerCountPolicy.runtimeThreadsForWorkers(workers))
        }
        for (workers in listOf(117, 135, 162)) {
            assertEquals(4, WorkerCountPolicy.runtimeThreadsForWorkers(workers))
        }
    }
    @Test
    fun everySupportedTotalRemainsAnExactMultipleOfNine() {
        val supported = (1..18).map { it * 9 }
        for ((groups, workers) in supported.withIndex()) {
            assertEquals(workers, WorkerCountPolicy.normalize(workers))
            assertEquals(groups + 1, workers / CsqttConstants.Tunnel.WORKERS_PER_GROUP)
        }
        assertEquals(162, supported.last())
    }

    @Test
    fun hashCapacityHasNoHiddenExtraNineWorkers() {
        assertEquals(27, WorkerCountPolicy.maximumForHashes(1))
        assertEquals(54, WorkerCountPolicy.maximumForHashes(2))
        assertEquals(81, WorkerCountPolicy.maximumForHashes(3))
        assertEquals(108, WorkerCountPolicy.maximumForHashes(4))
        assertEquals(135, WorkerCountPolicy.maximumForHashes(5))
        assertEquals(162, WorkerCountPolicy.maximumForHashes(6))
    }

    @Test
    fun participantCapacityComesFromLinkBeforeLocalProfileState() {
        assertEquals(
            108,
            WorkerCountPolicy.maximumForSources(
                linkMode = true,
                linkHashCount = 4,
                autoHashMode = false,
                manualHashCount = 0,
            ),
        )
        assertEquals(
            27,
            WorkerCountPolicy.maximumForSources(
                linkMode = false,
                linkHashCount = 4,
                autoHashMode = false,
                manualHashCount = 1,
            ),
        )
        assertEquals(
            162,
            WorkerCountPolicy.maximumForSources(
                linkMode = false,
                linkHashCount = 0,
                autoHashMode = true,
                manualHashCount = 1,
            ),
        )
    }

    @Test
    fun invalidPersistedCountsAreBoundedAndNeverCreatePartialCredentialGroup() {
        for (requested in -1_000..1_000) {
            val normalized = WorkerCountPolicy.normalize(requested)
            assertTrue(normalized in 9..162)
            assertEquals(0, normalized % 9)
            assertTrue(normalized <= requested.coerceAtLeast(9) || normalized == 162)
        }
    }

    @Test
    fun stalePersistedMaximumIsRecappedByCurrentHashCountAtRuntime() {
        assertEquals(27, WorkerCountPolicy.normalizeForHashes(162, 1))
        assertEquals(54, WorkerCountPolicy.normalizeForHashes(162, 2))
        assertEquals(81, WorkerCountPolicy.normalizeForHashes(162, 3))
        assertEquals(108, WorkerCountPolicy.normalizeForHashes(162, 4))
        assertEquals(135, WorkerCountPolicy.normalizeForHashes(162, 5))
        assertEquals(162, WorkerCountPolicy.normalizeForHashes(162, 6))
    }

    @Test
    fun automaticHashModeAllowsTheFullWorkerRange() {
        for (requested in -100..300) {
            val admitted = WorkerCountPolicy.normalize(requested)
            assertTrue(admitted in 9..162)
            assertEquals(0, admitted % 9)
        }
        assertEquals(162, WorkerCountPolicy.normalize(162))
    }

    @Test
    fun craftedIntentCountsCannotBypassHashAwareRuntimeAdmission() {
        for (requested in listOf(Int.MIN_VALUE, -1, 0, 8, 28, 109, Int.MAX_VALUE)) {
            for (hashCount in 1..CsqttConstants.Tunnel.MAX_VK_HASHES) {
                val admitted = WorkerCountPolicy.normalizeForHashes(requested, hashCount)
                assertTrue(admitted >= CsqttConstants.Tunnel.WORKERS_PER_GROUP)
                assertEquals(0, admitted % CsqttConstants.Tunnel.WORKERS_PER_GROUP)
                assertTrue(admitted <= WorkerCountPolicy.maximumForHashes(hashCount))
            }
        }
        assertEquals(
            27,
            WorkerCountPolicy.normalizeForHashValues(
                Int.MAX_VALUE,
                listOf("same", " same ", "same", ""),
            ),
        )
        assertEquals(
            162,
            WorkerCountPolicy.normalizeForHashValues(
                Int.MAX_VALUE,
                listOf("one", "two", "three", "four", "five", "six", "ignored-seventh"),
            ),
        )
    }

    @Test
    fun automaticCallCountScalesToSixHashes() {
        assertEquals(1, VkAutoCallsManager.callCountForWorkers(27))
        assertEquals(2, VkAutoCallsManager.callCountForWorkers(54))
        assertEquals(3, VkAutoCallsManager.callCountForWorkers(81))
        assertEquals(4, VkAutoCallsManager.callCountForWorkers(108))
        assertEquals(5, VkAutoCallsManager.callCountForWorkers(135))
        assertEquals(6, VkAutoCallsManager.callCountForWorkers(162))
        assertEquals(80L, VkAutoCallsManager.requestDelayForCallCount(1))
        assertEquals(80L, VkAutoCallsManager.requestDelayForCallCount(4))
        assertEquals(202L, VkAutoCallsManager.requestDelayForCallCount(5))
        assertEquals(202L, VkAutoCallsManager.requestDelayForCallCount(6))
    }

    @Test
    fun automaticCallFailureCanRedistributeWholeGroupsAcrossCreatedHashes() {
        assertEquals(
            162,
            WorkerCountPolicy.normalizeForHashValues(
                162,
                listOf("one", "two", "three", "four", "five"),
                allowRedistribution = true,
            ),
        )
        assertEquals(
            45,
            WorkerCountPolicy.normalizeForHashValues(
                50,
                listOf("one"),
                allowRedistribution = true,
            ),
        )
    }
}
