// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

internal object WorkerCountPolicy {
    fun normalize(
        requested: Int,
        maximum: Int = CsqttConstants.Tunnel.MAX_WORKERS,
    ): Int {
        val group = CsqttConstants.Tunnel.WORKERS_PER_GROUP
        val normalizedMaximum = (maximum.coerceAtLeast(group) / group) * group
        return (requested.coerceIn(group, normalizedMaximum) / group) * group
    }

    fun maximumForHashes(hashCount: Int): Int {
        val requested = hashCount.coerceIn(1, CsqttConstants.Tunnel.MAX_VK_HASHES) *
            CsqttConstants.Tunnel.GROUPS_PER_VK_HASH * CsqttConstants.Tunnel.WORKERS_PER_GROUP
        return normalize(requested)
    }

    fun maximumForSources(
        linkMode: Boolean,
        linkHashCount: Int,
        autoHashMode: Boolean,
        manualHashCount: Int,
    ): Int = when {
        linkMode && linkHashCount > 0 -> maximumForHashes(linkHashCount)
        autoHashMode -> CsqttConstants.Tunnel.MAX_WORKERS
        else -> maximumForHashes(manualHashCount)
    }

    fun normalizeForHashes(requested: Int, hashCount: Int): Int =
        normalize(requested, maximumForHashes(hashCount))

    fun normalizeForHashValues(
        requested: Int,
        hashes: Iterable<String>,
        allowRedistribution: Boolean = false,
    ): Int {
        if (allowRedistribution) return normalize(requested)
        val hashCount = hashes
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinct()
            .take(CsqttConstants.Tunnel.MAX_VK_HASHES)
            .count()
        return normalizeForHashes(requested, hashCount)
    }

    fun runtimeThreadsForWorkers(workers: Int): Int = when (normalize(workers)) {
        in 9..36 -> 2
        in 45..108 -> 3
        else -> 4
    }
}
