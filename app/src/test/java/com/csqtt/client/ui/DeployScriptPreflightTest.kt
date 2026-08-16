// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

class DeployScriptPreflightTest {
    private fun script(): String {
        val candidates = listOf(
            File("app/src/main/assets/deploy.sh"),
            File("src/main/assets/deploy.sh"),
        )
        return candidates.first(File::isFile).readText()
    }

    @Test
    fun `preflight performs working kernel probes`() {
        val deploy = script()
        assertTrue(deploy.contains("ip tuntap add dev \"\$probe_iface\" mode tun"))
        assertTrue(deploy.contains("iptables -w 10 -t \"\$table\" -N \"\$chain\""))
        assertTrue(deploy.contains("for table in filter nat mangle raw"))
        assertTrue(deploy.contains("/usr/local/bin/csqtt --io-uring-probe"))
        assertTrue(deploy.contains("run_platform_preflight"))
    }

    @Test
    fun `binary is installed before preflight and firewall configuration`() {
        val installBranch = script().substringAfter("install|--install|-i|*)")
        val binary = installBranch.indexOf("setup_csqtt_binary")
        val preflight = installBranch.indexOf("run_platform_preflight")
        val firewall = installBranch.indexOf("setup_nat_and_firewall")
        assertTrue(binary >= 0)
        assertTrue(preflight > binary)
        assertTrue(firewall > preflight)
    }

    @Test
    fun `docker uses compatibility privileges and repeats probes inside container`() {
        val deploy = script()
        assertTrue(deploy.contains("--privileged"))
        assertTrue(deploy.contains("--cap-add NET_ADMIN"))
        assertTrue(deploy.contains("--cap-add NET_RAW"))
        assertTrue(deploy.contains("--device /dev/net/tun:/dev/net/tun"))
        assertTrue(deploy.contains("--security-opt seccomp=unconfined"))
        assertTrue(deploy.contains("probe_docker_runtime"))
        assertTrue(deploy.split("--privileged").size >= 3)
    }

    @Test
    fun `configured network is verified after applying rules and after startup`() {
        val deploy = script()
        assertTrue(deploy.contains("verify_configured_network \"\$iface\""))
        assertTrue(deploy.split("verify_configured_network").size >= 5)
        assertTrue(deploy.contains("-j MASQUERADE >/dev/null 2>&1"))
        assertTrue(deploy.contains("-j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1"))
    }
}
