// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use anyhow::{Context, Result};
use std::process::Command;

pub const TUN_IFACE: &str = "csqtt1";
pub const TUN_ADDR: &str = "10.66.67.1";
pub const TUN_SUBNET: &str = "10.66.67.0/24";

pub fn enable_ipv4_forwarding() -> Result<()> {
    if std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .is_ok_and(|value| value.trim() == "1")
    {
        return Ok(());
    }
    std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1").context("enable IPv4 forwarding")
}

fn iptables(args: &[&str]) -> Result<std::process::Output> {
    Command::new("iptables")
        .args(args)
        .output()
        .with_context(|| format!("iptables {}", args.join(" ")))
}

pub fn setup_nat(tun_iface: &str) -> Result<()> {
    let _ = iptables(&[
        "-t",
        "nat",
        "-D",
        "POSTROUTING",
        "-s",
        TUN_SUBNET,
        "!",
        "-o",
        tun_iface,
        "-j",
        "MASQUERADE",
    ]);
    let output = iptables(&[
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        TUN_SUBNET,
        "!",
        "-o",
        tun_iface,
        "-j",
        "MASQUERADE",
    ])?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("[TUN] iptables MASQUERADE: {stderr}");
    }
    let _ = iptables(&["-D", "FORWARD", "-s", TUN_SUBNET, "-j", "ACCEPT"]);
    let _ = iptables(&["-A", "FORWARD", "-s", TUN_SUBNET, "-j", "ACCEPT"]);
    let _ = iptables(&["-D", "FORWARD", "-d", TUN_SUBNET, "-j", "ACCEPT"]);
    let _ = iptables(&["-A", "FORWARD", "-d", TUN_SUBNET, "-j", "ACCEPT"]);

    // TCP MSS Clamping to prevent PMTU blackholes and packet drops on mobile networks
    let _ = iptables(&[
        "-t",
        "mangle",
        "-D",
        "FORWARD",
        "-p",
        "tcp",
        "--tcp-flags",
        "SYN,RST",
        "SYN",
        "-j",
        "TCPMSS",
        "--clamp-mss-to-pmtu",
    ]);
    let _ = iptables(&[
        "-t",
        "mangle",
        "-A",
        "FORWARD",
        "-p",
        "tcp",
        "--tcp-flags",
        "SYN,RST",
        "SYN",
        "-j",
        "TCPMSS",
        "--clamp-mss-to-pmtu",
    ]);

    Ok(())
}
