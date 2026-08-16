// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::model::LocalProxyProfile;
use anyhow::{Context, Result, bail};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const LEGACY_POLICY_TABLE: &str = "1066";
const LEGACY_POLICY_PRIORITY: &str = "1066";
const NAT_COMMENT: &str = "CSQTT_LOCAL_SOCKS";
const MARK_COMMENT: &str = "CSQTT_LOCAL_SOCKS_MARK";
const POLICY_MARK: &str = "0x422";
const LEGACY_NAT_COMMENT: &str = "CSQTT_SOCKS";
const LEGACY_QUIC_COMMENT: &str = "CSQTT_CASCADE_NO_QUIC";
const TPROXY_TABLE: &str = "100";
const TPROXY_PRIORITY: &str = "100";
const TPROXY_RULE_MARK: &str = "0x1/0x1";
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);
const DNS_PROBE_ID: u16 = 0x4351;
const DNS_QUERY: &[u8] = &[
    0x43, 0x51, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a',
    b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
];

static RUNTIME_COUNTER: AtomicU64 = AtomicU64::new(1);
static ACTIVE_RUNTIME: AtomicU64 = AtomicU64::new(0);
static POLICY_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub type LogFn = Arc<dyn Fn(&str, &str) + Send + Sync>;

pub struct ProxyRoute {
    config: LocalProxyProfile,
    runtime_id: u64,
    port: u16,
    engine: tokio_util::sync::CancellationToken,
    pub cancel: tokio_util::sync::CancellationToken,
    stats: Arc<crate::tproxy::TproxyStats>,
}

impl Drop for ProxyRoute {
    fn drop(&mut self) {
        self.engine.cancel();
    }
}

impl ProxyRoute {
    pub async fn connect(config: &LocalProxyProfile, log: LogFn) -> Result<Arc<Self>> {
        validate_config(config)?;
        ensure_linux_platform()?;
        if !port_is_listening(config.port).await {
            bail!("SOCKS5 port {} is not listening", config.port);
        }

        let runtime_id = RUNTIME_COUNTER.fetch_add(1, Ordering::Relaxed);
        let port = crate::tproxy::tproxy_port(runtime_id);
        let sockets = crate::tproxy::bind_sockets(port)
            .with_context(|| format!("bind TPROXY sockets on port {port}"))?;

        activate_tproxy(runtime_id, port).await?;

        let cancel = tokio_util::sync::CancellationToken::new();
        let engine = tokio_util::sync::CancellationToken::new();
        let dead = cancel.clone();
        let engine_run = engine.clone();
        let log_run = log.clone();
        let config_arc = Arc::new(config.clone());
        let stats = Arc::new(crate::tproxy::TproxyStats::default());
        let engine_stats = stats.clone();
        tokio::spawn(async move {
            let cleanup_token = engine_run.clone();
            tokio::spawn(async move {
                cleanup_token.cancelled_owned().await;
                deactivate_tproxy(port).await;
            });
            let (tcp_sessions, udp_flows, udp_datagrams) = crate::tproxy::run(
                sockets,
                config_arc,
                engine_run,
                log_run.clone(),
                engine_stats,
            )
            .await;
            log_run(
                "INFO",
                &format!(
                    "TPROXY engine exited ({tcp_sessions} TCP sessions, {udp_flows} UDP flows, {udp_datagrams} UDP datagrams served)"
                ),
            );
            finish_route(runtime_id).await;
            dead.cancel();
        });

        let route = Arc::new(Self {
            config: config.clone(),
            runtime_id,
            port,
            engine,
            cancel,
            stats,
        });
        println!(
            "[LOCAL-PROXY] SOCKS5 route ready on 127.0.0.1:{} via TPROXY port {}",
            route.config.port, route.port
        );
        Ok(route)
    }

    pub fn is_alive(&self) -> bool {
        !self.cancel.is_cancelled()
    }

    pub fn matches(&self, config: &LocalProxyProfile) -> bool {
        self.config == *config
    }

    pub fn stats_snapshot(&self) -> (usize, usize) {
        let snapshot = self.stats.snapshot();
        (snapshot.tcp_active, snapshot.udp_active)
    }

    pub fn diagnostic_snapshot(&self) -> crate::tproxy::TproxyStatsSnapshot {
        self.stats.snapshot()
    }

    pub async fn deactivate(&self) {
        self.engine.cancel();
        if tokio::time::timeout(Duration::from_secs(5), self.cancel.cancelled())
            .await
            .is_err()
        {
            let _guard = POLICY_LOCK.lock().await;
            if ACTIVE_RUNTIME
                .compare_exchange(self.runtime_id, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                cleanup_shared_policy().await;
            }
        }
    }

    pub async fn cleanup_stale_policy() {
        let _guard = POLICY_LOCK.lock().await;
        if ACTIVE_RUNTIME.load(Ordering::Acquire) == 0 {
            cleanup_shared_policy().await;
            cleanup_legacy_proxy_policy().await;
        }
    }

    pub async fn cleanup_orphaned_policy() -> Result<()> {
        let _guard = POLICY_LOCK.lock().await;
        ACTIVE_RUNTIME.store(0, Ordering::Release);
        cleanup_shared_policy().await;
        cleanup_legacy_proxy_policy().await;
        verify_proxy_policy_clean().await
    }
}

pub(crate) async fn finish_route(runtime_id: u64) {
    let _guard = POLICY_LOCK.lock().await;
    if ACTIVE_RUNTIME
        .compare_exchange(runtime_id, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        cleanup_shared_policy().await;
    }
}

pub(crate) async fn port_is_listening(port: u16) -> bool {
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    matches!(
        tokio::time::timeout(Duration::from_millis(1500), TcpStream::connect(target)).await,
        Ok(Ok(_))
    )
}

pub fn validate_config(config: &LocalProxyProfile) -> Result<()> {
    if config.port == 0 {
        bail!("SOCKS5 port must be in range 1-65535");
    }
    if config.username.len() > u8::MAX as usize || config.password.len() > u8::MAX as usize {
        bail!("SOCKS5 username and password must not exceed 255 bytes");
    }
    if config.username.is_empty() && !config.password.is_empty() {
        bail!("SOCKS5 username is required when a password is set");
    }
    if config
        .username
        .chars()
        .chain(config.password.chars())
        .any(char::is_control)
    {
        bail!("SOCKS5 credentials must not contain control characters");
    }
    Ok(())
}

fn ensure_linux_platform() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    bail!("local SOCKS5 policy routing is supported only on Linux servers");
    #[cfg(target_os = "linux")]
    Ok(())
}

pub(crate) async fn socks_command(
    config: &LocalProxyProfile,
    command: u8,
    destination: SocketAddr,
) -> Result<(TcpStream, SocketAddr)> {
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, config.port));
    let mut stream = tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(proxy))
        .await
        .context("local SOCKS5 connection timed out")??;
    stream.set_nodelay(true).ok();

    let method = if config.username.is_empty() {
        0x00
    } else {
        0x02
    };
    stream.write_all(&[0x05, 0x01, method]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, method] {
        bail!("SOCKS5 authentication method was rejected");
    }

    if method == 0x02 {
        let username = config.username.as_bytes();
        let password = config.password.as_bytes();
        let mut auth = Vec::with_capacity(3 + username.len() + password.len());
        auth.extend_from_slice(&[0x01, username.len() as u8]);
        auth.extend_from_slice(username);
        auth.push(password.len() as u8);
        auth.extend_from_slice(password);
        stream.write_all(&auth).await?;
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        if response != [0x01, 0x00] {
            bail!("SOCKS5 username or password is incorrect");
        }
    }

    let mut request = vec![0x05, command, 0x00];
    append_socks_address(&mut request, destination);
    stream.write_all(&request).await?;
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 || response[1] != 0x00 || response[2] != 0x00 {
        bail!("SOCKS5 command {command} failed with reply {}", response[1]);
    }
    let mut bound = read_socks_address(&mut stream, response[3]).await?;
    if bound.ip().is_unspecified() {
        bound.set_ip(proxy.ip());
    }
    Ok((stream, bound))
}

pub(crate) fn append_socks_address(target: &mut Vec<u8>, address: SocketAddr) {
    match address {
        SocketAddr::V4(value) => {
            target.push(0x01);
            target.extend_from_slice(&value.ip().octets());
        }
        SocketAddr::V6(value) => {
            target.push(0x04);
            target.extend_from_slice(&value.ip().octets());
        }
    }
    target.extend_from_slice(&address.port().to_be_bytes());
}

async fn read_socks_address(stream: &mut TcpStream, atyp: u8) -> Result<SocketAddr> {
    match atyp {
        0x01 => {
            let mut bytes = [0u8; 6];
            stream.read_exact(&mut bytes).await?;
            Ok(SocketAddr::from((
                Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
                u16::from_be_bytes([bytes[4], bytes[5]]),
            )))
        }
        0x04 => {
            let mut bytes = [0u8; 18];
            stream.read_exact(&mut bytes).await?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&bytes[..16]);
            Ok(SocketAddr::from((
                std::net::Ipv6Addr::from(ip),
                u16::from_be_bytes([bytes[16], bytes[17]]),
            )))
        }
        0x03 => {
            let length = stream.read_u8().await? as usize;
            let mut bytes = vec![0u8; length + 2];
            stream.read_exact(&mut bytes).await?;
            let host =
                std::str::from_utf8(&bytes[..length]).context("invalid SOCKS5 relay host")?;
            let port = u16::from_be_bytes([bytes[length], bytes[length + 1]]);
            tokio::net::lookup_host((host, port))
                .await?
                .next()
                .context("SOCKS5 relay host did not resolve")
        }
        _ => bail!("invalid SOCKS5 address type {atyp}"),
    }
}

async fn probe_tcp(config: &LocalProxyProfile) -> Result<()> {
    let mut last_error = None;
    for endpoint in [
        SocketAddr::from(([1, 1, 1, 1], 443)),
        SocketAddr::from(([8, 8, 8, 8], 443)),
    ] {
        match tokio::time::timeout(PROBE_TIMEOUT, socks_command(config, 0x01, endpoint)).await {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => last_error = Some(anyhow::anyhow!("TCP probe to {endpoint} timed out")),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("SOCKS5 TCP probe failed")))
}

async fn probe_udp(config: &LocalProxyProfile) -> Result<()> {
    let (_control, relay) =
        socks_command(config, 0x03, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    let destination = SocketAddr::from(([1, 1, 1, 1], 53));
    let mut packet = Vec::with_capacity(DNS_QUERY.len() + 10);
    packet.extend_from_slice(&[0, 0, 0]);
    append_socks_address(&mut packet, destination);
    packet.extend_from_slice(DNS_QUERY);
    socket.send_to(&packet, relay).await?;

    let mut response = [0u8; 2048];
    let (length, _) = tokio::time::timeout(PROBE_TIMEOUT, socket.recv_from(&mut response))
        .await
        .context("SOCKS5 UDP probe timed out")??;
    let (_, payload) = socks_udp_response(&response[..length])?;
    validate_dns_response(payload)
}

pub(crate) fn socks_udp_response(packet: &[u8]) -> Result<(SocketAddr, &[u8])> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        bail!("invalid SOCKS5 UDP response header");
    }
    let address_len = match packet[3] {
        0x01 => 4usize,
        0x04 => 16,
        0x03 => bail!("SOCKS5 UDP responses must carry an IP address"),
        atyp => bail!("invalid SOCKS5 UDP address type {atyp}"),
    };
    let header_end = 4 + address_len + 2;
    if header_end > packet.len() {
        bail!("short SOCKS5 UDP response");
    }
    let address = &packet[4..4 + address_len];
    let ip = if address_len == 4 {
        std::net::IpAddr::V4(Ipv4Addr::new(
            address[0], address[1], address[2], address[3],
        ))
    } else {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(address);
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes))
    };
    let port = u16::from_be_bytes([packet[4 + address_len], packet[5 + address_len]]);
    Ok((SocketAddr::new(ip, port), &packet[header_end..]))
}

fn validate_dns_response(response: &[u8]) -> Result<()> {
    if response.len() < 12
        || u16::from_be_bytes([response[0], response[1]]) != DNS_PROBE_ID
        || response[2] & 0x80 == 0
    {
        bail!("invalid DNS response through SOCKS5 UDP relay");
    }
    Ok(())
}

pub async fn probe_proxy(config: &LocalProxyProfile) -> Result<()> {
    validate_config(config)?;
    probe_tcp(config).await.context("SOCKS5 TCP health check")?;
    probe_udp(config)
        .await
        .context("SOCKS5 UDP health check; enable UDP support in the 3x-ui SOCKS inbound")
}

async fn activate_tproxy(runtime_id: u64, port: u16) -> Result<()> {
    let _guard = POLICY_LOCK.lock().await;
    cleanup_legacy_proxy_policy().await;
    let _ = command_output("sysctl", &["-w", "net.ipv4.conf.all.rp_filter=2"]).await;
    let _ = command_output("sysctl", &["-w", "net.core.rmem_max=8388608"]).await;
    let _ = command_output("sysctl", &["-w", "net.core.wmem_max=8388608"]).await;

    add_tproxy_shared_rules().await?;
    add_tproxy_rules(port).await?;
    let _ = command_output("ip", &["route", "flush", "cache"]).await;
    ACTIVE_RUNTIME.store(runtime_id, Ordering::Release);
    Ok(())
}

async fn add_tproxy_shared_rules() -> Result<()> {
    while command_success(
        "ip",
        &[
            "rule",
            "del",
            "fwmark",
            TPROXY_RULE_MARK,
            "priority",
            TPROXY_PRIORITY,
            "table",
            TPROXY_TABLE,
        ],
    )
    .await
    {}
    command_required(
        "ip",
        &[
            "rule",
            "add",
            "fwmark",
            TPROXY_RULE_MARK,
            "priority",
            TPROXY_PRIORITY,
            "table",
            TPROXY_TABLE,
        ],
    )
    .await?;
    command_required(
        "ip",
        &[
            "route",
            "replace",
            "local",
            "0.0.0.0/0",
            "dev",
            "lo",
            "table",
            TPROXY_TABLE,
        ],
    )
    .await?;
    Ok(())
}

fn tproxy_comment(port: u16) -> String {
    format!("CSQTT_TPROXY:{port}")
}

async fn add_tproxy_rules(port: u16) -> Result<()> {
    cleanup_stale_tproxy_rules().await;
    let port_arg = port.to_string();
    let comment = tproxy_comment(port);
    for protocol in ["tcp", "udp"] {
        command_required(
            "iptables",
            &[
                "-t",
                "mangle",
                "-I",
                "PREROUTING",
                "1",
                "-i",
                crate::tun_device::TUN_IFACE,
                "-s",
                crate::tun_device::TUN_SUBNET,
                "-p",
                protocol,
                "-m",
                "comment",
                "--comment",
                &comment,
                "-j",
                "TPROXY",
                "--tproxy-mark",
                TPROXY_RULE_MARK,
                "--on-port",
                &port_arg,
            ],
        )
        .await?;
    }
    command_required(
        "iptables",
        &[
            "-t",
            "raw",
            "-I",
            "PREROUTING",
            "1",
            "-i",
            crate::tun_device::TUN_IFACE,
            "-s",
            crate::tun_device::TUN_SUBNET,
            "-m",
            "comment",
            "--comment",
            &comment,
            "-j",
            "NOTRACK",
        ],
    )
    .await?;
    Ok(())
}

async fn deactivate_tproxy(port: u16) {
    let port_arg = port.to_string();
    let comment = tproxy_comment(port);
    for protocol in ["tcp", "udp"] {
        while command_success(
            "iptables",
            &[
                "-t",
                "mangle",
                "-D",
                "PREROUTING",
                "-i",
                crate::tun_device::TUN_IFACE,
                "-s",
                crate::tun_device::TUN_SUBNET,
                "-p",
                protocol,
                "-m",
                "comment",
                "--comment",
                &comment,
                "-j",
                "TPROXY",
                "--tproxy-mark",
                TPROXY_RULE_MARK,
                "--on-port",
                &port_arg,
            ],
        )
        .await
        {}
    }
    while command_success(
        "iptables",
        &[
            "-t",
            "raw",
            "-D",
            "PREROUTING",
            "-i",
            crate::tun_device::TUN_IFACE,
            "-s",
            crate::tun_device::TUN_SUBNET,
            "-m",
            "comment",
            "--comment",
            &comment,
            "-j",
            "NOTRACK",
        ],
    )
    .await
    {}
}

async fn cleanup_stale_tproxy_rules() {
    for (table, chain) in [("mangle", "PREROUTING"), ("raw", "PREROUTING")] {
        for _ in 0..8 {
            let Ok(rules) = command_output("iptables", &["-t", table, "-S", chain]).await else {
                break;
            };
            let numbers = marked_rule_numbers(&rules, chain, &["CSQTT_TPROXY"]);
            if numbers.is_empty() {
                break;
            }
            for number in numbers.into_iter().rev() {
                let number = number.to_string();
                let _ = command_output("iptables", &["-t", table, "-D", chain, &number]).await;
            }
        }
    }
}

fn marked_rule_numbers(rules: &str, chain: &str, markers: &[&str]) -> Vec<usize> {
    let prefix = format!("-A {chain}");
    let mut number = 0;
    let mut matches = Vec::new();
    for line in rules.lines() {
        if line == prefix || line.starts_with(&format!("{prefix} ")) {
            number += 1;
            if markers.iter().any(|marker| line.contains(marker)) {
                matches.push(number);
            }
        }
    }
    matches
}

async fn remove_from_subnet_rule() {
    while command_success(
        "ip",
        &[
            "rule",
            "del",
            "from",
            crate::tun_device::TUN_SUBNET,
            "priority",
            LEGACY_POLICY_PRIORITY,
            "table",
            LEGACY_POLICY_TABLE,
        ],
    )
    .await
    {}
}

async fn drop_new_flow_mark_rules() {
    while command_success(
        "iptables",
        &[
            "-t",
            "mangle",
            "-D",
            "PREROUTING",
            "-s",
            crate::tun_device::TUN_SUBNET,
            "-m",
            "conntrack",
            "--ctstate",
            "NEW",
            "-m",
            "comment",
            "--comment",
            MARK_COMMENT,
            "-j",
            "CONNMARK",
            "--set-xmark",
            POLICY_MARK,
        ],
    )
    .await
    {}
}

async fn cleanup_mark_rules() {
    drop_new_flow_mark_rules().await;
    while command_success(
        "iptables",
        &[
            "-t",
            "mangle",
            "-D",
            "PREROUTING",
            "-s",
            crate::tun_device::TUN_SUBNET,
            "-m",
            "comment",
            "--comment",
            MARK_COMMENT,
            "-j",
            "CONNMARK",
            "--restore-mark",
        ],
    )
    .await
    {}
    while command_success(
        "ip",
        &[
            "rule",
            "del",
            "fwmark",
            POLICY_MARK,
            "priority",
            LEGACY_POLICY_PRIORITY,
            "table",
            LEGACY_POLICY_TABLE,
        ],
    )
    .await
    {}
}

async fn cleanup_nat_exemption(tun_name: &str) {
    for comment in [NAT_COMMENT, LEGACY_NAT_COMMENT] {
        while command_success(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                crate::tun_device::TUN_SUBNET,
                "-o",
                tun_name,
                "-m",
                "comment",
                "--comment",
                comment,
                "-j",
                "ACCEPT",
            ],
        )
        .await
        {}
    }
}

async fn cleanup_all_nat_exemptions() {
    let rules = command_output("iptables-save", &[])
        .await
        .unwrap_or_default();
    let mut interfaces = std::collections::BTreeSet::new();
    for line in rules.lines() {
        if (line.contains(NAT_COMMENT) || line.contains(LEGACY_NAT_COMMENT))
            && let Some(index) = line.find(" -o ")
            && let Some(interface) = line[index + 4..].split_whitespace().next()
        {
            interfaces.insert(interface.to_owned());
        }
    }
    for interface in interfaces {
        cleanup_nat_exemption(&interface).await;
    }
}

async fn cleanup_legacy_quic_rule() {
    while command_success(
        "iptables",
        &[
            "-D",
            "FORWARD",
            "-s",
            crate::tun_device::TUN_SUBNET,
            "-p",
            "udp",
            "--dport",
            "443",
            "-m",
            "comment",
            "--comment",
            LEGACY_QUIC_COMMENT,
            "-j",
            "REJECT",
            "--reject-with",
            "icmp-port-unreachable",
        ],
    )
    .await
    {}
}

async fn cleanup_legacy_proxy_policy() {
    cleanup_legacy_quic_rule().await;
    cleanup_mark_rules().await;
    remove_from_subnet_rule().await;
    let _ = command_output("ip", &["route", "flush", "table", LEGACY_POLICY_TABLE]).await;
    cleanup_all_nat_exemptions().await;
}

async fn cleanup_shared_policy() {
    cleanup_stale_tproxy_rules().await;
    while command_success(
        "ip",
        &[
            "rule",
            "del",
            "fwmark",
            TPROXY_RULE_MARK,
            "priority",
            TPROXY_PRIORITY,
            "table",
            TPROXY_TABLE,
        ],
    )
    .await
    {}
    let _ = command_output("ip", &["route", "flush", "table", TPROXY_TABLE]).await;
    let _ = command_output("ip", &["route", "flush", "cache"]).await;
}

async fn verify_proxy_policy_clean() -> Result<()> {
    let rules = command_output("iptables-save", &[]).await?;
    for marker in [
        "CSQTT_TPROXY",
        NAT_COMMENT,
        MARK_COMMENT,
        LEGACY_NAT_COMMENT,
        LEGACY_QUIC_COMMENT,
    ] {
        if rules.contains(marker) {
            bail!("stale netfilter rule remains: {marker}");
        }
    }
    let rules = command_output("ip", &["-4", "rule", "show"]).await?;
    for line in rules.lines() {
        let owned_tproxy = line.trim_start().starts_with("100:")
            && line.contains("fwmark 0x1")
            && line.contains("lookup 100");
        let owned_legacy = line.trim_start().starts_with("1066:")
            && (line.contains("lookup 1066") || line.contains("fwmark 0x422"));
        if owned_tproxy || owned_legacy {
            bail!("stale policy rule remains: {}", line.trim());
        }
    }
    Ok(())
}

async fn command_success(program: &str, args: &[&str]) -> bool {
    tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .is_ok_and(|output| output.status.success())
}

async fn command_output(program: &str, args: &[&str]) -> Result<String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .with_context(|| format!("run {program}"))?;
    if !output.status.success() {
        bail!(
            "{} {} failed: {}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

async fn command_required(program: &str, args: &[&str]) -> Result<()> {
    command_output(program, args).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::{marked_rule_numbers, socks_udp_response, validate_config, validate_dns_response};
    use crate::model::LocalProxyProfile;

    fn config() -> LocalProxyProfile {
        LocalProxyProfile {
            id: "test".to_owned(),
            name: "Test".to_owned(),
            port: 45000,
            username: String::new(),
            password: String::new(),
        }
    }

    #[test]
    fn validates_proxy_credentials() {
        assert!(validate_config(&config()).is_ok());
        let mut value = config();
        value.password = "password".to_owned();
        assert!(validate_config(&value).is_err());
        value.username = "user\nname".to_owned();
        assert!(validate_config(&value).is_err());
    }

    #[test]
    fn parses_socks5_udp_ipv4_response() {
        let mut packet = vec![0, 0, 0, 1, 1, 1, 1, 1, 0, 53];
        packet.extend_from_slice(b"dns");
        let (source, payload) = socks_udp_response(&packet).unwrap();
        assert_eq!(payload, b"dns");
        assert_eq!(source, "1.1.1.1:53".parse().unwrap());
    }

    #[test]
    fn accepts_only_matching_dns_response() {
        let mut response = vec![0u8; 12];
        response[..2].copy_from_slice(&super::DNS_PROBE_ID.to_be_bytes());
        response[2] = 0x80;
        assert!(validate_dns_response(&response).is_ok());
        response[0] ^= 1;
        assert!(validate_dns_response(&response).is_err());
    }

    #[test]
    fn locates_quoted_tproxy_rules_by_chain_position() {
        let rules = concat!(
            "-P PREROUTING ACCEPT\n",
            "-A PREROUTING -i csqtt1 -p udp -m comment --comment \"CSQTT_TPROXY:10669\" -j TPROXY\n",
            "-A PREROUTING -p tcp -j ACCEPT\n",
            "-A PREROUTING -i csqtt1 -p tcp -m comment --comment \"CSQTT_TPROXY:10669\" -j TPROXY\n",
        );
        assert_eq!(
            marked_rule_numbers(rules, "PREROUTING", &["CSQTT_TPROXY"]),
            vec![1, 3]
        );
    }

    #[test]
    fn ignores_other_chains_and_is_idempotent_after_cleanup() {
        let rules = concat!(
            "-A INPUT -m comment --comment \"CSQTT_TPROXY:10669\" -j ACCEPT\n",
            "-A PREROUTING -p tcp -j ACCEPT\n",
        );
        assert!(marked_rule_numbers(rules, "PREROUTING", &["CSQTT_TPROXY"]).is_empty());
        assert!(marked_rule_numbers("", "PREROUTING", &["CSQTT_TPROXY"]).is_empty());
    }
}
