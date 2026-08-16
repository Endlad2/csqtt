// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#[cfg(not(target_os = "linux"))]
use crate::model::LocalProxyProfile;
#[cfg(not(target_os = "linux"))]
use crate::proxy_route::LogFn;
#[cfg(not(target_os = "linux"))]
use anyhow::{Result, bail};
#[cfg(not(target_os = "linux"))]
use std::sync::Arc;

#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
pub const TCP_SESSION_LIMIT: usize = 2048;
#[cfg(target_os = "linux")]
pub const UDP_FLOW_LIMIT: usize = 2048;
#[cfg(target_os = "linux")]
pub const UDP_FLOW_IDLE: Duration = Duration::from_secs(60);
#[cfg(target_os = "linux")]
const SOCKS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const ENGINE_DRAIN_DEADLINE: Duration = Duration::from_secs(3);
const TPROXY_BASE_PORT: u16 = 10666;

#[derive(Default)]
pub struct TproxyStats {
    pub tcp_active: std::sync::atomic::AtomicUsize,
    pub udp_active: std::sync::atomic::AtomicUsize,
    tcp_peak: std::sync::atomic::AtomicUsize,
    udp_peak: std::sync::atomic::AtomicUsize,
    tcp_total: std::sync::atomic::AtomicU64,
    udp_total: std::sync::atomic::AtomicU64,
}

#[derive(Clone, Copy, Default)]
pub struct TproxyStatsSnapshot {
    pub tcp_active: usize,
    pub udp_active: usize,
    pub tcp_peak: usize,
    pub udp_peak: usize,
    pub tcp_total: u64,
    pub udp_total: u64,
}

impl TproxyStats {
    fn tcp_started(&self) {
        let active = self
            .tcp_active
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        self.tcp_peak
            .fetch_max(active, std::sync::atomic::Ordering::Relaxed);
        self.tcp_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn tcp_finished(&self) {
        self.tcp_active
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn udp_started(&self) {
        let active = self
            .udp_active
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        self.udp_peak
            .fetch_max(active, std::sync::atomic::Ordering::Relaxed);
        self.udp_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn udp_finished(&self) {
        self.udp_active
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> TproxyStatsSnapshot {
        TproxyStatsSnapshot {
            tcp_active: self.tcp_active.load(std::sync::atomic::Ordering::Relaxed),
            udp_active: self.udp_active.load(std::sync::atomic::Ordering::Relaxed),
            tcp_peak: self.tcp_peak.load(std::sync::atomic::Ordering::Relaxed),
            udp_peak: self.udp_peak.load(std::sync::atomic::Ordering::Relaxed),
            tcp_total: self.tcp_total.load(std::sync::atomic::Ordering::Relaxed),
            udp_total: self.udp_total.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

pub fn tproxy_port(runtime_id: u64) -> u16 {
    TPROXY_BASE_PORT + (runtime_id % 50_000) as u16
}

#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub use linux::{TproxySockets, bind_sockets, run};

#[cfg(not(target_os = "linux"))]
pub struct TproxySockets {
    _private: (),
}

#[cfg(not(target_os = "linux"))]
pub fn bind_sockets(_port: u16) -> Result<TproxySockets> {
    bail!("TPROXY forwarding is supported only on Linux servers")
}

#[cfg(not(target_os = "linux"))]
pub async fn run(
    _sockets: TproxySockets,
    _config: Arc<LocalProxyProfile>,
    _cancel: tokio_util::sync::CancellationToken,
    _log: LogFn,
    _stats: Arc<TproxyStats>,
) -> (u64, u64, u64) {
    (0, 0, 0)
}

#[cfg(target_os = "linux")]
mod linux {
    use crate::model::LocalProxyProfile;
    use crate::proxy_route::{LogFn, socks_command, socks_udp_response};
    use anyhow::{Context, Result};
    use socket2::{Domain, MaybeUninitSlice, MsgHdrMut, Protocol, SockAddr, Socket, Type};
    use std::collections::HashMap;
    use std::collections::VecDeque;
    use std::io;
    use std::mem;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::os::fd::{AsRawFd, RawFd};
    use std::ptr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tokio::io::unix::AsyncFd;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::task::JoinSet;
    use tokio_util::sync::CancellationToken;

    const IP_TRANSPARENT: libc::c_int = 19;
    pub(super) const IP_RECVORIGDSTADDR: libc::c_int = 20;
    const LISTEN_BACKLOG: libc::c_int = 4096;
    pub(super) const UDP_RECV_BUF: usize = 65_535;
    const UDP_CONTROL_BUF: usize = 64;
    const ASSOCIATION_BACKOFF: Duration = Duration::from_secs(2);
    const ASSOCIATION_POOL_TARGET: usize = 4;
    const OPENING_PENDING_LIMIT: usize = 64;
    const MAX_CONCURRENT_OPENINGS: usize = 128;

    pub struct TproxySockets {
        tcp: TcpListener,
        udp: Arc<UdpTproxy>,
    }

    pub fn bind_sockets(port: u16) -> Result<TproxySockets> {
        let tcp = bind_tcp_listener(port).context("bind transparent TCP listener")?;
        let udp = Arc::new(UdpTproxy::bind(port).context("bind transparent UDP socket")?);
        Ok(TproxySockets { tcp, udp })
    }

    pub async fn run(
        sockets: TproxySockets,
        config: Arc<LocalProxyProfile>,
        cancel: CancellationToken,
        log: LogFn,
        stats: Arc<super::TproxyStats>,
    ) -> (u64, u64, u64) {
        let udp_task = tokio::spawn(run_udp(
            sockets.udp.clone(),
            config.clone(),
            cancel.clone(),
            log.clone(),
            stats.clone(),
        ));
        let tcp_sessions = run_tcp(sockets.tcp, config, cancel, log, stats).await;
        let (udp_flows, udp_datagrams) = udp_task.await.unwrap_or((0, 0));
        (tcp_sessions, udp_flows, udp_datagrams)
    }

    fn set_int_option(
        fd: RawFd,
        level: libc::c_int,
        name: libc::c_int,
        value: libc::c_int,
    ) -> io::Result<()> {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &value as *const libc::c_int as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn bind_tcp_listener(port: u16) -> Result<TcpListener> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        set_int_option(socket.as_raw_fd(), libc::IPPROTO_IP, IP_TRANSPARENT, 1)?;
        let _ = socket.set_recv_buffer_size(256 * 1024);
        let _ = socket.set_send_buffer_size(256 * 1024);
        socket.set_nonblocking(true)?;
        socket.bind(&SockAddr::from(SocketAddr::from((
            Ipv4Addr::UNSPECIFIED,
            port,
        ))))?;
        socket.listen(LISTEN_BACKLOG)?;
        let listener: std::net::TcpListener = socket.into();
        Ok(TcpListener::from_std(listener)?)
    }

    async fn run_tcp(
        listener: TcpListener,
        config: Arc<LocalProxyProfile>,
        cancel: CancellationToken,
        _log: LogFn,
        stats: Arc<super::TproxyStats>,
    ) -> u64 {
        let mut sessions: JoinSet<()> = JoinSet::new();
        let mut served: u64 = 0;
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = sessions.join_next(), if !sessions.is_empty() => {},
                accept = listener.accept() => match accept {
                    Ok((connection, _client)) => {
                        let Ok(destination) = connection.local_addr() else {
                            continue;
                        };
                        if stats.tcp_active.load(Ordering::Relaxed) >= super::TCP_SESSION_LIMIT {
                            continue;
                        }
                        stats.tcp_started();
                        served += 1;
                        sessions.spawn(handle_tcp_session(
                            connection,
                            destination,
                            config.clone(),
                            stats.clone(),
                        ));
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                },
            }
        }
        let deadline = Instant::now() + super::ENGINE_DRAIN_DEADLINE;
        while !sessions.is_empty() {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            if tokio::time::timeout(deadline - now, sessions.join_next())
                .await
                .is_err()
            {
                break;
            }
        }
        sessions.abort_all();
        served
    }

    const TCP_IDLE_LIMIT_MS: i64 = 600_000;
    const TCP_HARD_LIMIT_MS: i64 = 7_200_000;
    const TCP_WATCHDOG_TICK: Duration = Duration::from_secs(30);
    pub(super) const RELAY_BUF: usize = 65_536;
    const _: () = assert!(super::TCP_SESSION_LIMIT * 2 * RELAY_BUF <= 256 * 1024 * 1024);
    const _: () = assert!(super::UDP_FLOW_LIMIT * UDP_RECV_BUF <= 256 * 1024 * 1024);

    struct TcpActiveGuard(Arc<super::TproxyStats>);

    impl Drop for TcpActiveGuard {
        fn drop(&mut self) {
            self.0.tcp_finished();
        }
    }

    pub(super) fn session_expired(last_ms: i64, start_ms: i64, now_ms: i64) -> bool {
        now_ms.saturating_sub(last_ms) > TCP_IDLE_LIMIT_MS
            || now_ms.saturating_sub(start_ms) > TCP_HARD_LIMIT_MS
    }

    async fn handle_tcp_session(
        client: TcpStream,
        destination: SocketAddr,
        config: Arc<LocalProxyProfile>,
        stats: Arc<super::TproxyStats>,
    ) {
        let _active = TcpActiveGuard(stats);
        client.set_nodelay(true).ok();
        let _ = socket2::SockRef::from(&client).set_keepalive(true);
        let _ = socket2::SockRef::from(&client).set_recv_buffer_size(256 * 1024);
        let _ = socket2::SockRef::from(&client).set_send_buffer_size(256 * 1024);
        let handshake = tokio::time::timeout(
            super::SOCKS_HANDSHAKE_TIMEOUT,
            socks_command(&config, 0x01, destination),
        )
        .await;
        let upstream = match handshake {
            Ok(Ok((stream, _bound))) => stream,
            _ => return,
        };
        upstream.set_nodelay(true).ok();
        let _ = socket2::SockRef::from(&upstream).set_recv_buffer_size(256 * 1024);
        let _ = socket2::SockRef::from(&upstream).set_send_buffer_size(256 * 1024);

        let session_cancel = CancellationToken::new();
        let _cancel_guard = session_cancel.clone().drop_guard();
        let start_ms = now_ms();
        let last = Arc::new(AtomicI64::new(start_ms));
        let watchdog_last = last.clone();
        let watchdog_cancel = session_cancel.clone();
        let watchdog = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = watchdog_cancel.cancelled() => break,
                    _ = tokio::time::sleep(TCP_WATCHDOG_TICK) => {}
                }
                if session_expired(watchdog_last.load(Ordering::Relaxed), start_ms, now_ms()) {
                    watchdog_cancel.cancel();
                    break;
                }
            }
        });

        let (mut client_rx, mut client_tx) = tokio::io::split(client);
        let (mut upstream_rx, mut upstream_tx) = tokio::io::split(upstream);
        let to_upstream = relay_direction(&mut client_rx, &mut upstream_tx, &last, &session_cancel);
        let to_client = relay_direction(&mut upstream_rx, &mut client_tx, &last, &session_cancel);
        tokio::select! {
            _ = to_upstream => {}
            _ = to_client => {}
        }
        session_cancel.cancel();
        let _ = watchdog.await;
    }

    async fn relay_direction<R, W>(
        reader: &mut R,
        writer: &mut W,
        last: &AtomicI64,
        cancel: &CancellationToken,
    ) where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut buf = Box::new([0u8; RELAY_BUF]);
        loop {
            let read = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                result = reader.read(&mut buf[..]) => result,
            };
            let received = match read {
                Ok(0) | Err(_) => break,
                Ok(received) => received,
            };
            let written = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                result = writer.write_all(&buf[..received]) => result,
            };
            if written.is_err() {
                break;
            }
            last.store(now_ms(), Ordering::Relaxed);
        }
        let _ = writer.shutdown().await;
    }

    struct UdpTproxy {
        socket: Socket,
    }

    impl UdpTproxy {
        fn bind(port: u16) -> io::Result<Self> {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_reuse_address(true)?;
            set_int_option(socket.as_raw_fd(), libc::IPPROTO_IP, IP_TRANSPARENT, 1)?;
            set_int_option(socket.as_raw_fd(), libc::IPPROTO_IP, IP_RECVORIGDSTADDR, 1)?;
            let _ = socket.set_recv_buffer_size(512 * 1024);
            let _ = socket.set_send_buffer_size(512 * 1024);
            socket.set_nonblocking(true)?;
            socket.bind(&SockAddr::from(SocketAddr::from((
                Ipv4Addr::UNSPECIFIED,
                port,
            ))))?;
            Ok(Self { socket })
        }

        fn try_recv(
            &self,
            buf: &mut [mem::MaybeUninit<u8>],
            control: &mut [mem::MaybeUninit<u8>],
        ) -> io::Result<(usize, SocketAddrV4, SocketAddrV4)> {
            let mut addr =
                SockAddr::from(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
            let (received, control_len) = {
                let mut slices = [MaybeUninitSlice::new(buf)];
                let mut msg = MsgHdrMut::new()
                    .with_addr(&mut addr)
                    .with_buffers(&mut slices)
                    .with_control(control);
                let received = self.socket.recvmsg(&mut msg, 0)?;
                (received, msg.control_len().min(control.len()))
            };
            let client = addr.as_socket_ipv4().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "non-IPv4 client datagram")
            })?;
            let control_bytes =
                unsafe { std::slice::from_raw_parts(control.as_ptr() as *const u8, control_len) };
            let destination = parse_orig_dst(control_bytes).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing IP_RECVORIGDSTADDR")
            })?;
            Ok((received, client, destination))
        }
    }

    impl AsRawFd for UdpTproxy {
        fn as_raw_fd(&self) -> RawFd {
            self.socket.as_raw_fd()
        }
    }

    pub(super) fn parse_orig_dst(mut control: &[u8]) -> Option<SocketAddrV4> {
        while control.len() >= mem::size_of::<libc::cmsghdr>() {
            let header: &libc::cmsghdr = unsafe { &*(control.as_ptr() as *const libc::cmsghdr) };
            let length = header.cmsg_len as usize;
            if length < mem::size_of::<libc::cmsghdr>() || length > control.len() {
                break;
            }
            if header.cmsg_level == libc::IPPROTO_IP && header.cmsg_type == IP_RECVORIGDSTADDR {
                let data = &control[mem::size_of::<libc::cmsghdr>()..length];
                if data.len() >= mem::size_of::<libc::sockaddr_in>() {
                    let sockaddr: libc::sockaddr_in =
                        unsafe { ptr::read(data.as_ptr() as *const libc::sockaddr_in) };
                    if sockaddr.sin_family == libc::AF_INET as libc::sa_family_t {
                        return Some(SocketAddrV4::new(
                            Ipv4Addr::from(sockaddr.sin_addr.s_addr.to_ne_bytes()),
                            u16::from_be(sockaddr.sin_port),
                        ));
                    }
                }
            }
            let advance = (length + 3) & !3;
            if advance == 0 {
                break;
            }
            control = &control[advance.min(control.len())..];
        }
        None
    }

    struct RawReplySocket {
        socket: Socket,
    }

    impl RawReplySocket {
        fn new() -> io::Result<Self> {
            let socket = Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::from(libc::IPPROTO_RAW)),
            )?;
            socket.set_nonblocking(true)?;
            set_int_option(socket.as_raw_fd(), libc::IPPROTO_IP, libc::IP_HDRINCL, 1)?;
            let _ = socket.set_send_buffer_size(512 * 1024);
            Ok(Self { socket })
        }

        fn send_reply(
            &self,
            source_ip: Ipv4Addr,
            dest_ip: Ipv4Addr,
            source_port: u16,
            dest_port: u16,
            payload: &[u8],
        ) {
            let total_len = 20 + 8 + payload.len();
            if total_len > 65535 {
                return;
            }
            let mut packet = [0u8; 28];
            // IPv4 header (20 bytes)
            packet[0] = 0x45; // Version 4, IHL 5
            packet[1] = 0x00; // DSCP / ECN
            packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            packet[4..6].copy_from_slice(&0u16.to_be_bytes()); // ID
            packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Flags: DF
            packet[8] = 64; // TTL
            packet[9] = libc::IPPROTO_UDP as u8; // Protocol 17
            // Checksum will be computed
            packet[12..16].copy_from_slice(&source_ip.octets());
            packet[16..20].copy_from_slice(&dest_ip.octets());
            let ip_checksum = calc_checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

            // UDP header (8 bytes)
            let udp_len = (8 + payload.len()) as u16;
            packet[20..22].copy_from_slice(&source_port.to_be_bytes());
            packet[22..24].copy_from_slice(&dest_port.to_be_bytes());
            packet[24..26].copy_from_slice(&udp_len.to_be_bytes());
            packet[26..28].copy_from_slice(&0u16.to_be_bytes()); // Checksum optional in IPv4 UDP

            // Send using sendmsg with 2 iovecs: header (28 bytes) + payload
            let iov = [
                libc::iovec {
                    iov_base: packet.as_ptr() as *mut libc::c_void,
                    iov_len: 28,
                },
                libc::iovec {
                    iov_base: payload.as_ptr() as *mut libc::c_void,
                    iov_len: payload.len(),
                },
            ];
            let raw_dest = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(dest_ip.octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                let mut msg: libc::msghdr = mem::zeroed();
                msg.msg_name = &raw_dest as *const libc::sockaddr_in as *mut libc::c_void;
                msg.msg_namelen = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                msg.msg_iov = iov.as_ptr() as *mut libc::iovec;
                msg.msg_iovlen = 2;
                libc::sendmsg(self.socket.as_raw_fd(), &msg, 0);
            }
        }
    }

    fn calc_checksum(header: &[u8]) -> u16 {
        let mut sum = 0u32;
        for i in (0..header.len()).step_by(2) {
            let word = u16::from_be_bytes([header[i], header[i + 1]]);
            sum += word as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !sum as u16
    }

    struct Association {
        relay: Arc<UdpSocket>,
        relay_addr: SocketAddr,
        _control: TcpStream,
    }

    async fn create_association(config: &LocalProxyProfile) -> Option<Association> {
        let associate = tokio::time::timeout(
            super::SOCKS_HANDSHAKE_TIMEOUT,
            socks_command(config, 0x03, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
        )
        .await;
        let Ok(Ok((control_stream, relay_addr))) = associate else {
            return None;
        };
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
        socket.set_reuse_address(true).ok()?;
        let _ = socket.set_recv_buffer_size(512 * 1024);
        let _ = socket.set_send_buffer_size(512 * 1024);
        socket.set_nonblocking(true).ok()?;
        socket
            .bind(&SockAddr::from(SocketAddr::from((
                Ipv4Addr::UNSPECIFIED,
                0,
            ))))
            .ok()?;
        let std_socket: std::net::UdpSocket = socket.into();
        let relay = UdpSocket::from_std(std_socket).ok()?;
        Some(Association {
            relay: Arc::new(relay),
            relay_addr,
            _control: control_stream,
        })
    }

    fn spawn_refill(
        config: Arc<LocalProxyProfile>,
        tx: tokio::sync::mpsc::Sender<Option<Association>>,
        delay: Option<Duration>,
    ) {
        tokio::spawn(async move {
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            let association = create_association(&config).await;
            let _ = tx.send(association).await;
        });
    }

    fn send_frame(flow: &UdpFlow, destination: SocketAddrV4, payload: &[u8]) {
        // Zero-allocation SOCKS5 UDP send using stack buffer or sendmsg
        // SOCKS5 UDP IPv4 header: RSV(2) + FRAG(1) + ATYP(1) + IP(4) + PORT(2) = 10 bytes
        let mut header = [0u8; 10];
        header[0] = 0x00; // RSV
        header[1] = 0x00; // RSV
        header[2] = 0x00; // FRAG
        header[3] = 0x01; // ATYP IPv4
        header[4..8].copy_from_slice(&destination.ip().octets());
        header[8..10].copy_from_slice(&destination.port().to_be_bytes());

        let raw_dest = match flow.relay_addr {
            SocketAddr::V4(v4) => libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            },
            SocketAddr::V6(_) => return,
        };

        let iov = [
            libc::iovec {
                iov_base: header.as_ptr() as *mut libc::c_void,
                iov_len: 10,
            },
            libc::iovec {
                iov_base: payload.as_ptr() as *mut libc::c_void,
                iov_len: payload.len(),
            },
        ];
        unsafe {
            let mut msg: libc::msghdr = mem::zeroed();
            msg.msg_name = &raw_dest as *const libc::sockaddr_in as *mut libc::c_void;
            msg.msg_namelen = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            msg.msg_iov = iov.as_ptr() as *mut libc::iovec;
            msg.msg_iovlen = 2;
            libc::sendmsg(flow.relay.as_raw_fd(), &msg, 0);
        }
    }

    fn evict_if_needed(flows: &mut HashMap<SocketAddr, UdpFlow>, stats: &super::TproxyStats) {
        if flows.len() >= super::UDP_FLOW_LIMIT
            && let Some(oldest) = flows
                .iter()
                .min_by_key(|(_, existing)| existing.last_seen.load(Ordering::Relaxed))
                .map(|(key, _)| *key)
            && let Some(evicted) = flows.remove(&oldest)
        {
            evicted.cancel.cancel();
            stats.udp_finished();
        }
    }

    struct UdpFlow {
        relay: Arc<UdpSocket>,
        relay_addr: SocketAddr,
        _control: TcpStream,
        last_seen: Arc<AtomicI64>,
        finished: Arc<AtomicBool>,
        cancel: CancellationToken,
    }

    impl UdpFlow {
        fn start(
            client: SocketAddrV4,
            association: Association,
            stats: &Arc<super::TproxyStats>,
            raw_socket: Arc<RawReplySocket>,
        ) -> Self {
            let last_seen = Arc::new(AtomicI64::new(now_ms()));
            let finished = Arc::new(AtomicBool::new(false));
            let cancel = CancellationToken::new();
            tokio::spawn(relay_responses(
                association.relay.clone(),
                client,
                last_seen.clone(),
                finished.clone(),
                cancel.clone(),
                raw_socket,
            ));
            stats.udp_started();
            Self {
                relay: association.relay,
                relay_addr: association.relay_addr,
                _control: association._control,
                last_seen,
                finished,
                cancel,
            }
        }

        fn touch(&self) {
            self.last_seen.store(now_ms(), Ordering::Relaxed);
        }

        fn idle(&self) -> bool {
            now_ms().saturating_sub(self.last_seen.load(Ordering::Relaxed))
                > super::UDP_FLOW_IDLE.as_millis() as i64
        }
    }

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as i64)
            .unwrap_or(0)
    }

    async fn run_udp(
        socket: Arc<UdpTproxy>,
        config: Arc<LocalProxyProfile>,
        cancel: CancellationToken,
        log: LogFn,
        stats: Arc<super::TproxyStats>,
    ) -> (u64, u64) {
        let raw_socket = match RawReplySocket::new() {
            Ok(s) => Arc::new(s),
            Err(e) => {
                log("ERROR", &format!("Failed to bind TPROXY raw socket: {e}"));
                return (0, 0);
            }
        };
        let async_fd = match AsyncFd::new(socket.clone()) {
            Ok(fd) => fd,
            Err(error) => {
                log(
                    "ERROR",
                    &format!("TPROXY UDP socket is not pollable: {error}"),
                );
                return (0, 0);
            }
        };
        let mut flows: HashMap<SocketAddr, UdpFlow> = HashMap::new();
        let mut opening: HashMap<SocketAddr, Vec<(SocketAddrV4, Vec<u8>)>> = HashMap::new();
        let mut pool: VecDeque<Association> = VecDeque::new();
        let (pool_tx, mut pool_rx) =
            tokio::sync::mpsc::channel::<Option<Association>>(ASSOCIATION_POOL_TARGET * 2);
        let (open_tx, mut open_rx) =
            tokio::sync::mpsc::channel::<(SocketAddr, Option<Association>)>(256);
        let mut refills_in_flight = 0usize;
        for _ in 0..ASSOCIATION_POOL_TARGET {
            spawn_refill(config.clone(), pool_tx.clone(), None);
            refills_in_flight += 1;
        }
        let mut sweep = tokio::time::interval(Duration::from_secs(15));
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut buf: Vec<mem::MaybeUninit<u8>> = vec![mem::MaybeUninit::uninit(); UDP_RECV_BUF];
        let mut control: Vec<mem::MaybeUninit<u8>> =
            vec![mem::MaybeUninit::uninit(); UDP_CONTROL_BUF];
        let mut association_failure = None::<Instant>;
        let mut served: u64 = 0;
        let mut datagrams: u64 = 0;
        let mut recv_errors_logged = false;

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = sweep.tick() => {
                    flows.retain(|_, flow| {
                        if flow.idle() || flow.finished.load(Ordering::Relaxed) {
                            flow.cancel.cancel();
                            stats.udp_finished();
                            false
                        } else {
                            true
                        }
                    });
                }
                received_pool = pool_rx.recv() => {
                    let Some(received) = received_pool else { break };
                    refills_in_flight = refills_in_flight.saturating_sub(1);
                    let failed = received.is_none();
                    if let Some(association) = received
                        && pool.len() < ASSOCIATION_POOL_TARGET
                    {
                        pool.push_back(association);
                    }
                    while pool.len() + refills_in_flight < ASSOCIATION_POOL_TARGET {
                        spawn_refill(
                            config.clone(),
                            pool_tx.clone(),
                            if failed { Some(ASSOCIATION_BACKOFF) } else { None },
                        );
                        refills_in_flight += 1;
                    }
                }
                opened = open_rx.recv() => {
                    let Some((key, association)) = opened else { break };
                    let pending = opening.remove(&key).unwrap_or_default();
                    let SocketAddr::V4(client) = key else { continue };
                    match association {
                        Some(association) => {
                            association_failure = None;
                            evict_if_needed(&mut flows, &stats);
                            let flow = UdpFlow::start(client, association, &stats, raw_socket.clone());
                            served += 1;
                            for (destination, payload) in pending {
                                send_frame(&flow, destination, &payload);
                            }
                            flows.insert(key, flow);
                        }
                        None => {
                            if association_failure.is_none() {
                                log(
                                    "WARNING",
                                    &format!(
                                        "SOCKS5 UDP association failed for {client}; datagrams are dropped until the proxy recovers"
                                    ),
                                );
                            }
                            association_failure = Some(Instant::now());
                        }
                    }
                }
                ready = async_fd.readable() => {
                    let Ok(mut guard) = ready else { break };
                    loop {
                        match socket.try_recv(&mut buf, &mut control) {
                            Ok((received, client, destination)) => {
                                datagrams += 1;
                                let payload = unsafe {
                                    std::slice::from_raw_parts(buf.as_ptr() as *const u8, received)
                                };
                                let key = SocketAddr::V4(client);
                                let existing_ok = flows
                                    .get(&key)
                                    .map(|flow| !flow.finished.load(Ordering::Relaxed))
                                    .unwrap_or(false);
                                if existing_ok {
                                    let flow = &flows[&key];
                                    flow.touch();
                                    send_frame(flow, destination, payload);
                                    continue;
                                }
                                if let Some(stale) = flows.remove(&key) {
                                    stale.cancel.cancel();
                                    stats.udp_finished();
                                }
                                if let Some(pending) = opening.get_mut(&key) {
                                    if pending.len() < OPENING_PENDING_LIMIT {
                                        pending.push((destination, payload.to_vec()));
                                    }
                                    continue;
                                }
                                if let Some(at) = association_failure {
                                    if at.elapsed() < ASSOCIATION_BACKOFF {
                                        continue;
                                    }
                                    association_failure = None;
                                }
                                if opening.len() >= MAX_CONCURRENT_OPENINGS {
                                    continue;
                                }
                                if let Some(association) = pool.pop_front() {
                                    evict_if_needed(&mut flows, &stats);
                                    let flow = UdpFlow::start(client, association, &stats, raw_socket.clone());
                                    served += 1;
                                    send_frame(&flow, destination, payload);
                                    flows.insert(key, flow);
                                } else {
                                    let task_tx = open_tx.clone();
                                    let task_config = config.clone();
                                    tokio::spawn(async move {
                                        let association = create_association(&task_config).await;
                                        let _ = task_tx.send((key, association)).await;
                                    });
                                    opening.insert(key, vec![(destination, payload.to_vec())]);
                                }
                                while pool.len() + refills_in_flight < ASSOCIATION_POOL_TARGET {
                                    spawn_refill(config.clone(), pool_tx.clone(), None);
                                    refills_in_flight += 1;
                                }
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                guard.clear_ready();
                                break;
                            }
                            Err(error) => {
                                if !recv_errors_logged {
                                    recv_errors_logged = true;
                                    log(
                                        "WARNING",
                                        &format!("TPROXY UDP receive error: {error}"),
                                    );
                                }
                                guard.clear_ready();
                                tokio::time::sleep(Duration::from_millis(50)).await;
                                break;
                            }
                        }
                    }
                }
            }
        }
        for (_, flow) in flows.drain() {
            flow.cancel.cancel();
            stats.udp_finished();
        }
        opening.clear();
        (served, datagrams)
    }

    async fn relay_responses(
        relay: Arc<UdpSocket>,
        client: SocketAddrV4,
        last_seen: Arc<AtomicI64>,
        finished: Arc<AtomicBool>,
        cancel: CancellationToken,
        raw_socket: Arc<RawReplySocket>,
    ) {
        let mut buf = Box::new([0u8; UDP_RECV_BUF]);
        loop {
            while let Ok((length, _source)) = relay.try_recv_from(&mut buf[..]) {
                last_seen.store(now_ms(), Ordering::Relaxed);
                if let Ok((source, payload)) = socks_udp_response(&buf[..length])
                    && let SocketAddr::V4(v4) = source
                {
                    raw_socket.send_reply(
                        *v4.ip(),
                        *client.ip(),
                        v4.port(),
                        client.port(),
                        payload,
                    );
                }
                if cancel.is_cancelled() {
                    return;
                }
            }
            let received = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                result = tokio::time::timeout(super::UDP_FLOW_IDLE, relay.readable()) => result,
            };
            match received {
                Ok(Ok(())) => {}
                _ => break,
            }
        }
        finished.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::{TproxyStats, tproxy_port};

    #[cfg(target_os = "linux")]
    #[test]
    fn engine_drain_finishes_before_route_deactivation_timeout() {
        assert!(super::ENGINE_DRAIN_DEADLINE < std::time::Duration::from_secs(5));
    }

    #[test]
    fn ports_are_unique_per_runtime_and_in_range() {
        let first = tproxy_port(1);
        let second = tproxy_port(2);
        assert_ne!(first, second);
        assert!(first >= 10666);
        assert_eq!(tproxy_port(1), first);
    }

    #[test]
    fn runtime_stats_track_active_peak_and_total() {
        let stats = TproxyStats::default();
        stats.tcp_started();
        stats.tcp_started();
        stats.tcp_finished();
        stats.udp_started();
        stats.udp_finished();
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.tcp_active, 1);
        assert_eq!(snapshot.tcp_peak, 2);
        assert_eq!(snapshot.tcp_total, 2);
        assert_eq!(snapshot.udp_active, 0);
        assert_eq!(snapshot.udp_peak, 1);
        assert_eq!(snapshot.udp_total, 1);
    }

    #[test]
    fn udp_flow_keys_do_not_collide_between_clients() {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
        let client_a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 66, 67, 1), 5353));
        let client_b = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 66, 67, 2), 5353));
        let mut flows = std::collections::HashMap::new();
        flows.insert(client_a, 1u8);
        flows.insert(client_b, 2u8);
        assert_eq!(flows.len(), 2);
        assert_eq!(flows.get(&client_a).copied(), Some(1));
        assert_eq!(flows.get(&client_b).copied(), Some(2));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn session_expiry_respects_idle_and_hard_limits() {
        use super::linux::session_expired;
        let start = 1_000_000i64;
        assert!(!session_expired(start + 1, start, start + 600_001));
        assert!(session_expired(start + 1, start, start + 600_002));
        assert!(session_expired(start + 7_200_001, start, start + 7_200_001));
        assert!(!session_expired(start, start, start));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_original_destination_from_control_message() {
        use std::mem;
        use std::net::Ipv4Addr;
        use std::ptr;
        let mut control = vec![0u8; 64];
        unsafe {
            let header = control.as_mut_ptr() as *mut libc::cmsghdr;
            (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::sockaddr_in>() as u32) as _;
            (*header).cmsg_level = libc::IPPROTO_IP;
            (*header).cmsg_type = super::linux::IP_RECVORIGDSTADDR;
            let sockaddr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 443u16.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes([93, 184, 216, 34]),
                },
                sin_zero: [0; 8],
            };
            ptr::copy_nonoverlapping(
                &sockaddr as *const libc::sockaddr_in as *const u8,
                libc::CMSG_DATA(header),
                mem::size_of::<libc::sockaddr_in>(),
            );
        }
        let parsed = match super::linux::parse_orig_dst(&control) {
            Some(parsed) => parsed,
            None => panic!("control message should contain the original destination"),
        };
        assert_eq!(*parsed.ip(), Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(parsed.port(), 443);
    }
}
