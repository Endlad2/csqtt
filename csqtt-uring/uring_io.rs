// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::packet::{
    COMPLETION_BATCH, PACKET_CAPACITY, PacketBuffer, TUN_MTU, TUN_TX_SLOTS, UDP_RX_SLOTS,
    UDP_TX_SLOTS, socket_addr_to_storage, storage_to_socket_addr,
};
use crate::perf::thread_cpu_time_ns;
use anyhow::{Context, Result, anyhow, bail};
use io_uring::{IoUring, cqueue, opcode, squeue, types};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::VecDeque,
    mem::MaybeUninit,
    net::SocketAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    ptr::NonNull,
    sync::atomic::{AtomicU16, Ordering},
    time::Instant,
};

const TAG_SHIFT: u64 = 56;
const TAG_MASK: u64 = 0xff << TAG_SHIFT;
const TAG_UDP_RX: u64 = 1;
const TAG_TUN_RX: u64 = 2;
const TAG_UDP_TX_READY: u64 = 3;
const TAG_TUN_TX: u64 = 4;
const TAG_EVENTFD: u64 = 5;
const TAG_TICK: u64 = 6;
const TAG_UDP_RX_MULTI: u64 = 7;
const TICK_INTERVAL_MS: i64 = 100;
const UDP_RECV_BUFFER_BYTES: usize = 16 * 1024 * 1024;
const UDP_SEND_BUFFER_BYTES: usize = 8 * 1024 * 1024;
const FEC_TX_SLOT_RESERVE: usize = 32;
const UDP_RX_BUFFER_GROUP: u16 = 1;
const UDP_RX_MULTI_BUFFERS: usize = 256;
const UDP_RX_MULTI_BUFFER_SIZE: usize = PACKET_CAPACITY + 256;
const CQ_WAIT_BATCH: usize = 8;
const CQ_ENTRIES: u32 = 4096;
const TUN_RX_DRAIN_BATCH: usize = 32;
const FIXED_UDP: u32 = 0;
const FIXED_TUN: u32 = 1;
const FIXED_EVENT: u32 = 2;
const FIXED_TICK: u32 = 3;
const URING_MODE_BASIC: u64 = 1;
const URING_MODE_SINGLE: u64 = 2;
const URING_MODE_COOP: u64 = 3;
const URING_MODE_COOP_TASKRUN: u64 = 4;
const URING_MODE_DEFER: u64 = 5;

#[derive(Clone, Copy)]
pub struct Completion {
    pub user_data: u64,
    pub result: i32,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WaitTiming {
    pub enter_calls: u64,
    pub enter_cpu_ns: u64,
    pub enter_wall_ns: u64,
    pub submit_calls: u64,
    pub submit_cpu_ns: u64,
    pub submit_wall_ns: u64,
    pub drain_calls: u64,
    pub drain_cpu_ns: u64,
    pub drain_wall_ns: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TunRxBatch {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IoCounters {
    pub udp_rx_packets: u64,
    pub udp_rx_bytes: u64,
    pub udp_rx_errors: u64,
    pub udp_tx_packets: u64,
    pub udp_tx_bytes: u64,
    pub udp_tx_errors: u64,
    pub udp_tx_drops: u64,
    pub tun_rx_packets: u64,
    pub tun_rx_bytes: u64,
    pub tun_rx_errors: u64,
    pub tun_tx_packets: u64,
    pub tun_tx_bytes: u64,
    pub tun_tx_errors: u64,
    pub tun_tx_drops: u64,
    pub sqe_submissions: u64,
    pub cqe_completions: u64,
    pub udp_rx_rearms: u64,
    pub tun_rx_rearms: u64,
    pub free_udp_tx_slots: u64,
    pub free_tun_tx_slots: u64,
    pub cq_min_wait_usec: u64,
    pub cq_wait_batch: u64,
    pub cq_capacity: u64,
    pub cq_overflow: u64,
    pub udp_rx_enobufs: u64,
    pub udp_rx_multishot: u64,
    pub udp_rx_buffer_count: u64,
    pub tun_fixed_buffers: u64,
    pub iowq_bounded_limit: u64,
    pub iowq_unbounded_limit: u64,
    pub uring_mode: u64,
}

struct UdpRxSlot {
    buffer: PacketBuffer,
    peer: Box<libc::sockaddr_storage>,
    iovec: Box<libc::iovec>,
    msg: Box<libc::msghdr>,
}

struct UdpRxBufferRing {
    ring: NonNull<types::BufRingEntry>,
    ring_bytes: usize,
    buffers: Box<[[u8; UDP_RX_MULTI_BUFFER_SIZE]]>,
    message: Box<libc::msghdr>,
    tail: u16,
    active: bool,
}

impl UdpRxBufferRing {
    fn new(ring: &IoUring) -> std::io::Result<Self> {
        let ring_bytes = UDP_RX_MULTI_BUFFERS
            .checked_mul(std::mem::size_of::<types::BufRingEntry>())
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
        let memory = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if memory == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        let ring_ptr = NonNull::new(memory.cast::<types::BufRingEntry>()).unwrap();
        if let Err(error) = unsafe {
            ring.submitter().register_buf_ring_with_flags(
                ring_ptr.as_ptr() as u64,
                UDP_RX_MULTI_BUFFERS as u16,
                UDP_RX_BUFFER_GROUP,
                0,
            )
        } {
            unsafe {
                libc::munmap(memory, ring_bytes);
            }
            return Err(error);
        }
        let buffers = (0..UDP_RX_MULTI_BUFFERS)
            .map(|_| [0u8; UDP_RX_MULTI_BUFFER_SIZE])
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let mut message: Box<libc::msghdr> =
            Box::new(unsafe { MaybeUninit::<libc::msghdr>::zeroed().assume_init() });
        message.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let mut this = Self {
            ring: ring_ptr,
            ring_bytes,
            buffers,
            message,
            tail: 0,
            active: true,
        };
        for bid in 0..UDP_RX_MULTI_BUFFERS as u16 {
            this.recycle(bid);
        }
        Ok(this)
    }

    fn recycle(&mut self, bid: u16) {
        let index = usize::from(self.tail) & (UDP_RX_MULTI_BUFFERS - 1);
        let entry = unsafe { &mut *self.ring.as_ptr().add(index) };
        entry.set_addr(self.buffers[usize::from(bid)].as_mut_ptr() as u64);
        entry.set_len(UDP_RX_MULTI_BUFFER_SIZE as u32);
        entry.set_bid(bid);
        self.tail = self.tail.wrapping_add(1);
        let tail = unsafe { types::BufRingEntry::tail(self.ring.as_ptr()) };
        unsafe {
            (&*(tail.cast::<AtomicU16>())).store(self.tail, Ordering::Release);
        }
    }
}

impl Drop for UdpRxBufferRing {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ring.as_ptr().cast(), self.ring_bytes);
        }
    }
}

impl UdpRxSlot {
    fn new() -> Self {
        let mut buffer = PacketBuffer::new();
        let mut peer =
            Box::new(unsafe { MaybeUninit::<libc::sockaddr_storage>::zeroed().assume_init() });
        let mut iovec = Box::new(libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: PACKET_CAPACITY,
        });
        let mut msg: Box<libc::msghdr> =
            Box::new(unsafe { MaybeUninit::<libc::msghdr>::zeroed().assume_init() });
        msg.msg_name = (&mut *peer as *mut libc::sockaddr_storage).cast();
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut *iovec;
        msg.msg_iovlen = 1;
        msg.msg_control = std::ptr::null_mut();
        msg.msg_controllen = 0;
        msg.msg_flags = 0;
        Self {
            buffer,
            peer,
            iovec,
            msg,
        }
    }

    fn reset(&mut self) {
        self.buffer.clear();
        self.iovec.iov_base = self.buffer.as_mut_ptr().cast();
        self.iovec.iov_len = PACKET_CAPACITY;
        self.msg.msg_name = (&mut *self.peer as *mut libc::sockaddr_storage).cast();
        self.msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        self.msg.msg_iov = &mut *self.iovec;
        self.msg.msg_iovlen = 1;
        self.msg.msg_control = std::ptr::null_mut();
        self.msg.msg_controllen = 0;
        self.msg.msg_flags = 0;
    }
}

struct UdpTxSlot {
    buffer: PacketBuffer,
    peer: Box<libc::sockaddr_storage>,
    iovec: Box<libc::iovec>,
    msg: Box<libc::msghdr>,
}

impl UdpTxSlot {
    fn new() -> Self {
        let mut buffer = PacketBuffer::new();
        let mut peer =
            Box::new(unsafe { MaybeUninit::<libc::sockaddr_storage>::zeroed().assume_init() });
        let mut iovec = Box::new(libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: 0,
        });
        let mut msg: Box<libc::msghdr> =
            Box::new(unsafe { MaybeUninit::<libc::msghdr>::zeroed().assume_init() });
        msg.msg_name = (&mut *peer as *mut libc::sockaddr_storage).cast();
        msg.msg_namelen = 0;
        msg.msg_iov = &mut *iovec;
        msg.msg_iovlen = 1;
        msg.msg_control = std::ptr::null_mut();
        msg.msg_controllen = 0;
        msg.msg_flags = 0;
        Self {
            buffer,
            peer,
            iovec,
            msg,
        }
    }

    fn prepare(&mut self, peer: SocketAddr, payload: &[u8]) -> bool {
        if !self.buffer.copy_from(payload) {
            return false;
        }
        self.prepare_current(peer);
        true
    }

    fn prepare_current(&mut self, peer: SocketAddr) {
        let name_len = socket_addr_to_storage(peer, &mut self.peer);
        self.iovec.iov_base = self.buffer.as_mut_ptr().cast();
        self.iovec.iov_len = self.buffer.len();
        self.msg.msg_name = (&mut *self.peer as *mut libc::sockaddr_storage).cast();
        self.msg.msg_namelen = name_len;
        self.msg.msg_iov = &mut *self.iovec;
        self.msg.msg_iovlen = 1;
        self.msg.msg_control = std::ptr::null_mut();
        self.msg.msg_controllen = 0;
        self.msg.msg_flags = 0;
    }
}

struct TunTxSlot {
    buffer: PacketBuffer,
}

impl TunTxSlot {
    fn new() -> Self {
        Self {
            buffer: PacketBuffer::new(),
        }
    }
}

pub struct UringIo {
    ring: IoUring,
    udp_socket: Socket,
    tun: tun::Device,
    event_fd: RawFd,
    tick_fd: OwnedFd,
    udp_rx: Vec<UdpRxSlot>,
    udp_rx_multi: Option<UdpRxBufferRing>,
    udp_tx: Vec<UdpTxSlot>,
    tun_rx: PacketBuffer,
    tun_tx: Vec<TunTxSlot>,
    free_udp_tx: VecDeque<usize>,
    pending_udp_tx: VecDeque<usize>,
    udp_tx_batch: Vec<libc::mmsghdr>,
    udp_tx_poll_armed: bool,
    free_tun_tx: VecDeque<usize>,
    pending_tun_tx: VecDeque<usize>,
    tun_rx_poll_armed: bool,
    tun_tx_poll_armed: bool,
    event_poll_armed: bool,
    tick_poll_armed: bool,
    counters: IoCounters,
    fixed_files: bool,
    ext_arg_supported: bool,
    cq_min_wait_usec: u32,
    last_rate_packets: u64,
}

pub struct PacketSink<'a> {
    tun_fd: RawFd,
    udp_tx: &'a mut [UdpTxSlot],
    tun_tx: &'a mut [TunTxSlot],
    free_udp_tx: &'a mut VecDeque<usize>,
    pending_udp_tx: &'a mut VecDeque<usize>,
    free_tun_tx: &'a mut VecDeque<usize>,
    pending_tun_tx: &'a mut VecDeque<usize>,
    counters: &'a mut IoCounters,
}

impl PacketSink<'_> {
    #[inline]
    pub fn send_udp_with_duplicate<F>(
        &mut self,
        peer: SocketAddr,
        duplicate: bool,
        build: F,
    ) -> bool
    where
        F: FnOnce(&mut PacketBuffer) -> bool,
    {
        let Some(slot_id) = self.free_udp_tx.pop_front() else {
            self.counters.udp_tx_drops = self.counters.udp_tx_drops.saturating_add(1);
            return false;
        };
        let slot = &mut self.udp_tx[slot_id];
        slot.buffer.clear();
        if !build(&mut slot.buffer) {
            self.free_udp_tx.push_front(slot_id);
            self.counters.udp_tx_drops = self.counters.udp_tx_drops.saturating_add(1);
            return false;
        }
        slot.prepare_current(peer);
        let duplicate_id = if duplicate && self.free_udp_tx.len() > FEC_TX_SLOT_RESERVE {
            self.free_udp_tx.pop_front().and_then(|duplicate_id| {
                let prepared = if slot_id < duplicate_id {
                    let (left, right) = self.udp_tx.split_at_mut(duplicate_id);
                    right[0].prepare(peer, left[slot_id].buffer.as_slice())
                } else {
                    let (left, right) = self.udp_tx.split_at_mut(slot_id);
                    left[duplicate_id].prepare(peer, right[0].buffer.as_slice())
                };
                if prepared {
                    Some(duplicate_id)
                } else {
                    self.free_udp_tx.push_front(duplicate_id);
                    None
                }
            })
        } else {
            None
        };
        self.pending_udp_tx.push_back(slot_id);
        if let Some(duplicate_id) = duplicate_id {
            self.pending_udp_tx.push_back(duplicate_id);
        }
        true
    }

    #[inline]
    pub fn send_udp(&mut self, peer: SocketAddr, payload: &[u8]) -> bool {
        let Some(slot_id) = self.free_udp_tx.pop_front() else {
            self.counters.udp_tx_drops = self.counters.udp_tx_drops.saturating_add(1);
            return false;
        };
        let slot = &mut self.udp_tx[slot_id];
        if !slot.prepare(peer, payload) {
            self.free_udp_tx.push_front(slot_id);
            self.counters.udp_tx_drops = self.counters.udp_tx_drops.saturating_add(1);
            return false;
        }
        self.pending_udp_tx.push_back(slot_id);
        true
    }

    #[inline]
    pub fn write_tun(&mut self, payload: &[u8]) -> bool {
        if self.pending_tun_tx.is_empty() {
            match write_tun_packet(self.tun_fd, payload) {
                Ok(true) => {
                    self.counters.tun_tx_packets = self.counters.tun_tx_packets.saturating_add(1);
                    self.counters.tun_tx_bytes = self
                        .counters
                        .tun_tx_bytes
                        .saturating_add(payload.len() as u64);
                    return true;
                }
                Ok(false) => {}
                Err(_) => {
                    self.counters.tun_tx_errors = self.counters.tun_tx_errors.saturating_add(1);
                    self.counters.tun_tx_drops = self.counters.tun_tx_drops.saturating_add(1);
                    return false;
                }
            }
        }
        let Some(slot_id) = self.free_tun_tx.pop_front() else {
            self.counters.tun_tx_drops = self.counters.tun_tx_drops.saturating_add(1);
            return false;
        };
        let slot = &mut self.tun_tx[slot_id];
        if !slot.buffer.copy_from(payload) {
            self.free_tun_tx.push_front(slot_id);
            self.counters.tun_tx_drops = self.counters.tun_tx_drops.saturating_add(1);
            return false;
        }
        self.pending_tun_tx.push_back(slot_id);
        true
    }
}

impl UringIo {
    pub fn new(
        listen: SocketAddr,
        event_fd: RawFd,
        tun_iface: &str,
        tun_addr: &str,
    ) -> Result<Self> {
        let (ring, uring_mode) = build_ring().context("create io_uring")?;
        let cpu_count = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1);
        let iowq_limits = [cpu_count.clamp(1, 16) as u32, cpu_count.clamp(1, 4) as u32];
        let mut iowq_previous = iowq_limits;
        let iowq_limited = ring
            .submitter()
            .register_iowq_max_workers(&mut iowq_previous)
            .is_ok();
        let ext_arg_supported = ring.params().is_feature_ext_arg();
        let multishot_enabled = std::env::var("CSQTT_UDP_MULTISHOT")
            .map(|value| value != "0" && !value.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        let udp_rx_multi = multishot_enabled
            .then(|| UdpRxBufferRing::new(&ring))
            .transpose()
            .ok()
            .flatten();

        let domain = if listen.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let udp_socket =
            Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("create UDP socket")?;
        udp_socket.set_reuse_address(true)?;
        udp_socket.set_recv_buffer_size(UDP_RECV_BUFFER_BYTES)?;
        udp_socket.set_send_buffer_size(UDP_SEND_BUFFER_BYTES)?;
        udp_socket
            .bind(&listen.into())
            .with_context(|| format!("bind {listen}"))?;

        let address = tun_addr
            .parse::<std::net::Ipv4Addr>()
            .with_context(|| format!("invalid TUN address {tun_addr}"))?;
        let mut config = tun::Configuration::default();
        config
            .tun_name(tun_iface)
            .address(address)
            .netmask((255, 255, 255, 0))
            .mtu(TUN_MTU)
            .up();
        let tun = tun::create(&config).context("create TUN device")?;
        tun.set_nonblock().context("set TUN nonblocking mode")?;
        let tick_fd = create_tick_timer().context("create dataplane timerfd")?;
        let fixed_files = ring
            .submitter()
            .register_files(&[
                udp_socket.as_raw_fd(),
                tun.as_raw_fd(),
                event_fd,
                tick_fd.as_raw_fd(),
            ])
            .is_ok();

        let udp_rx = if udp_rx_multi.is_some() {
            Vec::new()
        } else {
            (0..UDP_RX_SLOTS).map(|_| UdpRxSlot::new()).collect()
        };
        let udp_tx = (0..UDP_TX_SLOTS).map(|_| UdpTxSlot::new()).collect();
        let tun_rx = PacketBuffer::new();
        let tun_tx = (0..TUN_TX_SLOTS)
            .map(|_| TunTxSlot::new())
            .collect::<Vec<_>>();
        let free_udp_tx = (0..UDP_TX_SLOTS).collect();
        let pending_udp_tx = VecDeque::with_capacity(UDP_TX_SLOTS);
        let udp_tx_batch = Vec::with_capacity(UDP_TX_SLOTS);
        let free_tun_tx = (0..TUN_TX_SLOTS).collect();
        let pending_tun_tx = VecDeque::with_capacity(TUN_TX_SLOTS);

        let counters = IoCounters {
            uring_mode,
            iowq_bounded_limit: if iowq_limited {
                u64::from(iowq_limits[0])
            } else {
                0
            },
            iowq_unbounded_limit: if iowq_limited {
                u64::from(iowq_limits[1])
            } else {
                0
            },
            ..IoCounters::default()
        };
        let mut this = Self {
            ring,
            udp_socket,
            tun,
            event_fd,
            tick_fd,
            udp_rx,
            udp_rx_multi,
            udp_tx,
            tun_rx,
            tun_tx,
            free_udp_tx,
            pending_udp_tx,
            udp_tx_batch,
            udp_tx_poll_armed: false,
            free_tun_tx,
            pending_tun_tx,
            tun_rx_poll_armed: false,
            tun_tx_poll_armed: false,
            event_poll_armed: false,
            tick_poll_armed: false,
            counters,
            fixed_files,
            ext_arg_supported,
            cq_min_wait_usec: 0,
            last_rate_packets: 0,
        };
        this.arm_initial()?;
        Ok(this)
    }

    fn arm_initial(&mut self) -> Result<()> {
        if self.udp_rx_multi.is_some() {
            self.arm_udp_rx_multi()?;
        } else {
            for slot_id in 0..self.udp_rx.len() {
                self.arm_udp_rx(slot_id)?;
            }
        }
        self.arm_tun_rx_poll()?;
        self.arm_eventfd()?;
        self.arm_tick()?;
        submit_retry(&mut self.ring).context("submit initial io_uring requests")?;
        Ok(())
    }

    fn arm_udp_rx(&mut self, slot_id: usize) -> Result<()> {
        let slot = &mut self.udp_rx[slot_id];
        slot.reset();
        let entry = if self.fixed_files {
            opcode::RecvMsg::new(types::Fixed(FIXED_UDP), &mut *slot.msg).build()
        } else {
            opcode::RecvMsg::new(types::Fd(self.udp_socket.as_raw_fd()), &mut *slot.msg).build()
        }
        .user_data(make_tag(TAG_UDP_RX, slot_id));
        self.counters.sqe_submissions = self.counters.sqe_submissions.saturating_add(1);
        self.counters.udp_rx_rearms = self.counters.udp_rx_rearms.saturating_add(1);
        unsafe { self.ring.submission().push(&entry) }
            .map_err(|_| anyhow!("io_uring submission queue full while arming UDP RX"))
    }

    fn arm_udp_rx_multi(&mut self) -> Result<()> {
        let Some(receiver) = self.udp_rx_multi.as_ref() else {
            bail!("UDP multishot buffer ring unavailable");
        };
        let entry = if self.fixed_files {
            opcode::RecvMsgMulti::new(
                types::Fixed(FIXED_UDP),
                &*receiver.message,
                UDP_RX_BUFFER_GROUP,
            )
            .build()
        } else {
            opcode::RecvMsgMulti::new(
                types::Fd(self.udp_socket.as_raw_fd()),
                &*receiver.message,
                UDP_RX_BUFFER_GROUP,
            )
            .build()
        }
        .user_data(make_tag(TAG_UDP_RX_MULTI, 0));
        self.counters.sqe_submissions = self.counters.sqe_submissions.saturating_add(1);
        self.counters.udp_rx_rearms = self.counters.udp_rx_rearms.saturating_add(1);
        unsafe { self.ring.submission().push(&entry) }
            .map_err(|_| anyhow!("io_uring submission queue full while arming UDP multishot RX"))
    }

    fn arm_tun_rx_poll(&mut self) -> Result<()> {
        if self.tun_rx_poll_armed {
            return Ok(());
        }
        let entry = if self.fixed_files {
            opcode::PollAdd::new(types::Fixed(FIXED_TUN), libc::POLLIN as u32).build()
        } else {
            opcode::PollAdd::new(types::Fd(self.tun.as_raw_fd()), libc::POLLIN as u32).build()
        }
        .user_data(make_tag(TAG_TUN_RX, 0));
        self.counters.sqe_submissions = self.counters.sqe_submissions.saturating_add(1);
        self.counters.tun_rx_rearms = self.counters.tun_rx_rearms.saturating_add(1);
        push_or_submit(&mut self.ring, &entry, "polling TUN RX")?;
        self.tun_rx_poll_armed = true;
        Ok(())
    }

    fn arm_eventfd(&mut self) -> Result<()> {
        if self.event_poll_armed {
            return Ok(());
        }
        let entry = if self.fixed_files {
            opcode::PollAdd::new(types::Fixed(FIXED_EVENT), libc::POLLIN as u32).build()
        } else {
            opcode::PollAdd::new(types::Fd(self.event_fd), libc::POLLIN as u32).build()
        }
        .user_data(make_tag(TAG_EVENTFD, 0));
        push_or_submit(&mut self.ring, &entry, "polling eventfd")?;
        self.event_poll_armed = true;
        Ok(())
    }

    fn arm_tick(&mut self) -> Result<()> {
        if self.tick_poll_armed {
            return Ok(());
        }
        let entry = if self.fixed_files {
            opcode::PollAdd::new(types::Fixed(FIXED_TICK), libc::POLLIN as u32).build()
        } else {
            opcode::PollAdd::new(types::Fd(self.tick_fd.as_raw_fd()), libc::POLLIN as u32).build()
        }
        .user_data(make_tag(TAG_TICK, 0));
        push_or_submit(&mut self.ring, &entry, "polling timerfd")?;
        self.tick_poll_armed = true;
        Ok(())
    }

    pub fn wait_into(&mut self, output: &mut Vec<Completion>, measure: bool) -> Result<WaitTiming> {
        let mut timing = WaitTiming::default();
        output.clear();
        self.drain_completions_timed(output, measure, &mut timing);
        if output.is_empty() {
            self.counters.sqe_submissions = self.counters.sqe_submissions.saturating_add(1);
            timing.enter_calls = 1;
            let cpu_started = measure.then(thread_cpu_time_ns);
            let wall_started = measure.then(Instant::now);
            let wait_result = if self.cq_min_wait_usec == 0 || !self.ext_arg_supported {
                submit_and_wait_retry(&mut self.ring, 1)
                    .context("io_uring wait")
                    .map(|_| ())
            } else {
                let timeout = types::Timespec::new().nsec(self.cq_min_wait_usec * 1_000);
                let args = types::SubmitArgs::new().timespec(&timeout);
                let result = submit_with_args_retry(&mut self.ring, CQ_WAIT_BATCH, &args);
                match result {
                    Ok(_) => Ok(()),
                    Err(error) if error.raw_os_error() == Some(libc::ETIME) => Ok(()),
                    Err(error) if is_capability_error(&error) => {
                        self.ext_arg_supported = false;
                        self.cq_min_wait_usec = 0;
                        submit_and_wait_retry(&mut self.ring, 1)
                            .context("io_uring compatible wait")
                            .map(|_| ())
                    }
                    Err(error) => Err(error).context("io_uring deadline batch wait"),
                }
            };
            if let (Some(cpu_started), Some(wall_started)) = (cpu_started, wall_started) {
                timing.enter_cpu_ns = thread_cpu_time_ns().saturating_sub(cpu_started);
                timing.enter_wall_ns =
                    wall_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
            }
            wait_result?;
            self.drain_completions_timed(output, measure, &mut timing);
        } else if !self.ring.submission().is_empty() {
            self.counters.sqe_submissions = self.counters.sqe_submissions.saturating_add(1);
            timing.submit_calls = 1;
            let cpu_started = measure.then(thread_cpu_time_ns);
            let wall_started = measure.then(Instant::now);
            let submit_result = submit_retry(&mut self.ring).context("io_uring submit");
            if let (Some(cpu_started), Some(wall_started)) = (cpu_started, wall_started) {
                timing.submit_cpu_ns = thread_cpu_time_ns().saturating_sub(cpu_started);
                timing.submit_wall_ns =
                    wall_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
            }
            submit_result?;
        }
        Ok(timing)
    }

    fn drain_completions_timed(
        &mut self,
        output: &mut Vec<Completion>,
        measure: bool,
        timing: &mut WaitTiming,
    ) {
        timing.drain_calls = timing.drain_calls.saturating_add(1);
        let cpu_started = measure.then(thread_cpu_time_ns);
        let wall_started = measure.then(Instant::now);
        self.drain_completions(output);
        if let (Some(cpu_started), Some(wall_started)) = (cpu_started, wall_started) {
            timing.drain_cpu_ns = timing
                .drain_cpu_ns
                .saturating_add(thread_cpu_time_ns().saturating_sub(cpu_started));
            timing.drain_wall_ns = timing
                .drain_wall_ns
                .saturating_add(wall_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64);
        }
    }

    fn drain_completions(&mut self, output: &mut Vec<Completion>) {
        let count = {
            let mut cq = self.ring.completion();
            self.counters.cq_capacity = cq.capacity() as u64;
            self.counters.cq_overflow = u64::from(cq.overflow());
            for cqe in cq.by_ref().take(COMPLETION_BATCH) {
                output.push(Completion {
                    user_data: cqe.user_data(),
                    result: cqe.result(),
                    flags: cqe.flags(),
                });
            }
            output.len()
        };
        self.counters.cqe_completions = self.counters.cqe_completions.saturating_add(count as u64);
    }

    pub fn flush_udp_tx(&mut self) -> Result<()> {
        while !self.pending_udp_tx.is_empty() {
            self.udp_tx_batch.clear();
            for slot_id in self.pending_udp_tx.iter().copied() {
                let msg_hdr = unsafe { std::ptr::read(&*self.udp_tx[slot_id].msg) };
                self.udp_tx_batch.push(libc::mmsghdr {
                    msg_hdr,
                    msg_len: 0,
                });
            }
            let result = unsafe {
                libc::sendmmsg(
                    self.udp_socket.as_raw_fd(),
                    self.udp_tx_batch.as_mut_ptr(),
                    self.udp_tx_batch.len() as u32,
                    libc::MSG_DONTWAIT as u32,
                )
            };
            if result > 0 {
                let sent = (result as usize).min(self.pending_udp_tx.len());
                for index in 0..sent {
                    let Some(slot_id) = self.pending_udp_tx.pop_front() else {
                        break;
                    };
                    let length = self.udp_tx_batch[index].msg_len as usize;
                    self.counters.udp_tx_packets = self.counters.udp_tx_packets.saturating_add(1);
                    self.counters.udp_tx_bytes =
                        self.counters.udp_tx_bytes.saturating_add(length as u64);
                    self.udp_tx[slot_id].buffer.clear();
                    self.free_udp_tx.push_back(slot_id);
                }
                continue;
            }
            if result == 0 {
                self.arm_udp_tx_poll()?;
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == std::io::ErrorKind::WouldBlock {
                self.arm_udp_tx_poll()?;
                break;
            }
            self.counters.udp_tx_errors = self.counters.udp_tx_errors.saturating_add(1);
            self.counters.udp_tx_drops = self.counters.udp_tx_drops.saturating_add(1);
            if let Some(slot_id) = self.pending_udp_tx.pop_front() {
                self.udp_tx[slot_id].buffer.clear();
                self.free_udp_tx.push_back(slot_id);
            }
        }
        Ok(())
    }

    #[inline(always)]
    pub fn pending_udp_tx_len(&self) -> usize {
        self.pending_udp_tx.len()
    }

    pub fn flush_tun_tx(&mut self) -> Result<()> {
        while let Some(slot_id) = self.pending_tun_tx.front().copied() {
            let payload = self.tun_tx[slot_id].buffer.as_slice();
            match write_tun_packet(self.tun.as_raw_fd(), payload) {
                Ok(true) => {
                    self.counters.tun_tx_packets = self.counters.tun_tx_packets.saturating_add(1);
                    self.counters.tun_tx_bytes = self
                        .counters
                        .tun_tx_bytes
                        .saturating_add(payload.len() as u64);
                }
                Ok(false) => {
                    self.arm_tun_tx_poll()?;
                    break;
                }
                Err(_) => {
                    self.counters.tun_tx_errors = self.counters.tun_tx_errors.saturating_add(1);
                    self.counters.tun_tx_drops = self.counters.tun_tx_drops.saturating_add(1);
                }
            }
            self.pending_tun_tx.pop_front();
            self.tun_tx[slot_id].buffer.clear();
            self.free_tun_tx.push_back(slot_id);
        }
        Ok(())
    }

    #[inline(always)]
    pub fn pending_tun_tx_len(&self) -> usize {
        self.pending_tun_tx.len()
    }

    fn arm_udp_tx_poll(&mut self) -> Result<()> {
        if self.udp_tx_poll_armed || self.pending_udp_tx.is_empty() {
            return Ok(());
        }
        let entry = if self.fixed_files {
            opcode::PollAdd::new(types::Fixed(FIXED_UDP), libc::POLLOUT as u32).build()
        } else {
            opcode::PollAdd::new(types::Fd(self.udp_socket.as_raw_fd()), libc::POLLOUT as u32)
                .build()
        }
        .user_data(make_tag(TAG_UDP_TX_READY, 0));
        if unsafe { self.ring.submission().push(&entry) }.is_err() {
            self.counters.sqe_submissions = self.counters.sqe_submissions.saturating_add(1);
            submit_retry(&mut self.ring).context("submit before UDP writable poll")?;
            unsafe { self.ring.submission().push(&entry) }
                .map_err(|_| anyhow!("io_uring submission queue full while polling UDP TX"))?;
        }
        self.udp_tx_poll_armed = true;
        Ok(())
    }

    fn arm_tun_tx_poll(&mut self) -> Result<()> {
        if self.tun_tx_poll_armed || self.pending_tun_tx.is_empty() {
            return Ok(());
        }
        let entry = if self.fixed_files {
            opcode::PollAdd::new(types::Fixed(FIXED_TUN), libc::POLLOUT as u32).build()
        } else {
            opcode::PollAdd::new(types::Fd(self.tun.as_raw_fd()), libc::POLLOUT as u32).build()
        }
        .user_data(make_tag(TAG_TUN_TX, 0));
        push_or_submit(&mut self.ring, &entry, "polling TUN TX")?;
        self.tun_tx_poll_armed = true;
        Ok(())
    }

    pub fn completion_kind(completion: Completion) -> (u64, usize) {
        split_tag(completion.user_data)
    }

    pub fn process_udp_rx<F>(&mut self, slot_id: usize, result: i32, mut process: F) -> Result<()>
    where
        F: FnMut(SocketAddr, &mut [u8], &mut PacketSink<'_>),
    {
        if slot_id >= self.udp_rx.len() {
            bail!("invalid UDP RX slot {slot_id}");
        }
        if result < 0 {
            self.counters.udp_rx_errors = self.counters.udp_rx_errors.saturating_add(1);
            if -result == libc::ENOBUFS {
                self.counters.udp_rx_enobufs = self.counters.udp_rx_enobufs.saturating_add(1);
            }
            self.arm_udp_rx(slot_id)?;
            return Ok(());
        }
        let len = result as usize;
        if self.udp_rx[slot_id].msg.msg_flags & libc::MSG_TRUNC != 0 {
            self.counters.udp_rx_errors = self.counters.udp_rx_errors.saturating_add(1);
            self.arm_udp_rx(slot_id)?;
            return Ok(());
        }
        if len > PACKET_CAPACITY || !self.udp_rx[slot_id].buffer.set_len(len) {
            self.counters.udp_rx_errors = self.counters.udp_rx_errors.saturating_add(1);
            self.arm_udp_rx(slot_id)?;
            return Ok(());
        }
        let peer = {
            let slot = &self.udp_rx[slot_id];
            storage_to_socket_addr(&slot.peer, slot.msg.msg_namelen)
        };
        if let Some(peer) = peer {
            self.counters.udp_rx_packets = self.counters.udp_rx_packets.saturating_add(1);
            self.counters.udp_rx_bytes = self.counters.udp_rx_bytes.saturating_add(len as u64);
            let Self {
                tun,
                udp_rx,
                udp_tx,
                tun_tx,
                free_udp_tx,
                pending_udp_tx,
                free_tun_tx,
                pending_tun_tx,
                counters,
                ..
            } = self;
            let packet = udp_rx[slot_id].buffer.as_mut_slice();
            let mut sink = PacketSink {
                tun_fd: tun.as_raw_fd(),
                udp_tx,
                tun_tx,
                free_udp_tx,
                pending_udp_tx,
                free_tun_tx,
                pending_tun_tx,
                counters,
            };
            process(peer, packet, &mut sink);
        }
        self.arm_udp_rx(slot_id)?;
        Ok(())
    }

    pub fn process_udp_rx_multi<F>(&mut self, result: i32, flags: u32, mut process: F) -> Result<()>
    where
        F: FnMut(SocketAddr, &mut [u8], &mut PacketSink<'_>),
    {
        let more = cqueue::more(flags);
        if result < 0 {
            self.counters.udp_rx_errors = self.counters.udp_rx_errors.saturating_add(1);
            if -result == libc::ENOBUFS {
                self.counters.udp_rx_enobufs = self.counters.udp_rx_enobufs.saturating_add(1);
            }
            let unsupported = is_capability_errno(-result);
            if unsupported {
                if let Some(receiver) = self.udp_rx_multi.as_mut() {
                    receiver.active = false;
                }
                if self.udp_rx.is_empty() {
                    self.udp_rx = (0..UDP_RX_SLOTS).map(|_| UdpRxSlot::new()).collect();
                }
                for slot_id in 0..self.udp_rx.len() {
                    self.arm_udp_rx(slot_id)?;
                }
            } else if !more {
                self.arm_udp_rx_multi()?;
            }
            return Ok(());
        }
        let Some(bid) = cqueue::buffer_select(flags) else {
            self.counters.udp_rx_errors = self.counters.udp_rx_errors.saturating_add(1);
            if !more {
                self.arm_udp_rx_multi()?;
            }
            return Ok(());
        };
        let bid_index = usize::from(bid);
        let parsed = self
            .udp_rx_multi
            .as_ref()
            .filter(|receiver| receiver.active)
            .and_then(|receiver| {
                receiver
                    .buffers
                    .get(bid_index)
                    .map(|buffer| (receiver, buffer))
            })
            .and_then(|(receiver, buffer)| {
                types::RecvMsgOut::parse(buffer.as_slice(), &receiver.message).ok()
            });
        let packet = parsed.and_then(|output| {
            if output.is_name_data_truncated() || output.is_payload_truncated() {
                return None;
            }
            let name = output.name_data();
            let payload = output.payload_data();
            let receiver = self.udp_rx_multi.as_ref()?;
            let buffer = receiver.buffers.get(bid_index)?;
            let offset = payload.as_ptr() as usize - buffer.as_ptr() as usize;
            let mut storage =
                unsafe { MaybeUninit::<libc::sockaddr_storage>::zeroed().assume_init() };
            let name_len = name
                .len()
                .min(std::mem::size_of::<libc::sockaddr_storage>());
            unsafe {
                std::ptr::copy_nonoverlapping(
                    name.as_ptr(),
                    (&mut storage as *mut libc::sockaddr_storage).cast::<u8>(),
                    name_len,
                );
            }
            storage_to_socket_addr(&storage, name_len as libc::socklen_t)
                .map(|peer| (peer, offset, payload.len()))
        });
        if let Some((peer, offset, len)) = packet {
            self.counters.udp_rx_packets = self.counters.udp_rx_packets.saturating_add(1);
            self.counters.udp_rx_bytes = self.counters.udp_rx_bytes.saturating_add(len as u64);
            let Self {
                tun,
                udp_rx_multi,
                udp_tx,
                tun_tx,
                free_udp_tx,
                pending_udp_tx,
                free_tun_tx,
                pending_tun_tx,
                counters,
                ..
            } = self;
            let receiver = udp_rx_multi.as_mut().unwrap();
            let packet = &mut receiver.buffers[bid_index][offset..offset + len];
            let mut sink = PacketSink {
                tun_fd: tun.as_raw_fd(),
                udp_tx,
                tun_tx,
                free_udp_tx,
                pending_udp_tx,
                free_tun_tx,
                pending_tun_tx,
                counters,
            };
            process(peer, packet, &mut sink);
        } else {
            self.counters.udp_rx_errors = self.counters.udp_rx_errors.saturating_add(1);
        }
        if let Some(receiver) = self.udp_rx_multi.as_mut() {
            receiver.recycle(bid);
        }
        if !more {
            self.arm_udp_rx_multi()?;
        }
        Ok(())
    }

    pub fn process_tun_rx<F>(&mut self, result: i32, mut process: F) -> Result<TunRxBatch>
    where
        F: FnMut(&mut [u8], &mut PacketSink<'_>),
    {
        self.tun_rx_poll_armed = false;
        if result < 0 {
            if -result != libc::ECANCELED {
                self.counters.tun_rx_errors = self.counters.tun_rx_errors.saturating_add(1);
                self.arm_tun_rx_poll()?;
            }
            return Ok(TunRxBatch::default());
        }
        let mut batch = TunRxBatch::default();
        while batch.packets < TUN_RX_DRAIN_BATCH as u64 {
            let read_result = unsafe {
                libc::read(
                    self.tun.as_raw_fd(),
                    self.tun_rx.as_mut_ptr().cast(),
                    self.tun_rx.capacity(),
                )
            };
            if read_result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    break;
                }
                self.counters.tun_rx_errors = self.counters.tun_rx_errors.saturating_add(1);
                break;
            }
            if read_result == 0 {
                self.counters.tun_rx_errors = self.counters.tun_rx_errors.saturating_add(1);
                break;
            }
            let len = read_result as usize;
            if !self.tun_rx.set_len(len) {
                self.counters.tun_rx_errors = self.counters.tun_rx_errors.saturating_add(1);
                continue;
            }
            self.counters.tun_rx_packets = self.counters.tun_rx_packets.saturating_add(1);
            self.counters.tun_rx_bytes = self.counters.tun_rx_bytes.saturating_add(len as u64);
            batch.packets = batch.packets.saturating_add(1);
            batch.bytes = batch.bytes.saturating_add(len as u64);
            let Self {
                tun,
                tun_rx,
                udp_tx,
                tun_tx,
                free_udp_tx,
                pending_udp_tx,
                free_tun_tx,
                pending_tun_tx,
                counters,
                ..
            } = self;
            let packet = tun_rx.as_mut_slice();
            let mut sink = PacketSink {
                tun_fd: tun.as_raw_fd(),
                udp_tx,
                tun_tx,
                free_udp_tx,
                pending_udp_tx,
                free_tun_tx,
                pending_tun_tx,
                counters,
            };
            process(packet, &mut sink);
        }
        self.arm_tun_rx_poll()?;
        Ok(batch)
    }

    pub fn with_sink<R>(&mut self, process: impl FnOnce(&mut PacketSink<'_>) -> R) -> R {
        let Self {
            tun,
            udp_tx,
            tun_tx,
            free_udp_tx,
            pending_udp_tx,
            free_tun_tx,
            pending_tun_tx,
            counters,
            ..
        } = self;
        let mut sink = PacketSink {
            tun_fd: tun.as_raw_fd(),
            udp_tx,
            tun_tx,
            free_udp_tx,
            pending_udp_tx,
            free_tun_tx,
            pending_tun_tx,
            counters,
        };
        process(&mut sink)
    }

    pub fn process_tun_tx_ready(&mut self, result: i32) {
        self.tun_tx_poll_armed = false;
        if result < 0 && -result != libc::ECANCELED {
            self.counters.tun_tx_errors = self.counters.tun_tx_errors.saturating_add(1);
        }
    }

    pub fn process_udp_tx_ready(&mut self, result: i32) {
        self.udp_tx_poll_armed = false;
        if result < 0 && -result != libc::ECANCELED {
            self.counters.udp_tx_errors = self.counters.udp_tx_errors.saturating_add(1);
        }
    }

    pub fn process_eventfd_completion(&mut self, result: i32) -> Result<()> {
        self.event_poll_armed = false;
        if result < 0 {
            if -result == libc::ECANCELED {
                return Ok(());
            }
            return Err(std::io::Error::from_raw_os_error(-result).into());
        }
        read_counter_fd(self.event_fd).context("read eventfd")?;
        self.arm_eventfd()
    }

    pub fn process_tick_completion(&mut self, result: i32) -> Result<()> {
        self.tick_poll_armed = false;
        if result < 0 {
            if -result == libc::ECANCELED {
                return Ok(());
            }
            return Err(std::io::Error::from_raw_os_error(-result).into());
        }
        read_counter_fd(self.tick_fd.as_raw_fd()).context("read timerfd")?;
        let total_packets = self
            .counters
            .udp_rx_packets
            .saturating_add(self.counters.tun_rx_packets);
        let packets_per_second = total_packets
            .saturating_sub(self.last_rate_packets)
            .saturating_mul(1000 / TICK_INTERVAL_MS as u64);
        self.last_rate_packets = total_packets;
        self.cq_min_wait_usec = if !self.ext_arg_supported {
            0
        } else if packets_per_second >= 2_000 {
            750
        } else if packets_per_second >= 1_000 {
            350
        } else if packets_per_second >= 500 {
            150
        } else {
            0
        };
        self.arm_tick()
    }

    pub fn counters(&self) -> IoCounters {
        let mut snapshot = self.counters;
        snapshot.free_udp_tx_slots = self.free_udp_tx.len() as u64;
        snapshot.free_tun_tx_slots = self.free_tun_tx.len() as u64;
        snapshot.cq_min_wait_usec = self.cq_min_wait_usec as u64;
        snapshot.cq_wait_batch = if self.ext_arg_supported {
            CQ_WAIT_BATCH as u64
        } else {
            1
        };
        snapshot.udp_rx_multishot = self
            .udp_rx_multi
            .as_ref()
            .is_some_and(|receiver| receiver.active) as u64;
        snapshot.udp_rx_buffer_count = self
            .udp_rx_multi
            .as_ref()
            .map_or(0, |receiver| receiver.buffers.len() as u64);
        snapshot
    }

    pub fn tag_udp_rx() -> u64 {
        TAG_UDP_RX
    }

    pub fn tag_tun_rx() -> u64 {
        TAG_TUN_RX
    }

    pub fn tag_udp_rx_multi() -> u64 {
        TAG_UDP_RX_MULTI
    }

    pub fn tag_udp_tx_ready() -> u64 {
        TAG_UDP_TX_READY
    }

    pub fn tag_tun_tx() -> u64 {
        TAG_TUN_TX
    }

    pub fn tag_eventfd() -> u64 {
        TAG_EVENTFD
    }

    pub fn tag_tick() -> u64 {
        TAG_TICK
    }
}

impl Drop for UringIo {
    fn drop(&mut self) {
        if self.udp_rx_multi.is_some() {
            let _ = self
                .ring
                .submitter()
                .unregister_buf_ring(UDP_RX_BUFFER_GROUP);
        }
        if self.fixed_files {
            let _ = self.ring.submitter().unregister_files();
        }
    }
}

fn read_counter_fd(fd: RawFd) -> std::io::Result<u64> {
    loop {
        let mut value = 0u64;
        let result = unsafe {
            libc::read(
                fd,
                (&mut value as *mut u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        if result == std::mem::size_of::<u64>() as isize {
            return Ok(value);
        }
        if result >= 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "short counter fd read",
            ));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(0);
        }
        return Err(error);
    }
}

fn write_tun_packet(fd: RawFd, payload: &[u8]) -> std::io::Result<bool> {
    loop {
        let result = unsafe { libc::write(fd, payload.as_ptr().cast(), payload.len()) };
        if result == payload.len() as isize {
            return Ok(true);
        }
        if result >= 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short TUN packet write",
            ));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(false);
        }
        return Err(error);
    }
}

fn push_or_submit(ring: &mut IoUring, entry: &squeue::Entry, operation: &str) -> Result<()> {
    if unsafe { ring.submission().push(entry) }.is_ok() {
        return Ok(());
    }
    submit_retry(ring).with_context(|| format!("submit before {operation}"))?;
    unsafe { ring.submission().push(entry) }
        .map_err(|_| anyhow!("io_uring submission queue full while {operation}"))
}

fn create_tick_timer() -> std::io::Result<OwnedFd> {
    let fd = unsafe {
        libc::timerfd_create(
            libc::CLOCK_MONOTONIC,
            libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let interval = libc::timespec {
        tv_sec: 0,
        tv_nsec: TICK_INTERVAL_MS * 1_000_000,
    };
    let spec = libc::itimerspec {
        it_interval: interval,
        it_value: interval,
    };
    let result =
        unsafe { libc::timerfd_settime(owned.as_raw_fd(), 0, &spec, std::ptr::null_mut()) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(owned)
}

fn build_ring() -> std::io::Result<(IoUring, u64)> {
    match std::env::var("CSQTT_URING_MODE")
        .unwrap_or_else(|_| "defer".to_owned())
        .to_ascii_lowercase()
        .as_str()
    {
        "coop" => build_coop_ring(),
        "single" => build_single_ring(),
        "basic" => build_basic_ring(),
        _ => build_deferred_ring(),
    }
}

pub fn probe_compatibility() -> Result<&'static str> {
    const PROBE_USER_DATA: u64 = u64::MAX;

    let (mut ring, mode) = build_ring().context("io_uring_setup")?;
    let entry = opcode::Nop::new().build().user_data(PROBE_USER_DATA);
    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow!("io_uring submission queue rejected probe NOP"))?;
    submit_and_wait_retry(&mut ring, 1).context("io_uring_enter")?;
    let completion = ring
        .completion()
        .next()
        .ok_or_else(|| anyhow!("io_uring returned no completion for probe NOP"))?;
    if completion.user_data() != PROBE_USER_DATA {
        bail!("io_uring returned an unexpected completion");
    }
    if completion.result() < 0 {
        return Err(std::io::Error::from_raw_os_error(-completion.result()))
            .context("io_uring probe NOP");
    }

    Ok(match mode {
        URING_MODE_DEFER => "defer",
        URING_MODE_COOP_TASKRUN | URING_MODE_COOP => "coop",
        URING_MODE_SINGLE => "single",
        _ => "basic",
    })
}

fn build_deferred_ring() -> std::io::Result<(IoUring, u64)> {
    let mut deferred = IoUring::builder();
    deferred
        .setup_cqsize(CQ_ENTRIES)
        .setup_single_issuer()
        .setup_coop_taskrun()
        .setup_defer_taskrun();
    match deferred.build(1024) {
        Ok(ring) => return Ok((ring, URING_MODE_DEFER)),
        Err(error) if is_capability_error(&error) => {}
        Err(error) => return Err(error),
    }
    build_coop_ring()
}

fn build_coop_ring() -> std::io::Result<(IoUring, u64)> {
    let mut taskrun = IoUring::builder();
    taskrun
        .setup_cqsize(CQ_ENTRIES)
        .setup_single_issuer()
        .setup_coop_taskrun()
        .setup_taskrun_flag();
    match taskrun.build(1024) {
        Ok(ring) => return Ok((ring, URING_MODE_COOP_TASKRUN)),
        Err(error) if is_capability_error(&error) => {}
        Err(error) => return Err(error),
    }
    let mut single = IoUring::builder();
    single
        .setup_cqsize(CQ_ENTRIES)
        .setup_single_issuer()
        .setup_coop_taskrun();
    match single.build(1024) {
        Ok(ring) => return Ok((ring, URING_MODE_COOP)),
        Err(error) if is_capability_error(&error) => {}
        Err(error) => return Err(error),
    }
    build_single_ring()
}

fn build_single_ring() -> std::io::Result<(IoUring, u64)> {
    let mut single = IoUring::builder();
    single.setup_cqsize(CQ_ENTRIES).setup_single_issuer();
    match single.build(1024) {
        Ok(ring) => return Ok((ring, URING_MODE_SINGLE)),
        Err(error) if is_capability_error(&error) => {}
        Err(error) => return Err(error),
    }
    build_basic_ring()
}

fn build_basic_ring() -> std::io::Result<(IoUring, u64)> {
    let mut sized = IoUring::builder();
    sized.setup_cqsize(CQ_ENTRIES);
    match sized.build(1024) {
        Ok(ring) => Ok((ring, URING_MODE_BASIC)),
        Err(error) if is_capability_error(&error) => {
            IoUring::new(1024).map(|ring| (ring, URING_MODE_BASIC))
        }
        Err(error) => Err(error),
    }
}

fn submit_retry(ring: &mut IoUring) -> std::io::Result<usize> {
    loop {
        match ring.submit() {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

fn submit_and_wait_retry(ring: &mut IoUring, want: usize) -> std::io::Result<usize> {
    loop {
        match ring.submit_and_wait(want) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

fn submit_with_args_retry(
    ring: &mut IoUring,
    want: usize,
    args: &types::SubmitArgs<'_, '_>,
) -> std::io::Result<usize> {
    loop {
        match ring.submitter().submit_with_args(want, args) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

fn is_capability_error(error: &std::io::Error) -> bool {
    error.raw_os_error().is_some_and(is_capability_errno)
}

fn is_capability_errno(errno: i32) -> bool {
    matches!(
        errno,
        libc::EINVAL | libc::EOPNOTSUPP | libc::ENOSYS | libc::EPERM
    )
}

#[inline(always)]
fn make_tag(kind: u64, id: usize) -> u64 {
    (kind << TAG_SHIFT) | id as u64
}

#[inline(always)]
fn split_tag(value: u64) -> (u64, usize) {
    (
        (value & TAG_MASK) >> TAG_SHIFT,
        (value & !TAG_MASK) as usize,
    )
}

const _: () = {
    assert!(PACKET_CAPACITY >= TUN_MTU as usize);
    assert!(UDP_RX_SLOTS <= 1024);
    assert!(UDP_TX_SLOTS <= 4096);
    assert!(TUN_TX_SLOTS <= 4096);
};
