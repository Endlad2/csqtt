// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    net_setup::{TUN_ADDR, TUN_IFACE, enable_ipv4_forwarding, setup_nat},
    perf::{self, Profiler, Stage, thread_cpu_time_ns},
    uring_io::{IoCounters, PacketSink, UringIo},
};
use anyhow::{Context, Result, anyhow};
use std::{
    net::SocketAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{Arc, mpsc},
    thread::JoinHandle,
    time::Instant,
};

pub trait DataplaneLogic: Send + 'static {
    type Command: Send + 'static;

    fn on_udp(&mut self, peer: SocketAddr, packet: &mut [u8], sink: &mut PacketSink<'_>);
    fn on_tun(&mut self, packet: &mut [u8], sink: &mut PacketSink<'_>);
    fn begin_batch(&mut self, now: Instant);
    fn on_command(&mut self, command: Self::Command, sink: &mut PacketSink<'_>);
    fn on_tick(&mut self, sink: &mut PacketSink<'_>);
    fn on_io_counters(&mut self, counters: IoCounters);
}

pub struct DataplaneConfig {
    pub listen: SocketAddr,
    pub tun_iface: String,
    pub tun_addr: String,
    pub command_capacity: usize,
}

impl DataplaneConfig {
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            tun_iface: TUN_IFACE.to_owned(),
            tun_addr: TUN_ADDR.to_owned(),
            command_capacity: 1024,
        }
    }
}

enum RuntimeCommand<C> {
    Logic(C),
    Shutdown,
}

struct HandleInner<C> {
    sender: mpsc::SyncSender<RuntimeCommand<C>>,
    event_fd: Arc<OwnedFd>,
}

pub struct DataplaneHandle<C> {
    inner: Arc<HandleInner<C>>,
}

impl<C> Clone for DataplaneHandle<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<C> DataplaneHandle<C> {
    pub fn try_send(&self, command: C) -> Result<()> {
        self.inner
            .sender
            .try_send(RuntimeCommand::Logic(command))
            .map_err(|error| anyhow!("dataplane command queue: {error}"))?;
        signal_eventfd(self.inner.event_fd.as_raw_fd())
    }

    pub fn shutdown(&self) -> Result<()> {
        self.inner
            .sender
            .send(RuntimeCommand::Shutdown)
            .map_err(|error| anyhow!("dataplane shutdown queue: {error}"))?;
        signal_eventfd(self.inner.event_fd.as_raw_fd())
    }
}

pub struct DataplaneRuntime<C> {
    handle: DataplaneHandle<C>,
    join: Option<JoinHandle<Result<()>>>,
    status: tokio::sync::watch::Receiver<Option<String>>,
}

impl<C: Send + 'static> DataplaneRuntime<C> {
    pub fn handle(&self) -> DataplaneHandle<C> {
        self.handle.clone()
    }

    pub fn status_receiver(&self) -> tokio::sync::watch::Receiver<Option<String>> {
        self.status.clone()
    }

    pub fn shutdown(mut self) -> Result<()> {
        let signal_result = self.handle.shutdown();
        let join_result = if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| anyhow!("dataplane thread panicked"))?
        } else {
            Ok(())
        };
        match (signal_result, join_result) {
            (_, Err(error)) => Err(error),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

pub fn spawn<L>(config: DataplaneConfig, logic: L) -> Result<DataplaneRuntime<L::Command>>
where
    L: DataplaneLogic,
{
    let event_fd = create_eventfd()?;
    let (command_tx, command_rx) = mpsc::sync_channel(config.command_capacity.max(16));
    let handle = DataplaneHandle {
        inner: Arc::new(HandleInner {
            sender: command_tx,
            event_fd: event_fd.clone(),
        }),
    };
    let (startup_tx, startup_rx) = mpsc::sync_channel::<Result<()>>(1);
    let (status_tx, status_rx) = tokio::sync::watch::channel(None::<String>);
    let thread_event_fd = event_fd.clone();
    let join = std::thread::Builder::new()
        .name("csqtt-uring".to_owned())
        .spawn(move || {
            let result = run_dataplane(config, logic, command_rx, thread_event_fd, &startup_tx);
            let status = match &result {
                Ok(()) => "io_uring dataplane stopped".to_owned(),
                Err(error) => format!("io_uring dataplane failed: {error:#}"),
            };
            let _ = status_tx.send(Some(status));
            result
        })
        .context("spawn io_uring dataplane")?;
    match startup_rx.recv().context("wait dataplane startup")? {
        Ok(()) => Ok(DataplaneRuntime {
            handle,
            join: Some(join),
            status: status_rx,
        }),
        Err(error) => {
            let _ = join.join();
            Err(error)
        }
    }
}

fn run_dataplane<L>(
    config: DataplaneConfig,
    mut logic: L,
    command_rx: mpsc::Receiver<RuntimeCommand<L::Command>>,
    event_fd: Arc<OwnedFd>,
    startup_tx: &mpsc::SyncSender<Result<()>>,
) -> Result<()>
where
    L: DataplaneLogic,
{
    enable_ipv4_forwarding()?;
    let mut io = match UringIo::new(
        config.listen,
        event_fd.as_raw_fd(),
        &config.tun_iface,
        &config.tun_addr,
    ) {
        Ok(io) => io,
        Err(error) => {
            let _ = startup_tx.send(Err(clone_anyhow(&error)));
            return Err(error);
        }
    };
    setup_nat(&config.tun_iface)?;
    perf::publish_dataplane_tid();
    let _ = startup_tx.send(Ok(()));
    let mut running = true;
    let mut last_counters = io.counters();
    let mut last_report_packets = 0u64;
    let mut completions = Vec::with_capacity(crate::packet::COMPLETION_BATCH);
    let mut profiler = Profiler::default();
    while running {
        let wait_started = profiler.begin(Stage::IoWait, 0);
        let wait_result = io.wait_into(&mut completions, wait_started.is_some());
        profiler.finish(Stage::IoWait, wait_started);
        let wait_timing = wait_result?;
        profiler.record_timing(
            Stage::IoEnter,
            wait_timing.enter_calls,
            wait_started.is_some(),
            wait_timing.enter_cpu_ns,
            wait_timing.enter_wall_ns,
        );
        profiler.record_timing(
            Stage::SqSubmit,
            wait_timing.submit_calls,
            wait_started.is_some(),
            wait_timing.submit_cpu_ns,
            wait_timing.submit_wall_ns,
        );
        profiler.record_timing(
            Stage::CqDrain,
            wait_timing.drain_calls,
            wait_started.is_some(),
            wait_timing.drain_cpu_ns,
            wait_timing.drain_wall_ns,
        );
        let cqe_started = profiler.begin(Stage::CqeProcessing, completions.len());
        logic.begin_batch(Instant::now());
        let mut publish_perf = false;
        for completion in completions.iter().copied() {
            let (kind, _) = UringIo::completion_kind(completion);
            if kind == UringIo::tag_tun_tx() {
                io.process_tun_tx_ready(completion.result);
            }
        }
        for completion in completions.iter().copied() {
            let (kind, slot_id) = UringIo::completion_kind(completion);
            if kind == UringIo::tag_tun_tx() {
                continue;
            } else if kind == UringIo::tag_udp_tx_ready() {
                io.process_udp_tx_ready(completion.result);
            } else if kind == UringIo::tag_udp_rx() {
                let started = profiler.begin(Stage::UdpRx, completion.result.max(0) as usize);
                let mut callback_span = None;
                let result = io.process_udp_rx(slot_id, completion.result, |peer, packet, sink| {
                    let callback_started = started.map(|_| thread_cpu_time_ns());
                    logic.on_udp(peer, packet, sink);
                    if let Some(callback_started) = callback_started {
                        callback_span = Some((callback_started, thread_cpu_time_ns()));
                    }
                });
                finish_exclusive(&mut profiler, Stage::UdpRx, started, callback_span);
                result?;
            } else if kind == UringIo::tag_udp_rx_multi() {
                let started = profiler.begin(Stage::UdpRx, completion.result.max(0) as usize);
                let mut callback_span = None;
                let result = io.process_udp_rx_multi(
                    completion.result,
                    completion.flags,
                    |peer, packet, sink| {
                        let callback_started = started.map(|_| thread_cpu_time_ns());
                        logic.on_udp(peer, packet, sink);
                        if let Some(callback_started) = callback_started {
                            callback_span = Some((callback_started, thread_cpu_time_ns()));
                        }
                    },
                );
                finish_exclusive(&mut profiler, Stage::UdpRx, started, callback_span);
                result?;
            } else if kind == UringIo::tag_tun_rx() {
                let started = profiler.begin(Stage::TunRx, 0);
                let mut callback_ns = 0u64;
                let result = io.process_tun_rx(completion.result, |packet, sink| {
                    let callback_started = started.map(|_| thread_cpu_time_ns());
                    logic.on_tun(packet, sink);
                    if let Some(callback_started) = callback_started {
                        callback_ns = callback_ns
                            .saturating_add(thread_cpu_time_ns().saturating_sub(callback_started));
                    }
                });
                let batch = result?;
                profiler.expand_batch(Stage::TunRx, batch.packets, batch.bytes, started.is_some());
                finish_exclusive_total(&mut profiler, Stage::TunRx, started, callback_ns);
            } else if kind == UringIo::tag_eventfd() {
                io.process_eventfd_completion(completion.result)?;
                let SelfDrain { keep_running } = drain_commands(&command_rx, &mut logic, &mut io)?;
                running = keep_running;
            } else if kind == UringIo::tag_tick() {
                io.process_tick_completion(completion.result)?;
                profiler.refresh_enabled();
                if profiler.enabled() {
                    perf::publish_dataplane_cpu(thread_cpu_time_ns());
                }
                io.with_sink(|sink| logic.on_tick(sink));
                logic.on_io_counters(io.counters());
                publish_perf = true;
            }
        }
        profiler.finish(Stage::CqeProcessing, cqe_started);
        let pending_udp_tx = io.pending_udp_tx_len();
        if pending_udp_tx != 0 {
            let flush_started = profiler.begin(Stage::Flush, pending_udp_tx);
            let flush_result = io.flush_udp_tx();
            profiler.finish(Stage::Flush, flush_started);
            flush_result?;
        }
        let pending_tun_tx = io.pending_tun_tx_len();
        if pending_tun_tx != 0 {
            io.flush_tun_tx()?;
        }
        let bookkeeping_started = profiler.begin(Stage::Bookkeeping, 0);
        let counters = io.counters();
        let total_rx = counters
            .udp_rx_packets
            .saturating_add(counters.tun_rx_packets);
        let report_due = total_rx.saturating_sub(last_report_packets) >= 1024
            || counters.udp_tx_errors != last_counters.udp_tx_errors
            || counters.tun_tx_errors != last_counters.tun_tx_errors
            || counters.udp_rx_errors != last_counters.udp_rx_errors
            || counters.tun_rx_errors != last_counters.tun_rx_errors;
        if report_due {
            logic.on_io_counters(counters);
            last_counters = counters;
            last_report_packets = total_rx;
        }
        profiler.finish(Stage::Bookkeeping, bookkeeping_started);
        if publish_perf {
            profiler.publish_dataplane();
        }
    }
    Ok(())
}

fn finish_exclusive(
    profiler: &mut Profiler,
    stage: Stage,
    started: Option<u64>,
    callback_span: Option<(u64, u64)>,
) {
    let Some(started) = started else {
        return;
    };
    let finished = thread_cpu_time_ns();
    let elapsed = callback_span.map_or_else(
        || finished.saturating_sub(started),
        |(callback_started, callback_finished)| {
            callback_started
                .saturating_sub(started)
                .saturating_add(finished.saturating_sub(callback_finished))
        },
    );
    profiler.finish_elapsed(stage, elapsed);
}

fn finish_exclusive_total(
    profiler: &mut Profiler,
    stage: Stage,
    started: Option<u64>,
    excluded_ns: u64,
) {
    let Some(started) = started else {
        return;
    };
    let elapsed = thread_cpu_time_ns()
        .saturating_sub(started)
        .saturating_sub(excluded_ns);
    profiler.finish_elapsed(stage, elapsed);
}

struct SelfDrain {
    keep_running: bool,
}

fn drain_commands<L>(
    receiver: &mpsc::Receiver<RuntimeCommand<L::Command>>,
    logic: &mut L,
    io: &mut UringIo,
) -> Result<SelfDrain>
where
    L: DataplaneLogic,
{
    let mut keep_running = true;
    for _ in 0..4096 {
        match receiver.try_recv() {
            Ok(RuntimeCommand::Logic(command)) => {
                io.with_sink(|sink| logic.on_command(command, sink));
            }
            Ok(RuntimeCommand::Shutdown) => {
                keep_running = false;
                break;
            }
            Err(mpsc::TryRecvError::Empty) => break,
            Err(mpsc::TryRecvError::Disconnected) => {
                keep_running = false;
                break;
            }
        }
    }
    Ok(SelfDrain { keep_running })
}

fn create_eventfd() -> Result<Arc<OwnedFd>> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(Arc::new(owned))
}

fn signal_eventfd(fd: i32) -> Result<()> {
    let value = 1u64;
    let written = unsafe {
        libc::write(
            fd,
            (&value as *const u64).cast::<libc::c_void>(),
            std::mem::size_of::<u64>(),
        )
    };
    if written == std::mem::size_of::<u64>() as isize {
        Ok(())
    } else if written < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            Ok(())
        } else {
            Err(error.into())
        }
    } else {
        Err(anyhow!("short eventfd write: {written}"))
    }
}

fn clone_anyhow(error: &anyhow::Error) -> anyhow::Error {
    anyhow!(error.to_string())
}
