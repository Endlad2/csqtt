<!-- SPDX-FileCopyrightText: 2026 amurcanov -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# csqtt io_uring rewrite

Toolchain target: Rust 1.97.1, edition 2024, x86_64-unknown-linux-musl.

The packet data plane is single-owner and uses raw io_uring for UDP and TUN I/O. Tokio remains the cold control plane for the web panel, persistence, proxy orchestration, janitors, and administrative operations. The old per-stream Tokio mpsc packet fanout and O(N) worker probing are not used by the new TUN route path.

`udp_supervisor.rs` is compiled only by tests. Fatal io_uring dataplane termination is surfaced to `main.rs`, which performs orderly server shutdown so an external process supervisor can restart the process.

Run `build_linux.bat --tests` or `./build_linux.sh --tests` to verify formatting, Clippy with warnings denied, tests, and the Linux musl release link.
