// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    App, lock_unpoison, log_event,
    model::{MAX_PASSWORDS, PasswordEntry, is_expired, now, random_password, random_token},
    protocol,
};
use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use subtle::ConstantTimeEq;

#[derive(Clone)]
struct WebState {
    app: Arc<App>,
}

#[derive(Deserialize)]
struct LoginRequest {
    user: String,
    pass: String,
}

#[derive(Deserialize)]
struct CreateClientRequest {
    name: String,
    days: i64,
    hash: String,
    dtls_port: Option<u16>,
    wg_port: Option<u16>,
    local_port: Option<u16>,
}

#[derive(Deserialize)]
struct SettingsRequest {
    #[serde(default)]
    main_password: Option<String>,
    #[serde(default)]
    dns_primary: Option<String>,
    #[serde(default)]
    dns_secondary: Option<String>,
}

#[derive(Serialize)]
struct ClientInfo {
    password: String,
    down: i64,
    up: i64,
    expires: i64,
    active: bool,
    active_sessions: usize,
    vk_hash: String,
    ports: String,
    device_id: String,
    ip: String,
    name: String,
    vk_hashes: String,
    dtls_port: u16,
    wg_port: u16,
    local_port: u16,
}

#[derive(Deserialize)]
struct StreamDebugRequest {
    enabled: bool,
}

#[derive(Serialize)]
struct StreamDebugInfo {
    id: u64,
    source: String,
    device_id: String,
    generation: u64,
    tunnel_ip: String,
    mode: &'static str,
    tunnel_ready: bool,
    handshake_ready: bool,
    created_at: u64,
    last_seen: u64,
    debug_started_at: u64,
    up_bytes: u64,
    down_bytes: u64,
    up_packets: u64,
    down_packets: u64,
}

const CAESAR_SHIFT: u8 = 47;

fn caesar_decode(value: &str) -> String {
    if let Some(rest) = value.strip_prefix("c1:")
        && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(rest)
    {
        let decoded: Vec<u8> = bytes.iter().map(|b| b.wrapping_sub(CAESAR_SHIFT)).collect();
        if let Ok(s) = String::from_utf8(decoded) {
            return s;
        }
    }
    value.to_owned()
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn cookie_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .filter_map(|part| part.strip_prefix("csqtt_session=").map(str::to_owned))
        .collect()
}

fn constant_equal(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

fn authorized(app: &App, headers: &HeaderMap) -> bool {
    cookie_tokens(headers).iter().any(|token| {
        app.web_sessions
            .get(&hash_token(token))
            .map(|expiry| *expiry > now())
            .unwrap_or(false)
    })
}

async fn auth_middleware(
    State(state): State<WebState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if authorized(&state.app, request.headers()) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(header::SET_COOKIE, expired_session_cookie())],
        )
            .into_response()
    }
}

fn expired_session_cookie() -> &'static str {
    "csqtt_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict; Secure"
}

async fn root(State(state): State<WebState>, headers: HeaderMap) -> Response {
    if authorized(&state.app, &headers) {
        Html(PANEL_HTML).into_response()
    } else {
        (
            [(header::SET_COOKIE, expired_session_cookie())],
            Html(LOGIN_HTML),
        )
            .into_response()
    }
}

async fn login(
    State(state): State<WebState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Response {
    let trust_xff = std::env::var("CSQTT_TRUST_XFF")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let source = if trust_xff {
        headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| addr.ip().to_string())
    } else {
        addr.ip().to_string()
    };

    let current = now();
    if let Some(value) = state.app.login_limits.get(&source)
        && value.1 > current
        && value.0 >= 3
    {
        return (StatusCode::TOO_MANY_REQUESTS, "too many attempts").into_response();
    }

    let user = caesar_decode(&request.user);
    let pass = caesar_decode(&request.pass);
    let valid =
        constant_equal(&user, &state.app.web_user) & constant_equal(&pass, &state.app.web_pass);

    if !valid {
        state
            .app
            .login_limits
            .entry(source)
            .and_modify(|v| {
                if v.1 <= current {
                    *v = (1, current + 180);
                } else {
                    v.0 += 1;
                }
            })
            .or_insert((1, current + 180));
        return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
    }

    state.app.login_limits.remove(&source);
    let token = random_token(32);
    state.web_session_insert(token.clone());
    let cookie =
        format!("csqtt_session={token}; Path=/; Max-Age=86400; HttpOnly; SameSite=Strict; Secure");
    (StatusCode::OK, [(header::SET_COOKIE, cookie)], "ok").into_response()
}

impl WebState {
    fn web_session_insert(&self, token: String) {
        let key = hash_token(&token);
        self.app.web_sessions.insert(key, now() + 86400);
    }
}

async fn logout(State(state): State<WebState>, headers: HeaderMap) -> Response {
    let tokens = cookie_tokens(&headers);
    if !tokens.is_empty() {
        for token in &tokens {
            state.app.web_sessions.remove(&hash_token(token));
        }
    }
    (
        StatusCode::OK,
        [(header::SET_COOKIE, expired_session_cookie())],
        "ok",
    )
        .into_response()
}

async fn logout_all(State(state): State<WebState>) -> Response {
    state.app.web_sessions.clear();
    (
        StatusCode::OK,
        [(header::SET_COOKIE, expired_session_cookie())],
        "ok",
    )
        .into_response()
}

fn proc_kib(text: &str, field: &str) -> Option<u64> {
    text.lines()
        .find(|line| line.starts_with(field))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

#[derive(Default)]
struct ProcessMemory {
    rss: u64,
    peak: u64,
    anonymous: u64,
    file: u64,
    shared: u64,
    swap: u64,
}

fn process_memory(text: &str) -> ProcessMemory {
    ProcessMemory {
        rss: proc_kib(text, "VmRSS:").unwrap_or(0),
        peak: proc_kib(text, "VmHWM:").unwrap_or(0),
        anonymous: proc_kib(text, "RssAnon:").unwrap_or(0),
        file: proc_kib(text, "RssFile:").unwrap_or(0),
        shared: proc_kib(text, "RssShmem:").unwrap_or(0),
        swap: proc_kib(text, "VmSwap:").unwrap_or(0),
    }
}

fn format_memory_kib(kib: u64) -> String {
    let (value, unit) = if kib >= 1024 * 1024 {
        (kib as f64 / (1024.0 * 1024.0), "GB")
    } else {
        (kib as f64 / 1024.0, "MB")
    };
    let mut value = format!("{value:.2}");
    while value.ends_with('0') {
        value.pop();
    }
    if value.ends_with('.') {
        value.pop();
    }
    format!("{value} {unit}")
}

fn format_total_memory_kib(kib: u64) -> String {
    if kib >= 1024 * 1024 {
        let mut value = format!("{:.1}", kib as f64 / (1024.0 * 1024.0));
        if value.ends_with(".0") {
            value.truncate(value.len() - 2);
        }
        format!("{value} GB")
    } else {
        format!("{} MB", (kib + 512) / 1024)
    }
}

async fn stats(State(state): State<WebState>, _headers: HeaderMap) -> impl IntoResponse {
    let (process_status, memory_info) = tokio::join!(
        tokio::fs::read_to_string("/proc/self/status"),
        tokio::fs::read_to_string("/proc/meminfo")
    );
    let process_memory = process_status
        .as_deref()
        .map(process_memory)
        .unwrap_or_default();
    let total_ram = memory_info
        .ok()
        .and_then(|text| proc_kib(&text, "MemTotal:"))
        .unwrap_or(0);

    let cpu_total = state.app.cpu_percent.load(Ordering::Relaxed);
    let cpu_cores = state.app.cpu_cores.load(Ordering::Relaxed).max(1);
    let cpu_capacity = cpu_cores.saturating_mul(100);
    let cpu_normalized = cpu_total
        .saturating_mul(100)
        .checked_div(cpu_capacity)
        .unwrap_or(0)
        .min(100);
    let db = state.app.db.read().await;
    let (
        local_proxy_active,
        local_proxy_tcp_sessions,
        local_proxy_udp_flows,
        local_proxy_tcp_peak,
        local_proxy_udp_peak,
        local_proxy_tcp_total,
        local_proxy_udp_total,
    ) = {
        let route = state.app.proxy_route.read().await;
        let active = route.as_ref().is_some_and(|route| route.is_alive());
        let proxy_stats = route
            .as_ref()
            .map(|route| route.diagnostic_snapshot())
            .unwrap_or_default();
        (
            active,
            proxy_stats.tcp_active,
            proxy_stats.udp_active,
            proxy_stats.tcp_peak,
            proxy_stats.udp_peak,
            proxy_stats.tcp_total,
            proxy_stats.udp_total,
        )
    };
    Json(serde_json::json!({
        "ram": format!("{} / {}", format_memory_kib(process_memory.rss), format_total_memory_kib(total_ram)),
        "ram_used": format_memory_kib(process_memory.rss),
        "ram_total": format_total_memory_kib(total_ram),
        "ram_peak": format_memory_kib(process_memory.peak),
        "ram_anonymous": format_memory_kib(process_memory.anonymous),
        "ram_file": format_memory_kib(process_memory.file),
        "ram_shared": format_memory_kib(process_memory.shared),
        "ram_swap": format_memory_kib(process_memory.swap),
        "ram_used_kib": process_memory.rss,
        "ram_peak_kib": process_memory.peak,
        "ram_anonymous_kib": process_memory.anonymous,
        "ram_file_kib": process_memory.file,
        "ram_shared_kib": process_memory.shared,
        "ram_swap_kib": process_memory.swap,
        "cpu_total": cpu_total,
        "cpu_capacity": cpu_capacity,
        "cpu_normalized": cpu_normalized,
        "status": "Active",
        "uptime": now().saturating_sub(state.app.started),
        "active": state.app.sessions.len(),
        "total": state.app.total_connections.load(Ordering::Relaxed),
        "up": state.app.bytes_from_client.load(Ordering::Relaxed),
        "down": state.app.bytes_to_client.load(Ordering::Relaxed),
        "passwords": db.passwords.len(),
        "devices": db.devices.len(),
        "transport": "RTP/ChaCha20-Poly1305",
        "tunnel": "userspace-tun",
        "local_proxy_enabled": !db.local_proxy.active_profile_id.is_empty(),
        "local_proxy_port": db.local_proxy.active_profile().map(|p| p.port).unwrap_or(0),
        "local_proxy_active": local_proxy_active,
        "local_proxy_port_listening": state.app.proxy_port_listening.load(Ordering::Acquire),
        "local_proxy_health_error": state.app.proxy_health_error.read().unwrap().clone(),
        "local_proxy_tcp_sessions": local_proxy_tcp_sessions,
        "local_proxy_udp_flows": local_proxy_udp_flows,
        "local_proxy_tcp_peak": local_proxy_tcp_peak,
        "local_proxy_udp_peak": local_proxy_udp_peak,
        "local_proxy_tcp_total": local_proxy_tcp_total,
        "local_proxy_udp_total": local_proxy_udp_total,
        "hot_sessions": protocol::ACTIVE_SESSIONS_GAUGE.load(Ordering::Relaxed),
        "hot_session_capacity": protocol::HOT_SESSION_CAPACITY_GAUGE.load(Ordering::Relaxed),
        "public_session_capacity": state.app.sessions.capacity(),
        "stream_debug_enabled": state.app.stream_debug_active.load(Ordering::Acquire)
    }))
}

async fn settings_get(State(state): State<WebState>) -> impl IntoResponse {
    let db = state.app.db.read().await;
    let dns = db.dns.clone();
    let mut parts = dns.splitn(2, ',');
    let primary = parts.next().unwrap_or("1.1.1.1").trim().to_owned();
    let secondary = parts.next().unwrap_or("1.0.0.1").trim().to_owned();
    Json(serde_json::json!({
        "main_password": db.main_password,
        "dns_primary": primary,
        "dns_secondary": secondary,
        "restart_required": db.main_password != state.app.startup_main_password
            || db.dns != state.app.startup_dns
    }))
}

async fn settings_post(
    State(state): State<WebState>,
    Json(request): Json<SettingsRequest>,
) -> Response {
    if let Some(password) = request.main_password.as_ref()
        && !password.is_empty()
        && (password.len() < 4 || password.len() > 128)
    {
        return (
            StatusCode::BAD_REQUEST,
            "password length must be 4..128 or empty",
        )
            .into_response();
    }
    let dns = match (&request.dns_primary, &request.dns_secondary) {
        (None, None) => None,
        (Some(primary), secondary) => {
            let primary = primary.trim();
            let secondary = secondary.as_deref().unwrap_or_default().trim();
            if primary.is_empty() {
                return (StatusCode::BAD_REQUEST, "primary DNS is required").into_response();
            }
            if primary.parse::<std::net::Ipv4Addr>().is_err()
                || (!secondary.is_empty() && secondary.parse::<std::net::Ipv4Addr>().is_err())
            {
                return (StatusCode::BAD_REQUEST, "DNS must be a valid IPv4 address")
                    .into_response();
            }
            Some(if secondary.is_empty() {
                primary.to_owned()
            } else {
                format!("{primary},{secondary}")
            })
        }
        (None, Some(_)) => {
            return (StatusCode::BAD_REQUEST, "primary DNS is required").into_response();
        }
    };
    let revision = {
        let mut db = state.app.db.write().await;
        if let Some(password) = request.main_password {
            db.main_password = password;
        }
        if let Some(dns) = dns {
            db.dns = dns;
        }
        state.app.db_persistence.submit(db.clone())
    };
    match state.app.db_persistence.wait(revision).await {
        Ok(()) => {}
        Err(error) => {
            eprintln!("[SETTINGS] Failed to persist settings: {error}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist settings",
            )
                .into_response();
        }
    }
    if crate::protocol::refresh_credentials(&state.app)
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to refresh credentials",
        )
            .into_response();
    }
    let restart_required = {
        let db = state.app.db.read().await;
        db.main_password != state.app.startup_main_password || db.dns != state.app.startup_dns
    };
    Json(serde_json::json!({ "restart_required": restart_required })).into_response()
}

async fn clients_get(State(state): State<WebState>) -> impl IntoResponse {
    let db = state.app.db.read().await;
    let mut session_counts = std::collections::HashMap::new();
    for entry in state.app.sessions.iter() {
        *session_counts
            .entry(entry.value().password.clone())
            .or_insert(0) += 1;
    }

    let mut list: Vec<ClientInfo> = db
        .passwords
        .iter()
        .map(|(password, entry)| ClientInfo {
            password: password.clone(),
            down: entry.down_bytes,
            up: entry.up_bytes,
            expires: entry.expires_at,
            active: !entry.is_deactivated && !is_expired(entry),
            active_sessions: session_counts.get(password).copied().unwrap_or(0),
            vk_hash: entry.vk_hash.clone(),
            ports: entry.ports.clone(),
            device_id: entry.device_id.clone(),
            ip: db
                .devices
                .get(&entry.device_id)
                .map(|d| d.ip.clone())
                .unwrap_or_default(),
            name: entry.name.clone(),
            vk_hashes: entry.vk_hashes.clone(),
            dtls_port: entry.dtls_port,
            wg_port: entry.wg_port,
            local_port: entry.local_port,
        })
        .collect();
    if !db.main_password.is_empty() {
        let mut session_up = 0;
        let mut session_down = 0;
        if let Some(s) = state
            .app
            .sessions
            .iter()
            .find(|s| s.password == db.main_password)
        {
            session_up = s.up_bytes.load(Ordering::Relaxed) as i64;
            session_down = s.down_bytes.load(Ordering::Relaxed) as i64;
        }

        list.push(ClientInfo {
            password: db.main_password.clone(),
            down: db.main_down_bytes + session_down,
            up: db.main_up_bytes + session_up,
            expires: 0,
            active: true,
            active_sessions: session_counts.get(&db.main_password).copied().unwrap_or(0),
            vk_hash: String::new(),
            ports: String::new(),
            device_id: db.main_device_id.clone(),
            ip: db
                .devices
                .get(&db.main_device_id)
                .map(|d| d.ip.clone())
                .unwrap_or_else(|| "Сервер".to_string()),
            name: "Главный пароль".to_string(),
            vk_hashes: String::new(),
            dtls_port: 0,
            wg_port: 0,
            local_port: 0,
        });
    }

    Json(list)
}

async fn stream_debug_toggle(
    State(state): State<WebState>,
    Json(request): Json<StreamDebugRequest>,
) -> Response {
    state
        .app
        .stream_debug_active
        .store(false, Ordering::Release);
    if request.enabled {
        for entry in state.app.sessions.iter() {
            entry.value().stream_debug.reset();
        }
    }
    state
        .app
        .stream_debug_active
        .store(request.enabled, Ordering::Release);

    Json(serde_json::json!({ "enabled": request.enabled })).into_response()
}

async fn client_streams(
    State(state): State<WebState>,
    Path(password): Path<String>,
) -> impl IntoResponse {
    if !state.app.stream_debug_active.load(Ordering::Acquire) {
        return Json(serde_json::json!({
            "enabled": false,
            "server_now": now(),
            "streams": []
        }));
    }

    let mut sessions: Vec<_> = state
        .app
        .sessions
        .iter()
        .filter(|entry| entry.value().password == password)
        .map(|entry| entry.value().clone())
        .collect();
    sessions.sort_unstable_by_key(|session| (session.created_at, session.id));

    let streams: Vec<StreamDebugInfo> = sessions
        .into_iter()
        .filter_map(|session| {
            let metrics = session.stream_debug.snapshot();
            if !metrics.active {
                return None;
            }
            let device_id = lock_unpoison(&session.device_id).clone();
            let tunnel_ip = lock_unpoison(&session.tunnel_ip)
                .map(|ip| format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]))
                .unwrap_or_default();
            let mode = if session.is_srtp { "SRTP" } else { "RTP" };
            Some(StreamDebugInfo {
                id: session.id,
                source: session.address.to_string(),
                device_id,
                generation: session.generation_id.load(Ordering::Relaxed),
                tunnel_ip,
                mode,
                tunnel_ready: session.has_tunnel.load(Ordering::Relaxed),
                handshake_ready: session.handshake_done.load(Ordering::Relaxed),
                created_at: session.created_at,
                last_seen: session.last_seen.load(Ordering::Relaxed),
                debug_started_at: metrics.started_at,
                up_bytes: metrics.up_bytes,
                down_bytes: metrics.down_bytes,
                up_packets: metrics.up_packets,
                down_packets: metrics.down_packets,
            })
        })
        .collect();

    Json(serde_json::json!({
        "enabled": true,
        "server_now": now(),
        "streams": streams
    }))
}

fn normalize_client_vk_hashes(raw: &str) -> Result<String, &'static str> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.len() > 1024 {
        return Err("VK hashes are too long");
    }
    if value.chars().any(char::is_whitespace) {
        return Err("VK hashes must be comma-separated without spaces");
    }
    let hashes: Vec<_> = value.split(',').collect();
    if hashes.len() > 6 || hashes.iter().any(|hash| hash.len() < 16) {
        return Err("provide 1 to 6 valid VK hashes");
    }
    Ok(hashes.join(","))
}

async fn clients_create(
    State(state): State<WebState>,
    Json(request): Json<CreateClientRequest>,
) -> Response {
    if request.days < 0 || request.days > 3650 {
        return (StatusCode::BAD_REQUEST, "days must be 0..3650").into_response();
    }
    let vk_hashes = match normalize_client_vk_hashes(&request.hash) {
        Ok(value) => value,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };

    let dtls_port = request.dtls_port.unwrap_or(46000);
    let wg_port = request.wg_port.unwrap_or(46001);
    let local_port = request.local_port.unwrap_or(0);
    let ports = format!("{},{},{}", dtls_port, wg_port, local_port);

    let result = {
        let mut db = state.app.db.write().await;
        db.passwords.retain(|_, entry| !is_expired(entry));
        if db.passwords.len() >= MAX_PASSWORDS {
            return (StatusCode::BAD_REQUEST, "limit reached").into_response();
        }
        let password = (0..64)
            .map(|_| random_password())
            .find(|candidate| !db.passwords.contains_key(candidate));

        let Some(password) = password else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };

        let expires = if request.days == 0 {
            0
        } else {
            now().saturating_add(request.days.saturating_mul(86400))
        };
        db.passwords.insert(
            password.clone(),
            PasswordEntry {
                device_id: String::new(),
                expires_at: expires,
                down_bytes: 0,
                up_bytes: 0,
                vk_hash: vk_hashes.clone(),
                ports,
                is_deactivated: false,
                name: request.name.clone(),
                vk_hashes: vk_hashes.clone(),
                dtls_port,
                wg_port,
                local_port,
            },
        );
        state.app.db_persistence.submit(db.clone());
        (password, expires)
    };
    if crate::protocol::refresh_credentials(&state.app)
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to refresh credentials",
        )
            .into_response();
    }

    Json(serde_json::json!({
        "password": result.0,
        "expires": result.1,
        "dtls_port": dtls_port,
        "wg_port": wg_port,
        "local_port": local_port,
        "vk_hashes": vk_hashes
    }))
    .into_response()
}

async fn client_update(
    State(state): State<WebState>,
    Path(password): Path<String>,
    Json(request): Json<CreateClientRequest>,
) -> Response {
    if request.days < 0 || request.days > 3650 {
        return (StatusCode::BAD_REQUEST, "days must be 0..3650").into_response();
    }
    let vk_hashes = match normalize_client_vk_hashes(&request.hash) {
        Ok(value) => value,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };

    {
        let mut db = state.app.db.write().await;
        let Some(entry) = db.passwords.get_mut(&password) else {
            return StatusCode::NOT_FOUND.into_response();
        };

        let dtls_port = request.dtls_port.unwrap_or(46000);
        let wg_port = request.wg_port.unwrap_or(46001);
        let local_port = request.local_port.unwrap_or(0);

        entry.name = request.name.clone();
        entry.expires_at = if request.days == 0 {
            0
        } else {
            now().saturating_add(request.days.saturating_mul(86400))
        };
        entry.vk_hash = vk_hashes.clone();
        entry.vk_hashes = vk_hashes;
        entry.dtls_port = dtls_port;
        entry.wg_port = wg_port;
        entry.local_port = local_port;
        entry.ports = format!("{},{},{}", dtls_port, wg_port, local_port);
        state.app.db_persistence.submit(db.clone());
    }
    if crate::protocol::refresh_credentials(&state.app)
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to refresh credentials",
        )
            .into_response();
    }
    StatusCode::OK.into_response()
}

async fn client_toggle(State(state): State<WebState>, Path(password): Path<String>) -> Response {
    {
        let mut db = state.app.db.write().await;
        let Some(entry) = db.passwords.get_mut(&password) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        entry.is_deactivated = !entry.is_deactivated;
        state.app.db_persistence.submit(db.clone());
    }

    crate::protocol::drop_password_sessions(&state.app, &password);
    if crate::protocol::refresh_credentials(&state.app)
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to refresh credentials",
        )
            .into_response();
    }

    StatusCode::OK.into_response()
}

async fn client_unbind(State(state): State<WebState>, Path(password): Path<String>) -> Response {
    {
        let mut db = state.app.db.write().await;
        if password == db.main_password {
            db.main_device_id.clear();
            state.app.db_persistence.submit(db.clone());
        } else if let Some(entry) = db.passwords.get_mut(&password) {
            entry.device_id.clear();
            state.app.db_persistence.submit(db.clone());
        } else {
            return StatusCode::NOT_FOUND.into_response();
        }
    }

    crate::protocol::drop_password_sessions(&state.app, &password);

    StatusCode::OK.into_response()
}

async fn client_delete(State(state): State<WebState>, Path(password): Path<String>) -> Response {
    {
        let mut db = state.app.db.write().await;
        if db.passwords.remove(&password).is_none() {
            return StatusCode::NOT_FOUND.into_response();
        };
        state.app.derived_keys.remove(&password);
        state.app.db_persistence.submit(db.clone());
    }

    crate::protocol::drop_password_sessions(&state.app, &password);
    if crate::protocol::refresh_credentials(&state.app)
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to refresh credentials",
        )
            .into_response();
    }

    StatusCode::OK.into_response()
}

async fn reboot(State(state): State<WebState>) -> Response {
    if protocol::notify_panel_restart(&state.app).is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let app = state.app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let _ = protocol::notify_panel_restart(&app);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let _ = protocol::notify_panel_restart(&app);
        tokio::time::sleep(std::time::Duration::from_millis(650)).await;
        protocol::drop_all_sessions(&app);
        if let Err(error) = crate::request_service_restart() {
            log_event(
                &app,
                "ERROR",
                "SYSTEM",
                &format!("Managed restart request failed: {error:#}"),
            );
        }
    });
    StatusCode::ACCEPTED.into_response()
}

async fn web_session_janitor(app: Arc<App>) {
    let mut timer = tokio::time::interval(Duration::from_secs(300));
    loop {
        timer.tick().await;
        let current = now();
        app.web_sessions.retain(|_, expiry| *expiry > current);
        app.login_limits.retain(|_, value| value.1 > current);
        app.web_sessions.shrink_to_fit();
        app.login_limits.shrink_to_fit();
    }
}

pub enum DualProtocolStream {
    #[allow(dead_code)]
    Plain(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>),
}

impl tokio::io::AsyncRead for DualProtocolStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            DualProtocolStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            DualProtocolStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for DualProtocolStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            DualProtocolStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            DualProtocolStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            DualProtocolStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            DualProtocolStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            DualProtocolStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            DualProtocolStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

#[derive(Clone)]
pub struct DualAcceptor {
    tls_acceptor: axum_server::tls_rustls::RustlsAcceptor,
}

impl DualAcceptor {
    pub fn new(config: axum_server::tls_rustls::RustlsConfig) -> Self {
        Self {
            tls_acceptor: axum_server::tls_rustls::RustlsAcceptor::new(config),
        }
    }
}

impl<S> axum_server::accept::Accept<tokio::net::TcpStream, S> for DualAcceptor
where
    S: Send + Clone + 'static,
{
    type Stream = DualProtocolStream;
    type Service = S;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::io::Result<(Self::Stream, Self::Service)>> + Send,
        >,
    >;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let tls_acceptor = self.tls_acceptor.clone();
        Box::pin(async move {
            let mut buf = [0u8; 1];
            let _ = stream.peek(&mut buf).await?;
            if buf[0] == 0x16 {
                let (tls_stream, service) = tls_acceptor.accept(stream, service).await?;
                Ok((DualProtocolStream::Tls(Box::new(tls_stream)), service))
            } else {
                let mut stream = stream;
                use tokio::io::AsyncReadExt;
                let mut read_buf = vec![0u8; 4096];
                let mut total_read = 0;
                while total_read < read_buf.len() - 1 {
                    let max_to_read = std::cmp::min(1024, read_buf.len() - 1 - total_read);
                    match tokio::time::timeout(
                        Duration::from_millis(500),
                        stream.read(&mut read_buf[total_read..total_read + max_to_read]),
                    )
                    .await
                    {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => {
                            total_read += n;
                            if read_buf[..total_read].windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Ok(Err(_)) => break,
                        Err(_) => break,
                    }
                }

                let req_str = String::from_utf8_lossy(&read_buf[..total_read]);
                let mut host = String::new();
                let mut path = "/".to_string();

                let mut lines = req_str.lines();
                if let Some(first_line) = lines.next() {
                    let parts: Vec<&str> = first_line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        path = parts[1].to_string();
                    }
                }

                for line in lines {
                    if line.to_lowercase().starts_with("host:")
                        && let Some(h) = line.split_once(':').map(|x| x.1)
                    {
                        host = h.trim().to_string();
                    }
                }

                if host.is_empty() {
                    host = "127.0.0.1:46002".to_string();
                }

                let redirect_response = format!(
                    "HTTP/1.1 301 Moved Permanently\r\n\
                     Location: https://{}{}\r\n\
                     Connection: close\r\n\
                     Content-Length: 0\r\n\r\n",
                    host, path
                );

                use tokio::io::AsyncWriteExt;
                let _ = stream.write_all(redirect_response.as_bytes()).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;

                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "HTTP redirected to HTTPS",
                ))
            }
        })
    }
}

#[derive(Deserialize)]
struct LogsToggleRequest {
    active: bool,
}

async fn logs_get(State(state): State<WebState>) -> impl IntoResponse {
    let lines = lock_unpoison(&state.app.logs)
        .iter()
        .cloned()
        .collect::<Vec<String>>();
    Json(serde_json::json!({
        "path": state.app.log_file_path.to_string_lossy(),
        "active": state.app.logging_active.load(Ordering::Relaxed),
        "lines": lines
    }))
}

async fn logs_toggle(
    State(state): State<WebState>,
    Json(request): Json<LogsToggleRequest>,
) -> Response {
    state
        .app
        .logging_active
        .store(request.active, Ordering::Relaxed);

    {
        let mut db = state.app.db.write().await;
        db.logging_active = Some(request.active);
        state.app.db_persistence.submit(db.clone());
    }

    StatusCode::OK.into_response()
}

async fn logs_clear(State(state): State<WebState>) -> Response {
    lock_unpoison(&state.app.logs).clear();

    let path = state.app.log_file_path.clone();
    tokio::spawn(async move {
        let _ = tokio::fs::remove_file(&path).await;
    });

    StatusCode::OK.into_response()
}

#[derive(Deserialize)]
struct ProfileRequest {
    #[serde(default)]
    name: String,
    port: u16,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

async fn local_proxy_get(State(state): State<WebState>) -> impl IntoResponse {
    let (proxy_state, active, tcp_sessions, udp_flows) = {
        let db = state.app.db.read().await;
        let route = state.app.proxy_route.read().await;
        let active = route.as_ref().is_some_and(|r| r.is_alive());
        let (tcp_sessions, udp_flows) =
            route.as_ref().map(|r| r.stats_snapshot()).unwrap_or((0, 0));
        (db.local_proxy.clone(), active, tcp_sessions, udp_flows)
    };
    let profiles: Vec<serde_json::Value> = proxy_state
        .profiles
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "name": p.name,
                "port": p.port,
                "username": p.username,
                "password": p.password,
            })
        })
        .collect();
    Json(serde_json::json!({
        "active_profile_id": proxy_state.active_profile_id,
        "profiles": profiles,
        "route_active": active,
        "port_listening": state.app.proxy_port_listening.load(std::sync::atomic::Ordering::Acquire),
        "health_error": state.app.proxy_health_error.read().unwrap().clone(),
        "tcp_sessions": tcp_sessions,
        "udp_flows": udp_flows,
    }))
}

async fn local_proxy_create(
    State(state): State<WebState>,
    Json(request): Json<ProfileRequest>,
) -> Response {
    let port = if request.port == 0 {
        crate::model::DEFAULT_LOCAL_PROXY_PORT
    } else {
        request.port
    };
    let profile = crate::model::LocalProxyProfile {
        id: crate::model::LocalProxyProfile::new_id(),
        name: if request.name.is_empty() {
            format!("SOCKS5 :{port}")
        } else {
            request.name
        },
        port,
        username: request.username,
        password: request.password,
    };
    if let Err(error) = crate::proxy_route::validate_config(&profile) {
        return (StatusCode::BAD_REQUEST, error.to_string()).into_response();
    }
    let id = profile.id.clone();
    {
        let mut db = state.app.db.write().await;
        if db.local_proxy.profiles.len() >= 20 {
            return (StatusCode::BAD_REQUEST, "Too many profiles (max 20)").into_response();
        }
        db.local_proxy.profiles.push(profile);
        state.app.db_persistence.submit(db.clone());
    }
    log_event(
        &state.app,
        "INFO",
        "PROXY",
        &format!("SOCKS5 profile created: {id}"),
    );
    let port_listening = crate::proxy_route::port_is_listening(port).await;
    Json(serde_json::json!({ "id": id, "port_listening": port_listening })).into_response()
}

async fn local_proxy_update(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Json(request): Json<ProfileRequest>,
) -> Response {
    let port = if request.port == 0 {
        crate::model::DEFAULT_LOCAL_PROXY_PORT
    } else {
        request.port
    };
    let temp_profile = crate::model::LocalProxyProfile {
        id: id.clone(),
        name: request.name.clone(),
        port,
        username: request.username.clone(),
        password: request.password.clone(),
    };
    if let Err(error) = crate::proxy_route::validate_config(&temp_profile) {
        return (StatusCode::BAD_REQUEST, error.to_string()).into_response();
    }
    let was_active;
    {
        let mut db = state.app.db.write().await;
        was_active = db.local_proxy.active_profile_id == id;
        let Some(profile) = db.local_proxy.find_profile_mut(&id) else {
            return (StatusCode::NOT_FOUND, "Profile not found").into_response();
        };
        if !request.name.is_empty() {
            profile.name = request.name;
        }
        profile.port = port;
        profile.username = request.username;
        profile.password = request.password;
        state.app.db_persistence.submit(db.clone());
    }
    if was_active {
        state.app.proxy_trigger.notify_one();
    }
    log_event(
        &state.app,
        "INFO",
        "PROXY",
        &format!("SOCKS5 profile updated: {id}"),
    );
    let port_listening = crate::proxy_route::port_is_listening(port).await;
    Json(serde_json::json!({ "updated": true, "port_listening": port_listening })).into_response()
}

async fn local_proxy_delete(State(state): State<WebState>, Path(id): Path<String>) -> Response {
    let was_active;
    {
        let mut db = state.app.db.write().await;
        was_active = db.local_proxy.active_profile_id == id;
        if !db.local_proxy.remove_profile(&id) {
            return (StatusCode::NOT_FOUND, "Profile not found").into_response();
        }
        state.app.db_persistence.submit(db.clone());
    }
    if was_active {
        state.app.proxy_trigger.notify_one();
    }
    log_event(
        &state.app,
        "INFO",
        "PROXY",
        &format!("SOCKS5 profile deleted: {id}"),
    );
    Json(serde_json::json!({ "deleted": true })).into_response()
}

async fn local_proxy_activate(State(state): State<WebState>, Path(id): Path<String>) -> Response {
    {
        let mut db = state.app.db.write().await;
        if db.local_proxy.find_profile(&id).is_none() {
            return (StatusCode::NOT_FOUND, "Profile not found").into_response();
        }
        db.local_proxy.active_profile_id = id.clone();
        state.app.db_persistence.submit(db.clone());
    }
    log_event(
        &state.app,
        "INFO",
        "PROXY",
        "Local SOCKS5 settings saved; applying TPROXY route",
    );
    state.app.proxy_trigger.notify_one();
    Json(serde_json::json!({ "activated": true })).into_response()
}

async fn local_proxy_deactivate(State(state): State<WebState>) -> Response {
    {
        let mut db = state.app.db.write().await;
        db.local_proxy.active_profile_id.clear();
        state.app.db_persistence.submit(db.clone());
    }
    log_event(
        &state.app,
        "INFO",
        "PROXY",
        "Local SOCKS5 routing disabled; restoring direct route",
    );
    state.app.proxy_trigger.notify_one();
    Json(serde_json::json!({ "deactivated": true })).into_response()
}

async fn logs_download(State(state): State<WebState>) -> impl IntoResponse {
    let path = state.app.log_file_path.clone();
    if let Ok(file) = tokio::fs::File::open(&path).await {
        let body = axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(file));
        let headers = [
            (
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"csqtt.log\"",
            ),
        ];
        (headers, body).into_response()
    } else {
        (axum::http::StatusCode::NOT_FOUND, "Log file not found").into_response()
    }
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let h = response.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    h.insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'",
        ),
    );
    response
}

pub async fn run(
    app: Arc<App>,
    tls_config: axum_server::tls_rustls::RustlsConfig,
) -> anyhow::Result<()> {
    let state = WebState { app: app.clone() };
    let protected = Router::new()
        .route("/api/stats", get(stats))
        .route("/api/settings", get(settings_get).post(settings_post))
        .route("/api/clients", get(clients_get).post(clients_create))
        .route("/api/stream-debug", post(stream_debug_toggle))
        .route("/api/clients/{password}/streams", get(client_streams))
        .route(
            "/api/clients/{password}",
            post(client_update).delete(client_delete),
        )
        .route("/api/clients/{password}/toggle", post(client_toggle))
        .route("/api/clients/{password}/unbind", post(client_unbind))
        .route("/api/logs", get(logs_get))
        .route("/api/logs/toggle", post(logs_toggle))
        .route("/api/logs/clear", post(logs_clear))
        .route("/api/logs/download", get(logs_download))
        .route(
            "/api/local-proxy",
            get(local_proxy_get).post(local_proxy_create),
        )
        .route(
            "/api/local-proxy/profiles/{id}",
            put(local_proxy_update).delete(local_proxy_delete),
        )
        .route("/api/local-proxy/activate/{id}", post(local_proxy_activate))
        .route("/api/local-proxy/deactivate", post(local_proxy_deactivate))
        .route("/api/logout", post(logout))
        .route("/api/logout_all", post(logout_all))
        .route("/api/reboot", post(reboot))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let router = Router::new()
        .route("/", get(root))
        .route("/api/login", post(login))
        .merge(protected)
        .layer(middleware::from_fn(security_headers))
        .with_state(state);

    tokio::spawn(web_session_janitor(app.clone()));
    println!("[WEB] HTTP/HTTPS listening on 0.0.0.0:{}", app.web_port);
    let acceptor = DualAcceptor::new(tls_config);
    axum_server::Server::bind(SocketAddr::from(([0, 0, 0, 0], app.web_port)))
        .acceptor(acceptor)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

const LOGIN_HTML: &str = r##"
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Вход</title>
    <style>
        :root {
            --bg-color: #f8fafc;
            --surface: #ffffff;
            --primary: #0077ff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --error: #ef4444;
            --border: #e2e8f0;
            --glass: rgba(255, 255, 255, 0.9);
        }

        html { -webkit-text-size-adjust: none; text-size-adjust: none; }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif; }
        body { background-color: var(--bg-color); color: var(--text-main); min-height: 100vh; display: flex; align-items: center; justify-content: center; overflow: hidden; }

        main {
            z-index: 1; width: min(420px, calc(100% - 40px)); background: var(--glass);
            backdrop-filter: blur(20px); border: 1px solid var(--border); border-radius: 24px;
            padding: 48px 40px; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.05);
            animation: slideUp 0.6s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes slideUp { from { opacity: 0; transform: translateY(40px); } to { opacity: 1; transform: translateY(0); } }

        h1 { text-align: center; font-size: 28px; font-weight: 700; margin-bottom: 36px; color: var(--text-main); }

        .input-group { margin-bottom: 20px; }
        .input-group label { display: block; font-size: 13px; font-weight: 600; color: var(--text-muted); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.05em; }
        .input-group input { width: 100%; height: 52px; background: #f8fafc; border: 1px solid var(--border); border-radius: 14px; padding: 0 16px; font-size: 15px; color: var(--text-main); outline: none; transition: all 0.2s; }
        .input-group input:focus { border-color: var(--primary); box-shadow: 0 0 0 4px rgba(0, 119, 255, 0.1); }

        button { width: 100%; height: 52px; background: var(--primary); color: white; border: none; border-radius: 14px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.2s; margin-top: 12px; box-shadow: 0 8px 16px rgba(0, 119, 255, 0.25); }
        button:hover { transform: translateY(-2px); box-shadow: 0 12px 20px rgba(0, 119, 255, 0.35); }
        button:active { transform: translateY(0); }

        #e { min-height: 20px; color: var(--error); font-size: 14px; font-weight: 500; text-align: center; margin-top: 16px; opacity: 0; }
    </style>
</head>
<body>
    <main>
        <h1>Вход</h1>
        <form id="f">
            <div class="input-group">
                <label for="u">Пользователь</label>
                <input id="u" required>
            </div>
            <div class="input-group">
                <label for="p">Пароль</label>
                <input id="p" type="password" required>
            </div>
            <button id="submitBtn" type="submit">Войти</button>
            <div id="e"></div>
        </form>
    </main>
    <script>
        function caesarEncode(s) {
            const bytes = new TextEncoder().encode(s);
            let bin = '';
            for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode((bytes[i] + 47) & 0xff);
            return 'c1:' + btoa(bin);
        }
        f.onsubmit = async x => {
            x.preventDefault();
            const btn = document.getElementById('submitBtn');
            const err = document.getElementById('e');
            err.style.opacity = '0';
            try {
                let r = await fetch("/api/login", { method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify({user: caesarEncode(u.value), pass: caesarEncode(p.value)}) });
                if (r.ok) {
                    btn.innerHTML = 'Успешно!'; btn.style.background = '#0077ff';
                    setTimeout(() => location.reload(), 500);
                } else {
                    err.textContent = r.status === 429 ? "Подождите 3 минуты." : "Неверный логин или пароль"; err.style.opacity = '1';
                }
            } catch (error) { err.textContent = "Ошибка сети"; err.style.opacity = '1'; }
        };
    </script>
</body>
</html>

"##;

const PANEL_HTML: &str = r##"
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSQTT</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDggMTA4Ij48cmVjdCB3aWR0aD0iMTA4IiBoZWlnaHQ9IjEwOCIgcng9IjI0IiBmaWxsPSIjMEQwRTExIi8+PGRlZnM+PHJhZGlhbEdyYWRpZW50IGlkPSJnMSIgY3g9IjU0IiBjeT0iNTQiIHI9IjQwIj48c3RvcCBvZmZzZXQ9IjAlIiBzdG9wLWNvbG9yPSIjMDQ3NEZCIiBzdG9wLW9wYWNpdHk9IjAuMTUiLz48c3RvcCBvZmZzZXQ9IjYwJSIgc3RvcC1jb2xvcj0iIzAyNUVDQiIgc3RvcC1vcGFjaXR5PSIwLjA0Ii8+PHN0b3Agb2Zmc2V0PSIxMDAlIiBzdG9wLWNvbG9yPSIjMDAwMDAwIiBzdG9wLW9wYWNpdHk9IjAiLz48L3JhZGlhbEdyYWRpZW50PjxsaW5lYXJHcmFkaWVudCBpZD0iZzIiIHgxPSIyOCIgeTE9IjM2IiB4Mj0iNzgiIHkyPSI3MiIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPjxzdG9wIG9mZnNldD0iMCUiIHN0b3AtY29sb3I9IiM0RkEzRkYiLz48c3RvcCBvZmZzZXQ9IjEwMCUiIHN0b3AtY29sb3I9IiMwNDc0ZmIiLz48L2xpbmVhckdyYWRpZW50PjwvZGVmcz48Y2lyY2xlIGN4PSI1NCIgY3k9IjU0IiByPSI0MCIgZmlsbD0idXJsKCNnMSkiLz48cGF0aCBkPSJNIDc4LjYsMzYuOCBBIDMwLDMwIDAgMSwwIDc4LjYsNzEuMiBMIDY5LjYsNjQuOSBBIDE5LDE5IDAgMSwxIDY5LjYsNDMuMSBaIiBmaWxsPSJ1cmwoI2cyKSIvPjwvc3ZnPg==">
    <style>
        :root {
            --bg-color: #f8fafc;
            --surface: #ffffff;
            --surface-hover: #f1f5f9;
            --primary: #0077ff;
            --primary-hover: #0060cc;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --glass: rgba(255, 255, 255, 0.9);
            --icon-bg: rgba(0, 119, 255, 0.1);
            --header-glass: rgba(255, 255, 255, 0.8);
        }

        [data-theme="dark"] {
            --bg-color: #000000;
            --surface: #0a0a0c;
            --surface-hover: #161619;
            --text-main: #f4f4f5;
            --text-muted: #9ca3af;
            --border: #1f1f23;
            --glass: rgba(10, 10, 12, 0.85);
            --header-glass: rgba(0, 0, 0, 0.8);
            --icon-bg: rgba(0, 119, 255, 0.15);
        }

        html { -webkit-text-size-adjust: none; text-size-adjust: none; }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif; }
        body { background-color: var(--bg-color); color: var(--text-main); min-height: 100vh; display: flex; flex-direction: column; overflow-x: hidden; width: 100%; }

        body, header, .header-container, .brand, .brand-logo, .version-logo, .yoomoney-button, .support-card, .header-actions, .btn, main, .glass-panel,
        .stat-card, .stat-icon, .stat-value, .stat-sub, .progress-bar, .progress-fill,
        .section-header, .section-title, .table-wrapper, table, th, td, tr,
        .client-name, .client-pw, .client-hash, .traffic-flex, .badge, .actions,
        .settings-grid, .setting-card, .input-group, .input-group input,
        .toggle-row, .switch, .slider, dialog, .dlg-row, .dlg-actions,
        svg, path, rect, line, polyline, circle, .tab-btn {
            transition: background-color 0.3s ease, border-color 0.3s ease, color 0.3s ease, fill 0.3s ease, stroke 0.3s ease, box-shadow 0.3s ease;
        }

        .glass-panel { background: var(--surface); border: 1px solid var(--border); border-radius: 20px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); }

        header { position: sticky; top: 0; z-index: 40; height: 72px; background: var(--header-glass); backdrop-filter: blur(16px); border-bottom: 1px solid var(--border); width: 100%; }
        .header-container { max-width: 1300px; width: 100%; margin: 0 auto; padding: 0 24px; height: 100%; display: flex; align-items: center; justify-content: space-between; }
        .brand { display: flex; align-items: center; flex: 0 1 auto; min-width: 0; }
        .brand-logo { display: block; width: 165px; height: auto; }
        .version-logo { display: block; width: 180px; height: auto; flex: 0 1 auto; }
        .yoomoney-button {
            display: inline-flex; align-items: center; justify-content: center; width: 100%;
            height: 48px; min-height: 48px; padding: 0 16px; border: 0; border-radius: 12px;
            background: #8b3ffd; box-shadow: 0 4px 12px rgba(139, 63, 253, 0.28); text-decoration: none;
        }
        .yoomoney-button:hover { background: #7c2ee8; transform: translateY(-1px); box-shadow: 0 6px 16px rgba(139, 63, 253, 0.38); }
        .yoomoney-button:active { transform: scale(0.96); }
        .yoomoney-button:focus-visible { outline: 2px solid #8b3ffd; outline-offset: 3px; }
        .yoomoney-logo { display: block; width: 120px; height: 26px; }
        .crypto-button {
            display: inline-flex; align-items: center; justify-content: center; width: 100%;
            height: 48px; min-height: 48px; padding: 0 16px; border: 0; border-radius: 12px;
            background: #1e293b; box-shadow: 0 4px 12px rgba(30, 41, 59, 0.38); text-decoration: none; cursor: pointer;
        }
        .crypto-button:hover { background: #334155; transform: translateY(-1px); box-shadow: 0 6px 16px rgba(30, 41, 59, 0.48); }
        .crypto-button:active { transform: scale(0.96); }
        .crypto-button:focus-visible { outline: 2px solid #38bdf8; outline-offset: 3px; }
        .crypto-logo { display: block; width: 120px; height: auto; }

        .header-actions { display: flex; gap: 16px; align-items: center; }

        .restart-required-banner { display: none; width: 100%; padding: 11px 20px; background: #b91c1c; color: #fff; text-align: center; font-size: 13px; font-weight: 700; box-shadow: 0 8px 20px rgba(185, 28, 28, 0.24); transform: translateY(-100%); opacity: 0; }
        .restart-required-banner.visible { display: block; animation: restartBannerIn 0.32s ease-out forwards; }
        @keyframes restartBannerIn { to { transform: translateY(0); opacity: 1; } }

        .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 20px; font-size: 14px; font-weight: 600; border-radius: 12px; border: none; cursor: pointer; transition: all 0.2s; outline: none; }
        .btn:active { transform: scale(0.96); }
        .btn-primary { background: var(--primary); color: #fff; box-shadow: 0 4px 12px rgba(0, 119, 255, 0.25); }
        .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 6px 16px rgba(0, 119, 255, 0.35); }
        .btn:disabled { cursor: not-allowed; opacity: 0.42; transform: none !important; box-shadow: none; }
        .btn.save-success { background: #10b981; opacity: 1; }
        .btn-ghost { background: transparent; color: var(--text-muted); }
        .btn-ghost:hover { background: var(--surface-hover); color: var(--text-main); }
        .btn-icon { padding: 8px; border-radius: 10px; }

        main { max-width: 1300px; width: 100%; margin: 0 auto; padding: 32px 24px 80px; display: flex; flex-direction: column; gap: 32px; }

        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; }
        .stat-card { padding: 24px; display: flex; flex-direction: column; gap: 12px; position: relative; overflow: hidden; }
        .stat-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: var(--primary); opacity: 0.8; }
        .stat-header { display: flex; align-items: center; justify-content: space-between; }
        .stat-icon { width: 40px; height: 40px; border-radius: 12px; background: var(--icon-bg); color: var(--primary); display: grid; place-items: center; }
        .stat-icon svg { width: 20px; height: 20px; fill: currentColor; stroke: currentColor; }
        .stat-label { font-size: 13px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
        .stat-value { font-size: 28px; font-weight: 700; color: var(--text-main); line-height: 1.1; }
        #ram_val { white-space: nowrap; max-width: 100%; overflow: hidden; text-overflow: ellipsis; }
        #ram_detail { white-space: nowrap; max-width: 100%; overflow: hidden; text-overflow: ellipsis; }
        .stat-sub { font-size: 13px; color: var(--text-muted); margin-top: 4px; }
        .progress-bar { width: 100%; height: 6px; background: var(--surface-hover); border-radius: 3px; margin-top: 8px; overflow: hidden; }
        .progress-fill { height: 100%; background: var(--primary); border-radius: 3px; transition: width 0.5s ease-out; }

        .tabs-container { display: flex; justify-content: center; margin-bottom: 8px; }
        .tabs { display: inline-flex; background: var(--surface); border: 1px solid var(--border); padding: 4px; border-radius: 14px; gap: 4px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); }
        .tab-btn { background: transparent; border: none; color: var(--text-muted); padding: 8px 20px; font-size: 14px; font-weight: 600; border-radius: 10px; cursor: pointer; display: flex; align-items: center; gap: 8px; outline: none; white-space: nowrap; }
        .tab-btn:hover { color: var(--text-main); }
        .tab-btn.active { background: var(--primary); color: #ffffff; box-shadow: 0 4px 12px rgba(0, 119, 255, 0.2); }

        .section-header { display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 16px; }
        .section-title { font-size: 22px; font-weight: 700; display: flex; align-items: center; gap: 10px; color: var(--text-main); }
        .section-title svg { stroke: var(--primary); }

        .table-wrapper { overflow-x: auto; border-radius: 16px; background: var(--surface); border: 1px solid var(--border); }
        table { width: 100%; border-collapse: collapse; min-width: 900px; }
        th { text-align: left; padding: 16px 20px; font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; border-bottom: 1px solid var(--border); background: var(--bg-color); transition: background 0.3s; }
        td { padding: 16px 20px; border-bottom: 1px solid var(--border); vertical-align: middle; transition: background 0.2s, border-color 0.3s; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: var(--surface-hover); }

        .client-name { font-weight: 600; font-size: 15px; margin-bottom: 4px; display: flex; align-items: center; gap: 8px;}
        .client-pw { font-family: ui-monospace, SFMono-Regular, 'Cascadia Code', Consolas, monospace; font-size: 12px; color: var(--primary); background: var(--icon-bg); padding: 2px 6px; border-radius: 4px; }
        .client-hash { font-family: ui-monospace, SFMono-Regular, 'Cascadia Code', Consolas, monospace; font-size: 12px; color: var(--text-muted); max-width: 200px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 4px; }
        
        .traffic-flex { display: flex; flex-direction: column; gap: 4px; font-family: ui-monospace, SFMono-Regular, 'Cascadia Code', Consolas, monospace; font-size: 13px; }
        .t-up { color: var(--primary); } .t-down { color: var(--primary); }

        .badge { display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }
        .badge::before { content: ''; display: block; width: 6px; height: 6px; border-radius: 50%; background: var(--primary); }
        .badge.active { background: var(--icon-bg); color: var(--primary); border: 1px solid var(--primary); }
        .badge.inactive { background: var(--surface-hover); color: var(--text-muted); border: 1px solid var(--border); }
        .badge.inactive::before { background: var(--text-muted); }

        .actions { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
        .empty-state { text-align: center; padding: 64px 20px; color: var(--text-muted); }

        .settings-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .setting-card { padding: 24px; }
        .settings-actions-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin-bottom: 20px; }
        .settings-action-btn {
            width: 100%; min-width: 0; padding: 10px 8px; border: 0; background: transparent;
            color: var(--text-main); font-size: 14px; font-weight: 600; cursor: pointer; border-radius: 8px;
        }
        .settings-action-btn:hover { color: var(--primary); background: transparent; }
        .settings-action-btn:active { transform: scale(0.97); }
        .settings-action-btn:focus-visible { outline: 2px solid var(--primary); outline-offset: 2px; }
        .settings-action-btn.reboot { color: var(--primary); }
        .settings-action-btn.reboot:hover { color: #005fcc; }
        .settings-action-btn.danger { color: #ef4444; }
        .settings-action-btn.danger:hover { color: #dc2626; }
        .support-card { padding: 24px; display: flex; flex-direction: column; gap: 18px; }
        .support-card-title { margin: 0; color: var(--text-main); font-size: 16px; font-weight: 600; }
        .proxy-info-btn {
            width: 24px; height: 24px; flex: 0 0 24px; display: inline-flex; align-items: center; justify-content: center;
            border: 1px solid var(--border); border-radius: 50%; background: var(--bg-color); color: var(--text-muted);
            font-size: 14px; font-weight: 700; line-height: 1; cursor: pointer; transition: color .2s, border-color .2s, background .2s;
        }
        .proxy-info-btn:hover { color: var(--primary); border-color: var(--primary); background: var(--icon-bg); }
        .proxy-info-btn:focus-visible { outline: 2px solid var(--primary); outline-offset: 2px; }
        .proxy-info-btn svg { width: 15px; height: 15px; display: block; }
        .proxy-info-list { margin: 0; padding-left: 20px; color: var(--text-muted); font-size: 14px; line-height: 1.6; }
        .proxy-info-list li + li { margin-top: 12px; }
        .proxy-info-list strong { color: var(--text-main); }
        .proxy-profiles { display: flex; flex-direction: column; gap: 10px; }
        .proxy-profile-card {
            display: flex; align-items: center; gap: 12px; padding: 14px 16px;
            background: var(--bg-color); border: 1px solid var(--border); border-radius: 14px;
            transition: border-color .2s, background .2s, box-shadow .2s;
        }
        .proxy-profile-card.is-active { border-color: #10b981; background: rgba(16, 185, 129, 0.06); }
        .proxy-profile-dot {
            width: 10px; height: 10px; flex: 0 0 10px; border-radius: 50%;
            background: var(--border); transition: background .2s;
        }
        .proxy-profile-card.is-active .proxy-profile-dot { background: #10b981; box-shadow: 0 0 8px rgba(16, 185, 129, 0.4); }
        .proxy-profile-body { flex: 1; min-width: 0; }
        .proxy-profile-name { font-size: 14px; font-weight: 600; color: var(--text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .proxy-profile-meta { font-size: 12px; color: var(--text-muted); margin-top: 2px; }
        .proxy-profile-actions { display: flex; gap: 4px; flex-shrink: 0; }
        .proxy-profile-actions button {
            width: 32px; height: 32px; display: inline-flex; align-items: center; justify-content: center;
            border: 1px solid var(--border); border-radius: 8px; background: transparent;
            color: var(--text-muted); font-size: 15px; cursor: pointer; transition: color .2s, border-color .2s, background .2s;
        }
        .proxy-profile-actions button:hover { color: var(--primary); border-color: var(--primary); background: var(--icon-bg); }
        .proxy-profile-actions button.danger:hover { color: #ef4444; border-color: #ef4444; }
        .proxy-profile-actions button svg { width: 15px; height: 15px; display: block; }
        .proxy-empty { text-align: center; padding: 32px 16px; color: var(--text-muted); font-size: 14px; }
        .proxy-add-btn {
            display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px;
            border: 1px dashed var(--border); border-radius: 8px; background: transparent;
            color: var(--text-muted); font-size: 18px; font-weight: 400; cursor: pointer;
            transition: color .2s, border-color .2s, background .2s;
        }
        .proxy-add-btn:hover { color: var(--primary); border-color: var(--primary); background: var(--icon-bg); }
        .proxy-add-btn svg { width: 16px; height: 16px; display: block; }
        input { background: var(--bg-color); color: var(--text-main); border: 1px solid var(--border); border-radius: 12px; outline: none; }
        .input-group { margin-bottom: 16px; }
        .input-group label { display: block; font-size: 13px; font-weight: 600; color: var(--text-muted); margin-bottom: 8px; text-transform: uppercase; }
        .input-group input { width: 100%; height: 48px; background: var(--bg-color); color: var(--text-main); border: 1px solid var(--border); border-radius: 12px; padding: 0 16px; font-size: 14px; outline: none; transition: background 0.3s, border-color 0.3s, color 0.3s; }
        .input-group input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(0, 119, 255, 0.15); }
        .input-group input.is-invalid { border-color: #ef4444 !important; box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.15) !important; }
        
        .toggle-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 16px; padding: 12px; background: var(--bg-color); border-radius: 12px; border: 1px solid var(--border); transition: background 0.3s, border-color 0.3s; }
        .toggle-row label { font-size: 14px; font-weight: 600; color: var(--text-main); margin: 0; text-transform: none; white-space: nowrap; }
        .vk-hashes-toggle { margin-top: 10px; }
        .switch { position: relative; display: inline-block; width: 44px; height: 24px; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: var(--border); transition: .3s; border-radius: 24px; }
        .slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background-color: white; transition: .3s; border-radius: 50%; }
        input:checked + .slider { background-color: var(--primary); }
        input:checked + .slider:before { transform: translateX(20px); }

        dialog { margin: auto; width: min(500px, calc(100% - 32px)); background: var(--surface); color: var(--text-main); border: 1px solid var(--border); border-radius: 24px; padding: 32px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25); }
        dialog::backdrop { background: rgba(0,0,0,0.4); backdrop-filter: blur(4px); }
        dialog h2 { margin-bottom: 24px; font-size: 24px; }
        .dlg-row { display: flex; gap: 16px; }
        .dlg-row > div { flex: 1; }
        .dlg-actions { display: flex; justify-content: flex-end; flex-wrap: wrap; gap: 12px; margin-top: 32px; }

        .client-cards-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 16px;
            margin-top: 16px;
        }
        .client-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 16px;
            cursor: pointer;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
            display: flex;
            flex-direction: column;
            gap: 10px;
            position: relative;
        }
        .client-card:hover {
            background: var(--surface-hover);
            transform: translateY(-2px);
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }
        .client-card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
            margin-bottom: 2px;
        }
        .client-card-title {
            font-size: 15px;
            font-weight: 700;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .client-card-body {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .client-card-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 13px;
        }
        .client-card-label {
            color: var(--text-muted);
            font-weight: 600;
        }
        .client-card-value {
            color: var(--text-main);
            font-weight: 500;
        }
        .clients-toolbar {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 16px;
            width: 100%;
        }
        .stream-debug-control {
            display: flex;
            align-items: center;
            gap: 10px;
            color: var(--text-muted);
            font-size: 13px;
            font-weight: 600;
            white-space: nowrap;
        }
        .stream-card-actions {
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .stream-stats-btn {
            height: 28px;
            min-height: 28px;
            padding: 0 10px;
            border: 1px solid var(--primary);
            border-radius: 8px;
            background: var(--icon-bg);
            color: var(--primary);
            font-size: 11px;
            font-weight: 700;
            cursor: pointer;
            white-space: nowrap;
        }
        .stream-stats-btn:hover {
            background: var(--primary);
            color: #ffffff;
        }
        .stream-count-value {
            height: 28px;
            min-width: 28px;
            padding: 0 8px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border-radius: 8px;
            background: var(--surface-hover);
            color: var(--text-main);
            font-weight: 700;
            font-family: ui-monospace, SFMono-Regular, 'Cascadia Code', Consolas, monospace;
        }
        
        .dlg-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .dlg-header h2 {
            margin: 0;
            font-size: 22px;
        }
        .close-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 4px;
            border-radius: 50%;
            display: grid;
            place-items: center;
            outline: none;
        }
        .close-btn:hover {
            background: var(--surface-hover);
            color: var(--text-main);
        }

        @keyframes spin { 100% { transform: rotate(360deg); } }
        @keyframes shrink { from { width: 100%; } to { width: 0%; } }
        
        .toast-container { position: fixed; bottom: 24px; right: 24px; z-index: 100; display: flex; flex-direction: column; gap: 10px; }
        .toast { 
            position: relative;
            background: var(--surface); 
            border: 1px solid var(--border); 
            color: var(--text-main); 
            padding: 14px 20px; 
            border-radius: 12px; 
            font-size: 14px; 
            font-weight: 500; 
            display: flex; 
            align-items: center; 
            gap: 10px; 
            box-shadow: 0 10px 25px rgba(0,0,0,0.1); 
            animation: toastIn 0.3s forwards; 
            overflow: hidden;
            transition: all 0.3s;
        }
        .toast.hide { animation: toastOut 0.3s forwards; }
        @keyframes toastIn { from { opacity: 0; transform: translateX(50px); } to { opacity: 1; transform: translateX(0); } }
        @keyframes toastOut { from { opacity: 1; transform: translateX(0); } to { opacity: 0; transform: translateX(50px); } }
        .toast-icon { display: grid; place-items: center; width: 24px; height: 24px; border-radius: 50%; background: var(--icon-bg); color: var(--primary); }

        .toast-success { border-left: 3px solid #10b981; }
        .toast-error { border-left: 3px solid #ef4444; }
        
        .toast-progress {
            position: absolute; bottom: 0; left: 0; height: 3px; width: 100%;
            background: rgba(0,0,0,0.3);
            animation: shrink 1.5s linear forwards;
        }

        .show-mobile { display: none !important; }
        @media(max-width: 480px) {
            .hide-mobile { display: none !important; }
            .show-mobile { display: inline-block !important; }
            
            .header-container { padding: 0 10px !important; }
            .brand-logo { width: 92px !important; }
            .header-actions { gap: 6px !important; }
            .version-logo { width: 82px !important; }
            .header-actions .btn:not(.btn-icon) { padding: 6px 8px !important; font-size: 12px !important; white-space: nowrap !important; }
            .header-actions .btn-icon { padding: 6px !important; }
            
            .routing-panel { padding: 16px !important; }
            .routing-header { gap: 8px !important; margin-bottom: 16px !important; }
        }

        .toast-container { position: fixed; bottom: 24px; right: 24px; z-index: 100; display: flex; flex-direction: column; gap: 10px; }

        @media(max-width: 768px) { 
            header { height: 64px; } 
            .header-container { padding: 0 16px; }
            .brand-logo { width: 128px; }
            .version-logo { width: 132px; }
            main { padding: 20px 12px 80px; gap: 20px; } 
            
            .tabs-container { width: 100%; margin-bottom: 4px; }
            .tabs { display: flex; width: 100%; }
            .tab-btn { flex: 1; justify-content: center; padding: 10px 0; font-size: 13px; }

            .dashboard { grid-template-columns: repeat(2, 1fr); gap: 12px; } 
            .dashboard .stat-card {
                padding: 12px 14px;
                min-height: 106px;
                display: flex;
                flex-direction: column;
                justify-content: space-between;
                gap: 8px;
            }
            .dashboard .cpu-card,
            .dashboard .memory-card {
                grid-column: auto;
                min-width: 0;
                min-height: 106px;
            }
            .dashboard .traffic-card {
                grid-column: span 2;
                min-height: auto;
                flex-direction: row;
                align-items: center;
                justify-content: space-between;
                padding: 12px 16px;
            }
            .dashboard .traffic-card .stat-header {
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .dashboard .traffic-card div[style*="display: flex"] {
                flex-direction: row !important;
                gap: 16px !important;
            }
            .dashboard .traffic-card .stat-value {
                font-size: 15px !important;
            }
            .dashboard .cpu-card .stat-value,
            .dashboard .memory-card .stat-value {
                font-size: 18px;
                letter-spacing: -0.04em;
            }

            .stat-icon { width: 32px; height: 32px; border-radius: 8px; }
            .stat-icon svg { width: 16px; height: 16px; }
            .stat-label { font-size: 11px; }
            .stat-value { font-size: 18px; }
            .stat-sub { font-size: 11px; }
            .progress-bar { margin-top: 4px; }

            .section-header { flex-direction: column; align-items: flex-start; gap: 12px; }
            .section-header .btn { width: 100%; }
            .dlg-row { flex-direction: column; gap: 0; } 
            dialog { padding: 20px 16px; width: calc(100% - 24px); }
            .dlg-actions { flex-direction: row; flex-wrap: wrap; gap: 8px !important; }
            .dlg-actions .btn { flex: 1 1 0; width: auto; font-size: 13px !important; padding: 12px 4px !important; font-weight: 600; min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
            .toggle-row { gap: 8px; padding: 10px; }
            .toggle-row > label:first-child { font-size: 12px; flex-shrink: 0; }
            #edit_copyLinkBtn { width: 34px; min-width: 34px; height: 34px; padding: 0 !important; gap: 0 !important; font-size: 0 !important; }
            .switch { width: 56px; height: 32px; }
            .slider:before { height: 26px; width: 26px; left: 3px; bottom: 3px; }
            input:checked + .slider:before { transform: translateX(24px); }
            .setting-card { padding: 16px; }
            
            .table-wrapper { background: transparent; border: none; }
            table, thead, tbody, th, td, tr { display: block; width: 100%; }
            thead { display: none; }
            tbody { display: flex; flex-direction: column; gap: 12px; }
            
            tr {
                background: var(--surface);
                border: 1px solid var(--border);
                border-radius: 16px;
                padding: 16px;
                margin-bottom: 0;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
                display: flex;
                flex-direction: column;
                gap: 10px;
            }
            tr:hover td { background: transparent; }
            
            td {
                border: none;
                padding: 0;
                min-height: auto;
                display: flex;
                justify-content: space-between;
                align-items: center;
                text-align: left;
                width: 100%;
            }
            
            td::before {
                content: attr(data-label) ":";
                font-size: 11px;
                font-weight: 600;
                color: var(--text-muted);
                text-transform: uppercase;
                letter-spacing: 0.05em;
                display: inline-block;
            }
            
            td[data-label="Пользователь"] {
                flex-direction: column;
                align-items: flex-start;
                gap: 4px;
                border-bottom: 1px solid var(--border);
                padding-bottom: 8px;
                margin-bottom: 2px;
            }
            td[data-label="Пользователь"]::before {
                display: none;
            }
            td[data-label="Пользователь"] .client-name {
                font-size: 15px;
                font-weight: 700;
                width: 100%;
                justify-content: space-between;
            }
            td[data-label="Пользователь"] .client-hash {
                font-size: 11px;
                width: 100%;
                margin-top: 2px;
            }
            
            td[data-label="Действия"] {
                border-top: 1px solid var(--border);
                padding-top: 8px;
                margin-top: 2px;
                justify-content: flex-end;
            }
            td[data-label="Действия"]::before {
                display: none;
            }
            .actions {
                width: 100%;
                justify-content: flex-end;
                gap: 6px;
                margin-top: 0;
            }
        }
        @media(max-width: 480px) {
            dialog { padding: 20px 12px !important; width: calc(100% - 16px) !important; }
        }
        .log-line { margin-bottom: 4px; padding: 2px 4px; border-radius: 4px; color: #e2e8f0; }
        .log-line:hover { background: rgba(255, 255, 255, 0.05); }
        #logConsole ::selection { background: rgba(0, 119, 255, 0.3); color: #ffffff; }
        .log-time { color: var(--text-muted); margin-right: 8px; }
        .log-lvl { font-weight: 700; margin-right: 8px; padding: 1px 6px; border-radius: 4px; font-size: 11px; }
        .log-lvl.log-info { color: #38bdf8; background: rgba(56, 189, 248, 0.1); }
        .log-lvl.log-err { color: #f87171; background: rgba(248, 113, 113, 0.1); }
        .log-mod { color: #34d399; background: rgba(52, 211, 153, 0.1); padding: 1px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-right: 8px; }

        #logConsole::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        #logConsole::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.03);
            border-radius: 10px;
        }
        #logConsole::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.12);
            border-radius: 10px;
        }
        #logConsole::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.22);
        }

        select {
            background: var(--surface);
            color: var(--text-main);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 6px 12px;
            font-size: 13px;
            font-weight: 500;
            outline: none;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        select:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(0, 119, 255, 0.15);
        }

        input[type=number]::-webkit-outer-spin-button,
        input[type=number]::-webkit-inner-spin-button {
            -webkit-appearance: none;
            margin: 0;
        }
        input[type=number] {
            -moz-appearance: textfield;
        }

        .dlg-row {
            display: flex;
            gap: 8px !important;
            width: 100%;
        }
        .dlg-row .input-group {
            flex: 1 1 0% !important;
            min-width: 0;
            margin-bottom: 0;
        }
        .dlg-row input {
            text-align: center;
            font-size: 13px !important;
            padding: 0 4px !important;
            font-family: ui-monospace, SFMono-Regular, 'Cascadia Code', Consolas, monospace;
        }
        .night-switch {
            position: relative;
            display: inline-flex;
            align-items: center;
            background: var(--surface-hover);
            border: 1px solid var(--border);
            border-radius: 8px;
            cursor: pointer;
            user-select: none;
            font-size: 13px;
            font-weight: 500;
            height: 32px;
            padding: 2px;
            z-index: 1;
            box-sizing: border-box;
            width: 110px;
        }
        .night-switch::before {
            content: "";
            position: absolute;
            top: 2px;
            bottom: 2px;
            left: 2px;
            width: calc(50% - 2px);
            border-radius: 6px;
            transition: all 0.3s cubic-bezier(0.4, 0.0, 0.2, 1);
            z-index: -1;
        }
        .night-switch.is-on::before {
            transform: translateX(100%);
            background: #0077ff;
        }
        .night-switch.is-off::before {
            transform: translateX(0);
            background: #0077ff;
        }
        .night-switch .ns-side {
            flex: 1;
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-muted);
            transition: color 0.3s;
        }
        .night-switch.is-on .ns-on { color: #ffffff; }
        .night-switch.is-off .ns-off { color: #ffffff; }
        .stream-stats-dialog {
            width: min(1240px, calc(100% - 32px));
            max-height: calc(100vh - 40px);
            padding: 24px;
            overflow: hidden;
        }
        .stream-stats-summary {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 12px;
        }
        .stream-summary-chip {
            padding: 7px 10px;
            border-radius: 9px;
            background: var(--surface-hover);
            border: 1px solid var(--border);
            color: var(--text-main);
            font-size: 12px;
            font-family: ui-monospace, SFMono-Regular, 'Cascadia Code', Consolas, monospace;
        }
        .stream-stats-note {
            color: var(--text-muted);
            font-size: 12px;
            line-height: 1.45;
            margin-bottom: 12px;
        }
        .stream-stats-table-wrap {
            max-height: calc(100vh - 245px);
            overflow: auto;
            border: 1px solid var(--border);
            border-radius: 12px;
        }
        .stream-stats-table {
            display: table;
            min-width: 1160px;
            font-size: 12px;
        }
        .stream-stats-table thead {
            display: table-header-group;
        }
        .stream-stats-table tbody {
            display: table-row-group;
        }
        .stream-stats-table tr {
            display: table-row;
        }
        .stream-stats-table th,
        .stream-stats-table td {
            display: table-cell;
            width: auto;
            padding: 9px 10px;
            white-space: nowrap;
        }
        .stream-stats-table th {
            position: sticky;
            top: 0;
            z-index: 1;
        }
        .stream-state {
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .stream-state-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: #10b981;
        }
        .stream-state-dot.waiting {
            background: #f59e0b;
        }
        @media(max-width: 768px) {
            .clients-toolbar {
                align-items: stretch;
                flex-direction: column;
                gap: 10px;
            }
            .stream-debug-control {
                justify-content: space-between;
            }
            .stream-stats-dialog {
                width: calc(100% - 16px) !important;
                padding: 16px 12px !important;
            }
            .stream-stats-table-wrap {
                max-height: calc(100vh - 260px);
                max-height: calc(100dvh - 260px);
                overflow-x: hidden;
                padding: 8px;
                background: var(--bg-color);
            }
            .stream-stats-table {
                display: block;
                width: 100%;
                min-width: 0;
                font-size: 12px;
            }
            .stream-stats-table thead {
                display: none;
            }
            .stream-stats-table tbody {
                display: grid;
                gap: 8px;
            }
            .stream-stats-table tr {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 0;
                padding: 6px;
                background: var(--surface);
                border: 1px solid var(--border);
                border-radius: 10px;
            }
            .stream-stats-table td {
                display: flex;
                width: auto;
                min-width: 0;
                flex-direction: column;
                gap: 3px;
                padding: 6px 7px;
                white-space: normal;
                overflow-wrap: anywhere;
                border: 0;
            }
            .stream-stats-table td::before {
                content: attr(data-label);
                color: var(--text-muted);
                font-size: 9px;
                font-weight: 700;
                line-height: 1.2;
                text-transform: uppercase;
                letter-spacing: 0.04em;
            }
            .stream-stats-table .stream-cell-source,
            .stream-stats-table .stream-cell-packets,
            .stream-stats-table .stream-cell-total,
            .stream-stats-table .stream-cell-state,
            .stream-stats-table .stream-stats-empty {
                grid-column: 1 / -1;
            }
            .stream-stats-table .stream-stats-empty {
                display: block;
                padding: 12px;
                text-align: center;
            }
            .stream-stats-table .stream-stats-empty::before {
                content: none;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="header-container">
            <div class="brand" aria-label="CSQTT">
                <svg class="brand-logo" viewBox="0 0 760 184" role="img" aria-label="CSQTT">
                    <defs>
                        <linearGradient id="csqttLogoGradient" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="68" y2="340">
                            <stop offset="0" stop-color="#3DBFFD"></stop><stop offset="0.32" stop-color="#299BFD"></stop><stop offset="0.66" stop-color="#1475FD"></stop><stop offset="1" stop-color="#0450FC"></stop>
                        </linearGradient>
                    </defs>
                    <path fill="url(#csqttLogoGradient)" fill-rule="evenodd" d="M79,11 L66,15 L48,25 L40,32 L27,49 L21,62 L17,78 L17,98 L19,108 L22,117 L33,136 L40,144 L56,156 L66,161 L84,166 L108,166 L118,164 L127,161 L143,152 L157,139 L160,135 L160,133 L137,116 L135,116 L123,128 L113,133 L106,135 L100,135 L99,136 L87,135 L73,130 L67,126 L57,116 L51,105 L48,93 L48,83 L51,71 L58,59 L67,50 L83,42 L105,41 L115,44 L129,53 L136,61 L160,44 L160,42 L155,35 L144,25 L135,19 L124,14 L108,10 Z M219,13 L208,18 L201,23 L191,35 L186,49 L186,66 L188,73 L193,82 L200,89 L208,94 L219,98 L248,103 L264,108 L270,113 L272,117 L272,125 L267,132 L260,136 L255,137 L234,137 L220,133 L212,129 L199,119 L181,141 L199,155 L212,161 L222,164 L232,165 L233,166 L257,166 L276,161 L285,156 L292,150 L298,142 L302,132 L303,112 L297,97 L287,87 L276,81 L258,76 L234,72 L224,68 L218,63 L216,58 L217,50 L222,44 L228,41 L237,39 L248,39 L258,41 L268,45 L279,53 L281,53 L299,32 L285,21 L270,14 L259,11 L233,10 Z M354,25 L344,34 L333,49 L328,60 L324,74 L324,79 L323,80 L324,103 L329,119 L336,132 L349,147 L360,155 L372,161 L391,166 L414,166 L430,162 L442,156 L460,174 L478,156 L462,140 L469,131 L474,122 L479,109 L481,99 L481,77 L479,68 L474,54 L466,41 L453,27 L441,19 L430,14 L414,10 L385,11 L372,15 Z M389,42 L411,41 L427,47 L442,61 L449,76 L450,96 L447,106 L444,112 L439,118 L421,100 L404,116 L405,119 L418,132 L416,134 L399,136 L385,133 L377,129 L363,116 L355,99 L354,83 L357,71 L361,63 L373,50 L379,46 Z M496,13 L496,44 L536,44 L537,45 L537,163 L568,163 L568,45 L569,44 L609,44 L610,43 L610,13 Z M628,13 L627,14 L627,37 L628,38 L627,43 L628,44 L666,44 L667,45 L667,163 L698,163 L699,162 L699,45 L700,44 L738,44 L738,13 Z"></path>
                </svg>
            </div>
            <div class="header-actions">
                <button class="btn btn-ghost btn-icon" onclick="toggleTheme()" title="Сменить тему">
                    <svg id="themeIcon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
                </button>
                <svg class="version-logo" viewBox="0 0 504 64" role="img" aria-label="v2.0.0 by amurcanov" fill="none" stroke="url(#versionLogoGradient)" stroke-width="6" stroke-linecap="round" stroke-linejoin="round">
                    <defs><linearGradient id="versionLogoGradient" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="504" y2="64"><stop offset="0" stop-color="#45B7FF"></stop><stop offset="0.45" stop-color="#2087FF"></stop><stop offset="1" stop-color="#075BFF"></stop></linearGradient></defs>
                    <path d="M8,24 L18,48 L28,24 M34,20 Q38,14 46,14 H50 Q58,14 58,22 Q58,28 52,33 L36,48 H58 M67,47 L67.8,47 M86,14 C78,14 74,20 74,31 C74,42 78,48 86,48 C94,48 98,42 98,31 C98,20 94,14 86,14 Z M107,47 L107.8,47 M126,14 C118,14 114,20 114,31 C114,42 118,48 126,48 C134,48 138,42 138,31 C138,20 134,14 126,14 Z M150,12 V48 M150,31 Q155,24 162,24 Q172,24 172,36 Q172,48 162,48 Q155,48 150,41 M182,24 L192,47 M202,24 L192,47 L188,57 Q186,60 181,58 M238,30 Q234,24 227,24 Q216,24 216,36 Q216,48 227,48 Q234,48 238,42 M238,24 V48 M248,48 V24 M248,31 Q252,24 258,24 Q265,24 265,32 V48 M265,31 Q269,24 275,24 Q282,24 282,32 V48 M292,24 V39 Q292,48 302,48 Q312,48 312,39 V24 M322,48 V24 M322,32 Q326,24 336,24 M370,29 Q366,24 358,24 Q348,24 348,36 Q348,48 358,48 Q366,48 370,43 M402,30 Q398,24 391,24 Q380,24 380,36 Q380,48 391,48 Q398,48 402,42 M402,24 V48 M412,48 V24 M412,32 Q417,24 424,24 Q434,24 434,35 V48 M455,24 Q444,24 444,36 Q444,48 455,48 Q466,48 466,36 Q466,24 455,24 Z M476,24 L486,48 L496,24"></path>
                </svg>
            </div>
        </div>
    </header>
    <div id="restartRequiredBanner" class="restart-required-banner">Для применения изменений необходимо перезагрузить CSQTT на сервере (перейдите в настройки)</div>

    <main>
        <div class="tabs-container">
            <div class="tabs">
                <button class="tab-btn active" data-tab="monitoring" onclick="switchTab('monitoring')">Мониторинг</button>
                <button class="tab-btn" data-tab="clients" onclick="switchTab('clients')">Клиенты</button>
                <button class="tab-btn" data-tab="logs" onclick="switchTab('logs')">Логи</button>
                <button class="tab-btn" data-tab="settings" onclick="switchTab('settings')">Настройки</button>
            </div>
        </div>

        <div id="monitoring-section" style="display: none;">
            <div class="section-header" style="justify-content: flex-end; margin-bottom: 15px; display: flex; align-items: center; gap: 10px; flex-direction: row !important;">
                <label for="updateIntervalSelect" style="color: var(--text-secondary); font-size: 14px;" title="С какой периодичностью панель будет обновлять данные мониторинга, потоков и трафика">Обновление:</label>
                <select id="updateIntervalSelect" class="input" style="width: auto; padding: 4px 10px; min-height: 32px;" onchange="changeUpdateInterval()">
                    <option value="1000">1 сек</option>
                    <option value="3000" selected>3 сек</option>
                    <option value="5000">5 сек</option>
                    <option value="10000">10 сек</option>
                    <option value="15000">15 сек</option>
                    <option value="30000">30 сек</option>
                    <option value="60000">60 сек</option>
                    <option value="90000">90 сек</option>
                    <option value="120000">120 сек</option>
                </select>
            </div>
            <section class="dashboard">
                <div class="glass-panel stat-card">
                    <div class="stat-header">
                        <div class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg></div>
                        <div class="stat-label">Сервер</div>
                    </div>
                    <div>
                        <div class="stat-value" id="status_val">...</div>
                        <div class="stat-sub" id="status_uptime">Загрузка...</div>
                    </div>
                </div>

                <div class="glass-panel stat-card">
                    <div class="stat-header">
                        <div class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg></div>
                        <div class="stat-label">Сессии</div>
                    </div>
                    <div>
                        <div class="stat-value" id="active_val">0</div>
                        <div class="stat-sub">Активные сессии</div>
                    </div>
                </div>

                <div class="glass-panel stat-card cpu-card">
                    <div class="stat-header">
                        <div class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg></div>
                        <div class="stat-label">CPU</div>
                    </div>
                    <div>
                        <div class="stat-value" id="cpu_val">0% / 100%</div>
                        <div class="progress-bar"><div class="progress-fill" id="cpu_bar" style="width: 0%"></div></div>
                    </div>
                </div>

                <div class="glass-panel stat-card memory-card">
                    <div class="stat-header">
                        <div class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 9h20v6H2z"></path><path d="M5 15v2M8 15v2M11 15v2M14 15v2M17 15v2M20 15v2"></path><rect x="4" y="10" width="3" height="4" rx="0.5"></rect><rect x="9" y="10" width="3" height="4" rx="0.5"></rect><rect x="14" y="10" width="3" height="4" rx="0.5"></rect><rect x="19" y="10" width="3" height="4" rx="0.5"></rect></svg></div>
                        <div class="stat-label">ОЗУ</div>
                    </div>
                    <div>
                        <div class="stat-value" id="ram_val">0 MB</div>
                        <div class="stat-sub" id="ram_detail">Использование памяти</div>
                    </div>
                </div>

                <div class="glass-panel stat-card traffic-card">
                    <div class="stat-header">
                        <div class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="20" x2="12" y2="10"></line><line x1="18" y1="20" x2="18" y2="4"></line><line x1="6" y1="20" x2="6" y2="16"></line></svg></div>
                        <div class="stat-label">Трафик</div>
                    </div>
                    <div style="display: flex; flex-direction: column; gap: 4px;">
                        <div class="stat-value" style="font-size: 20px; color: var(--primary);" id="traffic_up">↑ 0 B</div>
                        <div class="stat-value" style="font-size: 20px; color: var(--primary);" id="traffic_down">↓ 0 B</div>
                    </div>
                </div>
            </section>
        </div>

        <div id="clients-section" style="display: none;">
            <section>
                <div class="section-header" style="justify-content: flex-end;">
                    <div class="clients-toolbar">
                        <div class="stream-debug-control">
                            <span>Расширенная отладка потоков</span>
                            <label class="switch">
                                <input type="checkbox" id="streamDebugToggle" onchange="toggleStreamDebug()">
                                <span class="slider"></span>
                            </label>
                        </div>
                        <button class="btn btn-primary" onclick="openNewClientDlg()">Создать доступ</button>
                    </div>
                </div>
                <div id="clientsCards" class="client-cards-grid"></div>
            </section>
        </div>

        <div id="logs-section" style="display: none;">
            <section style="display: flex; flex-direction: column; gap: 16px;">
                <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: nowrap; width: 100%;">
                    <div style="display: flex; align-items: center; gap: 8px; flex: 1; min-width: 0; overflow: hidden;">
                        <span style="font-size: 12px; color: var(--text-muted); font-family: ui-monospace, SFMono-Regular, 'Cascadia Code', Consolas, monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-shrink: 1; min-width: 0;" id="logFilePath" title="Путь: /etc/csqtt/csqtt.log">Путь: /etc/csqtt/csqtt.log</span>
                        <a class="btn btn-primary" id="downloadLogBtn" href="/api/logs/download" style="padding: 4px 10px; font-size: 11px; text-decoration: none; border-radius: 8px; height: 28px; min-height: auto; display: inline-flex; align-items: center; flex-shrink: 0; white-space: nowrap;" download>Скачать</a>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px; user-select: none; white-space: nowrap; flex-shrink: 0;">
                        <label for="loggingActiveToggle" style="font-size: 13px; font-weight: 600; color: var(--text-muted);">Логирование</label>
                        <label class="switch">
                            <input type="checkbox" id="loggingActiveToggle" onchange="toggleLoggingActive()">
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <div class="glass-panel" style="padding: 16px; background: #0a0b0d; border: 1px solid var(--border); border-radius: 16px; position: relative; width: 100%;">
                    <button onclick="clearLogs()" title="Очистить логи" style="position: absolute; top: 12px; right: 12px; background: #1c1215; border: 1px solid rgba(239, 68, 68, 0.25); color: #ef4444; width: 32px; height: 32px; border-radius: 8px; display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.2s; outline: none; z-index: 10;" onmouseover="this.style.background='#2a1519';this.style.borderColor='rgba(239,68,68,0.4)'" onmouseout="this.style.background='#1c1215';this.style.borderColor='rgba(239,68,68,0.25)'">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                    </button>
                    <div id="logConsole" style="height: 450px; overflow-y: auto; font-family: ui-monospace, SFMono-Regular, 'Cascadia Code', Consolas, monospace; font-size: 12px; line-height: 1.6; color: #e2e8f0; white-space: pre-wrap; word-break: break-all; scroll-behavior: smooth; padding-right: 32px;"></div>
                </div>
            </section>
        </div>

        <div id="settings-section" style="display: none;">
            <section>
                <div class="settings-actions-grid">
                    <button class="settings-action-btn reboot" onclick="document.getElementById('rebootDlg').showModal()">Перезагрузить</button>
                    <button class="settings-action-btn danger" onclick="logout()">Выйти</button>
                </div>
                <div class="settings-grid">
                    <div class="glass-panel setting-card">
                        <div class="input-group"><label for="mainpass">Главный пароль</label><input id="mainpass"></div>
                        <button id="saveMainPasswordBtn" class="btn btn-primary" style="width: 100%; margin-top: 8px;" onclick="saveMainPassword()" disabled>Сохранить главный пароль</button>
                    </div>
                    <div class="glass-panel setting-card" style="display: flex; flex-direction: column; justify-content: space-between;">
                        <div style="display: flex; gap: 12px; margin-top: 4px;">
                            <div class="input-group" style="flex: 1; margin-bottom: 0;"><label for="dns_primary">Основной DNS</label><input id="dns_primary" placeholder="1.1.1.1"></div>
                            <div class="input-group" style="flex: 1; margin-bottom: 0;"><label for="dns_secondary">Резервный DNS</label><input id="dns_secondary" placeholder="1.0.0.1"></div>
                        </div>
                        <button id="saveDnsBtn" class="btn btn-primary" style="width: 100%; margin-top: 22px;" onclick="saveDnsSettings()" disabled>Сохранить DNS</button>
                    </div>
                </div>
            </section>

            <section style="margin-top: 20px;">
                <div class="glass-panel routing-panel local-proxy-panel" style="padding: 24px;">
                    <div class="routing-header" style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 18px; gap: 12px;">
                        <div style="display: flex; align-items: center; gap: 8px; min-width: 0;">
                            <h3 style="margin: 0; font-size: 16px; font-weight: 600; white-space: nowrap;">
                                <span class="hide-mobile">Локальный прокси SOCKS5 UDP</span><span class="show-mobile">SOCKS5 UDP</span>
                            </h3>
                            <button class="proxy-info-btn" type="button" aria-label="Что такое локальный SOCKS5 UDP" title="Что такое локальный SOCKS5 UDP" onclick="document.getElementById('localProxyInfoDlg').showModal()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path><line x1="12" y1="17" x2="12.01" y2="17"></line></svg></button>
                        </div>
                        <button class="proxy-add-btn" type="button" aria-label="Добавить профиль" title="Добавить профиль" onclick="openProfileDlg()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" aria-hidden="true"><path d="M12 5v14M5 12h14"></path></svg></button>
                    </div>
                    <div id="proxyProfilesList" class="proxy-profiles"></div>
                </div>
            </section>

            <section style="margin-top: 20px;">
                <div class="glass-panel support-card">
                    <h3 class="support-card-title">Поддержать разработчика Amucanov</h3>
                    <a class="yoomoney-button" href="https://yoomoney.ru/to/4100119505530465/100" target="_blank" rel="noopener noreferrer" aria-label="Перейти в ЮMoney" title="ЮMoney">
                        <svg class="yoomoney-logo" viewBox="0 0 92 20" aria-hidden="true" fill="#ffffff">
                            <path d="M33.9287 15.222H36.2782V9.5425C36.2782 8.34 37.1107 7.9145 37.9247 7.9145C38.8127 7.9145 39.4047 8.4695 39.4047 9.5425V15.222H41.7542V9.5425C41.7542 8.3215 42.5867 7.9145 43.4007 7.9145C44.2887 7.9145 44.8807 8.4695 44.8807 9.5425V15.222H47.2302V9.3575C47.2302 6.9895 45.7502 5.75 43.9187 5.75C42.6977 5.75 41.8282 6.305 41.1622 7.119C40.5702 6.2125 39.6082 5.75 38.5167 5.75C37.5177 5.75 36.7592 6.194 36.1672 6.86L36.0377 5.9535H33.9287V15.222Z"></path>
                            <path d="M53.9553 5.75C51.1063 5.75 49.0157 7.8035 49.0157 10.5785C49.0157 13.372 51.1063 15.407 53.9553 15.407C56.8043 15.407 58.8948 13.372 58.8948 10.5785C58.8948 7.8035 56.8043 5.75 53.9553 5.75ZM53.9553 7.9145C55.4538 7.9145 56.4342 8.9875 56.4342 10.5785C56.4342 12.188 55.4538 13.261 53.9553 13.261C52.4568 13.261 51.4577 12.188 51.4577 10.5785C51.4577 8.9875 52.4568 7.9145 53.9553 7.9145Z"></path>
                            <path d="M60.8838 15.222H63.2333V10.005C63.2333 8.451 64.3063 7.933 65.2868 7.933C66.3783 7.933 67.1553 8.636 67.1553 10.005V15.222H69.5048V9.635C69.5048 7.082 67.8398 5.75 65.8603 5.75C64.8243 5.75 63.8808 6.1385 63.1408 6.8785L63.0113 5.9535H60.8838V15.222Z"></path>
                            <path d="M76.1941 15.407C78.4326 15.407 80.0421 14.3525 80.5971 12.5025L78.4141 12.0585C78.1181 12.8355 77.4151 13.372 76.1941 13.372C74.8621 13.372 73.9186 12.743 73.6966 11.3H80.5786C80.6526 10.9485 80.6896 10.5785 80.6896 10.2455C80.6896 7.563 78.8026 5.75 76.0831 5.75C73.2711 5.75 71.2916 7.822 71.2916 10.634C71.2916 13.3905 73.1231 15.407 76.1941 15.407ZM76.0831 7.6925C77.2671 7.6925 78.0256 8.34 78.2291 9.5055H73.7706C74.1036 8.2845 75.0101 7.6925 76.0831 7.6925Z"></path>
                            <path d="M81.2328 5.9535L85.2103 15.1665L83.6193 19.292H86.0428L91.1673 5.9535H88.6698L86.4313 12.2065L83.8413 5.9535H81.2328Z"></path>
                            <path d="M8.23663 9.97273C8.25147 4.47884 12.7503 0 18.4037 0C24.002 0 28.6351 4.49367 28.5708 10C28.5708 15.5063 24.002 20 18.4037 20C12.8145 20 8.25158 15.5841 8.23663 10.0274V17.4683H4.6331L0 2.91138H8.23663V9.97273ZM14.6071 10C14.6071 12.0253 16.3445 13.7342 18.4037 13.7342C20.5272 13.7342 22.2002 12.0253 22.2002 10C22.2002 7.97469 20.4628 6.26582 18.4037 6.26582C16.3445 6.26582 14.6071 7.97469 14.6071 10Z"></path>
                        </svg>
                    </a>
                    <button class="crypto-button" type="button" onclick="openCryptoDonateDlg()" aria-label="Поддержать криптовалютой" title="CRYPTO">
                        <svg class="crypto-logo" viewBox="0 0 320 60" aria-hidden="true">
                            <g transform="translate(160, 30) scale(0.9) translate(-160, -30)">
                                <path fill="#FFFFFF" d="M35,30 C35,17 45,8 60,8 C70,8 78,13 82,21 L70,28 C68,23 64,20 60,20 C52,20 47,24 47,30 C47,36 52,40 60,40 C64,40 68,37 70,32 L82,39 C78,47 70,52 60,52 C45,52 35,43 35,30 Z M92,10 L115,10 C126,10 133,16 133,24 C133,30 129,35 122,37 L135,50 L120,50 L109,38 L104,38 L104,50 L92,50 L92,10 Z M104,20 L104,29 L114,29 C118,29 121,27 121,24 C121,21 118,20 114,20 L104,20 Z M148,10 L160,29 L172,10 L186,10 L167,36 L167,50 L153,50 L153,36 L134,10 L148,10 Z M196,10 L219,10 C231,10 238,17 238,26 C238,35 231,42 219,42 L208,42 L208,50 L196,50 L196,10 Z M208,20 L208,32 L218,32 C223,32 226,30 226,26 C226,22 223,20 218,20 L208,20 Z M243,10 L279,10 L279,21 L267,21 L267,50 L255,50 L255,21 L243,21 L243,10 Z M285,30 C285,17 296,8 310,8 C324,8 335,17 335,30 C335,43 324,52 310,52 C296,52 285,43 285,30 Z M297,30 C297,37 302,41 310,41 C318,41 323,37 323,30 C323,23 318,19 310,19 C302,19 297,23 297,30 Z"></path>
                            </g>
                        </svg>
                    </button>
                </div>
            </section>
        </div>
    </main>

    <dialog id="confirmDlg">
        <h2 id="confirmTitle" style="font-size: 18px; margin-bottom: 12px;">Подтверждение</h2>
        <p id="confirmMessage" style="font-size: 14px; color: var(--text-muted); margin-bottom: 24px; line-height: 1.5;"></p>
        <div class="dlg-actions" style="margin-top: 0;">
            <button class="btn btn-ghost" onclick="document.getElementById('confirmDlg').close()">Отмена</button>
            <button class="btn btn-primary" id="confirmActionBtn">Подтвердить</button>
        </div>
    </dialog>

    <dialog id="cryptoDonateDlg">
        <h2 style="font-size: 20px; margin-bottom: 8px;">Поддержать криптовалютой</h2>
        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 20px; line-height: 1.5;">Переведите криптовалюту на один из указанных адресов кошельков.</p>
        
        <div style="background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 14px; margin-bottom: 14px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <span style="font-size: 13px; font-weight: 700; color: #31A1F5;">GRAM (Сеть TON)</span>
            </div>
            <div style="font-family: monospace; font-size: 13px; word-break: break-all; color: var(--text-main); line-height: 1.4; user-select: all;" id="gramWalletAddr">UQCsHSj_Bev5AG3vCz-84TQC7BSWjNdNdOjP9M2gWUEmbyD7</div>
            <div style="margin-top: 8px; text-align: right;">
                <button class="btn btn-ghost" style="padding: 4px 10px; font-size: 12px;" onclick="copyText('UQCsHSj_Bev5AG3vCz-84TQC7BSWjNdNdOjP9M2gWUEmbyD7', this)">Скопировать</button>
            </div>
        </div>

        <div style="background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 14px; margin-bottom: 14px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <span style="font-size: 13px; font-weight: 700; color: #50AF95;">USDT (Сеть TON)</span>
            </div>
            <div style="font-family: monospace; font-size: 13px; word-break: break-all; color: var(--text-main); line-height: 1.4; user-select: all;" id="usdtTonWalletAddr">UQCsHSj_Bev5AG3vCz-84TQC7BSWjNdNdOjP9M2gWUEmbyD7</div>
            <div style="margin-top: 8px; text-align: right;">
                <button class="btn btn-ghost" style="padding: 4px 10px; font-size: 12px;" onclick="copyText('UQCsHSj_Bev5AG3vCz-84TQC7BSWjNdNdOjP9M2gWUEmbyD7', this)">Скопировать</button>
            </div>
        </div>

        <div style="background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 14px; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <span style="font-size: 13px; font-weight: 700; color: #50AF95;">USDT (Сеть TRC20)</span>
            </div>
            <div style="font-family: monospace; font-size: 13px; word-break: break-all; color: var(--text-main); line-height: 1.4; user-select: all;" id="usdtTrcWalletAddr">TD1oiQiHmjqsRDPxfUjUbSWxEmcr4k7Lob</div>
            <div style="margin-top: 8px; text-align: right;">
                <button class="btn btn-ghost" style="padding: 4px 10px; font-size: 12px;" onclick="copyText('TD1oiQiHmjqsRDPxfUjUbSWxEmcr4k7Lob', this)">Скопировать</button>
            </div>
        </div>

        <div class="dlg-actions" style="margin-top: 0;">
            <button class="btn btn-primary" onclick="document.getElementById('cryptoDonateDlg').close()">Хорошо</button>
        </div>
    </dialog>

    <dialog id="localProxyInfoDlg">
        <h2 style="font-size: 20px; margin-bottom: 20px;">SOCKS5 UDP</h2>
        <ul class="proxy-info-list">
            <li><strong>Зачем нужно?</strong> Маршрутизировать трафик из CSQTT в Xray, 3x-ui и другие панели. Это нужно, чтобы маршрутизировать трафик через geoip/geodat и работать с любыми возможностями ваших панелей.</li>
            <li><strong>Как работает?</strong> CSQTT передаёт TCP и UDP в локальный SOCKS5. Если прокси недоступен, используется прямой выход через основной VPS.</li>
            <li><strong>Как настроить?</strong> В соответствующем ядре или веб-панели заранее создайте инбаунд SOCKS5-прокси (в некоторых панелях он может называться mixed) с предпочитаемым портом и включите UDP в настройках прокси. Затем укажите в панели CSQTT тот же самый порт.</li>
        </ul>
        <div class="dlg-actions" style="margin-top: 24px;">
            <button class="btn btn-primary" onclick="document.getElementById('localProxyInfoDlg').close()">Понятно</button>
        </div>
    </dialog>

    <dialog id="vkHashesInfoDlg">
        <h2 style="font-size: 20px; margin-bottom: 16px;">VK хеши в ссылке</h2>
        <p style="color: var(--text-muted); font-size: 14px; line-height: 1.6; margin: 0;">Укажите от 1 до 6 VK-хешей через запятую без пробелов. Вставляйте только сами значения хешей. Они будут добавлены в ссылку CSQTT v2, и пользователю не придётся вводить их вручную.</p>
        <div class="dlg-actions" style="margin-top: 24px;">
            <button class="btn btn-primary" onclick="document.getElementById('vkHashesInfoDlg').close()">Понятно</button>
        </div>
    </dialog>

    <dialog id="profileDlg">
        <h2 id="profileDlgTitle" style="font-size: 18px; margin-bottom: 18px;">Новый профиль</h2>
        <div class="input-group"><label for="profileDlgName">Имя</label><input id="profileDlgName" maxlength="64" placeholder="3x-ui VLESS"></div>
        <div class="input-group"><label for="profileDlgPort">Порт SOCKS5</label><input type="number" id="profileDlgPort" min="1" max="65535" value="45000" inputmode="numeric"></div>
        <div class="input-group"><label for="profileDlgUser">Логин (необязательно)</label><input id="profileDlgUser" maxlength="255" autocomplete="off"></div>
        <div class="input-group" style="margin-bottom: 0;"><label for="profileDlgPass">Пароль (необязательно)</label><input type="password" id="profileDlgPass" maxlength="255" autocomplete="new-password"></div>
        <div class="dlg-actions" style="margin-top: 20px;">
            <button class="btn btn-ghost" onclick="document.getElementById('profileDlg').close()">Отмена</button>
            <button class="btn btn-primary" id="profileDlgSave" onclick="saveProfileDlg()">Создать</button>
        </div>
    </dialog>

    <dialog id="newDlg">
        <h2>Создание доступа</h2>
        <div class="input-group">
            <label for="cname">Имя клиента</label>
            <input id="cname">
        </div>
        <div class="input-group">
            <label for="days">Срок действия (дней)</label>
            <input type="number" id="days" value="30" min="0" max="3650">
        </div>
        
        <div class="toggle-row">
            <label for="csqttToggle">Создать ссылку csqtt://</label>
            <label class="switch">
                <input type="checkbox" id="csqttToggle" onchange="toggleWdttFields()">
                <span class="slider"></span>
            </label>
        </div>

        <div id="csqttFields" style="display: none; margin-top: 16px;">
            <div class="dlg-row">
                <div class="input-group" style="flex: 1;"><label for="peer_port">PEER Port</label><input type="number" id="peer_port" value="46000"></div>
                <input type="hidden" id="wg_port" value="46001">
                <input type="hidden" id="local_port" value="0">
            </div>
            <div class="toggle-row vk-hashes-toggle">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <label for="vkHashesToggle">Добавить VK хеши</label>
                    <button class="proxy-info-btn" type="button" aria-label="Как добавить VK хеши" title="Как добавить VK хеши" onclick="document.getElementById('vkHashesInfoDlg').showModal()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path><line x1="12" y1="17" x2="12.01" y2="17"></line></svg></button>
                </div>
                <label class="switch">
                    <input type="checkbox" id="vkHashesToggle" onchange="toggleVkHashFields()">
                    <span class="slider"></span>
                </label>
            </div>
            <div id="vkHashesFields" style="display: none;">
                <div class="input-group" style="margin-bottom: 0;">
                    <label for="vk_hashes">VK Хеши</label>
                    <input id="vk_hashes" maxlength="1024" autocomplete="off" placeholder="hash1,hash2,...,hash6" oninput="this.classList.remove('is-invalid')">
                </div>
            </div>
        </div>

        <div class="dlg-actions">
            <button class="btn btn-ghost" onclick="document.getElementById('newDlg').close()">Отмена</button>
            <button class="btn btn-primary" onclick="createClient()" id="createBtn">Создать</button>
        </div>
    </dialog>

    <dialog id="editDlg">
        <div class="dlg-header">
            <h2>Управление доступом</h2>
            <button class="close-btn" onclick="document.getElementById('editDlg').close()">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
            </button>
        </div>
        
        <div class="input-group">
            <label for="edit_name">Имя клиента</label>
            <input id="edit_name">
        </div>
        
        <div class="input-group">
            <label for="edit_pass">Пароль (ключ)</label>
            <div style="display: flex; gap: 8px;">
                <input id="edit_pass" readonly style="background: var(--surface-hover); color: var(--text-muted); cursor: not-allowed; flex: 1; font-family: ui-monospace, SFMono-Regular, 'Cascadia Code', Consolas, monospace;">
                <button class="btn btn-ghost" onclick="copyPasswordText()" style="padding: 0 16px; display: flex; align-items: center; gap: 6px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>Копировать</button>
            </div>
        </div>

        <div class="input-group">
            <label for="edit_days">Срок действия (дней оставшихся)</label>
            <input type="number" id="edit_days" min="0" max="3650">
        </div>
        
        <div class="toggle-row">
            <label for="edit_csqttToggle">Использовать csqtt://</label>
            <div style="display: flex; align-items: center; gap: 12px;">
                <button class="btn btn-ghost" id="edit_copyLinkBtn" onclick="executeCopyLink()" style="padding: 0 16px; display: flex; align-items: center; gap: 6px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>Ссылка</button>
                <label class="switch">
                    <input type="checkbox" id="edit_csqttToggle" onchange="toggleEditWdttFields()">
                    <span class="slider"></span>
                </label>
            </div>
        </div>

        <div id="edit_csqttFields" style="display: none; margin-top: 16px;">
            <div class="dlg-row">
                <div class="input-group" style="flex: 1;"><label for="edit_peer_port">PEER Port</label><input type="number" id="edit_peer_port"></div>
                <input type="hidden" id="edit_wg_port" value="46001">
                <input type="hidden" id="edit_local_port" value="0">
            </div>
            <div class="toggle-row vk-hashes-toggle">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <label for="edit_vkHashesToggle">Добавить VK хеши</label>
                    <button class="proxy-info-btn" type="button" aria-label="Как добавить VK хеши" title="Как добавить VK хеши" onclick="document.getElementById('vkHashesInfoDlg').showModal()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path><line x1="12" y1="17" x2="12.01" y2="17"></line></svg></button>
                </div>
                <label class="switch">
                    <input type="checkbox" id="edit_vkHashesToggle" onchange="toggleEditVkHashFields()">
                    <span class="slider"></span>
                </label>
            </div>
            <div id="edit_vkHashesFields" style="display: none;">
                <div class="input-group" style="margin-bottom: 0;">
                    <label for="edit_vk_hashes">VK Хеши</label>
                    <input id="edit_vk_hashes" maxlength="1024" autocomplete="off" placeholder="hash1,hash2,...,hash6" oninput="this.classList.remove('is-invalid')">
                </div>
            </div>
        </div>

        <!-- Info Section -->
        <div style="border: 1px solid var(--border); border-radius: 12px; padding: 12px; margin-top: 16px; font-size: 13px; display: flex; flex-direction: column; gap: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center;"><span style="color: var(--text-muted);">Устройство:</span><span style="display: flex; gap: 8px; align-items: center;"><span id="edit_device_info" style="font-weight: 500;">—</span><button class="btn btn-ghost" id="edit_unbindBtn" onclick="executeUnbind()" style="font-size: 11px; padding: 2px 8px; height: auto; min-height: auto; display: none;">Отвязать</button></span></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-muted);">IP-адрес:</span><span id="edit_ip_info" style="font-weight: 500;">—</span></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-muted);">Трафик:</span><span id="edit_traffic_info" style="font-weight: 500; font-family: ui-monospace, SFMono-Regular, 'Cascadia Code', Consolas, monospace;">↑ 0 B / ↓ 0 B</span></div>
        </div>

        <div class="dlg-actions" style="margin-top: 16px;">
            <button class="btn btn-ghost" onclick="document.getElementById('editDlg').close()"><span class="hide-mobile">Отмена</span><span class="show-mobile">Отм.</span></button>
            <button class="btn btn-ghost" id="edit_deleteBtn" style="color: #ef4444;" onclick="executeDelete()"><span class="hide-mobile">Удалить</span><span class="show-mobile">Удал.</span></button>
            <button class="btn btn-ghost" id="edit_statusBtn" style="color: var(--primary);" onclick="executeToggle()">Выкл</button>
            <button class="btn btn-primary" onclick="saveClientChanges()" id="edit_saveBtn"><span class="hide-mobile">Сохранить</span><span class="show-mobile">Сохр.</span></button>
        </div>
    </dialog>

    <dialog id="streamStatsDlg" class="stream-stats-dialog" onclose="stopStreamStats()">
        <div class="dlg-header">
            <div>
                <h2 id="streamStatsTitle">Статистика потоков</h2>
                <div id="streamStatsPassword" style="color: var(--text-muted); font-size: 12px; margin-top: 4px;"></div>
            </div>
            <button class="close-btn" onclick="document.getElementById('streamStatsDlg').close()">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
            </button>
        </div>
        <div id="streamStatsSummary" class="stream-stats-summary"></div>
        <div class="stream-stats-note">Скорость и пакеты в секунду считаются по дельте серверных счётчиков раз в секунду. Протокол не измеряет RTT, поэтому в миллисекундах показана фактическая давность последней активности.</div>
        <div class="stream-stats-table-wrap">
            <table class="stream-stats-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Источник</th>
                        <th>Туннель</th>
                        <th>Режим</th>
                        <th>↑ Сейчас</th>
                        <th>↓ Сейчас</th>
                        <th>Пакеты/с</th>
                        <th>Всего отладки</th>
                        <th>Активность, мс</th>
                        <th>Возраст</th>
                        <th>Состояние</th>
                    </tr>
                </thead>
                <tbody id="streamStatsBody">
                    <tr><td class="stream-stats-empty" colspan="11">Загрузка...</td></tr>
                </tbody>
            </table>
        </div>
    </dialog>

    <dialog id="rebootDlg">
        <h2>Перезапуск сервера</h2>
        <p style="color: var(--text-muted); font-size: 15px; margin-bottom: 24px;">Вы уверены, что хотите перезапустить CSQTT? Активные соединения будут прерваны на несколько секунд.</p>
        <div class="dlg-actions">
            <button class="btn btn-ghost" onclick="document.getElementById('rebootDlg').close()">Отмена</button>
            <button class="btn btn-primary" onclick="executeReboot()">Перезапустить</button>
        </div>
    </dialog>


    <div class="toast-container" id="toastContainer"></div>

    <script>
        function openCryptoDonateDlg() {
            document.getElementById('cryptoDonateDlg').showModal();
        }
        async function copyText(text, btn) {
            if (await copyToClipboard(text)) {
                if (btn) {
                    const orig = btn.textContent;
                    btn.textContent = "Скопировано!";
                    setTimeout(() => { btn.textContent = orig; }, 2000);
                }
                showToast("Адрес скопирован в буфер");
            } else {
                showToast("Не удалось скопировать", "error");
            }
        }
        function toggleTheme() {
            const isDark = document.body.parentElement.getAttribute('data-theme') === 'dark';
            document.body.parentElement.setAttribute('data-theme', isDark ? 'light' : 'dark');
            localStorage.setItem('csqtt-theme', isDark ? 'light' : 'dark');
            document.getElementById('themeIcon').innerHTML = isDark 
                ? '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>' 
                : '<circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>';
        }
        if (localStorage.getItem('csqtt-theme') === 'dark') { toggleTheme(); }

        const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
        
        async function copyToClipboard(text) {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                try {
                    await navigator.clipboard.writeText(text);
                    return true;
                } catch (e) {}
            }
            try {
                const ta = document.createElement('textarea');
                ta.value = text;
                ta.style.position = 'absolute';
                ta.style.left = '-9999px';
                ta.style.top = '0';
                ta.setAttribute('readonly', '');
                document.body.appendChild(ta);
                ta.select();
                ta.setSelectionRange(0, 99999);
                const success = document.execCommand('copy');
                document.body.removeChild(ta);
                return success;
            } catch (e) {
                return false;
            }
        }

        let apiNetworkToastShown = false;
        async function api(u, o = {}) {
            try {
                let res = await fetch(u, { ...o, headers: { "content-type": "application/json", ...o.headers } });
                if (res.status === 401) { location.reload(); }
                apiNetworkToastShown = false;
                return res;
            } catch (e) {
                if (!apiNetworkToastShown) {
                    apiNetworkToastShown = true;
                    showToast("Ошибка сети", "error");
                }
                throw e;
            }
        }

        const size = n => {
            if (n < 1024) return n + " B";
            if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
            if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
            return (n / 1073741824).toFixed(2) + " GB";
        };

        const uptime = s => {
            const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
            return d > 0 ? d + "д " + h + "ч" : h > 0 ? h + "ч " + m + "м" : m + "м";
        };

        function showToast(text, type = 'success') {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            toast.className = 'toast';
            const icon = document.createElement('div');
            icon.className = 'toast-icon';
            icon.textContent = type === 'error' ? '✗' : '✓';
            const message = document.createElement('span');
            message.textContent = String(text);
            toast.append(icon, message);
            container.appendChild(toast);
            setTimeout(() => { toast.classList.add('hide'); setTimeout(() => toast.remove(), 300); }, 3000);
        }

        function showConfirm(title, message, btnText, btnClass, callback, cancelCallback) {
            const dlg = document.getElementById('confirmDlg');
            const titleEl = document.getElementById('confirmTitle');
            const msgEl = document.getElementById('confirmMessage');
            const btn = document.getElementById('confirmActionBtn');
            const cancelBtn = dlg.querySelector('button.btn-ghost');
            let actionTriggered = false;

            if (titleEl) titleEl.textContent = title || 'Подтверждение';
            if (msgEl) msgEl.textContent = message || '';
            if (btn) {
                btn.textContent = btnText || 'Подтвердить';
                btn.className = `btn ${btnClass || 'btn-primary'}`;
                btn.onclick = () => {
                    actionTriggered = true;
                    dlg.close();
                    if (callback) callback();
                };
            }
            if (cancelBtn) {
                cancelBtn.onclick = () => {
                    dlg.close();
                };
            }
            if (dlg) {
                dlg.onclose = () => {
                    if (!actionTriggered && cancelCallback) {
                        cancelCallback();
                    }
                };
                dlg.showModal();
            }
        }

        window.streamDebugEnabled = false;
        let streamDebugToggling = false;
        let streamStatsTimer = null;
        let streamStatsBusy = false;
        let streamStatsPassword = "";
        let streamStatsPrevious = new Map();

        async function loadStats() {
            let r = await api("/api/stats"); if(!r.ok) return; let x = await r.json();
            document.getElementById('status_val').textContent = x.status === "Active" ? "Активно" : x.status;
            document.getElementById('status_uptime').textContent = "Аптайм: " + uptime(x.uptime);
            document.getElementById('active_val').textContent = x.active;
            const cpuTotal = Number(x.cpu_total) || 0;
            const cpuCapacity = Math.max(100, Number(x.cpu_capacity) || 100);
            const cpuNormalized = Math.min(100, Math.max(0, Number(x.cpu_normalized) || 0));
            document.getElementById('cpu_val').textContent = cpuTotal + '% / ' + cpuCapacity + '%';
            document.getElementById('cpu_bar').style.width = cpuNormalized + '%';
            const ramValue = document.getElementById('ram_val');
            const ramDetail = document.getElementById('ram_detail');
            ramValue.textContent = x.ram_used || String(x.ram || '').split(' / ')[0] || '0 MB';
            ramDetail.textContent = `из ${x.ram_total || '0 MB'} · пик ${x.ram_peak || ramValue.textContent}`;
            ramValue.title = [
                `RSS: ${x.ram_used || '0 MB'}`,
                `Анонимная: ${x.ram_anonymous || '0 MB'}`,
                `Файлы: ${x.ram_file || '0 MB'}`,
                `Shared: ${x.ram_shared || '0 MB'}`,
                `Swap: ${x.ram_swap || '0 MB'}`,
                `Пик: ${x.ram_peak || '0 MB'}`,
                `Сессии: ${Number(x.hot_sessions) || 0}/${Number(x.hot_session_capacity) || 0}`,
                `TPROXY TCP/UDP: ${Number(x.local_proxy_tcp_sessions) || 0}/${Number(x.local_proxy_udp_flows) || 0}`
            ].join('\n');
            document.getElementById('traffic_up').textContent = "↑ " + size(x.up);
            document.getElementById('traffic_down').textContent = "↓ " + size(x.down);

            const streamDebugToggle = document.getElementById('streamDebugToggle');
            if (streamDebugToggle && !streamDebugToggling) {
                const enabled = Boolean(x.stream_debug_enabled);
                const changed = window.streamDebugEnabled !== enabled;
                window.streamDebugEnabled = enabled;
                streamDebugToggle.checked = enabled;
                if (!enabled) {
                    const dlg = document.getElementById('streamStatsDlg');
                    if (dlg && dlg.open) dlg.close();
                }
                if (changed && document.getElementById('clients-section').style.display !== 'none') {
                    loadClients();
                }
            }

            updateLocalProxyRuntime(
                Boolean(x.local_proxy_enabled),
                Boolean(x.local_proxy_active),
                x.local_proxy_port_listening,
                Number(x.local_proxy_tcp_sessions) || 0,
                Number(x.local_proxy_udp_flows) || 0,
                x.local_proxy_health_error || null
            );
        }

        let savedMainPassword = '';
        let savedDnsPrimary = '';
        let savedDnsSecondary = '';

        function setRestartRequired(required) {
            document.getElementById('restartRequiredBanner')?.classList.toggle('visible', Boolean(required));
        }

        function updateSettingsDirtyState() {
            const mainPassword = document.getElementById('mainpass')?.value ?? '';
            const dnsPrimary = document.getElementById('dns_primary')?.value.trim() ?? '';
            const dnsSecondary = document.getElementById('dns_secondary')?.value.trim() ?? '';
            const mainButton = document.getElementById('saveMainPasswordBtn');
            const dnsButton = document.getElementById('saveDnsBtn');
            if (mainButton && !mainButton.classList.contains('saving')) {
                mainButton.disabled = mainPassword === savedMainPassword;
            }
            if (dnsButton && !dnsButton.classList.contains('saving')) {
                dnsButton.disabled = dnsPrimary === savedDnsPrimary && dnsSecondary === savedDnsSecondary;
            }
        }

        async function loadSettings() {
            let r = await api("/api/settings"); if(!r.ok) return; let x = await r.json();
            savedMainPassword = x.main_password || '';
            savedDnsPrimary = x.dns_primary || '';
            savedDnsSecondary = x.dns_secondary || '';
            document.getElementById('mainpass').value = savedMainPassword;
            document.getElementById('dns_primary').value = savedDnsPrimary;
            document.getElementById('dns_secondary').value = savedDnsSecondary;
            setRestartRequired(x.restart_required);
            updateSettingsDirtyState();
            loadLocalProxy();
        }

        let localProxyData = { active_profile_id: '', profiles: [], route_active: false, port_listening: true, health_error: null, tcp_sessions: 0, udp_flows: 0 };
        let profileDlgEditId = null;
        let profileDlgSaving = false;

        function renderProxyProfiles() {
            const container = document.getElementById('proxyProfilesList');
            if (!container) return;
            const { profiles, active_profile_id, route_active, port_listening, health_error, tcp_sessions, udp_flows } = localProxyData;
            if (!profiles.length) {
                container.innerHTML = '<div class="proxy-empty">Нет профилей. Нажмите кнопку <strong>+</strong> чтобы добавить.</div>';
                return;
            }
            const playIcon = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M7.5 4.9v14.2a1 1 0 0 0 1.53.85l11.3-7.1a1 1 0 0 0 0-1.7L9.03 4.05a1 1 0 0 0-1.53.85z"/></svg>';
            const stopIcon = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="5.5" y="5.5" width="13" height="13" rx="2"/></svg>';
            const editIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>';
            const trashIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>';
            container.innerHTML = profiles.map(p => {
                const isActive = p.id === active_profile_id;
                let badge = '';
                if (isActive) {
                    if (route_active) {
                        badge = `<span style="font-size:11px;font-weight:600;color:#10b981;margin-left:6px;">Активен</span>`;
                    } else if (port_listening === false) {
                        badge = `<span style="font-size:11px;font-weight:600;color:#ef4444;margin-left:6px;">Порт не слушается</span>`;
                    } else if (health_error) {
                        badge = `<span style="font-size:11px;font-weight:600;color:#ef4444;margin-left:6px;" title="${esc(health_error)}">Проба не прошла (Direct)</span>`;
                    } else {
                        badge = `<span style="font-size:11px;font-weight:600;color:#f59e0b;margin-left:6px;">Подключение...</span>`;
                    }
                }
                let meta = p.username ? `${p.port} · ${p.username}` : `${p.port}`;
                if (isActive) {
                    if (route_active) {
                        meta += ` · ${tcp_sessions} TCP · ${udp_flows} UDP`;
                    } else if (health_error) {
                        meta += ` · Ошибка: ${esc(health_error)}`;
                    }
                }
                const toggleBtn = isActive
                    ? `<button title="Деактивировать" onclick="deactivateProxy()">${stopIcon}</button>`
                    : `<button title="Активировать" onclick="activateProxy('${esc(p.id)}')">${playIcon}</button>`;
                return `<div class="proxy-profile-card${isActive ? ' is-active' : ''}" data-id="${esc(p.id)}">
                    <div class="proxy-profile-dot"></div>
                    <div class="proxy-profile-body">
                        <div class="proxy-profile-name">${esc(p.name)}${badge}</div>
                        <div class="proxy-profile-meta">${meta}</div>
                    </div>
                    <div class="proxy-profile-actions">
                        ${toggleBtn}
                        <button title="Редактировать" onclick="openProfileDlg('${esc(p.id)}')">${editIcon}</button>
                        <button class="danger" title="Удалить" onclick="deleteProxy('${esc(p.id)}','${esc(p.name)}')">${trashIcon}</button>
                    </div>
                </div>`;
            }).join('');
        }

        function updateLocalProxyRuntime(enabled, active, portListening, tcpSessions, udpFlows, healthError) {
            const routeActive = Boolean(enabled) && Boolean(active);
            const listening = portListening !== false;
            const tcp = Number(tcpSessions) || 0;
            const udp = Number(udpFlows) || 0;
            const err = healthError || null;
            if (
                localProxyData.route_active === routeActive &&
                localProxyData.port_listening === listening &&
                localProxyData.health_error === err &&
                localProxyData.tcp_sessions === tcp &&
                localProxyData.udp_flows === udp
            ) return;
            localProxyData.route_active = routeActive;
            localProxyData.port_listening = listening;
            localProxyData.health_error = err;
            localProxyData.tcp_sessions = tcp;
            localProxyData.udp_flows = udp;
            if (document.getElementById('settings-section').style.display !== 'none') {
                renderProxyProfiles();
            }
        }


        async function loadLocalProxy() {
            const r = await api('/api/local-proxy');
            if (!r.ok) return;
            localProxyData = await r.json();
            renderProxyProfiles();
        }

        function openProfileDlg(editId) {
            profileDlgEditId = editId || null;
            const dlg = document.getElementById('profileDlg');
            const title = document.getElementById('profileDlgTitle');
            const saveBtn = document.getElementById('profileDlgSave');
            if (editId) {
                const p = localProxyData.profiles.find(x => x.id === editId);
                if (!p) return;
                title.textContent = 'Редактировать профиль';
                saveBtn.textContent = 'Сохранить';
                document.getElementById('profileDlgName').value = p.name;
                document.getElementById('profileDlgPort').value = p.port;
                document.getElementById('profileDlgUser').value = p.username || '';
                document.getElementById('profileDlgPass').value = p.password || '';
            } else {
                title.textContent = 'Новый профиль';
                saveBtn.textContent = 'Создать';
                document.getElementById('profileDlgName').value = '';
                document.getElementById('profileDlgPort').value = '45000';
                document.getElementById('profileDlgUser').value = '';
                document.getElementById('profileDlgPass').value = '';
            }
            dlg.showModal();
        }

        async function saveProfileDlg() {
            if (profileDlgSaving) return;
            const name = document.getElementById('profileDlgName').value.trim();
            const port = parseInt(document.getElementById('profileDlgPort').value, 10);
            const username = document.getElementById('profileDlgUser').value;
            const password = document.getElementById('profileDlgPass').value;
            if (!port || port < 1 || port > 65535) {
                showToast('Укажите порт от 1 до 65535', 'error'); return;
            }
            if (password && !username) {
                showToast('Для пароля SOCKS5 укажите логин', 'error'); return;
            }
            const body = JSON.stringify({ name, port, username, password });
            const btn = document.getElementById('profileDlgSave');
            profileDlgSaving = true;
            btn.disabled = true;
            btn.textContent = 'Сохранение...';
            try {
                let r;
                if (profileDlgEditId) {
                    r = await api(`/api/local-proxy/profiles/${profileDlgEditId}`, { method: 'PUT', body });
                } else {
                    r = await api('/api/local-proxy', { method: 'POST', body });
                }
                if (!r.ok) {
                    showToast((await r.text()) || 'Ошибка', 'error'); return;
                }
                const data = await r.json().catch(() => ({}));
                document.getElementById('profileDlg').close();
                showToast(profileDlgEditId ? 'Профиль обновлён' : 'Профиль создан', 'success');
                if (data.port_listening === false) {
                    showToast('Указанный вами порт никем не слушается', 'error');
                }
                await loadLocalProxy();
            } finally {
                profileDlgSaving = false;
                btn.disabled = false;
                btn.textContent = profileDlgEditId ? 'Сохранить' : 'Создать';
            }
        }

        async function activateProxy(id) {
            const r = await api(`/api/local-proxy/activate/${id}`, { method: 'POST', body: '{}' });
            if (!r.ok) { showToast((await r.text()) || 'Ошибка активации', 'error'); return; }
            showToast('Профиль активирован', 'success');
            await loadLocalProxy();
        }

        async function deactivateProxy() {
            const r = await api('/api/local-proxy/deactivate', { method: 'POST', body: '{}' });
            if (!r.ok) { showToast((await r.text()) || 'Ошибка', 'error'); return; }
            showToast('Маршрут SOCKS5 отключён', 'success');
            await loadLocalProxy();
        }

        async function deleteProxy(id, name) {
            showConfirm(`Удалить профиль «${name}»?`, `Удаление профиля необратимо.`, 'Удалить', 'btn-danger', async () => {
                const r = await api(`/api/local-proxy/profiles/${id}`, { method: 'DELETE', body: '{}' });
                if (!r.ok) { showToast((await r.text()) || 'Ошибка', 'error'); return; }
                showToast('Профиль удалён', 'success');
                await loadLocalProxy();
            });
        }

        window.clientsData = [];
        async function loadClients() {
            let r = await api("/api/clients"); if(!r.ok) return; let a = await r.json();
            window.clientsData = a || [];
            const container = document.getElementById('clientsCards');
            if(!a.length) { container.innerHTML = `<div class="empty-state" style="grid-column: 1/-1;">Нет созданных доступов.</div>`; return; }
            
            container.innerHTML = a.map((x, idx) => {
                const isMain = x.name === "Главный пароль";
                const expiryStr = isMain ? "—" : (x.expires ? new Date(x.expires * 1000).toLocaleDateString() : "∞ Бессрочно");
                
                return `
                <div class="client-card" onclick="openEditClientDlgByIndex(${idx})">
                    <div class="client-card-header">
                        <div class="client-card-title">${esc(x.name || 'Без имени')}</div>
                        <span class="badge ${x.active ? "active" : "inactive"}">${x.active ? "Активно" : "Неактивно"}</span>
                    </div>
                    <div class="client-card-body">
                        <div class="client-card-row">
                            <span class="client-card-label">Ключ (пароль):</span>
                            <span class="client-pw">${esc(x.password)}</span>
                        </div>
                        <div class="client-card-row">
                            <span class="client-card-label">Срок действия:</span>
                            <span class="client-card-value">${expiryStr}</span>
                        </div>
                        <div class="client-card-row">
                            <span class="client-card-label">Трафик:</span>
                            <span class="client-card-value" style="font-family: ui-monospace, SFMono-Regular, 'Cascadia Code', Consolas, monospace;">↑ ${size(x.up)} / ↓ ${size(x.down)}</span>
                        </div>
                        <div class="client-card-row">
                            <span class="client-card-label">Потоки:</span>
                            <span class="stream-card-actions">
                                ${window.streamDebugEnabled && x.active_sessions > 0 ? `<button class="stream-stats-btn" onclick="openStreamStats(event, ${idx})">Открыть статистику</button>` : ''}
                                <span class="stream-count-value">${x.active_sessions}</span>
                            </span>
                        </div>
                    </div>
                </div>
                `;
            }).join("");
        }

        async function toggleStreamDebug() {
            const toggle = document.getElementById('streamDebugToggle');
            if (!toggle || streamDebugToggling) return;
            const previous = window.streamDebugEnabled;
            const requested = toggle.checked;
            streamDebugToggling = true;
            toggle.disabled = true;
            try {
                const r = await api("/api/stream-debug", {
                    method: "POST",
                    body: JSON.stringify({ enabled: requested })
                });
                if (!r.ok) {
                    toggle.checked = previous;
                    showToast(await r.text(), "error");
                    return;
                }
                const result = await r.json();
                window.streamDebugEnabled = Boolean(result.enabled);
                toggle.checked = window.streamDebugEnabled;
                if (!window.streamDebugEnabled) {
                    const dlg = document.getElementById('streamStatsDlg');
                    if (dlg.open) dlg.close();
                }
                await loadClients();
                showToast(window.streamDebugEnabled ? "Отладка потоков включена" : "Отладка потоков выключена");
            } catch (e) {
                toggle.checked = previous;
            } finally {
                streamDebugToggling = false;
                toggle.disabled = false;
            }
        }

        function formatStreamRate(bytesPerSecond) {
            return bytesPerSecond === null ? "…" : size(Math.round(bytesPerSecond)) + "/с";
        }

        function formatStreamDuration(milliseconds) {
            const ms = Math.max(0, Math.round(milliseconds));
            if (ms < 1000) return ms + " мс";
            if (ms < 60000) return (ms / 1000).toFixed(1) + " с";
            if (ms < 3600000) return Math.floor(ms / 60000) + " м " + Math.floor(ms % 60000 / 1000) + " с";
            return uptime(Math.floor(ms / 1000));
        }

        function stopStreamStats() {
            if (streamStatsTimer) {
                clearInterval(streamStatsTimer);
                streamStatsTimer = null;
            }
            streamStatsPassword = "";
            streamStatsPrevious.clear();
        }

        function openStreamStats(event, idx) {
            event.stopPropagation();
            const client = window.clientsData && window.clientsData[idx];
            if (!client || !window.streamDebugEnabled) return;
            const dlg = document.getElementById('streamStatsDlg');
            stopStreamStats();
            streamStatsPassword = client.password;
            document.getElementById('streamStatsTitle').textContent = "Потоки: " + (client.name || "Без имени");
            document.getElementById('streamStatsPassword').textContent = "Пароль: " + client.password;
            document.getElementById('streamStatsSummary').innerHTML = '<span class="stream-summary-chip">Загрузка первого замера...</span>';
            document.getElementById('streamStatsBody').innerHTML = '<tr><td class="stream-stats-empty" colspan="11">Загрузка...</td></tr>';
            const tableWrap = dlg.querySelector('.stream-stats-table-wrap');
            tableWrap.scrollTop = 0;
            tableWrap.scrollLeft = 0;
            dlg.showModal();
            refreshStreamStats();
            streamStatsTimer = setInterval(refreshStreamStats, 1000);
        }

        async function refreshStreamStats() {
            const dlg = document.getElementById('streamStatsDlg');
            if (!dlg.open || !streamStatsPassword || streamStatsBusy) return;
            const requestedPassword = streamStatsPassword;
            streamStatsBusy = true;
            try {
                const r = await api("/api/clients/" + encodeURIComponent(requestedPassword) + "/streams");
                if (!r.ok || requestedPassword !== streamStatsPassword) return;
                const data = await r.json();
                if (!data.enabled) {
                    window.streamDebugEnabled = false;
                    const toggle = document.getElementById('streamDebugToggle');
                    if (toggle) toggle.checked = false;
                    dlg.close();
                    loadClients();
                    return;
                }

                const sampledAt = performance.now();
                const serverNow = Number(data.server_now) || 0;
                const streams = Array.isArray(data.streams) ? data.streams : [];
                const next = new Map();
                let totalUpRate = 0;
                let totalDownRate = 0;
                let ratedStreams = 0;

                const rows = streams.map((stream, index) => {
                    const previous = streamStatsPrevious.get(stream.id);
                    let upRate = null;
                    let downRate = null;
                    let upPps = null;
                    let downPps = null;
                    if (previous) {
                        const seconds = Math.max((sampledAt - previous.sampledAt) / 1000, 0.001);
                        upRate = Math.max(0, Number(stream.up_bytes) - previous.upBytes) / seconds;
                        downRate = Math.max(0, Number(stream.down_bytes) - previous.downBytes) / seconds;
                        upPps = Math.max(0, Number(stream.up_packets) - previous.upPackets) / seconds;
                        downPps = Math.max(0, Number(stream.down_packets) - previous.downPackets) / seconds;
                        totalUpRate += upRate;
                        totalDownRate += downRate;
                        ratedStreams++;
                    }
                    next.set(stream.id, {
                        sampledAt,
                        upBytes: Number(stream.up_bytes),
                        downBytes: Number(stream.down_bytes),
                        upPackets: Number(stream.up_packets),
                        downPackets: Number(stream.down_packets)
                    });

                    const activityMs = stream.last_seen ? Math.max(0, serverNow - Number(stream.last_seen)) * 1000 : null;
                    const ageMs = Math.max(0, serverNow - Number(stream.created_at)) * 1000;
                    const ready = Boolean(stream.tunnel_ready && stream.handshake_ready);
                    const stateText = ready ? "Готов" : (stream.handshake_ready ? "Туннель..." : "Рукопожатие...");
                    const sourceDetails = stream.device_id ? `<div style="color: var(--text-muted); font-size: 10px;">${esc(stream.device_id)} · gen ${Number(stream.generation)}</div>` : "";
                    return `<tr>
                        <td data-label="#">${index + 1}</td>
                        <td data-label="Источник" class="stream-cell-source"><div>${esc(stream.source)}</div>${sourceDetails}</td>
                        <td data-label="Туннель">${esc(stream.tunnel_ip || "—")}</td>
                        <td data-label="Режим">${esc(stream.mode)}</td>
                        <td data-label="↑ Сейчас">${formatStreamRate(upRate)}</td>
                        <td data-label="↓ Сейчас">${formatStreamRate(downRate)}</td>
                        <td data-label="Пакеты/с" class="stream-cell-packets">${upPps === null ? "…" : "↑ " + upPps.toFixed(0) + " / ↓ " + downPps.toFixed(0)}</td>
                        <td data-label="Всего" class="stream-cell-total">↑ ${size(Number(stream.up_bytes))} / ↓ ${size(Number(stream.down_bytes))}</td>
                        <td data-label="Активность">${activityMs === null ? "—" : formatStreamDuration(activityMs)}</td>
                        <td data-label="Возраст">${formatStreamDuration(ageMs)}</td>
                        <td data-label="Состояние" class="stream-cell-state"><span class="stream-state"><span class="stream-state-dot ${ready ? "" : "waiting"}"></span>${stateText}</span></td>
                    </tr>`;
                }).join("");

                streamStatsPrevious = next;
                document.getElementById('streamStatsBody').innerHTML = rows || '<tr><td class="stream-stats-empty" colspan="11">Активных потоков для этого пароля сейчас нет.</td></tr>';
                document.getElementById('streamStatsSummary').innerHTML = `
                    <span class="stream-summary-chip">Активных: ${streams.length}</span>
                    <span class="stream-summary-chip">↑ ${ratedStreams ? formatStreamRate(totalUpRate) : "первый замер"}</span>
                    <span class="stream-summary-chip">↓ ${ratedStreams ? formatStreamRate(totalDownRate) : "первый замер"}</span>
                    <span class="stream-summary-chip">Интервал: 1 с</span>
                `;
            } finally {
                streamStatsBusy = false;
            }
        }

        function openEditClientDlgByIndex(idx) {
            if (window.clientsData && window.clientsData[idx]) {
                openEditClientDlg(window.clientsData[idx]);
            }
        }

        function openNewClientDlg() {
            document.getElementById('cname').value = '';
            document.getElementById('csqttToggle').checked = false;
            document.getElementById('vkHashesToggle').checked = false;
            document.getElementById('vk_hashes').value = '';
            document.getElementById('vk_hashes').classList.remove('is-invalid');
            toggleWdttFields();
            document.getElementById('newDlg').showModal();
        }

        function toggleWdttFields() {
            const toggle = document.getElementById('csqttToggle').checked;
            document.getElementById('csqttFields').style.display = toggle ? 'block' : 'none';
            if (!toggle) document.getElementById('vkHashesToggle').checked = false;
            toggleVkHashFields();
        }

        function toggleVkHashFields() {
            const enabled = document.getElementById('csqttToggle').checked && document.getElementById('vkHashesToggle').checked;
            document.getElementById('vkHashesFields').style.display = enabled ? 'block' : 'none';
        }

        function readNewClientVkHashes() {
            return readVkHashes('vkHashesToggle', 'vk_hashes');
        }

        function readEditClientVkHashes() {
            return readVkHashes('edit_vkHashesToggle', 'edit_vk_hashes');
        }

        function readVkHashes(toggleId, inputId) {
            if (!document.getElementById(toggleId).checked) return [];
            const input = document.getElementById(inputId);
            const value = input.value.trim();
            const hashes = value.split(',');
            const valid = value.length > 0 && !/\s/.test(value) && hashes.length <= 6 && hashes.every(hash => hash.length >= 16);
            input.classList.toggle('is-invalid', !valid);
            if (!valid) throw new Error('Укажите от 1 до 6 VK-хешей через запятую без пробелов');
            return hashes;
        }

        async function createClient() {
            const toggle = document.getElementById('csqttToggle').checked;
            let vkHashes = [];
            try {
                vkHashes = readNewClientVkHashes();
            } catch (error) {
                showToast(error.message, "error");
                return;
            }

            const btn = document.getElementById('createBtn');
            btn.textContent = 'Создание...'; btn.disabled = true;
            
            try {
                let r = await api("/api/clients", {
                    method: "POST",
                    body: JSON.stringify({
                        name: document.getElementById('cname').value.trim(),
                        days: +document.getElementById('days').value,
                        hash: vkHashes.join(','),
                        dtls_port: toggle ? +document.getElementById('peer_port').value : 0,
                        wg_port: toggle ? +document.getElementById('wg_port').value : 0,
                        local_port: toggle ? +document.getElementById('local_port').value : 0
                    })
                });
                
                if(!r.ok) { showToast(await r.text(), "error"); } else {
                    let x = await r.json();
                    document.getElementById('newDlg').close();
                    if (toggle) {
                        const fullClient = {
                            ...x,
                            dtls_port: x.dtls_port || (toggle ? +document.getElementById('peer_port').value : 46000),
                            wg_port: x.wg_port || (toggle ? +document.getElementById('wg_port').value : 46001),
                            local_port: x.local_port || (toggle ? +document.getElementById('local_port').value : 0)
                        };
                        await copycsqtt(fullClient);
                    } else {
                        showToast("Ключ успешно создан");
                    }
                    loadClients();
                }
            } finally { btn.textContent = 'Создать'; btn.disabled = false; }
        }

        function buildCsqttLink(password, peerPort, rawHashes) {
            let url = "csqtt://connect?v=2&host=" + encodeURIComponent(location.hostname) +
                "&peer=" + encodeURIComponent(peerPort) +
                "&password=" + encodeURIComponent(password);
            const hashes = String(rawHashes || '').split(',').map(hash => hash.trim()).filter(Boolean);
            if (hashes.length) url += "&hashes=" + hashes.map(encodeURIComponent).join('+');
            return url;
        }

        async function copycsqtt(c) {
            const url = buildCsqttLink(c.password, c.dtls_port || 46000, c.vk_hashes);
            if (await copyToClipboard(url)) {
                showToast("Ссылка csqtt:// скопирована");
            } else {
                showToast("Не удалось скопировать", "error");
            }
        }

        let activeClient = null;

        function openEditClientDlg(c) {
            activeClient = c;
            const isMain = c.name === "Главный пароль";
            
            document.getElementById('edit_name').value = c.name || '';
            document.getElementById('edit_name').disabled = isMain;
            document.getElementById('edit_pass').value = c.password || '';
            
            let remainingDays = 0;
            if (c.expires) {
                remainingDays = Math.max(0, Math.ceil((c.expires * 1000 - Date.now()) / 86400000));
            }
            document.getElementById('edit_days').value = c.expires ? remainingDays : 0;
            document.getElementById('edit_days').disabled = isMain;
            
            const storedVkHashes = String(c.vk_hashes || c.vk_hash || '');
            const hasWdtt = Boolean(c.dtls_port || c.wg_port || c.local_port || storedVkHashes);
            document.getElementById('edit_csqttToggle').checked = hasWdtt;
            document.getElementById('edit_csqttToggle').disabled = isMain;
            
            document.getElementById('edit_peer_port').value = c.dtls_port || 46000;
            document.getElementById('edit_wg_port').value = c.wg_port || 46001;
            document.getElementById('edit_local_port').value = c.local_port || 0;
            document.getElementById('edit_vkHashesToggle').checked = storedVkHashes.length > 0;
            document.getElementById('edit_vkHashesToggle').disabled = isMain;
            document.getElementById('edit_vk_hashes').value = storedVkHashes;
            document.getElementById('edit_vk_hashes').disabled = isMain;
            document.getElementById('edit_vk_hashes').classList.remove('is-invalid');
            toggleEditWdttFields();

            document.getElementById('edit_device_info').textContent = c.device_id || '—';
            document.getElementById('edit_ip_info').textContent = c.ip || '—';
            document.getElementById('edit_traffic_info').textContent = `↑ ${size(c.up)} / ↓ ${size(c.down)}`;
            
            document.getElementById('edit_statusBtn').innerHTML = c.active ? 'Выкл' : 'Вкл';
            document.getElementById('edit_statusBtn').style.display = isMain ? 'none' : 'inline-block';
            
            document.getElementById('edit_unbindBtn').style.display = (!c.device_id) ? 'none' : 'inline-block';
            document.getElementById('edit_copyLinkBtn').style.display = hasWdtt ? 'inline-block' : 'none';
            document.getElementById('edit_deleteBtn').style.display = isMain ? 'none' : 'inline-block';
            document.getElementById('edit_saveBtn').style.display = isMain ? 'none' : 'inline-block';
            
            document.getElementById('editDlg').showModal();
        }

        function toggleEditWdttFields() {
            const toggle = document.getElementById('edit_csqttToggle').checked;
            document.getElementById('edit_csqttFields').style.display = toggle ? 'block' : 'none';
            if (!toggle) document.getElementById('edit_vkHashesToggle').checked = false;
            toggleEditVkHashFields();
            if (activeClient) {
                document.getElementById('edit_copyLinkBtn').style.display = toggle ? 'inline-block' : 'none';
            }
        }

        function toggleEditVkHashFields() {
            const enabled = document.getElementById('edit_csqttToggle').checked && document.getElementById('edit_vkHashesToggle').checked;
            document.getElementById('edit_vkHashesFields').style.display = enabled ? 'block' : 'none';
        }

        async function copyPasswordText() {
            let val = document.getElementById('edit_pass').value;
            if (await copyToClipboard(val)) {
                showToast("Пароль скопирован");
            } else {
                showToast("Не удалось скопировать", "error");
            }
        }

        async function executeToggle() {
            if (!activeClient) return;
            let r = await api("/api/clients/" + encodeURIComponent(activeClient.password) + "/toggle", {method: "POST"});
            if (r.ok) {
                showToast("Статус изменен");
                document.getElementById('editDlg').close();
                loadClients();
            }
        }

        async function executeUnbind() {
            if (!activeClient) return;
            let r = await api("/api/clients/" + encodeURIComponent(activeClient.password) + "/unbind", {method: "POST"});
            if (r.ok) {
                showToast("Привязка сброшена");
                document.getElementById('editDlg').close();
                loadClients();
            }
        }

        async function executeCopyLink() {
            if (!activeClient) return;
            const dtls = +document.getElementById('edit_peer_port').value || 46000;
            const password = activeClient.password;
            let vkHashes = [];
            try {
                vkHashes = readEditClientVkHashes();
            } catch (error) {
                showToast(error.message, "error");
                return;
            }

            const url = buildCsqttLink(password, dtls, vkHashes.join(','));
            if (await copyToClipboard(url)) {
                showToast("Ссылка csqtt:// скопирована");
            } else {
                showToast("Не удалось скопировать", "error");
            }
        }

        async function executeDelete() {
            if (!activeClient) return;
            let r = await api("/api/clients/" + encodeURIComponent(activeClient.password), {method: "DELETE"});
            if (r.ok) {
                showToast("Доступ удален");
                document.getElementById('editDlg').close();
                loadClients();
            }
        }

        async function saveClientChanges() {
            if (!activeClient) return;
            const toggle = document.getElementById('edit_csqttToggle').checked;
            let vkHashes = [];
            try {
                vkHashes = readEditClientVkHashes();
            } catch (error) {
                showToast(error.message, "error");
                return;
            }

            const btn = document.getElementById('edit_saveBtn');
            btn.textContent = 'Сохранение...'; btn.disabled = true;
            
            try {
                let r = await api("/api/clients/" + encodeURIComponent(activeClient.password), {
                    method: "POST",
                    body: JSON.stringify({
                        name: document.getElementById('edit_name').value.trim(),
                        days: +document.getElementById('edit_days').value,
                        hash: vkHashes.join(','),
                        dtls_port: toggle ? +document.getElementById('edit_peer_port').value : 0,
                        wg_port: toggle ? +document.getElementById('edit_wg_port').value : 0,
                        local_port: toggle ? +document.getElementById('edit_local_port').value : 0
                    })
                });
                
                if(!r.ok) { showToast(await r.text(), "error"); } else {
                    showToast("Изменения сохранены");
                    document.getElementById('editDlg').close();
                    loadClients();
                }
            } finally { btn.textContent = 'Сохранить'; btn.disabled = false; }
        }
        let logsLoadedOnce = false;
        async function loadLogs() {
            const consoleElem = document.getElementById('logConsole');
            
            const selection = window.getSelection();
            const isSelecting = selection && selection.toString().length > 0 && consoleElem.contains(selection.anchorNode);
            
            if (isSelecting) {
                return;
            }

            let r = await api("/api/logs"); if(!r.ok) return; let x = await r.json();
            document.getElementById('logFilePath').textContent = "Путь: " + x.path;
            document.getElementById('loggingActiveToggle').checked = x.active;
            
            const threshold = 30;
            const scrollBottom = consoleElem.scrollHeight - consoleElem.clientHeight;
            const isScrolledToBottom = (scrollBottom - consoleElem.scrollTop) <= threshold;

            const linesHtml = x.lines.map(line => {
                let escLine = esc(line);
                const match = escLine.match(/^\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)$/);
                if (match) {
                    const [, timestamp, level, message] = match;
                    const lvlClass = level.trim() === 'ERROR' ? 'log-err' : 'log-info';
                    return `<div class="log-line"><span class="log-time">[${timestamp}]</span><span class="log-lvl ${lvlClass}">${level}</span><span>${message}</span></div>`;
                }
                return `<div class="log-line"><span>${escLine}</span></div>`;
            }).join('');

            consoleElem.innerHTML = linesHtml;

            if (isScrolledToBottom || !logsLoadedOnce) {
                consoleElem.scrollTop = consoleElem.scrollHeight;
                logsLoadedOnce = true;
            }
        }

        async function toggleLoggingActive() {
            const active = document.getElementById('loggingActiveToggle').checked;
            let r = await api("/api/logs/toggle", {
                method: "POST",
                body: JSON.stringify({ active })
            });
            if (r.ok) {
                showToast(active ? "Логирование включено" : "Логирование выключено");
            }
        }

        async function clearLogs() {
            if (!confirm("Вы действительно хотите очистить всю историю логов?")) return;
            let r = await api("/api/logs/clear", {method: "POST"});
            if (r.ok) {
                document.getElementById('logConsole').textContent = '';
                showToast("История логов очищена");
            }
        }

        async function animateSavedButton(button, normalText) {
            button.classList.add('save-success');
            button.textContent = 'Успешно!';
            await new Promise(resolve => setTimeout(resolve, 700));
            button.classList.remove('save-success', 'saving');
            button.textContent = normalText;
            updateSettingsDirtyState();
        }

        async function saveMainPassword() {
            const button = document.getElementById('saveMainPasswordBtn');
            if (!button || button.disabled) return;
            button.classList.add('saving'); button.disabled = true;
            const value = document.getElementById('mainpass').value;
            const response = await api('/api/settings', {
                method: 'POST', body: JSON.stringify({ main_password: value })
            });
            if (!response.ok) {
                button.classList.remove('saving');
                showToast(await response.text(), 'error');
                updateSettingsDirtyState();
                return;
            }
            const result = await response.json();
            savedMainPassword = value;
            setRestartRequired(result.restart_required);
            await animateSavedButton(button, 'Сохранить главный пароль');
        }

        async function saveDnsSettings() {
            const button = document.getElementById('saveDnsBtn');
            if (!button || button.disabled) return;
            button.classList.add('saving'); button.disabled = true;
            const primary = document.getElementById('dns_primary').value.trim();
            const secondary = document.getElementById('dns_secondary').value.trim();
            const response = await api('/api/settings', {
                method: 'POST', body: JSON.stringify({ dns_primary: primary, dns_secondary: secondary })
            });
            if (!response.ok) {
                button.classList.remove('saving');
                showToast(await response.text(), 'error');
                updateSettingsDirtyState();
                return;
            }
            const result = await response.json();
            savedDnsPrimary = primary;
            savedDnsSecondary = secondary;
            setRestartRequired(result.restart_required);
            await animateSavedButton(button, 'Сохранить DNS');
        }
        async function executeReboot() {
            document.getElementById('rebootDlg').close();
            const response = await api("/api/reboot", {method: "POST"});
            if (!response.ok) {
                showToast("Не удалось подготовить перезагрузку", "error");
                return;
            }
            showToast("Сервер перезапускается...");
            setTimeout(() => location.reload(), 3000);
        }
        async function logout() { await api("/api/logout", {method: "POST"}); sessionStorage.clear(); location.reload(); }

        function switchTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
            });
            document.getElementById('monitoring-section').style.display = tabId === 'monitoring' ? 'block' : 'none';
            document.getElementById('clients-section').style.display = tabId === 'clients' ? 'block' : 'none';
            document.getElementById('logs-section').style.display = tabId === 'logs' ? 'block' : 'none';
            document.getElementById('settings-section').style.display = tabId === 'settings' ? 'block' : 'none';
            localStorage.setItem('csqtt-active-tab', tabId);
            if (tabId === 'logs') {
                loadLogs();
            }
        }

        const savedTab = localStorage.getItem('csqtt-active-tab') || 'monitoring';
        switchTab(savedTab);

        let updateIntervalId = null;
        let logsIntervalId = null;
        function startUpdateInterval(ms) {
            if (updateIntervalId) clearInterval(updateIntervalId);
            updateIntervalId = setInterval(() => {
                loadStats();
                if (document.getElementById('clients-section').style.display !== 'none') {
                    loadClients();
                }
            }, ms);
            if (!logsIntervalId) {
                logsIntervalId = setInterval(() => {
                    if (document.getElementById('logs-section').style.display !== 'none') {
                        loadLogs();
                    }
                }, 5000);
            }
        }

        function changeUpdateInterval() {
            const ms = parseInt(document.getElementById('updateIntervalSelect').value, 10);
            localStorage.setItem('csqtt-update-interval', ms);
            startUpdateInterval(ms);
        }

        document.getElementById('mainpass')?.addEventListener('input', updateSettingsDirtyState);
        document.getElementById('dns_primary')?.addEventListener('input', updateSettingsDirtyState);
        document.getElementById('dns_secondary')?.addEventListener('input', updateSettingsDirtyState);
        loadStats(); loadSettings(); loadClients(); if (savedTab === 'logs') { loadLogs(); }
        
        const savedInterval = parseInt(localStorage.getItem('csqtt-update-interval'), 10) || 3000;
        const selectElem = document.getElementById('updateIntervalSelect');
        if (selectElem) {
            selectElem.value = savedInterval;
        }
        startUpdateInterval(savedInterval);
    </script>
</body>
</html>

"##;

#[cfg(test)]
mod tests {
    use super::{PANEL_HTML, normalize_client_vk_hashes, process_memory};

    #[test]
    fn client_vk_hashes_accept_empty_or_one_to_six_values() {
        assert_eq!(normalize_client_vk_hashes("").unwrap(), "");
        for count in 1..=6 {
            let hashes = (1..=count)
                .map(|index| format!("abcdefghijklmnop{index}"))
                .collect::<Vec<_>>()
                .join(",");
            assert_eq!(normalize_client_vk_hashes(&hashes).unwrap(), hashes);
        }
    }

    #[test]
    fn client_vk_hashes_reject_spaces_short_values_and_more_than_six() {
        assert!(normalize_client_vk_hashes("abcdefghijklmnop, abcdefghijklmnop").is_err());
        assert!(normalize_client_vk_hashes("short").is_err());
        let seven = (1..=7)
            .map(|index| format!("abcdefghijklmnop{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(normalize_client_vk_hashes(&seven).is_err());
    }

    #[test]
    fn mobile_panel_keeps_compact_labels_and_consistent_memory_value() {
        assert!(PANEL_HTML.contains("Использование памяти"));
        assert!(PANEL_HTML.contains("#ram_val { white-space: nowrap;"));
        assert!(PANEL_HTML.contains("id=\"ram_detail\""));
        assert!(PANEL_HTML.contains("x.ram_used"));
        assert!(PANEL_HTML.contains("text-size-adjust: none"));
        assert!(PANEL_HTML.contains(".toggle-row label"));
        assert!(PANEL_HTML.contains("white-space: nowrap"));
    }

    #[test]
    fn process_memory_reads_linux_status_fields() {
        let memory = process_memory(
            "VmHWM:\t850000 kB\nVmRSS:\t400000 kB\nRssAnon:\t350000 kB\nRssFile:\t45000 kB\nRssShmem:\t5000 kB\nVmSwap:\t12000 kB\n",
        );
        assert_eq!(memory.rss, 400000);
        assert_eq!(memory.peak, 850000);
        assert_eq!(memory.anonymous, 350000);
        assert_eq!(memory.file, 45000);
        assert_eq!(memory.shared, 5000);
        assert_eq!(memory.swap, 12000);
    }
}
