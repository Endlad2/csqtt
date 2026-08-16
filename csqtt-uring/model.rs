// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use x25519_dalek::{PublicKey, StaticSecret};

pub const MAX_PASSWORDS: usize = 20;
pub const PASSWORD_LEN: usize = 16;
pub const PASS_CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
static DATABASE_SAVE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientDevice {
    pub device_id: String,
    pub ip: String,
    pub priv_key: String,
    pub pub_key: String,
    pub up_bytes: i64,
    pub down_bytes: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub bound_password: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_session_salt: String,
    pub last_generation_id: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordEntry {
    pub device_id: String,
    pub expires_at: i64,
    pub down_bytes: i64,
    pub up_bytes: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub vk_hash: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ports: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub is_deactivated: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub vk_hashes: String,
    pub dtls_port: u16,
    pub wg_port: u16,
    pub local_port: u16,
}

pub const DEFAULT_LOCAL_PROXY_PORT: u16 = 45000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalProxyProfile {
    pub id: String,
    pub name: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
}

impl LocalProxyProfile {
    pub fn new_id() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 6];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LocalProxyState {
    pub active_profile_id: String,
    pub profiles: Vec<LocalProxyProfile>,
}

impl LocalProxyState {
    pub fn normalize(&mut self) {
        for profile in &mut self.profiles {
            if profile.port == 0 {
                profile.port = DEFAULT_LOCAL_PROXY_PORT;
            }
        }
        if !self.active_profile_id.is_empty()
            && !self.profiles.iter().any(|p| p.id == self.active_profile_id)
        {
            self.active_profile_id.clear();
        }
    }

    pub fn active_profile(&self) -> Option<&LocalProxyProfile> {
        if self.active_profile_id.is_empty() {
            return None;
        }
        self.profiles
            .iter()
            .find(|p| p.id == self.active_profile_id)
    }

    pub fn find_profile(&self, id: &str) -> Option<&LocalProxyProfile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    pub fn find_profile_mut(&mut self, id: &str) -> Option<&mut LocalProxyProfile> {
        self.profiles.iter_mut().find(|p| p.id == id)
    }

    pub fn remove_profile(&mut self, id: &str) -> bool {
        let before = self.profiles.len();
        self.profiles.retain(|p| p.id != id);
        if self.active_profile_id == id {
            self.active_profile_id.clear();
        }
        self.profiles.len() < before
    }
}

impl<'de> serde::Deserialize<'de> for LocalProxyState {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        if let Some(profiles) = value.get("profiles") {
            let active_profile_id = value
                .get("active_profile_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            let profiles: Vec<LocalProxyProfile> =
                serde_json::from_value(profiles.clone()).unwrap_or_default();
            Ok(Self {
                active_profile_id,
                profiles,
            })
        } else if value.is_object() && value.get("port").is_some() {
            let enabled = value
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let port = value
                .get("port")
                .and_then(|v| v.as_u64())
                .unwrap_or(DEFAULT_LOCAL_PROXY_PORT as u64) as u16;
            let username = value
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            let password = value
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            let id = LocalProxyProfile::new_id();
            let profile = LocalProxyProfile {
                id: id.clone(),
                name: format!("SOCKS5 :{port}"),
                port: if port == 0 {
                    DEFAULT_LOCAL_PROXY_PORT
                } else {
                    port
                },
                username,
                password,
            };
            Ok(Self {
                active_profile_id: if enabled { id } else { String::new() },
                profiles: vec![profile],
            })
        } else {
            Ok(Self::default())
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Database {
    pub main_password: String,
    #[serde(default)]
    pub main_device_id: String,
    pub dns: String,
    pub main_up_bytes: i64,
    pub main_down_bytes: i64,
    pub admin_id: String,
    pub bot_token: String,
    pub passwords: BTreeMap<String, PasswordEntry>,
    pub devices: BTreeMap<String, ClientDevice>,
    pub web_sessions: BTreeMap<String, i64>,
    pub logging_active: Option<bool>,
    #[serde(default)]
    pub local_proxy: LocalProxyState,
}

#[derive(Clone)]
pub struct DatabasePersistence {
    inner: Arc<DatabasePersistenceInner>,
}

struct DatabasePersistenceInner {
    config_dir: PathBuf,
    state: Mutex<DatabasePersistenceState>,
    notify: tokio::sync::Notify,
}

#[derive(Default)]
struct DatabasePersistenceState {
    queue: PersistenceQueue<Database>,
    last_error: Option<String>,
}

struct PersistenceQueue<T> {
    next_revision: u64,
    processed_revision: u64,
    successful_revision: u64,
    pending: Option<(u64, T)>,
    worker_running: bool,
}

impl<T> Default for PersistenceQueue<T> {
    fn default() -> Self {
        Self {
            next_revision: 0,
            processed_revision: 0,
            successful_revision: 0,
            pending: None,
            worker_running: false,
        }
    }
}

impl<T> PersistenceQueue<T> {
    fn submit(&mut self, value: T) -> (u64, bool) {
        self.next_revision = self.next_revision.saturating_add(1);
        let revision = self.next_revision;
        self.pending = Some((revision, value));
        let start_worker = !self.worker_running;
        self.worker_running = true;
        (revision, start_worker)
    }

    fn take_pending(&mut self) -> Option<(u64, T)> {
        self.pending.take()
    }

    fn stop_worker(&mut self) {
        self.worker_running = false;
    }

    fn complete(&mut self, revision: u64, successful: bool) {
        if revision >= self.processed_revision {
            self.processed_revision = revision;
        }
        if successful && revision >= self.successful_revision {
            self.successful_revision = revision;
        }
    }
}

impl DatabasePersistence {
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            inner: Arc::new(DatabasePersistenceInner {
                config_dir,
                state: Mutex::new(DatabasePersistenceState::default()),
                notify: tokio::sync::Notify::new(),
            }),
        }
    }

    pub fn submit(&self, snapshot: Database) -> u64 {
        let (revision, start_worker) = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.queue.submit(snapshot)
        };
        if start_worker {
            let worker = self.clone();
            tokio::spawn(async move {
                worker.run().await;
            });
        }
        revision
    }

    async fn run(self) {
        loop {
            let Some((revision, snapshot)) = ({
                let mut state = self
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let pending = state.queue.take_pending();
                if pending.is_none() {
                    state.queue.stop_worker();
                }
                pending
            }) else {
                self.inner.notify.notify_waiters();
                return;
            };

            let config_dir = self.inner.config_dir.clone();
            let result =
                tokio::task::spawn_blocking(move || save_database(&config_dir, &snapshot)).await;
            let error = match result {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(format!("{error:#}")),
                Err(error) => Some(format!("database save task failed: {error}")),
            };
            {
                let mut state = self
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state.queue.complete(revision, error.is_none());
                if let Some(error) = error {
                    state.last_error = Some(error);
                } else if state.queue.successful_revision >= revision {
                    state.last_error = None;
                }
            }
            self.inner.notify.notify_waiters();
        }
    }

    pub async fn wait(&self, revision: u64) -> Result<()> {
        loop {
            let notified = self.inner.notify.notified();
            let outcome = {
                let state = self
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if state.queue.successful_revision >= revision {
                    Some(Ok(()))
                } else if state.queue.processed_revision >= revision {
                    Some(Err(anyhow::anyhow!(
                        "{}",
                        state
                            .last_error
                            .as_deref()
                            .unwrap_or("database persistence failed")
                    )))
                } else {
                    None
                }
            };
            if let Some(outcome) = outcome {
                return outcome;
            }
            notified.await;
        }
    }
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

static CACHED_NOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[inline(always)]
pub fn cached_now() -> u64 {
    let cached = CACHED_NOW.load(std::sync::atomic::Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    refresh_cached_now()
}

pub fn refresh_cached_now() -> u64 {
    let ts = now() as u64;
    CACHED_NOW.store(ts, std::sync::atomic::Ordering::Relaxed);
    ts
}

pub fn random_password() -> String {
    let mut data = [0u8; PASSWORD_LEN];
    OsRng.fill_bytes(&mut data);
    data.iter()
        .map(|v| PASS_CHARS[*v as usize % PASS_CHARS.len()] as char)
        .collect()
}

pub fn random_token(size: usize) -> String {
    let mut data = vec![0u8; size];
    OsRng.fill_bytes(&mut data);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn derive_wrap_key(password: &str) -> Result<[u8; 32]> {
    if password.is_empty() {
        bail!("empty password");
    }
    let hk = Hkdf::<Sha256>::new(Some(b"CSQTT-WRAP-v1"), password.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"rtp-obfs/chacha20poly1305", &mut key)
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;
    Ok(key)
}

pub fn is_expired(entry: &PasswordEntry) -> bool {
    entry.expires_at != 0 && now() > entry.expires_at
}

pub fn get_next_ip(db: &Database) -> Option<String> {
    let mut buf = String::with_capacity(16);
    for i in 2..=250u8 {
        buf.clear();
        use std::fmt::Write;
        let _ = write!(buf, "10.66.67.{i}");
        let is_used = db.devices.values().any(|d| d.ip == buf);
        if !is_used {
            return Some(buf);
        }
    }
    None
}

pub fn resolve_session_ip(
    db: &Database,
    session_password: &str,
    device_id: &str,
) -> Option<String> {
    if !device_id.is_empty()
        && let Some(device) = db.devices.get(device_id)
    {
        return Some(device.ip.clone());
    }
    if session_password != db.main_password
        && let Some(entry) = db.passwords.get(session_password)
        && !entry.device_id.is_empty()
    {
        return db.devices.get(&entry.device_id).map(|d| d.ip.clone());
    }
    None
}

pub fn generate_key_pair() -> (String, String) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes[0] &= 248;
    bytes[31] = (bytes[31] & 127) | 64;
    let private = StaticSecret::from(bytes);
    let public = PublicKey::from(&private);
    (
        STANDARD.encode(private.to_bytes()),
        STANDARD.encode(public.as_bytes()),
    )
}

pub fn load_database(config_dir: &Path) -> Result<Database> {
    let path = config_dir.join("passwords.json");
    if !path.exists() {
        return Ok(Database::default());
    }
    let data = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let mut db: Database =
        serde_json::from_slice(&data).with_context(|| format!("parse {}", path.display()))?;
    db.bot_token.clear();
    db.admin_id.clear();
    db.local_proxy.normalize();
    Ok(db)
}

#[cfg(windows)]
fn replace_database_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let result = unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0x1 | 0x8) };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_database_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

pub fn save_database(config_dir: &Path, db: &Database) -> Result<()> {
    let _guard = DATABASE_SAVE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    fs::create_dir_all(config_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(config_dir, fs::Permissions::from_mode(0o700))?;
    }
    let path = config_dir.join("passwords.json");
    let temp = config_dir.join(".passwords.json.tmp");
    let file = fs::File::create(&temp).with_context(|| format!("create {}", temp.display()))?;
    let mut writer = std::io::BufWriter::with_capacity(8192, file);
    serde_json::to_writer_pretty(&mut writer, db)
        .with_context(|| format!("serialize {}", temp.display()))?;
    {
        use std::io::Write;
        writer
            .flush()
            .with_context(|| format!("flush {}", temp.display()))?;
    }
    let file = writer
        .into_inner()
        .map_err(std::io::IntoInnerError::into_error)
        .with_context(|| format!("finish {}", temp.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", temp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod {}", temp.display()))?;
    }
    replace_database_file(&temp, &path).with_context(|| format!("replace {}", path.display()))?;
    #[cfg(unix)]
    fs::File::open(config_dir)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync {}", config_dir.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Database, DatabasePersistence, PersistenceQueue, load_database, save_database};

    #[test]
    fn dns_survives_database_restart() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("csqtt-dns-test-{unique}"));
        let database = Database {
            dns: "9.9.9.9,149.112.112.112".to_owned(),
            ..Database::default()
        };

        save_database(&directory, &database).expect("save database");
        let restored = load_database(&directory).expect("load database");

        assert_eq!(restored.dns, database.dns);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn persistence_queue_coalesces_mutations_and_ignores_late_completion() {
        let mut queue = PersistenceQueue::default();
        let (first_revision, start_first) = queue.submit(1u64);
        assert!(start_first);
        assert_eq!(queue.take_pending(), Some((first_revision, 1)));

        let (second_revision, start_second) = queue.submit(2);
        let (third_revision, start_third) = queue.submit(3);
        assert!(!start_second);
        assert!(!start_third);
        assert_eq!(queue.take_pending(), Some((third_revision, 3)));
        assert!(second_revision > first_revision);
        assert!(third_revision > second_revision);

        queue.complete(third_revision, true);
        queue.complete(first_revision, false);
        assert_eq!(queue.processed_revision, third_revision);
        assert_eq!(queue.successful_revision, third_revision);
    }

    #[tokio::test]
    async fn database_persistence_finishes_with_latest_coalesced_snapshot() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("csqtt-persistence-test-{unique}"));
        let persistence = DatabasePersistence::new(directory.clone());
        let mut final_revision = 0;
        for mutation in 1..=512 {
            final_revision = persistence.submit(Database {
                main_up_bytes: mutation,
                ..Database::default()
            });
        }
        persistence.wait(final_revision).await.unwrap();
        let restored = load_database(&directory).unwrap();
        assert_eq!(restored.main_up_bytes, 512);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_database_mutations_persist_the_highest_revision() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("csqtt-persistence-stress-test-{unique}"));
        let persistence = DatabasePersistence::new(directory.clone());
        let database = std::sync::Arc::new(tokio::sync::Mutex::new(Database::default()));
        let final_revision = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let database = database.clone();
            let persistence = persistence.clone();
            let final_revision = final_revision.clone();
            tasks.spawn(async move {
                for _ in 0..256 {
                    let mut database = database.lock().await;
                    database.main_up_bytes = database.main_up_bytes.saturating_add(1);
                    let revision = persistence.submit(database.clone());
                    final_revision.fetch_max(revision, std::sync::atomic::Ordering::AcqRel);
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        let final_revision = final_revision.load(std::sync::atomic::Ordering::Acquire);
        persistence.wait(final_revision).await.unwrap();
        let restored = load_database(&directory).unwrap();
        assert_eq!(restored.main_up_bytes, 4096);
        let _ = std::fs::remove_dir_all(directory);
    }
}
