//! What the node keeps on disk: its key (0600), which pavilion it belongs to, the keys it pinned, and the last event seq.
//! Phase 0 keeps the key in a file readable only by this user; the Keychain / Secure Enclave and the TPM come next.
//! On Windows the folder is %LOCALAPPDATA%\pavilion-node, and "only this user" is an ACL (icacls, platform/windows.rs).
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct State {
    /// e.g. https://pavilion-gate.powerhouse.workers.dev
    pub gate: String,
    pub pavilion: String,
    pub machine: String,
    pub name: String,
    /// The pavilion's job-signing key, pinned when joining.
    pub pavilion_key: String,
    /// The owner who confirmed this machine, pinned (end-to-end commands later).
    pub owner_key_id: String,
    pub owner_alg: String,
    pub owner_public_key: String,
    pub last_seq: u64,
}

/// The owner's stop switch (`pavilion-node pause`): while this file exists the node takes no work at all. It is the
/// owner's at the machine; nothing the pavilion sends can remove it (security audit 23 Nov 2026 #4).
pub fn pause_file() -> PathBuf { dir().join("paused") }
pub fn paused() -> bool { pause_file().exists() }

#[cfg_attr(windows, allow(unreachable_code))]
pub fn dir() -> PathBuf {
    if let Ok(d) = std::env::var("PAVILION_NODE_HOME") { return PathBuf::from(d); }
    #[cfg(windows)]
    return crate::platform::windows::state_dir();
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    if cfg!(target_os = "macos") { PathBuf::from(home).join("Library/Application Support/pavilion-node") } else { PathBuf::from(home).join(".local/share/pavilion-node") }
}

#[cfg(unix)]
pub(crate) fn write_private(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Windows: the folder is made owner-only first, so the file is born owner-only too; then the file itself.
#[cfg(windows)]
pub(crate) fn write_private(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().ok_or_else(|| anyhow!("{} has no folder", path.display()))?;
    std::fs::create_dir_all(dir)?;
    crate::platform::windows::private(dir, true)?;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new().create(true).truncate(true).write(true).open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    crate::platform::windows::private(&tmp, false)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn new_key() -> Result<SigningKey> {
    std::fs::create_dir_all(dir())?;
    let path = dir().join("node.key");
    if path.exists() { return Err(anyhow!("{} already exists: this machine has a key. Remove it to join again.", path.display())); }
    let k = SigningKey::generate(&mut rand::thread_rng());
    write_private(&path, &k.to_bytes())?;
    Ok(k)
}

pub fn key() -> Result<SigningKey> {
    let path = dir().join("node.key");
    let b = std::fs::read(&path).with_context(|| format!("no key at {}; run `pavilion-node join` first", path.display()))?;
    let b: [u8; 32] = b.as_slice().try_into().map_err(|_| anyhow!("{} is damaged", path.display()))?;
    Ok(SigningKey::from_bytes(&b))
}

pub fn load() -> Result<State> {
    let p = dir().join("state.json");
    Ok(serde_json::from_slice(&std::fs::read(&p).with_context(|| format!("no state at {}; run `pavilion-node join` first", p.display()))?)?)
}
pub fn save(s: &State) -> Result<()> { write_private(&dir().join("state.json"), &serde_json::to_vec_pretty(s)?) }

/// The node's settings (config.json): `vm_storage`, `model_storage`. Missing or damaged reads as empty.
pub fn config() -> serde_json::Value {
    std::fs::read(dir().join("config.json")).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()).filter(|v| v.is_object()).unwrap_or_else(|| serde_json::json!({}))
}
/// Sets one setting, keeping the others. Written owner-only like the key: it names where VM disks live and which disk
/// image the node attaches.
pub fn set_config(key: &str, value: serde_json::Value) -> Result<()> {
    std::fs::create_dir_all(dir())?;
    let mut c = config();
    c[key] = value;
    write_private(&dir().join("config.json"), &serde_json::to_vec_pretty(&c)?)
}

/// One `pavilion-node run` per computer: two would hold the same machine's link and take turns being kicked off it
/// (the service started at login, and someone typing `pavilion-node run` too). The lock is an flock on `run.lock`,
/// held for the life of the process and let go by the kernel when it ends, however it ends. Ok(false) when another
/// run already holds it.
#[cfg(unix)]
pub fn run_lock() -> Result<bool> {
    use std::io::{Seek, Write};
    use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
    std::fs::create_dir_all(dir())?;
    let mut f = std::fs::OpenOptions::new().create(true).read(true).write(true).mode(0o600).open(dir().join("run.lock"))?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 { return Ok(false); }
    f.set_len(0)?;
    f.rewind()?;
    write!(f, "{}", std::process::id())?;
    Box::leak(Box::new(f));
    Ok(true)
}
#[cfg(windows)]
pub fn run_lock() -> Result<bool> { Ok(true) }

/// The pid of the `pavilion-node run` holding this computer's lock, if one does.
#[cfg(unix)]
pub fn run_holder() -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    let f = std::fs::File::open(dir().join("run.lock")).ok()?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 { return None; }
    std::fs::read_to_string(dir().join("run.lock")).ok()?.trim().parse().ok()
}
#[cfg(windows)]
pub fn run_holder() -> Option<u32> { None }
