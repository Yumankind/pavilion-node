//! What the node keeps on disk: its key (0600), which pavilion it belongs to, the keys it pinned, and the last event seq.
//! Phase 0 keeps the key in a file readable only by this user; the Keychain / Secure Enclave and the TPM come next.
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct State {
    /// e.g. https://pavilion.example.com
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

pub fn dir() -> PathBuf {
    if let Ok(d) = std::env::var("PAVILION_NODE_HOME") { return PathBuf::from(d); }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    if cfg!(target_os = "macos") { PathBuf::from(home).join("Library/Application Support/pavilion-node") } else { PathBuf::from(home).join(".local/share/pavilion-node") }
}

fn write_private(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
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
