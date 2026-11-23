//! Account slots (docs/WORK-ROUTING.md §9, step 3; docs/MACHINES.md §6 Tier 3): your own model plans, signed in on
//! this machine by you, inside each provider's own flow, and kept here. The pavilion never sees a credential: it learns
//! only that this machine has named slots, which provider each is, and what state each is in. Plan logins stay on your
//! machine; the pavilion's vault holds API keys only.
//!
//!   pavilion-node accounts                       the slots on this machine and their states
//!   pavilion-node accounts add claude <label>    `claude setup-token` here; the token stays on this machine
//!   pavilion-node accounts add codex <label>     `codex login` here, into the slot's own private CODEX_HOME
//!   pavilion-node accounts add gemini <label>    the Gemini CLI's Google login here, into the slot's own private folder
//!   pavilion-node accounts disable|enable|remove [claude|codex|gemini] <label>
//!
//! A slot is `{ slot: "slt_…", harness: "claude-code" | "codex" | "gemini-cli", label: "work" }` plus its state: `ready`,
//! `in-use` (an agent job of the pavilion holds it), `limited` (until a time the provider stated, else a 5-minute
//! back-off), `signed-out` (the provider refused the sign-in: sign in again here) or `disabled` (you turned it off
//! here). The report carries the label you typed and nothing derived from the credential: no email, no plan, no id.
//!
//! An agent job that names a slot (`account: "slot"`, `slot: "slt_…"`, `harness`) gets a placeholder in its VM, and its
//! broker (broker.rs) adds the real credential on the way to the provider, for that provider's exact model calls only
//! (slot_auth.rs). One job per slot at a time, checked here as well as by the pavilion's lease.
//!
//! Token budgets (WORK-ROUTING §12): the pavilion may give a slot a per-turn and a per-day (UTC) budget, carried in
//! each envelope. The broker counts the tokens of every call it makes on the slot from the provider's own `usage`, as
//! the answer passes: at 80% it warns the pavilion, at a turn's budget it refuses the turn's next call and the pavilion
//! stops the job, at the day's budget the slot rests until midnight UTC. Today's count is in the slot's report
//! (`used_today`, `used_day`); the label and the state are still all the pavilion learns about the account.
//!
//! Phase 0 keeps a Claude slot's token in `accounts.json` beside the node's key, and a Codex or Gemini slot's sign-in in
//! its own folder (`slots/<id>/`, 0700) beside it, all readable only by this user, as the key is; the Keychain (and the
//! TPM on Linux and Windows) comes with the key's own move there (state.rs). Codex and Gemini refresh their tokens: that
//! happens here, on the host (slot_auth.rs), never in the VM.
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// The name the broker's egress form uses for a Claude job's slot: `http://<broker>/CLAUDE_SLOT/api.anthropic.com/v1/messages`.
/// Each provider's, and the one host its calls go to, are in slot_auth.rs `PROVIDERS`: fixed, so nothing in an envelope
/// or a VM can point a credential anywhere else.
pub const SLOT_SECRET: &str = crate::slot_auth::CLAUDE.secret;
/// A limit with no stated reset parks the slot this long; the pavilion's own back-off (WORK-ROUTING §8) decides when the
/// work tries again.
pub const UNKNOWN_RESET_MS: u64 = 5 * 60_000;
const FILE: &str = "accounts.json";
const MAX_SLOTS: usize = 12;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Slot {
    pub id: String,
    /// `claude-code`, `codex` or `gemini-cli`.
    pub harness: String,
    /// What the person typed: `work`, `personal`.
    pub label: String,
    /// A Claude slot's token. Never in a report, never sent to the pavilion, never into a VM.
    #[serde(default)]
    pub token: String,
    /// A Codex or Gemini slot's sign-in is kept in its own folder (slot_auth.rs `home`): true once it is there.
    #[serde(default)]
    pub folder: bool,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub signed_out: bool,
    #[serde(default)]
    pub limited_until: Option<u64>,
    #[serde(default)]
    pub last_used_at: Option<u64>,
    #[serde(default)]
    pub last_limited_at: Option<u64>,
    #[serde(default)]
    pub added_at: u64,
    /// Tokens counted on this slot on `tokens_day` (UTC, `2026-11-16`): its day's budget is read against this.
    #[serde(default)]
    pub tokens_today: u64,
    #[serde(default)]
    pub tokens_day: String,
}

/// A slot's token budgets for one job (WORK-ROUTING §12): per turn and per day (UTC); `None` for none.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Budget { pub turn: Option<u64>, pub day: Option<u64> }
/// Budgets by job: an agent job's envelope sets them before its sandbox (and so its broker) starts.
static BUDGETS: Mutex<Option<HashMap<String, Budget>>> = Mutex::new(None);
pub fn set_budget(job: &str, b: Budget) { BUDGETS.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).insert(job.to_string(), b); }
pub fn clear_budget(job: &str) { if let Some(m) = BUDGETS.lock().unwrap_or_else(|e| e.into_inner()).as_mut() { m.remove(job); } }
fn budget_of(job: &str) -> Budget { BUDGETS.lock().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(|m| m.get(job).copied()).unwrap_or_default() }
/// Warn the pavilion at this share of a budget.
pub const WARN_AT: f64 = 0.8;
/// `2026-11-16`: the UTC day a time falls on.
pub fn day_of(ms: u64) -> String { iso(ms)[..10].to_string() }
/// Midnight UTC after `ms`: when a day's budget starts again.
pub fn next_day(ms: u64) -> u64 { (ms / 86_400_000 + 1) * 86_400_000 }

/// Slots held by a running job here: slot id → job id.
static IN_USE: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);
/// One writer at a time for accounts.json (the broker and the CLI both change it).
static WRITE: Mutex<()> = Mutex::new(());

fn now_ms() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0) }

/// A label as a person types it: a short lower-case name.
pub fn label_ok(l: &str) -> bool {
    !l.is_empty() && l.len() <= 31 && l.as_bytes()[0].is_ascii_alphanumeric() && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}
pub fn slot_id_ok(s: &str) -> bool { s.len() > 4 && s.len() <= 28 && s.starts_with("slt_") && s[4..].bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) }
/// `claude` (what a person types) → `claude-code` (what the pavilion routes on); `codex`; `gemini` → `gemini-cli`.
pub fn harness_of(name: &str) -> Option<&'static str> {
    match name { "claude" | "claude-code" => Some("claude-code"), "codex" => Some("codex"), "gemini" | "gemini-cli" => Some("gemini-cli"), _ => None }
}
/// Whether the slot's sign-in is here: a Claude token, or a Codex or Gemini sign-in folder.
fn has_credential(s: &Slot) -> bool { if s.harness == "claude-code" { !s.token.is_empty() } else { s.folder } }

/// What a slot is now, in the pavilion's words.
pub fn state_of(s: &Slot, in_use: bool, now: u64) -> &'static str {
    if s.disabled { "disabled" } else if s.signed_out || !has_credential(s) { "signed-out" } else if s.limited_until.is_some_and(|u| u > now) { "limited" } else if in_use { "in-use" } else { "ready" }
}

/// What the pavilion may know: the slot, its harness, the label, the state and three times. Never the token.
pub fn report(slots: &[Slot], in_use: &HashMap<String, String>, now: u64) -> Value {
    let today = day_of(now);
    Value::Array(slots.iter().map(|s| json!({
        "slot": s.id, "harness": s.harness, "label": s.label, "state": state_of(s, in_use.contains_key(&s.id), now),
        "limited_until": s.limited_until.filter(|u| *u > now), "last_used_at": s.last_used_at, "last_limited_at": s.last_limited_at,
        "used_today": if s.tokens_day == today { s.tokens_today } else { 0 }, "used_day": today,
    })).collect())
}

/// Tests keep their slots in a folder of their own, never the real one (and never through the environment).
#[cfg(test)]
static TEST_DIR: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);
fn dir() -> std::path::PathBuf {
    #[cfg(test)]
    if let Some(d) = TEST_DIR.lock().unwrap_or_else(|e| e.into_inner()).clone() { return d; }
    crate::state::dir()
}
fn path() -> std::path::PathBuf { dir().join(FILE) }
/// A Codex or Gemini slot's own folder.
pub fn home_of(slot: &str) -> std::path::PathBuf { crate::slot_auth::home(&dir(), slot) }
/// The slots on this machine. Missing or damaged reads as none.
pub fn load() -> Vec<Slot> {
    std::fs::read(path()).ok().and_then(|b| serde_json::from_slice::<Vec<Slot>>(&b).ok()).unwrap_or_default()
}
fn save(slots: &[Slot]) -> Result<()> {
    std::fs::create_dir_all(dir())?;
    let bytes = Zeroizing::new(serde_json::to_vec_pretty(slots)?);
    crate::state::write_private(&path(), &bytes)
}
fn change(f: impl FnOnce(&mut Vec<Slot>) -> Result<()>) -> Result<()> {
    let _w = WRITE.lock().unwrap_or_else(|e| e.into_inner());
    let mut slots = load();
    f(&mut slots)?;
    save(&slots)
}
fn in_use() -> HashMap<String, String> { IN_USE.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_default() }

/// For the inventory and the live line.
pub fn current() -> Value { report(&load(), &in_use(), now_ms()) }

/// An agent job takes its slot: it must be here, of the harness the job runs, signed in, not turned off, not limited
/// and not held by another job.
pub fn take(slot: &str, job: &str, harness: &str) -> std::result::Result<(), String> {
    let s = load().into_iter().find(|s| s.id == slot).ok_or_else(|| format!("this machine has no account slot {slot}"))?;
    if s.harness != harness { return Err(format!("the \"{}\" slot is a {} slot, and this job runs {harness}", s.label, s.harness)); }
    let mut held = IN_USE.lock().unwrap_or_else(|e| e.into_inner());
    let map = held.get_or_insert_with(HashMap::new);
    match state_of(&s, map.contains_key(slot), now_ms()) {
        "ready" => {}
        "in-use" => return Err(format!("the \"{}\" slot is in use by another job: one agent per account at a time", s.label)),
        "limited" => return Err(format!("the \"{}\" slot is limited until {} (ms since 1970)", s.label, s.limited_until.unwrap_or(0))),
        st => return Err(format!("the \"{}\" slot is {st} on this machine", s.label)),
    }
    map.insert(slot.to_string(), job.to_string());
    Ok(())
}
pub fn release(slot: &str, job: &str) {
    let mut held = IN_USE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(m) = held.as_mut() { if m.get(slot).is_some_and(|j| j == job) { m.remove(slot); } }
}

/// What a job's broker needs to call the provider with a slot: the token, and the job's budgets with what it has used.
pub struct SlotDoor {
    pub slot: String,
    /// `claude-code`, `codex` or `gemini-cli`: which provider's calls this door carries (slot_auth.rs `allowed`).
    pub harness: String,
    /// A Claude slot's token; empty for Codex and Gemini, whose current token is read (and refreshed) from `home`.
    pub token: Zeroizing<String>,
    pub home: std::path::PathBuf,
    /// Where the calls go: the provider's own address, fixed (slot_auth.rs); tests point it at a stand-in.
    pub upstream: String,
    pub budget: Budget,
    /// Tokens this job (one turn) has used on the slot, as counted on the wire.
    pub turn_used: std::sync::atomic::AtomicU64,
    /// Which reports went already: 1 turn warned, 2 turn spent, 4 day warned, 8 day spent.
    pub told: std::sync::atomic::AtomicU8,
}
pub fn door(slot: &str) -> Option<SlotDoor> {
    let s = load().into_iter().find(|s| s.id == slot && has_credential(s))?;
    let p = crate::slot_auth::by_harness(&s.harness)?;
    Some(SlotDoor { home: home_of(&s.id), slot: s.id, harness: s.harness, token: Zeroizing::new(s.token), upstream: p.upstream.into(), budget: Budget::default(), turn_used: Default::default(), told: Default::default() })
}
/// The door for a job's broker: the slot's, with that job's budgets.
pub fn door_for(slot: &str, job: &str) -> Option<SlotDoor> { door(slot).map(|d| SlotDoor { budget: budget_of(job), ..d }) }

/// Counts a call's tokens from the provider's own `usage`, as the answer passes: SSE `data:` lines (message_start's
/// usage, then message_delta's running output count; Codex's `response.completed`; Gemini's `usageMetadata`) or one
/// JSON body. Input, output and both cache counts.
#[derive(Default)]
pub struct TokenTap { line: String, whole: Vec<u8>, seen: [u64; 4] }
impl TokenTap {
    pub fn feed(&mut self, b: &[u8]) {
        if self.whole.len() < 1 << 20 { self.whole.extend_from_slice(&b[..b.len().min((1 << 20) - self.whole.len())]); }
        self.line.push_str(&String::from_utf8_lossy(b));
        while let Some(i) = self.line.find('\n') {
            let l: String = self.line.drain(..=i).collect();
            if let Some(d) = l.trim_end().strip_prefix("data:") { if let Ok(v) = serde_json::from_str::<Value>(d.trim()) { self.read(&v); } }
        }
        if self.line.len() > 1 << 20 { self.line.clear(); }
    }
    fn read(&mut self, v: &Value) {
        // Anthropic: `usage` (or message_start's `message.usage`). Codex: `response.completed`'s `response.usage`, whose
        // input count already holds its cached tokens.
        for u in [&v["usage"], &v["message"]["usage"], &v["response"]["usage"]] {
            for (i, k) in ["input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"].iter().enumerate() {
                if let Some(n) = u[*k].as_u64() { self.seen[i] = self.seen[i].max(n); }
            }
        }
        // Gemini (Code Assist wraps the answer in `response`): `usageMetadata`, running totals per streamed chunk.
        for u in [&v["usageMetadata"], &v["response"]["usageMetadata"]] {
            if let Some(n) = u["promptTokenCount"].as_u64() { self.seen[0] = self.seen[0].max(n); }
            let out = u["candidatesTokenCount"].as_u64().unwrap_or(0) + u["thoughtsTokenCount"].as_u64().unwrap_or(0);
            if out > 0 { self.seen[1] = self.seen[1].max(out); }
        }
    }
    /// Every token the answer said it used.
    pub fn total(&mut self) -> u64 {
        if let Ok(v) = serde_json::from_slice::<Value>(&self.whole) { self.read(&v); }
        self.seen.iter().sum()
    }
}

/// Adds a call's tokens to the slot's day (a new UTC day starts at 0). Returns today's count.
pub fn add_tokens(slot: &str, n: u64) -> u64 {
    let today = day_of(now_ms());
    let mut total = n;
    let _ = change(|v| {
        if let Some(s) = v.iter_mut().find(|s| s.id == slot) {
            if s.tokens_day != today { s.tokens_day = today.clone(); s.tokens_today = 0; }
            s.tokens_today = s.tokens_today.saturating_add(n);
            total = s.tokens_today;
        }
        Ok(())
    });
    total
}
/// Today's count on a slot.
pub fn tokens_today(slot: &str) -> u64 {
    let today = day_of(now_ms());
    load().into_iter().find(|s| s.id == slot).filter(|s| s.tokens_day == today).map_or(0, |s| s.tokens_today)
}

/// What the broker does before a call on a slot: go on, or refuse because a budget is spent (and say which).
pub fn over_budget(d: &SlotDoor) -> Option<(&'static str, u64, u64)> {
    use std::sync::atomic::Ordering::Relaxed;
    if let Some(t) = d.budget.turn { let u = d.turn_used.load(Relaxed); if u >= t { return Some(("turn", u, t)); } }
    if let Some(t) = d.budget.day { let u = tokens_today(&d.slot); if u >= t { return Some(("day", u, t)); } }
    None
}
/// After a call: its tokens counted, and the reports due — `{"t":"budget", slot, scope, used, limit, warn?}` — each once
/// per job (a day's warning once per job too; the pavilion keeps the latest). A spent day rests the slot until midnight UTC.
pub fn count(d: &SlotDoor, n: u64) -> Vec<Value> {
    use std::sync::atomic::Ordering::Relaxed;
    let turn = d.turn_used.fetch_add(n, Relaxed) + n;
    let day = add_tokens(&d.slot, n);
    let mut out = vec![];
    let mut once = |bit: u8, v: Value| { if d.told.fetch_or(bit, Relaxed) & bit == 0 { out.push(v); } };
    for (scope, used, limit, warn_bit, spent_bit) in [("turn", turn, d.budget.turn, 1u8, 2u8), ("day", day, d.budget.day, 4, 8)] {
        let Some(limit) = limit else { continue };
        if used >= limit {
            if scope == "day" { limited(&d.slot, Some(next_day(now_ms()))); }
            once(spent_bit, json!({ "t": "budget", "slot": d.slot, "scope": scope, "used": used, "limit": limit }));
        } else if used as f64 >= limit as f64 * WARN_AT {
            once(warn_bit, json!({ "t": "budget", "slot": d.slot, "scope": scope, "used": used, "limit": limit, "warn": true }));
        }
    }
    out
}

/// The provider said the slot is spent: parked until the stated reset, else a short back-off.
pub fn limited(slot: &str, until_ms: Option<u64>) {
    let now = now_ms();
    let _ = change(|v| { if let Some(s) = v.iter_mut().find(|s| s.id == slot) { s.limited_until = Some(until_ms.filter(|u| *u > now).unwrap_or(now + UNKNOWN_RESET_MS)); s.last_limited_at = Some(now); } Ok(()) });
}
/// A call went through: used now, and no longer limited.
pub fn used(slot: &str) {
    let now = now_ms();
    let _ = change(|v| { if let Some(s) = v.iter_mut().find(|s| s.id == slot) { s.last_used_at = Some(now); if s.limited_until.is_some_and(|u| u <= now) { s.limited_until = None; } } Ok(()) });
}
/// The provider refused the token (401): signed out until the person signs in again here.
pub fn signed_out(slot: &str) {
    let _ = change(|v| { if let Some(s) = v.iter_mut().find(|s| s.id == slot) { s.signed_out = true; } Ok(()) });
}

fn new_id() -> String { format!("slt_{}", crate::signing::random_b64(9).to_ascii_lowercase().chars().filter(|c| c.is_ascii_alphanumeric()).take(10).collect::<String>()) }

/// Adds (or signs in again) a slot with a token already read. Separate from the CLI so tests need no `claude`.
pub fn put(harness: &str, label: &str, token: &str) -> Result<String> {
    if !label_ok(label) { bail!("a label is a short lower-case name like work or personal"); }
    let mut id = String::new();
    change(|v| {
        if let Some(s) = v.iter_mut().find(|s| s.harness == harness && s.label == label) {
            s.token = token.to_string(); s.signed_out = false; s.limited_until = None; id = s.id.clone();
        } else {
            if v.len() >= MAX_SLOTS { bail!("at most {MAX_SLOTS} slots on one machine"); }
            id = new_id();
            v.push(Slot { id: id.clone(), harness: harness.into(), label: label.into(), token: token.into(), added_at: now_ms(), ..Default::default() });
        }
        Ok(())
    })?;
    Ok(id)
}

/// Keeps a Codex or Gemini sign-in made in `fresh` (a private folder the provider's CLI just wrote) as the slot
/// `label`: it replaces the slot's folder (the old one scrubbed), and the slot is signed in again.
pub fn put_folder(harness: &str, label: &str, fresh: &std::path::Path) -> Result<String> {
    if !label_ok(label) { bail!("a label is a short lower-case name like work or personal"); }
    crate::slot_auth::check_signed_in(harness, fresh)?;
    let mut id = String::new();
    change(|v| {
        if let Some(s) = v.iter_mut().find(|s| s.harness == harness && s.label == label) {
            id = s.id.clone();
        } else {
            if v.len() >= MAX_SLOTS { bail!("at most {MAX_SLOTS} slots on one machine"); }
            id = new_id();
            v.push(Slot { id: id.clone(), harness: harness.into(), label: label.into(), added_at: now_ms(), ..Default::default() });
        }
        let home = home_of(&id);
        if home.exists() { crate::slot_auth::scrub(&home); }
        if let Some(parent) = home.parent() { crate::slot_auth::make_private_dir(parent)?; }
        std::fs::rename(fresh, &home)?;
        let s = v.iter_mut().find(|s| s.id == id).expect("just found or added");
        s.folder = true; s.signed_out = false; s.limited_until = None;
        Ok(())
    })?;
    Ok(id)
}

/// The plain line wherever accounts are added (21 Nov 2026, the owner's words).
pub const TERMS_LINE: &str = "Use your own accounts, within each plan's terms.";

/// Runs the provider's own sign-in on this machine into a fresh private folder, and keeps it as a slot.
async fn sign_in_folder(harness: &str, label: &str) -> Result<String> {
    let fresh = dir().join("slots").join(format!(".new-{}", crate::signing::random_b64(9).replace(['-', '_'], "x")));
    crate::slot_auth::make_private_dir(&fresh)?;
    struct Gone(std::path::PathBuf);
    impl Drop for Gone { fn drop(&mut self) { if self.0.exists() { crate::slot_auth::scrub(&self.0); } } }
    let guard = Gone(fresh.clone());
    let status = match harness {
        "codex" => {
            // Codex keeps its sign-in in a file here, never the system keyring, so the node can refresh it.
            std::fs::write(fresh.join("config.toml"), "cli_auth_credentials_store = \"file\"\n")?;
            tokio::process::Command::new("codex").arg("login").env("CODEX_HOME", &fresh)
                .stdin(std::process::Stdio::inherit()).stdout(std::process::Stdio::inherit()).stderr(std::process::Stdio::inherit())
                .status().await.map_err(|e| anyhow!("couldn't run `codex login` ({e}). Install the Codex CLI on this machine first (npm install -g @openai/codex)"))?
        }
        _ => {
            let (id, secret) = crate::slot_auth::find_gemini_client()?;
            crate::state::write_private(&crate::slot_auth::gemini_client(&fresh), serde_json::to_vec(&json!({ "client_id": id, "client_secret": secret }))?.as_slice())?;
            // A Google account's first run sets it up for Gemini (`onboardUser`). That happens here, with you, and never
            // inside a job: the job's broker refuses it (slot_auth.rs, decided 21 Nov 2026). Asking one question makes
            // the CLI finish it before you leave.
            eprintln!("  The Gemini CLI opens with \"Login with Google\": sign in in your browser, ask it one short question so it\n  finishes setting up your account, then type /quit to come back here.\n");
            tokio::process::Command::new("gemini").env("GEMINI_CLI_HOME", &fresh).env("GOOGLE_GENAI_USE_GCA", "true")
                .stdin(std::process::Stdio::inherit()).stdout(std::process::Stdio::inherit()).stderr(std::process::Stdio::inherit())
                .status().await.map_err(|e| anyhow!("couldn't run the Gemini CLI ({e}). Install it on this machine first (npm install -g @google/gemini-cli)"))?
        }
    };
    if !status.success() && !crate::slot_auth::signed_in(harness, &fresh) { bail!("the sign-in stopped ({status}); nothing was kept"); }
    let id = put_folder(harness, label, &fresh)?;
    drop(guard);
    Ok(id)
}

pub async fn cli(args: &[String]) -> Result<()> {
    let label_arg = |i: usize| args.get(i).map(|s| s.trim().to_lowercase()).filter(|l| label_ok(l)).ok_or_else(|| anyhow!("name the slot: a short lower-case label like work"));
    match args.first().map(String::as_str) {
        None | Some("list") => {
            let slots = load();
            if slots.is_empty() { println!("No account slots on this machine. Add one: pavilion-node accounts add claude|codex|gemini <label>\n{TERMS_LINE}"); }
            let now = now_ms();
            for s in &slots {
                let st = state_of(s, in_use().contains_key(&s.id), now);
                println!("{:<12} {:<12} {:<11} {}", s.label, s.harness, st, s.limited_until.filter(|u| *u > now).map(|u| format!("until {} UTC", iso(u))).unwrap_or_default());
            }
            Ok(())
        }
        Some("add") => {
            let harness = args.get(1).and_then(|h| harness_of(h)).ok_or_else(|| anyhow!("usage: pavilion-node accounts add claude|codex|gemini <label>"))?;
            let label = label_arg(2)?;
            let p = crate::slot_auth::by_harness(harness).expect("a known harness");
            eprintln!("\n  Your own {} plan, signed in here as the \"{label}\" slot. The sign-in stays on this machine:", p.name);
            eprintln!("  the pavilion learns the label, the provider and whether the slot is ready, in use, limited or signed out —");
            eprintln!("  nothing else. Plan logins stay on your machine; the pavilion's vault holds API keys only.");
            eprintln!("  It is used only for work you ask for or approve yourself (WORK-ROUTING §9).");
            eprintln!("  {TERMS_LINE}\n");
            let id = if harness == "claude-code" {
                let token = crate::onboard::run_claude_saying(crate::onboard::SLOT_PLACEHOLDER).await?;
                let id = put(harness, &label, &token)?;
                drop(token);
                id
            } else {
                sign_in_folder(harness, &label).await?
            };
            eprintln!("Signed in: {} slot \"{label}\" ({id}). A running node reports it within a few seconds.", p.name);
            Ok(())
        }
        Some(op @ ("disable" | "enable" | "remove")) => {
            // `<label>`, or `<provider> <label>` when the same label is on two providers.
            let (only, label) = match (args.get(1).and_then(|h| harness_of(h)), args.get(2)) { (Some(h), Some(_)) => (Some(h), label_arg(2)?), _ => (None, label_arg(1)?) };
            let hit = |s: &Slot| s.label == label && only.map_or(true, |h| s.harness == h);
            let n = load().iter().filter(|s| hit(s)).count();
            if n == 0 { bail!("no slot called {label} on this machine"); }
            if n > 1 { bail!("{label} is a slot on {n} providers here: name one, e.g. pavilion-node accounts {op} codex {label}"); }
            if op == "remove" {
                let mut gone = vec![];
                change(|v| { v.retain(|s| if hit(s) { gone.push(s.id.clone()); false } else { true }); Ok(()) })?;
                for id in gone { let h = home_of(&id); if h.exists() { crate::slot_auth::scrub(&h); } }
                eprintln!("Slot \"{label}\" removed, and its sign-in with it.");
            } else {
                change(|v| { for s in v.iter_mut().filter(|s| hit(s)) { s.disabled = op == "disable"; } Ok(()) })?;
                eprintln!("Slot \"{label}\" {}.", if op == "disable" { "disabled: nothing new starts on it (a job already running finishes)" } else { "enabled" });
            }
            Ok(())
        }
        Some(_) => bail!("usage: pavilion-node accounts [list] | add claude|codex|gemini <label> | disable|enable|remove [claude|codex|gemini] <label>"),
    }
}

/// ISO 8601 date and time in UTC, to the minute.
pub(crate) fn iso(ms: u64) -> String {
    let s = ms / 1000; let (days, rem) = (s / 86_400, s % 86_400);
    // Civil from days (Howard Hinnant), for 1970 onwards.
    let z = days as i64 + 719_468; let era = z.div_euclid(146_097); let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153; let d = doy - (153 * mp + 2) / 5 + 1; let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}", rem / 3600, rem % 3600 / 60)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    /// Tests that touch accounts.json share one folder of their own and take turns.
    pub static HOME: Mutex<()> = Mutex::new(());
    pub fn with_home<T>(f: impl FnOnce() -> T) -> T {
        let _g = HOME.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("pavilion-accounts-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        *TEST_DIR.lock().unwrap() = Some(dir.clone());
        *IN_USE.lock().unwrap() = None;
        let r = f();
        *TEST_DIR.lock().unwrap() = None;
        let _ = std::fs::remove_dir_all(&dir);
        r
    }
    /// Made up here, never real.
    pub const FAKE: &str = "sk-ant-oat01-fake-slot-token-for-tests-only-0000000000000000";

    #[test]
    fn a_report_names_slots_and_states_and_never_the_token() {
        with_home(|| {
            let work = put("claude-code", "work", FAKE).unwrap();
            let personal = put("claude-code", "personal", FAKE).unwrap();
            assert!(slot_id_ok(&work) && work != personal);
            let r = current();
            let text = r.to_string();
            assert!(!text.contains("sk-ant") && !text.contains("token"), "{text}");
            assert_eq!(r.as_array().unwrap().len(), 2);
            assert_eq!(r[0]["label"], "work"); assert_eq!(r[0]["state"], "ready"); assert_eq!(r[0]["harness"], "claude-code");
            // Signing in again keeps the slot: the same id.
            assert_eq!(put("claude-code", "work", FAKE).unwrap(), work);
            assert!(put("claude-code", "Bad Label", FAKE).is_err());
            // The file is the owner's alone.
            #[cfg(unix)]
            { use std::os::unix::fs::PermissionsExt; assert_eq!(std::fs::metadata(path()).unwrap().permissions().mode() & 0o777, 0o600); }
        });
    }

    #[test]
    fn one_job_per_slot_and_states_follow_what_the_provider_said() {
        with_home(|| {
            let id = put("claude-code", "work", FAKE).unwrap();
            assert!(take(&id, "job_a", "codex").unwrap_err().contains("claude-code slot"), "a job runs on a slot of its own harness only");
            take(&id, "job_a", "claude-code").unwrap();
            assert_eq!(current()[0]["state"], "in-use");
            assert!(take(&id, "job_b", "claude-code").unwrap_err().contains("in use"), "a second agent never starts on a slot in use");
            release(&id, "job_b"); // not its holder: nothing changes
            assert_eq!(current()[0]["state"], "in-use");
            release(&id, "job_a");
            assert_eq!(current()[0]["state"], "ready");
            let until = now_ms() + 3_600_000;
            limited(&id, Some(until));
            let r = current();
            assert_eq!((r[0]["state"].as_str(), r[0]["limited_until"].as_u64()), (Some("limited"), Some(until)));
            assert!(r[0]["last_limited_at"].as_u64().is_some());
            assert!(take(&id, "job_c", "claude-code").unwrap_err().contains("limited"));
            limited(&id, None);
            let u = current()[0]["limited_until"].as_u64().unwrap();
            assert!(u > now_ms() && u <= now_ms() + UNKNOWN_RESET_MS, "no stated reset: a short back-off");
            change(|v| { v[0].limited_until = Some(1); Ok(()) }).unwrap();
            used(&id);
            assert_eq!(current()[0]["state"], "ready");
            assert!(current()[0]["last_used_at"].as_u64().is_some());
            signed_out(&id);
            assert_eq!(current()[0]["state"], "signed-out");
            assert!(take(&id, "job_d", "claude-code").unwrap_err().contains("signed-out"));
            put("claude-code", "work", FAKE).unwrap();
            assert_eq!(current()[0]["state"], "ready", "signing in again clears it");
            change(|v| { v[0].disabled = true; Ok(()) }).unwrap();
            assert_eq!(current()[0]["state"], "disabled");
            assert!(door(&id).is_some_and(|d| d.token.as_str() == FAKE && d.upstream == crate::slot_auth::CLAUDE.upstream && d.harness == "claude-code"));
            assert!(door("slt_nothere").is_none());
        });
    }

    /// WORK-ROUTING §12: tokens counted from the provider's own usage, a warning at 80%, a spent turn, a spent day.
    #[test]
    fn token_budgets() {
        with_home(|| {
            // Streamed: message_start's usage, then message_delta's running output count; or one JSON body.
            let mut t = TokenTap::default();
            t.feed(b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":100,\"cache_read_input_tokens\":900,\"output_tokens\":1}}}\n\nevent: message_delta\nda");
            t.feed(b"ta: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":250}}\n\n");
            assert_eq!(t.total(), 1250);
            let mut t = TokenTap::default();
            t.feed(br#"{"type":"message","usage":{"input_tokens":40,"output_tokens":2,"cache_creation_input_tokens":8}}"#);
            assert_eq!(t.total(), 50);

            let id = put("claude-code", "work", FAKE).unwrap();
            let d = door_for(&id, "job_x").unwrap();
            assert_eq!(d.budget, Budget::default(), "no budget unless the envelope gave one");
            set_budget("job_x", Budget { turn: Some(1000), day: Some(5000) });
            let d = door_for(&id, "job_x").unwrap();
            assert!(over_budget(&d).is_none());
            assert!(count(&d, 500).is_empty());
            let warn = count(&d, 350);
            assert_eq!(warn, vec![json!({ "t": "budget", "slot": id, "scope": "turn", "used": 850, "limit": 1000, "warn": true })]);
            assert!(count(&d, 10).is_empty(), "a warning goes once");
            let spent = count(&d, 200);
            assert_eq!(spent[0]["scope"], "turn"); assert_eq!(spent[0]["used"], 1060); assert!(spent[0].get("warn").is_none());
            assert_eq!(over_budget(&d), Some(("turn", 1060, 1000)));
            assert_eq!(current()[0]["used_today"], 1060);
            // Another job on the same slot: a new turn, the same day. The day's budget spent rests the slot until midnight UTC.
            set_budget("job_y", Budget { turn: None, day: Some(5000) });
            let d2 = door_for(&id, "job_y").unwrap();
            assert!(over_budget(&d2).is_none());
            let r = count(&d2, 3000);
            assert_eq!((r[0]["scope"].as_str(), r[0]["warn"].as_bool()), (Some("day"), Some(true)));
            let r = count(&d2, 1000);
            assert_eq!((r[0]["scope"].as_str(), r[0]["used"].as_u64()), (Some("day"), Some(5060)));
            assert_eq!(over_budget(&d2).map(|o| o.0), Some("day"));
            let now = current();
            assert_eq!(now[0]["state"], "limited");
            assert_eq!(now[0]["limited_until"].as_u64(), Some(next_day(now_ms())));
            assert!(!now.to_string().contains("sk-ant"));
            clear_budget("job_x"); clear_budget("job_y");
            assert_eq!(door_for(&id, "job_x").unwrap().budget, Budget::default());
            // A new day starts at nothing.
            change(|v| { v[0].tokens_day = "2000-01-01".into(); Ok(()) }).unwrap();
            assert_eq!(tokens_today(&id), 0);
            assert_eq!(add_tokens(&id, 7), 7);
        });
    }

    /// A Codex or Gemini slot: its sign-in in its own private folder, reported like any slot, scrubbed when replaced.
    #[test]
    fn folder_slots_keep_their_sign_in_in_their_own_folder() {
        with_home(|| {
            let fresh = dir().join("fresh");
            crate::slot_auth::make_private_dir(&fresh).unwrap();
            assert!(put_folder("codex", "personal", &fresh).unwrap_err().to_string().contains("auth.json"), "nothing signed in: nothing kept");
            std::fs::write(fresh.join("auth.json"), r#"{"OPENAI_API_KEY":"sk-proj-x","tokens":null}"#).unwrap();
            assert!(put_folder("codex", "personal", &fresh).unwrap_err().to_string().contains("API-key login"), "an API key belongs in the vault");
            std::fs::write(fresh.join("auth.json"), r#"{"OPENAI_API_KEY":null,"tokens":{"id_token":"a.b.c","access_token":"x.y.z","refresh_token":"rt-fake","account_id":"acc-fake"}}"#).unwrap();
            let id = put_folder("codex", "personal", &fresh).unwrap();
            assert!(!fresh.exists() && crate::slot_auth::codex_auth(&home_of(&id)).is_file());
            #[cfg(unix)]
            { use std::os::unix::fs::PermissionsExt; assert_eq!(std::fs::metadata(home_of(&id)).unwrap().permissions().mode() & 0o777, 0o700); }
            let r = current();
            assert_eq!((r[0]["harness"].as_str(), r[0]["state"].as_str()), (Some("codex"), Some("ready")));
            assert!(!r.to_string().contains("rt-fake") && !r.to_string().contains("acc-fake"));
            let d = door(&id).unwrap();
            assert_eq!((d.harness.as_str(), d.upstream.as_str(), d.token.is_empty()), ("codex", "https://chatgpt.com", true));
            // Signing in again replaces the folder (the old one scrubbed) and keeps the slot's id.
            signed_out(&id);
            assert_eq!(current()[0]["state"], "signed-out");
            crate::slot_auth::make_private_dir(&fresh).unwrap();
            std::fs::write(fresh.join("auth.json"), r#"{"tokens":{"access_token":"x.y.z","refresh_token":"rt-two"}}"#).unwrap();
            assert_eq!(put_folder("codex", "personal", &fresh).unwrap(), id);
            assert_eq!(current()[0]["state"], "ready");
            assert!(std::fs::read_to_string(crate::slot_auth::codex_auth(&home_of(&id))).unwrap().contains("rt-two"));
            // A Gemini slot needs its Google sign-in and the CLI's client beside it.
            crate::slot_auth::make_private_dir(&fresh.join(".gemini")).unwrap();
            std::fs::write(fresh.join(".gemini/oauth_creds.json"), r#"{"access_token":"ya29.fake","refresh_token":"1//fake","expiry_date":1}"#).unwrap();
            assert!(put_folder("gemini-cli", "personal", &fresh).unwrap_err().to_string().contains("client"), "without the CLI's client it could never refresh");
            std::fs::write(crate::slot_auth::gemini_client(&fresh), r#"{"client_id":"fake.apps.googleusercontent.com","client_secret":"fake"}"#).unwrap();
            let g = put_folder("gemini-cli", "personal", &fresh).unwrap();
            assert_ne!(g, id, "the same label on another provider is another slot");
            assert_eq!(current().as_array().unwrap().len(), 2);
            assert_eq!((current()[1]["harness"].as_str(), current()[1]["state"].as_str()), (Some("gemini-cli"), Some("ready")));
            assert_eq!(harness_of("gemini"), Some("gemini-cli")); assert_eq!(harness_of("codex"), Some("codex")); assert_eq!(harness_of("gpt"), None);
        });
    }

    #[test]
    fn dates_are_iso_8601() {
        assert_eq!(iso(0), "1970-01-01T00:00");
        assert_eq!(iso(1_763_208_000_000), "2025-11-15T12:00");
    }
}
