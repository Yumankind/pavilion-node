//! Device actions on this computer (docs/DEVICES.md §6, docs/DEVICES-PROTOCOL.md §4): an agent asks the Gate for a
//! photo, a Bluetooth reading or the services on the network; the Gate signs one action for this machine; the node
//!
//!   1. receives it on the node socket (`{type: "device_action", payload, sig}`), or finds it when it polls
//!      `GET /node/devices/actions?open=1`;
//!   2. checks it: the pavilion's signature over the exact string, this machine, not expired, never seen before
//!      (remembered on disk), and the local ceiling's `devices:` section (ceiling.rs);
//!   3. asks the person **at this computer** (a window; for captures and acts, Touch ID or the login password after
//!      Allow), unless the ceiling lets this computer allow looks and reads by itself;
//!   4. signs the answer with the machine key, does the one action, shows captures for 3 seconds with Cancel and Send
//!      now, and uploads the result signed with the machine key, or reports why it failed;
//!   5. writes a line to its own history (`pavilion-node devices history`).
//!
//! Hardware is touched only here, on the host, outside any sandbox. Agents get typed results, never a device.
pub mod caps;
pub mod envelope;
pub mod standards;
#[cfg(target_os = "macos")]
pub mod helper;
#[cfg(windows)]
pub mod windows;

use crate::ceiling;
use crate::signing::{b64, sha256, signed_headers};
use caps::{Lent, Op, Output, Prep};
use ed25519_dalek::SigningKey;
use envelope::Envelope;
use serde_json::{json, Value};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
const POLL: Duration = Duration::from_secs(30);
const PREVIEW_SECONDS: u32 = 3;

pub fn now() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() }

/* ---------- what the person at this computer is shown ---------- */

/// The question, in the Gate's words (never the agent's), with the agent's reason labelled as theirs.
#[derive(Clone, Debug, PartialEq)]
pub struct Ask {
    pub text: String,
    pub reason: Option<String>,
    pub agent: String,
    /// The adopted device's name, quoted.
    pub device: Option<String>,
    /// What exactly will happen, written here from the typed action.
    pub detail: String,
    /// Allow also needs Touch ID or the login password (Windows Hello on Windows).
    pub presence: bool,
    pub expires_at: u64,
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Decision { Allow, Deny, NoAnswer }

/// A capture shown for 3 seconds before it's sent.
#[derive(Clone, Debug, PartialEq)]
pub struct Preview { pub kind: &'static str, pub path: Option<PathBuf>, pub text: Option<String>, pub seconds: u32 }

/// Everything the handler needs from outside: the Gate, the person, the hardware. Real on a computer; a stand-in in tests.
pub trait Side: Send + Sync {
    /// A signed request to the Gate: (status, body).
    fn gate<'a>(&'a self, method: &'a str, path: &'a str, ctype: &'a str, body: Vec<u8>, header: Option<(&'static str, String)>) -> BoxFut<'a, Result<(u16, Vec<u8>), String>>;
    fn ask<'a>(&'a self, a: &'a Ask) -> BoxFut<'a, Result<Decision, String>>;
    /// true: send it.
    fn preview<'a>(&'a self, p: &'a Preview) -> BoxFut<'a, Result<bool, String>>;
    /// Before the person is asked: what the device itself says (standards::prepare). The real one by default.
    fn prepare<'a>(&'a self, op: &'a Op, lent: &'a Lent) -> BoxFut<'a, Result<Prep, String>> {
        Box::pin(async move { match op { Op::Std(s) => standards::prepare(s, lent).await, _ => Ok(Prep::default()) } })
    }
    fn run<'a>(&'a self, op: &'a Op, lent: &'a Lent) -> BoxFut<'a, Result<Output, String>>;
}

/* ---------- remembered on disk: actions seen, and the history ---------- */

pub fn dir() -> PathBuf { crate::state::dir().join("devices") }

/// Action ids already seen, with their expiry, so an action is done at most once even across restarts.
pub struct Seen { path: PathBuf, lock: std::sync::Mutex<()> }
impl Seen {
    pub fn at(dir: &Path) -> Seen { Seen { path: dir.join("seen.json"), lock: std::sync::Mutex::new(()) } }
    fn read(&self) -> serde_json::Map<String, Value> { std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).and_then(|v| v.as_object().cloned()).unwrap_or_default() }
    pub fn contains(&self, act: &str) -> bool { let _g = self.lock.lock().unwrap(); self.read().contains_key(act) }
    /// Marks `act` seen. false if it already was. Entries are kept a day past their expiry.
    pub fn first_time(&self, act: &str, expires_at: u64, now: u64) -> Result<bool, String> {
        let _g = self.lock.lock().unwrap();
        let mut m = self.read();
        if m.contains_key(act) { return Ok(false); }
        m.retain(|_, v| v.as_u64().unwrap_or(0) + 86_400 > now);
        m.insert(act.to_string(), json!(expires_at));
        write_private(&self.path, &serde_json::to_vec(&m).unwrap()).map_err(|e| format!("can't remember the action: {e}"))?;
        Ok(true)
    }
    pub fn len(&self) -> usize { self.read().len() }
}

/// The history the person can read: one JSON line per action, newest last.
pub struct History { path: PathBuf }
impl History {
    pub fn at(dir: &Path) -> History { History { path: dir.join("history.jsonl") } }
    pub fn add(&self, entry: Value) {
        use std::io::Write;
        let _ = std::fs::create_dir_all(self.path.parent().unwrap());
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.path) { let _ = writeln!(f, "{entry}"); }
        // Keep the last 1000.
        if std::fs::metadata(&self.path).map_or(0, |m| m.len()) > 2 * 1024 * 1024 {
            let lines = self.read(1000);
            let _ = write_private(&self.path, lines.iter().map(|l| format!("{l}\n")).collect::<String>().as_bytes());
        }
    }
    pub fn read(&self, n: usize) -> Vec<Value> {
        let text = std::fs::read_to_string(&self.path).unwrap_or_default();
        let all: Vec<Value> = text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
        all[all.len().saturating_sub(n)..].to_vec()
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::create_dir_all(path.parent().unwrap())?;
    let tmp = path.with_extension("tmp");
    #[cfg(unix)]
    { use std::os::unix::fs::OpenOptionsExt; use std::io::Write; let mut f = std::fs::OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(&tmp)?; f.write_all(bytes)?; }
    #[cfg(not(unix))]
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/* ---------- one action, start to end ---------- */

pub struct Ctx {
    pub pavilion: String,
    pub machine: String,
    pub pavilion_key: String,
    pub key: SigningKey,
    pub ceiling: ceiling::Devices,
    pub minute: u16,
    pub now: u64,
    pub seen: Arc<Seen>,
    pub history: Arc<History>,
    /// The node's devices folder (previews are written there while they're shown).
    pub dir: PathBuf,
    /// The Gate's origin (pavilion URLs a Cast device may play).
    pub gate: String,
}

fn route(pav: &str, rest: &str) -> String { format!("/p/{pav}/node/devices{rest}") }

/// What happened, for the history and the tests.
#[derive(Debug, PartialEq)]
pub enum Outcome { Ignored(String), Refused(String), Denied, NoAnswer, Canceled, Failed(String), Sent { bytes: usize, ctype: String } }

/// What will happen, in this computer's own words (shown under the Gate's text).
pub fn describe(op: &Op) -> String {
    match op {
        Op::CameraSnapshot { camera, max_px } => format!("One photo from the {camera} camera, at most {max_px} px. You'll see it for 3 seconds before it's sent."),
        Op::CameraClip { camera, seconds } => format!("A {seconds}-second video from the {camera} camera, no sound. You'll see it before it's sent."),
        Op::RecordAudio { seconds } => format!("{seconds} seconds from the microphone. You'll hear it before it's sent."),
        Op::ScreenCapture => "One screenshot of this screen. You'll see it for 3 seconds before it's sent.".into(),
        Op::PlayAudio { text: Some(t), .. } => format!("Speak this aloud: “{}”", t.chars().take(160).collect::<String>()),
        Op::PlayAudio { .. } => "Play a sound file from the pavilion on this computer's speaker.".into(),
        Op::Location { accuracy_m } => format!("This computer's location, rounded to about {accuracy_m} m. You'll see it before it's sent."),
        Op::BleScan { seconds, .. } => format!("List the Bluetooth devices nearby for {seconds} s (their addresses are hidden)."),
        Op::BleRead { characteristic, .. } => format!("Read one value ({characteristic}) from the device."),
        Op::BleWrite { characteristic, bytes, .. } => format!("Write {} byte(s) to {characteristic} on the device: {}", bytes.len(), bytes.iter().take(32).map(|b| format!("{b:02x}")).collect::<String>()),
        Op::BleSubscribe { characteristic, seconds, .. } => format!("Read {characteristic} from the device for {seconds} s."),
        Op::LanDiscover { types, seconds } => format!("List the services on this network for {seconds} s ({} kinds).", types.len()),
        Op::LanRequest { method, path, .. } => format!("{method} {path} on the device."),
        Op::Std(s) => s.describe(),
    }
}

fn preview_of(op: &Op, out: &Output, file: Option<PathBuf>) -> Option<Preview> {
    if !op.is_capture() { return None; }
    let kind = match op { Op::CameraSnapshot { .. } | Op::ScreenCapture | Op::Std(_) => "image", Op::CameraClip { .. } => "video", Op::RecordAudio { .. } => "audio", _ => "text" };
    let text = match out { Output::Json(v) => Some(format!("Location: {}, {} (± {} m)", v["lat"], v["lon"], v["accuracy_m"])), _ => None };
    Some(Preview { kind, path: file, text, seconds: PREVIEW_SECONDS })
}

/// Checks, asks, does and reports one action. Never panics on what the Gate sent; every refusal says why.
pub async fn handle(side: &dyn Side, ctx: &Ctx, payload: &str, sig: &str) -> Outcome {
    let fail = |act: String, status: &'static str, why: String| async move {
        let body = serde_json::to_vec(&json!({ "status": status, "error": why })).unwrap();
        let _ = side.gate("POST", &route(&ctx.pavilion, &format!("/actions/{act}/fail")), "application/json", body, None).await;
    };
    let env: Envelope = match envelope::verify(&ctx.pavilion_key, &ctx.pavilion, &ctx.machine, payload, sig, ctx.now) {
        Ok(e) => e,
        Err(r) => {
            eprintln!("devices: refused an action: {}", r.why);
            ctx.history.add(json!({ "at": ctx.now, "act": r.act, "status": "refused", "error": r.why }));
            // Tell the Gate only about actions that were really ours and not yet seen (never twice).
            if let Some(act) = r.act.clone().filter(|_| r.report) {
                if ctx.seen.first_time(&act, ctx.now + 600, ctx.now).unwrap_or(false) { fail(act, "failed", r.why.clone()).await; }
            }
            return Outcome::Refused(r.why);
        }
    };
    let act = env.action.clone();
    // Single use: from here on this action id is spent, whatever happens.
    match ctx.seen.first_time(&act, env.expires_at, ctx.now) {
        Ok(true) => {}
        Ok(false) => return Outcome::Ignored("already seen".into()),
        Err(e) => return Outcome::Ignored(e),
    }
    let base = json!({ "at": ctx.now, "act": act, "agent": env.agent, "agentName": env.agent_name, "tool": env.tool, "text": env.text, "reason": env.reason, "external": env.external.as_ref().map(|e| e.name.clone()) });
    let log = |extra: Value| { let mut b = base.clone(); if let (Some(o), Some(e)) = (b.as_object_mut(), extra.as_object()) { o.extend(e.clone()); } ctx.history.add(b); };

    if let Err(why) = ctx.ceiling.allows(&env.tool, &env.agent, ctx.minute) {
        log(json!({ "status": "refused", "error": why }));
        fail(act, "failed", why.clone()).await;
        return Outcome::Refused(why);
    }
    let op = match caps::parse(&env.tool, &env.args, env.external.as_ref()) {
        Ok(op) => op,
        Err(why) => { log(json!({ "status": "refused", "error": why })); fail(act, "failed", why.clone()).await; return Outcome::Refused(why); }
    };

    // A secret lent to this host for this device (a hub token, a camera login): fetched sealed to a key made for this
    // action, held in memory until the action ends (standards/lent.rs).
    let mut lent = Lent { gate: ctx.gate.clone(), act: act.clone(), ..Default::default() };
    if let Some(name) = op.external().and_then(|e| e.secret.clone()) {
        let rx = standards::lent::Receiver::new();
        let got = match side.gate("POST", &route(&ctx.pavilion, &format!("/actions/{act}/secret")), "application/json", rx.request(), None).await {
            Ok((200, b)) => rx.open_answer(&act, &b),
            Ok((s, _)) => Err(format!("the Gate didn't lend the secret {name} ({s})")),
            Err(e) => Err(e),
        };
        match got {
            Ok(secret) => lent.secret = Some(secret),
            Err(why) => { log(json!({ "status": "failed", "error": why })); fail(act, "failed", why.clone()).await; return Outcome::Failed(why); }
        }
    }
    // What the device itself says, before anyone is asked: a lock is safety-critical whatever the envelope says, and
    // a car that's moving won't have its codes cleared.
    let prep = match side.prepare(&op, &lent).await {
        Ok(p) => p,
        Err(why) => { log(json!({ "status": "refused", "error": why })); fail(act, "failed", why.clone()).await; return Outcome::Refused(why); }
    };
    if let Some(c) = &prep.critical {
        if env.kind != "critical" {
            let why = format!("this device is safety-critical ({c}), so the action must be a critical one, allowed with presence; it came as {}", env.kind);
            log(json!({ "status": "refused", "error": why })); fail(act, "failed", why.clone()).await; return Outcome::Refused(why);
        }
    }

    // Ask the person here, unless the ceiling lets this computer allow this kind by itself (looks and reads only).
    let unattended = env.key_needed == "unlocked" && ctx.ceiling.unattended.contains(&env.kind) && prep.critical.is_none();
    let decision = if unattended { Decision::Allow } else {
        let detail = match &prep.critical { Some(c) => format!("{} Safety-critical: {c}.", describe(&op)), None => describe(&op) };
        let a = Ask { text: env.text.clone(), reason: env.reason.clone(), agent: if env.agent_name.is_empty() { env.agent.clone() } else { env.agent_name.clone() },
            device: env.external.as_ref().map(|e| format!("“{}”", e.name.chars().take(64).collect::<String>())), detail,
            presence: env.key_needed == "presence" || prep.critical.is_some(), expires_at: env.expires_at };
        match side.ask(&a).await {
            Ok(d) => d,
            Err(why) => { let why = format!("couldn't ask the person at this computer: {why}"); log(json!({ "status": "failed", "error": why })); fail(act, "failed", why.clone()).await; return Outcome::Failed(why); }
        }
    };
    if decision == Decision::NoAnswer { log(json!({ "status": "no answer" })); return Outcome::NoAnswer; }
    let word = if decision == Decision::Allow { "allow" } else { "deny" };
    let answer = json!({ "decision": word, "key": env.key_needed, "answerSig": envelope::sign(&ctx.key, &envelope::answer_message(&act, &env.args_hash, word)) });
    let r = side.gate("POST", &route(&ctx.pavilion, &format!("/actions/{act}/answer")), "application/json", serde_json::to_vec(&answer).unwrap(), None).await;
    if decision == Decision::Deny { log(json!({ "status": "denied" })); return Outcome::Denied; }
    match r {
        Ok((s, b)) if (200..300).contains(&s) => {
            let st = serde_json::from_slice::<Value>(&b).ok().and_then(|v| v["status"].as_str().map(String::from)).unwrap_or_default();
            if !st.is_empty() && st != "approved" && st != "running" {
                let why = format!("the Gate didn't approve it after the Allow ({st})");
                log(json!({ "status": "stopped", "error": why, "decision": "allow" }));
                return Outcome::Failed(why);
            }
        }
        Ok((s, b)) => { let why = format!("the Gate refused the answer ({s}: {})", String::from_utf8_lossy(&b).chars().take(200).collect::<String>()); log(json!({ "status": "stopped", "error": why })); return Outcome::Failed(why); }
        Err(e) => { log(json!({ "status": "stopped", "error": e })); return Outcome::Failed(e); }
    }
    let _ = side.gate("POST", &route(&ctx.pavilion, &format!("/actions/{act}/running")), "application/json", b"{}".to_vec(), None).await;

    // play_audio, cast_media and print of an asset: the bytes come from the Gate, for this action only.
    lent.asset = match &op {
        _ if op.needs_asset() => match side.gate("GET", &route(&ctx.pavilion, &format!("/actions/{act}/asset")), "", vec![], None).await {
            Ok((200, b)) if b.len() <= 25 << 20 => Some(b),
            Ok((s, _)) => { let why = format!("the Gate didn't give the action's asset ({s})"); log(json!({ "status": "failed", "error": why })); fail(act, "failed", why.clone()).await; return Outcome::Failed(why); }
            Err(e) => { log(json!({ "status": "failed", "error": e })); fail(act, "failed", e.clone()).await; return Outcome::Failed(e); }
        },
        _ => None,
    };

    let out = match side.run(&op, &lent).await {
        Ok(o) => o,
        Err(why) => { log(json!({ "status": "failed", "error": why })); fail(act, "failed", why.clone()).await; return Outcome::Failed(why); }
    };
    let (ctype, body) = match &out {
        Output::Bytes { ctype, bytes } => (ctype.clone(), bytes.clone()),
        Output::Json(v) => ("application/json".to_string(), serde_json::to_vec(v).unwrap()),
    };
    if let (Output::Bytes { .. }, Some(u)) = (&out, &env.upload) {
        let base_type = ctype.split(';').next().unwrap_or("").trim();
        if !u.types.is_empty() && !u.types.iter().any(|t| t == base_type) {
            let why = format!("it made {base_type}, which the action doesn't accept ({})", u.types.join(", "));
            log(json!({ "status": "failed", "error": why })); fail(act, "failed", why.clone()).await; return Outcome::Failed(why);
        }
        if body.len() as u64 > u.max_bytes {
            let why = format!("it made {} bytes, over the action's {} limit", body.len(), u.max_bytes);
            log(json!({ "status": "failed", "error": why })); fail(act, "failed", why.clone()).await; return Outcome::Failed(why);
        }
    }

    // Captures: shown for 3 seconds, with Cancel and Send now. Cancel sends nothing.
    let file = match &out { Output::Bytes { bytes, ctype } => preview_file(&ctx.dir, &act, ctype, bytes), _ => None };
    if let Some(p) = preview_of(&op, &out, file.clone()) {
        let send = side.preview(&p).await;
        if let Some(f) = &file { let _ = std::fs::remove_file(f); }
        match send {
            Ok(true) => {}
            Ok(false) => { log(json!({ "status": "canceled", "decision": "allow" })); fail(act, "canceled", "the person at this computer canceled before it was sent".into()).await; return Outcome::Canceled; }
            Err(why) => { let why = format!("couldn't show the preview: {why}"); log(json!({ "status": "failed", "error": why })); fail(act, "failed", why.clone()).await; return Outcome::Failed(why); }
        }
    }

    let sig = envelope::sign(&ctx.key, &envelope::result_message(&act, &body));
    let hash = b64(&sha256(&body));
    match side.gate("PUT", &route(&ctx.pavilion, &format!("/actions/{act}/result")), &ctype, body.clone(), Some(("x-pavilion-result-sig", sig))).await {
        Ok((s, b)) if (200..300).contains(&s) => {
            let v: Value = serde_json::from_slice(&b).unwrap_or(json!({}));
            log(json!({ "status": "succeeded", "decision": if unattended { "allowed by the ceiling" } else { "allow" }, "bytes": body.len(), "type": ctype, "sha256": hash, "asset": v["asset"] }));
            Outcome::Sent { bytes: body.len(), ctype }
        }
        Ok((s, b)) => { let why = format!("the Gate refused the result ({s}: {})", String::from_utf8_lossy(&b).chars().take(200).collect::<String>()); log(json!({ "status": "failed", "error": why })); Outcome::Failed(why) }
        Err(e) => { log(json!({ "status": "failed", "error": e })); Outcome::Failed(e) }
    }
}

/// Captures are written to a private folder only while they're shown, then removed.
fn preview_file(dir: &Path, act: &str, ctype: &str, bytes: &[u8]) -> Option<PathBuf> {
    let ext = match ctype { "image/jpeg" => "jpg", "image/png" => "png", "video/mp4" => "mp4", "audio/mp4" => "m4a", "audio/wav" => "wav", _ => return None };
    let p = dir.join("preview").join(format!("{act}.{ext}"));
    write_private(&p, bytes).ok()?;
    Some(p)
}

/* ---------- the real side: the Gate over HTTPS, the person through the platform ---------- */

pub struct Real { http: reqwest::Client, base: String, host: String, key: SigningKey, timeout_s: u64 }

/// A connection that isn't up in this long won't be: said as such rather than waiting out the whole request's time.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The inbox and the ceiling are small JSON both ways: the Gate answers in well under a second (58 ms measured on
/// staging, 21 Nov 2026). The 120 s that results need (up to 50 MB) made each stuck poll take two and a half minutes.
const POLL_TIMEOUT: Duration = Duration::from_secs(30);

impl Real {
    /// For an action: results go up to 50 MB, so the request may take two minutes.
    pub fn new() -> anyhow::Result<Real> { Real::with_timeout(Duration::from_secs(120)) }
    /// For the inbox poll and the ceiling mirror.
    pub fn polling() -> anyhow::Result<Real> { Real::with_timeout(POLL_TIMEOUT) }
    fn with_timeout(timeout: Duration) -> anyhow::Result<Real> {
        let st = crate::state::load()?;
        let url = reqwest::Url::parse(&st.gate)?;
        let host = url.host_str().unwrap_or_default().to_string() + &url.port().map(|p| format!(":{p}")).unwrap_or_default();
        let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).connect_timeout(CONNECT_TIMEOUT).timeout(timeout).build()?;
        Ok(Real { http, base: st.gate.trim_end_matches('/').to_string(), host, key: crate::state::key()?, timeout_s: timeout.as_secs() })
    }
}

/// What failed, in words: reqwest says "error sending request for url (…)" for a refused connection, a failed name
/// lookup, a bad certificate and a timeout alike, and keeps the cause in its sources.
pub fn failure_words(e: &reqwest::Error, host: &str, timeout_s: u64) -> String {
    let mut causes = vec![];
    let mut src = std::error::Error::source(e);
    while let Some(s) = src { causes.push(s.to_string()); src = s.source(); }
    let all = causes.join(" ").to_lowercase();
    let deepest = causes.iter().rev().find(|c| !c.trim().is_empty()).cloned().unwrap_or_else(|| e.to_string());
    if e.is_timeout() || all.contains("timed out") {
        if e.is_connect() || all.contains("connect") { format!("couldn't connect to {host} within {} s", CONNECT_TIMEOUT.as_secs()) } else { format!("{host} didn't answer within {timeout_s} s") }
    } else if all.contains("dns error") || all.contains("failed to lookup") || all.contains("nodename nor servname") {
        format!("couldn't look up {host} (the name didn't resolve: {deepest})")
    } else if all.contains("certificate") || all.contains("tls") || all.contains("handshake") {
        format!("the secure connection to {host} failed ({deepest})")
    } else if e.is_connect() {
        format!("couldn't connect to {host} ({deepest})")
    } else {
        format!("the request to {host} failed ({deepest})")
    }
}

/// How the device loop waits after the Gate fails it: the usual 30 s while all is well, then 1, 2, 4, 8 and at most 10
/// minutes; a line when the failure starts, when its words change, every tenth time, and when the Gate answers again
/// (21 Nov 2026: the same line every poll, with no cause).
#[derive(Default)]
pub struct Backoff { failures: u32, last: String }
impl Backoff {
    pub const MAX: Duration = Duration::from_secs(600);
    /// A failure: how long to wait, and the line to print, if any.
    pub fn failed(&mut self, why: &str) -> (Duration, Option<String>) {
        self.failures += 1;
        let wait = (POLL * 2u32.pow(self.failures.min(5))).min(Backoff::MAX);
        let say = self.failures == 1 || why != self.last || self.failures.is_multiple_of(10);
        let times = if self.failures == 1 { String::new() } else { format!(" ({} times in a row)", self.failures) };
        self.last = why.to_string();
        (wait, say.then(|| format!("devices: couldn't check for device actions: {why}{times}; trying again in {}", minutes(wait))))
    }
    /// A success: the line to print when it ends a run of failures.
    pub fn ok(&mut self) -> Option<String> {
        let n = std::mem::take(&mut self.failures);
        self.last.clear();
        (n > 0).then(|| format!("devices: the Gate answers again, after {n} failed check{}", if n == 1 { "" } else { "s" }))
    }
}
fn minutes(d: Duration) -> String { let s = d.as_secs(); if s < 120 { format!("{s} s") } else { format!("{} min", s / 60) } }

impl Side for Real {
    fn gate<'a>(&'a self, method: &'a str, path: &'a str, ctype: &'a str, body: Vec<u8>, header: Option<(&'static str, String)>) -> BoxFut<'a, Result<(u16, Vec<u8>), String>> {
        Box::pin(async move {
            let mut rb = self.http.request(method.parse().map_err(|_| "bad method")?, format!("{}{path}", self.base));
            for (k, v) in signed_headers(&self.key, &self.host, method, path, &body) { rb = rb.header(k, v); }
            if let Some((k, v)) = header { rb = rb.header(k, v); }
            if !body.is_empty() || method != "GET" { rb = rb.header("content-type", ctype).body(body); }
            let r = rb.send().await.map_err(|e| failure_words(&e, &self.host, self.timeout_s))?;
            let s = r.status().as_u16();
            Ok((s, r.bytes().await.map_err(|e| failure_words(&e, &self.host, self.timeout_s))?.to_vec()))
        })
    }
    fn ask<'a>(&'a self, a: &'a Ask) -> BoxFut<'a, Result<Decision, String>> { Box::pin(platform_ask(a)) }
    fn preview<'a>(&'a self, p: &'a Preview) -> BoxFut<'a, Result<bool, String>> { Box::pin(platform_preview(p)) }
    fn run<'a>(&'a self, op: &'a Op, lent: &'a Lent) -> BoxFut<'a, Result<Output, String>> {
        Box::pin(async move { let pav = crate::state::load().map(|s| s.pavilion).unwrap_or_default(); caps::run(op, &pav, lent).await })
    }
}

#[cfg(target_os = "macos")]
async fn platform_ask(a: &Ask) -> Result<Decision, String> { helper::ask(a).await }
#[cfg(target_os = "macos")]
async fn platform_preview(p: &Preview) -> Result<bool, String> { helper::preview(p).await }
#[cfg(windows)]
async fn platform_ask(a: &Ask) -> Result<Decision, String> { windows::ask(a).await }
#[cfg(windows)]
async fn platform_preview(p: &Preview) -> Result<bool, String> { windows::preview(p).await }
#[cfg(not(any(target_os = "macos", windows)))]
async fn platform_ask(_a: &Ask) -> Result<Decision, String> { Err("this system has no way to ask the person at the computer yet".into()) }
#[cfg(not(any(target_os = "macos", windows)))]
async fn platform_preview(_p: &Preview) -> Result<bool, String> { Err("no preview on this system yet".into()) }

/* ---------- the loop: socket messages, polling, the ceiling mirror ---------- */

static QUEUE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn ctx() -> anyhow::Result<Ctx> {
    let st = crate::state::load()?;
    let d = dir();
    Ok(Ctx { pavilion: st.pavilion, machine: st.machine, pavilion_key: st.pavilion_key, key: crate::state::key()?, ceiling: ceiling::load().devices,
        minute: ceiling::local_minute(), now: now(), seen: Arc::new(Seen::at(&d)), history: Arc::new(History::at(&d)), dir: d, gate: st.gate })
}

/// One action at a time: a person answers one question at a time.
async fn take(payload: String, sig: String) {
    let _turn = QUEUE.lock().await;
    let (Ok(side), Ok(c)) = (Real::new(), ctx()) else { eprintln!("devices: not joined"); return };
    let o = handle(&side, &c, &payload, &sig).await;
    if !matches!(o, Outcome::Ignored(_)) { eprintln!("devices: {o:?}"); }
}

/// A message on the node socket: `{type: "device_action", payload, sig}` (or inside an event). true if it was one.
pub fn incoming(v: &Value) -> bool {
    let m = if v["event"].is_object() { &v["event"] } else { v };
    if m["type"] != "device_action" && m["t"] != "device_action" { return false; }
    let (Some(p), Some(s)) = (m["payload"].as_str(), m["sig"].as_str()) else { return true };
    tokio::spawn(take(p.to_string(), s.to_string()));
    true
}

/// Polls the inbox (the fallback when a socket message is lost) and keeps the Gate's copy of the ceiling current.
pub async fn run_loop() {
    let mut mirrored: Option<String> = None;
    let mut quiet_404 = false;
    let mut backoff = Backoff::default();
    // A failure to reach the Gate waits longer each time and is said once, with its cause (Backoff).
    let failed = |backoff: &mut Backoff, why: &str| { let (wait, say) = backoff.failed(why); if let Some(l) = say { eprintln!("{l}"); } wait };
    loop {
        let mut wait = POLL;
        if let (Ok(side), Ok(st)) = (Real::polling(), crate::state::load()) {
            // The ceiling, mirrored whenever it changes (the Gate then doesn't ask for what this computer refuses).
            let c = ceiling::load();
            if let Some(p) = &c.problem { if mirrored.is_none() { eprintln!("devices: {p}"); } }
            let body = c.devices.mirror().to_string();
            if mirrored.as_deref() != Some(body.as_str()) {
                match side.gate("PUT", &route(&st.pavilion, "/ceiling"), "application/json", body.clone().into_bytes(), None).await {
                    Ok((s, _)) if (200..300).contains(&s) => mirrored = Some(body),
                    Ok((s, _)) => if !quiet_404 { eprintln!("devices: the Gate didn't take the ceiling ({s})"); quiet_404 = s == 404; },
                    Err(e) => wait = failed(&mut backoff, &e),
                }
            }
            match side.gate("GET", &route(&st.pavilion, "/actions?open=1"), "", vec![], None).await {
                Ok((s, _)) if s >= 500 || s == 429 => wait = failed(&mut backoff, &format!("the Gate answered {s}")),
                Ok((s, b)) => {
                    if let Some(l) = backoff.ok() { eprintln!("{l}"); }
                    if s == 200 { inbox(&b).await; } else if !quiet_404 { eprintln!("devices: the inbox answered {s}"); quiet_404 = s == 404; }
                }
                Err(e) => wait = failed(&mut backoff, &e),
            }
        }
        tokio::time::sleep(wait).await;
    }
}

/// The inbox's open actions, each taken in turn unless already seen.
async fn inbox(b: &[u8]) {
    let seen = Seen::at(&dir());
    let list: Value = serde_json::from_slice(b).unwrap_or(json!([]));
    let items = list.as_array().or_else(|| list["actions"].as_array()).cloned().unwrap_or_default();
    for it in items {
        let (Some(p), Some(s)) = (it["payload"].as_str(), it["sig"].as_str()) else { continue };
        let act = serde_json::from_str::<Value>(p).ok().and_then(|v| v["action"].as_str().map(String::from)).unwrap_or_default();
        if it["status"].as_str().unwrap_or("asking") != "asking" || seen.contains(&act) { continue; }
        take(p.to_string(), s.to_string()).await;
    }
}

/* ---------- `pavilion-node devices …` ---------- */

pub async fn cli(args: &[String]) -> anyhow::Result<()> {
    let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match a.as_slice() {
        ["status"] | [] => status().await,
        // Only the device side (inbox polling and the ceiling mirror), without jobs: for trying devices on a computer.
        ["run"] => { run_loop().await; Ok(()) }
        ["history"] => history(20),
        ["history", n] => history(n.parse().unwrap_or(20)),
        ["scan", kind, rest @ ..] if *kind == "ble" || *kind == "lan" => {
            #[cfg(target_os = "macos")]
            if helper::delegate_to_app(args)? { return Ok(()); }
            scan(kind, rest).await
        }
        ["scan", kind, rest @ ..] if standards::scan::KINDS.contains(kind) => {
            #[cfg(target_os = "macos")]
            if helper::delegate_to_app(args)? { return Ok(()); }
            scan_standard(kind, rest).await
        }
        ["test", tool, rest @ ..] => {
            #[cfg(target_os = "macos")]
            if helper::delegate_to_app(args)? { return Ok(()); }
            test(tool, rest.first().copied()).await
        }
        _ => anyhow::bail!("usage: pavilion-node devices status | history [n] | scan ble|lan|obd|home|cast|printers|cameras [seconds] [--no-send] [--no-ble] | scan modbus <host[:port]> | test <tool>|ask|preview ['{{json args}}'] | run"),
    }
}

async fn status() -> anyhow::Result<()> {
    let c = ceiling::load();
    println!("Ceiling: {}", c.source);
    if let Some(p) = &c.problem { println!("  NOT USED: {p}"); }
    let d = &c.devices;
    if d.is_none() { println!("  devices: none (every device action is refused)"); } else {
        println!("  capabilities: {}", d.capabilities.iter().cloned().collect::<Vec<_>>().join(", "));
        println!("  agents: {}", if d.agents.is_empty() { "none (every agent is refused)".into() } else { d.agents.iter().cloned().collect::<Vec<_>>().join(", ") });
        let hm = |m: u16| format!("{:02}:{:02}", m / 60, m % 60);
        println!("  quiet hours: {}", d.quiet.map(|(a, b)| format!("{}–{} {}", hm(a), hm(b), ceiling::local_tz())).unwrap_or_else(|| "none".into()));
        println!("  allowed with nobody here: {}", if d.unattended.is_empty() { "nothing (every action asks)".into() } else { d.unattended.iter().cloned().collect::<Vec<_>>().join(", ") });
    }
    match crate::state::load() { Ok(s) => println!("Pavilion: {} as {}", s.pavilion, s.machine), Err(_) => println!("Pavilion: not joined (`pavilion-node join`)") }
    println!("Actions remembered (single use): {}", Seen::at(&dir()).len());
    #[cfg(target_os = "macos")]
    match helper::permissions().await {
        Ok(p) => { println!("This Mac's permissions for {}:", helper::app_label()); for (k, v) in p.as_object().into_iter().flatten() { println!("  {k}: {}", v.as_str().unwrap_or("?")); } }
        Err(e) => println!("Permissions: {e}"),
    }
    #[cfg(windows)]
    println!("{}", windows::status());
    Ok(())
}

fn history(n: usize) -> anyhow::Result<()> {
    let h = History::at(&dir()).read(n);
    if h.is_empty() { println!("No device actions yet."); return Ok(()); }
    for e in h {
        let when = e["at"].as_u64().map(|t| { let ago = now().saturating_sub(t); if ago < 120 { format!("{ago} s ago") } else if ago < 7200 { format!("{} min ago", ago / 60) } else if ago < 172_800 { format!("{} h ago", ago / 3600) } else { format!("{} days ago", ago / 86_400) } }).unwrap_or_default();
        let who = e["agentName"].as_str().filter(|s| !s.is_empty()).or(e["agent"].as_str()).unwrap_or("?");
        println!("{when:>12}  {:<10} {who:<16} {:<16} {}{}", e["status"].as_str().unwrap_or("?"), e["tool"].as_str().unwrap_or("-"),
            e["text"].as_str().unwrap_or(""), e["error"].as_str().map(|x| format!(" — {x}")).unwrap_or_default());
    }
    Ok(())
}

/// A scan a person starts here, shown here and sent to the Gate so an owner can adopt a device in the console.
async fn scan(kind: &str, rest: &[&str]) -> anyhow::Result<()> {
    let seconds: u32 = rest.iter().find_map(|s| s.parse().ok()).unwrap_or(5).clamp(1, 10);
    let send = !rest.contains(&"--no-send");
    let st = crate::state::load().ok();
    let pav = st.as_ref().map(|s| s.pavilion.clone()).unwrap_or_else(|| "local".into());
    eprintln!("Scanning {} for {seconds} s…", if kind == "ble" { "Bluetooth LE" } else { "the local network (Bonjour)" });
    let items: Vec<Value> = if kind == "ble" {
        let items = tokio::time::timeout(Duration::from_secs(seconds as u64 + 20), caps::ble::scan(seconds, None)).await
            .map_err(|_| anyhow::anyhow!("Bluetooth didn't answer in time (if macOS is asking whether Pavilion Node may use Bluetooth, click Allow and scan again)"))?.map_err(|e| anyhow::anyhow!(e))?;
        for i in &items { println!("{:>5}  {:<28} {}  {}", i.rssi.map(|r| r.to_string()).unwrap_or_default(), i.name.clone().unwrap_or_else(|| "(no name)".into()), i.address, if i.services.is_empty() { String::new() } else { format!("services {}", i.services.join(" ")) }); }
        items.iter().map(|i| i.for_adoption(&pav)).collect()
    } else {
        let types: Vec<String> = caps::DEFAULT_LAN_TYPES.iter().map(|s| s.to_string()).collect();
        let items = caps::lan::discover(&types, seconds).await.map_err(|e| anyhow::anyhow!(e))?;
        for i in &items { println!("{:<22} {:<40} {}:{}", i.ty, i.name, i.host, i.port); }
        items.iter().map(|i| i.for_adoption(&pav)).collect()
    };
    println!("{} found.", items.len());
    if send && st.is_some() && !items.is_empty() {
        let side = Real::new()?;
        let (s, b) = side.gate("POST", &route(&pav, "/scan"), "application/json", serde_json::to_vec(&json!({ "kind": kind, "items": items }))?, None).await.map_err(|e| anyhow::anyhow!(e))?;
        if (200..300).contains(&s) { println!("Sent to the pavilion: adopt one in the console (Devices › this machine)."); } else { eprintln!("The Gate didn't take the scan ({s}: {})", String::from_utf8_lossy(&b)); }
    } else if send && st.is_none() { println!("Not joined to a pavilion, so nothing was sent."); }
    Ok(())
}

/// Scans for devices that speak one of the standards (standards/scan.rs), for adoption in the console.
async fn scan_standard(kind: &str, rest: &[&str]) -> anyhow::Result<()> {
    let seconds: u32 = rest.iter().find_map(|s| s.parse().ok()).unwrap_or(5).clamp(1, 10);
    let target = rest.iter().find(|s| !s.starts_with("--") && s.parse::<u32>().is_err()).copied();
    let send = !rest.contains(&"--no-send");
    let st = crate::state::load().ok();
    let pav = st.as_ref().map(|s| s.pavilion.clone()).unwrap_or_else(|| "local".into());
    eprintln!("Looking for {kind} for {seconds} s…");
    // OBD-II adapters over BLE too, unless `--no-ble` (Bluetooth needs the app's permission on a Mac).
    let items = standards::scan_kind(kind, &pav, seconds, target, !rest.contains(&"--no-ble")).await.map_err(|e| anyhow::anyhow!(e))?;
    for i in &items { println!("{}", standards::scan_line(i)); }
    println!("{} found.", items.len());
    if send && st.is_some() && !items.is_empty() {
        let side = Real::new()?;
        let body = serde_json::to_vec(&json!({ "kind": standards::scan::wire_kind(kind), "items": items }))?;
        let (s, b) = side.gate("POST", &route(&pav, "/scan"), "application/json", body, None).await.map_err(|e| anyhow::anyhow!(e))?;
        if (200..300).contains(&s) { println!("Sent to the pavilion: adopt one in the console (Devices › this machine)."); } else { eprintln!("The Gate didn't take the scan ({s}: {})", String::from_utf8_lossy(&b)); }
    } else if send && st.is_none() { println!("Not joined to a pavilion, so nothing was sent."); }
    Ok(())
}

/// Tries one capability here, for the person at this computer (checking permissions): nothing is sent anywhere, and
/// the ceiling isn't involved, since nobody else asked. The output is saved in the node's folder.
async fn test(tool: &str, args: Option<&str>) -> anyhow::Result<()> {
    let args: Value = serde_json::from_str(args.unwrap_or("{}"))?;
    if tool == "ask" {
        let a = Ask { text: "This is a test: nothing will happen if you allow it".into(), reason: Some("checking that the prompt works".into()), agent: "you".into(), device: None,
            detail: "Nothing is captured or sent.".into(), presence: args["presence"].as_bool().unwrap_or(false), expires_at: now() + args["seconds"].as_u64().unwrap_or(60).clamp(3, 600) };
        println!("{:?}", platform_ask(&a).await.map_err(|e| anyhow::anyhow!(e))?);
        return Ok(());
    }
    if tool == "preview" {
        // A made-up picture (no capture), shown the way captures are: it sends itself after 3 seconds.
        let p = Preview { kind: "text", path: None, text: Some("This is a test preview: nothing is captured or sent.".into()), seconds: PREVIEW_SECONDS };
        println!("send: {}", platform_preview(&p).await.map_err(|e| anyhow::anyhow!(e))?);
        return Ok(());
    }
    let op = caps::parse(tool, &args, None).map_err(|e| anyhow::anyhow!(e))?;
    let out = caps::run(&op, "local", &Lent::default()).await.map_err(|e| anyhow::anyhow!(e))?;
    match out {
        Output::Json(v) => println!("{}", serde_json::to_string_pretty(&v)?),
        Output::Bytes { ctype, bytes } => {
            let p = preview_file(&dir(), &format!("test-{tool}-{}", now()), &ctype, &bytes).ok_or_else(|| anyhow::anyhow!("unexpected type {ctype}"))?;
            println!("{} bytes of {ctype} in {}", bytes.len(), p.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::envelope::tests::{envelope, gate_key, signed, ME, NOW, PAV};
    use super::*;
    use std::sync::Mutex;

    /// A stand-in for the Gate, the person and the hardware: records every Gate call, answers as scripted.
    struct Fake { calls: Mutex<Vec<(String, String, Vec<u8>, Option<String>)>>, decision: Decision, send: bool, asked: Mutex<Vec<Ask>> }
    impl Fake { fn new(decision: Decision, send: bool) -> Fake { Fake { calls: Mutex::new(vec![]), decision, send, asked: Mutex::new(vec![]) } } }
    impl Side for Fake {
        fn gate<'a>(&'a self, method: &'a str, path: &'a str, _ctype: &'a str, body: Vec<u8>, header: Option<(&'static str, String)>) -> BoxFut<'a, Result<(u16, Vec<u8>), String>> {
            self.calls.lock().unwrap().push((method.into(), path.into(), body, header.map(|h| h.1)));
            let reply = if path.ends_with("/answer") { r#"{"status":"approved"}"# } else if path.ends_with("/result") { r#"{"status":"succeeded","asset":"ast_1"}"# } else { "{}" };
            Box::pin(async move { Ok((200, reply.as_bytes().to_vec())) })
        }
        fn ask<'a>(&'a self, a: &'a Ask) -> BoxFut<'a, Result<Decision, String>> { self.asked.lock().unwrap().push(a.clone()); Box::pin(async move { Ok(self.decision) }) }
        fn preview<'a>(&'a self, _p: &'a Preview) -> BoxFut<'a, Result<bool, String>> { Box::pin(async move { Ok(self.send) }) }
        fn run<'a>(&'a self, op: &'a Op, _l: &'a Lent) -> BoxFut<'a, Result<Output, String>> {
            Box::pin(async move { Ok(match op { Op::CameraSnapshot { .. } => Output::Bytes { ctype: "image/jpeg".into(), bytes: vec![0xff, 0xd8, 0xff, 0xd9] }, _ => Output::Json(json!({ "items": [] })) }) })
        }
    }
    fn tmp() -> PathBuf { let d = std::env::temp_dir().join(format!("pavilion-devices-test-{}", crate::signing::random_b64(6))); std::fs::create_dir_all(&d).unwrap(); d }
    fn ctx(dir: &Path, ceiling: &str) -> Ctx {
        Ctx { pavilion: PAV.into(), machine: ME.into(), pavilion_key: b64(gate_key().verifying_key().as_bytes()), key: SigningKey::from_bytes(&[3u8; 32]),
            ceiling: ceiling::parse(ceiling).unwrap(), minute: 12 * 60, now: NOW, seen: Arc::new(Seen::at(dir)), history: Arc::new(History::at(dir)), dir: dir.to_path_buf(), gate: "https://gate.example".into() }
    }
    const OPEN: &str = "devices:\n  capabilities: camera, lan, ble\n  agents: agt_linkcheck\n";
    fn paths(f: &Fake) -> Vec<String> { f.calls.lock().unwrap().iter().map(|c| format!("{} {}", c.0, c.1.rsplit('/').next().unwrap())).collect() }

    /// 21 Nov 2026: "devices: the Gate: error sending request for url (…/actions?open=1)" every poll, the cause unsaid.
    #[test]
    fn a_failing_gate_is_said_once_and_waited_out_longer_each_time() {
        let mut b = Backoff::default();
        let why = "staging.cloudpavilion.net didn't answer within 30 s";
        let mut waits = vec![];
        let mut said = vec![];
        for _ in 0..12 { let (w, l) = b.failed(why); waits.push(w.as_secs()); if let Some(l) = l { said.push(l); } }
        assert_eq!(waits, vec![60, 120, 240, 480, 600, 600, 600, 600, 600, 600, 600, 600]);
        assert_eq!(said, vec![
            "devices: couldn't check for device actions: staging.cloudpavilion.net didn't answer within 30 s; trying again in 60 s".to_string(),
            "devices: couldn't check for device actions: staging.cloudpavilion.net didn't answer within 30 s (10 times in a row); trying again in 10 min".to_string(),
        ]);
        // A different cause is said at once; an answer ends the run, said once, and the next failure starts over.
        assert!(b.failed("couldn't connect to staging.cloudpavilion.net within 10 s").1.unwrap().contains("(13 times in a row)"));
        assert_eq!(b.ok().as_deref(), Some("devices: the Gate answers again, after 13 failed checks"));
        assert_eq!(b.ok(), None);
        assert_eq!(b.failed(why).0, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn what_failed_is_said_in_words() {
        let client = |t: u64| reqwest::Client::builder().connect_timeout(Duration::from_secs(2)).timeout(Duration::from_secs(t)).build().unwrap();
        // Nothing listening: refused.
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);
        let e = client(5).get(format!("http://127.0.0.1:{port}/p/x/node/devices/actions?open=1")).send().await.unwrap_err();
        let w = failure_words(&e, &format!("127.0.0.1:{port}"), 5);
        assert!(w.starts_with(&format!("couldn't connect to 127.0.0.1:{port} (")) && !w.contains("error sending request"), "{w}");
        // A server that takes the connection and never answers: the request's own time runs out.
        let mute = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = mute.local_addr().unwrap();
        let held = tokio::spawn(async move { let (s, _) = mute.accept().await.unwrap(); tokio::time::sleep(Duration::from_secs(10)).await; drop(s); });
        let e = client(1).get(format!("http://{addr}/p/x/node/devices/actions?open=1")).send().await.unwrap_err();
        assert_eq!(failure_words(&e, &addr.to_string(), 1), format!("{addr} didn't answer within 1 s"));
        held.abort();
        // A name that can't resolve (`.invalid` never does, RFC 6761).
        let e = client(5).get("https://gate.pavilion.invalid/").send().await.unwrap_err();
        let w = failure_words(&e, "gate.pavilion.invalid", 5);
        assert!(w.starts_with("couldn't look up gate.pavilion.invalid") || w.starts_with("couldn't connect to gate.pavilion.invalid"), "{w}");
    }

    #[tokio::test]
    async fn a_photo_is_asked_with_presence_answered_shown_and_sent_signed() {
        let d = tmp();
        let c = ctx(&d, OPEN);
        let (p, s) = signed(&envelope("camera_snapshot", json!({ "host": ME, "max_px": 1024 }), "capture", |e| { e["upload"] = json!({ "maxBytes": 1000, "types": ["image/jpeg"] }) }), &gate_key());
        let f = Fake::new(Decision::Allow, true);
        assert_eq!(handle(&f, &c, &p, &s).await, Outcome::Sent { bytes: 4, ctype: "image/jpeg".into() });
        assert!(f.asked.lock().unwrap()[0].presence);
        assert_eq!(f.asked.lock().unwrap()[0].reason.as_deref(), Some("to find the printer"));
        assert_eq!(paths(&f), ["POST answer", "POST running", "PUT result"]);
        let calls = f.calls.lock().unwrap();
        let answer: Value = serde_json::from_slice(&calls[0].2).unwrap();
        assert_eq!((answer["decision"].as_str(), answer["key"].as_str()), (Some("allow"), Some("presence")));
        let pk = b64(c.key.verifying_key().as_bytes());
        assert!(crate::signing::verify_member("Ed25519", &pk, &envelope::answer_message("act_0123456789abcdef0123", &envelope::args_hash(&json!({ "host": ME, "max_px": 1024 })), "allow"), answer["answerSig"].as_str().unwrap()));
        assert!(crate::signing::verify_member("Ed25519", &pk, &envelope::result_message("act_0123456789abcdef0123", &calls[2].2), calls[2].3.as_deref().unwrap()));
        assert_eq!(c.history.read(5).last().unwrap()["status"], "succeeded");
    }

    #[tokio::test]
    async fn a_replayed_action_is_done_once() {
        let d = tmp();
        let c = ctx(&d, OPEN);
        let (p, s) = signed(&envelope("lan_discover", json!({ "host": ME }), "look", |_| {}), &gate_key());
        let f = Fake::new(Decision::Allow, true);
        assert!(matches!(handle(&f, &c, &p, &s).await, Outcome::Sent { .. }));
        assert_eq!(handle(&f, &c, &p, &s).await, Outcome::Ignored("already seen".into()));
        // Even after a restart: the ids are on disk.
        let c2 = ctx(&d, OPEN);
        assert_eq!(handle(&f, &c2, &p, &s).await, Outcome::Ignored("already seen".into()));
        assert_eq!(paths(&f).iter().filter(|p| p.ends_with("result")).count(), 1);
    }

    #[tokio::test]
    async fn the_ceiling_refuses_before_anyone_is_asked() {
        let d = tmp();
        for (ceiling, tool, args, kind, why) in [
            ("devices: none\n", "lan_discover", json!({ "host": ME }), "look", "devices: none"),
            ("devices:\n  capabilities: lan\n  agents: agt_linkcheck\n", "camera_snapshot", json!({ "host": ME }), "capture", "camera is switched off"),
            ("devices:\n  capabilities: screen\n  agents: agt_other\n", "screen_capture", json!({ "host": ME }), "capture", "agt_linkcheck"),
        ] {
            let c = ctx(&d, ceiling);
            let (p, s) = signed(&envelope(tool, args, kind, |e| { e["action"] = json!(format!("act_{:020x}", rand::random::<u64>())) }), &gate_key());
            let f = Fake::new(Decision::Allow, true);
            match handle(&f, &c, &p, &s).await { Outcome::Refused(w) => assert!(w.contains(why), "{w}"), o => panic!("{o:?}") }
            assert!(f.asked.lock().unwrap().is_empty());
            assert_eq!(paths(&f), ["POST fail"]);
        }
    }

    #[tokio::test]
    async fn deny_cancel_and_unattended_reads() {
        let d = tmp();
        // Deny: a signed deny, nothing run.
        let c = ctx(&d, OPEN);
        let (p, s) = signed(&envelope("camera_snapshot", json!({ "host": ME }), "capture", |_| {}), &gate_key());
        let f = Fake::new(Decision::Deny, true);
        assert_eq!(handle(&f, &c, &p, &s).await, Outcome::Denied);
        assert_eq!(paths(&f), ["POST answer"]);
        // Cancel in the preview: nothing uploaded, reported canceled.
        let (p, s) = signed(&envelope("camera_snapshot", json!({ "host": ME }), "capture", |e| { e["action"] = json!("act_00000000000000000001") }), &gate_key());
        let f = Fake::new(Decision::Allow, false);
        assert_eq!(handle(&f, &c, &p, &s).await, Outcome::Canceled);
        assert_eq!(paths(&f), ["POST answer", "POST running", "POST fail"]);
        assert!(String::from_utf8_lossy(&f.calls.lock().unwrap()[2].2).contains("canceled"));
        // A look, with a ceiling that lets this computer allow looks by itself: nobody is asked.
        let c = ctx(&d, "devices:\n  capabilities: lan\n  agents: agt_linkcheck\n  unattended: look\n");
        let (p, s) = signed(&envelope("lan_discover", json!({ "host": ME }), "look", |e| { e["action"] = json!("act_00000000000000000002") }), &gate_key());
        let f = Fake::new(Decision::Deny, true);
        assert!(matches!(handle(&f, &c, &p, &s).await, Outcome::Sent { .. }));
        assert!(f.asked.lock().unwrap().is_empty());
        // …but a capture still asks.
        let c = ctx(&d, "devices:\n  capabilities: camera\n  agents: agt_linkcheck\n  unattended: look, read\n");
        let (p, s) = signed(&envelope("camera_snapshot", json!({ "host": ME }), "capture", |e| { e["action"] = json!("act_00000000000000000003") }), &gate_key());
        let f = Fake::new(Decision::Allow, true);
        handle(&f, &c, &p, &s).await;
        assert_eq!(f.asked.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_forged_or_expired_action_does_nothing() {
        let d = tmp();
        let c = ctx(&d, OPEN);
        let (p, s) = signed(&envelope("camera_snapshot", json!({ "host": ME }), "capture", |_| {}), &SigningKey::from_bytes(&[9u8; 32]));
        let f = Fake::new(Decision::Allow, true);
        assert!(matches!(handle(&f, &c, &p, &s).await, Outcome::Refused(_)));
        assert!(paths(&f).is_empty() && f.asked.lock().unwrap().is_empty()); // a forged one isn't even reported
        let (p, s) = signed(&envelope("camera_snapshot", json!({ "host": ME }), "capture", |e| { e["expiresAt"] = json!(NOW - 1) }), &gate_key());
        assert!(matches!(handle(&f, &c, &p, &s).await, Outcome::Refused(_)));
        assert_eq!(paths(&f), ["POST fail"]);
        assert!(f.asked.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_oversized_or_wrong_type_result_isnt_sent() {
        let d = tmp();
        let c = ctx(&d, OPEN);
        let (p, s) = signed(&envelope("camera_snapshot", json!({ "host": ME }), "capture", |e| { e["upload"] = json!({ "maxBytes": 2, "types": ["image/jpeg"] }) }), &gate_key());
        let f = Fake::new(Decision::Allow, true);
        match handle(&f, &c, &p, &s).await { Outcome::Failed(w) => assert!(w.contains("over")), o => panic!("{o:?}") }
        assert!(!paths(&f).iter().any(|p| p.ends_with("result")));
    }

    /* ---------- the standards on the real path: the real adapters against simulators ---------- */

    /// The Gate and the person are stand-ins; everything else is the node's own code: the envelope check, the ceiling,
    /// the lent secret (sealed to a key made for the action), `prepare`, the ask, and `caps::run` with the real
    /// adapters talking to local simulators.
    struct Bench { calls: Mutex<Vec<(String, String, Vec<u8>)>>, decision: Decision, asked: Mutex<Vec<Ask>>, secret: &'static str }
    impl Bench { fn new(decision: Decision, secret: &'static str) -> Bench { Bench { calls: Mutex::new(vec![]), decision, asked: Mutex::new(vec![]), secret } } }
    impl Side for Bench {
        fn gate<'a>(&'a self, method: &'a str, path: &'a str, _ctype: &'a str, body: Vec<u8>, _h: Option<(&'static str, String)>) -> BoxFut<'a, Result<(u16, Vec<u8>), String>> {
            self.calls.lock().unwrap().push((method.into(), path.into(), body.clone()));
            let reply = if path.ends_with("/secret") {
                // The Gate's side: the vault value sealed to the key in the request, bound to this action.
                let act = path.rsplit('/').nth(1).unwrap();
                let pk: [u8; 32] = crate::signing::unb64(serde_json::from_slice::<Value>(&body).unwrap()["pub"].as_str().unwrap()).unwrap().try_into().unwrap();
                json!({ "name": "LENT", "sealed": b64(&standards::lent::seal(&pk, &standards::lent::info(act), self.secret.as_bytes())) }).to_string()
            } else if path.ends_with("/answer") { r#"{"status":"approved"}"#.into() } else if path.ends_with("/result") { r#"{"status":"succeeded"}"#.into() } else { "{}".into() };
            Box::pin(async move { Ok((200, reply.into_bytes())) })
        }
        fn ask<'a>(&'a self, a: &'a Ask) -> BoxFut<'a, Result<Decision, String>> { self.asked.lock().unwrap().push(a.clone()); Box::pin(async move { Ok(self.decision) }) }
        fn preview<'a>(&'a self, _p: &'a Preview) -> BoxFut<'a, Result<bool, String>> { Box::pin(async move { Ok(true) }) }
        fn run<'a>(&'a self, op: &'a Op, lent: &'a Lent) -> BoxFut<'a, Result<Output, String>> { Box::pin(async move { caps::run(op, PAV, lent).await }) }
    }
    fn result_of(b: &Bench) -> Value { b.calls.lock().unwrap().iter().find(|c| c.1.ends_with("/result")).map(|c| serde_json::from_slice(&c.2).unwrap()).unwrap_or(Value::Null) }
    fn act_id(n: u64) -> Value { json!(format!("act_{n:020x}")) }
    const STD: &str = "devices:\n  capabilities: home, obd\n  agents: agt_linkcheck\n";

    #[tokio::test]
    async fn a_lock_needs_a_critical_action_whatever_the_envelope_says() {
        let d = tmp();
        let c = ctx(&d, STD);
        let calls = Arc::new(Mutex::new(vec![]));
        let hub = standards::home::tests::hub(calls.clone()).await;
        let ext = json!({ "id": "ext_hub", "name": "Home", "kind": "home", "hub": "home-assistant", "address": hub, "secret": "HA_TOKEN", "critical": false });
        let args = json!({ "external": "ext_hub", "device": "lock.front_door", "command": "unlock" });
        // Sent as an ordinary act: the hub says it's a lock, so it's refused before anyone is asked.
        let (p, s) = signed(&envelope("home_command", args.clone(), "act", |e| { e["external"] = ext.clone(); e["action"] = act_id(1) }), &gate_key());
        let b = Bench::new(Decision::Allow, standards::home::tests::TOKEN);
        match handle(&b, &c, &p, &s).await { Outcome::Refused(w) => assert!(w.contains("safety-critical (a lock)"), "{w}"), o => panic!("{o:?}") }
        assert!(b.asked.lock().unwrap().is_empty());
        assert!(calls.lock().unwrap().is_empty()); // nothing reached the lock
        assert!(b.calls.lock().unwrap().iter().any(|c| c.1.ends_with("/fail")));
        // Sent as critical: asked with presence, then done.
        let (p, s) = signed(&envelope("home_command", args, "critical", |e| { e["external"] = ext.clone(); e["action"] = act_id(2) }), &gate_key());
        let b = Bench::new(Decision::Allow, standards::home::tests::TOKEN);
        assert!(matches!(handle(&b, &c, &p, &s).await, Outcome::Sent { .. }));
        let asked = b.asked.lock().unwrap()[0].clone();
        assert!(asked.presence && asked.detail.contains("Safety-critical: a lock"), "{asked:?}");
        assert_eq!(calls.lock().unwrap()[0].0, "lock/unlock");
        assert_eq!(result_of(&b), json!({ "done": true, "state": "unlocked" }));
        // A lamp is an ordinary act (still asked, with presence, as every act on a computer is).
        let (p, s) = signed(&envelope("home_command", json!({ "external": "ext_hub", "device": "light.desk", "command": "on" }), "act", |e| { e["external"] = ext.clone(); e["action"] = act_id(3) }), &gate_key());
        let b = Bench::new(Decision::Allow, standards::home::tests::TOKEN);
        assert!(matches!(handle(&b, &c, &p, &s).await, Outcome::Sent { .. }));
        assert!(!b.asked.lock().unwrap()[0].detail.contains("Safety-critical"));
        assert_eq!(result_of(&b)["state"], "on");
        // A wrong lent token: the hub refuses, nothing happens.
        let (p, s) = signed(&envelope("home_state", json!({ "external": "ext_hub", "device": "light.desk" }), "read", |e| { e["external"] = ext.clone(); e["action"] = act_id(4) }), &gate_key());
        let b = Bench::new(Decision::Allow, "not-the-token");
        match handle(&b, &c, &p, &s).await { Outcome::Failed(w) => assert!(w.contains("refused the lent token"), "{w}"), o => panic!("{o:?}") }
    }

    #[tokio::test]
    async fn fault_codes_are_not_cleared_while_the_car_moves() {
        let d = tmp();
        let c = ctx(&d, STD);
        let car = standards::obd::tests::Car::new(42);
        let addr = standards::obd::tests::simulator(car.clone()).await;
        let ext = json!({ "id": "ext_car", "name": "Van", "kind": "obd", "transport": "wifi", "address": addr, "allow": { "pids": "standard" } });
        let (p, s) = signed(&envelope("obd_clear_codes", json!({ "external": "ext_car" }), "act", |e| { e["external"] = ext.clone(); e["action"] = act_id(11) }), &gate_key());
        let b = Bench::new(Decision::Allow, "");
        match handle(&b, &c, &p, &s).await { Outcome::Refused(w) => assert!(w.contains("moving (42 km/h)"), "{w}"), o => panic!("{o:?}") }
        assert!(b.asked.lock().unwrap().is_empty()); // the driver isn't asked for Touch ID
        assert!(!car.commands.lock().unwrap().iter().any(|c| c == "04"));
        // Standing still: asked with presence, then cleared.
        car.speed.store(0, std::sync::atomic::Ordering::SeqCst);
        let (p, s) = signed(&envelope("obd_clear_codes", json!({ "external": "ext_car" }), "act", |e| { e["external"] = ext.clone(); e["action"] = act_id(12) }), &gate_key());
        let b = Bench::new(Decision::Allow, "");
        assert!(matches!(handle(&b, &c, &p, &s).await, Outcome::Sent { .. }));
        assert!(b.asked.lock().unwrap()[0].presence);
        assert_eq!(result_of(&b), json!({ "done": true }));
        assert!(car.cleared.load(std::sync::atomic::Ordering::SeqCst));
        // Reads go through too, only allowed values; an agent can't slip in an AT command.
        let (p, s) = signed(&envelope("obd_read", json!({ "external": "ext_car", "pids": ["rpm", "ATZ"] }), "read", |e| { e["external"] = ext.clone(); e["action"] = act_id(13) }), &gate_key());
        match handle(&Bench::new(Decision::Allow, ""), &c, &p, &s).await { Outcome::Refused(w) => assert!(w.contains("ATZ"), "{w}"), o => panic!("{o:?}") }
        let (p, s) = signed(&envelope("obd_codes", json!({ "external": "ext_car" }), "read", |e| { e["external"] = ext.clone(); e["action"] = act_id(14) }), &gate_key());
        let b = Bench::new(Decision::Allow, "");
        assert!(matches!(handle(&b, &c, &p, &s).await, Outcome::Sent { .. }));
        assert_eq!(result_of(&b)["codes"], json!([])); // cleared above
        // The ceiling: obd switched off refuses before anything reaches the adapter.
        let c2 = ctx(&d, "devices:\n  capabilities: home\n  agents: agt_linkcheck\n");
        let n = car.commands.lock().unwrap().len();
        let (p, s) = signed(&envelope("obd_read", json!({ "external": "ext_car", "pids": ["rpm"] }), "read", |e| { e["external"] = ext.clone(); e["action"] = act_id(15) }), &gate_key());
        match handle(&Bench::new(Decision::Allow, ""), &c2, &p, &s).await { Outcome::Refused(w) => assert!(w.contains("obd is switched off")), o => panic!("{o:?}") }
        assert_eq!(car.commands.lock().unwrap().len(), n);
    }

    #[tokio::test]
    async fn a_modbus_write_is_critical_and_only_listed_registers() {
        let d = tmp();
        let c = ctx(&d, "devices:\n  capabilities: industrial\n  agents: agt_linkcheck\n  unattended: read\n");
        let holding = Arc::new(Mutex::new(vec![0u16; 100]));
        let addr = standards::modbus::tests::device(holding.clone(), vec![7; 100]).await;
        let ext = |critical: bool| json!({ "id": "ext_inverter", "name": "Inverter", "kind": "modbus", "address": addr, "critical": critical,
            "allow": { "registers": [{ "name": "export_limit", "table": "holding", "address": 40, "type": "u16", "unit": "W" }] } });
        // A read of a listed register, allowed by the ceiling with nobody here.
        let (p, s) = signed(&envelope("modbus_read", json!({ "external": "ext_inverter", "register": "export_limit" }), "read", |e| { e["external"] = ext(false); e["action"] = act_id(21) }), &gate_key());
        let b = Bench::new(Decision::Deny, "");
        assert!(matches!(handle(&b, &c, &p, &s).await, Outcome::Sent { .. }));
        assert!(b.asked.lock().unwrap().is_empty());
        // A write: the envelope must be critical (the floor), and the adoption marked critical.
        let (p, s) = signed(&envelope("modbus_write", json!({ "external": "ext_inverter", "register": "export_limit", "value": 2500 }), "act", |e| { e["external"] = ext(true); e["action"] = act_id(22) }), &gate_key());
        assert!(matches!(handle(&Bench::new(Decision::Allow, ""), &c, &p, &s).await, Outcome::Refused(_)));
        let (p, s) = signed(&envelope("modbus_write", json!({ "external": "ext_inverter", "register": "export_limit", "value": 2500 }), "critical", |e| { e["external"] = ext(false); e["action"] = act_id(23) }), &gate_key());
        match handle(&Bench::new(Decision::Allow, ""), &c, &p, &s).await { Outcome::Refused(w) => assert!(w.contains("marked critical")), o => panic!("{o:?}") }
        let (p, s) = signed(&envelope("modbus_write", json!({ "external": "ext_inverter", "register": "export_limit", "value": 2500 }), "critical", |e| { e["external"] = ext(true); e["action"] = act_id(24) }), &gate_key());
        let b = Bench::new(Decision::Allow, "");
        assert!(matches!(handle(&b, &c, &p, &s).await, Outcome::Sent { .. }));
        assert!(b.asked.lock().unwrap()[0].presence);
        assert_eq!(holding.lock().unwrap()[40], 2500);
    }

    #[test]
    fn socket_messages_are_recognised() {
        assert!(!incoming(&json!({ "t": "event", "event": { "t": "job" } })));
        assert!(!incoming(&json!({ "t": "host" })));
    }
}
