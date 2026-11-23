//! The machine model relay (docs/MODEL-ACCOUNTS.md §7): a local model on this machine (Ollama, LM Studio), used from
//! anywhere in the pavilion over the link this node already dialled out on. Nothing listens beyond loopback and no
//! port is opened: the Gate sends `model.call` on the socket, the node answers with frames on the same socket.
//!
//!   model.call   {id, payload, sig}  the envelope, signed by the pavilion's key as `pavilion-model-v1\n<payload>`
//!   model.head   {id, status, headers}            the runtime answered
//!   model.chunk  {id, seq, data}                  its bytes (SSE text), in order, batched: every 100 ms or 8 KB
//!   model.end    {id, seq, usage}                 the last seq sent, and the usage the node saw (a cross-check)
//!   model.error  {id, code, message}              machine_busy, guard, model_missing, bad_request, timeout, cancelled…
//!   model.cancel {id, reason}  (Gate → node)      the caller went away, the deadline passed, the owner pressed stop
//!   machine.sleep {}           (node → Gate)      macOS is about to sleep (platform/macos_sleep.rs)
//!
//! What the node refuses before anything reaches the runtime (a mirror of `checkEnvelope` in
//! gate/src/model-providers/machine.ts, plus what only the node can know):
//! - a bad signature, or an envelope for another pavilion or machine, expired, or living longer than two minutes;
//! - a model this machine does not have (the runtime's own list, read now) or the owner did not offer here
//!   (`relay_models` in config.json); the whole relay when `model_relay` is "off";
//! - any path but `POST /v1/chat/completions` and `POST /v1/messages`: nothing that pulls, pushes, creates or deletes;
//! - a body naming another model, too large, or with silly limits;
//! - an image that is not inline base64 (the host never fetches a URL for a model), and any document (the pavilion
//!   extracts text first, docs/MODEL-ACCOUNTS.md §5);
//! - a new call at amber or worse (the guard); a call when every slot is busy (`model_slots`, default 1).
//!
//! Timeouts: the envelope must arrive within its 60 s; the whole call has `timeoutS` (10 minutes by default, 30 at
//! most); a stream with nothing for 120 s is cancelled (the first byte waits as long, since loading a model takes time).
//! At red the guard cancels running calls. Cancelling drops the loopback request, and Ollama and LM Studio stop
//! generating when their client goes away.
use crate::guard::Level;
use crate::signing::unb64;
use ed25519_dalek::{Verifier, VerifyingKey};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify};

/// The two runtimes and where they listen. Loopback only; config.json may move the port (`ollama_url`, `lmstudio_url`)
/// but never off this machine.
pub const RUNTIMES: [(&str, &str); 2] = [("ollama", "http://127.0.0.1:11434"), ("lmstudio", "http://127.0.0.1:1234")];
/// The only calls the relay makes to a runtime, by shape. Nothing that pulls, pushes, creates or deletes a model.
pub const PATHS: [(&str, &str); 2] = [("openai-chat", "/v1/chat/completions"), ("anthropic-messages", "/v1/messages")];
pub const MAX_BODY: usize = 32 * 1024 * 1024;
pub const MAX_TIMEOUT_S: u64 = 1800;
pub const MAX_OUTPUT_TOKENS: u64 = 262_144;
/// An envelope is made to be used at once: the Gate gives it 60 s; anything meant to live longer is refused.
pub const MAX_ENVELOPE_LIFE_MS: u64 = 120_000;
pub const MAX_SLOTS: usize = 8;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub v: u32,
    pub t: String,
    pub id: String,
    pub pavilion: String,
    pub machine: String,
    #[serde(default)]
    pub by: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub runtime: String,
    pub model: String,
    pub shape: String,
    pub path: String,
    pub stream: bool,
    pub body: String,
    pub max_output_tokens: u64,
    pub timeout_s: u64,
}

/// Checks the pavilion's signature on a model envelope (gate/src/model-relay.ts `signModelEnvelope`).
pub fn verify(pavilion_key_b64: &str, payload_b64: &str, sig_b64: &str) -> bool {
    let (Ok(pk), Ok(sig)) = (unb64(pavilion_key_b64), unb64(sig_b64)) else { return false };
    let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(pk.as_slice()), ed25519_dalek::Signature::from_slice(&sig)) else { return false };
    let msg = format!("pavilion-model-v1\n{payload_b64}");
    VerifyingKey::from_bytes(&pk).map(|k| k.verify(msg.as_bytes(), &sig).is_ok()).unwrap_or(false)
}

pub fn open(payload_b64: &str) -> Result<Envelope, String> {
    let b = unb64(payload_b64).map_err(|_| "the envelope is not base64".to_string())?;
    serde_json::from_slice::<Envelope>(&b).map_err(|e| format!("the envelope is not a model call: {e}"))
}

pub fn path_allowed(shape: &str, path: &str) -> bool { PATHS.iter().any(|(s, p)| *s == shape && *p == path) }

pub struct Expect<'a> { pub pavilion: &'a str, pub machine: &'a str, pub models: &'a [String], pub now: u64, pub max_body: usize }

/// Why an envelope is refused: the relay's error code and a sentence for the caller.
pub type Refusal = (&'static str, String);
fn no(code: &'static str, why: &str) -> Refusal { (code, why.to_string()) }

/// The mirror of `checkEnvelope` (gate/src/model-providers/machine.ts), in the same order, with the same sentences.
pub fn check(e: &Envelope, x: &Expect) -> Result<(), Refusal> {
    if e.v != 1 || e.t != "model.call" { return Err(no("bad_request", "not a model call")); }
    if e.pavilion != x.pavilion || e.machine != x.machine { return Err(no("grant_refused", "not for this machine")); }
    if e.expires_at <= x.now || e.issued_at > x.now + 60_000 { return Err(no("timeout", "expired or from the future")); }
    if e.expires_at.saturating_sub(e.issued_at) > MAX_ENVELOPE_LIFE_MS { return Err(no("grant_refused", "an envelope lives at most two minutes")); }
    if !RUNTIMES.iter().any(|(r, _)| *r == e.runtime) { return Err(no("bad_request", "unknown runtime")); }
    if !x.models.iter().any(|m| *m == format!("{}:{}", e.runtime, e.model)) { return Err(no("model_missing", "that model is not offered from this machine")); }
    if !path_allowed(&e.shape, &e.path) { return Err(no("grant_refused", "that path is not allowed")); }
    if e.body.len() > x.max_body { return Err(no("bad_request", "the request is too large")); }
    let b: Value = serde_json::from_str(&e.body).map_err(|_| no("bad_request", "the body is not JSON"))?;
    if !b.is_object() || b["model"] != e.model.as_str() { return Err(no("bad_request", "the body names another model")); }
    if e.timeout_s < 1 || e.timeout_s > MAX_TIMEOUT_S || e.max_output_tokens < 1 || e.max_output_tokens > MAX_OUTPUT_TOKENS { return Err(no("bad_request", "bad limits")); }
    Ok(())
}

/// Anything in a request that would make the host fetch, read or parse something on a model's behalf: an image that
/// isn't inline base64, or a document of any kind. None when the body is only text, tools and inline images.
pub fn media_problem(v: &Value) -> Option<String> {
    match v {
        Value::Object(o) => {
            let t = o.get("type").and_then(Value::as_str).unwrap_or("");
            match t {
                "image" => {
                    if o.get("source").and_then(|s| s.get("type")).and_then(Value::as_str) != Some("base64") {
                        return Some("an image must be inline (base64): this machine never fetches a URL for a model".into());
                    }
                }
                "image_url" | "input_image" => {
                    let u = o.get("image_url").map(|u| u.get("url").unwrap_or(u)).and_then(Value::as_str).unwrap_or("");
                    if !u.starts_with("data:image/") { return Some("an image must be inline (a data: URL): this machine never fetches a URL for a model".into()); }
                }
                "document" | "file" | "input_file" => {
                    return Some("documents are not sent to a local model: the pavilion extracts their text first".into());
                }
                _ => {}
            }
            o.values().find_map(media_problem)
        }
        Value::Array(a) => a.iter().find_map(media_problem),
        _ => None,
    }
}

/// The body the runtime gets: the model as named, `stream` as the envelope says, and the output capped whatever the
/// body asked for (`max_tokens`, and `max_completion_tokens` when present).
pub fn prepare_body(e: &Envelope) -> Result<Vec<u8>, Refusal> {
    let mut b: Value = serde_json::from_str(&e.body).map_err(|_| no("bad_request", "the body is not JSON"))?;
    if let Some(why) = media_problem(&b) { return Err(("bad_request", why)); }
    let cap = |v: &Value| v.as_u64().map_or(e.max_output_tokens, |n| n.min(e.max_output_tokens));
    let o = b.as_object_mut().ok_or(no("bad_request", "the body is not a JSON object"))?;
    let mt = cap(o.get("max_tokens").unwrap_or(&Value::Null));
    o.insert("max_tokens".into(), json!(mt));
    if let Some(m) = o.get("max_completion_tokens").cloned() { o.insert("max_completion_tokens".into(), json!(cap(&m))); }
    o.insert("stream".into(), json!(e.stream));
    serde_json::to_vec(&b).map_err(|_| no("bad_request", "the body could not be written"))
}

/* ---------------------------------------------------------------- batching */

/// Chunks are batched so a long answer is tens of socket messages, not thousands: incoming WebSocket messages bill at
/// 20:1 (docs/COSTS.md §2). A batch goes when it holds 8 KB or its first byte is 100 ms old, and is never cut inside a
/// UTF-8 character.
pub struct Batcher { buf: Vec<u8>, since: Option<Instant>, pub seq: u64, pub max_bytes: usize, pub max_wait: Duration }
/// The most one frame carries: well under the pavilion's 256 KB message limit.
pub const FRAME_MAX: usize = 64 * 1024;

impl Batcher {
    pub fn new(max_bytes: usize, max_wait: Duration) -> Batcher { Batcher { buf: vec![], since: None, seq: 0, max_bytes, max_wait } }
    pub fn push(&mut self, b: &[u8], now: Instant) {
        if b.is_empty() { return; }
        if self.buf.is_empty() { self.since = Some(now); }
        self.buf.extend_from_slice(b);
    }
    pub fn ready(&self, now: Instant) -> bool {
        !self.buf.is_empty() && (self.buf.len() >= self.max_bytes || self.since.is_some_and(|s| now.duration_since(s) >= self.max_wait))
    }
    pub fn pending(&self) -> usize { self.buf.len() }
    /// The next frame's seq and text: up to FRAME_MAX, ending on a whole character. `all` takes what is left even if
    /// it ends inside a character (the stream is over).
    pub fn take(&mut self, all: bool, now: Instant) -> Option<(u64, String)> {
        if self.buf.is_empty() { return None; }
        let mut cut = self.buf.len().min(FRAME_MAX);
        match std::str::from_utf8(&self.buf[..cut]) {
            Ok(_) => {}
            Err(e) if e.error_len().is_none() => { if !(all && cut == self.buf.len()) { cut = e.valid_up_to(); } }
            Err(_) => {} // invalid bytes: sent as they read (lossy), never held back forever
        }
        if cut == 0 { return None; }
        let text = String::from_utf8_lossy(&self.buf[..cut]).into_owned();
        self.buf.drain(..cut);
        self.since = if self.buf.is_empty() { None } else { Some(now) };
        self.seq += 1;
        Some((self.seq, text))
    }
}

/* ---------------------------------------------------------------- what the node saw used (a cross-check, not the bill) */

#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub struct Seen { pub input: u64, pub output: u64 }

/// Reads `usage` from SSE `data:` lines as they pass (and from a whole JSON body at the end).
#[derive(Default)]
pub struct UsageTap { line: String, whole: Vec<u8>, pub seen: Seen }
impl UsageTap {
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
        for u in [&v["usage"], &v["message"]["usage"]] {
            let n = |a: &str, b: &str| u[a].as_u64().or_else(|| u[b].as_u64());
            if let Some(i) = n("prompt_tokens", "input_tokens") { self.seen.input = self.seen.input.max(i); }
            if let Some(o) = n("completion_tokens", "output_tokens") { self.seen.output = self.seen.output.max(o); }
        }
    }
    pub fn finish(&mut self) -> Seen {
        if let Ok(v) = serde_json::from_slice::<Value>(&self.whole) { self.read(&v); }
        self.seen
    }
}

/* ---------------------------------------------------------------- running calls: slots, cancel */

pub struct Cancel { notify: Notify, reason: Mutex<Option<(&'static str, String)>> }
impl Cancel {
    pub fn new() -> Arc<Cancel> { Arc::new(Cancel { notify: Notify::new(), reason: Mutex::new(None) }) }
    pub fn fire(&self, code: &'static str, why: &str) {
        let mut r = self.reason.lock().unwrap();
        if r.is_none() { *r = Some((code, why.to_string())); }
        self.notify.notify_one();
    }
    fn reason(&self) -> (&'static str, String) { self.reason.lock().unwrap().clone().unwrap_or(("cancelled", "cancelled".into())) }
}

/// The calls running on this machine, by id. One per node in production (`global`); tests make their own.
#[derive(Default)]
pub struct Registry { m: Mutex<HashMap<String, Arc<Cancel>>> }

/// A taken slot; dropping it frees the slot.
pub struct Slot(Arc<Registry>, String);
impl Drop for Slot { fn drop(&mut self) { self.0.m.lock().unwrap().remove(&self.1); } }

impl Registry {
    /// Takes one of `slots` for call `id`, or None when every slot is busy. The pavilion's queue is the one queue: a
    /// busy machine answers `machine_busy` and the priority order moves on (docs/MODEL-ACCOUNTS.md §7.3).
    pub fn take_slot(self: &Arc<Self>, id: &str, slots: usize, cancel: Arc<Cancel>) -> Option<Slot> {
        let mut m = self.m.lock().unwrap();
        if m.len() >= slots.max(1) || m.contains_key(id) { return None; }
        m.insert(id.to_string(), cancel);
        Some(Slot(self.clone(), id.to_string()))
    }
    #[cfg(test)]
    pub fn running(&self) -> usize { self.m.lock().unwrap().len() }
    /// `model.cancel` from the Gate.
    pub fn cancel(&self, id: &str, why: &str) -> bool {
        let c = self.m.lock().unwrap().get(id).cloned();
        if let Some(c) = &c { c.fire("cancelled", why); }
        c.is_some()
    }
    /// Every running call: at red (the guard), when the link drops, when the machine goes to sleep.
    pub fn cancel_all(&self, code: &'static str, why: &str) -> usize {
        let all: Vec<Arc<Cancel>> = self.m.lock().unwrap().values().cloned().collect();
        for c in &all { c.fire(code, why); }
        all.len()
    }
    /// The guard changed level: at red or worse, running calls stop, like a job (docs/MODEL-ACCOUNTS.md §7.3).
    pub fn on_level(&self, l: Level) -> usize {
        if l < Level::Red { return 0; }
        self.cancel_all("guard", &format!("this machine's resource guard went {}", format!("{l:?}").to_lowercase()))
    }
}

pub fn global() -> &'static Arc<Registry> { static R: std::sync::OnceLock<Arc<Registry>> = std::sync::OnceLock::new(); R.get_or_init(Default::default) }
pub fn cancel(id: &str, why: &str) -> bool { global().cancel(id, why) }
pub fn cancel_all(code: &'static str, why: &str) -> usize { global().cancel_all(code, why) }
pub fn on_level(l: Level) { let n = global().on_level(l); if n > 0 { eprintln!("relay: the guard stopped {n} model call(s)"); } }

/* ---------------------------------------------------------------- settings (config.json, the owner's) */

/// The owner's settings on this machine: `model_relay` ("off" turns it off), `model_slots` (1–8, default 1),
/// `relay_models` (the only models offered, as `ollama:<name>` / `lmstudio:<key>`; absent means every local model).
#[derive(Clone, Debug)]
pub struct Settings { pub on: bool, pub slots: usize, pub only: Option<Vec<String>> }
pub fn settings_from(cfg: &Value) -> Settings {
    Settings {
        on: cfg["model_relay"].as_str() != Some("off") && cfg["model_relay"] != false,
        slots: cfg["model_slots"].as_u64().map_or(1, |n| (n as usize).clamp(1, MAX_SLOTS)),
        only: cfg["relay_models"].as_array().map(|a| a.iter().filter_map(|m| m.as_str().map(String::from)).collect()),
    }
}

/// Where each runtime listens: the default, or config.json's own address for it if that is loopback.
#[derive(Clone, Debug)]
pub struct Bases { pub ollama: String, pub lmstudio: String }
pub fn loopback(u: &str) -> bool { reqwest::Url::parse(u).is_ok_and(|u| matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")) && u.scheme() == "http") }
impl Bases {
    pub fn from_config(cfg: &Value) -> Bases {
        let pick = |k: &str, d: &str| cfg[k].as_str().filter(|u| loopback(u)).unwrap_or(d).trim_end_matches('/').to_string();
        Bases { ollama: pick("ollama_url", RUNTIMES[0].1), lmstudio: pick("lmstudio_url", RUNTIMES[1].1) }
    }
    pub fn of(&self, runtime: &str) -> Option<&str> { match runtime { "ollama" => Some(&self.ollama), "lmstudio" => Some(&self.lmstudio), _ => None } }
}

fn client(timeout: Option<Duration>) -> reqwest::Client {
    let b = reqwest::Client::builder().no_proxy();
    let b = match timeout { Some(t) => b.timeout(t), None => b };
    b.build().unwrap_or_default()
}

/// The models the runtimes have right now, as `ollama:<name>` and `lmstudio:<key>`: read at every call, so a model
/// removed since the last inventory is refused here and not by a confused runtime.
pub async fn local_ids(b: &Bases) -> Vec<String> {
    let c = client(Some(Duration::from_secs(3)));
    let mut out = vec![];
    if let Ok(j) = async { c.get(format!("{}/api/tags", b.ollama)).send().await?.json::<Value>().await }.await {
        for m in j["models"].as_array().cloned().unwrap_or_default() { if let Some(n) = m["name"].as_str().or(m["model"].as_str()) { out.push(format!("ollama:{n}")); } }
    }
    let v1 = async { let r = c.get(format!("{}/api/v1/models", b.lmstudio)).send().await?; r.error_for_status()?.json::<Value>().await }.await.ok();
    if let Some(j) = v1.filter(|j| j["models"].is_array() || j["data"].is_array()) {
        let list = j["models"].as_array().or(j["data"].as_array()).cloned().unwrap_or_default();
        for m in list { if m["type"] == "llm" { if let Some(k) = m["key"].as_str().or(m["id"].as_str()) { out.push(format!("lmstudio:{k}")); } } }
    } else if let Ok(j) = async { c.get(format!("{}/api/v0/models", b.lmstudio)).send().await?.json::<Value>().await }.await {
        for m in j["data"].as_array().cloned().unwrap_or_default() { if m["type"] == "llm" || m["type"] == "vlm" { if let Some(k) = m["id"].as_str() { out.push(format!("lmstudio:{k}")); } } }
    }
    out
}

/* ---------------------------------------------------------------- one call */

#[derive(Clone, Copy, Debug)]
pub struct Timing { pub idle: Duration, pub batch_wait: Duration, pub batch_bytes: usize }
impl Default for Timing { fn default() -> Timing { Timing { idle: Duration::from_secs(120), batch_wait: Duration::from_millis(100), batch_bytes: 8 * 1024 } } }

pub type Sink = mpsc::UnboundedSender<Value>;
fn err(out: &Sink, id: &str, code: &str, message: &str) { let _ = out.send(json!({ "t": "model.error", "id": id, "code": code, "message": message })); }

/// Calls the runtime on loopback and streams its answer back as frames. Ends with `model.end`, or `model.error` when
/// cancelled, timed out or the runtime failed. Holds its slot until it returns.
pub async fn run_call(e: Envelope, body: Vec<u8>, base: String, out: Sink, cancel: Arc<Cancel>, t: Timing, _slot: Slot) {
    let id = e.id.clone();
    let deadline = Instant::now() + Duration::from_secs(e.timeout_s);
    let mut rb = client(None).post(format!("{base}{}", e.path)).header("content-type", "application/json").body(body);
    if e.shape == "anthropic-messages" { rb = rb.header("anthropic-version", "2023-06-01"); }
    let wait = |d: Instant| d.min(Instant::now() + t.idle);
    // The first answer gets the idle limit too: loading a big model can take a minute.
    let res = tokio::select! {
        r = rb.send() => match r { Ok(r) => r, Err(x) => { err(&out, &id, "runtime_error", &format!("the local model server didn't answer: {}", x.without_url())); return; } },
        _ = cancel.notify.notified() => { let (c, w) = cancel.reason(); err(&out, &id, c, &w); return; }
        _ = tokio::time::sleep_until(wait(deadline).into()) => { err(&out, &id, "timeout", "the local model didn't start answering in time"); return; }
    };
    let ct = res.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("application/json").to_string();
    let _ = out.send(json!({ "t": "model.head", "id": id, "status": res.status().as_u16(), "headers": { "content-type": ct } }));
    let mut stream = res.bytes_stream();
    let mut b = Batcher::new(t.batch_bytes, t.batch_wait);
    let mut tap = UsageTap::default();
    let mut last = Instant::now();
    let mut tick = tokio::time::interval(t.batch_wait.min(Duration::from_millis(250)));
    let send = |b: &mut Batcher, all: bool, out: &Sink| { while let Some((seq, data)) = b.take(all, Instant::now()) { let _ = out.send(json!({ "t": "model.chunk", "id": id, "seq": seq, "data": data })); if !all && b.pending() < b.max_bytes { break; } } };
    loop {
        tokio::select! {
            c = stream.next() => match c {
                Some(Ok(bytes)) => {
                    let now = Instant::now();
                    last = now;
                    tap.feed(&bytes);
                    b.push(&bytes, now);
                    if b.ready(now) { send(&mut b, false, &out); }
                }
                Some(Err(x)) => { send(&mut b, true, &out); err(&out, &id, "runtime_error", &format!("the local model's stream broke: {}", x.without_url())); return; }
                None => break,
            },
            _ = tick.tick() => {
                let now = Instant::now();
                if b.ready(now) { send(&mut b, false, &out); }
                if now >= deadline { send(&mut b, true, &out); err(&out, &id, "timeout", &format!("the call ran past its {} s", e.timeout_s)); return; }
                if now.duration_since(last) >= t.idle { send(&mut b, true, &out); err(&out, &id, "timeout", &format!("the local model said nothing for {} s", t.idle.as_secs())); return; }
            }
            _ = cancel.notify.notified() => { send(&mut b, true, &out); let (c, w) = cancel.reason(); err(&out, &id, c, &w); return; }
        }
    }
    send(&mut b, true, &out);
    let s = tap.finish();
    let _ = out.send(json!({ "t": "model.end", "id": id, "seq": b.seq, "usage": { "input": s.input, "output": s.output } }));
}

/// Everything `handle` needs from the link, so it can be tested without one.
pub struct Ctx { pub reg: Arc<Registry>, pub pavilion_key: String, pub pavilion: String, pub machine: String, pub level: Level, pub out: Sink, pub bases: Bases, pub settings: Settings, pub timing: Timing }

/// `model.call` from the link: every check, then the call runs on its own task. Each refusal is a `model.error` with
/// its code, so the Gate can tell "try the next route" from "this request is wrong".
pub async fn handle(v: &Value, cx: Ctx) {
    let id = v["id"].as_str().unwrap_or_default().to_string();
    if id.is_empty() || id.len() > 100 { return; }
    let out = cx.out.clone();
    if !cx.settings.on { return err(&out, &id, "grant_refused", "this machine's owner turned the model relay off"); }
    if crate::state::paused() { return err(&out, &id, "grant_refused", "this machine's owner paused pavilion-node"); }
    let (payload, sig) = (v["payload"].as_str().unwrap_or_default(), v["sig"].as_str().unwrap_or_default());
    if !verify(&cx.pavilion_key, payload, sig) { eprintln!("relay: refused a model call with a bad signature"); return err(&out, &id, "grant_refused", "bad signature"); }
    let e = match open(payload) { Ok(e) => e, Err(w) => return err(&out, &id, "bad_request", &w) };
    if e.id != id { return err(&out, &id, "grant_refused", "the envelope is for another call"); }
    if cx.level >= Level::Amber { return err(&out, &id, "guard", &format!("this machine is at {}; it takes no new model calls until it's green", format!("{:?}", cx.level).to_lowercase())); }
    let mut models = local_ids(&cx.bases).await;
    if let Some(only) = &cx.settings.only { models.retain(|m| only.contains(m)); }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    if let Err((code, why)) = check(&e, &Expect { pavilion: &cx.pavilion, machine: &cx.machine, models: &models, now, max_body: MAX_BODY }) { return err(&out, &id, code, &why); }
    let body = match prepare_body(&e) { Ok(b) => b, Err((code, why)) => return err(&out, &id, code, &why) };
    let Some(base) = cx.bases.of(&e.runtime).map(String::from) else { return err(&out, &id, "bad_request", "unknown runtime") };
    let c = Cancel::new();
    let Some(slot) = cx.reg.take_slot(&id, cx.settings.slots, c.clone()) else {
        return err(&out, &id, "machine_busy", &format!("every model slot on this machine is busy ({} at once)", cx.settings.slots));
    };
    eprintln!("relay: {} {} for {} ({})", e.runtime, e.model, if e.by.is_empty() { "the pavilion" } else { &e.by }, e.path);
    tokio::spawn(run_call(e, body, base, out, c, cx.timing, slot));
}

#[cfg(test)]
pub(crate) mod standin {
    //! A stand-in local runtime on loopback, for tests: Ollama's `/api/tags`, `/api/show`, `/api/ps`, LM Studio's
    //! `/api/v1/models` and `/api/v0/models`, and streamed `/v1/chat/completions` and `/v1/messages` with tool calls.
    //! It records every request and notices when a client goes away mid-stream. No model, nothing downloaded.
    use bytes::Bytes;
    use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
    use hyper::body::{Frame, Incoming};
    use hyper::{Request, Response};
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Default)]
    pub struct Runtime {
        /// "ollama", or "lmstudio-v1" / "lmstudio-v0" for LM Studio with or without the newer list.
        pub kind: String,
        pub seen: Mutex<Vec<(String, String, Value)>>,
        /// Milliseconds between streamed events, and before the first one.
        pub gap_ms: AtomicU64,
        pub first_ms: AtomicU64,
        /// A stream's client went away before the end.
        pub dropped: AtomicBool,
        /// How many events a stream has (beyond the fixed ones): long answers for batching and cancel.
        pub extra: AtomicU64,
    }

    struct OnDrop(Arc<Runtime>, bool);
    impl Drop for OnDrop { fn drop(&mut self) { if !self.1 { self.0.dropped.store(true, Ordering::SeqCst); } } }
    impl OnDrop { fn finished(&mut self) { self.1 = true; } }

    type Body = BoxBody<Bytes, std::io::Error>;
    fn full(status: u16, ct: &str, s: String) -> Response<Body> {
        Response::builder().status(status).header("content-type", ct).body(Full::new(Bytes::from(s)).map_err(|e| match e {}).boxed()).unwrap()
    }
    fn sse(rt: Arc<Runtime>, events: Vec<String>) -> Response<Body> {
        let (gap, first) = (rt.gap_ms.load(Ordering::SeqCst), rt.first_ms.load(Ordering::SeqCst));
        let guard = OnDrop(rt, false);
        let s = futures_util::stream::unfold((events.into_iter(), 0usize, guard), move |(mut it, n, mut g)| async move {
            let e = it.next();
            match e {
                Some(e) => { tokio::time::sleep(Duration::from_millis(if n == 0 { first } else { gap })).await; Some((Ok::<_, std::io::Error>(Frame::data(Bytes::from(e))), (it, n + 1, g))) }
                None => { g.finished(); None }
            }
        });
        Response::builder().status(200).header("content-type", "text/event-stream").body(BodyExt::boxed(StreamBody::new(s))).unwrap()
    }

    pub fn chat_events(model: &str, tools: bool, extra: u64) -> Vec<String> {
        let d = |v: Value| format!("data: {v}\n\n");
        let mut ev = vec![d(json!({ "id": "c1", "object": "chat.completion.chunk", "model": model, "choices": [{ "index": 0, "delta": { "role": "assistant", "content": "" } }] }))];
        for i in 0..extra { ev.push(d(json!({ "id": "c1", "object": "chat.completion.chunk", "model": model, "choices": [{ "index": 0, "delta": { "content": format!("word{i} é ") } }] }))); }
        if tools {
            ev.push(d(json!({ "id": "c1", "object": "chat.completion.chunk", "model": model, "choices": [{ "index": 0, "delta": { "tool_calls": [{ "index": 0, "id": "call_1", "type": "function", "function": { "name": "get_weather", "arguments": "" } }] } }] })));
            ev.push(d(json!({ "id": "c1", "object": "chat.completion.chunk", "model": model, "choices": [{ "index": 0, "delta": { "tool_calls": [{ "index": 0, "function": { "arguments": "{\"city\":\"Lisbon\"}" } }] } }] })));
        } else {
            ev.push(d(json!({ "id": "c1", "object": "chat.completion.chunk", "model": model, "choices": [{ "index": 0, "delta": { "content": "hello" } }] })));
        }
        ev.push(d(json!({ "id": "c1", "object": "chat.completion.chunk", "model": model, "choices": [{ "index": 0, "delta": {}, "finish_reason": if tools { "tool_calls" } else { "stop" } }] })));
        ev.push(d(json!({ "id": "c1", "object": "chat.completion.chunk", "model": model, "choices": [], "usage": { "prompt_tokens": 42, "completion_tokens": 17, "total_tokens": 59 } })));
        ev.push("data: [DONE]\n\n".into());
        ev
    }
    pub fn messages_events(model: &str, tools: bool, extra: u64) -> Vec<String> {
        let d = |ty: &str, v: Value| format!("event: {ty}\ndata: {v}\n\n");
        let mut ev = vec![d("message_start", json!({ "type": "message_start", "message": { "id": "msg_1", "type": "message", "role": "assistant", "model": model, "content": [], "usage": { "input_tokens": 42, "output_tokens": 1 } } }))];
        ev.push(d("content_block_start", json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "text", "text": "" } })));
        for i in 0..extra { ev.push(d("content_block_delta", json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": format!("word{i} é ") } }))); }
        ev.push(d("content_block_delta", json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": "Let me look." } })));
        ev.push(d("content_block_stop", json!({ "type": "content_block_stop", "index": 0 })));
        if tools {
            ev.push(d("content_block_start", json!({ "type": "content_block_start", "index": 1, "content_block": { "type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {} } })));
            ev.push(d("content_block_delta", json!({ "type": "content_block_delta", "index": 1, "delta": { "type": "input_json_delta", "partial_json": "{\"city\":\"Lisbon\"}" } })));
            ev.push(d("content_block_stop", json!({ "type": "content_block_stop", "index": 1 })));
        }
        ev.push(d("message_delta", json!({ "type": "message_delta", "delta": { "stop_reason": if tools { "tool_use" } else { "end_turn" } }, "usage": { "output_tokens": 17 } })));
        ev.push(d("message_stop", json!({ "type": "message_stop" })));
        ev
    }

    async fn answer(rt: Arc<Runtime>, req: Request<Incoming>) -> Response<Body> {
        let (method, path) = (req.method().to_string(), req.uri().path().to_string());
        let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
        let j: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        rt.seen.lock().unwrap().push((method.clone(), path.clone(), j.clone()));
        let ollama = rt.kind == "ollama";
        let model = j["model"].as_str().unwrap_or("").to_string();
        let tools = j["tools"].as_array().is_some_and(|t| !t.is_empty());
        let extra = rt.extra.load(Ordering::SeqCst);
        match (method.as_str(), path.as_str()) {
            ("GET", "/api/tags") if ollama => full(200, "application/json", json!({ "models": [
                { "name": "qwen3:8b", "model": "qwen3:8b", "size": 5_200_000_000u64, "details": { "family": "qwen3", "parameter_size": "8.2B", "quantization_level": "Q4_K_M" } },
                { "name": "llava:7b", "model": "llava:7b", "size": 4_700_000_000u64, "details": { "family": "llama", "parameter_size": "7B" } },
                { "name": "nomic-embed-text:latest", "model": "nomic-embed-text:latest", "size": 274_000_000u64 } ] }).to_string()),
            ("POST", "/api/show") if ollama => {
                let caps = match j["model"].as_str() { Some("qwen3:8b") => json!(["completion", "tools", "thinking"]), Some("llava:7b") => json!(["completion", "vision"]), _ => json!(["embedding"]) };
                // The real answer carries the whole tokenizer and the model file; the node keeps none of it.
                full(200, "application/json", json!({ "capabilities": caps, "modelfile": "FROM x\n".repeat(200), "template": "{{ .Prompt }}", "license": "L".repeat(5000),
                    "details": { "family": "qwen3" }, "model_info": { "general.architecture": "qwen3", "qwen3.context_length": 40960, "tokenizer.ggml.tokens": vec!["tok"; 5000] } }).to_string())
            }
            ("GET", "/api/ps") if ollama => full(200, "application/json", json!({ "models": [{ "name": "qwen3:8b", "model": "qwen3:8b", "size_vram": 5_000_000_000u64, "context_length": 4096 }] }).to_string()),
            ("GET", "/api/v1/models") if rt.kind == "lmstudio-v1" => full(200, "application/json", json!({ "models": [
                { "type": "llm", "key": "qwen/qwen3-vl-8b", "display_name": "Qwen3 VL 8B", "capabilities": { "vision": true, "trained_for_tool_use": true }, "loaded_instances": [{ "id": "x" }], "max_context_length": 32768, "size_bytes": 6_000_000_000u64 },
                { "type": "embedding", "key": "text-embedding-nomic" } ] }).to_string()),
            ("GET", "/api/v0/models") if rt.kind.starts_with("lmstudio") => full(200, "application/json", json!({ "data": [
                { "id": "qwen/qwen3-vl-8b", "type": "vlm", "state": "loaded", "max_context_length": 32768 }, { "id": "text-embedding-nomic", "type": "embeddings" } ] }).to_string()),
            ("POST", "/v1/chat/completions") if j["stream"] == true => sse(rt.clone(), chat_events(&model, tools, extra)),
            ("POST", "/v1/messages") if j["stream"] == true => sse(rt.clone(), messages_events(&model, tools, extra)),
            ("POST", "/v1/chat/completions") => full(200, "application/json", json!({ "id": "c2", "object": "chat.completion", "model": model, "choices": [{ "index": 0, "message": { "role": "assistant", "content": "hi" }, "finish_reason": "stop" }], "usage": { "prompt_tokens": 9, "completion_tokens": 2 } }).to_string()),
            ("POST", "/v1/messages") => full(200, "application/json", json!({ "id": "msg_2", "type": "message", "model": model, "content": [{ "type": "text", "text": "hi" }], "usage": { "input_tokens": 9, "output_tokens": 2 } }).to_string()),
            // What the relay must never reach: it answers, so a test can tell it was never asked.
            ("POST", "/api/pull") | ("DELETE", "/api/delete") | ("POST", "/api/push") | ("POST", "/api/create") => full(200, "application/json", "{\"status\":\"success\"}".into()),
            _ => full(404, "application/json", "{\"error\":\"not found\"}".into()),
        }
    }

    /// Starts one on a free loopback port; returns it and its base URL.
    pub async fn start(kind: &str) -> (Arc<Runtime>, String) {
        let rt = Arc::new(Runtime { kind: kind.into(), ..Default::default() });
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let r2 = rt.clone();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { break };
                let rt = r2.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req| { let rt = rt.clone(); async move { Ok::<_, std::convert::Infallible>(answer(rt, req).await) } });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
                });
            }
        });
        (rt, format!("http://127.0.0.1:{port}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::b64;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::atomic::Ordering;

    fn now() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 }
    fn env(id: &str, shape: &str, model: &str, body: Value) -> Envelope {
        let path = PATHS.iter().find(|(s, _)| *s == shape).unwrap().1;
        Envelope { v: 1, t: "model.call".into(), id: id.into(), pavilion: "pv".into(), machine: "mch_a".into(), by: "job:job_x".into(), issued_at: now(), expires_at: now() + 60_000,
            runtime: "ollama".into(), model: model.into(), shape: shape.into(), path: path.into(), stream: true, body: body.to_string(), max_output_tokens: 4096, timeout_s: 600 }
    }
    fn to_json(e: &Envelope) -> Value {
        json!({ "v": e.v, "t": e.t, "id": e.id, "pavilion": e.pavilion, "machine": e.machine, "by": e.by, "issuedAt": e.issued_at, "expiresAt": e.expires_at, "runtime": e.runtime,
            "model": e.model, "shape": e.shape, "path": e.path, "stream": e.stream, "body": e.body, "maxOutputTokens": e.max_output_tokens, "timeoutS": e.timeout_s })
    }
    fn signed(k: &SigningKey, e: &Envelope) -> Value {
        let payload = b64(to_json(e).to_string().as_bytes());
        let sig = k.sign(format!("pavilion-model-v1\n{payload}").as_bytes());
        json!({ "t": "model.call", "id": e.id, "payload": payload, "sig": b64(&sig.to_bytes()) })
    }
    fn models() -> Vec<String> { vec!["ollama:qwen3:8b".into(), "ollama:llava:7b".into()] }
    fn x<'a>(m: &'a [String]) -> Expect<'a> { Expect { pavilion: "pv", machine: "mch_a", models: m, now: now(), max_body: MAX_BODY } }
    fn ctx(k: &SigningKey, base: &str, out: Sink, slots: usize, level: Level, t: Timing) -> Ctx { ctx_in(&Arc::new(Registry::default()), k, base, out, slots, level, t) }
    fn ctx_in(reg: &Arc<Registry>, k: &SigningKey, base: &str, out: Sink, slots: usize, level: Level, t: Timing) -> Ctx {
        Ctx { reg: reg.clone(), pavilion_key: b64(k.verifying_key().as_bytes()), pavilion: "pv".into(), machine: "mch_a".into(), level, out, bases: Bases { ollama: base.into(), lmstudio: "http://127.0.0.1:9".into() },
            settings: Settings { on: true, slots, only: None }, timing: t }
    }
    async fn frames(rx: &mut mpsc::UnboundedReceiver<Value>, ms: u64) -> Vec<Value> {
        let mut v = vec![];
        let end = Instant::now() + Duration::from_millis(ms);
        loop {
            match tokio::time::timeout_at(end.into(), rx.recv()).await {
                Ok(Some(f)) => { let last = f["t"] == "model.end" || f["t"] == "model.error"; v.push(f); if last { break; } }
                _ => break,
            }
        }
        v
    }
    fn text(f: &[Value]) -> String { f.iter().filter(|x| x["t"] == "model.chunk").map(|x| x["data"].as_str().unwrap_or("").to_string()).collect() }

    /// Every rule of `checkEnvelope`, mirrored, with its sentence; and the signature with its own prefix.
    #[test]
    fn envelopes_are_checked_like_the_gate_checks_them() {
        let m = models();
        let good = env("rel_1", "openai-chat", "qwen3:8b", json!({ "model": "qwen3:8b", "messages": [] }));
        assert_eq!(check(&good, &x(&m)), Ok(()));
        let bad = |f: &dyn Fn(&mut Envelope)| { let mut e = good.clone(); f(&mut e); check(&e, &x(&m)).unwrap_err().1 };
        assert_eq!(bad(&|e| e.t = "model.cancel".into()), "not a model call");
        assert_eq!(bad(&|e| e.machine = "mch_b".into()), "not for this machine");
        assert_eq!(bad(&|e| e.pavilion = "other".into()), "not for this machine");
        assert_eq!(bad(&|e| e.expires_at = now() - 1), "expired or from the future");
        assert_eq!(bad(&|e| e.issued_at = now() + 120_000), "expired or from the future");
        assert_eq!(bad(&|e| e.expires_at = e.issued_at + 3_600_000), "an envelope lives at most two minutes");
        assert_eq!(bad(&|e| e.runtime = "vllm".into()), "unknown runtime");
        assert_eq!(bad(&|e| { e.model = "llama3:70b".into(); e.body = json!({ "model": "llama3:70b" }).to_string(); }), "that model is not offered from this machine");
        assert_eq!(bad(&|e| e.path = "/api/pull".into()), "that path is not allowed");
        assert_eq!(bad(&|e| e.path = "/v1/messages".into()), "that path is not allowed"); // the path must match the shape
        assert_eq!(bad(&|e| e.body = "x".repeat(MAX_BODY + 1)), "the request is too large");
        assert_eq!(bad(&|e| e.body = "{not json".into()), "the body is not JSON");
        assert_eq!(bad(&|e| e.body = json!({ "model": "llava:7b" }).to_string()), "the body names another model");
        assert_eq!(bad(&|e| e.timeout_s = 0), "bad limits");
        assert_eq!(bad(&|e| e.timeout_s = 1801), "bad limits");
        assert_eq!(bad(&|e| e.max_output_tokens = 0), "bad limits");
        assert_eq!(check(&good, &x(&m[1..])).unwrap_err().0, "model_missing");
        // The signature: the pavilion's key, the model prefix (a job signature is not a model signature), the bytes.
        let k = SigningKey::from_bytes(&[3u8; 32]);
        let s = signed(&k, &good);
        let pk = b64(k.verifying_key().as_bytes());
        assert!(verify(&pk, s["payload"].as_str().unwrap(), s["sig"].as_str().unwrap()));
        let job_sig = b64(&k.sign(format!("pavilion-job-v1\n{}", s["payload"].as_str().unwrap()).as_bytes()).to_bytes());
        assert!(!verify(&pk, s["payload"].as_str().unwrap(), &job_sig));
        assert!(!verify(&b64(SigningKey::from_bytes(&[4u8; 32]).verifying_key().as_bytes()), s["payload"].as_str().unwrap(), s["sig"].as_str().unwrap()));
        let e = open(s["payload"].as_str().unwrap()).unwrap();
        assert_eq!((e.id.as_str(), e.max_output_tokens, e.stream), ("rel_1", 4096, true));
    }

    /// Images go inline as base64 only; documents never reach a local model; the output is capped whatever the body says.
    #[test]
    fn bodies_carry_inline_images_only_and_a_capped_output() {
        let img = json!({ "type": "image", "source": { "type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo=" } });
        let ok = env("rel_1", "anthropic-messages", "llava:7b", json!({ "model": "llava:7b", "max_tokens": 100_000, "messages": [{ "role": "user", "content": [img, { "type": "text", "text": "what is this?" }] }] }));
        let b: Value = serde_json::from_slice(&prepare_body(&ok).unwrap()).unwrap();
        assert_eq!((b["max_tokens"].as_u64(), b["stream"].as_bool(), b["model"].as_str()), (Some(4096), Some(true), Some("llava:7b")));
        assert_eq!(b["messages"][0]["content"][0]["source"]["data"], "iVBORw0KGgo=");
        let small = env("rel_1", "openai-chat", "qwen3:8b", json!({ "model": "qwen3:8b", "max_completion_tokens": 50, "messages": [] }));
        let b: Value = serde_json::from_slice(&prepare_body(&small).unwrap()).unwrap();
        assert_eq!((b["max_tokens"].as_u64(), b["max_completion_tokens"].as_u64()), (Some(4096), Some(50)));
        let data_url = json!({ "model": "llava:7b", "messages": [{ "role": "user", "content": [{ "type": "image_url", "image_url": { "url": "data:image/png;base64,iVBORw0KGgo=" } }] }] });
        assert!(prepare_body(&env("rel_1", "openai-chat", "llava:7b", data_url)).is_ok());
        for (shape, part, says) in [
            ("anthropic-messages", json!({ "type": "image", "source": { "type": "url", "url": "http://169.254.169.254/latest" } }), "inline (base64)"),
            ("openai-chat", json!({ "type": "image_url", "image_url": { "url": "https://example.com/cat.png" } }), "inline (a data: URL)"),
            ("openai-chat", json!({ "type": "image_url", "image_url": { "url": "file:///etc/passwd" } }), "inline (a data: URL)"),
            ("anthropic-messages", json!({ "type": "document", "source": { "type": "base64", "media_type": "application/pdf", "data": "JVBERi0=" } }), "extracts their text first"),
            ("openai-chat", json!({ "type": "file", "file": { "file_data": "data:application/pdf;base64,JVBERi0=" } }), "extracts their text first"),
        ] {
            let e = env("rel_1", shape, "llava:7b", json!({ "model": "llava:7b", "messages": [{ "role": "user", "content": [part] }] }));
            let (code, why) = prepare_body(&e).unwrap_err();
            assert!(code == "bad_request" && why.contains(says), "{why}");
        }
        // Nested inside a tool result too.
        let nested = json!({ "model": "llava:7b", "messages": [{ "role": "user", "content": [{ "type": "tool_result", "tool_use_id": "t", "content": [{ "type": "image", "source": { "type": "url", "url": "https://x/y.png" } }] }] }] });
        assert!(prepare_body(&env("rel_1", "anthropic-messages", "llava:7b", nested)).is_err());
    }

    /// Batches go at 8 KB or after 100 ms, are numbered from 1, and never split a character.
    #[test]
    fn chunks_are_batched_numbered_and_whole_characters() {
        let t0 = Instant::now();
        let mut b = Batcher::new(8 * 1024, Duration::from_millis(100));
        b.push(b"data: a\n\n", t0);
        assert!(!b.ready(t0) && !b.ready(t0 + Duration::from_millis(99)) && b.ready(t0 + Duration::from_millis(100)));
        assert_eq!(b.take(false, t0), Some((1, "data: a\n\n".into())));
        assert_eq!(b.take(false, t0), None);
        // 200 small events in one window: one frame, not 200.
        for _ in 0..200 { b.push(b"data: {\"x\":1}\n\n", t0); }
        assert!(!b.ready(t0));
        let (seq, s) = b.take(false, t0).unwrap();
        assert_eq!((seq, s.matches("data:").count()), (2, 200));
        // Over 8 KB: ready at once.
        b.push(&vec![b'x'; 9000], t0);
        assert!(b.ready(t0));
        assert_eq!(b.take(false, t0).unwrap().1.len(), 9000);
        // "é" is two bytes; a batch that ends between them holds the first byte back until the second arrives.
        let e = "é".as_bytes();
        b.push(b"ab", t0); b.push(&e[..1], t0);
        assert_eq!(b.take(false, t0), Some((4, "ab".into())));
        assert_eq!(b.pending(), 1);
        b.push(&e[1..], t0);
        assert_eq!(b.take(false, t0), Some((5, "é".into())));
        // A frame never exceeds 64 KB.
        b.push(&vec![b'y'; 150 * 1024], t0);
        let sizes: Vec<usize> = std::iter::from_fn(|| b.take(false, t0)).map(|(_, s)| s.len()).collect();
        assert_eq!(sizes, vec![FRAME_MAX, FRAME_MAX, 150 * 1024 - 2 * FRAME_MAX]);
        let mut u = UsageTap::default();
        for e in standin::chat_events("m", true, 3) { u.feed(e.as_bytes()); }
        assert_eq!(u.finish(), Seen { input: 42, output: 17 });
        let mut u = UsageTap::default();
        for e in standin::messages_events("m", true, 0) { for c in e.as_bytes().chunks(7) { u.feed(c); } }
        assert_eq!(u.finish(), Seen { input: 42, output: 17 });
    }

    #[test]
    fn owner_settings_and_loopback_only() {
        let s = settings_from(&json!({}));
        assert!(s.on && s.slots == 1 && s.only.is_none());
        let s = settings_from(&json!({ "model_relay": "off", "model_slots": 99, "relay_models": ["ollama:qwen3:8b"] }));
        assert!(!s.on && s.slots == MAX_SLOTS && s.only.as_deref() == Some(&["ollama:qwen3:8b".to_string()][..]));
        assert_eq!(settings_from(&json!({ "model_slots": 0 })).slots, 1);
        let b = Bases::from_config(&json!({ "ollama_url": "http://192.168.1.5:11434", "lmstudio_url": "http://localhost:4321/" }));
        assert_eq!((b.ollama.as_str(), b.lmstudio.as_str()), ("http://127.0.0.1:11434", "http://localhost:4321"));
        assert!(!loopback("https://127.0.0.1:1234") && !loopback("http://127.0.0.1.evil.example") && loopback("http://[::1]:11434"));
    }

    /// A streamed answer with a tool call, in both shapes: the runtime gets the allowed path only, the frames come back
    /// numbered and in order, the text is the runtime's own bytes, and `model.end` carries the usage seen.
    #[tokio::test]
    async fn a_call_streams_back_in_both_shapes_with_tool_calls() {
        let (rt, base) = standin::start("ollama").await;
        let k = SigningKey::from_bytes(&[9u8; 32]);
        let reg = Arc::new(Registry::default());
        for (n, shape) in ["openai-chat", "anthropic-messages"].into_iter().enumerate() {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let tools = json!([{ "type": "function", "function": { "name": "get_weather", "parameters": { "type": "object" } } }]);
            let e = env(&format!("rel_s{n}"), shape, "qwen3:8b", json!({ "model": "qwen3:8b", "stream": true, "tools": tools, "messages": [{ "role": "user", "content": "weather in Lisbon?" }] }));
            handle(&signed(&k, &e), ctx_in(&reg, &k, &base, tx, 1, Level::Green, Timing::default())).await;
            let f = frames(&mut rx, 5000).await;
            assert_eq!(f[0]["t"], "model.head", "{f:?}");
            assert_eq!((f[0]["status"].as_u64(), f[0]["headers"]["content-type"].as_str()), (Some(200), Some("text/event-stream")));
            let end = f.last().unwrap();
            assert_eq!(end["t"], "model.end", "{f:?}");
            let seqs: Vec<u64> = f.iter().filter(|x| x["t"] == "model.chunk").map(|x| x["seq"].as_u64().unwrap()).collect();
            assert!(!seqs.is_empty() && seqs.iter().enumerate().all(|(i, s)| *s == i as u64 + 1) && end["seq"] == *seqs.last().unwrap(), "{seqs:?}");
            let t = text(&f);
            if shape == "openai-chat" { assert!(t.contains("\"tool_calls\"") && t.contains("get_weather") && t.ends_with("data: [DONE]\n\n"), "{t}"); }
            else { assert!(t.contains("\"tool_use\"") && t.contains("input_json_delta") && t.contains("message_stop"), "{t}"); }
            assert_eq!((end["usage"]["input"].as_u64(), end["usage"]["output"].as_u64()), (Some(42), Some(17)));
        }
        let seen = rt.seen.lock().unwrap().clone();
        let calls: Vec<String> = seen.iter().filter(|(_, p, _)| p.starts_with("/v1/")).map(|(m, p, _)| format!("{m} {p}")).collect();
        assert_eq!(calls, vec!["POST /v1/chat/completions", "POST /v1/messages"]);
        assert!(seen.iter().filter(|(_, p, _)| p.starts_with("/v1/")).all(|(_, _, b)| b["max_tokens"] == 4096 && b["tools"].is_array()));
        assert_eq!(reg.running(), 0);
    }

    /// An image request reaches the runtime as the same base64; a URL image never does.
    #[tokio::test]
    async fn an_image_request_goes_inline_and_a_url_is_refused() {
        let (rt, base) = standin::start("ollama").await;
        let k = SigningKey::from_bytes(&[10u8; 32]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let img = json!({ "type": "image", "source": { "type": "base64", "media_type": "image/png", "data": "iVBORw0KGgoAAAANSUhEUg==" } });
        let e = env("rel_img", "anthropic-messages", "llava:7b", json!({ "model": "llava:7b", "stream": true, "messages": [{ "role": "user", "content": [img, { "type": "text", "text": "what is it?" }] }] }));
        handle(&signed(&k, &e), ctx(&k, &base, tx.clone(), 1, Level::Green, Timing::default())).await;
        let f = frames(&mut rx, 5000).await;
        assert_eq!(f.last().unwrap()["t"], "model.end", "{f:?}");
        let got = rt.seen.lock().unwrap().iter().rev().find(|(_, p, _)| p == "/v1/messages").unwrap().2.clone();
        assert_eq!(got["messages"][0]["content"][0]["source"]["data"], "iVBORw0KGgoAAAANSUhEUg==");
        let before = rt.seen.lock().unwrap().len();
        let url = json!({ "type": "image", "source": { "type": "url", "url": "http://127.0.0.1:11434/api/pull" } });
        let e = env("rel_url", "anthropic-messages", "llava:7b", json!({ "model": "llava:7b", "messages": [{ "role": "user", "content": [url] }] }));
        handle(&signed(&k, &e), ctx(&k, &base, tx, 1, Level::Green, Timing::default())).await;
        let f = frames(&mut rx, 2000).await;
        assert!(f.len() == 1 && f[0]["code"] == "bad_request" && f[0]["message"].as_str().unwrap().contains("never fetches"), "{f:?}");
        assert!(rt.seen.lock().unwrap()[before..].iter().all(|(_, p, _)| p == "/api/tags"), "only the model list was read");
    }

    /// Only the two chat paths: an envelope for `/api/pull` (or any other path) is refused and nothing reaches the runtime
    /// but its model list; a bad signature, a model the runtime doesn't have, and the owner's own limit are refused too.
    #[tokio::test]
    async fn only_allow_listed_paths_and_offered_models() {
        let (rt, base) = standin::start("ollama").await;
        let k = SigningKey::from_bytes(&[11u8; 32]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        for path in ["/api/pull", "/api/delete", "/api/push", "/api/create", "/api/chat", "/v1/embeddings", "/v1/chat/completions/../../api/pull"] {
            let mut e = env("rel_p", "openai-chat", "qwen3:8b", json!({ "model": "qwen3:8b", "name": "evil/model" }));
            e.path = path.into();
            handle(&signed(&k, &e), ctx(&k, &base, tx.clone(), 1, Level::Green, Timing::default())).await;
            let f = frames(&mut rx, 2000).await;
            assert!(f.len() == 1 && f[0]["code"] == "grant_refused" && f[0]["message"] == "that path is not allowed", "{path}: {f:?}");
        }
        assert!(rt.seen.lock().unwrap().iter().all(|(m, p, _)| m == "GET" && p == "/api/tags"), "{:?}", rt.seen.lock().unwrap());
        // Signed by another key.
        let e = env("rel_k", "openai-chat", "qwen3:8b", json!({ "model": "qwen3:8b" }));
        handle(&signed(&SigningKey::from_bytes(&[12u8; 32]), &e), ctx(&k, &base, tx.clone(), 1, Level::Green, Timing::default())).await;
        assert_eq!(frames(&mut rx, 1000).await[0]["message"], "bad signature");
        // A model the runtime doesn't have.
        let e = env("rel_m", "openai-chat", "llama3:70b", json!({ "model": "llama3:70b" }));
        handle(&signed(&k, &e), ctx(&k, &base, tx.clone(), 1, Level::Green, Timing::default())).await;
        assert_eq!(frames(&mut rx, 1000).await[0]["code"], "model_missing");
        // The owner offers only qwen3 here: llava is refused although the runtime has it.
        let e = env("rel_o", "openai-chat", "llava:7b", json!({ "model": "llava:7b" }));
        let mut c = ctx(&k, &base, tx.clone(), 1, Level::Green, Timing::default());
        c.settings.only = Some(vec!["ollama:qwen3:8b".into()]);
        handle(&signed(&k, &e), c).await;
        assert_eq!(frames(&mut rx, 1000).await[0]["code"], "model_missing");
        // The relay turned off on this machine.
        let mut c = ctx(&k, &base, tx, 1, Level::Green, Timing::default());
        c.settings.on = false;
        handle(&signed(&k, &e), c).await;
        assert!(frames(&mut rx, 1000).await[0]["message"].as_str().unwrap().contains("turned the model relay off"));
    }

    /// One at a time by default: a second call while one runs is `machine_busy`; amber refuses new calls; red stops the
    /// running one with `guard`; a slot frees when its call ends.
    #[tokio::test]
    async fn slots_and_the_guard() {
        let (rt, base) = standin::start("ollama").await;
        rt.gap_ms.store(100, Ordering::SeqCst);
        rt.extra.store(30, Ordering::SeqCst);
        let k = SigningKey::from_bytes(&[13u8; 32]);
        let reg = Arc::new(Registry::default());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let call = |id: &str| signed(&k, &env(id, "openai-chat", "qwen3:8b", json!({ "model": "qwen3:8b", "stream": true, "messages": [] })));
        handle(&call("rel_g1"), ctx_in(&reg, &k, &base, tx.clone(), 1, Level::Green, Timing::default())).await;
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        handle(&call("rel_g2"), ctx_in(&reg, &k, &base, tx2.clone(), 1, Level::Green, Timing::default())).await;
        let f = frames(&mut rx2, 1000).await;
        assert!(f[0]["code"] == "machine_busy" && f[0]["message"].as_str().unwrap().contains("1 at once"), "{f:?}");
        // Amber: no new call, even with a free slot.
        handle(&call("rel_g3"), ctx_in(&reg, &k, &base, tx2.clone(), 4, Level::Amber, Timing::default())).await;
        assert_eq!(frames(&mut rx2, 1000).await[0]["code"], "guard");
        // Red: the running call stops.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(reg.on_level(Level::Amber), 0);
        assert_eq!(reg.on_level(Level::Red), 1);
        let f = frames(&mut rx, 3000).await;
        let last = f.last().unwrap();
        assert!(last["t"] == "model.error" && last["code"] == "guard" && last["message"].as_str().unwrap().contains("red"), "{f:?}");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(reg.running(), 0);
        assert!(rt.dropped.load(Ordering::SeqCst), "the loopback request was dropped");
        // Two slots: two at once.
        rt.gap_ms.store(5, Ordering::SeqCst);
        handle(&call("rel_g4"), ctx_in(&reg, &k, &base, tx.clone(), 2, Level::Green, Timing::default())).await;
        handle(&call("rel_g5"), ctx_in(&reg, &k, &base, tx2.clone(), 2, Level::Green, Timing::default())).await;
        assert_eq!(frames(&mut rx, 5000).await.last().unwrap()["t"], "model.end");
        assert_eq!(frames(&mut rx2, 5000).await.last().unwrap()["t"], "model.end");
    }

    /// `model.cancel` stops a call mid-stream: the frames end with `cancelled`, and the runtime sees its client go.
    #[tokio::test]
    async fn cancel_drops_the_loopback_request() {
        let (rt, base) = standin::start("ollama").await;
        rt.gap_ms.store(100, Ordering::SeqCst);
        rt.extra.store(50, Ordering::SeqCst);
        let k = SigningKey::from_bytes(&[14u8; 32]);
        let reg = Arc::new(Registry::default());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let e = env("rel_c1", "anthropic-messages", "qwen3:8b", json!({ "model": "qwen3:8b", "stream": true, "messages": [] }));
        handle(&signed(&k, &e), ctx_in(&reg, &k, &base, tx, 1, Level::Green, Timing::default())).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(reg.cancel("rel_c1", "the caller went away"));
        assert!(!reg.cancel("rel_nope", "x"));
        let f = frames(&mut rx, 3000).await;
        let last = f.last().unwrap();
        assert!(last["t"] == "model.error" && last["code"] == "cancelled" && last["message"] == "the caller went away", "{f:?}");
        assert!(f.iter().any(|x| x["t"] == "model.chunk"), "some text came first");
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(rt.dropped.load(Ordering::SeqCst));
        assert_eq!(reg.running(), 0);
    }

    /// Timeouts: an idle stream is cancelled; the whole call has its limit; an expired envelope never starts.
    #[tokio::test]
    async fn timeouts() {
        let (rt, base) = standin::start("ollama").await;
        let k = SigningKey::from_bytes(&[15u8; 32]);
        let quick = Timing { idle: Duration::from_millis(300), batch_wait: Duration::from_millis(50), batch_bytes: 8 * 1024 };
        // Nothing for longer than the idle limit before the first byte.
        rt.first_ms.store(1000, Ordering::SeqCst);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let e = env("rel_t1", "openai-chat", "qwen3:8b", json!({ "model": "qwen3:8b", "stream": true, "messages": [] }));
        handle(&signed(&k, &e), ctx(&k, &base, tx.clone(), 1, Level::Green, quick)).await;
        let f = frames(&mut rx, 3000).await;
        let last = f.last().unwrap();
        assert!(last["code"] == "timeout" && last["message"].as_str().unwrap().contains("said nothing"), "{f:?}");
        // A gap mid-stream longer than the idle limit.
        rt.first_ms.store(0, Ordering::SeqCst);
        rt.gap_ms.store(800, Ordering::SeqCst);
        let e = env("rel_t2", "openai-chat", "qwen3:8b", json!({ "model": "qwen3:8b", "stream": true, "messages": [] }));
        handle(&signed(&k, &e), ctx(&k, &base, tx.clone(), 1, Level::Green, quick)).await;
        let f = frames(&mut rx, 3000).await;
        assert_eq!(f.last().unwrap()["code"], "timeout", "{f:?}");
        assert!(f.iter().any(|x| x["t"] == "model.head"));
        // The whole call's limit: 1 s, with a stream that never goes idle but never ends.
        rt.gap_ms.store(100, Ordering::SeqCst);
        rt.extra.store(100, Ordering::SeqCst);
        let mut e = env("rel_t3", "openai-chat", "qwen3:8b", json!({ "model": "qwen3:8b", "stream": true, "messages": [] }));
        e.timeout_s = 1;
        handle(&signed(&k, &e), ctx(&k, &base, tx.clone(), 1, Level::Green, quick)).await;
        let f = frames(&mut rx, 4000).await;
        let last = f.last().unwrap();
        assert!(last["code"] == "timeout" && last["message"].as_str().unwrap().contains("past its 1 s"), "{f:?}");
        // An envelope that expired on the way: refused before the runtime is called.
        let calls = rt.seen.lock().unwrap().iter().filter(|(_, p, _)| p.starts_with("/v1/")).count();
        let mut e = env("rel_t4", "openai-chat", "qwen3:8b", json!({ "model": "qwen3:8b" }));
        e.issued_at = now() - 61_000; e.expires_at = now() - 1_000;
        handle(&signed(&k, &e), ctx(&k, &base, tx, 1, Level::Green, quick)).await;
        assert_eq!(frames(&mut rx, 1000).await[0]["message"], "expired or from the future");
        assert_eq!(rt.seen.lock().unwrap().iter().filter(|(_, p, _)| p.starts_with("/v1/")).count(), calls);
    }

    /// A long answer is a few batched frames, not one per event.
    #[tokio::test]
    async fn a_long_answer_is_few_frames() {
        let (rt, base) = standin::start("ollama").await;
        rt.extra.store(400, Ordering::SeqCst);
        let k = SigningKey::from_bytes(&[16u8; 32]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let e = env("rel_l", "openai-chat", "qwen3:8b", json!({ "model": "qwen3:8b", "stream": true, "messages": [] }));
        handle(&signed(&k, &e), ctx(&k, &base, tx, 1, Level::Green, Timing::default())).await;
        let f = frames(&mut rx, 5000).await;
        let chunks = f.iter().filter(|x| x["t"] == "model.chunk").count();
        let t = text(&f);
        assert_eq!(t.matches("data: ").count(), 405);
        assert!(chunks <= 16 && t.len() > 40_000, "{chunks} frames for {} bytes", t.len());
        assert!(t.contains("word399 é"));
    }
}
