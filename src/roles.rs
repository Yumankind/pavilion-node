//! The host role (docs/HOST-AND-VOICE.md §1): when an owner makes this machine the host, it runs the Steward and the
//! orchestrators of chosen projects, each in a long-lived sandbox of its own that doesn't time out while the role is here.
//! Every 30 s (and whenever the pavilion nudges) the node renews its roles at the Gate, which answers what to run and,
//! for the roles this machine holds, the lease epoch and the model grant. Each sandbox runs Claude Code turns with only
//! the pavilion's tools, reached through its own broker (signed by this machine, with the epoch). The model key stays in
//! the Gate; an orchestrator may use a local model (Ollama) instead, when one is set up. A sandbox that dies is started again;
//! one whose role leaves is removed; at red or critical every one stops, the node stops renewing, and the lease moves
//! to the cloud.
use crate::broker::{Broker, Grant, RoleDoor};
use crate::guard::Level;
use crate::signing::signed_headers;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Mutex, Notify};

/// Memory each role's sandbox gets (Claude Code and Node.js).
pub const ROLE_MEMORY_MIB: u64 = 2048;
const RENEW: Duration = Duration::from_secs(30);
/// Not the host: look again when nudged, or every 5 minutes.
const IDLE: Duration = Duration::from_secs(300);
const DEFAULT_IMAGE: &str = "docker.io/library/node:24-bookworm-slim";

/// How long a renewal waits for its answer on the socket before going over HTTP instead.
const SOCKET_WAIT: Duration = Duration::from_secs(10);

static NUDGE: Notify = Notify::const_new();
static MEMORY: AtomicU64 = AtomicU64::new(0);
/// The link's channel to the pavilion while its socket is up (link.rs owns the socket and sets this).
static SOCKET: std::sync::Mutex<Option<mpsc::UnboundedSender<Value>>> = std::sync::Mutex::new(None);
/// Renewals sent on the socket, by id, waiting for their answer.
static WAITING: std::sync::Mutex<BTreeMap<u64, oneshot::Sender<Value>>> = std::sync::Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
/// The pavilion said something changed (a role, a queued turn, an orchestrator wake-up): renew and look for work now.
pub fn nudge() { NUDGE.notify_one(); }
/// link.rs: the socket is up, and renewals may go on it (docs/COSTS.md §5, finding 4).
pub fn socket_up(tx: mpsc::UnboundedSender<Value>) { *SOCKET.lock().unwrap() = Some(tx); }
/// link.rs: the socket went away. Renewals go back to HTTP until it is back.
pub fn socket_down() { SOCKET.lock().unwrap().take(); WAITING.lock().unwrap().clear(); }
/// link.rs: a `host.roles` answer arrived on the socket; hand it to the renewal waiting for it.
pub fn socket_answer(v: &Value) {
    let id = v["id"].as_u64().unwrap_or(0);
    let waiter = WAITING.lock().unwrap().remove(&id);
    if let Some(tx) = waiter { let _ = tx.send(v.clone()); }
}
/// Memory the role sandboxes hold, for the guard's admission of jobs.
pub fn memory_mib() -> u64 { MEMORY.load(Ordering::Relaxed) }

/// One role the Gate wants on this machine.
#[derive(Clone, Debug, PartialEq)]
pub struct Want { pub role: String, pub held: bool, pub epoch: u64, pub mcp: String, pub grant: Option<(String, String, Vec<String>)>, pub image: Option<String>, pub system: String, pub local_model: bool }

/// The words a project's orchestrator role may be spelled with: `orchestrator:<project>`, and `lead:<project>`, which
/// older Gates still send (compatibility window, docs/PROJECTS.md §2f). A role is used exactly as the Gate spelled it,
/// on every call back, and never rewritten into the other spelling.
const ORCHESTRATOR_WORDS: [&str; 2] = ["orchestrator", "lead" /* compatibility: older Gates */];
/// Sent with every renewal: the role words this node understands beyond the original ones. A Gate that knows the field
/// answers `orchestrator:<project>`; an older Gate ignores it and answers `lead:<project>`.
pub const SPEAKS: [&str; 1] = ["orchestrator"];

fn role_ok(r: &str) -> bool {
    let p = |s: &str| !s.is_empty() && s.len() <= 63 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') && !s.starts_with('-');
    r == "steward" || r.split_once(':').map_or(false, |(word, project)| ORCHESTRATOR_WORDS.contains(&word) && p(project))
}
/// The MCP route that belongs to a role, in the role's own spelling: `/node/mcp/steward`,
/// `/node/mcp/orchestrator/<project>`, or `/node/mcp/lead/<project>` for the older spelling. A route in the other
/// spelling, for another project, or with any other path trick doesn't match, and the role is dropped.
fn mcp_for(role: &str) -> String { format!("/node/mcp/{}", role.replace(':', "/")) }
fn image_ok(i: &str) -> bool { (3..=200).contains(&i.len()) && i.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"./_:@-".contains(&b)) }

/// The Gate's answer, checked: known role names, the MCP route that belongs to each, a sane image.
pub fn parse_wants(v: &Value) -> Vec<Want> {
    v.as_array().cloned().unwrap_or_default().iter().filter_map(|w| {
        let role = w["role"].as_str().filter(|r| role_ok(r))?.to_string();
        let mcp = mcp_for(&role);
        if w["mcp"].as_str() != Some(mcp.as_str()) { return None; }
        let grant = w["grant"].as_object().and_then(|g| Some((g.get("secret")?.as_str()?.to_string(), g.get("id")?.as_str()?.to_string(),
            g.get("hosts")?.as_array()?.iter().filter_map(|h| h.as_str().map(String::from)).collect())));
        Some(Want { held: w["held"] == true, epoch: w["epoch"].as_u64().unwrap_or(0), grant, image: w["image"].as_str().filter(|i| image_ok(i)).map(String::from),
            system: w["system"].as_str().unwrap_or_default().chars().take(32_000).collect(), local_model: w["local_model"] == true, mcp, role })
    }).collect()
}

#[derive(Debug, PartialEq)]
pub enum Action { Start(String), Restart(String), Stop(String) }

/// What to do with the role sandboxes: start what's wanted, restart what died, stop what's no longer wanted; at red
/// or critical, stop everything (the lease moves to the cloud).
pub fn plan(wanted: &[String], have: &[(String, bool)], level: Level) -> Vec<Action> {
    if level >= Level::Red { return have.iter().map(|(r, _)| Action::Stop(r.clone())).collect(); }
    let mut a = vec![];
    for (r, alive) in have { if !wanted.contains(r) { a.push(Action::Stop(r.clone())) } else if !alive { a.push(Action::Restart(r.clone())) } }
    for r in wanted { if !have.iter().any(|(h, _)| h == r) { a.push(Action::Start(r.clone())) } }
    a
}

#[derive(Clone, Debug, PartialEq)]
pub enum Model { Gate, Local(String) }

/// The environment of one turn: the prompt, the role's instructions and its MCP config (as base64), and the model's
/// address. With the Gate's key, Claude Code talks to the broker's egress (the Gate adds the key); the sandbox has a
/// placeholder only.
pub fn turn_env(broker: &str, model: &Model, prompt: &str, system: &str) -> Vec<(String, String)> {
    let mcp = json!({ "mcpServers": { "pavilion": { "type": "http", "url": format!("{broker}/mcp") } } }).to_string();
    let mut env = vec![
        ("PAVILION_PROMPT_B64".to_string(), STANDARD.encode(prompt)), ("PAVILION_SYSTEM_B64".into(), STANDARD.encode(system)), ("PAVILION_MCP_B64".into(), STANDARD.encode(mcp)),
        ("IS_SANDBOX".into(), "1".into()), ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".into(), "1".into()), ("MCP_TOOL_TIMEOUT".into(), "900000".into()),
    ];
    match model {
        Model::Gate => env.extend([("ANTHROPIC_BASE_URL".to_string(), format!("{broker}/ANTHROPIC_API_KEY/api.anthropic.com")), ("ANTHROPIC_API_KEY".into(), "sk-ant-pavilion-placeholder".into())]),
        Model::Local(m) => env.extend([("ANTHROPIC_BASE_URL".to_string(), format!("{broker}/local")), ("ANTHROPIC_AUTH_TOKEN".into(), "local".into()),
            ("ANTHROPIC_MODEL".into(), m.clone()), ("ANTHROPIC_SMALL_FAST_MODEL".into(), m.clone())]),
    }
    env
}

/// One turn: Claude Code in print mode with no shell, no files, no web, only the pavilion's tools, continuing the
/// sandbox's conversation.
pub fn turn_script(model: &Model, limit_s: u64) -> String {
    let flag = if *model == Model::Gate { " --model opus" } else { "" };
    format!(r#"D=/work/.pavilion; mkdir -p $D && cd /work || exit 70
printf %s "$PAVILION_PROMPT_B64" | base64 -d > $D/prompt && printf %s "$PAVILION_SYSTEM_B64" | base64 -d > $D/system.md && printf %s "$PAVILION_MCP_B64" | base64 -d > $D/mcp.json || exit 70
CONT=""; [ -f $D/has-session ] && CONT="--continue"
timeout {limit_s} claude -p "$(cat $D/prompt)" $CONT --tools "" --strict-mcp-config --mcp-config $D/mcp.json --allowedTools mcp__pavilion --append-system-prompt-file $D/system.md{flag}
code=$?; touch $D/has-session; exit $code"#)
}

/// The machine: sandboxes, the guard. The real one is below; tests use a fake.
pub trait Runtime: Send + Sync + 'static {
    fn level(&self) -> Level;
    fn admit(&self, level: Level) -> impl Future<Output = Result<(), String>> + Send;
    fn start(&self, name: &str, label: &str, image: &str) -> impl Future<Output = Result<(String, (u32, u32))>> + Send;
    fn alive(&self, name: &str) -> impl Future<Output = bool> + Send;
    fn exec(&self, name: &str, env: &[(String, String)], script: &str, timeout_s: u64) -> impl Future<Output = (i32, String, String)> + Send;
    fn remove(&self, name: &str) -> impl Future<Output = ()> + Send;
}

pub struct Real;
impl Runtime for Real {
    fn level(&self) -> Level { crate::media::level_now().0 }
    async fn admit(&self, level: Level) -> Result<(), String> {
        let s = crate::guard::sample();
        let used = (crate::sandbox::running_memory_mib().await).max(memory_mib()) + crate::sandbox::warm_idle_memory_mib().await;
        crate::guard::admit(&s, &crate::guard::Limits::defaults(&s), level, used, ROLE_MEMORY_MIB, 3 * 1024)
    }
    async fn start(&self, name: &str, label: &str, image: &str) -> Result<(String, (u32, u32))> { crate::sandbox::start_long(name, label, image, ROLE_MEMORY_MIB, 2).await }
    async fn alive(&self, name: &str) -> bool { crate::sandbox::alive(name).await }
    async fn exec(&self, name: &str, env: &[(String, String)], script: &str, timeout_s: u64) -> (i32, String, String) { crate::sandbox::exec_in(name, env, script, timeout_s).await }
    async fn remove(&self, name: &str) { crate::sandbox::remove_named(name).await }
}

/// Signed calls to the Gate's `/node/host` routes.
pub struct GateLink { http: reqwest::Client, base: String, host: String, pavilion: String, key: ed25519_dalek::SigningKey }
impl GateLink {
    pub fn new(base: &str, pavilion: &str, key: ed25519_dalek::SigningKey) -> Result<GateLink> {
        let url = reqwest::Url::parse(base)?;
        let host = url.host_str().unwrap_or_default().to_string() + &url.port().map(|p| format!(":{p}")).unwrap_or_default();
        Ok(GateLink { http: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(60)).build()?,
            base: base.trim_end_matches('/').to_string(), host, pavilion: pavilion.into(), key })
    }
    async fn post(&self, sub: &str, body: &Value) -> Result<Value, String> {
        let path = format!("/p/{}/node/host{sub}", self.pavilion);
        let bytes = serde_json::to_vec(body).unwrap();
        let mut rb = self.http.post(format!("{}{path}", self.base)).header("content-type", "application/json");
        for (k, v) in signed_headers(&self.key, &self.host, "POST", &path, &bytes) { rb = rb.header(k, v); }
        let r = rb.body(bytes).send().await.map_err(|e| format!("the Gate: {e}"))?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(json!({}));
        if !status.is_success() || v.get("error").is_some() { return Err(v["error"].as_str().unwrap_or(status.as_str()).to_string()); }
        Ok(v)
    }
}

/// A role's sandbox and its broker.
struct RoleBox { name: String, door: Arc<RoleDoor>, broker: tokio::task::JoinHandle<()>, url: String, ready: bool, note: Option<String>, busy: bool }
impl Drop for RoleBox { fn drop(&mut self) { self.broker.abort(); } }

pub struct Manager<R: Runtime> {
    rt: R,
    gate: GateLink,
    /// For the brokers: where the Gate is and the machine's key.
    pavilion: String,
    gate_base: String,
    key: ed25519_dalek::SigningKey,
    boxes: Mutex<HashMap<String, RoleBox>>,
    wants: Mutex<Vec<Want>>,
    /// (Ollama's address, the model) when a local model is set up for orchestrators.
    pub local: std::sync::Mutex<Option<(String, String)>>,
    pub image: String,
}

fn box_name(role: &str) -> String { format!("pav-role-{}", role.replace(':', "-")) }

impl<R: Runtime> Manager<R> {
    pub fn new(rt: R, gate_base: &str, pavilion: &str, key: ed25519_dalek::SigningKey) -> Result<Manager<R>> {
        let image = crate::state::config()["host_image"].as_str().filter(|i| image_ok(i)).unwrap_or(DEFAULT_IMAGE).to_string();
        Ok(Manager { gate: GateLink::new(gate_base, pavilion, key.clone())?, rt, pavilion: pavilion.into(), gate_base: gate_base.into(), key,
            boxes: Mutex::default(), wants: Mutex::default(), local: std::sync::Mutex::new(None), image })
    }

    fn model_for(&self, w: &Want) -> Model {
        match (&*self.local.lock().unwrap(), w.role != "steward" && w.local_model) { (Some((_, m)), true) => Model::Local(m.clone()), _ => Model::Gate }
    }

    /// What this machine says about each role it runs: ready (sandbox up, Claude Code in it), and which model.
    async fn report(&self) -> Value {
        let wants = self.wants.lock().await.clone();
        let boxes = self.boxes.lock().await;
        let mut roles = serde_json::Map::new();
        for (role, b) in boxes.iter() {
            let model = wants.iter().find(|w| &w.role == role).map(|w| self.model_for(w)).unwrap_or(Model::Gate);
            roles.insert(role.clone(), json!({ "ready": b.ready, "note": b.note, "model": match model { Model::Gate => "gate".to_string(), Model::Local(m) => format!("local:{m}") } }));
        }
        json!({ "level": self.rt.level(), "roles": roles, "speaks": SPEAKS })
    }

    /// Renews the roles: on the socket this machine already holds to the pavilion when there is one, over HTTP
    /// otherwise. The body and the answer are the same either way, so the lease behaves identically; the socket is
    /// preferred only because an incoming message bills at a twentieth of a request (docs/COSTS.md §5, finding 4).
    /// HTTP is the fallback for a socket that is down or reconnecting, and for a Gate too old to answer on it.
    async fn renew(&self, report: &Value) -> Result<Value, String> {
        match self.renew_on_socket(report).await {
            Some(v) => Ok(v),
            None => self.gate.post("", report).await,
        }
    }
    /// One renewal on the socket, waiting for its `host.roles` answer. `None` means "use HTTP": no socket, the link
    /// dropped it, or nothing answered in time.
    async fn renew_on_socket(&self, report: &Value) -> Option<Value> {
        let tx = SOCKET.lock().unwrap().clone()?;
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let (otx, orx) = oneshot::channel();
        WAITING.lock().unwrap().insert(id, otx);
        let mut msg = report.clone();
        msg["t"] = json!("host");
        msg["id"] = json!(id);
        // The live line rides on the renewal when both fall due (docs/WORK-ROUTING.md §4): one message, not two.
        if let Some(l) = crate::live::for_renewal() { msg["live"] = l; }
        if tx.send(msg).is_err() { WAITING.lock().unwrap().remove(&id); return None; }
        match tokio::time::timeout(SOCKET_WAIT, orx).await {
            Ok(Ok(v)) => Some(v),
            _ => { WAITING.lock().unwrap().remove(&id); None }
        }
    }

    /// One round: renew, start/restart/stop sandboxes, set each broker's epoch and grant, and take work for held roles.
    /// Returns whether this machine is asked to run anything.
    pub async fn tick(self: &Arc<Self>) -> Result<bool> {
        let level = self.rt.level();
        let v = self.renew(&self.report().await).await.map_err(|e| anyhow!(e))?;
        let wants = parse_wants(&v["roles"]);
        *self.wants.lock().await = wants.clone();
        let names: Vec<String> = wants.iter().map(|w| w.role.clone()).collect();
        let have: Vec<(String, String)> = self.boxes.lock().await.iter().map(|(r, b)| (r.clone(), b.name.clone())).collect();
        let mut alive = vec![];
        for (r, n) in &have { alive.push((r.clone(), self.rt.alive(n).await)); }
        let mut readied = false;
        for a in plan(&names, &alive, level) {
            match a {
                Action::Stop(r) => { if let Some(b) = self.boxes.lock().await.remove(&r) { eprintln!("host: stopping the {r} sandbox"); self.rt.remove(&b.name).await; } }
                Action::Restart(r) => {
                    if let Some(b) = self.boxes.lock().await.remove(&r) { eprintln!("host: the {r} sandbox died; starting it again"); self.rt.remove(&b.name).await; }
                    readied |= self.start(&r, &wants, level).await;
                }
                Action::Start(r) => readied |= self.start(&r, &wants, level).await,
            }
        }
        MEMORY.store(self.boxes.lock().await.len() as u64 * ROLE_MEMORY_MIB, Ordering::Relaxed);
        self.apply(&wants).await;
        // A sandbox just became ready: say so now, so the lease moves without waiting 30 s.
        let wants = if readied {
            let v = self.renew(&self.report().await).await.map_err(|e| anyhow!(e))?;
            let w = parse_wants(&v["roles"]);
            *self.wants.lock().await = w.clone();
            self.apply(&w).await;
            w
        } else { wants };
        for w in wants.iter().filter(|w| w.held && w.epoch > 0) {
            let take = { let mut b = self.boxes.lock().await; match b.get_mut(&w.role) { Some(x) if x.ready && !x.busy => { x.busy = true; true } _ => false } };
            if take { let me = self.clone(); let w = w.clone(); tokio::spawn(async move { me.work(&w).await; }); }
        }
        Ok(!names.is_empty())
    }

    /// Each broker's epoch and grant: the lease's when this machine holds the role, nothing otherwise.
    async fn apply(&self, wants: &[Want]) {
        let boxes = self.boxes.lock().await;
        for w in wants {
            let Some(b) = boxes.get(&w.role) else { continue };
            b.door.epoch.store(if w.held { w.epoch } else { 0 }, Ordering::SeqCst);
            let mut g = b.door.grants.write().unwrap();
            g.clear();
            if let (true, Some((secret, id, hosts))) = (w.held, &w.grant) { g.insert(secret.clone(), Grant { id: id.clone(), hosts: hosts.clone() }); }
            *b.door.local.write().unwrap() = match self.model_for(w) { Model::Local(_) => self.local.lock().unwrap().as_ref().map(|(base, _)| base.clone()), Model::Gate => None };
        }
    }

    /// Starts a role's sandbox and its broker, if the guard admits it. Returns whether it's ready.
    async fn start(&self, role: &str, wants: &[Want], level: Level) -> bool {
        let Some(w) = wants.iter().find(|w| w.role == role) else { return false };
        if let Err(why) = self.rt.admit(level).await { eprintln!("host: not starting the {role} sandbox: {why}"); return false; }
        let name = box_name(role);
        let image = w.image.clone().unwrap_or_else(|| self.image.clone());
        // The Gate may name the image, so the local ceiling's image list (jobs: images, ceiling.rs) holds here too.
        if let Err(why) = crate::ceiling::load_jobs().and_then(|j| j.allows_image(&image)) { eprintln!("host: not starting the {role} sandbox: {why}"); return false; }
        eprintln!("host: starting the {role} sandbox ({image})");
        let (gw, sub) = match self.rt.start(&name, &format!("pavilion.job=role-{}", role.replace(':', "-")), &image).await {
            Ok(x) => x, Err(e) => { eprintln!("host: couldn't start the {role} sandbox: {e}"); return false; }
        };
        let door = Arc::new(RoleDoor { mcp: w.mcp.clone(), epoch: AtomicU64::new(0), grants: Default::default(), local: Default::default() });
        let http = match reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build() { Ok(h) => h, Err(_) => return false };
        let broker = Arc::new(Broker { gate: self.gate_base.clone(), pavilion: self.pavilion.clone(), job: String::new(), key: self.key.clone(), grants: HashMap::new(), subnet: sub, http, role: Some(door.clone()), slot: None });
        let (port, task) = match broker.serve().await { Ok(x) => x, Err(e) => { eprintln!("host: no broker for {role}: {e}"); self.rt.remove(&name).await; return false; } };
        let (_, out, note) = self.rt.exec(&name, &[], "command -v claude >/dev/null && echo ready", 60).await;
        let ready = out.contains("ready");
        let note = (!ready).then(|| format!("the role image has no Claude Code ({note}); set the host image to one with it (gate/container/Dockerfile builds one)"));
        if let Some(n) = &note { eprintln!("host: {role}: {n}"); }
        self.boxes.lock().await.insert(role.to_string(), RoleBox { name, door, broker: task, url: format!("http://{gw}:{port}"), ready, note, busy: false });
        ready
    }

    /// Takes the next piece of work for a held role, runs it as one turn in its sandbox, and reports it. The role goes
    /// back in the spelling the Gate gave it. The item's `kind` (`turn` for the Steward; `orchestrator`, or `lead` from an
    /// older Gate) isn't read: every item is one turn.
    async fn work(&self, w: &Want) {
        let r = self.gate.post("/next", &json!({ "role": w.role, "epoch": w.epoch })).await;
        let item = r.as_ref().ok().map(|v| v["work"].clone()).filter(|x| x.is_object());
        if let Err(e) = &r { eprintln!("host: {}: {e}", w.role); }
        if let Some(item) = item {
            let (name, url) = match self.boxes.lock().await.get(&w.role) { Some(b) => (b.name.clone(), b.url.clone()), None => return };
            let model = self.model_for(w);
            let (id, prompt) = (item["id"].as_str().unwrap_or_default().to_string(), item["prompt"].as_str().unwrap_or_default().to_string());
            eprintln!("host: {} takes {id} ({})", w.role, if let Model::Local(m) = &model { format!("local model {m}") } else { "model key through the Gate".into() });
            let limit = if w.role == "steward" { 1200 } else { 900 };
            let (code, out, note) = self.rt.exec(&name, &turn_env(&url, &model, &prompt, &w.system), &turn_script(&model, limit), limit + 60).await;
            let output = if note.is_empty() { out } else { format!("{out}\n[{note}]") };
            if let Err(e) = self.gate.post("/done", &json!({ "role": w.role, "epoch": w.epoch, "id": id, "output": output, "exitCode": code })).await { eprintln!("host: {} {id}: {e}", w.role); }
            nudge(); // there may be more
        }
        if let Some(b) = self.boxes.lock().await.get_mut(&w.role) { b.busy = false; }
    }
}

/// Which local model orchestrators use, from the node's config.json: `orchestrator_model`, or `lead_model`, the older
/// key, still read when the new one is absent (compatibility window, docs/PROJECTS.md §2f). Both set: the new one.
fn local_model_name(cfg: &Value) -> Option<String> {
    cfg["orchestrator_model"].as_str().or_else(|| cfg["lead_model"].as_str() /* compatibility: the older key */).map(String::from)
}

/// A local model for orchestrators (`local_model_name`), served by Ollama on this machine (`ollama_url`, loopback only).
/// None otherwise, and orchestrators use the model key lent through the Gate.
pub async fn detect_local() -> Option<(String, String)> {
    let cfg = crate::state::config();
    let model = local_model_name(&cfg)?;
    let base = cfg["ollama_url"].as_str().unwrap_or("http://127.0.0.1:11434").trim_end_matches('/').to_string();
    let u = reqwest::Url::parse(&base).ok()?;
    if !matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")) { return None; }
    let v: Value = reqwest::Client::new().get(format!("{base}/api/tags")).timeout(Duration::from_secs(3)).send().await.ok()?.json().await.ok()?;
    let has = v["models"].as_array()?.iter().any(|m| [&m["name"], &m["model"]].iter().any(|n| n.as_str().map_or(false, |n| n == model || n.strip_suffix(":latest") == Some(&model))));
    has.then_some((base, model))
}

/// `pavilion-node run`: the host roles alongside the link.
pub async fn run_loop() {
    let m = loop {
        match (|| -> Result<Manager<Real>> { let st = crate::state::load()?; Manager::new(Real, &st.gate, &st.pavilion, crate::state::key()?) })() {
            Ok(m) => break Arc::new(m),
            Err(e) => { eprintln!("host: {e}"); tokio::time::sleep(IDLE).await; }
        }
    };
    let mut last_err = String::new();
    loop {
        *m.local.lock().unwrap() = detect_local().await;
        let wait = match m.tick().await {
            Ok(hosting) => { last_err.clear(); if hosting { RENEW } else { IDLE } }
            Err(e) => { let e = e.to_string(); if e != last_err { eprintln!("host: renewing: {e}"); last_err = e; } RENEW }
        };
        tokio::select! { _ = tokio::time::sleep(wait) => {}, _ = NUDGE.notified() => {} }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Incoming, Request, Response};

    /// The old spelling (`lead:a`) here and in `wants_are_checked` is the compatibility path; the new one has twins.
    #[test]
    fn plans() {
        let s = |x: &str| x.to_string();
        assert_eq!(plan(&[s("orchestrator:a")], &[(s("lead:a"), true)], Level::Green), vec![Action::Stop(s("lead:a")), Action::Start(s("orchestrator:a"))]);
        assert_eq!(plan(&[s("steward"), s("lead:a")], &[], Level::Green), vec![Action::Start(s("steward")), Action::Start(s("lead:a"))]);
        assert_eq!(plan(&[s("steward")], &[(s("steward"), true), (s("lead:a"), true)], Level::Amber), vec![Action::Stop(s("lead:a"))]);
        assert_eq!(plan(&[s("steward")], &[(s("steward"), false)], Level::Green), vec![Action::Restart(s("steward"))]);
        assert_eq!(plan(&[s("steward")], &[(s("steward"), true)], Level::Red), vec![Action::Stop(s("steward"))]);
        assert_eq!(plan(&[s("steward")], &[], Level::Critical), vec![]);
    }

    #[test]
    fn wants_are_checked() {
        let w = parse_wants(&json!([
            { "role": "steward", "held": true, "epoch": 3, "mcp": "/node/mcp/steward", "grant": { "id": "grt_x", "secret": "ANTHROPIC_API_KEY", "hosts": ["api.anthropic.com"] }, "system": "be good" },
            { "role": "lead:album-art", "held": false, "epoch": null, "mcp": "/node/mcp/lead/album-art", "local_model": true, "image": "BAD IMAGE" },
            { "role": "lead:x", "mcp": "/node/mcp/steward" },
            { "role": "admin", "mcp": "/node/mcp/admin" },
            { "role": "lead:../a", "mcp": "/node/mcp/lead/../a" },
        ]));
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].grant, Some(("ANTHROPIC_API_KEY".into(), "grt_x".into(), vec!["api.anthropic.com".into()])));
        assert!(w[0].held && w[0].epoch == 3 && !w[1].held && w[1].local_model && w[1].image.is_none());
    }

    #[test]
    fn role_names() {
        for ok in ["steward", "orchestrator:album-art", "lead:album-art", "orchestrator:a1", "lead:a1"] { assert!(role_ok(ok), "{ok}"); }
        for bad in ["", "admin", "orchestrator", "orchestrator:", "lead:", "orchestrator:-a", "lead:-a", "orchestrator:A", "orchestrator:a:b", "lead:a:b",
            "orchestrator:../a", "lead:../a", "orchestrator:a/b", "orchestrators:a", "Orchestrator:a", "steward:a", "member:a"] { assert!(!role_ok(bad), "{bad}"); }
        assert!(role_ok(&format!("orchestrator:{}", "a".repeat(63))) && !role_ok(&format!("orchestrator:{}", "a".repeat(64))));
    }

    /// A Gate that knows the word answers `orchestrator:<project>` with its route; an older one answers `lead:<project>`.
    /// Each is taken as spelled, and a route in the other spelling, for another project or with a path trick is not.
    #[test]
    fn wants_in_either_spelling() {
        let new_gate = parse_wants(&json!([
            { "role": "steward", "held": true, "epoch": 2, "mcp": "/node/mcp/steward" },
            { "role": "orchestrator:album-art", "held": true, "epoch": 5, "mcp": "/node/mcp/orchestrator/album-art", "local_model": true },
        ]));
        assert_eq!(new_gate.iter().map(|w| (w.role.as_str(), w.mcp.as_str())).collect::<Vec<_>>(),
            vec![("steward", "/node/mcp/steward"), ("orchestrator:album-art", "/node/mcp/orchestrator/album-art")]);
        assert!(new_gate[1].held && new_gate[1].epoch == 5 && new_gate[1].local_model);
        let old_gate = parse_wants(&json!([{ "role": "lead:album-art", "held": true, "epoch": 5, "mcp": "/node/mcp/lead/album-art" }]));
        assert_eq!((old_gate[0].role.as_str(), old_gate[0].mcp.as_str()), ("lead:album-art", "/node/mcp/lead/album-art"));
        let refused = parse_wants(&json!([
            { "role": "orchestrator:a", "mcp": "/node/mcp/lead/a" },
            { "role": "lead:a", "mcp": "/node/mcp/orchestrator/a" },
            { "role": "orchestrator:a", "mcp": "/node/mcp/orchestrator/b" },
            { "role": "orchestrator:a", "mcp": "/node/mcp/steward" },
            { "role": "steward", "mcp": "/node/mcp/orchestrator/a" },
            { "role": "orchestrator:a", "mcp": "/node/mcp/orchestrator/a/../b" },
            { "role": "orchestrator:a", "mcp": "/node/mcp/orchestrator:a" },
            { "role": "orchestrator:a" },
            { "role": "orchestrator:../a", "mcp": "/node/mcp/orchestrator/../a" },
            { "role": "orchestrator:a/b", "mcp": "/node/mcp/orchestrator/a/b" },
        ]));
        assert!(refused.is_empty(), "{refused:?}");
    }

    #[test]
    fn local_model_key() {
        assert_eq!(local_model_name(&json!({ "orchestrator_model": "qwen3" })).as_deref(), Some("qwen3"));
        assert_eq!(local_model_name(&json!({ "lead_model": "llama4" })).as_deref(), Some("llama4"), "the older key still works alone");
        assert_eq!(local_model_name(&json!({ "orchestrator_model": "qwen3", "lead_model": "llama4" })).as_deref(), Some("qwen3"), "the new key wins");
        assert_eq!(local_model_name(&json!({ "orchestrator_model": null, "lead_model": "llama4" })).as_deref(), Some("llama4"));
        assert_eq!(local_model_name(&json!({})), None);
        assert_eq!(local_model_name(&json!({ "ollama_url": "http://127.0.0.1:11434" })), None);
    }

    #[test]
    fn turns_carry_no_key() {
        let env: HashMap<String, String> = turn_env("http://10.89.1.1:47100", &Model::Gate, "hi", "sys").into_iter().collect();
        assert_eq!(env["ANTHROPIC_BASE_URL"], "http://10.89.1.1:47100/ANTHROPIC_API_KEY/api.anthropic.com");
        assert_eq!(env["ANTHROPIC_API_KEY"], "sk-ant-pavilion-placeholder");
        let mcp = String::from_utf8(STANDARD.decode(&env["PAVILION_MCP_B64"]).unwrap()).unwrap();
        assert!(mcp.contains(r#""url":"http://10.89.1.1:47100/mcp""#), "{mcp}");
        let local: HashMap<String, String> = turn_env("http://b", &Model::Local("qwen3".into()), "hi", "sys").into_iter().collect();
        assert_eq!(local["ANTHROPIC_BASE_URL"], "http://b/local");
        assert_eq!(local["ANTHROPIC_MODEL"], "qwen3");
        assert!(!local.contains_key("ANTHROPIC_API_KEY"));
        let script = turn_script(&Model::Gate, 1200);
        assert!(script.contains(r#"--tools "" --strict-mcp-config"#) && script.contains("--allowedTools mcp__pavilion") && script.contains("timeout 1200"));
    }

    /// `SOCKET` and `WAITING` are the link's, one per process: the tests that use them take this first.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The renewal goes on the socket the link already holds, and over HTTP when there isn't one: the same body, the
    /// same answer, the same lease (docs/COSTS.md §5, finding 4; docs/HOST-AND-VOICE.md §1b).
    #[tokio::test]
    async fn renewals_prefer_the_socket() {
        let _hold = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let st = Arc::new(std::sync::Mutex::new(Script { wanted: true, ..Default::default() }));
        let port = standin(st.clone()).await;
        let fake = Arc::new(Fake::default());
        let m = Arc::new(Manager::new(fake.clone(), &format!("http://127.0.0.1:{port}"), "pv", ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])).unwrap());

        // A link with a socket: the renewal arrives there as {t:"host"}, carrying what the HTTP body carries.
        let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
        socket_up(tx);
        let sent: Arc<std::sync::Mutex<Vec<Value>>> = Arc::default();
        let seen = sent.clone();
        let pump = tokio::spawn(async move {
            while let Some(v) = rx.recv().await {
                seen.lock().unwrap().push(v.clone());
                socket_answer(&json!({ "t": "host.roles", "id": v["id"], "roles": [], "renew_s": 30 }));
            }
        });
        assert!(!m.tick().await.unwrap());
        let s = sent.lock().unwrap().clone();
        assert_eq!(s.len(), 1, "{s:?}");
        assert!(s[0]["t"] == "host" && s[0]["id"].is_u64() && s[0]["level"] == "green" && s[0]["roles"].is_object(), "{}", s[0]);
        assert_eq!(s[0]["speaks"], json!(["orchestrator"]), "the socket renewal says which role words it understands");
        assert!(!st.lock().unwrap().seen.iter().any(|x| x.starts_with("/p/pv/node/host ")), "nothing was posted: {:?}", st.lock().unwrap().seen);

        // The socket went away mid-renewal: the same renewal goes over HTTP at once, and the role is taken as before.
        pump.abort();
        socket_down();
        assert!(m.tick().await.unwrap());
        assert!(st.lock().unwrap().seen.iter().any(|x| x.starts_with("/p/pv/node/host ")), "{:?}", st.lock().unwrap().seen);
        assert!(st.lock().unwrap().reports.iter().all(|r| r["speaks"] == json!(["orchestrator"])), "so does the HTTP one");

        // A socket whose link has dropped it falls back without waiting for an answer.
        let (tx2, rx2) = mpsc::unbounded_channel::<Value>();
        drop(rx2);
        socket_up(tx2);
        let before = st.lock().unwrap().seen.len();
        m.tick().await.unwrap();
        assert!(st.lock().unwrap().seen.len() > before, "a dead socket renews over HTTP");
        socket_down();
        for (_, b) in m.boxes.lock().await.iter() { fake.remove(&b.name).await; }
    }

    /// A machine with no real sandboxes: records what the manager asks for.
    #[derive(Default)]
    struct Fake { log: std::sync::Mutex<Vec<String>>, dead: std::sync::Mutex<Vec<String>>, level: std::sync::Mutex<Option<Level>>, envs: std::sync::Mutex<Vec<HashMap<String, String>>> }
    impl Runtime for Arc<Fake> {
        fn level(&self) -> Level { self.level.lock().unwrap().unwrap_or(Level::Green) }
        async fn admit(&self, _: Level) -> Result<(), String> { Ok(()) }
        async fn start(&self, name: &str, label: &str, _image: &str) -> Result<(String, (u32, u32))> {
            self.log.lock().unwrap().push(format!("start {name} {label}")); self.dead.lock().unwrap().retain(|n| n != name);
            Ok(("127.0.0.1".into(), crate::broker::parse_subnet("127.0.0.0/8").unwrap()))
        }
        async fn alive(&self, name: &str) -> bool { !self.dead.lock().unwrap().contains(&name.to_string()) }
        async fn exec(&self, name: &str, env: &[(String, String)], script: &str, _t: u64) -> (i32, String, String) {
            if script.contains("command -v claude") { return (0, "ready\n".into(), String::new()); }
            self.log.lock().unwrap().push(format!("turn {name}"));
            self.envs.lock().unwrap().push(env.iter().cloned().collect());
            (0, "Planned it.".into(), String::new())
        }
        async fn remove(&self, name: &str) { self.log.lock().unwrap().push(format!("remove {name}")); }
    }

    /// A stand-in Gate: holds the Steward's lease once the sandbox is ready, hands out one turn, records the rest. With
    /// `orchestrator`, it offers that project's orchestrator instead, spelled the way a Gate does: `orchestrator:<p>` to
    /// a node that says it speaks the word, `lead:<p>` otherwise or when it is an `old` Gate that ignores the field.
    #[derive(Default)]
    struct Script { wanted: bool, seen: Vec<String>, done: Vec<Value>, handed: bool, orchestrator: Option<String>, old: bool, reports: Vec<Value>, nexts: Vec<Value> }
    async fn standin(state: Arc<std::sync::Mutex<Script>>) -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { break };
                let st = state.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| { let st = st.clone(); async move {
                        let path = req.uri().to_string();
                        let signed = req.headers().contains_key("x-pavilion-signature");
                        let body: Value = serde_json::from_slice(&req.into_body().collect().await.unwrap().to_bytes()).unwrap_or(json!({}));
                        let mut s = st.lock().unwrap();
                        s.seen.push(format!("{path} signed={signed}"));
                        let speaks = !s.old && body["speaks"].as_array().map_or(false, |a| a.iter().any(|x| x == "orchestrator"));
                        let word = if speaks { "orchestrator" } else { "lead" };
                        let (role, mcp, kind) = match &s.orchestrator {
                            None => ("steward".to_string(), "/node/mcp/steward".to_string(), "turn"),
                            Some(p) => (format!("{word}:{p}"), format!("/node/mcp/{word}/{p}"), word),
                        };
                        let out = if path == "/p/pv/node/host" {
                            s.reports.push(body.clone());
                            let ready = body["roles"][&role]["ready"] == true;
                            if !s.wanted { json!({ "roles": [] }) } else {
                                json!({ "roles": [{ "role": role, "held": ready, "epoch": if ready { 1 } else { 0 }, "mcp": mcp, "system": "You are the Steward.",
                                    "grant": if ready { json!({ "id": "grt_abc", "secret": "ANTHROPIC_API_KEY", "hosts": ["api.anthropic.com"] }) } else { Value::Null } }] })
                            }
                        } else if path == "/p/pv/node/host/next" {
                            s.nexts.push(body.clone());
                            if s.handed { json!({ "work": null }) } else { s.handed = true; json!({ "work": { "id": "turn_1", "kind": kind, "prompt": "make a schedule" } }) }
                        } else if path == "/p/pv/node/host/done" { s.done.push(body); json!({ "ok": true }) }
                        else { json!({ "jsonrpc": "2.0", "id": 1, "result": { "tools": [] } }) };
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(out.to_string()))))
                    } });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
                });
            }
        });
        port
    }

    /// A role's broker: the model call goes to the Gate's egress with the lease's grant and without the sandbox's
    /// placeholder key; an orchestrator's local model call goes to the local server, and only /v1/messages.
    #[tokio::test]
    async fn role_broker_model_paths() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let eport = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = echo.accept().await else { break };
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                        let mut h: Vec<String> = req.headers().keys().map(|k| k.to_string()).collect(); h.sort();
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(format!("{} {}", req.uri(), h.join(","))))))
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
                });
            }
        });
        // The broker doesn't read the route's spelling; the older one (compatibility) stands for both here.
        let door = Arc::new(RoleDoor { mcp: "/node/mcp/lead/site".into(), epoch: AtomicU64::new(4), grants: Default::default(), local: Default::default() });
        door.grants.write().unwrap().insert("ANTHROPIC_API_KEY".into(), Grant { id: "grt_abc".into(), hosts: vec!["api.anthropic.com".into()] });
        *door.local.write().unwrap() = Some(format!("http://127.0.0.1:{eport}"));
        let b = Arc::new(Broker { gate: format!("http://127.0.0.1:{eport}"), pavilion: "pv".into(), job: String::new(), key: ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]),
            grants: HashMap::new(), subnet: crate::broker::parse_subnet("127.0.0.0/8").unwrap(), http: reqwest::Client::new(), role: Some(door.clone()), slot: None });
        let (port, task) = b.serve().await.unwrap();
        let c = reqwest::Client::new();
        let t = c.post(format!("http://127.0.0.1:{port}/ANTHROPIC_API_KEY/api.anthropic.com/v1/messages?beta=true")).header("x-api-key", "sk-ant-pavilion-placeholder").body("{}").send().await.unwrap().text().await.unwrap();
        assert!(t.starts_with("/p/pv/node/egress/grt_abc/api.anthropic.com/v1/messages?beta=true ") && t.contains("x-pavilion-signature") && !t.contains("x-api-key"), "{t}");
        let t = c.post(format!("http://127.0.0.1:{port}/OTHER_KEY/api.anthropic.com/v1/messages")).body("{}").send().await.unwrap();
        assert_eq!(t.status(), 403);
        let t = c.post(format!("http://127.0.0.1:{port}/local/v1/messages")).header("authorization", "Bearer local").body("{}").send().await.unwrap().text().await.unwrap();
        assert!(t.starts_with("/v1/messages ") && !t.contains("authorization") && !t.contains("x-pavilion"), "{t}");
        assert_eq!(c.post(format!("http://127.0.0.1:{port}/local/api/pull")).body("{}").send().await.unwrap().status(), 404);
        // The lease left: the door has no epoch, and the tools are closed.
        door.epoch.store(0, Ordering::SeqCst);
        assert_eq!(c.post(format!("http://127.0.0.1:{port}/mcp")).body("{}").send().await.unwrap().status(), 503);
        task.abort();
    }

    /// The whole life of a role sandbox, with a fake runtime: started when wanted, the lease taken once ready, a turn
    /// run with the epoch and the grant in place, restarted when it dies, stopped at red and when the role leaves.
    #[tokio::test]
    async fn role_sandbox_lifecycle() {
        let _hold = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        socket_down(); // this one renews over HTTP
        let st = Arc::new(std::sync::Mutex::new(Script { wanted: true, ..Default::default() }));
        let port = standin(st.clone()).await;
        let fake = Arc::new(Fake::default());
        let m = Arc::new(Manager::new(fake.clone(), &format!("http://127.0.0.1:{port}"), "pv", ed25519_dalek::SigningKey::from_bytes(&[9u8; 32])).unwrap());

        assert!(m.tick().await.unwrap());
        assert_eq!(fake.log.lock().unwrap()[0], "start pav-role-steward pavilion.job=role-steward");
        // Ready → renewed again at once → held at epoch 1, its broker carries the epoch and the grant; one turn runs.
        for _ in 0..50 { if !st.lock().unwrap().done.is_empty() { break; } tokio::time::sleep(Duration::from_millis(20)).await; }
        let done = st.lock().unwrap().done.clone();
        assert_eq!(done.len(), 1, "{:?}", st.lock().unwrap().seen);
        assert_eq!((done[0]["role"].as_str(), done[0]["epoch"].as_u64(), done[0]["id"].as_str(), done[0]["exitCode"].as_i64()), (Some("steward"), Some(1), Some("turn_1"), Some(0)));
        let env = fake.envs.lock().unwrap()[0].clone();
        assert_eq!(String::from_utf8(STANDARD.decode(&env["PAVILION_PROMPT_B64"]).unwrap()).unwrap(), "make a schedule");
        assert!(env["ANTHROPIC_BASE_URL"].ends_with("/ANTHROPIC_API_KEY/api.anthropic.com") && !env.values().any(|v| v.contains("grt_abc")));
        assert!(st.lock().unwrap().seen.iter().all(|s| s.ends_with("signed=true")));

        // The sandbox reaches its tools through the broker: the Gate sees the role's route with the epoch, signed.
        let url = m.boxes.lock().await["steward"].url.clone();
        let r = reqwest::Client::new().post(format!("{url}/mcp")).body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert!(st.lock().unwrap().seen.iter().any(|s| s == "/p/pv/node/mcp/steward?epoch=1 signed=true"));
        // …and nothing else: no media doors, no SSH, no local model for the Steward.
        let r = reqwest::Client::new().post(format!("{url}/v1/images/generations")).body("{}").send().await.unwrap();
        assert_eq!(r.status(), 403);
        let r = reqwest::Client::new().post(format!("{url}/local/v1/messages")).body("{}").send().await.unwrap();
        assert_eq!(r.status(), 404);
        assert_eq!(memory_mib(), ROLE_MEMORY_MIB);

        // It dies: started again on the next round.
        fake.dead.lock().unwrap().push("pav-role-steward".into());
        m.tick().await.unwrap();
        let log = fake.log.lock().unwrap().clone();
        assert!(log.ends_with(&["remove pav-role-steward".to_string(), "start pav-role-steward pavilion.job=role-steward".to_string()]), "{log:?}");

        // Red: everything stops (the lease goes to the cloud after 2 quiet minutes).
        *fake.level.lock().unwrap() = Some(Level::Red);
        m.tick().await.unwrap();
        assert!(m.boxes.lock().await.is_empty() && fake.log.lock().unwrap().last().unwrap() == "remove pav-role-steward");
        *fake.level.lock().unwrap() = None;
        m.tick().await.unwrap();
        assert_eq!(m.boxes.lock().await.len(), 1);

        // The owner takes the role away: stopped, nothing held.
        st.lock().unwrap().wanted = false;
        assert!(!m.tick().await.unwrap());
        assert!(m.boxes.lock().await.is_empty());
        assert_eq!(fake.log.lock().unwrap().last().unwrap(), "remove pav-role-steward");
        assert_eq!(memory_mib(), 0);
    }

    /// A project's orchestrator hosted here, against a Gate that knows the word and against an older one: the node
    /// runs whichever spelling it was given, and says it back the same way on `/next`, `/done`, its role report and
    /// its tools route. Neither work kind (`orchestrator`, `lead`) is refused.
    #[tokio::test]
    async fn orchestrator_in_either_spelling() {
        let _hold = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        socket_down(); // these renew over HTTP
        for (old, word) in [(false, "orchestrator"), (true, "lead")] {
            let st = Arc::new(std::sync::Mutex::new(Script { wanted: true, orchestrator: Some("site".into()), old, ..Default::default() }));
            let port = standin(st.clone()).await;
            let fake = Arc::new(Fake::default());
            let m = Arc::new(Manager::new(fake.clone(), &format!("http://127.0.0.1:{port}"), "pv", ed25519_dalek::SigningKey::from_bytes(&[5u8; 32])).unwrap());
            let role = format!("{word}:site");

            assert!(m.tick().await.unwrap());
            assert_eq!(fake.log.lock().unwrap()[0], format!("start pav-role-{word}-site pavilion.job=role-{word}-site"));
            for _ in 0..50 { if !st.lock().unwrap().done.is_empty() { break; } tokio::time::sleep(Duration::from_millis(20)).await; }
            let (done, nexts, reports) = { let s = st.lock().unwrap(); (s.done.clone(), s.nexts.clone(), s.reports.clone()) };
            assert_eq!(done.len(), 1, "{word}: {:?}", st.lock().unwrap().seen);
            assert_eq!((done[0]["role"].as_str(), done[0]["epoch"].as_u64(), done[0]["id"].as_str()), (Some(role.as_str()), Some(1), Some("turn_1")), "{word}");
            assert!(!nexts.is_empty() && nexts.iter().all(|n| n["role"] == role.as_str()), "{word}: {nexts:?}");
            assert!(reports.iter().all(|r| r["speaks"] == json!(["orchestrator"])), "{word}");
            let last = reports.last().unwrap()["roles"].as_object().unwrap().keys().cloned().collect::<Vec<_>>();
            assert_eq!(last, vec![role.clone()], "{word}: the role report keeps the Gate's spelling");

            let url = m.boxes.lock().await[&role].url.clone();
            assert_eq!(reqwest::Client::new().post(format!("{url}/mcp")).body("{}").send().await.unwrap().status(), 200);
            let route = format!("/p/pv/node/mcp/{word}/site?epoch=1 signed=true");
            assert!(st.lock().unwrap().seen.iter().any(|s| *s == route), "{word}: {:?}", st.lock().unwrap().seen);

            st.lock().unwrap().wanted = false;
            assert!(!m.tick().await.unwrap());
            assert!(m.boxes.lock().await.is_empty());
        }
    }
}
