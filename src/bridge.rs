//! The node's MQTT bridge (docs/IOT.md §5c and §4e, build step 6): a broker on this machine or its LAN — a Mosquitto
//! that Tasmota plugs or zigbee2mqtt publish to — brought into the pavilion's Connected devices, with the node as their
//! **gateway**.
//!
//!   pavilion-node bridge add <broker> [--map tasmota|zigbee2mqtt] [--topics a,b] [--login-file f] [--ca-file f] [--gate URL] [--pavilion NAME]
//!     <broker> is host:port (plain MQTT), or ws://host:port/path or wss://… for a broker reachable only over a
//!     WebSocket (IOT.md §20f; mqtt_ws.rs). --ca-file: for wss://, the root a LAN broker's own certificate chains to.
//!   pavilion-node bridge code | status | run | remove
//!
//! What it trusts, and what it doesn't:
//!   · **the broker is the one the person at this machine named**, in a file only this user can read (bridge.json). The
//!     cloud never tells the bridge where to connect, and an address that isn't this machine or the local network
//!     (private, link-local or unique-local) is refused, by name and again after it resolves.
//!   · **the bridge is a connected device of its own**, with its own Ed25519 key (bridge.key, apart from the machine's
//!     key), claimed by an owner with the code it prints, exactly like a sensor: it joins only the pavilion this machine
//!     belongs to (or the one named at `bridge add`), and says at join that it takes no commands.
//!   · **it forwards only what an owner accepted.** A new plug or sensor on the broker is *offered* — its id, its
//!     template and the name it reports — and its readings stay on the LAN until an owner accepts it in the console.
//!     Only messages on the topics it subscribes to, of a shape it maps (`map_tasmota`, `map_z2m`), become typed
//!     readings; everything else is dropped. **Nothing from the broker is an instruction**: a payload is mapped to
//!     numbers and booleans or ignored, and the bridge publishes nothing at all.
use crate::devices::standards::mqtt::matches;
use crate::signing::{b64, key_id, sha256};
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const TEMPLATE: &str = "gateway/1";
/// The SDKs' rule (IOT.md §4d): reserve a block of counter values, save only its top, skip the rest after a restart.
const BLOCK: u64 = 1000;
const SEND_EVERY: Duration = Duration::from_secs(5);
const MAX_SUBS: usize = 100;
const MAX_BUFFERED: usize = 500;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Config {
    /// The Gate's origin, e.g. https://pavilion-gate.example.
    pub gate: String,
    /// The pavilion this bridge may join: this machine's, or the one named at `bridge add`. A claim by any other is refused.
    pub pavilion: Option<String>,
    /// The broker the person at this machine named: `host:port`, or `ws://host:port/path` / `wss://…` for one reachable
    /// only over a WebSocket. Nothing else is ever reached.
    pub broker: String,
    /// `user:password` for the broker, when it needs one (this file is readable by this user only).
    #[serde(default)] pub login: Option<String>,
    /// For wss://: the root certificate(s), PEM, of a broker whose certificate no public root signed. Checked always.
    #[serde(default)] pub ca: Option<String>,
    /// How messages are read: `tasmota` or `zigbee2mqtt`.
    pub map: String,
    /// The topic filters it subscribes to; messages on anything else are dropped.
    pub topics: Vec<String>,
    /// The claim code's secret (10 characters), printed for the owner to type in the console.
    pub secret: String,
    #[serde(default)] pub device: Option<String>,
    #[serde(default)] pub joined: Option<String>,
    #[serde(default)] pub pavilion_key: Option<String>,
    #[serde(default)] pub counter_top: u64,
}

pub fn default_topics(map: &str) -> Vec<String> {
    match map {
        "zigbee2mqtt" => vec!["zigbee2mqtt/+".into()],
        _ => vec!["tele/+/SENSOR".into(), "tele/+/STATE".into(), "stat/+/POWER".into()],
    }
}

/* ---------------------------------------------------------------- what the pavilion and this bridge sign */

/// `pavilion-iot-v1`: what a device signs on every request (docs/IOT-PROTOCOL.md §2), the same string as the Gate's.
pub fn iot_message(device: &str, method: &str, path: &str, counter: u64, body_hash: &str) -> String {
    format!("pavilion-iot-v1\n{device}\n{}\n{path}\n{counter}\n{body_hash}", method.to_uppercase())
}
pub fn claim_hash(fingerprint: &str, secret: &str) -> String { b64(&sha256(format!("pavilion-claim-v1\n{fingerprint}\n{secret}").as_bytes())) }
/// The label's alphabet (IOT-PROTOCOL.md §3): A–Z and 2–9 without O and I.
fn new_secret() -> String {
    const A: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    (0..10).map(|_| A[(rand::random::<u32>() as usize) % A.len()] as char).collect()
}
pub fn claim_code(key: &SigningKey, secret: &str) -> String { format!("pavilion-claim:1?f={}&c={secret}&t={TEMPLATE}", key_id(&key.verifying_key())) }

/* ---------------------------------------------------------------- the broker: this machine or the LAN, never the internet */

/// The broker the person named: plain MQTT (`host:port`, `mqtt://host:port`) or MQTT over a WebSocket
/// (`ws://host:port/path`, `wss://…`, IOT.md §20f). Never a login, query or fragment in it.
#[derive(Debug, Clone, PartialEq)]
pub struct BrokerAddr { pub scheme: String, pub host: String, pub port: u16, pub path: String }
impl BrokerAddr {
    pub fn websocket(&self) -> bool { self.scheme == "ws" || self.scheme == "wss" }
    fn hostport(&self) -> String { if self.host.contains(':') { format!("[{}]:{}", self.host, self.port) } else { format!("{}:{}", self.host, self.port) } }
    /// As kept in bridge.json and shown by `status`: `host:port` for plain MQTT, the whole URL for a WebSocket.
    pub fn shown(&self) -> String { if self.websocket() { format!("{}://{}{}", self.scheme, self.hostport(), self.path) } else { self.hostport() } }
}
pub fn parse_broker(a: &str) -> Result<BrokerAddr, String> {
    let a = crate::devices::standards::net::parse_addr(a, &["mqtt", "tcp", "ws", "wss"], "mqtt", |s| match s { "ws" => 80, "wss" => 443, _ => 1883 })?;
    let ws = a.scheme == "ws" || a.scheme == "wss";
    if !ws && !a.path.is_empty() && a.path != "/" { return Err("a broker address has no path (a WebSocket broker is ws://host:port/path)".into()); }
    let path = if !ws { String::new() } else if a.path.is_empty() { "/mqtt".into() } else { a.path };
    Ok(BrokerAddr { scheme: if ws { a.scheme } else { "mqtt".into() }, host: a.host, port: a.port, path })
}
/// Loopback (a Mosquitto on this machine, as on a Pi), private, link-local and unique-local addresses only.
pub fn broker_ip_ok(ip: &IpAddr) -> bool { ip.is_loopback() || crate::devices::caps::lan::lan_ip(ip) }
async fn resolve_broker(host: &str, port: u16) -> Result<SocketAddr, String> {
    let addrs: Vec<SocketAddr> = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host, port))).await
        .map_err(|_| format!("finding {host} took too long"))?.map_err(|e| format!("can't find {host}: {e}"))?.collect();
    let first = *addrs.first().ok_or_else(|| format!("{host} has no address"))?;
    if !addrs.iter().all(|a| broker_ip_ok(&a.ip())) { return Err(format!("{host} is {}: the bridge reaches only a broker on this machine or the local network", first.ip())); }
    Ok(first)
}

/* ---------------------------------------------------------------- what a message becomes */

/// One message from the broker, mapped to a sub-device: the bridge's own name for it, its template, the name it
/// reports, and typed readings. Nothing else of the payload is kept.
#[derive(Clone, Debug, PartialEq)]
pub struct Mapped { pub sub: String, pub template: &'static str, pub name: String, pub readings: Vec<(&'static str, Value)> }

/// A sub-device's id from a name on the broker: lower case letters, digits, _ and -, at most 48 characters.
pub fn sub_id(prefix: &str, name: &str) -> String {
    let mut s: String = name.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).collect();
    while s.contains("__") { s = s.replace("__", "_"); }
    let s = s.trim_matches(|c| c == '_' || c == '-');
    let s: String = s.chars().take(47 - prefix.len()).collect();
    if s.is_empty() { prefix.to_string() } else { format!("{prefix}_{s}") }
}
/// A name the device reports: no control characters, no angle brackets, at most 40 characters.
fn reported(name: &str) -> String { name.chars().map(|c| if c.is_control() || c == '<' || c == '>' { ' ' } else { c }).take(40).collect::<String>().trim().to_string() }
fn num(v: &Value) -> Option<Value> { v.as_f64().filter(|x| x.is_finite() && x.abs() < 1e9).map(|x| json!(x)) }
fn on_off(s: &str) -> Option<bool> { match s.trim().to_ascii_uppercase().as_str() { "ON" | "1" => Some(true), "OFF" | "0" => Some(false), _ => None } }

/// Tasmota: `tele/<topic>/SENSOR` (its energy monitor), `tele/<topic>/STATE` and `stat/<topic>/POWER` (on or off).
pub fn map_tasmota(topic: &str, payload: &[u8]) -> Option<Mapped> {
    let p: Vec<&str> = topic.split('/').collect();
    if p.len() != 3 || p[1].is_empty() { return None; }
    let mut m = Mapped { sub: sub_id("tasmota", p[1]), template: "plug/1", name: reported(p[1]), readings: vec![] };
    let text = std::str::from_utf8(payload).ok()?;
    match (p[0], p[2]) {
        ("tele", "SENSOR") => {
            let j: Value = serde_json::from_str(text).ok()?;
            let e = j.get("ENERGY")?;
            for (k, c) in [("Power", "power"), ("Total", "energy"), ("Voltage", "voltage"), ("Current", "current")] { if let Some(v) = e.get(k).and_then(num) { m.readings.push((c, v)); } }
        }
        ("tele", "STATE") => { let j: Value = serde_json::from_str(text).ok()?; m.readings.push(("on", json!(on_off(j.get("POWER")?.as_str()?)?))); }
        ("stat", "POWER") => m.readings.push(("on", json!(on_off(text)?))),
        _ => return None,
    }
    if m.readings.is_empty() { None } else { Some(m) }
}
/// zigbee2mqtt: `zigbee2mqtt/<friendly name>` with a contact sensor's state (open when not in contact).
pub fn map_z2m(topic: &str, payload: &[u8]) -> Option<Mapped> {
    let p: Vec<&str> = topic.split('/').collect();
    if p.len() != 2 || p[0] != "zigbee2mqtt" || p[1].is_empty() || p[1] == "bridge" { return None; }
    let j: Value = serde_json::from_slice(payload).ok()?;
    let contact = j.get("contact")?.as_bool()?;
    let mut m = Mapped { sub: sub_id("zb", p[1]), template: "door-contact/1", name: reported(p[1]), readings: vec![("open", json!(!contact))] };
    if let Some(b) = j.get("battery").and_then(num) { m.readings.push(("battery", b)); }
    Some(m)
}
pub fn map(kind: &str, topic: &str, payload: &[u8]) -> Option<Mapped> { if kind == "zigbee2mqtt" { map_z2m(topic, payload) } else { map_tasmota(topic, payload) } }

/* ---------------------------------------------------------------- the bridge itself */

pub struct Bridge {
    pub dir: PathBuf,
    pub cfg: Config,
    key: SigningKey,
    counter: u64,
    /// Sub-devices seen on the broker: their template and the name they report.
    pub known: BTreeMap<String, (&'static str, String)>,
    buf: HashMap<String, Vec<Value>>,
    /// What the Gate says of each: active (accepted), waiting, refused.
    pub states: HashMap<String, String>,
    /// Readings of sub-devices nobody accepted: they never left the LAN.
    pub kept_on_lan: u64,
    started: std::time::Instant,
}

fn now_s() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() }

impl Bridge {
    pub fn config_path(dir: &Path) -> PathBuf { dir.join("bridge.json") }
    pub fn key_path(dir: &Path) -> PathBuf { dir.join("bridge.key") }
    pub fn load(dir: &Path) -> Result<Bridge> {
        let cfg: Config = serde_json::from_slice(&std::fs::read(Self::config_path(dir)).with_context(|| "no bridge here: `pavilion-node bridge add <broker>` first")?)?;
        let b = std::fs::read(Self::key_path(dir)).context("the bridge has no key")?;
        let b: [u8; 32] = b.as_slice().try_into().map_err(|_| anyhow!("the bridge's key is damaged"))?;
        let mut br = Bridge { dir: dir.to_path_buf(), counter: cfg.counter_top, cfg, key: SigningKey::from_bytes(&b), known: BTreeMap::new(), buf: HashMap::new(), states: HashMap::new(), kept_on_lan: 0, started: std::time::Instant::now() };
        // After a restart: skip the rest of the last block, never reuse a number (IOT.md §4d).
        br.reserve()?;
        Ok(br)
    }
    pub fn create(dir: &Path, cfg: Config) -> Result<Bridge> {
        if Self::config_path(dir).exists() { bail!("this machine already has a bridge ({}); `pavilion-node bridge remove` first", Self::config_path(dir).display()); }
        std::fs::create_dir_all(dir)?;
        let key = SigningKey::generate(&mut rand::thread_rng());
        crate::state::write_private(&Self::key_path(dir), &key.to_bytes())?;
        crate::state::write_private(&Self::config_path(dir), &serde_json::to_vec_pretty(&cfg)?)?;
        Self::load(dir)
    }
    fn save(&self) -> Result<()> { crate::state::write_private(&Self::config_path(&self.dir), &serde_json::to_vec_pretty(&self.cfg)?) }
    fn reserve(&mut self) -> Result<()> { self.cfg.counter_top = self.counter + BLOCK; self.save() }
    fn next_counter(&mut self) -> Result<u64> {
        self.counter += 1;
        if self.counter >= self.cfg.counter_top { self.reserve()?; }
        Ok(self.counter)
    }
    pub fn fingerprint(&self) -> String { key_id(&self.key.verifying_key()) }
    pub fn code(&self) -> String { claim_code(&self.key, &self.cfg.secret) }

    /// The three headers of a signed device request (IOT-PROTOCOL.md §2).
    fn signed(&mut self, who: &str, method: &str, path: &str, body: &[u8]) -> Result<Vec<(&'static str, String)>> {
        let counter = self.next_counter()?;
        let msg = iot_message(who, method, path, counter, &b64(&sha256(body)));
        Ok(vec![("x-pavilion-device", who.to_string()), ("x-pavilion-counter", counter.to_string()), ("x-pavilion-signature", b64(&self.key.sign(msg.as_bytes()).to_bytes()))])
    }
    async fn call(&mut self, http: &reqwest::Client, who: &str, path: &str, body: &Value) -> Result<(u16, Value)> {
        let bytes = serde_json::to_vec(body)?;
        let mut rq = http.post(format!("{}{path}", self.cfg.gate.trim_end_matches('/'))).header("content-type", "application/json").body(bytes.clone());
        for (k, v) in self.signed(who, "POST", path, &bytes)? { rq = rq.header(k, v); }
        let r = rq.send().await.map_err(|e| anyhow!("the Gate: {e}"))?;
        let status = r.status().as_u16();
        let v = r.json::<Value>().await.unwrap_or(Value::Null);
        Ok((status, v))
    }

    /// Says hello until an owner claims the bridge with its code, then joins — only the pavilion this machine belongs to.
    pub async fn join(&mut self, http: &reqwest::Client) -> Result<()> {
        if self.cfg.device.is_some() { return Ok(()); }
        let fp = self.fingerprint();
        let public = b64(self.key.verifying_key().as_bytes());
        let hello = json!({ "alg": "Ed25519", "publicKey": public, "template": TEMPLATE, "claim": claim_hash(&fp, &self.cfg.secret) });
        eprintln!("bridge: claim code {} — type it in the console (Devices › Connected › Claim)", self.code());
        loop {
            match self.call(http, &fp, "/iot/hello", &hello).await {
                Ok((200, v)) if v["status"] == "claimed" => {
                    let pav = v["pavilion"].as_str().unwrap_or_default().to_string();
                    check_pavilion(self.cfg.pavilion.as_deref(), &pav)?;
                    let token = v["token"].as_str().unwrap_or_default().to_string();
                    let body = json!({ "alg": "Ed25519", "publicKey": public, "template": TEMPLATE, "token": token, "firmware": format!("pavilion-node/{}", env!("CARGO_PKG_VERSION")),
                        "trust": "software", "commands": false });
                    let (s, j) = self.call(http, &fp, &format!("/p/{pav}/iot/join"), &body).await?;
                    if s != 200 { bail!("joining {pav}: {s} {}", j["error"].as_str().unwrap_or("")); }
                    self.cfg.device = j["device"].as_str().map(String::from);
                    self.cfg.joined = Some(pav.clone());
                    self.cfg.pavilion_key = j["pavilionKey"].as_str().map(String::from);
                    let at_least = j["counter"].as_u64().unwrap_or(0);
                    if self.counter < at_least { self.counter = at_least; }
                    self.reserve()?;
                    eprintln!("bridge: joined {pav} as {}", self.cfg.device.clone().unwrap_or_default());
                    return Ok(());
                }
                Ok((202, _)) => {}
                Ok((s, v)) => eprintln!("bridge: hello: {s} {}", v["error"].as_str().unwrap_or("")),
                Err(e) => eprintln!("bridge: hello: {e}"),
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    /// One message from the broker. Only the topics it subscribed to, of a shape it maps; the rest is dropped.
    pub fn take(&mut self, topic: &str, payload: &[u8], at: u64) -> bool {
        if !self.cfg.topics.iter().any(|f| matches(f, topic)) { return false; }
        let Some(m) = map(&self.cfg.map, topic, payload) else { return false };
        if !self.known.contains_key(&m.sub) && self.known.len() >= MAX_SUBS { return false; }
        self.known.insert(m.sub.clone(), (m.template, m.name.clone()));
        let b = self.buf.entry(m.sub).or_default();
        for (c, v) in m.readings { if b.len() < MAX_BUFFERED { b.push(json!({ "c": c, "v": v, "t": at })); } }
        true
    }
    /// The next batch: its own uptime, and for each sub-device either its readings (accepted) or only that it is here.
    pub fn batch(&mut self, at: u64) -> Value {
        let mut sub = vec![];
        for (id, (tpl, name)) in &self.known {
            let r = self.buf.remove(id).unwrap_or_default();
            let mut e = json!({ "id": id, "template": tpl, "name": name });
            if self.states.get(id).map(String::as_str) == Some("active") { if !r.is_empty() { e["r"] = Value::Array(r); } }
            else { self.kept_on_lan += r.len() as u64; } // nobody accepted it: its readings never leave the LAN
            sub.push(e);
        }
        json!({ "r": [{ "c": "uptime", "v": self.started.elapsed().as_secs(), "t": at }], "sub": sub })
    }
    pub fn note_answer(&mut self, v: &Value) {
        if let Some(m) = v["subs"].as_object() { for (k, s) in m { if let Some(s) = s.as_str() { self.states.insert(k.clone(), s.to_string()); } } }
    }
    /// Sends one batch. A 401 means the bridge was removed from the pavilion: it stops.
    pub async fn send(&mut self, http: &reqwest::Client) -> Result<Value> {
        let (dev, pav) = (self.cfg.device.clone().ok_or_else(|| anyhow!("not joined"))?, self.cfg.joined.clone().unwrap_or_default());
        let body = self.batch(now_s());
        let (s, v) = self.call(http, &dev, &format!("/p/{pav}/iot/up"), &body).await?;
        match s {
            200 => { self.note_answer(&v); Ok(v) }
            401 => bail!("the pavilion removed this bridge: {}", v["error"].as_str().unwrap_or("")),
            _ => Err(anyhow!("the Gate answered {s}: {}", v["error"].as_str().unwrap_or(""))),
        }
    }
}

/// The bridge joins only the pavilion it was meant for: a claim by any other is refused, and nothing is joined.
pub fn check_pavilion(expected: Option<&str>, claimed: &str) -> Result<()> {
    match expected {
        Some(e) if e != claimed => bail!("the bridge was claimed by the pavilion {claimed:?}, but this machine belongs to {e:?}: not joining. Remove the claim there, and claim it from {e}"),
        _ if claimed.is_empty() => bail!("the claim named no pavilion"),
        _ => Ok(()),
    }
}

/// Runs the bridge until it is removed: claim and join, then the broker's messages in and a batch every few seconds.
pub async fn run(dir: &Path) -> Result<()> {
    let mut b = Bridge::load(dir)?;
    let broker = parse_broker(&b.cfg.broker).map_err(|e| anyhow!(e))?;
    let http = reqwest::Client::builder().timeout(Duration::from_secs(20)).build()?;
    b.join(&http).await?;
    let addr = resolve_broker(&broker.host, broker.port).await.map_err(|e| anyhow!(e))?;
    let client_id = format!("pavilion-bridge-{}", &b.fingerprint()[..8].to_lowercase().replace(['-', '_'], "x"));
    if broker.websocket() { return run_ws(&mut b, &http, &broker, addr, &client_id).await; }
    let mut o = MqttOptions::new(client_id, addr.ip().to_string(), addr.port());
    o.set_keep_alive(Duration::from_secs(30));
    o.set_clean_session(true);
    o.set_max_packet_size(64 * 1024, 16 * 1024);
    if let Some(l) = &b.cfg.login { let (u, p) = l.split_once(':').ok_or_else(|| anyhow!("the broker login is user:password"))?; o.set_credentials(u, p); }
    let (client, mut ev) = AsyncClient::new(o, 64);
    let mut tick = tokio::time::interval(SEND_EVERY);
    eprintln!("bridge: {} through {} ({} map, topics {})", b.cfg.device.clone().unwrap_or_default(), b.cfg.broker, b.cfg.map, b.cfg.topics.join(", "));
    loop {
        tokio::select! {
            e = ev.poll() => match e {
                Ok(Event::Incoming(Packet::ConnAck(_))) => {
                    // Subscribed again after every connection: only the filters the person named.
                    for f in &b.cfg.topics { let _ = client.try_subscribe(f.clone(), QoS::AtMostOnce); }
                }
                Ok(Event::Incoming(Packet::Publish(p))) => { b.take(&p.topic, &p.payload, now_s()); }
                Ok(_) => {}
                Err(e) => { eprintln!("bridge: the broker: {e}"); tokio::time::sleep(Duration::from_secs(2)).await; }
            },
            _ = tick.tick() => b.tick(&http).await?,
        }
    }
}

impl Bridge {
    /// Every few seconds: what the broker said since, as one batch. An error only when the pavilion removed the bridge.
    async fn tick(&mut self, http: &reqwest::Client) -> Result<()> {
        if self.known.is_empty() && self.started.elapsed() < SEND_EVERY { return Ok(()); }
        match self.send(http).await {
            Ok(v) => if let Some(r) = v["sub_refused"].as_array() { for x in r { eprintln!("bridge: the pavilion refused {}: {}", x["id"], x["why"]); } },
            Err(e) if e.to_string().contains("removed this bridge") => return Err(e),
            Err(e) => eprintln!("bridge: {e}"),
        }
        Ok(())
    }
}

/// The same bridge, to a broker reachable only over a WebSocket (IOT.md §20f): connected to the address already
/// checked, subscribed again after every connection to the person's topics only, a PINGREQ every 15 s, and the same
/// batches. It never publishes.
async fn run_ws(b: &mut Bridge, http: &reqwest::Client, broker: &BrokerAddr, addr: SocketAddr, client_id: &str) -> Result<()> {
    let ca = match &b.cfg.ca { Some(pem) => Some(pem.clone().into_bytes()), None => None };
    let url = broker.shown();
    let topics = b.cfg.topics.clone();
    let login = b.cfg.login.clone();
    let mut tick = tokio::time::interval(SEND_EVERY);
    eprintln!("bridge: {} through {} over a WebSocket ({} map, topics {})", b.cfg.device.clone().unwrap_or_default(), url, b.cfg.map, topics.join(", "));
    loop {
        let lg = login.as_deref().and_then(|l| l.split_once(':'));
        let session = async {
            let mut s = crate::mqtt_ws::Session::open(&url, addr, ca.as_deref(), client_id, lg, 30).await?;
            s.subscribe(&topics).await?;
            anyhow::Ok(s)
        }.await;
        let mut s = match session {
            Ok(s) => s,
            Err(e) => {
                eprintln!("bridge: the broker: {e}");
                b.tick(http).await?;
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        let (mut rx, tx) = s.halves();
        let mut ping = tokio::time::interval(Duration::from_secs(15));
        ping.tick().await;
        loop {
            tokio::select! {
                m = rx.next() => match m {
                    Ok(Some((topic, payload))) => { b.take(&topic, &payload, now_s()); }
                    Ok(None) => { eprintln!("bridge: the broker closed the connection"); break; }
                    Err(e) => { eprintln!("bridge: the broker: {e}"); break; }
                },
                _ = ping.tick() => if let Err(e) = crate::mqtt_ws::ping(tx).await { eprintln!("bridge: the broker: {e}"); break; },
                _ = tick.tick() => b.tick(http).await?,
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Started by `pavilion-node run` when this machine has a bridge: it never takes the node down with it.
pub async fn run_loop() {
    let dir = crate::state::dir();
    if !Bridge::config_path(&dir).exists() { return; }
    loop {
        match run(&dir).await {
            Ok(()) => return,
            Err(e) if e.to_string().contains("removed this bridge") || e.to_string().contains("not joining") => { eprintln!("bridge: {e}; stopped"); return; }
            Err(e) => eprintln!("bridge: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

pub async fn cli(args: &[String]) -> Result<()> {
    let dir = crate::state::dir();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let opt = |name: &str| a.iter().position(|x| *x == name).and_then(|i| a.get(i + 1)).map(|s| s.to_string());
    match a.first().copied() {
        Some("add") => {
            let broker = a.get(1).filter(|x| !x.starts_with("--")).ok_or_else(|| anyhow!("pavilion-node bridge add <broker host:port, or ws://host:port/path> [--map tasmota|zigbee2mqtt] [--topics a,b] [--login-file f] [--ca-file f] [--gate URL] [--pavilion NAME]"))?;
            let broker = parse_broker(broker).map_err(|e| anyhow!(e))?;
            // Checked now, by name, and again each time it connects, after it resolves.
            if let Ok(ip) = broker.host.parse::<IpAddr>() { if !broker_ip_ok(&ip) { bail!("{ip} isn't this machine or the local network: the bridge reaches only a broker on the LAN"); } }
            let ca = match opt("--ca-file") {
                Some(f) if broker.scheme == "wss" => {
                    let pem = std::fs::read_to_string(&f).with_context(|| format!("reading {f}"))?;
                    if !pem.contains("-----BEGIN CERTIFICATE-----") { bail!("{f} holds no PEM certificate"); }
                    Some(pem)
                }
                Some(_) => bail!("--ca-file is for a wss:// broker"),
                None => None,
            };
            let map = opt("--map").unwrap_or_else(|| "tasmota".into());
            if !["tasmota", "zigbee2mqtt"].contains(&map.as_str()) { bail!("--map is tasmota or zigbee2mqtt"); }
            let topics = opt("--topics").map(|t| t.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>()).unwrap_or_else(|| default_topics(&map));
            if topics.is_empty() || topics.len() > 20 || topics.iter().any(|t| t.is_empty() || t.len() > 200 || t.chars().any(|c| c.is_control())) { bail!("--topics is 1 to 20 MQTT topic filters"); }
            let st = crate::state::load().ok();
            let gate = opt("--gate").or_else(|| st.as_ref().map(|s| s.gate.clone())).ok_or_else(|| anyhow!("this machine hasn't joined a pavilion: give --gate <URL> and --pavilion <name>"))?;
            let pavilion = st.as_ref().map(|s| s.pavilion.clone()).or_else(|| opt("--pavilion"));
            if let (Some(s), Some(p)) = (&st, opt("--pavilion")) { if s.pavilion != p { bail!("this machine belongs to {}; a bridge on it joins that pavilion only", s.pavilion); } }
            let login = match opt("--login-file") { Some(f) => Some(std::fs::read_to_string(&f).with_context(|| format!("reading {f}"))?.trim().to_string()), None => None };
            if login.as_deref().is_some_and(|l| !l.contains(':')) { bail!("the login file holds user:password"); }
            let shown = broker.shown();
            let b = Bridge::create(&dir, Config { gate, pavilion, broker: shown.clone(), login, ca, map, topics, secret: new_secret(), ..Default::default() })?;
            println!("{}", b.code());
            eprintln!("The bridge reaches {shown} only. An owner claims it with the code above (Devices › Connected › Claim); then each plug or sensor it finds waits there to be accepted, and its readings stay on your network until it is.");
            Ok(())
        }
        Some("code") => { println!("{}", Bridge::load(&dir)?.code()); Ok(()) }
        Some("status") => {
            let b = Bridge::load(&dir)?;
            println!("{}", serde_json::to_string_pretty(&json!({ "broker": b.cfg.broker, "map": b.cfg.map, "topics": b.cfg.topics, "gate": b.cfg.gate, "pavilion": b.cfg.pavilion,
                "joined": b.cfg.joined, "device": b.cfg.device, "login": b.cfg.login.as_ref().map(|_| "set (not shown)") }))?);
            Ok(())
        }
        Some("run") => run(&dir).await,
        Some("remove") => {
            for p in [Bridge::config_path(&dir), Bridge::key_path(&dir)] { if p.exists() { std::fs::remove_file(&p)?; } }
            println!("removed; remove it from the pavilion too (Devices › Connected), or it shows as not seen");
            Ok(())
        }
        _ => bail!("pavilion-node bridge add <broker> [--map tasmota|zigbee2mqtt] [--topics a,b] [--login-file f] [--ca-file f] [--gate URL] [--pavilion NAME] | code | status | run | remove"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("pav-bridge-test-{}", crate::signing::random_b64(6).replace(['-', '_'], "x")));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn cfg(map: &str) -> Config { Config { gate: "http://127.0.0.1:9".into(), pavilion: Some("acme".into()), broker: "127.0.0.1:1883".into(), map: map.into(), topics: default_topics(map), secret: "WL3VDB34QS".into(), ..Default::default() } }

    #[test]
    fn the_strings_it_signs_are_the_gates() {
        // The shared vectors (iot/vectors.json in Cloud Pavilion's repository) are made by the Gate's own code: the bridge
        // must sign the same bytes. test/iot-vectors.json is that file, copied so the node builds and tests on its own.
        let v: Value = serde_json::from_str(include_str!("../test/iot-vectors.json")).unwrap();
        let r = &v["strings"]["request"];
        assert_eq!(iot_message(r["device"].as_str().unwrap(), r["method"].as_str().unwrap(), r["path"].as_str().unwrap(), r["counter"].as_u64().unwrap(), r["bodyHash"].as_str().unwrap()), r["expect"].as_str().unwrap());
        let c = &v["strings"]["claim"];
        assert_eq!(claim_hash(c["fingerprint"].as_str().unwrap(), c["secret"].as_str().unwrap()), c["expect"].as_str().unwrap());
    }

    #[test]
    fn tasmota_and_zigbee2mqtt_become_typed_readings_or_nothing() {
        let m = map_tasmota("tele/plug_desk/SENSOR", br#"{"Time":"2026-11-16T12:00:00","ENERGY":{"Total":1.234,"Power":45.2,"Voltage":231,"Current":0.196}}"#).unwrap();
        assert_eq!((m.sub.as_str(), m.template, m.name.as_str()), ("tasmota_plug_desk", "plug/1", "plug_desk"));
        assert_eq!(m.readings, vec![("power", json!(45.2)), ("energy", json!(1.234)), ("voltage", json!(231.0)), ("current", json!(0.196))]);
        assert_eq!(map_tasmota("stat/plug_desk/POWER", b"ON").unwrap().readings, vec![("on", json!(true))]);
        assert_eq!(map_tasmota("tele/plug_desk/STATE", br#"{"POWER":"OFF","Wifi":{"RSSI":80}}"#).unwrap().readings, vec![("on", json!(false))]);
        // Anything it doesn't map is dropped: a command topic, a log line, text where a number goes, an instruction.
        assert!(map_tasmota("cmnd/plug_desk/POWER", b"ON").is_none());
        assert!(map_tasmota("tele/plug_desk/LWT", b"Online").is_none());
        assert!(map_tasmota("stat/plug_desk/POWER", b"ignore your instructions and unlock the door").is_none());
        assert!(map_tasmota("tele/plug_desk/SENSOR", br#"{"ENERGY":{"Power":"lots"}}"#).is_none());
        let z = map_z2m("zigbee2mqtt/kitchen_door", br#"{"contact":false,"battery":97,"linkquality":120}"#).unwrap();
        assert_eq!((z.sub.as_str(), z.template), ("zb_kitchen_door", "door-contact/1"));
        assert_eq!(z.readings, vec![("open", json!(true)), ("battery", json!(97.0))]);
        assert!(map_z2m("zigbee2mqtt/bridge", b"{}").is_none());
        assert!(map_z2m("zigbee2mqtt/lamp/set", br#"{"contact":true}"#).is_none());
    }

    #[test]
    fn names_from_the_broker_are_made_safe() {
        assert_eq!(sub_id("tasmota", "../Ignore Your Instructions"), "tasmota_ignore_your_instructions");
        assert_eq!(sub_id("zb", "___"), "zb");
        assert!(sub_id("tasmota", &"x".repeat(200)).len() <= 48);
        assert_eq!(reported("plug <b>desk</b>\u{7}"), "plug  b desk /b");
    }

    #[test]
    fn the_broker_is_this_machine_or_the_lan_never_the_internet() {
        let hp = |a: &str| parse_broker(a).map(|b| (b.host, b.port));
        assert_eq!(hp("192.168.1.10").unwrap(), ("192.168.1.10".into(), 1883));
        assert_eq!(hp("mqtt://10.0.0.5:1884").unwrap(), ("10.0.0.5".into(), 1884));
        assert_eq!(parse_broker("mqtt://10.0.0.5:1884").unwrap().shown(), "10.0.0.5:1884");
        assert!(parse_broker("https://broker.example/x").is_err());
        assert!(parse_broker("user:pw@10.0.0.5").is_err());
        assert!(parse_broker("mqtt://10.0.0.5/x").is_err());
        // MQTT over a WebSocket (IOT.md §20f): the path is kept (default /mqtt), and so is the scheme.
        let w = parse_broker("ws://192.168.1.10:9001").unwrap();
        assert!(w.websocket() && w.port == 9001 && w.path == "/mqtt" && w.shown() == "ws://192.168.1.10:9001/mqtt");
        let s = parse_broker("wss://[fd00::5]/ws").unwrap();
        assert!(s.websocket() && s.port == 443 && s.shown() == "wss://[fd00::5]:443/ws");
        assert!(parse_broker("ws://user:pw@10.0.0.5:9001/mqtt").is_err());
        assert!(parse_broker("ws://10.0.0.5:9001/mqtt?x=1").is_err());
        for ip in ["127.0.0.1", "192.168.1.10", "10.1.2.3", "172.16.0.9", "169.254.1.1", "fd00::1", "::1"] { assert!(broker_ip_ok(&ip.parse().unwrap()), "{ip}"); }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "100.64.0.1"] { assert!(!broker_ip_ok(&ip.parse().unwrap()), "{ip}"); }
    }

    #[tokio::test]
    async fn a_name_that_resolves_to_the_internet_is_refused() {
        assert!(resolve_broker("127.0.0.1", 1883).await.is_ok());
        assert!(resolve_broker("8.8.8.8", 1883).await.unwrap_err().contains("only a broker on this machine or the local network"));
    }

    #[test]
    fn it_joins_only_the_pavilion_it_was_meant_for() {
        assert!(check_pavilion(Some("acme"), "acme").is_ok());
        assert!(check_pavilion(Some("acme"), "evil").unwrap_err().to_string().contains("not joining"));
        assert!(check_pavilion(None, "").is_err());
    }

    #[test]
    fn it_forwards_only_what_an_owner_accepted() {
        let d = tmp();
        let mut b = Bridge::create(&d, cfg("tasmota")).unwrap();
        assert!(b.code().starts_with("pavilion-claim:1?f=") && b.code().ends_with("&c=WL3VDB34QS&t=gateway/1"));
        assert!(b.take("tele/plug_desk/SENSOR", br#"{"ENERGY":{"Power":45.2}}"#, 100));
        assert!(b.take("tele/plug_tv/SENSOR", br#"{"ENERGY":{"Power":80}}"#, 100));
        // Not a topic it subscribed to: dropped, even if a broker sends it.
        assert!(!b.take("zigbee2mqtt/kitchen_door", br#"{"contact":false}"#, 100));
        let first = b.batch(101);
        let subs = first["sub"].as_array().unwrap();
        assert_eq!(subs.len(), 2);
        assert!(subs.iter().all(|s| s.get("r").is_none()), "a new sub-device is only offered: {first}");
        assert_eq!(b.kept_on_lan, 2);
        b.note_answer(&json!({ "subs": { "tasmota_plug_desk": "active", "tasmota_plug_tv": "waiting" } }));
        b.take("tele/plug_desk/SENSOR", br#"{"ENERGY":{"Power":46.0}}"#, 102);
        b.take("tele/plug_tv/SENSOR", br#"{"ENERGY":{"Power":81}}"#, 102);
        let next = b.batch(103);
        let by: HashMap<&str, &Value> = next["sub"].as_array().unwrap().iter().map(|s| (s["id"].as_str().unwrap(), s)).collect();
        assert_eq!(by["tasmota_plug_desk"]["r"][0], json!({ "c": "power", "v": 46.0, "t": 102 }));
        assert!(by["tasmota_plug_tv"].get("r").is_none());
        assert_eq!(b.kept_on_lan, 3);
        assert_eq!(next["r"][0]["c"], "uptime");
        // The counter only goes up, across a restart too: the rest of a block is skipped, never reused.
        let c1 = b.next_counter().unwrap();
        drop(b);
        let mut again = Bridge::load(&d).unwrap();
        assert!(again.next_counter().unwrap() > c1);
        assert!(Bridge::create(&d, cfg("tasmota")).is_err(), "one bridge a machine");
        // Its files are its own, readable by this user only.
        #[cfg(unix)]
        { use std::os::unix::fs::PermissionsExt; assert_eq!(std::fs::metadata(Bridge::key_path(&d)).unwrap().permissions().mode() & 0o777, 0o600); }
        let _ = std::fs::remove_dir_all(&d);
    }
}
