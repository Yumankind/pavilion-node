//! The capabilities themselves: one typed operation per tool (DEVICES-PROTOCOL.md §5), with its arguments checked
//! again here (sizes, durations, adopted devices, listed paths), then done once on this computer, outside any sandbox.
//!
//! Bluetooth LE (`btleplug`: CoreBluetooth on macOS, WinRT on Windows) and the local network (`mdns-sd`, `reqwest`)
//! are the same code on both. Camera, mic, screen, speaker and location go to the platform: the Swift helper inside
//! `Pavilion Node.app` on macOS (helper.rs), the Windows APIs on Windows (windows.rs).
use super::envelope::{scan_id, External};
pub use super::standards::{Lent, Prep};
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq)]
pub enum Op {
    CameraSnapshot { camera: String, max_px: u32 },
    CameraClip { camera: String, seconds: u32 },
    RecordAudio { seconds: u32 },
    ScreenCapture,
    PlayAudio { text: Option<String>, asset: Option<String> },
    Location { accuracy_m: u32 },
    BleScan { seconds: u32, service: Option<String> },
    BleRead { ext: External, characteristic: String },
    BleWrite { ext: External, characteristic: String, bytes: Vec<u8> },
    BleSubscribe { ext: External, characteristic: String, seconds: u32 },
    LanDiscover { types: Vec<String>, seconds: u32 },
    LanRequest { ext: External, method: String, path: String, body: Option<String> },
    /// The first set of standards: OBD-II, Home Assistant, MQTT, Cast, IPP, ONVIF, Modbus (standards/).
    Std(super::standards::StdOp),
}

/// What an operation produced: bytes for an asset (a photo, a clip, a recording), or a JSON reading.
#[derive(Debug)]
pub enum Output { Bytes { ctype: String, bytes: Vec<u8> }, Json(Value) }

/// Bonjour types listed by default for `lan_discover`, and in the app's NSBonjourServices (node/macos/Info.plist).
pub const DEFAULT_LAN_TYPES: &[&str] = &["_http._tcp", "_https._tcp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_scanner._tcp",
    "_uscan._tcp", "_airplay._tcp", "_raop._tcp", "_googlecast._tcp", "_spotify-connect._tcp", "_sonos._tcp", "_hap._tcp", "_matter._tcp",
    "_matterc._udp", "_mqtt._tcp", "_home-assistant._tcp", "_hue._tcp", "_smb._tcp", "_afpovertcp._tcp", "_ssh._tcp", "_sftp-ssh._tcp", "_rfb._tcp",
    "_device-info._tcp", "_workstation._tcp", "_companion-link._tcp", "_esphomelib._tcp", "_octoprint._tcp", "_daap._tcp"];

const MAX_ITEMS: usize = 200;
const MAX_LAN_BODY: usize = 256 * 1024;

fn uuid_ok(s: &str) -> bool {
    let s = s.trim();
    (s.len() == 4 || s.len() == 8) && s.bytes().all(|b| b.is_ascii_hexdigit())
        || (s.len() == 36 && s.bytes().enumerate().all(|(i, b)| if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() }))
}
/// A Bluetooth UUID in its full 128-bit form, lowercase (16- and 32-bit ones expanded with the Bluetooth base).
pub fn full_uuid(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_lowercase();
    if !uuid_ok(&s) { return None; }
    Some(match s.len() { 4 => format!("0000{s}-0000-1000-8000-00805f9b34fb"), 8 => format!("{s}-0000-1000-8000-00805f9b34fb"), _ => s })
}
pub fn lan_type_ok(t: &str) -> bool {
    let Some((name, proto)) = t.strip_prefix('_').and_then(|r| r.split_once("._")) else { return false };
    (proto == "tcp" || proto == "udp") && !name.is_empty() && name.len() <= 15 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn int(args: &Value, k: &str, lo: u64, hi: u64, default: Option<u64>) -> Result<u32, String> {
    match &args[k] {
        Value::Null => default.map(|d| d as u32).ok_or_else(|| format!("{k} is missing")),
        v => v.as_u64().filter(|n| (lo..=hi).contains(n)).map(|n| n as u32).ok_or_else(|| format!("{k} must be a whole number from {lo} to {hi}")),
    }
}

pub(crate) fn adopted<'a>(ext: Option<&'a External>, args: &Value, kind: &str) -> Result<&'a External, String> {
    let e = ext.ok_or("this tool needs an adopted device, and the action names none")?;
    if args["external"].as_str() != Some(e.id.as_str()) { return Err("the action's device isn't the one it was adopted as".into()); }
    if e.kind != kind { return Err(format!("{} is a {} device, not {kind}", e.id, e.kind)); }
    if e.address.trim().is_empty() { return Err(format!("{} has no address", e.id)); }
    Ok(e)
}

/// Only the characteristics the adoption lists.
fn listed_characteristic(e: &External, c: &str) -> Result<String, String> {
    let want = full_uuid(c).ok_or_else(|| format!("{c:?} isn't a Bluetooth UUID"))?;
    if !e.characteristics.iter().any(|x| full_uuid(x).as_deref() == Some(want.as_str())) { return Err(format!("characteristic {c} isn't one the adoption of {} lists", e.id)); }
    Ok(want)
}

/// The tool's arguments, checked again on this computer (the Gate checked them too).
pub fn parse(tool: &str, args: &Value, ext: Option<&External>) -> Result<Op, String> {
    let camera = || -> Result<String, String> {
        let c = args["camera"].as_str().unwrap_or("front");
        if c.len() > 200 || c.chars().any(|c| c.is_control()) { return Err("camera isn't a camera name".into()); }
        Ok(c.to_string())
    };
    if let Some(r) = super::standards::parse(tool, args, ext) { return r.map(Op::Std); }
    Ok(match tool {
        "camera_snapshot" => Op::CameraSnapshot { camera: camera()?, max_px: int(args, "max_px", 256, 4096, Some(2048))? },
        "camera_clip" => Op::CameraClip { camera: camera()?, seconds: int(args, "seconds", 1, 30, None)? },
        "record_audio" => Op::RecordAudio { seconds: int(args, "seconds", 1, 60, None)? },
        "screen_capture" => Op::ScreenCapture,
        "play_audio" => {
            let text = args["text"].as_str().map(String::from);
            let asset = args["asset"].as_str().map(String::from);
            if text.as_ref().map_or(false, |t| t.chars().count() > 500 || t.trim().is_empty()) { return Err("text must be 1 to 500 characters".into()); }
            if asset.as_ref().map_or(false, |a| !a.starts_with("ast_") || a.len() > 64) { return Err("asset isn't an asset id".into()); }
            if text.is_none() == asset.is_none() { return Err("play_audio takes text or an asset, one of them".into()); }
            Op::PlayAudio { text, asset }
        }
        "location" => Op::Location { accuracy_m: int(args, "accuracy_m", 10, 100_000, Some(1000))? },
        "ble_scan" => {
            let service = match args["service"].as_str() { Some(s) => Some(full_uuid(s).ok_or("service isn't a Bluetooth UUID")?), None => None };
            Op::BleScan { seconds: int(args, "seconds", 1, 10, Some(5))?, service }
        }
        "ble_read" | "ble_write" | "ble_subscribe" => {
            let e = adopted(ext, args, "ble")?.clone();
            let characteristic = listed_characteristic(&e, args["characteristic"].as_str().ok_or("characteristic is missing")?)?;
            match tool {
                "ble_read" => Op::BleRead { ext: e, characteristic },
                "ble_subscribe" => Op::BleSubscribe { ext: e, characteristic, seconds: int(args, "seconds", 1, 30, None)? },
                _ => {
                    let hex = args["hex"].as_str().ok_or("hex is missing")?;
                    if hex.len() % 2 != 0 || hex.len() > 1024 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) || hex.is_empty() { return Err("hex must be 1 to 512 bytes in hex".into()); }
                    let bytes = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
                    Op::BleWrite { ext: e, characteristic, bytes }
                }
            }
        }
        "lan_discover" => {
            let types: Vec<String> = match &args["types"] {
                Value::Null => DEFAULT_LAN_TYPES.iter().map(|s| s.to_string()).collect(),
                Value::Array(a) if !a.is_empty() && a.len() <= 32 => a.iter().map(|t| t.as_str().filter(|t| lan_type_ok(t)).map(String::from).ok_or_else(|| format!("{t} isn't a service type like _http._tcp"))).collect::<Result<_, _>>()?,
                _ => return Err("types must be a list of 1 to 32 service types".into()),
            };
            Op::LanDiscover { types, seconds: int(args, "seconds", 1, 10, Some(3))? }
        }
        "lan_request" => {
            let e = adopted(ext, args, "lan")?.clone();
            let method = args["method"].as_str().filter(|m| ["GET", "POST", "PUT"].contains(m)).ok_or("method must be GET, POST or PUT")?.to_string();
            let path = args["path"].as_str().ok_or("path is missing")?.to_string();
            if !path.starts_with('/') || path.len() > 2048 || path.chars().any(|c| c.is_control() || c == ' ') { return Err("path must start with / and have no spaces".into()); }
            if !e.paths.iter().any(|r| r.method == method && r.path == path) { return Err(format!("{method} {path} isn't a path the adoption of {} lists", e.id)); }
            let body = args["body"].as_str().map(String::from);
            if body.as_ref().map_or(false, |b| b.len() > 64 * 1024) { return Err("body is over 64 KB".into()); }
            if method == "GET" && body.is_some() { return Err("a GET has no body".into()); }
            Op::LanRequest { ext: e, method, path, body }
        }
        "sensor_read" | "nfc_read" | "nfc_write" => return Err(format!("{tool} isn't something a computer can do (phones only)")),
        t => return Err(format!("{t} isn't a device tool")),
    })
}

impl Op {
    /// Whether the person sees what will be sent before it goes (DEVICES.md §6a step 8).
    pub fn is_capture(&self) -> bool { matches!(self, Op::CameraSnapshot { .. } | Op::CameraClip { .. } | Op::RecordAudio { .. } | Op::ScreenCapture | Op::Location { .. }) || matches!(self, Op::Std(s) if s.is_capture()) }
    /// The adopted device the operation acts on, if any.
    pub fn external(&self) -> Option<&External> {
        match self { Op::BleRead { ext, .. } | Op::BleWrite { ext, .. } | Op::BleSubscribe { ext, .. } | Op::LanRequest { ext, .. } => Some(ext), Op::Std(s) => Some(s.external()), _ => None }
    }
    /// Needs the action's asset from the Gate (`…/actions/<act>/asset`).
    pub fn needs_asset(&self) -> bool { matches!(self, Op::PlayAudio { asset: Some(_), .. }) || matches!(self, Op::Std(s) if s.needs_asset()) }
    /// Upper bound on how long it takes once started (for timeouts).
    pub fn budget(&self) -> Duration {
        if let Op::Std(s) = self { return s.budget(); }
        Duration::from_secs(match self {
            Op::CameraClip { seconds, .. } | Op::RecordAudio { seconds } | Op::BleSubscribe { seconds, .. } => *seconds as u64 + 30,
            Op::BleScan { seconds, .. } | Op::LanDiscover { seconds, .. } => *seconds as u64 + 10,
            Op::PlayAudio { .. } => 120,
            _ => 45,
        })
    }
}

/// Does one operation. `pavilion` names the scan-id hash; `lent` holds what the node fetched for this action (the
/// asset, a lent secret).
pub async fn run(op: &Op, pavilion: &str, lent: &Lent) -> Result<Output, String> {
    let budget = op.budget();
    let work = async {
        match op {
            Op::BleScan { seconds, service } => ble::scan(*seconds, service.clone()).await.map(|items| Output::Json(json!({ "items": items.iter().map(|i| i.for_agent(pavilion)).collect::<Vec<_>>() }))),
            Op::BleRead { ext, characteristic } => ble::read(ext, characteristic).await.map(Output::Json),
            Op::BleWrite { ext, characteristic, bytes } => ble::write(ext, characteristic, bytes).await.map(|_| Output::Json(json!({ "done": true }))),
            Op::BleSubscribe { ext, characteristic, seconds } => ble::subscribe(ext, characteristic, *seconds).await.map(Output::Json),
            Op::LanDiscover { types, seconds } => lan::discover(types, *seconds).await.map(|items| Output::Json(json!({ "items": items.iter().map(|i| i.for_agent()).collect::<Vec<_>>() }))),
            Op::LanRequest { ext, method, path, body } => lan::request(ext, method, path, body.as_deref()).await.map(Output::Json),
            Op::Std(s) => super::standards::run(s, lent).await,
            other => platform(other, lent.asset.clone()).await,
        }
    };
    tokio::time::timeout(budget, work).await.map_err(|_| format!("it took longer than {} s", budget.as_secs()))?
}

#[cfg(target_os = "macos")]
async fn platform(op: &Op, asset: Option<Vec<u8>>) -> Result<Output, String> { super::helper::run(op, asset).await }
#[cfg(windows)]
async fn platform(op: &Op, asset: Option<Vec<u8>>) -> Result<Output, String> { super::windows::run(op, asset).await }
#[cfg(not(any(target_os = "macos", windows)))]
async fn platform(_op: &Op, _asset: Option<Vec<u8>>) -> Result<Output, String> { Err("this computer's node has no camera, mic, screen or location support yet (Linux)".into()) }

/// Rounds a position to the accuracy allowed: a grid of about `accuracy_m` metres.
pub fn round_position(lat: f64, lon: f64, accuracy_m: u32) -> (f64, f64) {
    let step_lat = accuracy_m as f64 / 111_320.0;
    let step_lon = step_lat / lat.to_radians().cos().abs().max(0.01);
    ((lat / step_lat).round() * step_lat, (lon / step_lon).round() * step_lon)
}

/* ---------- Bluetooth LE ---------- */

#[derive(Clone, Debug, PartialEq)]
pub struct BleItem { pub address: String, pub name: Option<String>, pub rssi: Option<i16>, pub services: Vec<String> }
impl BleItem {
    /// What an agent sees: the hashed id, never the address.
    pub fn for_agent(&self, pavilion: &str) -> Value { json!({ "id": scan_id(pavilion, &self.address), "name": self.name, "rssi": self.rssi, "services": self.services }) }
    /// What the owner sees for adoption: the address too.
    pub fn for_adoption(&self, pavilion: &str) -> Value { let mut v = self.for_agent(pavilion); v["address"] = json!(self.address); v }
}

/// A reading as hex, with the value decoded for the Bluetooth standard profiles (standards/gatt.rs): heart rate,
/// blood pressure, weight, thermometer, glucose, pulse oximeter, cycling power and speed, running speed, indoor bike,
/// environmental sensing, battery.
pub fn reading(characteristic: &str, bytes: &[u8]) -> Value {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let c = characteristic.to_ascii_lowercase();
    let parsed = (c.len() == 36 && c.starts_with("0000") && c.ends_with("-0000-1000-8000-00805f9b34fb")).then(|| super::standards::gatt::decode(&c[4..8], bytes)).flatten();
    json!({ "hex": hex, "parsed": parsed })
}

#[cfg(any(target_os = "macos", windows))]
pub mod ble {
    use super::{reading, BleItem, External, MAX_ITEMS};
    use btleplug::api::{Central, CharPropFlags, Manager as _, Peripheral as _, ScanFilter, WriteType};
    use btleplug::platform::{Adapter, Manager, Peripheral};
    use futures_util::StreamExt;
    use serde_json::{json, Value};
    use std::time::Duration;

    fn err(e: btleplug::Error) -> String {
        let s = e.to_string();
        if s.to_lowercase().contains("permission") || s.to_lowercase().contains("unauthorized") { format!("Bluetooth permission isn't granted to Pavilion Node ({s})") } else { format!("Bluetooth: {s}") }
    }
    async fn adapter() -> Result<Adapter, String> {
        let m = Manager::new().await.map_err(err)?;
        m.adapters().await.map_err(err)?.into_iter().next().ok_or_else(|| "this computer has no Bluetooth adapter".to_string())
    }
    fn uuid(s: &str) -> Result<uuid::Uuid, String> { uuid::Uuid::parse_str(s).map_err(|_| format!("{s:?} isn't a UUID")) }
    fn same_address(p: &Peripheral, a: &str) -> bool { p.id().to_string().eq_ignore_ascii_case(a.trim()) || p.address().to_string().eq_ignore_ascii_case(a.trim()) }

    pub async fn scan(seconds: u32, service: Option<String>) -> Result<Vec<BleItem>, String> {
        let a = adapter().await?;
        let filter = ScanFilter { services: service.iter().map(|s| uuid(s)).collect::<Result<_, _>>()? };
        a.start_scan(filter).await.map_err(err)?;
        tokio::time::sleep(Duration::from_secs(seconds as u64)).await;
        let _ = a.stop_scan().await;
        let mut items = vec![];
        for p in a.peripherals().await.map_err(err)?.into_iter().take(MAX_ITEMS) {
            let Ok(Some(pr)) = p.properties().await else { continue };
            let address = p.id().to_string();
            let name = pr.local_name.or(pr.advertisement_name).map(|n| n.chars().filter(|c| !c.is_control()).take(64).collect());
            items.push(BleItem { address, name, rssi: pr.rssi, services: pr.services.iter().map(|u| u.to_string()).collect() });
        }
        items.sort_by_key(|i| std::cmp::Reverse(i.rssi.unwrap_or(-127)));
        Ok(items)
    }

    /// Finds the adopted device (a short scan, filtered by its service when the adoption names one) and connects.
    async fn connect(e: &External) -> Result<(Adapter, Peripheral), String> {
        let a = adapter().await?;
        let services = e.service.as_deref().and_then(super::full_uuid).map(|s| uuid(&s)).transpose()?.into_iter().collect();
        a.start_scan(ScanFilter { services }).await.map_err(err)?;
        let mut found = None;
        for _ in 0..16 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Some(p) = a.peripherals().await.map_err(err)?.into_iter().find(|p| same_address(p, &e.address)) { found = Some(p); break; }
        }
        let _ = a.stop_scan().await;
        let p = found.ok_or_else(|| format!("{} isn't in range (looked for 8 s)", e.id))?;
        if !p.is_connected().await.unwrap_or(false) {
            tokio::time::timeout(Duration::from_secs(10), p.connect()).await.map_err(|_| format!("{} didn't accept a connection within 10 s", e.id))?.map_err(err)?;
        }
        tokio::time::timeout(Duration::from_secs(10), p.discover_services()).await.map_err(|_| "discovering services timed out".to_string())?.map_err(err)?;
        Ok((a, p))
    }
    fn characteristic(p: &Peripheral, c: &str) -> Result<btleplug::api::Characteristic, String> {
        let u = uuid(c)?;
        p.characteristics().into_iter().find(|x| x.uuid == u).ok_or_else(|| format!("the device has no characteristic {c}"))
    }

    pub async fn read(e: &External, c: &str) -> Result<Value, String> {
        let (_a, p) = connect(e).await?;
        let ch = characteristic(&p, c)?;
        let r = p.read(&ch).await.map_err(err);
        let _ = p.disconnect().await;
        let b = r?;
        Ok(reading(c, &b[..b.len().min(512)]))
    }
    pub async fn write(e: &External, c: &str, bytes: &[u8]) -> Result<(), String> {
        let (_a, p) = connect(e).await?;
        let ch = characteristic(&p, c)?;
        let wt = if ch.properties.contains(CharPropFlags::WRITE) { WriteType::WithResponse } else { WriteType::WithoutResponse };
        let r = p.write(&ch, bytes, wt).await.map_err(err);
        let _ = p.disconnect().await;
        r
    }
    pub async fn subscribe(e: &External, c: &str, seconds: u32) -> Result<Value, String> {
        let (_a, p) = connect(e).await?;
        let ch = characteristic(&p, c)?;
        let mut stream = p.notifications().await.map_err(err)?;
        p.subscribe(&ch).await.map_err(err)?;
        let mut readings = vec![];
        let end = tokio::time::Instant::now() + Duration::from_secs(seconds as u64);
        while readings.len() < 300 {
            match tokio::time::timeout_at(end, stream.next()).await {
                Ok(Some(n)) if n.uuid == ch.uuid => { let mut r = reading(c, &n.value[..n.value.len().min(512)]); r["at"] = json!(super::super::now()); readings.push(r); }
                Ok(Some(_)) => {}
                _ => break,
            }
        }
        let _ = p.unsubscribe(&ch).await;
        let _ = p.disconnect().await;
        Ok(json!({ "readings": readings }))
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
pub mod ble {
    use super::{BleItem, External};
    use serde_json::Value;
    const NO: &str = "Bluetooth isn't supported by the node on this system yet";
    pub async fn scan(_s: u32, _f: Option<String>) -> Result<Vec<BleItem>, String> { Err(NO.into()) }
    pub async fn read(_e: &External, _c: &str) -> Result<Value, String> { Err(NO.into()) }
    pub async fn write(_e: &External, _c: &str, _b: &[u8]) -> Result<(), String> { Err(NO.into()) }
    pub async fn subscribe(_e: &External, _c: &str, _s: u32) -> Result<Value, String> { Err(NO.into()) }
}

/* ---------- the local network ---------- */

pub mod lan {
    use super::{External, MAX_ITEMS, MAX_LAN_BODY};
    use crate::devices::envelope::scan_id;
    use serde_json::{json, Map, Value};
    use std::net::{IpAddr, SocketAddr};
    use std::time::Duration;

    #[derive(Clone, Debug, PartialEq)]
    pub struct LanItem { pub name: String, pub ty: String, pub host: String, pub port: u16, pub addresses: Vec<IpAddr>, pub txt: Map<String, Value> }
    impl LanItem {
        pub fn for_agent(&self) -> Value { json!({ "name": self.name, "type": self.ty, "host": self.host, "port": self.port, "txt": self.txt }) }
        /// For adoption: the address an owner would adopt (`host:port`) and its hashed id.
        pub fn for_adoption(&self, pavilion: &str) -> Value {
            let address = format!("{}:{}", self.host, self.port);
            let mut v = self.for_agent();
            v["id"] = json!(scan_id(pavilion, &address));
            v["address"] = json!(address);
            v["addresses"] = json!(self.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>());
            v
        }
    }

    fn clean(s: &str, n: usize) -> String { s.chars().filter(|c| !c.is_control()).take(n).collect() }

    /// Bonjour / mDNS browsing for `seconds`, every type at once.
    pub async fn discover(types: &[String], seconds: u32) -> Result<Vec<LanItem>, String> {
        let types = types.to_vec();
        tokio::task::spawn_blocking(move || {
            let d = mdns_sd::ServiceDaemon::new().map_err(|e| format!("mDNS: {e}"))?;
            let rxs: Vec<_> = types.iter().filter_map(|t| d.browse(&format!("{t}.local.")).ok()).collect();
            let end = std::time::Instant::now() + Duration::from_secs(seconds as u64);
            let mut found: std::collections::BTreeMap<String, LanItem> = Default::default();
            while std::time::Instant::now() < end && found.len() < MAX_ITEMS {
                let mut any = false;
                for rx in &rxs {
                    while let Ok(ev) = rx.try_recv() {
                        any = true;
                        if let mdns_sd::ServiceEvent::ServiceResolved(s) = ev {
                            let ty = s.ty_domain.trim_end_matches('.').trim_end_matches(".local").to_string();
                            let name = s.fullname.strip_suffix(&format!(".{}", s.ty_domain)).unwrap_or(&s.fullname).replace("\\032", " ");
                            let mut txt = Map::new();
                            for p in s.txt_properties.iter().take(32) { txt.insert(clean(p.key(), 64), json!(clean(p.val_str(), 200))); }
                            let mut addresses: Vec<IpAddr> = s.addresses.iter().map(|a| a.to_ip_addr()).collect();
                            addresses.sort();
                            found.insert(s.fullname.clone(), LanItem { name: clean(&name, 128), ty, host: clean(s.host.trim_end_matches('.'), 128), port: s.port, addresses, txt });
                        }
                    }
                }
                if !any { std::thread::sleep(Duration::from_millis(50)); }
            }
            let _ = d.shutdown();
            Ok(found.into_values().collect())
        }).await.map_err(|e| e.to_string())?
    }

    /// Addresses an adopted LAN device may have: private, link-local or unique-local. Never loopback (this computer's
    /// own services) and never the internet (the node isn't a way out: docs/MACHINES.md §3, direct egress off).
    pub fn lan_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v) => v.is_private() || v.is_link_local(),
            IpAddr::V6(v) => (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80,
        }
    }

    /// `host`, `host:port`, `http://host:port` → (scheme, host, port).
    pub fn split_address(a: &str) -> Result<(String, String, u16), String> {
        let a = a.trim();
        let (scheme, rest) = if let Some(r) = a.strip_prefix("http://") { ("http", r) } else if let Some(r) = a.strip_prefix("https://") { ("https", r) } else { ("http", a) };
        let rest = rest.trim_end_matches('/');
        if rest.is_empty() || rest.contains('/') || rest.contains('@') { return Err(format!("{a:?} isn't a device address")); }
        let (host, port) = if let Some(r) = rest.strip_prefix('[') {
            let (h, p) = r.split_once(']').ok_or("bad IPv6 address")?;
            (h.to_string(), p.strip_prefix(':').map(|p| p.parse::<u16>().map_err(|_| "bad port")).transpose()?)
        } else if rest.matches(':').count() == 1 {
            let (h, p) = rest.split_once(':').unwrap();
            (h.to_string(), Some(p.parse::<u16>().map_err(|_| "bad port")?))
        } else { (rest.to_string(), None) };
        Ok((scheme.to_string(), host, port.unwrap_or(if scheme == "https" { 443 } else { 80 })))
    }

    /// One HTTP call to an adopted device, to a path its adoption lists. The address is resolved once, checked to be
    /// on the local network, and pinned, so a name can't be pointed somewhere else between the check and the call.
    pub async fn request(e: &External, method: &str, path: &str, body: Option<&str>) -> Result<Value, String> {
        use futures_util::StreamExt;
        let (scheme, host, port) = split_address(&e.address)?;
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port)).await.map_err(|err| format!("can't find {host}: {err}"))?.collect();
        let addr = *addrs.first().ok_or_else(|| format!("{host} has no address"))?;
        if !addrs.iter().all(|a| lan_ip(&a.ip())) { return Err(format!("{host} isn't on the local network ({}); only LAN devices can be called", addr.ip())); }
        let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(15))
            .resolve(&host, addr).build().map_err(|e| e.to_string())?;
        let url_host = if host.contains(':') { format!("[{host}]") } else { host.clone() };
        let mut rb = client.request(method.parse().map_err(|_| "bad method")?, format!("{scheme}://{url_host}:{port}{path}"));
        if let Some(b) = body {
            let ctype = if serde_json::from_str::<Value>(b).is_ok() { "application/json" } else { "text/plain; charset=utf-8" };
            rb = rb.header("content-type", ctype).body(b.to_string());
        }
        let r = rb.send().await.map_err(|err| format!("{} didn't answer: {err}", e.id))?;
        let status = r.status().as_u16();
        let mut headers = Map::new();
        for (k, v) in r.headers().iter().take(40) {
            if let Ok(v) = v.to_str() { if ["content-type", "content-length", "date", "etag", "last-modified", "location", "server"].contains(&k.as_str()) { headers.insert(k.to_string(), json!(v.chars().take(300).collect::<String>())); } }
        }
        let mut bytes = vec![];
        let mut truncated = false;
        let mut s = r.bytes_stream();
        while let Some(c) = s.next().await {
            let c = c.map_err(|err| format!("reading {}'s answer: {err}", e.id))?;
            if bytes.len() + c.len() > MAX_LAN_BODY { bytes.extend_from_slice(&c[..MAX_LAN_BODY - bytes.len()]); truncated = true; break; }
            bytes.extend_from_slice(&c);
        }
        let (body, encoding) = match String::from_utf8(bytes) { Ok(t) => (json!(t), "text"), Err(b) => (json!(crate::signing::b64(b.as_bytes())), "b64") };
        Ok(json!({ "status": status, "headers": headers, "body": body, "encoding": encoding, "truncated": truncated }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::envelope::PathRule;

    fn ext(kind: &str) -> External {
        External { id: "ext_thermo".into(), name: "Kitchen thermometer".into(), kind: kind.into(), address: "6F1C2A4B-0000-4000-8000-00000000AAAA".into(),
            service: Some("181a".into()), characteristics: vec!["2a6e".into()], paths: vec![PathRule { method: "GET".into(), path: "/status".into() }], ..Default::default() }
    }

    #[test]
    fn arguments_are_bounded() {
        assert_eq!(parse("camera_snapshot", &json!({}), None).unwrap(), Op::CameraSnapshot { camera: "front".into(), max_px: 2048 });
        assert!(parse("camera_snapshot", &json!({ "max_px": 99999 }), None).is_err());
        assert!(parse("camera_clip", &json!({ "seconds": 31 }), None).is_err());
        assert!(parse("camera_clip", &json!({}), None).is_err());
        assert!(parse("record_audio", &json!({ "seconds": 60 }), None).is_ok());
        assert!(parse("play_audio", &json!({ "text": "hi", "asset": "ast_1" }), None).is_err());
        assert!(parse("play_audio", &json!({ "text": "x".repeat(501) }), None).is_err());
        assert!(parse("lan_discover", &json!({ "types": ["_http._tcp", "_ipp._tcp"] }), None).is_ok());
        assert!(parse("lan_discover", &json!({ "types": ["_http._tcp; rm -rf"] }), None).is_err());
        assert!(parse("ble_scan", &json!({ "service": "not-a-uuid" }), None).is_err());
        assert!(parse("nfc_read", &json!({}), None).unwrap_err().contains("phones only"));
    }

    #[test]
    fn only_adopted_devices_and_listed_characteristics_and_paths() {
        let e = ext("ble");
        assert!(parse("ble_read", &json!({ "external": "ext_thermo", "characteristic": "2a6e" }), None).unwrap_err().contains("adopted"));
        assert!(parse("ble_read", &json!({ "external": "ext_other", "characteristic": "2a6e" }), Some(&e)).is_err());
        assert!(parse("ble_read", &json!({ "external": "ext_thermo", "characteristic": "2a19" }), Some(&e)).unwrap_err().contains("isn't one the adoption"));
        match parse("ble_read", &json!({ "external": "ext_thermo", "characteristic": "00002A6E-0000-1000-8000-00805F9B34FB" }), Some(&e)).unwrap() {
            Op::BleRead { characteristic, .. } => assert_eq!(characteristic, "00002a6e-0000-1000-8000-00805f9b34fb"),
            o => panic!("{o:?}"),
        }
        assert!(parse("ble_write", &json!({ "external": "ext_thermo", "characteristic": "2a6e", "hex": "0g" }), Some(&e)).is_err());
        assert!(parse("lan_request", &json!({ "external": "ext_thermo", "method": "GET", "path": "/status" }), Some(&e)).unwrap_err().contains("ble device"));
        let l = ext("lan");
        assert!(parse("lan_request", &json!({ "external": "ext_thermo", "method": "GET", "path": "/status" }), Some(&l)).is_ok());
        assert!(parse("lan_request", &json!({ "external": "ext_thermo", "method": "POST", "path": "/status" }), Some(&l)).unwrap_err().contains("isn't a path"));
        assert!(parse("lan_request", &json!({ "external": "ext_thermo", "method": "GET", "path": "/admin" }), Some(&l)).is_err());
    }

    #[test]
    fn lan_calls_stay_on_the_lan() {
        use lan::{lan_ip, split_address};
        for ok in ["192.168.1.20", "10.0.0.3", "172.16.4.1", "169.254.3.3", "fe80::1", "fd00::5"] { assert!(lan_ip(&ok.parse().unwrap()), "{ok}"); }
        for no in ["127.0.0.1", "8.8.8.8", "::1", "2606:4700::1111", "0.0.0.0", "100.64.0.1"] { assert!(!lan_ip(&no.parse().unwrap()), "{no}"); }
        assert_eq!(split_address("printer.local:631").unwrap(), ("http".into(), "printer.local".into(), 631));
        assert_eq!(split_address("https://192.168.1.4").unwrap(), ("https".into(), "192.168.1.4".into(), 443));
        assert_eq!(split_address("[fe80::1]:80").unwrap(), ("http".into(), "fe80::1".into(), 80));
        assert!(split_address("user@evil.com").is_err());
        assert!(split_address("host/path").is_err());
    }

    #[test]
    fn known_characteristics_are_parsed() {
        assert_eq!(reading("00002a19-0000-1000-8000-00805f9b34fb", &[87])["parsed"]["battery_percent"], 87);
        assert_eq!(reading("00002a6e-0000-1000-8000-00805f9b34fb", &[0x2a, 0x08])["parsed"]["temperature_c"], 20.9);
        assert_eq!(reading("12345678-0000-1000-8000-00805f9b34fb", &[1, 2])["hex"], "0102");
    }

    #[test]
    fn scan_results_hide_addresses_from_agents() {
        let i = BleItem { address: "6F1C2A4B-0000-4000-8000-00000000AAAA".into(), name: Some("Thermo".into()), rssi: Some(-60), services: vec![] };
        let a = i.for_agent("acme");
        assert!(a.get("address").is_none() && a["id"].as_str().unwrap().len() == 16);
        assert_eq!(i.for_adoption("acme")["address"], "6F1C2A4B-0000-4000-8000-00000000AAAA");
    }

    #[test]
    fn positions_are_rounded_to_the_allowed_accuracy() {
        let (lat, lon) = round_position(38.736946, -9.142685, 1000);
        assert!((lat - 38.736946).abs() < 0.005 && (lon - -9.142685).abs() < 0.007);
        assert_ne!((lat, lon), (38.736946, -9.142685));
    }
}
