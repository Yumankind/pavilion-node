//! The first set of device standards (docs/DEVICES.md §4b "Which come first"): OBD-II, Home Assistant, MQTT, Bluetooth
//! standard profiles (gatt.rs, used by `ble_read` / `ble_subscribe`), Google Cast, IPP printing, ONVIF snapshots and
//! Modbus TCP. Each is a small adapter that speaks the standard; agents get typed tools (DEVICES-PROTOCOL.md §5), never
//! the raw protocol: no AT commands, no raw Modbus, no arbitrary topics, no service calls outside the home vocabulary.
//!
//! Every tool here acts on an adopted device (`external`), and only within what its adoption allows (`allow.pids`,
//! `allow.registers`, `allow.topics`, `allow.devices`). Arguments are checked again here, as for the other tools.
pub mod cast;
pub mod gatt;
pub mod home;
pub mod ipp;
pub mod lent;
pub mod modbus;
pub mod mqtt;
pub mod net;
pub mod obd;
pub mod onvif;
pub mod scan;

use super::caps::{adopted, Output};
use super::envelope::External;
use serde_json::{json, Value};
use std::time::Duration;

pub const TOOLS: &[&str] = &["obd_info", "obd_read", "obd_codes", "obd_monitor", "obd_clear_codes", "home_list", "home_state", "home_command",
    "mqtt_read", "mqtt_publish", "cast_media", "media_control", "print", "modbus_read", "modbus_write"];

#[derive(Clone, Debug, PartialEq)]
pub enum StdOp {
    ObdInfo { ext: External },
    ObdRead { ext: External, pids: Vec<u8> },
    ObdCodes { ext: External, which: Vec<String> },
    ObdMonitor { ext: External, pids: Vec<u8>, every_s: u32, seconds: u32 },
    ObdClear { ext: External },
    HomeList { ext: External },
    HomeState { ext: External, device: String },
    HomeCommand { ext: External, device: String, command: String, value: Value },
    MqttRead { ext: External, topic: String, seconds: u32, max: u32, qos: u8 },
    MqttPublish { ext: External, topic: String, payload: String, qos: u8, retain: bool },
    CastMedia { ext: External, url: Option<String>, asset: Option<String>, content_type: Option<String>, title: String },
    MediaControl { ext: External, command: String, value: Option<f64> },
    Print { ext: External, asset: String, pages: Option<(u32, u32)>, copies: u32 },
    CameraSnapshot { ext: External, profile: Option<String> },
    ModbusRead { ext: External, registers: Vec<modbus::Register> },
    ModbusWrite { ext: External, register: modbus::Register, value: f64 },
}

/// What the node lends an operation for this one action: the asset it fetched, the secret lent to it, the Gate's
/// origin (pavilion URLs), the action id. Held in memory and dropped when the action ends.
#[derive(Debug, Default)]
pub struct Lent { pub asset: Option<Vec<u8>>, pub secret: Option<lent::Secret>, pub gate: String, pub act: String }

/// What the node learned before asking the person: a reason the device is safety-critical (from the device itself).
#[derive(Debug, Default, PartialEq)]
pub struct Prep { pub critical: Option<String> }

fn int(args: &Value, k: &str, lo: u64, hi: u64, default: Option<u64>) -> Result<u32, String> {
    match &args[k] {
        Value::Null => default.map(|d| d as u32).ok_or_else(|| format!("{k} is missing")),
        v => v.as_u64().filter(|n| (lo..=hi).contains(n)).map(|n| n as u32).ok_or_else(|| format!("{k} must be a whole number from {lo} to {hi}")),
    }
}
fn text(args: &Value, k: &str, max: usize) -> Result<Option<String>, String> {
    match &args[k] {
        Value::Null => Ok(None),
        Value::String(s) if s.chars().count() <= max && !s.chars().any(|c| c.is_control() && c != '\n' && c != '\t') => Ok(Some(s.clone())),
        _ => Err(format!("{k} must be text of at most {max} characters")),
    }
}
fn asset_id(v: &Value) -> Result<Option<String>, String> {
    match v { Value::Null => Ok(None), Value::String(a) if a.starts_with("ast_") && a.len() <= 64 && a[4..].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') => Ok(Some(a.clone())), _ => Err("asset isn't an asset id (ast_…)".into()) }
}

/// The tool's typed operation, or None when the tool isn't one of these (or `camera_snapshot` has no `external`).
pub fn parse(tool: &str, args: &Value, ext: Option<&External>) -> Option<Result<StdOp, String>> {
    if !TOOLS.contains(&tool) && !(tool == "camera_snapshot" && args["external"].is_string()) { return None; }
    Some(parse_inner(tool, args, ext))
}

fn parse_inner(tool: &str, args: &Value, ext: Option<&External>) -> Result<StdOp, String> {
    let kind = match tool.split('_').next().unwrap_or("") { "obd" => "obd", "home" => "home", "mqtt" => "mqtt", "cast" | "media" => "cast", "print" => "printer", "camera" => "camera", _ => "modbus" };
    let e = adopted(ext, args, kind)?.clone();
    Ok(match tool {
        "obd_info" => StdOp::ObdInfo { ext: e },
        "obd_read" => StdOp::ObdRead { pids: obd::pids_arg(&args["pids"], &e, 10)?, ext: e },
        "obd_codes" => {
            let which: Vec<String> = match &args["which"] {
                Value::Null => vec!["stored".into(), "pending".into(), "permanent".into()],
                Value::Array(a) if !a.is_empty() && a.len() <= 3 => a.iter().map(|w| w.as_str().filter(|w| ["stored", "pending", "permanent"].contains(w)).map(String::from).ok_or("which lists stored, pending or permanent")).collect::<Result<_, _>>()?,
                _ => return Err("which is a list of stored, pending, permanent".into()),
            };
            StdOp::ObdCodes { ext: e, which }
        }
        "obd_monitor" => {
            let every_s = int(args, "every_s", 1, 10, Some(2))?;
            let seconds = int(args, "seconds", 5, 300, None)?;
            if every_s > seconds { return Err("every_s is longer than seconds".into()); }
            StdOp::ObdMonitor { pids: obd::pids_arg(&args["pids"], &e, 5)?, ext: e, every_s, seconds }
        }
        "obd_clear_codes" => StdOp::ObdClear { ext: e },
        "home_list" => StdOp::HomeList { ext: e },
        "home_state" | "home_command" => {
            let device = args["device"].as_str().filter(|d| home::entity_ok(d)).ok_or("device must be a device id from home_list (like light.desk)")?.to_string();
            if !home::device_allowed(&e, &device) { return Err(format!("{device} isn't a device the adoption of {} lists", e.id)); }
            if tool == "home_state" { StdOp::HomeState { ext: e, device } } else {
                let command = args["command"].as_str().filter(|c| home::COMMANDS.contains(c)).ok_or_else(|| format!("command must be one of {}", home::COMMANDS.join(", ")))?.to_string();
                // Checked fully against the device's domain later; here only that it maps at all.
                home::service(&device, &command, &args["value"])?;
                StdOp::HomeCommand { ext: e, device, command, value: args["value"].clone() }
            }
        }
        "mqtt_read" => {
            let topic = args["topic"].as_str().ok_or("topic is missing")?.to_string();
            mqtt::readable(&e, &topic)?;
            StdOp::MqttRead { ext: e, topic, seconds: int(args, "seconds", 1, 30, Some(5))?, max: int(args, "max", 1, 100, Some(20))?, qos: int(args, "qos", 0, 1, Some(0))? as u8 }
        }
        "mqtt_publish" => {
            let topic = args["topic"].as_str().ok_or("topic is missing")?.to_string();
            mqtt::publishable(&e, &topic)?;
            let payload = args["payload"].as_str().ok_or("payload is text")?.to_string();
            if payload.len() > mqtt::MAX_PUBLISH { return Err(format!("payload is over {} KB", mqtt::MAX_PUBLISH / 1024)); }
            let retain = match &args["retain"] { Value::Null => false, Value::Bool(b) => *b, _ => return Err("retain is true or false".into()) };
            StdOp::MqttPublish { ext: e, topic, payload, qos: int(args, "qos", 0, 1, Some(1))? as u8, retain }
        }
        "cast_media" => {
            let asset = asset_id(&args["asset"])?;
            let url = text(args, "url", 2048)?;
            if asset.is_some() == url.is_some() { return Err("cast_media takes an asset or a pavilion url, one of them".into()); }
            if let Some(u) = &url { if !u.starts_with("https://") || u.contains(char::is_whitespace) { return Err("url must be an https address on the pavilion's Gate".into()); } }
            let content_type = text(args, "content_type", 100)?;
            if content_type.as_ref().map_or(false, |t| !t.contains('/') || t.contains(char::is_whitespace)) { return Err("content_type isn't a media type".into()); }
            StdOp::CastMedia { ext: e, url, asset, content_type, title: text(args, "title", 100)?.unwrap_or_else(|| "From the pavilion".into()) }
        }
        "media_control" => {
            let command = args["command"].as_str().filter(|c| ["play", "pause", "stop", "volume"].contains(c)).ok_or("command must be play, pause, stop or volume")?.to_string();
            let value = match (&args["value"], command.as_str()) {
                (Value::Null, "volume") => return Err("volume needs a value from 0 to 100".into()),
                (Value::Null, _) => None,
                (v, "volume") => Some(v.as_f64().filter(|x| (0.0..=100.0).contains(x)).ok_or("volume needs a value from 0 to 100")?),
                _ => return Err(format!("{command} takes no value")),
            };
            StdOp::MediaControl { ext: e, command, value }
        }
        "print" => {
            let asset = asset_id(&args["asset"])?.ok_or("print needs an asset (a PDF or a JPEG)")?;
            let pages = match &args["pages"] { Value::Null => None, Value::String(s) => Some(ipp::pages(s)?), Value::Number(n) => Some(ipp::pages(&n.to_string())?), _ => return Err("pages looks like \"3\" or \"2-5\"".into()) };
            StdOp::Print { ext: e, asset, pages, copies: int(args, "copies", 1, ipp::MAX_COPIES as u64, Some(1))? }
        }
        "camera_snapshot" => {
            let profile = text(args, "profile", 64)?;
            StdOp::CameraSnapshot { ext: e, profile }
        }
        "modbus_read" => StdOp::ModbusRead { registers: modbus::registers_arg(args, &e)?, ext: e },
        "modbus_write" => {
            if !e.critical { return Err(format!("writing Modbus registers is refused unless the adoption of {} is marked critical", e.id)); }
            let mut regs = modbus::registers_arg(args, &e)?;
            if regs.len() != 1 { return Err("modbus_write writes one register".into()); }
            let register = regs.remove(0);
            if register.table != modbus::Table::Holding { return Err(format!("{} is an input register, which can't be written", register.name)); }
            let value = args["value"].as_f64().ok_or("value must be a number")?;
            modbus::words_for(&register, value)?;
            StdOp::ModbusWrite { ext: e, register, value }
        }
        t => return Err(format!("{t} isn't a device tool")),
    })
}

impl StdOp {
    pub fn external(&self) -> &External {
        use StdOp::*;
        match self {
            ObdInfo { ext } | ObdRead { ext, .. } | ObdCodes { ext, .. } | ObdMonitor { ext, .. } | ObdClear { ext } | HomeList { ext } | HomeState { ext, .. } | HomeCommand { ext, .. }
            | MqttRead { ext, .. } | MqttPublish { ext, .. } | CastMedia { ext, .. } | MediaControl { ext, .. } | Print { ext, .. } | CameraSnapshot { ext, .. }
            | ModbusRead { ext, .. } | ModbusWrite { ext, .. } => ext,
        }
    }
    pub fn is_capture(&self) -> bool { matches!(self, StdOp::CameraSnapshot { .. }) }
    /// The action's asset is needed (fetched from the Gate once the action is approved).
    pub fn needs_asset(&self) -> bool { matches!(self, StdOp::Print { .. } | StdOp::CastMedia { asset: Some(_), .. }) }
    pub fn budget(&self) -> Duration {
        Duration::from_secs(match self {
            StdOp::ObdMonitor { seconds, .. } => *seconds as u64 + 60,
            StdOp::MqttRead { seconds, .. } => *seconds as u64 + 20,
            StdOp::ObdInfo { .. } | StdOp::ObdCodes { .. } | StdOp::CastMedia { .. } => 90,
            StdOp::Print { .. } => 180,
            _ => 60,
        })
    }
    /// What will happen, in this computer's words (shown under the Gate's text).
    pub fn describe(&self) -> String {
        let name = |e: &External| format!("“{}”", e.name.chars().take(64).collect::<String>());
        let pids = |p: &[u8]| p.iter().filter_map(|c| obd::pid(*c)).map(|p| p.name.replace('_', " ")).collect::<Vec<_>>().join(", ");
        match self {
            StdOp::ObdInfo { ext } => format!("Read the car's VIN, protocol and which values it reports, through {}.", name(ext)),
            StdOp::ObdRead { ext, pids: p } => format!("Read {} from the car, through {}.", pids(p), name(ext)),
            StdOp::ObdCodes { ext, which } => format!("Read the car's {} fault codes and the freeze frame, through {}.", which.join(", "), name(ext)),
            StdOp::ObdMonitor { ext, pids: p, every_s, seconds } => format!("Read {} every {every_s} s for {seconds} s, through {}.", pids(p), name(ext)),
            StdOp::ObdClear { ext } => format!("Clear the car's fault codes and the check-engine light, through {}. Only if the car is standing still.", name(ext)),
            StdOp::HomeList { ext } => format!("List the rooms and devices on the hub {}.", name(ext)),
            StdOp::HomeState { ext, device } => format!("Read {device} on {}.", name(ext)),
            StdOp::HomeCommand { ext, device, command, value } => format!("{} {device} on {}{}.", command.replace('_', " "), name(ext), if value.is_null() { String::new() } else { format!(" ({value})") }),
            StdOp::MqttRead { ext, topic, seconds, .. } => format!("Listen to {topic} on {} for {seconds} s.", name(ext)),
            StdOp::MqttPublish { ext, topic, payload, retain, .. } => format!("Publish to {topic} on {}{}: {}", name(ext), if *retain { " (kept by the broker)" } else { "" }, payload.chars().take(120).collect::<String>()),
            StdOp::CastMedia { ext, title, .. } => format!("Play “{}” on {}.", title.chars().take(64).collect::<String>(), name(ext)),
            StdOp::MediaControl { ext, command, value } => format!("{} on {}{}.", command, name(ext), value.map(|v| format!(" to {v}%")).unwrap_or_default()),
            StdOp::Print { ext, copies, pages, .. } => format!("Print {copies} cop{} of a document{} on {}.", if *copies == 1 { "y" } else { "ies" }, pages.map(|(a, b)| if a == b { format!(", page {a}") } else { format!(", pages {a}–{b}") }).unwrap_or_default(), name(ext)),
            StdOp::CameraSnapshot { ext, .. } => format!("One photo from the camera {}. You'll see it for 3 seconds before it's sent.", name(ext)),
            StdOp::ModbusRead { ext, registers } => format!("Read {} from {}.", registers.iter().map(|r| r.name.as_str()).collect::<Vec<_>>().join(", "), name(ext)),
            StdOp::ModbusWrite { ext, register, value } => format!("Write {value} to {} on {}.", register.name, name(ext)),
        }
    }
}

/// Before the person is asked: what the device itself says (a lock is critical whatever the envelope says), and
/// refusals that make asking pointless (a car that's moving).
pub async fn prepare(op: &StdOp, lent: &Lent) -> Result<Prep, String> {
    match op {
        StdOp::HomeCommand { ext, device, command, .. } => {
            let hub = home::Hub::open(ext, lent.secret.as_ref()).await?;
            Ok(Prep { critical: hub.check(ext, device, command).await?.map(String::from) })
        }
        StdOp::ObdClear { ext } => {
            let mut elm = obd::Elm::open(ext).await?;
            obd::standing_still(&mut elm).await?;
            Ok(Prep::default())
        }
        _ => Ok(Prep::default()),
    }
}

pub async fn run(op: &StdOp, lent: &Lent) -> Result<Output, String> {
    let s = lent.secret.as_ref();
    let j = |v: Result<Value, String>| v.map(Output::Json);
    match op {
        StdOp::ObdInfo { ext } => j(obd::info(obd::Elm::open(ext).await?, ext).await),
        StdOp::ObdRead { ext, pids } => j(obd::read(obd::Elm::open(ext).await?, pids).await),
        StdOp::ObdCodes { ext, which } => j(obd::codes(obd::Elm::open(ext).await?, ext, which).await),
        StdOp::ObdMonitor { ext, pids, every_s, seconds } => j(obd::monitor(obd::Elm::open(ext).await?, pids, *every_s, *seconds).await),
        StdOp::ObdClear { ext } => j(obd::clear_codes(obd::Elm::open(ext).await?).await),
        StdOp::HomeList { ext } => j(home::Hub::open(ext, s).await?.list(ext).await),
        StdOp::HomeState { ext, device } => j(home::Hub::open(ext, s).await?.read(ext, device).await),
        StdOp::HomeCommand { ext, device, command, value } => j(home::Hub::open(ext, s).await?.command(device, command, value).await),
        StdOp::MqttRead { ext, topic, seconds, max, qos } => j(mqtt::read(ext, s, topic, *seconds, *max as usize, *qos).await),
        StdOp::MqttPublish { ext, topic, payload, qos, retain } => j(mqtt::publish(ext, s, topic, payload, *qos, *retain).await),
        StdOp::CastMedia { ext, url, content_type, title, .. } => {
            if let Some(u) = url { if !same_host(u, &lent.gate) { return Err("url must be on the pavilion's Gate".into()); } }
            j(cast::cast(ext, url.as_deref(), lent.asset.clone(), content_type.as_deref(), title).await)
        }
        StdOp::MediaControl { ext, command, value } => j(cast::control(ext, command, *value).await),
        StdOp::Print { ext, pages, copies, .. } => j(ipp::print(ext, &lent.act, lent.asset.as_deref().ok_or("the document didn't arrive")?, *copies, *pages).await),
        StdOp::CameraSnapshot { ext, profile } => onvif::snapshot(ext, s, profile.as_deref()).await.map(|bytes| Output::Bytes { ctype: "image/jpeg".into(), bytes }),
        StdOp::ModbusRead { ext, registers } => j(modbus::read(ext, registers).await),
        StdOp::ModbusWrite { ext, register, value } => j(modbus::write(ext, register, *value).await),
    }
}

/// Whether `url` is https on the Gate's own host.
pub fn same_host(url: &str, gate: &str) -> bool {
    let host = |u: &str| u.split_once("://").map(|(_, r)| r.split(['/', '?', '#']).next().unwrap_or("").to_ascii_lowercase());
    url.starts_with("https://") && !gate.is_empty() && host(url).is_some() && host(url) == host(gate)
}

/// For `POST …/scan`: a scan of one kind, items for adoption.
pub async fn scan_kind(kind: &str, pavilion: &str, seconds: u32, target: Option<&str>, ble: bool) -> Result<Vec<Value>, String> {
    match kind {
        "obd" => Ok(scan::obd(pavilion, seconds, ble).await),
        "home" => scan::home(pavilion, seconds).await,
        "cast" => scan::cast(pavilion, seconds).await,
        "printers" => scan::printers(pavilion, seconds).await,
        "cameras" => scan::cameras(pavilion, seconds).await,
        "modbus" => scan::modbus(pavilion, target).await,
        k => Err(format!("{k} isn't a scan ({})", scan::KINDS.join(", "))),
    }
}

/// One line per item, for the person who ran the scan.
pub fn scan_line(v: &Value) -> String {
    format!("{:<28} {:<44} {}", net::clean(v["name"].as_str().unwrap_or("(no name)"), 28), v["suggest"]["address"].as_str().or(v["address"].as_str()).unwrap_or(""),
        json!(v["suggest"]).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_checked_again() {
        let car = obd::tests::adapter("192.168.0.10:35000", json!(["rpm", "speed"]));
        let a = |v: Value| { let mut v = v; v["external"] = json!("ext_car"); v };
        assert!(matches!(parse("obd_read", &a(json!({ "pids": ["rpm"] })), Some(&car)), Some(Ok(StdOp::ObdRead { .. }))));
        assert!(parse("obd_read", &a(json!({ "pids": ["coolant_temp"] })), Some(&car)).unwrap().is_err());
        assert!(parse("obd_monitor", &a(json!({ "pids": ["rpm"], "every_s": 11, "seconds": 60 })), Some(&car)).unwrap().is_err());
        assert!(parse("obd_monitor", &a(json!({ "pids": ["rpm"], "every_s": 2, "seconds": 301 })), Some(&car)).unwrap().is_err());
        assert!(parse("obd_codes", &a(json!({ "which": ["raw"] })), Some(&car)).unwrap().is_err());
        assert!(parse("obd_read", &a(json!({ "pids": ["rpm"] })), None).unwrap().unwrap_err().contains("adopted"));
        let hub = home::tests::adoption("192.168.1.2:8123", &["light.desk"]);
        let h = |v: Value| { let mut v = v; v["external"] = json!("ext_hub"); v };
        assert!(parse("home_command", &h(json!({ "device": "light.desk", "command": "on" })), Some(&hub)).unwrap().is_ok());
        assert!(parse("home_command", &h(json!({ "device": "lock.front_door", "command": "unlock" })), Some(&hub)).unwrap().unwrap_err().contains("isn't a device"));
        assert!(parse("home_command", &h(json!({ "device": "light.desk", "command": "self_destruct" })), Some(&hub)).unwrap().is_err());
        assert!(parse("home_command", &car_args(), Some(&hub)).unwrap().is_err());
        let tv = External { id: "ext_tv".into(), kind: "cast".into(), address: "10.0.0.5".into(), ..Default::default() };
        let t = |v: Value| { let mut v = v; v["external"] = json!("ext_tv"); v };
        assert!(parse("cast_media", &t(json!({ "asset": "ast_1", "url": "https://x/y" })), Some(&tv)).unwrap().is_err());
        assert!(parse("cast_media", &t(json!({ "url": "http://evil.example/a.mp4" })), Some(&tv)).unwrap().is_err());
        assert!(parse("media_control", &t(json!({ "command": "volume" })), Some(&tv)).unwrap().is_err());
        assert!(parse("media_control", &t(json!({ "command": "play", "value": 3 })), Some(&tv)).unwrap().is_err());
        let p = External { id: "ext_p".into(), kind: "printer".into(), address: "10.0.0.6".into(), ..Default::default() };
        let pa = |v: Value| { let mut v = v; v["external"] = json!("ext_p"); v };
        assert!(parse("print", &pa(json!({ "asset": "ast_doc", "copies": 6 })), Some(&p)).unwrap().is_err());
        assert_eq!(parse("print", &pa(json!({ "asset": "ast_doc", "copies": 2, "pages": "1-2" })), Some(&p)).unwrap().unwrap(), StdOp::Print { ext: p.clone(), asset: "ast_doc".into(), pages: Some((1, 2)), copies: 2 });
        let inv = modbus::tests::inverter("10.0.0.7:502", false);
        let m = |v: Value| { let mut v = v; v["external"] = json!("ext_inverter"); v };
        assert!(parse("modbus_write", &m(json!({ "register": "export_limit", "value": 1 })), Some(&inv)).unwrap().unwrap_err().contains("marked critical"));
        let inv = modbus::tests::inverter("10.0.0.7:502", true);
        assert!(parse("modbus_write", &m(json!({ "register": "pv_power", "value": 1 })), Some(&inv)).unwrap().unwrap_err().contains("input register"));
        assert!(parse("modbus_write", &m(json!({ "register": "export_limit", "value": 1 })), Some(&inv)).unwrap().is_ok());
        // A camera_snapshot without external is the computer's own camera, not this module's.
        assert!(parse("camera_snapshot", &json!({ "host": "mch_x" }), None).is_none());
        assert!(same_host("https://gate.example/p/a/x.mp3", "https://gate.example") && !same_host("https://gate.example.evil/x", "https://gate.example") && !same_host("http://gate.example/x", "https://gate.example"));
    }
    fn car_args() -> Value { json!({ "external": "ext_car", "device": "light.desk", "command": "on" }) }
}
