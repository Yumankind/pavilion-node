//! Home Assistant, through its local REST API (`/api/states`, `/api/services/<domain>/<service>`) with a long-lived
//! access token lent to this host (lent.rs). Agents get the one home vocabulary (DEVICES.md §4b): `home_list`,
//! `home_state`, and `home_command` with `on`, `off`, `toggle`, `set_level`, `set_color`, `set_temperature`, `open`,
//! `close`, `stop`, `lock`, `unlock`, `arm`, `disarm`, `start`, `pause`, `return_home`, each only where the device has it.
//!
//! **Safety-critical by class**, decided here from what the hub says the device is, never from the agent: locks,
//! garage doors, gates and doors, alarm panels, heating (climate with a heat mode, water heaters), valves, and
//! anything named like an oven, cooktop, heater, boiler or EV charger. A command to one of them is refused unless
//! the action is `critical` (the holder allows it with presence, never "always"), whatever the envelope says.
use super::super::envelope::External;
use super::lent::Secret;
use super::net;
use serde_json::{json, Map, Value};
use std::time::Duration;

pub const COMMANDS: &[&str] = &["on", "off", "toggle", "set_level", "set_color", "set_temperature", "open", "close", "stop", "lock", "unlock", "arm", "disarm", "start", "pause", "return_home"];
const MAX_DEVICES: usize = 500;

/// An entity id: `light.kitchen`.
pub fn entity_ok(id: &str) -> bool {
    let Some((d, o)) = id.split_once('.') else { return false };
    id.len() <= 255 && !d.is_empty() && !o.is_empty() && d.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') && o.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Only devices the adoption lists, when it lists any.
pub fn device_allowed(e: &External, id: &str) -> bool { e.allow.devices.is_empty() || e.allow.devices.iter().any(|d| d == id) }

/// The vocabulary's class for a Home Assistant domain.
pub fn class(domain: &str) -> &'static str {
    match domain {
        "light" => "light", "switch" | "input_boolean" => "switch", "fan" => "fan", "cover" => "cover", "lock" => "lock", "climate" => "climate",
        "water_heater" => "water_heater", "valve" => "valve", "alarm_control_panel" => "alarm", "media_player" => "media_player", "vacuum" => "vacuum",
        "lawn_mower" => "lawn_mower", "humidifier" => "humidifier", "siren" => "siren", "scene" => "scene", "sensor" => "sensor", "binary_sensor" => "binary_sensor",
        "button" => "button", "camera" => "camera", "person" | "device_tracker" => "presence", "weather" => "weather", _ => "other",
    }
}

/// The commands a device has, from its domain (and, for lights, its colour modes).
pub fn capabilities(domain: &str, attrs: &Value) -> Vec<&'static str> {
    let color = attrs["supported_color_modes"].as_array().map_or(false, |m| m.iter().any(|x| ["hs", "rgb", "rgbw", "rgbww", "xy"].contains(&x.as_str().unwrap_or(""))));
    let dimmable = attrs["supported_color_modes"].as_array().map_or(false, |m| m.iter().any(|x| x != "onoff")) || attrs["brightness"].is_number();
    let mut c: Vec<&'static str> = match domain {
        "light" => { let mut v = vec!["on", "off", "toggle"]; if dimmable { v.push("set_level"); } if color { v.push("set_color"); } v }
        "switch" | "input_boolean" | "siren" => vec!["on", "off", "toggle"],
        "fan" => vec!["on", "off", "toggle", "set_level"],
        "humidifier" => vec!["on", "off", "toggle"],
        "cover" => vec!["open", "close", "stop", "set_level"],
        "valve" => vec!["open", "close", "stop", "set_level"],
        "lock" => vec!["lock", "unlock"],
        "climate" => vec!["on", "off", "set_temperature"],
        "water_heater" => vec!["on", "off", "set_temperature"],
        "alarm_control_panel" => vec!["arm", "disarm"],
        "media_player" => vec!["on", "off", "toggle", "set_level", "stop", "pause", "start"],
        "vacuum" => vec!["start", "pause", "stop", "return_home"],
        "lawn_mower" => vec!["start", "pause", "return_home"],
        "scene" => vec!["on"],
        _ => vec![],
    };
    c.dedup();
    c
}

const CRITICAL_WORDS: &[&str] = &["oven", "cooktop", "hob", "stove", "heater", "boiler", "ev_charger", "ev charger", "wallbox", "evse", "garage", "gate", "valve"];

/// Why a device is safety-critical (DEVICES.md §4b), or None. From the hub's own description of the device.
pub fn critical(entity: &str, attrs: &Value, marked: bool) -> Option<&'static str> {
    if marked { return Some("the owner marked this device critical"); }
    let (domain, _) = entity.split_once('.').unwrap_or((entity, ""));
    let dc = attrs["device_class"].as_str().unwrap_or("");
    match domain {
        "lock" => return Some("a lock"),
        "alarm_control_panel" => return Some("an alarm"),
        "valve" => return Some("a valve"),
        "water_heater" => return Some("a water heater"),
        "cover" if ["garage", "gate", "door"].contains(&dc) => return Some("a garage door, gate or door"),
        "climate" => {
            let modes = attrs["hvac_modes"].as_array();
            // Heating, or a thermostat that doesn't say: treated as heating.
            if modes.map_or(true, |m| m.iter().any(|x| ["heat", "heat_cool", "auto"].contains(&x.as_str().unwrap_or("")))) { return Some("heating"); }
        }
        _ => {}
    }
    let name = format!("{} {}", entity, attrs["friendly_name"].as_str().unwrap_or("")).to_lowercase();
    if CRITICAL_WORDS.iter().any(|w| name.contains(w)) && domain != "sensor" && domain != "binary_sensor" {
        return Some("an oven, heater, boiler, gate, valve or EV charger (by its name)");
    }
    None
}

/// The Home Assistant service call for a vocabulary command: (domain, service, extra data).
pub fn service(entity: &str, command: &str, value: &Value) -> Result<(String, &'static str, Map<String, Value>), String> {
    let (domain, _) = entity.split_once('.').ok_or("not an entity id")?;
    let mut data = Map::new();
    let num = |lo: f64, hi: f64| value.as_f64().filter(|v| (lo..=hi).contains(v)).ok_or_else(|| format!("{command} needs a value from {lo} to {hi}"));
    let svc: &'static str = match (domain, command) {
        (_, "on") if domain == "scene" => "turn_on",
        ("light" | "switch" | "input_boolean" | "fan" | "humidifier" | "media_player" | "climate" | "water_heater" | "siren", "on") => "turn_on",
        ("light" | "switch" | "input_boolean" | "fan" | "humidifier" | "media_player" | "climate" | "water_heater" | "siren", "off") => "turn_off",
        ("light" | "switch" | "input_boolean" | "fan" | "humidifier" | "media_player" | "siren", "toggle") => "toggle",
        ("light", "set_level") => { data.insert("brightness_pct".into(), json!(num(0.0, 100.0)?.round())); "turn_on" }
        ("light", "set_color") => { data.insert("rgb_color".into(), json!(rgb(value)?)); "turn_on" }
        ("fan", "set_level") => { data.insert("percentage".into(), json!(num(0.0, 100.0)?.round())); "set_percentage" }
        ("cover", "set_level") => { data.insert("position".into(), json!(num(0.0, 100.0)?.round())); "set_cover_position" }
        ("valve", "set_level") => { data.insert("position".into(), json!(num(0.0, 100.0)?.round())); "set_valve_position" }
        ("media_player", "set_level") => { data.insert("volume_level".into(), json!(num(0.0, 100.0)? / 100.0)); "volume_set" }
        ("climate" | "water_heater", "set_temperature") => { data.insert("temperature".into(), json!(num(-20.0, 90.0)?)); "set_temperature" }
        ("cover", "open") => "open_cover", ("cover", "close") => "close_cover", ("cover", "stop") => "stop_cover",
        ("valve", "open") => "open_valve", ("valve", "close") => "close_valve", ("valve", "stop") => "stop_valve",
        ("lock", "lock") => "lock", ("lock", "unlock") => "unlock",
        ("alarm_control_panel", "arm") => match value.as_str().unwrap_or("away") { "home" => "alarm_arm_home", "away" => "alarm_arm_away", "night" => "alarm_arm_night", v => return Err(format!("arm takes home, away or night, not {v:?}")) },
        ("alarm_control_panel", "disarm") => "alarm_disarm",
        ("media_player", "start") => "media_play", ("media_player", "pause") => "media_pause", ("media_player", "stop") => "media_stop",
        ("vacuum", "start") => "start", ("vacuum", "pause") => "pause", ("vacuum", "stop") => "stop", ("vacuum", "return_home") => "return_to_base",
        ("lawn_mower", "start") => "start_mowing", ("lawn_mower", "pause") => "pause", ("lawn_mower", "return_home") => "dock",
        _ => return Err(format!("{entity} has no {command:?} (a {} device)", class(domain))),
    };
    let needs_value = ["set_level", "set_color", "set_temperature"].contains(&command);
    if !needs_value && !value.is_null() && !(domain == "alarm_control_panel" && command == "arm") { return Err(format!("{command} takes no value")); }
    data.insert("entity_id".into(), json!(entity));
    Ok((domain.to_string(), svc, data))
}

/// `"#ff8800"` or `[255, 136, 0]`.
fn rgb(v: &Value) -> Result<[u8; 3], String> {
    if let Some(s) = v.as_str().and_then(|s| s.strip_prefix('#')).filter(|s| s.len() == 6) {
        let p = |i: usize| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "set_color takes #rrggbb or [r, g, b]".to_string());
        return Ok([p(0)?, p(2)?, p(4)?]);
    }
    let a = v.as_array().filter(|a| a.len() == 3).ok_or("set_color takes #rrggbb or [r, g, b]")?;
    let c = |i: usize| a[i].as_u64().filter(|x| *x <= 255).map(|x| x as u8).ok_or("each colour is 0 to 255".to_string());
    Ok([c(0)?, c(1)?, c(2)?])
}

/// Attributes an agent sees: small values only, nothing that looks like a secret or a picture.
fn attributes(a: &Value) -> Value {
    let mut out = Map::new();
    for (k, v) in a.as_object().into_iter().flatten().take(40) {
        if ["access_token", "entity_picture", "token", "code_format", "password"].contains(&k.as_str()) { continue; }
        let s = v.to_string();
        if s.len() <= 500 { out.insert(net::clean(k, 64), v.clone()); }
    }
    Value::Object(out)
}

/// The adopted hub: its address pinned on the LAN, with the lent token.
pub struct Hub { base: String, http: reqwest::Client, token: String }

impl Hub {
    pub async fn open(e: &External, secret: Option<&Secret>) -> Result<Hub, String> {
        if e.hub.as_deref().unwrap_or("home-assistant") != "home-assistant" {
            return Err(format!("{} is a {} hub; only Home Assistant hubs are built on the node so far", e.id, e.hub.as_deref().unwrap_or("?")));
        }
        let s = secret.ok_or_else(|| format!("the adoption of {} lends no Home Assistant token to this computer", e.id))?;
        let a = net::parse_addr(&e.address, &["http", "https"], "http", |s| if s == "https" { 443 } else { 8123 })?;
        let addr = net::resolve(&a.host, a.port).await?;
        let http = net::client(&a.host, addr, Duration::from_secs(15), a.scheme == "https")?;
        Ok(Hub { base: format!("{}{}", net::origin(&a.scheme, &a.host, a.port), a.path.trim_end_matches('/')), http, token: s.token().to_string() })
    }
    async fn get(&self, path: &str) -> Result<Value, String> {
        let r = self.http.get(format!("{}{path}", self.base)).bearer_auth(&self.token).send().await.map_err(|e| format!("Home Assistant didn't answer: {e}"))?;
        let st = r.status().as_u16();
        let b = net::body_capped(r, 8 << 20, "Home Assistant's answer").await?;
        match st {
            200 => serde_json::from_slice(&b).map_err(|_| "Home Assistant's answer isn't JSON".to_string()),
            401 | 403 => Err("Home Assistant refused the lent token".into()),
            404 => Err("Home Assistant has no such device".into()),
            s => Err(format!("Home Assistant answered {s}")),
        }
    }
    pub async fn state(&self, entity: &str) -> Result<Value, String> { self.get(&format!("/api/states/{entity}")).await }

    pub async fn list(&self, e: &External) -> Result<Value, String> {
        let all = self.get("/api/states").await?;
        let mut devices = vec![];
        for s in all.as_array().into_iter().flatten() {
            let Some(id) = s["entity_id"].as_str().filter(|id| entity_ok(id) && device_allowed(e, id)) else { continue };
            let (domain, _) = id.split_once('.').unwrap();
            if ["automation", "script", "zone", "sun", "update", "conversation", "tts", "stt", "event", "todo", "image", "notify"].contains(&domain) { continue; }
            let a = &s["attributes"];
            devices.push(json!({ "id": id, "name": net::clean(a["friendly_name"].as_str().unwrap_or(id), 100), "room": Value::Null, "class": class(domain),
                "device_class": a["device_class"], "capabilities": capabilities(domain, a), "critical": critical(id, a, e.critical).is_some(), "state": net::clean(s["state"].as_str().unwrap_or(""), 100) }));
            if devices.len() >= MAX_DEVICES { break; }
        }
        // Rooms are Home Assistant areas, which the REST API only gives through a template. A fixed one, never the agent's.
        let mut rooms: Vec<String> = vec![];
        if !devices.is_empty() {
            let ids: Vec<&str> = devices.iter().filter_map(|d| d["id"].as_str()).collect();
            let tpl = format!("{{% for e in {} %}}{{{{ e }}}}={{{{ area_name(e) }}}}\n{{% endfor %}}", serde_json::to_string(&ids).unwrap());
            if let Ok(r) = self.http.post(format!("{}/api/template", self.base)).bearer_auth(&self.token).json(&json!({ "template": tpl })).send().await {
                if r.status().is_success() {
                    let text = String::from_utf8_lossy(&net::body_capped(r, 1 << 20, "rooms").await.unwrap_or_default()).to_string();
                    for line in text.lines() {
                        let Some((id, area)) = line.split_once('=') else { continue };
                        if area.is_empty() || area == "None" { continue; }
                        let area = net::clean(area, 64);
                        if let Some(d) = devices.iter_mut().find(|d| d["id"] == id) { d["room"] = json!(area); }
                        if !rooms.contains(&area) { rooms.push(area); }
                    }
                }
            }
        }
        rooms.sort();
        Ok(json!({ "rooms": rooms, "devices": devices }))
    }

    pub async fn read(&self, e: &External, entity: &str) -> Result<Value, String> {
        let s = self.state(entity).await?;
        let at = s["last_updated"].as_str().and_then(net::unix_time).unwrap_or_else(super::super::now);
        Ok(json!({ "state": net::clean(s["state"].as_str().unwrap_or(""), 200), "attributes": attributes(&s["attributes"]), "critical": critical(entity, &s["attributes"], e.critical).is_some(), "at": at }))
    }

    /// What the hub says the device is: whether a command is critical, and that it has the command at all.
    pub async fn check(&self, e: &External, entity: &str, command: &str) -> Result<Option<&'static str>, String> {
        let s = self.state(entity).await?;
        let (domain, _) = entity.split_once('.').unwrap_or(("", ""));
        if !capabilities(domain, &s["attributes"]).contains(&command) { return Err(format!("{entity} has no {command:?} (a {} device)", class(domain))); }
        Ok(critical(entity, &s["attributes"], e.critical))
    }

    pub async fn command(&self, entity: &str, command: &str, value: &Value) -> Result<Value, String> {
        let (domain, svc, data) = service(entity, command, value)?;
        let r = self.http.post(format!("{}/api/services/{domain}/{svc}", self.base)).bearer_auth(&self.token).json(&Value::Object(data)).send().await
            .map_err(|e| format!("Home Assistant didn't answer: {e}"))?;
        let st = r.status().as_u16();
        if !(200..300).contains(&st) {
            let b = net::body_capped(r, 64 << 10, "Home Assistant's answer").await.unwrap_or_default();
            return Err(format!("Home Assistant refused {command} ({st}: {})", net::clean(&String::from_utf8_lossy(&b), 200)));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let s = self.state(entity).await?;
        Ok(json!({ "done": true, "state": net::clean(s["state"].as_str().unwrap_or(""), 200) }))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn domains_map_to_the_vocabulary() {
        assert_eq!(capabilities("light", &json!({ "supported_color_modes": ["hs"] })), vec!["on", "off", "toggle", "set_level", "set_color"]);
        assert_eq!(capabilities("light", &json!({ "supported_color_modes": ["onoff"] })), vec!["on", "off", "toggle"]);
        assert_eq!(capabilities("lock", &json!({})), vec!["lock", "unlock"]);
        assert_eq!(capabilities("sensor", &json!({})), Vec::<&str>::new());
        assert_eq!(class("alarm_control_panel"), "alarm");
        assert_eq!(service("light.desk", "on", &Value::Null).unwrap().1, "turn_on");
        let (d, s, data) = service("light.desk", "set_color", &json!("#ff8800")).unwrap();
        assert_eq!((d.as_str(), s, &data["rgb_color"]), ("light", "turn_on", &json!([255, 136, 0])));
        assert_eq!(service("cover.garage", "set_level", &json!(40)).unwrap().2["position"], json!(40.0));
        assert_eq!(service("media_player.tv", "set_level", &json!(25)).unwrap().2["volume_level"], json!(0.25));
        assert_eq!(service("climate.living", "set_temperature", &json!(21.5)).unwrap().1, "set_temperature");
        assert_eq!(service("alarm_control_panel.home", "arm", &json!("night")).unwrap().1, "alarm_arm_night");
        assert_eq!(service("vacuum.robo", "return_home", &Value::Null).unwrap().1, "return_to_base");
        assert!(service("sensor.temp", "on", &Value::Null).is_err());
        assert!(service("lock.front", "open", &Value::Null).is_err()); // unlatching isn't in the vocabulary
        assert!(service("light.desk", "set_level", &json!(140)).is_err());
        assert!(service("light.desk", "on", &json!("x")).is_err());
        assert!(entity_ok("light.desk_2") && !entity_ok("light.desk/../x") && !entity_ok("light") && !entity_ok("Light.Desk"));
    }

    #[test]
    fn critical_classes_come_from_the_hub() {
        assert!(critical("lock.front_door", &json!({}), false).is_some());
        assert!(critical("cover.garage", &json!({ "device_class": "garage" }), false).is_some());
        assert!(critical("cover.blinds", &json!({ "device_class": "blind" }), false).is_none());
        assert!(critical("alarm_control_panel.home", &json!({}), false).is_some());
        assert!(critical("climate.living", &json!({ "hvac_modes": ["off", "heat"] }), false).is_some());
        assert!(critical("climate.bedroom_ac", &json!({ "hvac_modes": ["off", "cool", "dry"] }), false).is_none());
        assert!(critical("climate.unknown", &json!({}), false).is_some());
        assert!(critical("water_heater.tank", &json!({}), false).is_some());
        assert!(critical("valve.main_water", &json!({}), false).is_some());
        assert!(critical("switch.kitchen_oven", &json!({}), false).is_some());
        assert!(critical("switch.plug_3", &json!({ "friendly_name": "Wallbox Pulsar" }), false).is_some());
        assert!(critical("sensor.oven_temperature", &json!({}), false).is_none()); // reading is just a read
        assert!(critical("light.desk", &json!({}), false).is_none());
        assert!(critical("light.desk", &json!({}), true).is_some()); // the owner marked it
    }

    /* ---------- a stand-in Home Assistant ---------- */

    pub const TOKEN: &str = "test-long-lived-token";

    /// Serves `/api/states`, `/api/states/<id>`, `/api/services/<d>/<s>` and `/api/template` for a desk lamp, a front
    /// door lock, a garage door, a thermostat and a sensor. Records service calls.
    pub async fn hub(calls: std::sync::Arc<std::sync::Mutex<Vec<(String, Value)>>>) -> String {
        use http_body_util::{BodyExt, Full};
        use hyper::{body::Incoming, Request, Response};
        let states = std::sync::Arc::new(std::sync::Mutex::new(json!({
            "light.desk": { "entity_id": "light.desk", "state": "off", "attributes": { "friendly_name": "Desk lamp", "supported_color_modes": ["brightness"] }, "last_updated": "2026-11-13T09:30:00+00:00" },
            "lock.front_door": { "entity_id": "lock.front_door", "state": "locked", "attributes": { "friendly_name": "Front door" }, "last_updated": "2026-11-13T09:30:00+00:00" },
            "cover.garage": { "entity_id": "cover.garage", "state": "closed", "attributes": { "friendly_name": "Garage", "device_class": "garage" }, "last_updated": "2026-11-13T09:30:00+00:00" },
            "climate.living": { "entity_id": "climate.living", "state": "heat", "attributes": { "friendly_name": "Living room", "hvac_modes": ["off", "heat"], "temperature": 20 }, "last_updated": "2026-11-13T09:30:00+00:00" },
            "sensor.outside": { "entity_id": "sensor.outside", "state": "11.5", "attributes": { "friendly_name": "Outside", "unit_of_measurement": "°C", "entity_picture": "/x.png" }, "last_updated": "2026-11-13T09:30:00+00:00" },
        })));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { return };
                let (states, calls) = (states.clone(), calls.clone());
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let (states, calls) = (states.clone(), calls.clone());
                        async move {
                            let ok_auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {TOKEN}"));
                            let (method, path) = (req.method().clone(), req.uri().path().to_string());
                            let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                            let resp = |code: u16, v: Value| Ok::<_, hyper::Error>(Response::builder().status(code).header("content-type", "application/json").body(Full::new(bytes::Bytes::from(v.to_string()))).unwrap());
                            if !ok_auth { return resp(401, json!({ "message": "Unauthorized" })); }
                            let st = states.lock().unwrap().clone();
                            match (method.as_str(), path.as_str()) {
                                ("GET", "/api/states") => resp(200, json!(st.as_object().unwrap().values().collect::<Vec<_>>())),
                                ("GET", p) if p.starts_with("/api/states/") => match st.get(&p[12..]) { Some(s) => resp(200, s.clone()), None => resp(404, json!({ "message": "Entity not found." })) },
                                ("POST", "/api/template") => Ok(Response::builder().status(200).header("content-type", "text/plain").body(Full::new(bytes::Bytes::from("light.desk=Office\nlock.front_door=Hall\ncover.garage=None\n"))).unwrap()),
                                ("POST", p) if p.starts_with("/api/services/") => {
                                    let data: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                                    calls.lock().unwrap().push((p[14..].to_string(), data.clone()));
                                    let id = data["entity_id"].as_str().unwrap_or("").to_string();
                                    let new = match &p[14..] { "light/turn_on" => "on", "light/turn_off" => "off", "lock/unlock" => "unlocked", "lock/lock" => "locked", "cover/open_cover" => "open", _ => "" };
                                    if !new.is_empty() { states.lock().unwrap()[&id]["state"] = json!(new); }
                                    resp(200, json!([]))
                                }
                                _ => resp(404, json!({ "message": "not found" })),
                            }
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
                });
            }
        });
        addr
    }

    pub fn adoption(addr: &str, devices: &[&str]) -> External {
        External { id: "ext_hub".into(), name: "Home".into(), kind: "home".into(), hub: Some("home-assistant".into()), address: addr.into(), secret: Some("HA_TOKEN".into()),
            allow: crate::devices::envelope::Allow { devices: devices.iter().map(|s| s.to_string()).collect(), ..Default::default() }, ..Default::default() }
    }

    #[tokio::test]
    async fn list_read_and_command_through_the_rest_api() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let addr = hub(calls.clone()).await;
        let e = adoption(&addr, &[]);
        let token = Secret::new("HA_TOKEN", TOKEN);
        let h = Hub::open(&e, Some(&token)).await.unwrap();
        let l = h.list(&e).await.unwrap();
        assert_eq!(l["rooms"], json!(["Hall", "Office"]));
        let lamp = l["devices"].as_array().unwrap().iter().find(|d| d["id"] == "light.desk").unwrap().clone();
        assert_eq!((lamp["room"].as_str(), lamp["critical"].as_bool()), (Some("Office"), Some(false)));
        let lock = l["devices"].as_array().unwrap().iter().find(|d| d["id"] == "lock.front_door").unwrap().clone();
        assert_eq!((lock["class"].as_str(), lock["critical"].as_bool()), (Some("lock"), Some(true)));
        let s = h.read(&e, "sensor.outside").await.unwrap();
        assert_eq!(s["state"], "11.5");
        assert!(s["attributes"].get("entity_picture").is_none());
        assert_eq!(s["at"], 1_794_562_200);
        assert_eq!(h.check(&e, "light.desk", "on").await.unwrap(), None);
        assert!(h.check(&e, "lock.front_door", "unlock").await.unwrap().is_some());
        assert!(h.check(&e, "sensor.outside", "on").await.is_err());
        assert_eq!(h.command("light.desk", "on", &Value::Null).await.unwrap(), json!({ "done": true, "state": "on" }));
        assert_eq!(calls.lock().unwrap()[0], ("light/turn_on".to_string(), json!({ "entity_id": "light.desk" })));
        // Only the listed devices, when the adoption lists them.
        let e2 = adoption(&addr, &["light.desk"]);
        assert_eq!(h.list(&e2).await.unwrap()["devices"].as_array().unwrap().len(), 1);
        // A wrong token.
        let bad = Secret::new("HA_TOKEN", "nope");
        assert!(Hub::open(&e, Some(&bad)).await.unwrap().list(&e).await.unwrap_err().contains("refused the lent token"));
        assert!(Hub::open(&e, None).await.err().unwrap().contains("lends no"));
    }
}
