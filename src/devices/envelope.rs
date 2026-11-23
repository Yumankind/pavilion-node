//! Device action envelopes (docs/DEVICES-PROTOCOL.md §4a): what the Gate signs, what this computer checks before it
//! asks anyone, and the signatures it sends back (answers, results). Pure functions, so every check is tested here.
use crate::signing::{b64, sha256, unb64};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;

/// Longest an action may live (DEVICES-PROTOCOL.md §4a: at most 10 minutes).
pub const MAX_LIFETIME_S: u64 = 600;
/// How far ahead of this computer's clock an action may say it was issued.
pub const CLOCK_SKEW_S: u64 = 300;

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct PathRule { pub method: String, pub path: String }

/// What an adoption allows beyond its kind (DEVICES-PROTOCOL.md §8): OBD-II PIDs, Modbus registers, MQTT topics, hub
/// devices. Each adapter reads the part it needs, strictly (standards/).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Allow {
    /// OBD-II: `"standard"` (every PID the node knows), or a list of PIDs (`"0C"`) and names (`"rpm"`).
    #[serde(default)] pub pids: Value,
    /// Modbus: `[{name, table: "holding"|"input", address, type, scale?, unit?, unit_id?, words?}]`.
    #[serde(default)] pub registers: Vec<Value>,
    #[serde(default)] pub commands: Vec<String>,
    /// MQTT: topic filters (`+` and `#` allowed) an agent may read and publish to.
    #[serde(default)] pub topics: Vec<String>,
    /// Hubs: the device ids (Home Assistant entity ids) agents may see and command. Empty: all of the hub's.
    #[serde(default)] pub devices: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct External {
    pub id: String,
    #[serde(default)] pub name: String,
    pub kind: String,
    pub address: String,
    /// OBD-II adapters: `usb`, `classic`, `ble` or `wifi`.
    #[serde(default)] pub transport: Option<String>,
    /// Home hubs: `home-assistant` (the one built on the node so far), …
    #[serde(default)] pub hub: Option<String>,
    #[serde(default)] pub service: Option<String>,
    #[serde(default)] pub characteristics: Vec<String>,
    /// LAN devices: the methods and paths the adoption lists.
    #[serde(default)] pub paths: Vec<PathRule>,
    #[serde(default)] pub allow: Allow,
    /// The name of the vault secret lent to this host for this device (a hub token, a camera login), never its value.
    /// The value is fetched sealed for each action (`…/actions/<act>/secret`) and held in memory only.
    #[serde(default)] pub secret: Option<String>,
    #[serde(default)] pub critical: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Upload { pub max_bytes: u64, #[serde(default)] pub types: Vec<String> }

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub v: u32,
    pub pavilion: String,
    pub device: String,
    pub action: String,
    pub agent: String,
    #[serde(default)] pub agent_name: String,
    pub tool: String,
    #[serde(default)] pub args: Value,
    pub args_hash: String,
    pub kind: String,
    pub text: String,
    #[serde(default)] pub reason: Option<String>,
    #[serde(default)] pub external: Option<External>,
    #[serde(default)] pub approval: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub key_needed: String,
    #[serde(default)] pub mode: String,
    #[serde(default)] pub upload: Option<Upload>,
}

/// Why an envelope was refused, and whether it's worth telling the Gate (`…/fail`).
#[derive(Debug, PartialEq)]
pub struct Refusal { pub act: Option<String>, pub why: String, pub report: bool }

fn refuse(act: Option<&str>, why: impl Into<String>) -> Refusal { Refusal { act: act.map(String::from), why: why.into(), report: act.is_some() } }

/// Canonical JSON: keys sorted (by UTF-16 code units, as JavaScript sorts them), no spaces, UTF-8. The same text as
/// `JSON.stringify` of a key-sorted object.
pub fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let parts: Vec<String> = keys.iter().map(|k| format!("{}:{}", Value::String((*k).clone()), canonical_json(&m[k.as_str()]))).collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => format!("[{}]", a.iter().map(canonical_json).collect::<Vec<_>>().join(",")),
        other => other.to_string(),
    }
}

pub fn args_hash(args: &Value) -> String { b64(&sha256(canonical_json(args).as_bytes())) }

fn rank(kind: &str) -> Option<u8> { Some(match kind { "look" => 0, "read" => 1, "capture" => 2, "act" => 3, "critical" => 4, _ => return None }) }

/// The least kind a tool can be (DEVICES.md §7a). The Gate may make an action stricter, never weaker: a photo can't be
/// sent as a "look" to skip the person's presence.
pub fn floor_kind(tool: &str, args: &Value, external: Option<&External>) -> Option<&'static str> {
    let k = match tool {
        "ble_scan" | "lan_discover" => "look",
        "ble_read" | "ble_subscribe" | "sensor_read" => "read",
        "camera_snapshot" | "camera_clip" | "record_audio" | "screen_capture" | "location" | "nfc_read" => "capture",
        "ble_write" | "play_audio" | "nfc_write" => "act",
        "lan_request" => if args["method"].as_str() == Some("GET") { "read" } else { "act" },
        // The first set of standards (DEVICES.md §4b). home_command is an act here; the node also asks the hub what
        // the device is and refuses a lock, a garage door or a heater unless the action is critical (standards/home.rs).
        "home_list" => "look",
        "obd_info" | "obd_read" | "obd_codes" | "obd_monitor" | "home_state" | "mqtt_read" | "modbus_read" => "read",
        "obd_clear_codes" | "home_command" | "mqtt_publish" | "cast_media" | "media_control" | "print" => "act",
        "modbus_write" => "critical",
        _ => return None,
    };
    if external.map_or(false, |e| e.critical) { return Some("critical"); }
    Some(k)
}

/// The key an answer for this kind must use: the presence key (here: LocalAuthentication / Windows Hello first) for
/// captures, acts and critical actions.
pub fn key_for(kind: &str) -> &'static str { if rank(kind).map_or(true, |r| r >= 2) { "presence" } else { "unlocked" } }

pub fn action_id_ok(a: &str) -> bool { a.len() == 24 && a.starts_with("act_") && a[4..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }

/// Checks an envelope as received: the signature over the exact string, then what it says. `now` is Unix seconds.
/// Single use is checked separately (`Seen`), since it has to be remembered on disk.
pub fn verify(pavilion_key_b64: &str, pavilion: &str, machine: &str, payload: &str, sig_b64: &str, now: u64) -> Result<Envelope, Refusal> {
    let (Ok(pk), Ok(sig)) = (unb64(pavilion_key_b64), unb64(sig_b64)) else { return Err(refuse(None, "the action isn't signed")) };
    let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(pk.as_slice()), ed25519_dalek::Signature::from_slice(&sig)) else { return Err(refuse(None, "the action's signature is malformed")) };
    let msg = format!("pavilion-device-action-v1\n{payload}");
    if !VerifyingKey::from_bytes(&pk).map(|k| k.verify(msg.as_bytes(), &sig).is_ok()).unwrap_or(false) {
        return Err(refuse(None, "the action isn't signed by this pavilion's key"));
    }
    let raw: Value = serde_json::from_str(payload).map_err(|_| refuse(None, "the action isn't JSON"))?;
    let act = raw["action"].as_str().filter(|a| action_id_ok(a));
    let e: Envelope = serde_json::from_value(raw.clone()).map_err(|err| refuse(act, format!("the action is missing a field: {err}")))?;
    let act = Some(e.action.as_str()).filter(|a| action_id_ok(a));
    if act.is_none() { return Err(refuse(None, "the action id isn't act_ and 20 hex digits")); }
    if e.v != 1 { return Err(refuse(act, format!("action version {} isn't one this node reads", e.v))); }
    if e.pavilion != pavilion { return Err(refuse(act, "the action is for another pavilion")); }
    if e.device != machine { return Err(refuse(act, "the action is meant for another device")); }
    if e.expires_at <= now { return Err(refuse(act, "the action expired before it could be asked")); }
    if e.issued_at > now + CLOCK_SKEW_S { return Err(refuse(act, "the action says it was issued in the future (check this computer's clock)")); }
    if e.expires_at <= e.issued_at || e.expires_at - e.issued_at > MAX_LIFETIME_S { return Err(refuse(act, "the action lives longer than 10 minutes")); }
    if args_hash(&e.args) != e.args_hash { return Err(refuse(act, "the action's arguments don't match their hash")); }
    let floor = floor_kind(&e.tool, &e.args, e.external.as_ref()).ok_or_else(|| refuse(act, format!("{} isn't a device tool", e.tool)))?;
    let kr = rank(&e.kind).ok_or_else(|| refuse(act, format!("{:?} isn't a kind of action", e.kind)))?;
    if kr < rank(floor).unwrap() { return Err(refuse(act, format!("{} must be at least a {floor} action, not {}", e.tool, e.kind))); }
    if e.key_needed != key_for(&e.kind) { return Err(refuse(act, format!("a {} action needs the {} key, not {:?}", e.kind, key_for(&e.kind), e.key_needed))); }
    if e.text.trim().is_empty() || e.text.len() > 500 { return Err(refuse(act, "the action has no text to show")); }
    if e.reason.as_ref().map_or(false, |r| r.len() > 500) { return Err(refuse(act, "the agent's reason is too long")); }
    Ok(e)
}

/// `pavilion-device-answer-v1\n<act>\n<argsHash>\n<decision>`
pub fn answer_message(act: &str, args_hash: &str, decision: &str) -> String { format!("pavilion-device-answer-v1\n{act}\n{args_hash}\n{decision}") }
/// `pavilion-device-result-v1\n<act>\n<b64u(sha256(body))>`
pub fn result_message(act: &str, body: &[u8]) -> String { format!("pavilion-device-result-v1\n{act}\n{}", b64(&sha256(body))) }
pub fn sign(key: &SigningKey, msg: &str) -> String { b64(&key.sign(msg.as_bytes()).to_bytes()) }

/// A scanned device's id as agents see it: `b64u(sha256(pavilion + ":" + address))[0..16]` (DEVICES-PROTOCOL.md §8).
pub fn scan_id(pavilion: &str, address: &str) -> String { b64(&sha256(format!("{pavilion}:{address}").as_bytes()))[..16].to_string() }

#[cfg(test)]
pub mod tests {
    use super::*;
    use serde_json::json;

    pub const PAV: &str = "acme";
    pub const ME: &str = "mch_studio";
    pub const NOW: u64 = 1_763_000_000;

    /// A stand-in for the Gate: an envelope signed with a test pavilion key, exactly as the wire carries it.
    pub fn gate_key() -> SigningKey { SigningKey::from_bytes(&[7u8; 32]) }
    pub fn envelope(tool: &str, args: Value, kind: &str, edit: impl FnOnce(&mut Value)) -> Value {
        let mut e = json!({ "v": 1, "pavilion": PAV, "device": ME, "action": "act_0123456789abcdef0123", "agent": "agt_linkcheck",
            "agentName": "linkcheck", "tool": tool, "argsHash": args_hash(&args), "args": args, "kind": kind,
            "text": "linkcheck wants to list the services on this computer's network", "reason": "to find the printer",
            "external": null, "approval": null, "issuedAt": NOW - 5, "expiresAt": NOW + 115,
            "keyNeeded": key_for(kind), "mode": "foreground", "upload": null });
        edit(&mut e);
        e
    }
    pub fn signed(e: &Value, key: &SigningKey) -> (String, String) {
        let payload = e.to_string();
        let sig = b64(&key.sign(format!("pavilion-device-action-v1\n{payload}").as_bytes()).to_bytes());
        (payload, sig)
    }
    fn check(e: &Value) -> Result<Envelope, Refusal> {
        let (p, s) = signed(e, &gate_key());
        verify(&b64(gate_key().verifying_key().as_bytes()), PAV, ME, &p, &s, NOW)
    }

    #[test]
    fn a_good_envelope_passes() {
        let e = check(&envelope("lan_discover", json!({ "host": ME, "seconds": 3 }), "look", |_| {})).unwrap();
        assert_eq!(e.tool, "lan_discover");
        assert_eq!(e.key_needed, "unlocked");
    }

    #[test]
    fn a_tampered_envelope_is_refused() {
        let (p, s) = signed(&envelope("lan_discover", json!({ "host": ME }), "look", |_| {}), &gate_key());
        let tampered = p.replace("lan_discover", "camera_snapshot");
        let r = verify(&b64(gate_key().verifying_key().as_bytes()), PAV, ME, &tampered, &s, NOW).unwrap_err();
        assert!(r.why.contains("isn't signed by") && !r.report);
        // Signed by some other key.
        let (p, s) = signed(&envelope("lan_discover", json!({ "host": ME }), "look", |_| {}), &SigningKey::from_bytes(&[9u8; 32]));
        assert!(verify(&b64(gate_key().verifying_key().as_bytes()), PAV, ME, &p, &s, NOW).is_err());
        // The same JSON with a space added: the signature is over the exact string.
        let (p, s) = signed(&envelope("lan_discover", json!({ "host": ME }), "look", |_| {}), &gate_key());
        assert!(verify(&b64(gate_key().verifying_key().as_bytes()), PAV, ME, &p.replacen('{', "{ ", 1), &s, NOW).is_err());
    }

    #[test]
    fn expired_wrong_device_and_stretched_envelopes_are_refused() {
        let r = check(&envelope("lan_discover", json!({}), "look", |e| { e["expiresAt"] = json!(NOW - 1) })).unwrap_err();
        assert!(r.why.contains("expired") && r.report && r.act.as_deref() == Some("act_0123456789abcdef0123"));
        assert!(check(&envelope("lan_discover", json!({}), "look", |e| { e["device"] = json!("mch_other") })).unwrap_err().why.contains("another device"));
        assert!(check(&envelope("lan_discover", json!({}), "look", |e| { e["pavilion"] = json!("other") })).unwrap_err().why.contains("another pavilion"));
        assert!(check(&envelope("lan_discover", json!({}), "look", |e| { e["expiresAt"] = json!(NOW + 3600) })).unwrap_err().why.contains("10 minutes"));
        assert!(check(&envelope("lan_discover", json!({}), "look", |e| { e["issuedAt"] = json!(NOW + 3000); e["expiresAt"] = json!(NOW + 3100) })).unwrap_err().why.contains("future"));
        assert!(check(&envelope("lan_discover", json!({}), "look", |e| { e["action"] = json!("act_XYZ") })).is_err());
    }

    #[test]
    fn arguments_must_match_their_hash() {
        let r = check(&envelope("camera_snapshot", json!({ "host": ME, "max_px": 512 }), "capture", |e| { e["args"]["max_px"] = json!(4096) })).unwrap_err();
        assert!(r.why.contains("hash"));
    }

    #[test]
    fn kinds_and_keys_cant_be_weakened() {
        // A photo sent as a "look", so it wouldn't need the person's presence.
        assert!(check(&envelope("camera_snapshot", json!({ "host": ME }), "look", |_| {})).unwrap_err().why.contains("at least a capture"));
        // The right kind with the weaker key.
        assert!(check(&envelope("camera_snapshot", json!({ "host": ME }), "capture", |e| { e["keyNeeded"] = json!("unlocked") })).unwrap_err().why.contains("presence"));
        // A POST to a LAN device is an act; a GET is a read.
        assert!(check(&envelope("lan_request", json!({ "external": "ext_a", "method": "POST", "path": "/x" }), "read", |_| {})).is_err());
        assert!(check(&envelope("lan_request", json!({ "external": "ext_a", "method": "GET", "path": "/x" }), "read", |_| {})).is_ok());
        // A device the owner marked critical.
        let ext = json!({ "id": "ext_lock", "name": "Front door", "kind": "ble", "address": "A-B", "characteristics": ["2a19"], "critical": true });
        assert!(check(&envelope("ble_write", json!({ "external": "ext_lock", "characteristic": "2a19", "hex": "01" }), "act", |e| { e["external"] = ext.clone() })).unwrap_err().why.contains("critical"));
        assert!(check(&envelope("shell", json!({}), "look", |_| {})).unwrap_err().why.contains("isn't a device tool"));
    }

    #[test]
    fn canonical_json_matches_javascript() {
        let v = json!({ "b": [1, { "z": true, "a": null }], "a": "é\n\"", "c": 1.5 });
        assert_eq!(canonical_json(&v), r#"{"a":"é\n\"","b":[1,{"a":null,"z":true}],"c":1.5}"#);
        // JSON.stringify sorts by UTF-16 code units: U+FF5E sorts after U+1F600 (a surrogate pair, 0xD83D…).
        assert_eq!(canonical_json(&json!({ "\u{FF5E}": 1, "\u{1F600}": 2 })), "{\"😀\":2,\"～\":1}");
        // The value the Gate would compute: sha256 of {"host":"mch_studio","max_px":512}.
        assert_eq!(args_hash(&json!({ "max_px": 512, "host": "mch_studio" })), b64(&sha256(br#"{"host":"mch_studio","max_px":512}"#)));
    }

    #[test]
    fn answer_and_result_signatures_verify_with_the_machine_key() {
        let k = SigningKey::from_bytes(&[3u8; 32]);
        let m = answer_message("act_0123456789abcdef0123", "HASH", "allow");
        assert_eq!(m, "pavilion-device-answer-v1\nact_0123456789abcdef0123\nHASH\nallow");
        assert!(crate::signing::verify_member("Ed25519", &b64(k.verifying_key().as_bytes()), &m, &sign(&k, &m)));
        let r = result_message("act_0123456789abcdef0123", b"{}");
        assert_eq!(r, "pavilion-device-result-v1\nact_0123456789abcdef0123\nRBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o");
        assert!(crate::signing::verify_member("Ed25519", &b64(k.verifying_key().as_bytes()), &r, &sign(&k, &r)));
        assert!(!crate::signing::verify_member("Ed25519", &b64(k.verifying_key().as_bytes()), &result_message("act_0123456789abcdef0123", b"{ }"), &sign(&k, &r)));
    }

    #[test]
    fn scan_ids_are_hashed_per_pavilion() {
        let a = scan_id("acme", "6F1C2A4B-0000-4000-8000-00000000AAAA");
        assert_eq!(a.len(), 16);
        assert_eq!(a, b64(&sha256(b"acme:6F1C2A4B-0000-4000-8000-00000000AAAA"))[..16]);
        assert_ne!(a, scan_id("other", "6F1C2A4B-0000-4000-8000-00000000AAAA"));
        assert!(!a.contains("6F1C"));
    }
}
