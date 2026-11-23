//! Adoption helpers: `pavilion-node devices scan obd|home|cast|printers|cameras|modbus`. A person starts a scan on
//! this computer; what's found is shown here and sent to the pavilion (`POST …/node/devices/scan`) so an owner can adopt
//! a device in the console. Each item carries the real address (adoption needs it), its hashed id, and `suggest`: the
//! adoption kind (and transport or hub) the console should prefill. Scans only look: nothing is sent to a device except
//! an `ATI` (who are you) to a Wi-Fi OBD adapter and one register read for `scan modbus <host>`.
use super::super::caps::lan;
use super::super::envelope::scan_id;
use serde_json::{json, Value};
use std::time::Duration;

pub const KINDS: &[&str] = &["obd", "home", "cast", "printers", "cameras", "modbus"];

/// The kind `POST …/scan` carries for each scan.
pub fn wire_kind(k: &str) -> &'static str { match k { "obd" => "obd", "home" => "home", "cast" => "cast", "printers" => "printer", "cameras" => "camera", _ => "modbus" } }

fn lan_items(items: &[lan::LanItem], pavilion: &str, suggest: impl Fn(&lan::LanItem) -> Value) -> Vec<Value> {
    items.iter().map(|i| { let mut v = i.for_adoption(pavilion); v["suggest"] = suggest(i); v }).collect()
}

/// Serial ports that could be an OBD-II adapter (USB, or Bluetooth Classic once paired).
pub fn serial_ports(pavilion: &str) -> Vec<Value> {
    let Ok(ports) = serialport::available_ports() else { return vec![] };
    ports.into_iter().filter(|p| {
        let n = p.port_name.to_ascii_lowercase();
        !(n.contains("bluetooth-incoming") || n.contains("debug-console") || n.contains("wlan-debug") || (cfg!(target_os = "macos") && n.starts_with("/dev/tty.")))
    }).map(|p| {
        let (transport, name) = match &p.port_type {
            serialport::SerialPortType::UsbPort(u) => ("usb", u.product.clone().unwrap_or_else(|| format!("USB {:04x}:{:04x}", u.vid, u.pid))),
            serialport::SerialPortType::BluetoothPort => ("classic", p.port_name.clone()),
            _ => (if p.port_name.to_ascii_lowercase().contains("usb") { "usb" } else { "classic" }, p.port_name.clone()),
        };
        json!({ "id": scan_id(pavilion, &p.port_name), "address": p.port_name, "name": super::net::clean(&name, 64), "transport": transport, "suggest": { "kind": "obd", "transport": transport } })
    }).collect()
}

/// A Wi-Fi OBD adapter at its usual address (this computer must have joined the adapter's network).
async fn wifi_obd(pavilion: &str) -> Option<Value> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = "192.168.0.10:35000";
    let mut s = tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(addr)).await.ok()?.ok()?;
    s.write_all(b"ATI\r").await.ok()?;
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await.ok()?.ok()?;
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    text.contains("ELM").then(|| json!({ "id": scan_id(pavilion, addr), "address": addr, "name": super::net::clean(text.trim().trim_end_matches('>').trim(), 40), "transport": "wifi", "suggest": { "kind": "obd", "transport": "wifi" } }))
}

const BLE_OBD_SERVICES: &[&str] = &["0000fff0", "0000ffe0", "000018f0"];
const BLE_OBD_NAMES: &[&str] = &["obd", "elm", "vgate", "vlink", "obdlink", "icar", "veepeak", "konnwei"];

/// Serial ports, a Wi-Fi adapter at its usual address, and (with `ble`) BLE adapters by their services or names.
pub async fn obd(pavilion: &str, seconds: u32, ble: bool) -> Vec<Value> {
    let mut out = serial_ports(pavilion);
    if let Some(w) = wifi_obd(pavilion).await { out.push(w); }
    #[cfg(any(target_os = "macos", windows))]
    if !ble { return out; }
    #[cfg(any(target_os = "macos", windows))]
    if let Ok(items) = super::super::caps::ble::scan(seconds, None).await {
        for i in items {
            let named = i.name.as_deref().map_or(false, |n| BLE_OBD_NAMES.iter().any(|w| n.to_ascii_lowercase().contains(w)));
            let served = i.services.iter().any(|s| BLE_OBD_SERVICES.iter().any(|p| s.starts_with(p)));
            if named || served {
                let mut v = i.for_adoption(pavilion);
                v["transport"] = json!("ble");
                v["suggest"] = json!({ "kind": "obd", "transport": "ble" });
                out.push(v);
            }
        }
    }
    let _ = (seconds, ble);
    out
}

pub async fn home(pavilion: &str, seconds: u32) -> Result<Vec<Value>, String> {
    let found = lan::discover(&["_home-assistant._tcp".into(), "_mqtt._tcp".into()], seconds).await?;
    Ok(lan_items(&found, pavilion, |i| if i.ty.starts_with("_home-assistant") {
        let base = i.txt.get("base_url").and_then(|v| v.as_str()).filter(|u| u.starts_with("http")).map(String::from).unwrap_or_else(|| format!("http://{}:{}", i.host, i.port));
        json!({ "kind": "home", "hub": "home-assistant", "address": base })
    } else { json!({ "kind": "mqtt", "address": format!("{}:{}", i.host, i.port) }) }))
}

pub async fn cast(pavilion: &str, seconds: u32) -> Result<Vec<Value>, String> {
    let found = lan::discover(&["_googlecast._tcp".into()], seconds).await?;
    Ok(lan_items(&found, pavilion, |i| json!({ "kind": "cast", "address": format!("{}:{}", i.host, i.port), "name": i.txt.get("fn"), "model": i.txt.get("md") })))
}

pub async fn printers(pavilion: &str, seconds: u32) -> Result<Vec<Value>, String> {
    let found = lan::discover(&["_ipp._tcp".into(), "_ipps._tcp".into()], seconds).await?;
    Ok(lan_items(&found, pavilion, |i| {
        let rp = i.txt.get("rp").and_then(|v| v.as_str()).unwrap_or("ipp/print").trim_start_matches('/').to_string();
        let scheme = if i.ty.starts_with("_ipps") { "ipps" } else { "ipp" };
        json!({ "kind": "printer", "address": format!("{scheme}://{}:{}/{rp}", i.host, i.port), "model": i.txt.get("ty"), "formats": i.txt.get("pdl") })
    }))
}

/// The WS-Discovery Probe for ONVIF video devices.
pub fn probe(message_id: &str) -> String {
    format!(concat!(r#"<?xml version="1.0" encoding="UTF-8"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" "#,
        r#"xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><e:Header><w:MessageID>uuid:{}</w:MessageID>"#,
        r#"<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>"#,
        r#"</e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>"#), message_id)
}

/// A ProbeMatch → (service addresses, name from the scopes, hardware from the scopes).
pub fn probe_match(xml: &str) -> Option<(Vec<String>, Option<String>, Option<String>)> {
    use super::onvif::texts;
    let xaddrs: Vec<String> = texts(xml, "XAddrs").iter().flat_map(|x| x.split_whitespace().map(String::from).collect::<Vec<_>>()).filter(|x| x.starts_with("http://") || x.starts_with("https://")).collect();
    if xaddrs.is_empty() { return None; }
    let scopes = texts(xml, "Scopes").join(" ");
    let scope = |k: &str| scopes.split_whitespace().find_map(|s| s.strip_prefix(&format!("onvif://www.onvif.org/{k}/"))).map(|v| super::net::clean(&v.replace("%20", " "), 64));
    Some((xaddrs, scope("name"), scope("hardware")))
}

pub async fn cameras(pavilion: &str, seconds: u32) -> Result<Vec<Value>, String> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
    let _ = sock.set_multicast_ttl_v4(1);
    let id = crate::signing::random_b64(12);
    let msg = probe(&format!("{}-{}", &id[..8], &id[8..]));
    sock.send_to(msg.as_bytes(), "239.255.255.250:3702").await.map_err(|e| format!("WS-Discovery: {e}"))?;
    let end = tokio::time::Instant::now() + Duration::from_secs(seconds as u64);
    let mut out: Vec<Value> = vec![];
    let mut buf = vec![0u8; 65_535];
    while let Ok(Ok((n, from))) = tokio::time::timeout_at(end, sock.recv_from(&mut buf)).await {
        if !super::net::allowed_ip(&from.ip()) { continue; }
        let Some((xaddrs, name, hw)) = probe_match(&String::from_utf8_lossy(&buf[..n])) else { continue };
        // The device service's host and port; the adoption address is the camera itself.
        let Some(addr) = xaddrs.iter().find_map(|x| { let a = super::net::parse_addr(x, &["http"], "http", |_| 80).ok()?; Some(format!("{}:{}", a.host, a.port)) }) else { continue };
        if out.iter().any(|v| v["address"] == addr) { continue; }
        out.push(json!({ "id": scan_id(pavilion, &addr), "address": addr, "addresses": [from.ip().to_string()], "name": name.clone().unwrap_or_else(|| "ONVIF camera".into()),
            "model": hw, "type": "onvif", "suggest": { "kind": "camera", "address": format!("http://{addr}") } }));
    }
    Ok(out)
}

/// Modbus has no discovery: `scan modbus <host[:port]>` checks one address answers Modbus TCP (one holding register
/// read at address 0, unit 1; an exception answer counts as Modbus too).
pub async fn modbus(pavilion: &str, host: Option<&str>) -> Result<Vec<Value>, String> {
    let host = host.ok_or("Modbus devices can't be discovered: give an address, e.g. `pavilion-node devices scan modbus 192.168.1.50`")?;
    let e = super::super::envelope::External { id: "scan".into(), kind: "modbus".into(), address: host.into(), ..Default::default() };
    let mut c = super::modbus::Client::open(&e).await?;
    let r = super::modbus::register(&json!({ "name": "probe", "table": "holding", "address": 0, "type": "u16" }))?;
    let speaks = match c.read(&r).await { Ok(_) => true, Err(e) => e.contains("answered with") };
    if !speaks { return Err(format!("{host} didn't answer as a Modbus TCP device")); }
    let a = super::net::parse_addr(host, &["tcp", "modbus"], "tcp", |_| 502)?;
    let addr = format!("{}:{}", a.host, a.port);
    Ok(vec![json!({ "id": scan_id(pavilion, &addr), "address": addr, "name": format!("Modbus device at {addr}"), "type": "modbus", "suggest": { "kind": "modbus" } })])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_discovery() {
        let p = probe("1234-5678");
        assert!(p.contains("<d:Types>dn:NetworkVideoTransmitter</d:Types>") && p.contains("uuid:1234-5678"));
        let m = r#"<SOAP-ENV:Envelope><SOAP-ENV:Body><d:ProbeMatches><d:ProbeMatch><d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/name/Front%20Door onvif://www.onvif.org/hardware/IPC-HDW</d:Scopes><d:XAddrs>http://192.168.1.64/onvif/device_service http://[fe80::1]/onvif/device_service</d:XAddrs></d:ProbeMatch></d:ProbeMatches></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
        let (x, name, hw) = probe_match(m).unwrap();
        assert_eq!(x[0], "http://192.168.1.64/onvif/device_service");
        assert_eq!((name.as_deref(), hw.as_deref()), (Some("Front Door"), Some("IPC-HDW")));
        assert!(probe_match("<x/>").is_none());
    }

    #[tokio::test]
    async fn a_modbus_address_is_checked() {
        let addr = super::super::modbus::tests::device(std::sync::Arc::new(std::sync::Mutex::new(vec![0; 10])), vec![0; 10]).await;
        let v = modbus("acme", Some(&addr)).await.unwrap();
        assert_eq!(v[0]["suggest"]["kind"], "modbus");
        assert!(modbus("acme", None).await.unwrap_err().contains("can't be discovered"));
    }
}
