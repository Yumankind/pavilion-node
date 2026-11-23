//! OBD-II through an ELM327-type adapter (DEVICES.md §4c): the node talks to the adapter; agents ask for values by
//! name and get numbers, codes and their standard meanings. Agents never send `AT` commands or raw OBD requests: the
//! only things sent to an adapter are the fixed set-up below and the requests built here from typed arguments.
//!
//! Transports: a serial port (USB, or Bluetooth Classic once paired, which shows up as `/dev/cu.*` or a COM port),
//! BLE (the common serial-over-GATT services FFF0, FFE0 and 18F0), and Wi-Fi (TCP, usually `192.168.0.10:35000`).
//!
//! Set-up: `ATZ` (reset), `ATE0` (no echo), `ATL0` (no line feeds), `ATS0` (no spaces), `ATH0` (no headers),
//! `ATSP0` (find the car's protocol by itself), then `ATDPN` / `ATDP` once the car has answered.
use super::super::envelope::External;
use super::super::BoxFut;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::time::Duration;

/* ---------- Mode 01 values ---------- */

pub struct Pid { pub code: u8, pub name: &'static str, pub unit: &'static str, pub len: usize, pub f: fn(&[u8]) -> f64 }

fn ab(d: &[u8]) -> f64 { 256.0 * d[0] as f64 + d[1] as f64 }
/// Mode 01 PIDs the node knows, with the SAE J1979 formulas (A, B = the data bytes).
pub const PIDS: &[Pid] = &[
    Pid { code: 0x04, name: "engine_load", unit: "%", len: 1, f: |d| d[0] as f64 * 100.0 / 255.0 },
    Pid { code: 0x05, name: "coolant_temp", unit: "°C", len: 1, f: |d| d[0] as f64 - 40.0 },
    Pid { code: 0x06, name: "short_fuel_trim_1", unit: "%", len: 1, f: |d| (d[0] as f64 - 128.0) * 100.0 / 128.0 },
    Pid { code: 0x07, name: "long_fuel_trim_1", unit: "%", len: 1, f: |d| (d[0] as f64 - 128.0) * 100.0 / 128.0 },
    Pid { code: 0x08, name: "short_fuel_trim_2", unit: "%", len: 1, f: |d| (d[0] as f64 - 128.0) * 100.0 / 128.0 },
    Pid { code: 0x09, name: "long_fuel_trim_2", unit: "%", len: 1, f: |d| (d[0] as f64 - 128.0) * 100.0 / 128.0 },
    Pid { code: 0x0A, name: "fuel_pressure", unit: "kPa", len: 1, f: |d| d[0] as f64 * 3.0 },
    Pid { code: 0x0B, name: "intake_pressure", unit: "kPa", len: 1, f: |d| d[0] as f64 },
    Pid { code: 0x0C, name: "rpm", unit: "rpm", len: 2, f: |d| ab(d) / 4.0 },
    Pid { code: 0x0D, name: "speed", unit: "km/h", len: 1, f: |d| d[0] as f64 },
    Pid { code: 0x0E, name: "timing_advance", unit: "°", len: 1, f: |d| d[0] as f64 / 2.0 - 64.0 },
    Pid { code: 0x0F, name: "intake_temp", unit: "°C", len: 1, f: |d| d[0] as f64 - 40.0 },
    Pid { code: 0x10, name: "maf", unit: "g/s", len: 2, f: |d| ab(d) / 100.0 },
    Pid { code: 0x11, name: "throttle", unit: "%", len: 1, f: |d| d[0] as f64 * 100.0 / 255.0 },
    Pid { code: 0x1F, name: "run_time", unit: "s", len: 2, f: ab },
    Pid { code: 0x21, name: "distance_with_mil", unit: "km", len: 2, f: ab },
    Pid { code: 0x2C, name: "egr_commanded", unit: "%", len: 1, f: |d| d[0] as f64 * 100.0 / 255.0 },
    Pid { code: 0x2F, name: "fuel_level", unit: "%", len: 1, f: |d| d[0] as f64 * 100.0 / 255.0 },
    Pid { code: 0x30, name: "warmups_since_clear", unit: "count", len: 1, f: |d| d[0] as f64 },
    Pid { code: 0x31, name: "distance_since_clear", unit: "km", len: 2, f: ab },
    Pid { code: 0x33, name: "barometric_pressure", unit: "kPa", len: 1, f: |d| d[0] as f64 },
    Pid { code: 0x42, name: "module_voltage", unit: "V", len: 2, f: |d| ab(d) / 1000.0 },
    Pid { code: 0x43, name: "absolute_load", unit: "%", len: 2, f: |d| ab(d) * 100.0 / 255.0 },
    Pid { code: 0x45, name: "relative_throttle", unit: "%", len: 1, f: |d| d[0] as f64 * 100.0 / 255.0 },
    Pid { code: 0x46, name: "ambient_temp", unit: "°C", len: 1, f: |d| d[0] as f64 - 40.0 },
    Pid { code: 0x49, name: "accelerator_pedal_d", unit: "%", len: 1, f: |d| d[0] as f64 * 100.0 / 255.0 },
    Pid { code: 0x4D, name: "time_with_mil", unit: "min", len: 2, f: ab },
    Pid { code: 0x4E, name: "time_since_clear", unit: "min", len: 2, f: ab },
    Pid { code: 0x5C, name: "oil_temp", unit: "°C", len: 1, f: |d| d[0] as f64 - 40.0 },
    Pid { code: 0x5E, name: "fuel_rate", unit: "L/h", len: 2, f: |d| ab(d) / 20.0 },
];
pub const SPEED: u8 = 0x0D;

pub fn pid(code: u8) -> Option<&'static Pid> { PIDS.iter().find(|p| p.code == code) }
/// `"0C"`, `"0x0c"`, `"010C"` or a name (`"rpm"`) → the PID.
pub fn pid_arg(s: &str) -> Option<&'static Pid> {
    let t = s.trim().to_ascii_lowercase();
    if let Some(p) = PIDS.iter().find(|p| p.name == t) { return Some(p); }
    let h = t.strip_prefix("0x").unwrap_or(&t);
    let h = if h.len() == 4 && h.starts_with("01") { &h[2..] } else { h };
    if h.len() != 2 { return None; }
    u8::from_str_radix(h, 16).ok().and_then(pid)
}
pub fn decode(p: &Pid, data: &[u8]) -> Option<f64> {
    if data.len() < p.len { return None; }
    let v = (p.f)(&data[..p.len]);
    Some((v * 100.0).round() / 100.0)
}

/// The adoption's `allow.pids`: `"standard"` (or `["standard"]`) is every PID above; otherwise only those listed.
pub fn allowed(ext: &External) -> Result<BTreeSet<u8>, String> {
    let all = || PIDS.iter().map(|p| p.code).collect();
    match &ext.allow.pids {
        Value::String(s) if s == "standard" || s == "all" => Ok(all()),
        Value::Array(a) if a.iter().any(|x| x == "standard" || x == "all") => Ok(all()),
        Value::Array(a) => a.iter().map(|x| x.as_str().and_then(pid_arg).map(|p| p.code).ok_or_else(|| format!("the adoption of {} lists {x}, which isn't an OBD-II value the node knows", ext.id))).collect(),
        Value::Null => Err(format!("the adoption of {} doesn't list which values agents may read (allow.pids)", ext.id)),
        _ => Err(format!("allow.pids of {} should be \"standard\" or a list", ext.id)),
    }
}

/// Typed `pids` from an agent: up to `max`, each known and allowed by the adoption.
pub fn pids_arg(v: &Value, ext: &External, max: usize) -> Result<Vec<u8>, String> {
    let ok = allowed(ext)?;
    let a = v.as_array().filter(|a| !a.is_empty() && a.len() <= max).ok_or_else(|| format!("pids must be a list of 1 to {max} values"))?;
    let mut out = vec![];
    for x in a {
        let s = x.as_str().ok_or("each pid is a string: a name like \"rpm\" or a PID like \"0C\"")?;
        let p = pid_arg(s).ok_or_else(|| format!("{s:?} isn't an OBD-II value the node knows ({})", PIDS.iter().map(|p| p.name).collect::<Vec<_>>().join(", ")))?;
        if !ok.contains(&p.code) { return Err(format!("{} isn't a value the adoption of {} allows", p.name, ext.id)); }
        if !out.contains(&p.code) { out.push(p.code); }
    }
    Ok(out)
}

/* ---------- what the adapter says ---------- */

/// One answer from the adapter as lines of hex (spaces removed), or why there's none.
#[derive(Debug, PartialEq)]
pub enum Answer { Lines(Vec<String>), NoData }

/// Cleans a raw answer (everything before the `>` prompt): drops the echo, `SEARCHING...`, `BUS INIT: ...OK`; turns
/// the adapter's error words into reasons.
pub fn answer(cmd: &str, raw: &str) -> Result<Answer, String> {
    let mut lines = vec![];
    for l in raw.split(['\r', '\n']) {
        let l = l.trim().trim_end_matches('>').trim();
        if l.is_empty() || l.eq_ignore_ascii_case(cmd) || l.starts_with("SEARCHING") || (l.starts_with("BUS INIT") && l.ends_with("OK")) { continue; }
        let u = l.to_ascii_uppercase();
        if u == "NO DATA" { return Ok(Answer::NoData); }
        if u == "?" { return Err(format!("the adapter didn't understand {cmd}")); }
        if u.contains("UNABLE TO CONNECT") { return Err("the adapter can't reach the car (is the ignition on?)".into()); }
        if u.contains("ERROR") || u == "STOPPED" || u.contains("BUFFER FULL") || u.contains("LV RESET") || u.contains("ACT ALERT") {
            return Err(format!("the adapter said {:?}", super::net::clean(l, 60)));
        }
        lines.push(l.replace(' ', ""));
    }
    Ok(Answer::Lines(lines))
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || s.is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) { return None; }
    Some((0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect())
}

/// The frames in an answer: one per line, and CAN multi-frame answers (ISO 15765-2) put back together. With headers
/// off an ELM327 prints those as a byte count (`014`) and then numbered lines (`0:…`, `1:…`).
pub fn frames(lines: &[String]) -> Vec<Vec<u8>> {
    let mut out = vec![];
    let mut i = 0;
    while i < lines.len() {
        let l = &lines[i];
        let is_len = l.len() == 3 && l.bytes().all(|b| b.is_ascii_hexdigit());
        if is_len && lines.get(i + 1).map_or(false, |n| n.starts_with("0:")) {
            let total = usize::from_str_radix(l, 16).unwrap_or(0);
            let mut data = vec![];
            i += 1;
            while i < lines.len() {
                let Some((n, rest)) = lines[i].split_once(':') else { break };
                if n.is_empty() || !n.bytes().all(|b| b.is_ascii_hexdigit()) { break; }
                data.extend(hex_bytes(rest).unwrap_or_default());
                i += 1;
            }
            data.truncate(total);
            out.push(data);
            continue;
        }
        if let Some(b) = hex_bytes(l) { out.push(b); }
        i += 1;
    }
    out
}

/// The data bytes of the first frame answering `mode` (`0x41` for mode 01) and `pid`.
pub fn data_for(frames: &[Vec<u8>], mode: u8, pid: u8) -> Option<Vec<u8>> {
    frames.iter().find(|f| f.len() >= 2 && f[0] == mode && f[1] == pid).map(|f| f[2..].to_vec())
}

/// Which mode 01 PIDs the car reports, from the answers to `0100`, `0120`, … (each a bitmask of the next 32 PIDs).
pub fn supported(base: u8, frames: &[Vec<u8>]) -> BTreeSet<u8> {
    let mut s = BTreeSet::new();
    for f in frames.iter().filter(|f| f.len() >= 6 && f[0] == 0x41 && f[1] == base) {
        for i in 0..32u8 { if f[2 + (i / 8) as usize] & (0x80 >> (i % 8)) != 0 { s.insert(base + i + 1); } }
    }
    s
}

/// A trouble code from its two bytes: `01 33` → `P0133`.
pub fn dtc(a: u8, b: u8) -> String {
    let letter = ['P', 'C', 'B', 'U'][(a >> 6) as usize];
    format!("{letter}{}{:X}{:X}{:X}", (a >> 4) & 0x03, a & 0x0F, b >> 4, b & 0x0F)
}

/// Codes from a mode 03 / 07 / 0A answer (`0x43`, `0x47`, `0x4A`). CAN answers start with a count, so their data has
/// an odd length; older protocols send pairs padded with `0000`.
pub fn dtcs(resp_mode: u8, frames: &[Vec<u8>]) -> Vec<String> {
    let mut out = vec![];
    for f in frames.iter().filter(|f| f.first() == Some(&resp_mode)) {
        let d = &f[1..];
        let (count, pairs) = if d.len() % 2 == 1 { (Some(d[0] as usize), &d[1..]) } else { (None, d) };
        for (n, p) in pairs.chunks_exact(2).enumerate() {
            if count.map_or(false, |c| n >= c) { break; }
            if p[0] == 0 && p[1] == 0 { continue; }
            let c = dtc(p[0], p[1]);
            if !out.contains(&c) { out.push(c); }
        }
    }
    out
}

/// The VIN from a mode 09 PID 02 answer: CAN sends one message (a count byte, then 17 characters); older protocols
/// send five numbered frames of four bytes.
pub fn vin(frames: &[Vec<u8>]) -> Option<String> {
    let mut parts: Vec<&Vec<u8>> = frames.iter().filter(|f| f.len() >= 3 && f[0] == 0x49 && f[1] == 0x02).collect();
    let bytes: Vec<u8> = if parts.iter().any(|f| f.len() > 7) {
        parts.iter().find(|f| f.len() > 7).map(|f| f[3..].to_vec())?
    } else {
        parts.sort_by_key(|f| f[2]);
        parts.iter().flat_map(|f| f[3..].to_vec()).collect()
    };
    let s: String = bytes.iter().filter(|b| b.is_ascii_alphanumeric()).map(|b| *b as char).collect();
    let v = s.get(s.len().saturating_sub(17)..)?.to_string();
    (v.len() == 17 && !v.contains(['I', 'O', 'Q'])).then_some(v)
}

pub fn protocol_name(dpn: &str) -> &'static str {
    match dpn.trim().trim_start_matches('A') {
        "1" => "SAE J1850 PWM", "2" => "SAE J1850 VPW", "3" => "ISO 9141-2", "4" => "ISO 14230-4 KWP (5 baud init)", "5" => "ISO 14230-4 KWP (fast init)",
        "6" => "ISO 15765-4 CAN (11 bit ID, 500 kbaud)", "7" => "ISO 15765-4 CAN (29 bit ID, 500 kbaud)", "8" => "ISO 15765-4 CAN (11 bit ID, 250 kbaud)",
        "9" => "ISO 15765-4 CAN (29 bit ID, 250 kbaud)", "A" => "SAE J1939 CAN", _ => "unknown",
    }
}

/// The standard (SAE J2012 generic) meaning of common codes. Codes not here get no meaning: the node never guesses,
/// and manufacturer codes (P1xxx, …) mean different things in different cars.
pub fn meaning(code: &str) -> Option<&'static str> {
    if let Some(n) = code.strip_prefix("P030").and_then(|d| d.parse::<u8>().ok()).filter(|n| (1..=8).contains(n)) {
        return Some(["", "Cylinder 1 misfire detected", "Cylinder 2 misfire detected", "Cylinder 3 misfire detected", "Cylinder 4 misfire detected",
            "Cylinder 5 misfire detected", "Cylinder 6 misfire detected", "Cylinder 7 misfire detected", "Cylinder 8 misfire detected"][n as usize]);
    }
    if let Some(n) = code.strip_prefix("P020").and_then(|d| d.parse::<u8>().ok()).filter(|n| (1..=8).contains(n)) {
        return Some(["", "Injector circuit malfunction, cylinder 1", "Injector circuit malfunction, cylinder 2", "Injector circuit malfunction, cylinder 3",
            "Injector circuit malfunction, cylinder 4", "Injector circuit malfunction, cylinder 5", "Injector circuit malfunction, cylinder 6",
            "Injector circuit malfunction, cylinder 7", "Injector circuit malfunction, cylinder 8"][n as usize]);
    }
    Some(match code {
        "P0010" => "Intake camshaft position actuator circuit (bank 1)",
        "P0011" => "Intake camshaft position timing over-advanced or system performance (bank 1)",
        "P0016" => "Crankshaft position / camshaft position correlation (bank 1, sensor A)",
        "P0087" => "Fuel rail / system pressure too low",
        "P0100" => "Mass or volume air flow circuit malfunction",
        "P0101" => "Mass or volume air flow circuit range/performance problem",
        "P0102" => "Mass or volume air flow circuit low input",
        "P0103" => "Mass or volume air flow circuit high input",
        "P0106" => "Manifold absolute pressure / barometric pressure circuit range/performance problem",
        "P0107" => "Manifold absolute pressure / barometric pressure circuit low input",
        "P0108" => "Manifold absolute pressure / barometric pressure circuit high input",
        "P0110" => "Intake air temperature circuit malfunction",
        "P0112" => "Intake air temperature circuit low input",
        "P0113" => "Intake air temperature circuit high input",
        "P0115" => "Engine coolant temperature circuit malfunction",
        "P0116" => "Engine coolant temperature circuit range/performance problem",
        "P0117" => "Engine coolant temperature circuit low input",
        "P0118" => "Engine coolant temperature circuit high input",
        "P0120" => "Throttle / pedal position sensor A circuit malfunction",
        "P0121" => "Throttle / pedal position sensor A circuit range/performance problem",
        "P0122" => "Throttle / pedal position sensor A circuit low input",
        "P0123" => "Throttle / pedal position sensor A circuit high input",
        "P0125" => "Insufficient coolant temperature for closed loop fuel control",
        "P0128" => "Coolant thermostat (coolant temperature below thermostat regulating temperature)",
        "P0130" => "O2 sensor circuit malfunction (bank 1, sensor 1)",
        "P0131" => "O2 sensor circuit low voltage (bank 1, sensor 1)",
        "P0132" => "O2 sensor circuit high voltage (bank 1, sensor 1)",
        "P0133" => "O2 sensor circuit slow response (bank 1, sensor 1)",
        "P0134" => "O2 sensor circuit no activity detected (bank 1, sensor 1)",
        "P0135" => "O2 sensor heater circuit malfunction (bank 1, sensor 1)",
        "P0136" => "O2 sensor circuit malfunction (bank 1, sensor 2)",
        "P0137" => "O2 sensor circuit low voltage (bank 1, sensor 2)",
        "P0138" => "O2 sensor circuit high voltage (bank 1, sensor 2)",
        "P0140" => "O2 sensor circuit no activity detected (bank 1, sensor 2)",
        "P0141" => "O2 sensor heater circuit malfunction (bank 1, sensor 2)",
        "P0150" => "O2 sensor circuit malfunction (bank 2, sensor 1)",
        "P0155" => "O2 sensor heater circuit malfunction (bank 2, sensor 1)",
        "P0171" => "System too lean (bank 1)",
        "P0172" => "System too rich (bank 1)",
        "P0174" => "System too lean (bank 2)",
        "P0175" => "System too rich (bank 2)",
        "P0191" => "Fuel rail pressure sensor circuit range/performance",
        "P0200" => "Injector circuit malfunction",
        "P0217" => "Engine over temperature condition",
        "P0230" => "Fuel pump primary circuit malfunction",
        "P0234" => "Turbocharger / supercharger overboost condition",
        "P0299" => "Turbocharger / supercharger underboost",
        "P0300" => "Random / multiple cylinder misfire detected",
        "P0325" => "Knock sensor 1 circuit malfunction (bank 1 or single sensor)",
        "P0335" => "Crankshaft position sensor A circuit malfunction",
        "P0336" => "Crankshaft position sensor A circuit range/performance",
        "P0340" => "Camshaft position sensor circuit malfunction",
        "P0380" => "Glow plug / heater circuit A malfunction",
        "P0400" => "Exhaust gas recirculation flow malfunction",
        "P0401" => "Exhaust gas recirculation flow insufficient detected",
        "P0402" => "Exhaust gas recirculation flow excessive detected",
        "P0403" => "Exhaust gas recirculation circuit malfunction",
        "P0411" => "Secondary air injection system incorrect flow detected",
        "P0420" => "Catalyst system efficiency below threshold (bank 1)",
        "P0430" => "Catalyst system efficiency below threshold (bank 2)",
        "P0440" => "Evaporative emission control system malfunction",
        "P0441" => "Evaporative emission control system incorrect purge flow",
        "P0442" => "Evaporative emission control system leak detected (small leak)",
        "P0443" => "Evaporative emission control system purge control valve circuit malfunction",
        "P0446" => "Evaporative emission control system vent control circuit malfunction",
        "P0455" => "Evaporative emission control system leak detected (gross leak)",
        "P0456" => "Evaporative emission control system leak detected (very small leak)",
        "P0500" => "Vehicle speed sensor malfunction",
        "P0505" => "Idle control system malfunction",
        "P0506" => "Idle control system RPM lower than expected",
        "P0507" => "Idle control system RPM higher than expected",
        "P0560" => "System voltage malfunction",
        "P0562" => "System voltage low",
        "P0563" => "System voltage high",
        "P0600" => "Serial communication link malfunction",
        "P0601" => "Internal control module memory check sum error",
        "P0700" => "Transmission control system malfunction",
        "P0705" => "Transmission range sensor circuit malfunction (PRNDL input)",
        "P0715" => "Input / turbine speed sensor circuit malfunction",
        "P0720" => "Output speed sensor circuit malfunction",
        "P0740" => "Torque converter clutch circuit malfunction",
        "P0750" => "Shift solenoid A malfunction",
        "U0100" => "Lost communication with ECM/PCM A",
        _ => return None,
    })
}

/* ---------- talking to the adapter ---------- */

/// One command out, everything up to the `>` prompt back.
pub trait Io: Send {
    fn exchange<'a>(&'a mut self, cmd: &'a str, timeout: Duration) -> BoxFut<'a, Result<String, String>>;
}

/// Any byte stream: TCP (Wi-Fi adapters), and the simulators in tests.
pub struct StreamIo<S>(pub S);
impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for StreamIo<S> {
    fn exchange<'a>(&'a mut self, cmd: &'a str, timeout: Duration) -> BoxFut<'a, Result<String, String>> {
        Box::pin(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            self.0.write_all(format!("{cmd}\r").as_bytes()).await.map_err(|e| format!("the adapter: {e}"))?;
            let mut out = vec![];
            let read = async {
                let mut buf = [0u8; 512];
                loop {
                    let n = self.0.read(&mut buf).await.map_err(|e| format!("the adapter: {e}"))?;
                    if n == 0 { return Err("the adapter closed the connection".to_string()); }
                    out.extend_from_slice(&buf[..n]);
                    if out.contains(&b'>') || out.len() > 16 * 1024 { return Ok(()); }
                }
            };
            tokio::time::timeout(timeout, read).await.map_err(|_| format!("the adapter didn't answer {cmd} within {} s", timeout.as_secs()))??;
            Ok(String::from_utf8_lossy(&out).to_string())
        })
    }
}

/// A serial port (USB adapters, and Bluetooth Classic ones once paired). Blocking reads run on a blocking thread.
pub struct SerialIo { port: Option<Box<dyn serialport::SerialPort>> }
impl SerialIo {
    /// `/dev/cu.OBDII`, `/dev/ttyUSB0` or `COM5`, optionally `@115200` (38400 by default, the ELM327 default).
    pub fn open(address: &str) -> Result<SerialIo, String> {
        let (path, baud) = match address.rsplit_once('@') { Some((p, b)) => (p, b.parse::<u32>().map_err(|_| "the baud rate isn't a number")?), None => (address, 38_400) };
        let ok = path.starts_with("/dev/cu.") || path.starts_with("/dev/tty") || (path.len() <= 6 && path.to_ascii_uppercase().starts_with("COM") && path[3..].bytes().all(|b| b.is_ascii_digit()) && path.len() > 3);
        if !ok || path.contains("..") { return Err(format!("{path:?} isn't a serial port")); }
        let port = serialport::new(path, baud).timeout(Duration::from_millis(200)).open().map_err(|e| format!("can't open {path}: {e}"))?;
        Ok(SerialIo { port: Some(port) })
    }
}
impl Io for SerialIo {
    fn exchange<'a>(&'a mut self, cmd: &'a str, timeout: Duration) -> BoxFut<'a, Result<String, String>> {
        Box::pin(async move {
            let mut port = self.port.take().ok_or("the serial port is gone")?;
            let cmd = cmd.to_string();
            let (port, r) = tokio::task::spawn_blocking(move || {
                let r = (|| {
                    port.write_all(format!("{cmd}\r").as_bytes()).map_err(|e| format!("the adapter: {e}"))?;
                    let end = std::time::Instant::now() + timeout;
                    let mut out = vec![];
                    let mut buf = [0u8; 256];
                    while std::time::Instant::now() < end {
                        match port.read(&mut buf) {
                            Ok(n) => { out.extend_from_slice(&buf[..n]); if out.contains(&b'>') { return Ok(String::from_utf8_lossy(&out).to_string()); } }
                            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                            Err(e) => return Err(format!("the adapter: {e}")),
                        }
                    }
                    Err(format!("the adapter didn't answer {cmd} within {} s", timeout.as_secs()))
                })();
                (port, r)
            }).await.map_err(|e| e.to_string())?;
            self.port = Some(port);
            r
        })
    }
}

#[cfg(any(target_os = "macos", windows))]
pub mod ble_io {
    //! BLE adapters: most cheap ones are a serial line over GATT: write commands to one characteristic, answers come
    //! as notifications on another. Known pairs: FFF0 (notify FFF1, write FFF2), FFE0 (FFE1 both), 18F0 (notify
    //! 2AF0, write 2AF1).
    use super::{BoxFut, Duration, External, Io};
    use btleplug::api::{Central, CharPropFlags, Characteristic, Manager as _, Peripheral as _, ScanFilter, ValueNotification, WriteType};
    use btleplug::platform::{Manager, Peripheral};
    use futures_util::{Stream, StreamExt};
    use std::pin::Pin;

    const PAIRS: &[(&str, &str, &str)] = &[("fff0", "fff1", "fff2"), ("ffe0", "ffe1", "ffe1"), ("18f0", "2af0", "2af1")];
    fn short(u: &uuid::Uuid) -> String { u.to_string()[4..8].to_string() }

    pub struct BleIo { p: Peripheral, notify: Characteristic, write: Characteristic, stream: Pin<Box<dyn Stream<Item = ValueNotification> + Send>> }

    impl BleIo {
        pub async fn open(e: &External) -> Result<BleIo, String> {
            let m = Manager::new().await.map_err(|e| format!("Bluetooth: {e}"))?;
            let a = m.adapters().await.map_err(|e| format!("Bluetooth: {e}"))?.into_iter().next().ok_or("this computer has no Bluetooth adapter")?;
            a.start_scan(ScanFilter::default()).await.map_err(|e| format!("Bluetooth: {e}"))?;
            let mut found = None;
            for _ in 0..16 {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if let Some(p) = a.peripherals().await.map_err(|e| e.to_string())?.into_iter().find(|p| p.id().to_string().eq_ignore_ascii_case(e.address.trim()) || p.address().to_string().eq_ignore_ascii_case(e.address.trim())) { found = Some(p); break; }
            }
            let _ = a.stop_scan().await;
            let p = found.ok_or_else(|| format!("the adapter {} isn't in range (looked for 8 s)", e.id))?;
            if !p.is_connected().await.unwrap_or(false) { tokio::time::timeout(Duration::from_secs(10), p.connect()).await.map_err(|_| "the adapter didn't accept a connection".to_string())?.map_err(|e| e.to_string())?; }
            tokio::time::timeout(Duration::from_secs(10), p.discover_services()).await.map_err(|_| "discovering the adapter's services timed out".to_string())?.map_err(|e| e.to_string())?;
            let chars = p.characteristics();
            let find = |svc: &str, c: &str| chars.iter().find(|x| short(&x.service_uuid) == svc && short(&x.uuid) == c).cloned();
            let (notify, write) = PAIRS.iter().find_map(|(s, n, w)| Some((find(s, n)?, find(s, w)?)))
                .ok_or("the adapter has none of the known OBD serial services (FFF0, FFE0, 18F0)")?;
            if !notify.properties.intersects(CharPropFlags::NOTIFY | CharPropFlags::INDICATE) { return Err("the adapter's answer characteristic can't notify".into()); }
            let stream = p.notifications().await.map_err(|e| e.to_string())?;
            p.subscribe(&notify).await.map_err(|e| e.to_string())?;
            Ok(BleIo { p, notify, write, stream })
        }
    }

    /// The adapter is let go when the action ends.
    impl Drop for BleIo {
        fn drop(&mut self) {
            let (p, n) = (self.p.clone(), self.notify.clone());
            tokio::spawn(async move { let _ = p.unsubscribe(&n).await; let _ = p.disconnect().await; });
        }
    }

    impl Io for BleIo {
        fn exchange<'a>(&'a mut self, cmd: &'a str, timeout: Duration) -> BoxFut<'a, Result<String, String>> {
            Box::pin(async move {
                let wt = if self.write.properties.contains(CharPropFlags::WRITE_WITHOUT_RESPONSE) { WriteType::WithoutResponse } else { WriteType::WithResponse };
                for chunk in format!("{cmd}\r").as_bytes().chunks(20) { self.p.write(&self.write, chunk, wt).await.map_err(|e| format!("the adapter: {e}"))?; }
                let mut out = vec![];
                let end = tokio::time::Instant::now() + timeout;
                while !out.contains(&b'>') && out.len() < 16 * 1024 {
                    match tokio::time::timeout_at(end, self.stream.next()).await {
                        Ok(Some(n)) if n.uuid == self.notify.uuid => out.extend_from_slice(&n.value),
                        Ok(Some(_)) => {}
                        Ok(None) => return Err("the adapter disconnected".into()),
                        Err(_) => return Err(format!("the adapter didn't answer {cmd} within {} s", timeout.as_secs())),
                    }
                }
                Ok(String::from_utf8_lossy(&out).to_string())
            })
        }
    }
}

/// A set-up adapter, talking to one car.
pub struct Elm { io: Box<dyn Io>, pub adapter: String, pub protocol: String }

const SHORT: Duration = Duration::from_secs(3);
/// The first request after `ATSP0` makes the adapter try each protocol in turn.
const SEARCH: Duration = Duration::from_secs(15);

impl Elm {
    /// Opens the adopted adapter by its transport.
    pub async fn open(e: &External) -> Result<Elm, String> {
        let t = e.transport.as_deref().unwrap_or(if e.address.starts_with("/dev/") || e.address.to_ascii_uppercase().starts_with("COM") { "usb" } else { "wifi" });
        let io: Box<dyn Io> = match t {
            "wifi" => {
                let a = super::net::parse_addr(&e.address, &["tcp"], "tcp", |_| 35000)?;
                let addr = super::net::resolve(&a.host, a.port).await?;
                let s = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr)).await
                    .map_err(|_| format!("the adapter at {addr} didn't answer (is this computer on its Wi-Fi?)"))?.map_err(|err| format!("can't reach the adapter at {addr}: {err}"))?;
                let _ = s.set_nodelay(true);
                Box::new(StreamIo(s))
            }
            "usb" | "classic" => { let a = e.address.clone(); Box::new(tokio::task::spawn_blocking(move || SerialIo::open(&a)).await.map_err(|e| e.to_string())??) }
            #[cfg(any(target_os = "macos", windows))]
            "ble" => Box::new(ble_io::BleIo::open(e).await?),
            other => return Err(format!("{other} isn't an OBD-II adapter transport this computer can use")),
        };
        Elm::init(io).await
    }

    /// The fixed set-up. Nothing an agent sends ever reaches the adapter as a command.
    pub async fn init(mut io: Box<dyn Io>) -> Result<Elm, String> {
        let z = io.exchange("ATZ", Duration::from_secs(5)).await?;
        let adapter = z.split(['\r', '\n']).map(|l| l.trim().trim_end_matches('>').trim()).find(|l| l.to_ascii_uppercase().contains("ELM327"))
            .map(|l| super::net::clean(l, 40)).ok_or("the device didn't say it's an ELM327 adapter")?;
        for c in ["ATE0", "ATL0", "ATS0", "ATH0", "ATSP0"] {
            let r = io.exchange(c, SHORT).await?;
            if !r.to_ascii_uppercase().contains("OK") { return Err(format!("the adapter refused {c}")); }
        }
        let mut elm = Elm { io, adapter, protocol: String::new() };
        // Wakes the car's computer and settles the protocol.
        match elm.raw("0100", SEARCH).await? {
            Answer::NoData => return Err("the car didn't answer (is the ignition on?)".into()),
            Answer::Lines(_) => {}
        }
        let dpn = elm.io.exchange("ATDPN", SHORT).await.unwrap_or_default();
        let dpn = dpn.split(['\r', '\n']).map(|l| l.trim().trim_end_matches('>').trim()).find(|l| !l.is_empty() && l.len() <= 3).unwrap_or("").to_string();
        elm.protocol = protocol_name(&dpn).to_string();
        Ok(elm)
    }

    async fn raw(&mut self, cmd: &str, timeout: Duration) -> Result<Answer, String> { answer(cmd, &self.io.exchange(cmd, timeout).await?) }
    async fn frames(&mut self, cmd: &str) -> Result<Vec<Vec<u8>>, String> {
        Ok(match self.raw(cmd, SHORT).await? { Answer::NoData => vec![], Answer::Lines(l) => frames(&l) })
    }

    /// Mode 01 values, by PID. A PID the car doesn't report is None.
    pub async fn values(&mut self, pids: &[u8]) -> Result<Vec<(u8, Option<f64>)>, String> {
        let mut out = vec![];
        for &p in pids {
            let f = self.frames(&format!("01{p:02X}")).await?;
            out.push((p, data_for(&f, 0x41, p).and_then(|d| pid(p).and_then(|x| decode(x, &d)))));
        }
        Ok(out)
    }
    pub async fn supported(&mut self) -> Result<BTreeSet<u8>, String> {
        let mut all = BTreeSet::new();
        let mut base = 0u8;
        loop {
            let s = supported(base, &self.frames(&format!("01{base:02X}")).await?);
            let more = s.contains(&(base + 0x20));
            all.extend(s);
            if !more || base >= 0xA0 { break; }
            base += 0x20;
        }
        Ok(all)
    }
    pub async fn vin(&mut self) -> Result<Option<String>, String> { Ok(vin(&self.frames("0902").await?)) }
    pub async fn codes(&mut self, mode: u8) -> Result<Vec<String>, String> { Ok(dtcs(mode + 0x40, &self.frames(&format!("{mode:02X}")).await?)) }
    /// Mode 02, frame 0: the code that stored the freeze frame and the values in it (only allowed PIDs).
    pub async fn freeze_frame(&mut self, allowed: &BTreeSet<u8>) -> Result<Option<Value>, String> {
        let f = self.frames("020200").await?;
        let Some(d) = data_for(&f, 0x42, 0x02).filter(|d| d.len() >= 3 && (d[1] != 0 || d[2] != 0)) else { return Ok(None) };
        let mut values = Map::new();
        for p in [0x04, 0x05, 0x0B, 0x0C, 0x0D, 0x0F, 0x11, 0x06, 0x07].into_iter().filter(|p| allowed.contains(p)) {
            let fr = self.frames(&format!("02{p:02X}00")).await?;
            if let Some(v) = data_for(&fr, 0x42, p).filter(|d| d.len() > 1).and_then(|d| pid(p).and_then(|x| decode(x, &d[1..]))) {
                let x = pid(p).unwrap();
                values.insert(x.name.into(), json!({ "value": v, "unit": x.unit }));
            }
        }
        Ok(Some(json!({ "code": dtc(d[1], d[2]), "values": values })))
    }
    /// The car's speed now. None if the car doesn't say.
    pub async fn speed(&mut self) -> Result<Option<f64>, String> { Ok(self.values(&[SPEED]).await?[0].1) }
    /// Mode 04. The caller has checked the speed just before.
    async fn clear(&mut self) -> Result<(), String> {
        let f = self.frames("04").await?;
        if f.iter().any(|x| x.first() == Some(&0x44)) { Ok(()) } else { Err("the car didn't confirm the codes were cleared".into()) }
    }
}

fn values_json(v: &[(u8, Option<f64>)]) -> Value {
    let mut m = Map::new();
    for (p, x) in v { let d = pid(*p).unwrap(); m.insert(d.name.into(), json!({ "value": x, "unit": d.unit })); }
    Value::Object(m)
}

/* ---------- the tools ---------- */

pub async fn info(mut elm: Elm, e: &External) -> Result<Value, String> {
    let ok = allowed(e)?;
    let vin = elm.vin().await?;
    let sup = elm.supported().await?;
    let status = elm.frames("0101").await?;
    let mil = data_for(&status, 0x41, 0x01).filter(|d| !d.is_empty()).map(|d| json!({ "check_engine_light": d[0] & 0x80 != 0, "codes_stored": d[0] & 0x7F }));
    let pids: Vec<&str> = PIDS.iter().filter(|p| sup.contains(&p.code) && ok.contains(&p.code)).map(|p| p.name).collect();
    Ok(json!({ "vin": vin, "protocol": elm.protocol, "adapter": elm.adapter, "pids": pids, "status": mil }))
}

pub async fn read(mut elm: Elm, pids: &[u8]) -> Result<Value, String> {
    let v = elm.values(pids).await?;
    Ok(json!({ "values": values_json(&v), "at": super::super::now() }))
}

pub async fn codes(mut elm: Elm, e: &External, which: &[String]) -> Result<Value, String> {
    let mut list = vec![];
    for w in which {
        let mode = match w.as_str() { "stored" => 0x03, "pending" => 0x07, "permanent" => 0x0A, _ => continue };
        for c in elm.codes(mode).await? { list.push(json!({ "code": c, "meaning": meaning(&c), "status": w })); }
    }
    let ff = if which.iter().any(|w| w == "stored") { elm.freeze_frame(&allowed(e).unwrap_or_default()).await? } else { None };
    let mut out = json!({ "codes": list });
    if let Some(f) = ff { out["freeze_frame"] = f; }
    Ok(out)
}

pub async fn monitor(mut elm: Elm, pids: &[u8], every_s: u32, seconds: u32) -> Result<Value, String> {
    let start = tokio::time::Instant::now();
    let end = start + Duration::from_secs(seconds as u64);
    let mut readings = vec![];
    let mut next = start;
    while tokio::time::Instant::now() < end && readings.len() < 300 {
        let v = elm.values(pids).await?;
        readings.push(json!({ "values": values_json(&v), "at": super::super::now() }));
        next += Duration::from_secs(every_s as u64);
        if next >= end { break; }
        tokio::time::sleep_until(next).await;
    }
    Ok(json!({ "readings": readings }))
}

/// Refused unless the car says it's standing still, read just before the request. Not knowing the speed is a refusal
/// too.
pub async fn standing_still(elm: &mut Elm) -> Result<(), String> {
    match elm.speed().await? {
        Some(s) if s > 0.0 => Err(format!("the car is moving ({s} km/h): fault codes are only cleared while it stands still")),
        Some(_) => Ok(()),
        None => Err("the car didn't report its speed, so the codes weren't cleared".into()),
    }
}

pub async fn clear_codes(mut elm: Elm) -> Result<Value, String> {
    standing_still(&mut elm).await?;
    elm.clear().await?;
    Ok(json!({ "done": true }))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    use std::sync::Arc;

    fn lines(s: &str) -> Vec<String> { match answer("X", s).unwrap() { Answer::Lines(l) => l, _ => panic!() } }

    #[test]
    fn formulas() {
        let d = |code: u8, b: &[u8]| decode(pid(code).unwrap(), b).unwrap();
        assert_eq!(d(0x0C, &[0x1A, 0xF8]), 1726.0); // (26·256 + 248) / 4
        assert_eq!(d(0x0D, &[0x32]), 50.0);
        assert_eq!(d(0x05, &[0x7B]), 83.0); // 123 − 40
        assert_eq!(d(0x0F, &[0x3C]), 20.0);
        assert_eq!(d(0x10, &[0x01, 0x90]), 4.0); // 400 / 100 g/s
        assert_eq!(d(0x11, &[0xFF]), 100.0);
        assert_eq!(d(0x04, &[0x80]), 50.2);
        assert_eq!(d(0x2F, &[0x40]), 25.1);
        assert_eq!(d(0x42, &[0x36, 0xB0]), 14.0); // 14 000 mV
        assert_eq!(d(0x1F, &[0x01, 0x2C]), 300.0);
        assert!(decode(pid(0x0C).unwrap(), &[0x1A]).is_none());
        assert_eq!(pid_arg("rpm").unwrap().code, 0x0C);
        assert_eq!(pid_arg("0x0d").unwrap().code, 0x0D);
        assert_eq!(pid_arg("010C").unwrap().code, 0x0C);
        assert!(pid_arg("ATZ").is_none() && pid_arg("0C;ATZ").is_none());
    }

    #[test]
    fn real_adapter_answers() {
        // As an ELM327 v1.5 prints them with ATS0/ATH0, after a protocol search.
        assert_eq!(frames(&lines("SEARCHING...\r410C1AF8\r\r>")), vec![vec![0x41, 0x0C, 0x1A, 0xF8]]);
        // Spaces left on by a clone that ignores ATS0.
        assert_eq!(frames(&lines("41 0D 32 \r\r>")), vec![vec![0x41, 0x0D, 0x32]]);
        assert_eq!(answer("010C", "NO DATA\r\r>").unwrap(), Answer::NoData);
        assert!(answer("010C", "UNABLE TO CONNECT\r\r>").unwrap_err().contains("ignition"));
        assert!(answer("010C", "CAN ERROR\r\r>").is_err());
        assert!(answer("01ZZ", "?\r\r>").is_err());
        // Two ECUs answering 0100 (engine and gearbox): both masks count.
        let f = frames(&lines("4100BE3FA813\r410098180001\r\r>"));
        let s = supported(0x00, &f);
        assert!(s.contains(&0x0C) && s.contains(&0x0D) && s.contains(&0x05) && s.contains(&0x20) && !s.contains(&0x02));
    }

    #[test]
    fn vin_over_can_and_older_protocols() {
        // CAN, multi-frame (ISO 15765-2): 20 bytes in three numbered lines.
        let f = frames(&lines("014\r0:490201314434\r1:47503030523535\r2:42313233343536\r\r>"));
        assert_eq!(vin(&f).as_deref(), Some("1D4GP00R55B123456"));
        // ISO 9141-2: five frames of four bytes, numbered 1 to 5 (a stray space, as some clones print).
        let f = frames(&lines("49020100000031\r49020244344750\r490203303052 35\r49020435423132\r49020533343536\r\r>"));
        assert_eq!(f.len(), 5);
        assert_eq!(vin(&f).as_deref(), Some("1D4GP00R55B123456"));
        // A VIN with I, O or Q isn't one.
        assert_eq!(vin(&frames(&lines("014\r0:4902014F4434\r1:47503030523535\r2:42313233343536\r>"))), None);
    }

    #[test]
    fn trouble_codes() {
        assert_eq!(dtc(0x01, 0x33), "P0133");
        assert_eq!(dtc(0x41, 0x23), "C0123");
        assert_eq!(dtc(0x93, 0x00), "B1300");
        assert_eq!(dtc(0xC1, 0x00), "U0100");
        // CAN: a count, then pairs.
        assert_eq!(dtcs(0x43, &frames(&lines("430201330420\r>"))), vec!["P0133", "P0420"]);
        assert_eq!(dtcs(0x43, &frames(&lines("4300\r>"))), Vec::<String>::new());
        // Older protocols: three pairs a line, padded.
        assert_eq!(dtcs(0x43, &frames(&lines("43030000000000\r>"))), vec!["P0300"]);
        // Many codes over CAN arrive as a multi-frame answer.
        assert_eq!(dtcs(0x43, &frames(&lines("00A\r0:430401330301\r1:02010171000000\r>"))), vec!["P0133", "P0301", "P0201", "P0171"]);
        assert_eq!(meaning("P0420"), Some("Catalyst system efficiency below threshold (bank 1)"));
        assert_eq!(meaning("P0304"), Some("Cylinder 4 misfire detected"));
        assert_eq!(meaning("P1234"), None); // manufacturer-specific: never guessed
        assert_eq!(meaning("P0309"), None);
    }

    #[test]
    fn only_allowed_pids() {
        let mut e = External { id: "ext_car".into(), kind: "obd".into(), address: "192.168.0.10:35000".into(), ..Default::default() };
        assert!(pids_arg(&json!(["rpm"]), &e, 10).unwrap_err().contains("allow.pids"));
        e.allow.pids = json!(["speed", "0C"]);
        assert_eq!(pids_arg(&json!(["rpm", "0D", "speed"]), &e, 10).unwrap(), vec![0x0C, 0x0D]);
        assert!(pids_arg(&json!(["coolant_temp"]), &e, 10).unwrap_err().contains("allows"));
        assert!(pids_arg(&json!(["ATZ"]), &e, 10).is_err());
        assert!(pids_arg(&json!(["rpm", "speed"]), &e, 1).is_err());
        e.allow.pids = json!("standard");
        assert_eq!(pids_arg(&json!(["coolant_temp"]), &e, 10).unwrap(), vec![0x05]);
        e.allow.pids = json!(["warp_drive"]);
        assert!(allowed(&e).is_err());
    }

    /* ---------- an ELM327 simulator, over TCP ---------- */

    /// A car behind an ELM327 v1.5 on CAN 11/500: two stored codes (P0133, P0420), one pending (P0171), a freeze
    /// frame, a VIN over three CAN frames. `speed` is what PID 0D reads; clearing empties the codes.
    pub struct Car { pub speed: AtomicU8, pub cleared: AtomicBool, pub commands: std::sync::Mutex<Vec<String>> }
    impl Car { pub fn new(speed: u8) -> Arc<Car> { Arc::new(Car { speed: AtomicU8::new(speed), cleared: AtomicBool::new(false), commands: Default::default() }) } }

    fn reply(car: &Car, cmd: &str, echo: &mut bool, searched: &mut bool) -> String {
        let c = cmd.to_ascii_uppercase().replace(' ', "");
        let body = match c.as_str() {
            "ATZ" => { *echo = true; "\r\rELM327 v1.5".to_string() }
            "ATE0" => { *echo = false; "OK".into() }
            "ATL0" | "ATS0" | "ATH0" | "ATSP0" => "OK".into(),
            "ATDPN" => "A6".into(),
            "0100" => { let s = if *searched { "" } else { "SEARCHING...\r" }; *searched = true; format!("{s}4100BE3FA813") }
            "0101" => if car.cleared.load(Ordering::SeqCst) { "410100076100".into() } else { "410182076100".into() },
            "0120" => "4120A007B011".into(),
            "0140" => "4140FED00400".into(),
            "010C" => "410C1AF8".into(),
            "010D" => format!("410D{:02X}", car.speed.load(Ordering::SeqCst)),
            "0105" => "41057B".into(),
            "012F" => "412F40".into(),
            "0142" => "414236B0".into(),
            "015C" => "NO DATA".into(),
            "0902" => "014\r0:490201314434\r1:47503030523535\r2:42313233343536".into(),
            "03" => if car.cleared.load(Ordering::SeqCst) { "4300".into() } else { "430201330420".into() },
            "07" => if car.cleared.load(Ordering::SeqCst) { "4700".into() } else { "47010171".into() },
            "0A" => "4A00".into(),
            "020200" => if car.cleared.load(Ordering::SeqCst) { "4202000000".into() } else { "4202000133".into() },
            "020C00" => "420C001AF8".into(),
            "020D00" => "420D0000".into(),
            "020500" => "4205007B".into(),
            "04" => { car.cleared.store(true, Ordering::SeqCst); "44".into() }
            _ if c.starts_with("01") || c.starts_with("02") => "NO DATA".into(),
            _ => "?".into(),
        };
        format!("{}{body}\r\r>", if *echo { format!("{cmd}\r") } else { String::new() })
    }

    /// Serves one connection at a time on a local port; returns `127.0.0.1:port`.
    pub async fn simulator(car: Arc<Car>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { return };
                let car = car.clone();
                tokio::spawn(async move {
                    let (mut echo, mut searched, mut buf) = (true, false, String::new());
                    let mut b = [0u8; 256];
                    while let Ok(n) = s.read(&mut b).await {
                        if n == 0 { return; }
                        buf.push_str(&String::from_utf8_lossy(&b[..n]));
                        while let Some(i) = buf.find('\r') {
                            let cmd: String = buf.drain(..=i).collect();
                            let cmd = cmd.trim().to_string();
                            car.commands.lock().unwrap().push(cmd.clone());
                            let r = reply(&car, &cmd, &mut echo, &mut searched);
                            if s.write_all(r.as_bytes()).await.is_err() { return; }
                        }
                    }
                });
            }
        });
        addr
    }

    pub fn adapter(addr: &str, pids: Value) -> External {
        External { id: "ext_car".into(), name: "Car".into(), kind: "obd".into(), address: addr.into(), transport: Some("wifi".into()), allow: crate::devices::envelope::Allow { pids, ..Default::default() }, ..Default::default() }
    }

    #[tokio::test]
    async fn a_whole_session_with_the_simulator() {
        let car = Car::new(0);
        let e = adapter(&simulator(car.clone()).await, json!(["rpm", "speed", "coolant_temp", "fuel_level", "module_voltage", "oil_temp"]));
        let i = info(Elm::open(&e).await.unwrap(), &e).await.unwrap();
        assert_eq!(i["vin"], "1D4GP00R55B123456");
        assert_eq!(i["protocol"], "ISO 15765-4 CAN (11 bit ID, 500 kbaud)");
        assert_eq!(i["adapter"], "ELM327 v1.5");
        assert_eq!(i["status"], json!({ "check_engine_light": true, "codes_stored": 2 }));
        assert!(i["pids"].as_array().unwrap().contains(&json!("rpm")));
        let r = read(Elm::open(&e).await.unwrap(), &[0x0C, 0x0D, 0x05, 0x5C]).await.unwrap();
        assert_eq!(r["values"]["rpm"], json!({ "value": 1726.0, "unit": "rpm" }));
        assert_eq!(r["values"]["coolant_temp"]["value"], 83.0);
        assert_eq!(r["values"]["oil_temp"]["value"], Value::Null); // NO DATA: this car doesn't say
        let c = codes(Elm::open(&e).await.unwrap(), &e, &["stored".into(), "pending".into(), "permanent".into()]).await.unwrap();
        assert_eq!(c["codes"], json!([
            { "code": "P0133", "meaning": "O2 sensor circuit slow response (bank 1, sensor 1)", "status": "stored" },
            { "code": "P0420", "meaning": "Catalyst system efficiency below threshold (bank 1)", "status": "stored" },
            { "code": "P0171", "meaning": "System too lean (bank 1)", "status": "pending" }]));
        assert_eq!(c["freeze_frame"]["code"], "P0133");
        assert_eq!(c["freeze_frame"]["values"]["rpm"]["value"], 1726.0);
        assert!(c["freeze_frame"]["values"].get("engine_load").is_none()); // not allowed by the adoption
        let m = monitor(Elm::open(&e).await.unwrap(), &[0x0C, 0x0D], 1, 2).await.unwrap();
        assert_eq!(m["readings"].as_array().unwrap().len(), 2);
        // Only the fixed set-up and typed requests ever reached the adapter.
        let sent = car.commands.lock().unwrap().clone();
        assert!(sent.iter().all(|c| c.starts_with("AT") && ["ATZ", "ATE0", "ATL0", "ATS0", "ATH0", "ATSP0", "ATDPN"].contains(&c.as_str()) || c.bytes().all(|b| b.is_ascii_hexdigit())), "{sent:?}");
    }

    /// Against the independent `ELM327-emulator` (Python, `uv run --with ELM327-emulator elm -n 35001 -s car`):
    /// `ELM327_EMULATOR=127.0.0.1:35001 cargo test emulator -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "needs ELM327-emulator running; set ELM327_EMULATOR=host:port"]
    async fn against_the_elm327_emulator() {
        let addr = std::env::var("ELM327_EMULATOR").expect("ELM327_EMULATOR=host:port");
        let e = adapter(&addr, json!("standard"));
        let i = info(Elm::open(&e).await.unwrap(), &e).await.unwrap();
        eprintln!("obd_info: {i}");
        assert_eq!(i["vin"].as_str().map(|v| v.len()), Some(17));
        assert!(i["protocol"].as_str().unwrap().contains("CAN"));
        let r = read(Elm::open(&e).await.unwrap(), &[0x0C, 0x0D, 0x05, 0x0F, 0x10, 0x11, 0x04, 0x2F, 0x42, 0x1F]).await.unwrap();
        eprintln!("obd_read: {r}");
        assert!(r["values"]["rpm"]["value"].is_number() && r["values"]["coolant_temp"]["value"].is_number());
        let c = codes(Elm::open(&e).await.unwrap(), &e, &["stored".into(), "pending".into(), "permanent".into()]).await.unwrap();
        eprintln!("obd_codes: {c}");
        let m = monitor(Elm::open(&e).await.unwrap(), &[0x0C, 0x0D], 1, 3).await.unwrap();
        eprintln!("obd_monitor: {m}");
        let mut elm = Elm::open(&e).await.unwrap();
        eprintln!("clearing codes now: {:?}", standing_still(&mut elm).await.map(|_| "allowed (standing still)"));
    }

    #[tokio::test]
    async fn codes_are_cleared_only_standing_still() {
        let car = Car::new(37);
        let e = adapter(&simulator(car.clone()).await, json!("standard"));
        let err = clear_codes(Elm::open(&e).await.unwrap()).await.unwrap_err();
        assert!(err.contains("moving (37 km/h)"), "{err}");
        assert!(!car.cleared.load(Ordering::SeqCst));
        assert!(!car.commands.lock().unwrap().iter().any(|c| c == "04"));
        car.speed.store(0, Ordering::SeqCst);
        assert_eq!(clear_codes(Elm::open(&e).await.unwrap()).await.unwrap(), json!({ "done": true }));
        assert!(car.cleared.load(Ordering::SeqCst));
    }
}
