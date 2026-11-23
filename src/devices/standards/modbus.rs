//! Modbus TCP (DEVICES.md §4b, Energy, building and industrial): solar inverters, batteries, meters, heat pumps.
//! Agents read registers **by the names the adoption lists** (`allow.registers`), never by raw address, and get
//! numbers with their unit. Writing is safety-critical: refused unless the adoption is marked critical, the action is
//! `critical` (a presence answer), and the register is a listed holding register.
//!
//! A register in the adoption: `{name, table: "holding"|"input", address: 0..65535, type: "u16"|"i16"|"u32"|"i32"|"f32",
//! scale?: 1, unit?: "W", unit_id?: 1, words?: "big"|"little"}`. 32-bit values span two registers, high word first
//! unless `words` is `"little"`.
use super::super::envelope::External;
use super::net;
use serde_json::{json, Map, Value};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Table { Holding, Input }
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Ty { U16, I16, U32, I32, F32 }

#[derive(Clone, Debug, PartialEq)]
pub struct Register { pub name: String, pub table: Table, pub address: u16, pub ty: Ty, pub scale: f64, pub unit: Option<String>, pub unit_id: u8, pub little_words: bool }

impl Ty {
    pub fn words(self) -> u16 { match self { Ty::U16 | Ty::I16 => 1, _ => 2 } }
}

/// One register definition from the adoption, strictly.
pub fn register(v: &Value) -> Result<Register, String> {
    let name = v["name"].as_str().filter(|n| !n.is_empty() && n.len() <= 64 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')).ok_or("each register needs a name (letters, digits, _ - .)")?;
    let table = match v["table"].as_str().unwrap_or("holding") { "holding" => Table::Holding, "input" => Table::Input, t => return Err(format!("register {name}: table {t:?} isn't holding or input")) };
    let address = v["address"].as_u64().filter(|a| *a <= 65535).ok_or_else(|| format!("register {name}: address must be 0 to 65535"))? as u16;
    let ty = match v["type"].as_str().unwrap_or("u16") { "u16" => Ty::U16, "i16" => Ty::I16, "u32" => Ty::U32, "i32" => Ty::I32, "f32" => Ty::F32, t => return Err(format!("register {name}: type {t:?} isn't u16, i16, u32, i32 or f32")) };
    if address as u32 + ty.words() as u32 > 65536 { return Err(format!("register {name} runs past the last address")); }
    let scale = match &v["scale"] { Value::Null => 1.0, s => s.as_f64().filter(|s| s.is_finite() && *s != 0.0).ok_or_else(|| format!("register {name}: scale must be a number other than 0"))? };
    let unit_id = match &v["unit_id"] { Value::Null => 1, u => u.as_u64().filter(|u| *u <= 247).ok_or_else(|| format!("register {name}: unit_id must be 0 to 247"))? as u8 };
    let little_words = match v["words"].as_str() { None | Some("big") => false, Some("little") => true, Some(w) => return Err(format!("register {name}: words {w:?} isn't big or little")) };
    Ok(Register { name: name.into(), table, address, ty, scale, unit: v["unit"].as_str().map(|u| net::clean(u, 16)), unit_id, little_words })
}

/// The registers an agent named (one name, or a list of up to 16), each from the adoption.
pub fn registers_arg(args: &Value, e: &External) -> Result<Vec<Register>, String> {
    let names: Vec<&str> = match &args["register"] {
        Value::String(s) => vec![s.as_str()],
        Value::Array(a) if !a.is_empty() && a.len() <= 16 => a.iter().map(|x| x.as_str().ok_or("register names are strings")).collect::<Result<_, _>>()?,
        _ => return Err("register is a name from the adoption, or a list of up to 16".into()),
    };
    let listed: Vec<Register> = e.allow.registers.iter().map(register).collect::<Result<_, _>>()?;
    names.iter().map(|n| listed.iter().find(|r| r.name == *n).cloned().ok_or_else(|| format!("{n} isn't a register the adoption of {} lists", e.id))).collect()
}

/// Registers (16-bit words, as read) → the value, scaled.
pub fn value(r: &Register, words: &[u16]) -> Option<f64> {
    if words.len() < r.ty.words() as usize { return None; }
    let w32 = || if r.little_words { (words[1] as u32) << 16 | words[0] as u32 } else { (words[0] as u32) << 16 | words[1] as u32 };
    let raw = match r.ty { Ty::U16 => words[0] as f64, Ty::I16 => words[0] as i16 as f64, Ty::U32 => w32() as f64, Ty::I32 => w32() as i32 as f64, Ty::F32 => f32::from_bits(w32()) as f64 };
    if !raw.is_finite() { return None; }
    let v = raw * r.scale;
    Some((v * 1e6).round() / 1e6)
}

/// A value to write → the registers, checked against the type's range after removing the scale.
pub fn words_for(r: &Register, v: f64) -> Result<Vec<u16>, String> {
    if !v.is_finite() { return Err("the value must be a number".into()); }
    let raw = v / r.scale;
    let int = |lo: f64, hi: f64| { let x = raw.round(); if x < lo || x > hi || (raw - x).abs() > 1e-6 { Err(format!("{v} doesn't fit register {} ({:?}, scale {})", r.name, r.ty, r.scale)) } else { Ok(x) } };
    let split = |x: u32| if r.little_words { vec![x as u16, (x >> 16) as u16] } else { vec![(x >> 16) as u16, x as u16] };
    Ok(match r.ty {
        Ty::U16 => vec![int(0.0, 65535.0)? as u16],
        Ty::I16 => vec![int(-32768.0, 32767.0)? as i16 as u16],
        Ty::U32 => split(int(0.0, 4_294_967_295.0)? as u32),
        Ty::I32 => split(int(-2_147_483_648.0, 2_147_483_647.0)? as i32 as u32),
        Ty::F32 => split((raw as f32).to_bits()),
    })
}

/// A request PDU wrapped in the MBAP header (transaction, protocol 0, length, unit).
pub fn frame(tid: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(7 + pdu.len());
    f.extend(tid.to_be_bytes());
    f.extend(0u16.to_be_bytes());
    f.extend(((pdu.len() + 1) as u16).to_be_bytes());
    f.push(unit);
    f.extend_from_slice(pdu);
    f
}

fn exception(code: u8) -> &'static str {
    match code { 1 => "illegal function", 2 => "illegal data address", 3 => "illegal data value", 4 => "server device failure", 5 => "acknowledge", 6 => "server busy", 0x0A => "gateway path unavailable", 0x0B => "gateway target failed to respond", _ => "an exception" }
}

/// One connection to an adopted device.
pub struct Client { s: tokio::net::TcpStream, tid: u16 }

impl Client {
    pub async fn open(e: &External) -> Result<Client, String> {
        let a = net::parse_addr(&e.address, &["tcp", "modbus"], "tcp", |_| 502)?;
        let addr = net::resolve(&a.host, a.port).await?;
        let s = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr)).await.map_err(|_| format!("{} didn't answer on {addr}", e.id))?.map_err(|err| format!("can't reach {}: {err}", e.id))?;
        let _ = s.set_nodelay(true);
        Ok(Client { s, tid: rand::random() })
    }

    async fn call(&mut self, unit: u8, pdu: &[u8]) -> Result<Vec<u8>, String> {
        self.tid = self.tid.wrapping_add(1);
        let tid = self.tid;
        self.s.write_all(&frame(tid, unit, pdu)).await.map_err(|e| format!("Modbus: {e}"))?;
        let work = async {
            loop {
                let mut h = [0u8; 7];
                self.s.read_exact(&mut h).await.map_err(|e| format!("Modbus: {e}"))?;
                let len = u16::from_be_bytes([h[4], h[5]]) as usize;
                if !(2..=254).contains(&len) { return Err("the device sent a malformed Modbus answer".to_string()); }
                let mut p = vec![0u8; len - 1];
                self.s.read_exact(&mut p).await.map_err(|e| format!("Modbus: {e}"))?;
                if u16::from_be_bytes([h[0], h[1]]) != tid { continue; } // an older answer
                if p[0] == pdu[0] | 0x80 { return Err(format!("the device answered with {} (code {})", exception(p.get(1).copied().unwrap_or(0)), p.get(1).copied().unwrap_or(0))); }
                if p[0] != pdu[0] { return Err("the device answered another request".into()); }
                return Ok(p);
            }
        };
        tokio::time::timeout(Duration::from_secs(5), work).await.map_err(|_| "the device didn't answer within 5 s".to_string())?
    }

    pub async fn read(&mut self, r: &Register) -> Result<Vec<u16>, String> {
        let f = match r.table { Table::Holding => 0x03, Table::Input => 0x04 };
        let n = r.ty.words();
        let mut pdu = vec![f];
        pdu.extend(r.address.to_be_bytes());
        pdu.extend(n.to_be_bytes());
        let p = self.call(r.unit_id, &pdu).await?;
        if p.len() < 2 || p[1] as usize != 2 * n as usize || p.len() < 2 + 2 * n as usize { return Err("the device sent the wrong number of registers".into()); }
        Ok((0..n as usize).map(|i| u16::from_be_bytes([p[2 + 2 * i], p[3 + 2 * i]])).collect())
    }

    pub async fn write(&mut self, r: &Register, words: &[u16]) -> Result<(), String> {
        if r.table != Table::Holding { return Err(format!("{} is an input register, which can't be written", r.name)); }
        let pdu = if words.len() == 1 {
            let mut p = vec![0x06];
            p.extend(r.address.to_be_bytes());
            p.extend(words[0].to_be_bytes());
            p
        } else {
            let mut p = vec![0x10];
            p.extend(r.address.to_be_bytes());
            p.extend((words.len() as u16).to_be_bytes());
            p.push((words.len() * 2) as u8);
            for w in words { p.extend(w.to_be_bytes()); }
            p
        };
        self.call(r.unit_id, &pdu).await.map(|_| ())
    }
}

pub async fn read(e: &External, regs: &[Register]) -> Result<Value, String> {
    let mut c = Client::open(e).await?;
    let mut values = Map::new();
    for r in regs {
        let w = c.read(r).await?;
        values.insert(r.name.clone(), json!({ "value": value(r, &w), "unit": r.unit, "raw": w }));
    }
    Ok(json!({ "values": values, "at": super::super::now() }))
}

pub async fn write(e: &External, r: &Register, v: f64) -> Result<Value, String> {
    let words = words_for(r, v)?;
    let mut c = Client::open(e).await?;
    c.write(r, &words).await?;
    let back = c.read(r).await?;
    Ok(json!({ "done": true, "value": value(r, &back) }))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn reg(v: Value) -> Register { register(&v).unwrap() }

    #[test]
    fn value_types_and_scale() {
        let r = |ty: &str, extra: Value| { let mut v = json!({ "name": "x", "address": 0, "type": ty }); for (k, x) in extra.as_object().unwrap() { v[k] = x.clone(); } reg(v) };
        assert_eq!(value(&r("u16", json!({})), &[0xFFFF]), Some(65535.0));
        assert_eq!(value(&r("i16", json!({})), &[0xFFFF]), Some(-1.0));
        assert_eq!(value(&r("i16", json!({ "scale": 0.1 })), &[0xFF9C]), Some(-10.0)); // -100 × 0.1
        assert_eq!(value(&r("u32", json!({})), &[0x0001, 0x0002]), Some(65538.0));
        assert_eq!(value(&r("u32", json!({ "words": "little" })), &[0x0002, 0x0001]), Some(65538.0));
        assert_eq!(value(&r("i32", json!({})), &[0xFFFF, 0xFFFE]), Some(-2.0));
        assert_eq!(value(&r("f32", json!({})), &[0x4148, 0x0000]), Some(12.5)); // 0x41480000
        assert_eq!(value(&r("f32", json!({ "scale": 1000 })), &[0x3F80, 0x0000]), Some(1000.0));
        assert_eq!(value(&r("u32", json!({})), &[0x0001]), None);
        assert_eq!(words_for(&r("i16", json!({ "scale": 0.1 })), -10.0).unwrap(), vec![0xFF9C]);
        assert_eq!(words_for(&r("u32", json!({})), 65538.0).unwrap(), vec![1, 2]);
        assert_eq!(words_for(&r("f32", json!({})), 12.5).unwrap(), vec![0x4148, 0]);
        assert!(words_for(&r("u16", json!({})), 70000.0).is_err());
        assert!(words_for(&r("u16", json!({})), 1.5).is_err());
        assert!(register(&json!({ "name": "x", "address": 65535, "type": "u32" })).is_err());
        assert!(register(&json!({ "name": "x", "address": 1, "type": "u64" })).is_err());
        assert_eq!(frame(0x0102, 1, &[0x03, 0x00, 0x10, 0x00, 0x02]), vec![1, 2, 0, 0, 0, 6, 1, 3, 0, 0x10, 0, 2]);
    }

    /// A Modbus TCP device: holding registers 0..100 and input registers 0..100, unit 1. Records writes.
    pub async fn device(holding: Arc<Mutex<Vec<u16>>>, input: Vec<u16>) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { return };
                let (holding, input) = (holding.clone(), input.clone());
                tokio::spawn(async move {
                    loop {
                        let mut h = [0u8; 7];
                        if s.read_exact(&mut h).await.is_err() { return; }
                        let mut p = vec![0u8; u16::from_be_bytes([h[4], h[5]]) as usize - 1];
                        if s.read_exact(&mut p).await.is_err() { return; }
                        let (f, a) = (p[0], u16::from_be_bytes([p[1], p[2]]) as usize);
                        let reply = if h[6] != 1 { vec![f | 0x80, 0x0B] } else { match f {
                            0x03 | 0x04 => {
                                let n = u16::from_be_bytes([p[3], p[4]]) as usize;
                                let t = if f == 3 { holding.lock().unwrap().clone() } else { input.clone() };
                                if a + n > t.len() { vec![f | 0x80, 2] } else { let mut r = vec![f, (2 * n) as u8]; for w in &t[a..a + n] { r.extend(w.to_be_bytes()); } r }
                            }
                            0x06 => { holding.lock().unwrap()[a] = u16::from_be_bytes([p[3], p[4]]); p.clone() }
                            0x10 => { let n = u16::from_be_bytes([p[3], p[4]]) as usize; for i in 0..n { holding.lock().unwrap()[a + i] = u16::from_be_bytes([p[6 + 2 * i], p[7 + 2 * i]]); } p[..5].to_vec() }
                            _ => vec![f | 0x80, 1],
                        } };
                        let out = frame(u16::from_be_bytes([h[0], h[1]]), h[6], &reply);
                        if s.write_all(&out).await.is_err() { return; }
                    }
                });
            }
        });
        addr
    }

    pub fn inverter(addr: &str, critical: bool) -> External {
        External { id: "ext_inverter".into(), name: "Inverter".into(), kind: "modbus".into(), address: addr.into(), critical,
            allow: crate::devices::envelope::Allow { registers: vec![
                json!({ "name": "pv_power", "table": "input", "address": 10, "type": "u32", "unit": "W" }),
                json!({ "name": "battery_temp", "table": "input", "address": 12, "type": "i16", "scale": 0.1, "unit": "°C" }),
                json!({ "name": "export_limit", "table": "holding", "address": 40, "type": "u16", "unit": "W" }),
            ], ..Default::default() }, ..Default::default() }
    }

    #[tokio::test]
    async fn reads_and_writes_against_a_device() {
        let mut input = vec![0u16; 100];
        input[10] = 0x0001; input[11] = 0x1170; // 70 000 W
        input[12] = 0x00FA; // 25.0 °C
        let holding = Arc::new(Mutex::new(vec![0u16; 100]));
        holding.lock().unwrap()[40] = 5000;
        let e = inverter(&device(holding.clone(), input).await, true);
        let regs = registers_arg(&json!({ "register": ["pv_power", "battery_temp", "export_limit"] }), &e).unwrap();
        let v = read(&e, &regs).await.unwrap();
        assert_eq!(v["values"]["pv_power"], json!({ "value": 70000.0, "unit": "W", "raw": [1, 0x1170] }));
        assert_eq!(v["values"]["battery_temp"]["value"], 25.0);
        assert!(registers_arg(&json!({ "register": "secret_coil" }), &e).unwrap_err().contains("isn't a register"));
        let w = registers_arg(&json!({ "register": "export_limit" }), &e).unwrap();
        assert_eq!(write(&e, &w[0], 3000.0).await.unwrap(), json!({ "done": true, "value": 3000.0 }));
        assert_eq!(holding.lock().unwrap()[40], 3000);
        assert!(write(&e, &regs[0], 1.0).await.unwrap_err().contains("input register"));
        // An address the device doesn't have: its exception, in words.
        let mut bad = w[0].clone();
        bad.address = 99; bad.ty = Ty::U32;
        assert!(Client::open(&e).await.unwrap().read(&bad).await.unwrap_err().contains("illegal data address"));
    }
}
