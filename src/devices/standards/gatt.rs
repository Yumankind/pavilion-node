//! Bluetooth standard profiles, decoded for `ble_read` / `ble_subscribe` `parsed` (DEVICES.md §4b, Health and fitness).
//! Field layouts follow the Bluetooth GATT Specification Supplement: a flags field first, and each flag says which
//! optional fields follow, in order. Medical values use IEEE-11073 SFLOAT (16-bit) and FLOAT (32-bit).
//! A reading that doesn't fit its layout gets no `parsed` (the hex is still there): nothing is guessed.
use serde_json::{json, Map, Value};

/// Reads little-endian fields in order; any read past the end is None, which makes the whole decode None.
struct R<'a> { b: &'a [u8], i: usize }
impl<'a> R<'a> {
    fn new(b: &'a [u8]) -> R<'a> { R { b, i: 0 } }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> { let s = self.b.get(self.i..self.i + n)?; self.i += n; Some(s) }
    fn u8(&mut self) -> Option<u8> { self.take(1).map(|s| s[0]) }
    fn u16(&mut self) -> Option<u16> { self.take(2).map(|s| u16::from_le_bytes([s[0], s[1]])) }
    fn i16(&mut self) -> Option<i16> { self.u16().map(|v| v as i16) }
    fn u24(&mut self) -> Option<u32> { self.take(3).map(|s| u32::from_le_bytes([s[0], s[1], s[2], 0])) }
    fn u32(&mut self) -> Option<u32> { self.take(4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])) }
    fn sfloat(&mut self) -> Option<Value> { self.u16().map(sfloat) }
    fn float(&mut self) -> Option<Value> { self.u32().map(float) }
    /// Date Time (7 bytes): year, month, day, hours, minutes, seconds.
    fn datetime(&mut self) -> Option<Value> {
        let (y, mo, d, h, mi, s) = (self.u16()?, self.u8()?, self.u8()?, self.u8()?, self.u8()?, self.u8()?);
        Some(json!(format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}")))
    }
    fn rest(&self) -> usize { self.b.len().saturating_sub(self.i) }
}

fn round(v: f64, places: i32) -> f64 { let p = 10f64.powi(places); (v * p).round() / p }

/// IEEE-11073 16-bit SFLOAT: a 4-bit signed exponent and a 12-bit signed mantissa. Special values become null.
pub fn sfloat(raw: u16) -> Value {
    match raw { 0x07FF | 0x0800 | 0x07FE | 0x0802 | 0x0801 => return Value::Null, _ => {} }
    let mut m = (raw & 0x0FFF) as i32;
    if m >= 0x0800 { m -= 0x1000; }
    let mut e = (raw >> 12) as i32;
    if e >= 8 { e -= 16; }
    json!(round(m as f64 * 10f64.powi(e), (-e).max(0)))
}
/// IEEE-11073 32-bit FLOAT: an 8-bit signed exponent and a 24-bit signed mantissa.
pub fn float(raw: u32) -> Value {
    match raw { 0x007F_FFFF | 0x0080_0000 | 0x007F_FFFE | 0x0080_0002 | 0x0080_0001 => return Value::Null, _ => {} }
    let mut m = (raw & 0x00FF_FFFF) as i32;
    if m >= 0x0080_0000 { m -= 0x0100_0000; }
    let e = (raw >> 24) as i8 as i32;
    json!(round(m as f64 * 10f64.powi(e), (-e).max(0)))
}

fn obj(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs { if !v.is_null() { m.insert(k.to_string(), v); } }
    Value::Object(m)
}

/// The decoded value for a characteristic (its 16-bit UUID, lowercase hex), or None when it isn't one the node knows
/// or the bytes don't fit.
pub fn decode(uuid16: &str, b: &[u8]) -> Option<Value> {
    match uuid16 {
        "2a19" => (b.len() == 1 && b[0] <= 100).then(|| json!({ "battery_percent": b[0] })),
        "2a37" => heart_rate(b),
        "2a35" | "2a36" => blood_pressure(b),
        "2a9d" => weight(b),
        "2a1c" | "2a1e" => thermometer(b),
        "2a18" => glucose(b),
        "2a5f" => plx_continuous(b),
        "2a5e" => plx_spot(b),
        "2a63" => cycling_power(b),
        "2a5b" => csc(b),
        "2a53" => rsc(b),
        "2ad2" => indoor_bike(b),
        // Environmental Sensing
        "2a6e" => (b.len() == 2).then(|| json!({ "temperature_c": round(i16::from_le_bytes([b[0], b[1]]) as f64 / 100.0, 2) })),
        "2a6f" => (b.len() == 2).then(|| json!({ "humidity_percent": round(u16::from_le_bytes([b[0], b[1]]) as f64 / 100.0, 2) })),
        "2a6d" => (b.len() == 4).then(|| json!({ "pressure_hpa": round(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f64 / 1000.0, 3) })),
        // Text: device name, manufacturer, model, firmware.
        "2a00" | "2a29" | "2a24" | "2a26" => std::str::from_utf8(b).ok().map(|s| json!({ "text": super::net::clean(s, 200) })),
        _ => None,
    }
}

/// Heart Rate Measurement (0x2A37).
fn heart_rate(b: &[u8]) -> Option<Value> {
    let mut r = R::new(b);
    let f = r.u8()?;
    let bpm = if f & 0x01 != 0 { r.u16()? } else { r.u8()? as u16 };
    let contact = match (f >> 1) & 0x03 { 3 => json!(true), 2 => json!(false), _ => Value::Null };
    let energy = if f & 0x08 != 0 { json!(r.u16()?) } else { Value::Null };
    let rr = if f & 0x10 != 0 {
        let mut v = vec![];
        while r.rest() >= 2 { v.push(json!(round(r.u16()? as f64 / 1024.0, 4))); }
        json!(v)
    } else { Value::Null };
    Some(obj(vec![("heart_rate_bpm", json!(bpm)), ("sensor_contact", contact), ("energy_expended_kj", energy), ("rr_intervals_s", rr)]))
}

/// Blood Pressure Measurement (0x2A35) and Intermediate Cuff Pressure (0x2A36).
fn blood_pressure(b: &[u8]) -> Option<Value> {
    let mut r = R::new(b);
    let f = r.u8()?;
    let unit = if f & 0x01 != 0 { "kPa" } else { "mmHg" };
    let (sys, dia, map) = (r.sfloat()?, r.sfloat()?, r.sfloat()?);
    let at = if f & 0x02 != 0 { r.datetime()? } else { Value::Null };
    let pulse = if f & 0x04 != 0 { r.sfloat()? } else { Value::Null };
    let user = if f & 0x08 != 0 { json!(r.u8()?) } else { Value::Null };
    let status = if f & 0x10 != 0 {
        let s = r.u16()?;
        json!({ "body_movement": s & 0x01 != 0, "cuff_too_loose": s & 0x02 != 0, "irregular_pulse": s & 0x04 != 0, "improper_position": s & 0x20 != 0 })
    } else { Value::Null };
    Some(obj(vec![("systolic", sys), ("diastolic", dia), ("mean_arterial", map), ("unit", json!(unit)), ("time", at), ("pulse_bpm", pulse), ("user", user), ("status", status)]))
}

/// Weight Measurement (0x2A9D).
fn weight(b: &[u8]) -> Option<Value> {
    let mut r = R::new(b);
    let f = r.u8()?;
    let imperial = f & 0x01 != 0;
    let raw = r.u16()?;
    if raw == 0xFFFF { return Some(json!({ "weight": null, "note": "measurement unsuccessful" })); }
    let (w, unit) = if imperial { (round(raw as f64 * 0.01, 2), "lb") } else { (round(raw as f64 * 0.005, 3), "kg") };
    let at = if f & 0x02 != 0 { r.datetime()? } else { Value::Null };
    let user = if f & 0x04 != 0 { json!(r.u8()?) } else { Value::Null };
    let (bmi, height) = if f & 0x08 != 0 {
        let (bmi, h) = (r.u16()?, r.u16()?);
        (json!(round(bmi as f64 * 0.1, 1)), if imperial { json!({ "height": round(h as f64 * 0.1, 1), "unit": "in" }) } else { json!({ "height": round(h as f64 * 0.001, 3), "unit": "m" }) })
    } else { (Value::Null, Value::Null) };
    Some(obj(vec![("weight", json!(w)), ("unit", json!(unit)), ("time", at), ("user", user), ("bmi", bmi), ("height", height)]))
}

/// Temperature Measurement (0x2A1C) and Intermediate Temperature (0x2A1E).
fn thermometer(b: &[u8]) -> Option<Value> {
    let mut r = R::new(b);
    let f = r.u8()?;
    let t = r.float()?;
    let unit = if f & 0x01 != 0 { "F" } else { "C" };
    let at = if f & 0x02 != 0 { r.datetime()? } else { Value::Null };
    let place = if f & 0x04 != 0 {
        json!(match r.u8()? { 1 => "armpit", 2 => "body", 3 => "ear", 4 => "finger", 5 => "gastrointestinal", 6 => "mouth", 7 => "rectum", 8 => "toe", 9 => "tympanum", _ => "other" })
    } else { Value::Null };
    Some(obj(vec![("temperature", t), ("unit", json!(unit)), ("time", at), ("site", place)]))
}

/// Glucose Measurement (0x2A18).
fn glucose(b: &[u8]) -> Option<Value> {
    let mut r = R::new(b);
    let f = r.u8()?;
    let seq = r.u16()?;
    let at = r.datetime()?;
    let offset = if f & 0x01 != 0 { json!(r.i16()?) } else { Value::Null };
    let (conc, unit, ty, loc) = if f & 0x02 != 0 {
        let c = r.sfloat()?;
        let tl = r.u8()?;
        // kg/L → mg/dL (×100 000); mol/L → mmol/L (×1000).
        let (c, unit) = match c.as_f64() { Some(v) if f & 0x04 != 0 => (json!(round(v * 1000.0, 2)), "mmol/L"), Some(v) => (json!(round(v * 100_000.0, 1)), "mg/dL"), None => (Value::Null, "") };
        let ty = match tl & 0x0F { 1 => "capillary whole blood", 2 => "capillary plasma", 3 => "venous whole blood", 4 => "venous plasma", 5 => "arterial whole blood", 6 => "arterial plasma", 9 => "interstitial fluid", 10 => "control solution", _ => "other" };
        let loc = match tl >> 4 { 1 => "finger", 2 => "alternate site test", 3 => "earlobe", 4 => "control solution", _ => "other" };
        (c, json!(unit), json!(ty), json!(loc))
    } else { (Value::Null, Value::Null, Value::Null, Value::Null) };
    let status = if f & 0x08 != 0 { json!(r.u16()?) } else { Value::Null };
    Some(obj(vec![("sequence", json!(seq)), ("time", at), ("time_offset_min", offset), ("concentration", conc), ("unit", unit), ("sample", ty), ("location", loc), ("status_flags", status), ("context_follows", json!(f & 0x10 != 0))]))
}

/// PLX Continuous Measurement (0x2A5F): SpO2 and pulse rate, then the optional fast and slow pairs.
fn plx_continuous(b: &[u8]) -> Option<Value> {
    let mut r = R::new(b);
    let f = r.u8()?;
    let (spo2, pr) = (r.sfloat()?, r.sfloat()?);
    let fast = if f & 0x01 != 0 { json!({ "spo2_percent": r.sfloat()?, "pulse_bpm": r.sfloat()? }) } else { Value::Null };
    let slow = if f & 0x02 != 0 { json!({ "spo2_percent": r.sfloat()?, "pulse_bpm": r.sfloat()? }) } else { Value::Null };
    let status = if f & 0x04 != 0 { json!(r.u16()?) } else { Value::Null };
    let dev = if f & 0x08 != 0 { json!(r.u24()?) } else { Value::Null };
    let pai = if f & 0x10 != 0 { r.sfloat()? } else { Value::Null };
    Some(obj(vec![("spo2_percent", spo2), ("pulse_bpm", pr), ("fast", fast), ("slow", slow), ("measurement_status", status), ("device_status", dev), ("pulse_amplitude_index", pai)]))
}

/// PLX Spot-Check Measurement (0x2A5E).
fn plx_spot(b: &[u8]) -> Option<Value> {
    let mut r = R::new(b);
    let f = r.u8()?;
    let (spo2, pr) = (r.sfloat()?, r.sfloat()?);
    let at = if f & 0x01 != 0 { r.datetime()? } else { Value::Null };
    let status = if f & 0x02 != 0 { json!(r.u16()?) } else { Value::Null };
    let dev = if f & 0x04 != 0 { json!(r.u24()?) } else { Value::Null };
    let pai = if f & 0x08 != 0 { r.sfloat()? } else { Value::Null };
    Some(obj(vec![("spo2_percent", spo2), ("pulse_bpm", pr), ("time", at), ("measurement_status", status), ("device_status", dev), ("pulse_amplitude_index", pai)]))
}

/// Cycling Power Measurement (0x2A63): 16-bit flags, instantaneous power, then the optional fields in flag order.
fn cycling_power(b: &[u8]) -> Option<Value> {
    let mut r = R::new(b);
    let f = r.u16()?;
    let power = r.i16()?;
    let mut out = vec![("power_w", json!(power))];
    if f & 0x0001 != 0 { let v = r.u8()?; out.push(("pedal_power_balance_percent", json!(v as f64 / 2.0))); out.push(("balance_reference", json!(if f & 0x0002 != 0 { "left" } else { "unknown" }))); }
    if f & 0x0004 != 0 { out.push(("accumulated_torque_nm", json!(round(r.u16()? as f64 / 32.0, 3)))); }
    if f & 0x0010 != 0 { out.push(("wheel_revolutions", json!(r.u32()?))); out.push(("last_wheel_event_s", json!(round(r.u16()? as f64 / 2048.0, 4)))); }
    if f & 0x0020 != 0 { out.push(("crank_revolutions", json!(r.u16()?))); out.push(("last_crank_event_s", json!(round(r.u16()? as f64 / 1024.0, 4)))); }
    if f & 0x0040 != 0 { out.push(("max_force_n", json!(r.i16()?))); out.push(("min_force_n", json!(r.i16()?))); }
    if f & 0x0080 != 0 { out.push(("max_torque_nm", json!(round(r.i16()? as f64 / 32.0, 3)))); out.push(("min_torque_nm", json!(round(r.i16()? as f64 / 32.0, 3)))); }
    if f & 0x0100 != 0 { let a = r.u24()?; out.push(("max_angle_deg", json!(a & 0x0FFF))); out.push(("min_angle_deg", json!(a >> 12))); }
    if f & 0x0200 != 0 { out.push(("top_dead_spot_deg", json!(r.u16()?))); }
    if f & 0x0400 != 0 { out.push(("bottom_dead_spot_deg", json!(r.u16()?))); }
    if f & 0x0800 != 0 { out.push(("accumulated_energy_kj", json!(r.u16()?))); }
    Some(obj(out))
}

/// CSC Measurement (0x2A5B): wheel and crank revolutions.
fn csc(b: &[u8]) -> Option<Value> {
    let mut r = R::new(b);
    let f = r.u8()?;
    let mut out = vec![];
    if f & 0x01 != 0 { out.push(("wheel_revolutions", json!(r.u32()?))); out.push(("last_wheel_event_s", json!(round(r.u16()? as f64 / 1024.0, 4)))); }
    if f & 0x02 != 0 { out.push(("crank_revolutions", json!(r.u16()?))); out.push(("last_crank_event_s", json!(round(r.u16()? as f64 / 1024.0, 4)))); }
    Some(obj(out))
}

/// RSC Measurement (0x2A53): speed, cadence, stride length, distance.
fn rsc(b: &[u8]) -> Option<Value> {
    let mut r = R::new(b);
    let f = r.u8()?;
    let speed = round(r.u16()? as f64 / 256.0, 3);
    let cadence = r.u8()?;
    let stride = if f & 0x01 != 0 { json!(round(r.u16()? as f64 / 100.0, 2)) } else { Value::Null };
    let dist = if f & 0x02 != 0 { json!(round(r.u32()? as f64 / 10.0, 1)) } else { Value::Null };
    Some(obj(vec![("speed_m_s", json!(speed)), ("cadence_per_min", json!(cadence)), ("stride_length_m", stride), ("total_distance_m", dist), ("running", json!(f & 0x04 != 0))]))
}

/// Fitness Machine: Indoor Bike Data (0x2AD2). Bit 0 ("more data") set means the instantaneous speed is absent.
fn indoor_bike(b: &[u8]) -> Option<Value> {
    let mut r = R::new(b);
    let f = r.u16()?;
    let mut out = vec![];
    if f & 0x0001 == 0 { out.push(("speed_kmh", json!(round(r.u16()? as f64 / 100.0, 2)))); }
    if f & 0x0002 != 0 { out.push(("average_speed_kmh", json!(round(r.u16()? as f64 / 100.0, 2)))); }
    if f & 0x0004 != 0 { out.push(("cadence_rpm", json!(r.u16()? as f64 / 2.0))); }
    if f & 0x0008 != 0 { out.push(("average_cadence_rpm", json!(r.u16()? as f64 / 2.0))); }
    if f & 0x0010 != 0 { out.push(("total_distance_m", json!(r.u24()?))); }
    if f & 0x0020 != 0 { out.push(("resistance_level", json!(r.i16()?))); }
    if f & 0x0040 != 0 { out.push(("power_w", json!(r.i16()?))); }
    if f & 0x0080 != 0 { out.push(("average_power_w", json!(r.i16()?))); }
    if f & 0x0100 != 0 {
        let (total, per_h, per_min) = (r.u16()?, r.u16()?, r.u8()?);
        if total != 0xFFFF { out.push(("energy_kcal", json!(total))); }
        if per_h != 0xFFFF { out.push(("energy_kcal_per_hour", json!(per_h))); }
        if per_min != 0xFF { out.push(("energy_kcal_per_min", json!(per_min))); }
    }
    if f & 0x0200 != 0 { out.push(("heart_rate_bpm", json!(r.u8()?))); }
    if f & 0x0400 != 0 { out.push(("metabolic_equivalent", json!(r.u8()? as f64 / 10.0))); }
    if f & 0x0800 != 0 { out.push(("elapsed_s", json!(r.u16()?))); }
    if f & 0x1000 != 0 { out.push(("remaining_s", json!(r.u16()?))); }
    Some(obj(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_formats() {
        assert_eq!(sfloat(0x0078), json!(120.0));
        assert_eq!(sfloat(0xF3A5), json!(93.3)); // 933 × 10^-1
        assert_eq!(sfloat(0x0FFF), json!(-1.0)); // mantissa -1
        assert_eq!(sfloat(0x07FF), Value::Null); // NaN
        assert_eq!(float(0xFF00_0172), json!(37.0)); // 370 × 10^-1
        assert_eq!(float(0x007F_FFFF), Value::Null);
    }

    #[test]
    fn heart_rate_with_contact_and_rr() {
        // Flags 0x16: 8-bit value, contact detected, RR intervals present. 72 bpm; RR 1024/1024 s and 0.75 s.
        let v = decode("2a37", &[0x16, 0x48, 0x00, 0x04, 0x00, 0x03]).unwrap();
        assert_eq!(v, json!({ "heart_rate_bpm": 72, "sensor_contact": true, "rr_intervals_s": [1.0, 0.75] }));
        // A 16-bit value (0x012C) with energy expended (16 kJ), no contact information.
        assert_eq!(decode("2a37", &[0x09, 0x2c, 0x01, 0x10, 0x00]).unwrap(), json!({ "heart_rate_bpm": 300, "energy_expended_kj": 16 }));
        assert!(decode("2a37", &[0x01, 0x48]).is_none()); // says 16-bit, has one byte
    }

    #[test]
    fn blood_pressure_with_time_and_pulse() {
        let mut b = vec![0x06]; // mmHg, time stamp, pulse
        b.extend([0x78, 0x00, 0x50, 0x00, 0xA5, 0xF3]); // 120 / 80 / 93.3
        b.extend([0xEA, 0x07, 11, 13, 9, 30, 0]); // 2026-11-13 09:30:00
        b.extend([0x48, 0x00]); // pulse 72
        let v = decode("2a35", &b).unwrap();
        assert_eq!(v, json!({ "systolic": 120.0, "diastolic": 80.0, "mean_arterial": 93.3, "unit": "mmHg", "time": "2026-11-13T09:30:00", "pulse_bpm": 72.0 }));
    }

    #[test]
    fn weight_bmi_and_height() {
        // SI, BMI and height: 0x3A98 × 0.005 = 75 kg; BMI 245 × 0.1 = 24.5; height 1750 mm.
        let v = decode("2a9d", &[0x08, 0x98, 0x3A, 0xF5, 0x00, 0xD6, 0x06]).unwrap();
        assert_eq!(v, json!({ "weight": 75.0, "unit": "kg", "bmi": 24.5, "height": { "height": 1.75, "unit": "m" } }));
        assert_eq!(decode("2a9d", &[0x01, 0x10, 0x27]).unwrap()["unit"], "lb"); // 100.00 lb
    }

    #[test]
    fn thermometer_celsius_with_site() {
        let v = decode("2a1c", &[0x04, 0x72, 0x01, 0x00, 0xFF, 0x03]).unwrap();
        assert_eq!(v, json!({ "temperature": 37.0, "unit": "C", "site": "ear" }));
    }

    #[test]
    fn glucose_in_mg_dl_and_mmol() {
        // Sequence 1, 2026-11-13 08:00:00, concentration in kg/L: 95 mg/dL = 0.00095 kg/L = 950 × 10^-6 → SFLOAT 0xA3B6.
        let mut b = vec![0x02, 0x01, 0x00, 0xEA, 0x07, 11, 13, 8, 0, 0];
        b.extend([0xB6, 0xA3, 0x11]); // capillary whole blood, finger
        let v = decode("2a18", &b).unwrap();
        assert_eq!((v["concentration"].as_f64(), v["unit"].as_str(), v["sample"].as_str(), v["location"].as_str()), (Some(95.0), Some("mg/dL"), Some("capillary whole blood"), Some("finger")));
        // mol/L: 5.3 mmol/L = 0.0053 mol/L = 53 × 10^-4 → SFLOAT 0xC035.
        let mut b = vec![0x06, 0x02, 0x00, 0xEA, 0x07, 11, 13, 8, 0, 0];
        b.extend([0x35, 0xC0, 0x11]);
        assert_eq!(decode("2a18", &b).unwrap()["concentration"], json!(5.3));
    }

    #[test]
    fn pulse_oximeter() {
        assert_eq!(decode("2a5f", &[0x00, 0x62, 0x00, 0x48, 0x00]).unwrap(), json!({ "spo2_percent": 98.0, "pulse_bpm": 72.0 }));
        assert_eq!(decode("2a5e", &[0x00, 0x61, 0x00, 0x3C, 0x00]).unwrap(), json!({ "spo2_percent": 97.0, "pulse_bpm": 60.0 }));
    }

    #[test]
    fn cycling_power_speed_cadence_and_running() {
        // Flags 0x0020 (crank data): 250 W, 1000 crank revolutions, last event 2048/1024 = 2 s.
        assert_eq!(decode("2a63", &[0x20, 0x00, 0xFA, 0x00, 0xE8, 0x03, 0x00, 0x08]).unwrap(), json!({ "power_w": 250, "crank_revolutions": 1000, "last_crank_event_s": 2.0 }));
        // CSC with both: 5000 wheel revolutions at 1 s, 300 crank revolutions at 0.5 s.
        assert_eq!(decode("2a5b", &[0x03, 0x88, 0x13, 0, 0, 0x00, 0x04, 0x2C, 0x01, 0x00, 0x02]).unwrap(),
            json!({ "wheel_revolutions": 5000, "last_wheel_event_s": 1.0, "crank_revolutions": 300, "last_crank_event_s": 0.5 }));
        // RSC: 3.5 m/s (896/256), 170 steps/min, stride 1.25 m, running.
        assert_eq!(decode("2a53", &[0x05, 0x80, 0x03, 0xAA, 0x7D, 0x00]).unwrap(), json!({ "speed_m_s": 3.5, "cadence_per_min": 170, "stride_length_m": 1.25, "running": true }));
    }

    #[test]
    fn indoor_bike_data() {
        // Flags 0x0044: speed present (bit 0 clear), cadence, power. 25.50 km/h, 90 rpm, 200 W.
        assert_eq!(decode("2ad2", &[0x44, 0x00, 0xF6, 0x09, 0xB4, 0x00, 0xC8, 0x00]).unwrap(), json!({ "speed_kmh": 25.5, "cadence_rpm": 90.0, "power_w": 200 }));
        // "More data": no speed, heart rate only.
        assert_eq!(decode("2ad2", &[0x01, 0x02, 0x8C]).unwrap(), json!({ "heart_rate_bpm": 140 }));
    }

    #[test]
    fn environment_and_battery() {
        assert_eq!(decode("2a6e", &[0x2a, 0x08]).unwrap(), json!({ "temperature_c": 20.9 }));
        assert_eq!(decode("2a6f", &[0x88, 0x13]).unwrap(), json!({ "humidity_percent": 50.0 }));
        assert_eq!(decode("2a6d", &[0x08, 0x75, 0x0F, 0x00]).unwrap(), json!({ "pressure_hpa": 1013.0 })); // 1 013 000 × 0.1 Pa
        assert_eq!(decode("2a19", &[87]).unwrap(), json!({ "battery_percent": 87 }));
        assert!(decode("2a19", &[187]).is_none());
        assert!(decode("ffe1", &[1, 2]).is_none());
    }
}
