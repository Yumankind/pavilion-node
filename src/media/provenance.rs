//! Outputs carry a provenance note (docs/MEDIA.md §7): which model, when, which pavilion and job. Inside the file where
//! the format has a place for it (a PNG text chunk, a WAV INFO comment), and always in a JSON sidecar uploaded beside it.
//! The file's type comes from its bytes, never from what the runner named it.
use serde_json::{json, Value};

/// What a file is, from its first bytes: (extension, media type).
pub fn sniff(b: &[u8]) -> Option<(&'static str, &'static str)> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") { return Some(("png", "image/png")); }
    if b.starts_with(&[0xff, 0xd8, 0xff]) { return Some(("jpg", "image/jpeg")); }
    if b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WAVE" { return Some(("wav", "audio/wav")); }
    if b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP" { return Some(("webp", "image/webp")); }
    if b.len() >= 12 && &b[4..8] == b"ftyp" { return Some(("mp4", "video/mp4")); }
    if b.starts_with(b"ID3") || (b.len() > 1 && b[0] == 0xff && b[1] & 0xe0 == 0xe0) { return Some(("mp3", "audio/mpeg")); }
    if b.starts_with(b"fLaC") { return Some(("flac", "audio/flac")); }
    if b.starts_with(b"OggS") { return Some(("ogg", "audio/ogg")); }
    // Text: valid UTF-8 without control characters other than whitespace. JSON if it parses as an object.
    let s = std::str::from_utf8(b).ok()?;
    if s.chars().any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')) { return None; }
    if serde_json::from_str::<Value>(s).map_or(false, |v| v.is_object() || v.is_array()) { return Some(("json", "application/json")); }
    Some(("txt", "text/plain"))
}

/// The note, as one line of JSON.
pub fn note(model: &str, job: &str, pavilion: &str, at: &str) -> Value {
    json!({ "generator": "Cloud Pavilion (pavilion-node)", "model": model, "job": job, "pavilion": pavilion, "created_at": at })
}

/// Adds the note to a file whose format has a place for it; other formats come back as they were.
pub fn embed(bytes: Vec<u8>, ext: &str, note: &Value) -> Vec<u8> {
    match ext { "png" => png_text(bytes, "Comment", &note.to_string()), "wav" => wav_info(bytes, &note.to_string()), _ => bytes }
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &b in data { c ^= b as u32; for _ in 0..8 { c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 }; } }
    !c
}

/// A tEXt chunk right after IHDR (Latin-1 text: anything else is replaced).
pub fn png_text(png: Vec<u8>, key: &str, text: &str) -> Vec<u8> {
    if png.len() < 33 || &png[12..16] != b"IHDR" { return png; }
    let text: String = text.chars().map(|c| if (c as u32) < 256 && c != '\0' { c } else { '?' }).collect();
    let mut data = key.as_bytes().to_vec(); data.push(0); data.extend(text.chars().map(|c| c as u8));
    let mut chunk = (data.len() as u32).to_be_bytes().to_vec();
    let mut typed = b"tEXt".to_vec(); typed.extend(&data);
    chunk.extend(&typed); chunk.extend(crc32(&typed).to_be_bytes());
    let mut out = png[..33].to_vec(); out.extend(chunk); out.extend(&png[33..]);
    out
}

/// A LIST/INFO chunk at the end with the note as its comment (ICMT) and the software (ISFT).
pub fn wav_info(wav: Vec<u8>, text: &str) -> Vec<u8> {
    if wav.len() < 12 || &wav[..4] != b"RIFF" || &wav[8..12] != b"WAVE" { return wav; }
    let sub = |id: &[u8], s: &str| { let mut v = s.as_bytes().to_vec(); v.push(0); if v.len() % 2 == 1 { v.push(0); } let mut c = id.to_vec(); c.extend((v.len() as u32).to_le_bytes()); c.extend(v); c };
    let mut info = b"INFO".to_vec(); info.extend(sub(b"ISFT", "Cloud Pavilion")); info.extend(sub(b"ICMT", text));
    let mut out = wav;
    if out.len() % 2 == 1 { out.push(0); }
    out.extend(b"LIST"); out.extend((info.len() as u32).to_le_bytes()); out.extend(info);
    let riff = (out.len() - 8) as u32;
    out[4..8].copy_from_slice(&riff.to_le_bytes());
    out
}

/// The sidecar for one output: `{version, kind, model, params, created_at, pavilion, job}`, secret-looking values scrubbed.
pub fn sidecar(kind: &str, model: &str, task: &str, inputs: &Value, at: &str, pavilion: &str, job: &str, media_type: &str) -> Value {
    let mut params = inputs.clone();
    if let Some(o) = params.as_object_mut() { o.remove("references"); }
    json!({ "version": 1, "kind": kind, "task": task, "model": model, "media_type": media_type, "params": scrub(params), "created_at": at, "pavilion": pavilion, "job": job,
        "generator": "Cloud Pavilion (pavilion-node)" })
}

/// Replaces values that look like keys or tokens.
pub fn scrub(v: Value) -> Value {
    match v {
        Value::String(s) if secretish(&s) => Value::String("[scrubbed]".into()),
        Value::Array(a) => Value::Array(a.into_iter().map(scrub).collect()),
        Value::Object(o) => Value::Object(o.into_iter().map(|(k, v)| {
            let k_secret = ["key", "token", "secret", "password", "authorization"].iter().any(|w| k.to_lowercase().contains(w));
            (k, if k_secret && v.is_string() { Value::String("[scrubbed]".into()) } else { scrub(v) })
        }).collect()),
        v => v,
    }
}
fn secretish(s: &str) -> bool {
    let prefixes = ["sk-", "sk_live_", "sk_test_", "ghp_", "gho_", "github_pat_", "hf_", "xoxb-", "xoxp-", "AKIA", "AIza", "glpat-", "eyJ"];
    s.split_whitespace().any(|w| {
        let long_opaque = w.len() >= 32 && w.chars().all(|c| c.is_ascii_alphanumeric() || "-_+/=.".contains(c)) && w.chars().any(|c| c.is_ascii_digit()) && w.chars().any(|c| c.is_ascii_alphabetic());
        (prefixes.iter().any(|p| w.starts_with(p)) && w.len() >= 16) || long_opaque
    })
}

/// Now, as `2026-11-13T09:00:00Z`.
pub fn now_iso() -> String { iso(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()) }
pub fn iso(secs: u64) -> String {
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    // Civil date from days since 1970 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem / 60 % 60, rem % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dates() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(1_794_528_000), "2026-11-13T00:00:00Z");
        assert_eq!(iso(951_782_400 + 3661), "2000-02-29T01:01:01Z");
    }
    #[test]
    fn file_types_come_from_bytes() {
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n...."), Some(("png", "image/png")));
        assert_eq!(sniff(b"RIFF\0\0\0\0WAVEfmt "), Some(("wav", "audio/wav")));
        assert_eq!(sniff(b"\0\0\0\x18ftypisom"), Some(("mp4", "video/mp4")));
        assert_eq!(sniff(b"{\"text\":\"hi\"}"), Some(("json", "application/json")));
        assert_eq!(sniff("Olá mundo\n".as_bytes()), Some(("txt", "text/plain")));
        assert_eq!(sniff(b"<html>\x00"), None);
        assert_eq!(sniff(&[0x00, 0x01, 0x02]), None);
    }
    #[test]
    fn png_gets_a_valid_text_chunk() {
        // The smallest PNG: 1x1 grey.
        let png: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0x0D, 0x49, 0x48, 0x44, 0x52, 0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0, 0x3A, 0x7E, 0x9B, 0x55,
            0, 0, 0, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x08, 0xD7, 0x63, 0x68, 0, 0, 0, 0x82, 0, 0x81, 0xDD, 0x43, 0x6A, 0xF4, 0, 0, 0, 0, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];
        assert_eq!(crc32(&png[12..29]), u32::from_be_bytes(png[29..33].try_into().unwrap()), "crc32 matches IHDR's");
        let out = embed(png.clone(), "png", &note("test-pattern", "mj_x", "pav", "2026-11-13T00:00:00Z"));
        assert_eq!(&out[37..41], b"tEXt");
        let len = u32::from_be_bytes(out[33..37].try_into().unwrap()) as usize;
        assert_eq!(crc32(&out[37..41 + len]), u32::from_be_bytes(out[41 + len..45 + len].try_into().unwrap()));
        assert!(String::from_utf8_lossy(&out).contains("\"model\":\"test-pattern\""));
        assert_eq!(&out[45 + len..], &png[33..]);
    }
    #[test]
    fn wav_gets_an_info_comment_and_stays_valid() {
        let mut w = super::super::vm::wav_header(24000, 1, 4800); w.extend(vec![0u8; 4800]);
        let out = embed(w, "wav", &note("test-tone", "mj_x", "pav", "t"));
        let p = super::super::vm::parse_wav(&out).unwrap();
        assert_eq!(p.data_len, 4800);
        assert_eq!(u32::from_le_bytes(out[4..8].try_into().unwrap()) as usize, out.len() - 8);
        assert!(String::from_utf8_lossy(&out).contains("ICMT"));
    }
    #[test]
    fn sidecars_scrub_secrets() {
        let s = sidecar("image", "m", "image.generate", &serde_json::json!({ "prompt": "a cat", "references": [{ "asset": "ast_1" }],
            "params": { "api_key": "abc", "note": "use sk-ant-REDACTED0123456789abcdef please", "steps": 4, "hash": "0123456789abcdef0123456789abcdef01" } }), "t", "pav", "mj_x", "image/png");
        assert_eq!(s["version"], 1);
        assert_eq!(s["params"]["prompt"], "a cat");
        assert!(s["params"].get("references").is_none());
        assert_eq!(s["params"]["params"]["api_key"], "[scrubbed]");
        assert_eq!(s["params"]["params"]["note"], "[scrubbed]");
        assert_eq!(s["params"]["params"]["hash"], "[scrubbed]");
        assert_eq!(s["params"]["params"]["steps"], 4);
    }
}
