//! IP cameras (ONVIF / RTSP): `camera_snapshot` with `external` asks the camera for its snapshot address through ONVIF
//! (`GetCapabilities` → `GetProfiles` → `GetSnapshotUri`, SOAP with a WS-UsernameToken digest), then fetches one
//! JPEG with HTTP digest (or basic) auth. The login is a secret lent to this host. A camera whose adoption lists a
//! `GET` path (`/snapshot.jpg`, many cameras have one) is fetched there directly, without ONVIF.
//!
//! Everything goes to the adopted camera's own address: the host in the URIs a camera returns is replaced by the
//! adopted one (cameras often report an internal address), so a camera can't point the node somewhere else.
//! The photo's metadata segments (EXIF and the like) are removed before it's shown and sent.
use super::super::envelope::External;
use super::lent::Secret;
use super::net;
use base64::Engine;
use sha1::{Digest, Sha1};
use std::time::Duration;

pub const MAX_SNAPSHOT: usize = 10 << 20;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// `YYYY-MM-DDThh:mm:ssZ` for a Unix time.
pub fn utc(t: u64) -> String {
    let days = (t / 86_400) as i64;
    let s = t % 86_400;
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60)
}

/// WS-UsernameToken PasswordDigest: Base64(SHA-1(nonce ‖ created ‖ password)).
pub fn password_digest(nonce: &[u8], created: &str, password: &str) -> String {
    let mut h = Sha1::new();
    h.update(nonce);
    h.update(created.as_bytes());
    h.update(password.as_bytes());
    B64.encode(h.finalize())
}

fn xml_escape(s: &str) -> String { s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;") }

/// A SOAP 1.2 envelope, with a WS-Security UsernameToken when there's a login.
pub fn envelope(body: &str, login: Option<(&str, &str)>, nonce: &[u8], created: &str) -> String {
    let header = match login {
        Some((u, p)) => format!(concat!(
            r#"<s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">"#,
            r#"<UsernameToken><Username>{}</Username>"#,
            r#"<Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{}</Password>"#,
            r#"<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{}</Nonce>"#,
            r#"<Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{}</Created>"#,
            r#"</UsernameToken></Security></s:Header>"#), xml_escape(u), password_digest(nonce, created, p), B64.encode(nonce), created),
        None => String::new(),
    };
    format!(r#"<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">{header}<s:Body>{body}</s:Body></s:Envelope>"#)
}

pub const GET_CAPABILITIES: &str = r#"<GetCapabilities xmlns="http://www.onvif.org/ver10/device/wsdl"><Category>Media</Category></GetCapabilities>"#;
pub const GET_PROFILES: &str = r#"<GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>"#;
pub fn get_snapshot_uri(token: &str) -> String { format!(r#"<GetSnapshotUri xmlns="http://www.onvif.org/ver10/media/wsdl"><ProfileToken>{}</ProfileToken></GetSnapshotUri>"#, xml_escape(token)) }

/// The text of each element named `local` (any namespace prefix), in order.
pub fn texts(xml: &str, local: &str) -> Vec<String> {
    let mut out = vec![];
    let mut rest = xml;
    while let Some(i) = rest.find('<') {
        rest = &rest[i + 1..];
        let end = rest.find(|c: char| c == '>' || c.is_whitespace() || c == '/').unwrap_or(rest.len());
        let name = &rest[..end];
        if name.rsplit(':').next() == Some(local) && !name.starts_with('/') {
            let Some(gt) = rest.find('>') else { break };
            if rest[..gt].ends_with('/') { continue; }
            let body = &rest[gt + 1..];
            if let Some(close) = body.find("</") { out.push(body[..close].trim().replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'")); }
        }
    }
    out
}
/// The value of `attr` on each element named `local`.
pub fn attrs(xml: &str, local: &str, attr: &str) -> Vec<String> {
    let mut out = vec![];
    let mut rest = xml;
    while let Some(i) = rest.find('<') {
        rest = &rest[i + 1..];
        let end = rest.find(|c: char| c == '>' || c.is_whitespace() || c == '/').unwrap_or(rest.len());
        if rest[..end].rsplit(':').next() != Some(local) { continue; }
        let tag = &rest[..rest.find('>').unwrap_or(rest.len())];
        for quote in ['"', '\''] {
            if let Some(j) = tag.find(&format!(" {attr}={quote}")) {
                let v = &tag[j + attr.len() + 3..];
                if let Some(k) = v.find(quote) { out.push(v[..k].to_string()); }
            }
        }
    }
    out
}

/// `scheme://host[:port]/path?query` → (port, path with query). The host is dropped (the adopted one is used).
pub fn path_of(uri: &str, default_port: u16) -> Option<(u16, String)> {
    let (scheme, rest) = uri.trim().split_once("://")?;
    if scheme != "http" { return None; }
    let (hostport, path) = match rest.find('/') { Some(i) => (&rest[..i], &rest[i..]), None => (rest, "/") };
    let port = match hostport.strip_prefix('[') {
        Some(r) => r.split_once("]:").map(|(_, p)| p),
        None => hostport.rsplit_once(':').map(|(_, p)| p),
    };
    let port = match port { Some(p) => p.parse().ok()?, None => default_port };
    (!path.chars().any(|c| c.is_whitespace() || c.is_control())).then(|| (port, path.to_string()))
}

/// `WWW-Authenticate: Digest realm="…", nonce="…", qop="auth", opaque="…", algorithm=MD5` → its parameters.
pub fn challenge(h: &str) -> Option<(String, std::collections::BTreeMap<String, String>)> {
    let h = h.trim();
    let (scheme, rest) = h.split_once(' ').unwrap_or((h, ""));
    let mut m = std::collections::BTreeMap::new();
    let mut s = rest.trim();
    while !s.is_empty() {
        let Some(eq) = s.find('=') else { break };
        let k = s[..eq].trim().trim_start_matches(',').trim().to_ascii_lowercase();
        s = s[eq + 1..].trim_start();
        let v;
        if let Some(r) = s.strip_prefix('"') {
            let mut out = String::new();
            let mut chars = r.char_indices();
            let mut end = r.len();
            while let Some((i, c)) = chars.next() {
                if c == '\\' { if let Some((_, n)) = chars.next() { out.push(n); } continue; }
                if c == '"' { end = i + 1; break; }
                out.push(c);
            }
            v = out;
            s = r[end..].trim_start().trim_start_matches(',').trim_start();
        } else {
            let e = s.find(',').unwrap_or(s.len());
            v = s[..e].trim().to_string();
            s = s[e..].trim_start_matches(',').trim_start();
        }
        m.insert(k, v);
    }
    Some((scheme.to_ascii_lowercase(), m))
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

/// The `Authorization: Digest …` answer to a challenge (RFC 7616: MD5 or SHA-256, qop `auth` or none).
pub fn digest_header(ch: &std::collections::BTreeMap<String, String>, user: &str, pass: &str, method: &str, uri: &str, cnonce: &str, nc: u32) -> Result<String, String> {
    let alg = ch.get("algorithm").map(|a| a.to_ascii_uppercase()).unwrap_or_else(|| "MD5".into());
    let h = |s: &str| -> String { if alg == "SHA-256" { hex(&sha2::Sha256::digest(s.as_bytes())) } else { hex(&md5::Md5::digest(s.as_bytes())) } };
    if alg != "MD5" && alg != "SHA-256" { return Err(format!("the camera asks for digest {alg}, which the node doesn't do")); }
    let (realm, nonce) = (ch.get("realm").cloned().unwrap_or_default(), ch.get("nonce").ok_or("the camera's challenge has no nonce")?.clone());
    let ha1 = h(&format!("{user}:{realm}:{pass}"));
    let ha2 = h(&format!("{method}:{uri}"));
    let qop = ch.get("qop").map(|q| q.split(',').map(str::trim).any(|x| x == "auth")).unwrap_or(false);
    let nc = format!("{nc:08x}");
    let response = if qop { h(&format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")) } else { h(&format!("{ha1}:{nonce}:{ha2}")) };
    let q = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let mut out = format!(r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", algorithm={alg}, response="{response}""#, q(user), q(&realm), q(&nonce), q(uri));
    if qop { out.push_str(&format!(r#", qop=auth, nc={nc}, cnonce="{cnonce}""#)); }
    if let Some(o) = ch.get("opaque") { out.push_str(&format!(r#", opaque="{}""#, q(o))); }
    Ok(out)
}

/// Removes metadata from a JPEG: APP1–APP15 (EXIF, XMP, maker notes) and comments. The image data is unchanged.
pub fn strip_metadata(jpeg: &[u8]) -> Result<Vec<u8>, String> {
    if !jpeg.starts_with(&[0xFF, 0xD8]) { return Err("the camera didn't send a JPEG".into()); }
    let mut out = vec![0xFF, 0xD8];
    let mut i = 2;
    while i + 4 <= jpeg.len() {
        if jpeg[i] != 0xFF { return Err("the camera's JPEG is malformed".into()); }
        let m = jpeg[i + 1];
        if m == 0xDA { out.extend_from_slice(&jpeg[i..]); return Ok(out); } // start of scan: the rest is image data
        if m == 0xFF { i += 1; continue; }
        if (0xD0..=0xD7).contains(&m) || m == 0x01 { out.extend_from_slice(&jpeg[i..i + 2]); i += 2; continue; }
        let len = u16::from_be_bytes([jpeg[i + 2], jpeg[i + 3]]) as usize;
        if len < 2 || i + 2 + len > jpeg.len() { return Err("the camera's JPEG is malformed".into()); }
        if !((0xE1..=0xEF).contains(&m) || m == 0xFE) { out.extend_from_slice(&jpeg[i..i + 2 + len]); }
        i += 2 + len;
    }
    Err("the camera's JPEG has no image data".into())
}

struct Cam { http: reqwest::Client, origin: String, host: String, port: u16, login: Option<(String, zeroize::Zeroizing<String>)> }

impl Cam {
    async fn soap(&self, path: &str, body: &str) -> Result<String, String> {
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let created = utc(super::super::now());
        let env = envelope(body, self.login.as_ref().map(|(u, p)| (u.as_str(), p.as_str())), &nonce, &created);
        let r = self.http.post(format!("{}{path}", self.origin)).header("content-type", "application/soap+xml; charset=utf-8").body(env).send().await
            .map_err(|e| format!("the camera didn't answer: {e}"))?;
        let st = r.status().as_u16();
        let text = String::from_utf8_lossy(&net::body_capped(r, 1 << 20, "the camera's answer").await?).to_string();
        if st == 401 || text.contains("NotAuthorized") { return Err("the camera refused the lent login".into()); }
        if !(200..300).contains(&st) { return Err(format!("the camera answered {st}: {}", net::clean(&texts(&text, "Text").join(" "), 200))); }
        Ok(text)
    }

    /// The snapshot path: ONVIF media service → first (or named) profile → its snapshot URI, on the adopted host.
    async fn snapshot_path(&self, profile: Option<&str>) -> Result<(u16, String), String> {
        let caps = self.soap("/onvif/device_service", GET_CAPABILITIES).await?;
        let media = texts(&caps, "XAddr").into_iter().find(|x| x.contains("media") || x.contains("Media")).or_else(|| texts(&caps, "XAddr").into_iter().next())
            .and_then(|x| path_of(&x, self.port)).map(|(_, p)| p).unwrap_or_else(|| "/onvif/media_service".into());
        let profiles = attrs(&self.soap(&media, GET_PROFILES).await?, "Profiles", "token");
        let token = match profile { Some(p) => profiles.iter().find(|t| *t == p).cloned().ok_or_else(|| format!("the camera has no profile {p}"))?, None => profiles.first().cloned().ok_or("the camera has no media profiles")? };
        let uri = texts(&self.soap(&media, &get_snapshot_uri(&token)).await?, "Uri").into_iter().next().ok_or("the camera has no snapshot address (it may only stream over RTSP)")?;
        path_of(&uri, 80).ok_or_else(|| format!("the camera's snapshot address isn't plain http ({})", net::clean(&uri, 120)))
    }

    async fn fetch(&self, port: u16, path: &str) -> Result<Vec<u8>, String> {
        let addr = net::resolve(&self.host, port).await?;
        let http = net::client(&self.host, addr, Duration::from_secs(20), false)?;
        let url = format!("{}{path}", net::origin("http", &self.host, port));
        let r = http.get(&url).send().await.map_err(|e| format!("the camera didn't send the photo: {e}"))?;
        let r = if r.status().as_u16() == 401 {
            let (u, p) = self.login.as_ref().ok_or("the camera wants a login and its adoption lends none")?;
            let h = r.headers().get_all("www-authenticate").iter().filter_map(|v| v.to_str().ok()).map(String::from).collect::<Vec<_>>();
            let auth = if let Some((_, ch)) = h.iter().filter_map(|x| challenge(x)).find(|(s, _)| s == "digest") {
                let mut cn = [0u8; 8];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut cn);
                digest_header(&ch, u, p, "GET", path, &hex(&cn), 1)?
            } else if h.iter().any(|x| x.to_ascii_lowercase().starts_with("basic")) {
                format!("Basic {}", B64.encode(format!("{u}:{}", p.as_str())))
            } else { return Err("the camera asks for a login the node can't give".into()) };
            http.get(&url).header("authorization", auth).send().await.map_err(|e| format!("the camera didn't send the photo: {e}"))?
        } else { r };
        match r.status().as_u16() {
            200 => {}
            401 | 403 => return Err("the camera refused the lent login".into()),
            s => return Err(format!("the camera answered {s} for the photo")),
        }
        net::body_capped(r, MAX_SNAPSHOT, "the photo").await
    }
}

pub async fn snapshot(e: &External, secret: Option<&Secret>, profile: Option<&str>) -> Result<Vec<u8>, String> {
    let a = net::parse_addr(&e.address, &["http"], "http", |_| 80)?;
    let addr = net::resolve(&a.host, a.port).await?;
    let cam = Cam { http: net::client(&a.host, addr, Duration::from_secs(15), false)?, origin: net::origin("http", &a.host, a.port), host: a.host.clone(), port: a.port,
        login: secret.map(|s| s.login()).transpose()? };
    let (port, path) = match e.paths.iter().find(|p| p.method == "GET") {
        Some(p) => (a.port, p.path.clone()),
        None => cam.snapshot_path(profile).await?,
    };
    strip_metadata(&cam.fetch(port, &path).await?)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn username_token_digest() {
        // Fixed inputs; the expected value is Base64(SHA-1(nonce ‖ created ‖ password)) computed independently
        // (Python: base64.b64encode(hashlib.sha1(nonce + created + password).digest())).
        let nonce = b"0123456789abcdef";
        assert_eq!(password_digest(nonce, "2026-11-13T09:30:00Z", "pass"), "5T8FfbHHvwWogmwAcoaHamatqOE=");
        let env = envelope(GET_PROFILES, Some(("admin", "pass")), nonce, "2026-11-13T09:30:00Z");
        assert_eq!(texts(&env, "Username"), vec!["admin"]);
        assert_eq!(texts(&env, "Password"), vec!["5T8FfbHHvwWogmwAcoaHamatqOE="]);
        assert_eq!(texts(&env, "Nonce"), vec!["MDEyMzQ1Njc4OWFiY2RlZg=="]);
        assert!(env.contains("<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>"));
        assert!(!envelope(GET_PROFILES, None, nonce, "x").contains("Security"));
        assert_eq!(utc(1_794_562_200), "2026-11-13T09:30:00Z");
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn digest_header_rfc_2617_example() {
        // RFC 2617 §3.5: Mufasa / "Circle Of Life", GET /dir/index.html.
        let (_, ch) = challenge(r#"Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#).unwrap();
        let h = digest_header(&ch, "Mufasa", "Circle Of Life", "GET", "/dir/index.html", "0a4f113b", 1).unwrap();
        assert!(h.contains(r#"response="6629fae49393a05397450978507c4ef1""#), "{h}");
        assert!(h.contains("qop=auth, nc=00000001, cnonce=\"0a4f113b\"") && h.contains(r#"opaque="5ccc069c403ebaf9f0171e9517f40e41""#));
        let (_, ch) = challenge(r#"Digest realm="r", nonce="n", algorithm=SHA-512"#).unwrap();
        assert!(digest_header(&ch, "u", "p", "GET", "/", "c", 1).is_err());
    }

    #[test]
    fn soap_answers_and_jpeg_metadata() {
        let caps = r#"<env:Envelope><env:Body><tds:GetCapabilitiesResponse><tds:Capabilities><tt:Media><tt:XAddr>http://10.0.0.9/onvif/Media</tt:XAddr></tt:Media></tds:Capabilities></tds:GetCapabilitiesResponse></env:Body></env:Envelope>"#;
        assert_eq!(texts(caps, "XAddr"), vec!["http://10.0.0.9/onvif/Media"]);
        assert_eq!(attrs(r#"<trt:Profiles fixed="true" token="Profile_1"><tt:Name>main</tt:Name></trt:Profiles><trt:Profiles token='sub'>"#, "Profiles", "token"), vec!["Profile_1", "sub"]);
        assert_eq!(path_of("http://192.168.1.20:8080/onvif-http/snapshot?Profile_1&amp;x", 80), Some((8080, "/onvif-http/snapshot?Profile_1&amp;x".into())));
        assert_eq!(path_of("http://cam/snap.jpg", 80), Some((80, "/snap.jpg".into())));
        assert_eq!(path_of("rtsp://cam/stream", 80), None);
        // SOI, APP0 (kept), APP1 EXIF (removed), COM (removed), DQT (kept), SOS…
        let jpeg = [&[0xFF, 0xD8][..], &[0xFF, 0xE0, 0, 4, 1, 2], &[0xFF, 0xE1, 0, 6, b'E', b'x', b'i', b'f'], &[0xFF, 0xFE, 0, 3, b'c'], &[0xFF, 0xDB, 0, 3, 9], &[0xFF, 0xDA, 0, 2, 7, 7, 0xFF, 0xD9]].concat();
        assert_eq!(strip_metadata(&jpeg).unwrap(), [&[0xFF, 0xD8][..], &[0xFF, 0xE0, 0, 4, 1, 2], &[0xFF, 0xDB, 0, 3, 9], &[0xFF, 0xDA, 0, 2, 7, 7, 0xFF, 0xD9]].concat());
        assert!(strip_metadata(b"<html>").is_err());
    }

    /// An ONVIF camera: device and media services checking the UsernameToken, and a snapshot behind digest auth.
    pub async fn camera(user: &'static str, pass: &'static str) -> String {
        use http_body_util::{BodyExt, Full};
        use hyper::{body::Incoming, Request, Response};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { return };
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| async move {
                        let port = port;
                        let path = req.uri().path_and_query().map(|p| p.to_string()).unwrap_or_default();
                        let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).map(String::from);
                        let body = String::from_utf8_lossy(&req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default()).to_string();
                        let r = |code: u16, ctype: &str, b: Vec<u8>, www: Option<&str>| {
                            let mut x = Response::builder().status(code).header("content-type", ctype);
                            if let Some(w) = www { x = x.header("www-authenticate", w); }
                            Ok::<_, hyper::Error>(x.body(Full::new(bytes::Bytes::from(b))).unwrap())
                        };
                        if path.starts_with("/onvif/") {
                            // The UsernameToken, checked as a camera does.
                            let nonce = B64.decode(texts(&body, "Nonce").first().cloned().unwrap_or_default()).unwrap_or_default();
                            let created = texts(&body, "Created").first().cloned().unwrap_or_default();
                            let good = texts(&body, "Username").first().map(|u| u == user).unwrap_or(false) && texts(&body, "Password").first() == Some(&password_digest(&nonce, &created, pass));
                            if !good { return r(400, "application/soap+xml", b"<s:Fault><s:Code><s:Subcode><s:Value>ter:NotAuthorized</s:Value></s:Subcode></s:Code></s:Fault>".to_vec(), None); }
                            let out = if body.contains("GetCapabilities") { "<tt:Media><tt:XAddr>http://10.9.9.9/onvif/Media</tt:XAddr></tt:Media>".to_string() }
                                else if body.contains("GetProfiles") { r#"<trt:Profiles token="main" fixed="true"></trt:Profiles>"#.to_string() }
                                else if body.contains("<ProfileToken>main</ProfileToken>") { format!("<trt:MediaUri><tt:Uri>http://10.9.9.9:{port}/cgi/snap.jpg?ch=1</tt:Uri></trt:MediaUri>") }
                                else { return r(400, "text/plain", vec![], None) };
                            return r(200, "application/soap+xml", out.into_bytes(), None);
                        }
                        if path == "/cgi/snap.jpg?ch=1" {
                            let ch = r#"Digest realm="cam", qop="auth", nonce="abc123", opaque="op""#;
                            let Some(a) = auth else { return r(401, "text/plain", vec![], Some(ch)) };
                            let (_, got) = challenge(&a).unwrap();
                            let (_, c) = challenge(ch).unwrap();
                            let want = digest_header(&c, user, pass, "GET", "/cgi/snap.jpg?ch=1", got.get("cnonce").map(|s| s.as_str()).unwrap_or(""), 1).unwrap();
                            if challenge(&want).unwrap().1.get("response") != got.get("response") { return r(401, "text/plain", vec![], Some(ch)); }
                            let jpeg = [&[0xFF, 0xD8][..], &[0xFF, 0xE1, 0, 6, b'E', b'x', b'i', b'f'], &[0xFF, 0xDA, 0, 2, 1, 2, 0xFF, 0xD9]].concat();
                            return r(200, "image/jpeg", jpeg, None);
                        }
                        r(404, "text/plain", vec![], None)
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn a_snapshot_through_onvif_and_digest_auth() {
        let addr = camera("viewer", "s3cret").await;
        let e = External { id: "ext_door".into(), kind: "camera".into(), address: addr.clone(), secret: Some("DOOR_CAM".into()), ..Default::default() };
        let jpeg = snapshot(&e, Some(&Secret::new("DOOR_CAM", "viewer:s3cret")), None).await.unwrap();
        assert_eq!(jpeg, [&[0xFF, 0xD8][..], &[0xFF, 0xDA, 0, 2, 1, 2, 0xFF, 0xD9]].concat()); // EXIF gone
        assert!(snapshot(&e, Some(&Secret::new("DOOR_CAM", "viewer:wrong")), None).await.unwrap_err().contains("refused the lent login"));
        assert!(snapshot(&e, Some(&Secret::new("DOOR_CAM", "viewer:s3cret")), Some("sub")).await.unwrap_err().contains("no profile sub"));
    }
}
