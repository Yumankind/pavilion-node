//! Google Cast (Chromecast, Nest speakers, Cast TVs): `cast_media` plays one thing on an adopted device, and
//! `media_control` plays, pauses, stops or sets the volume. Cast v2 is small: length-prefixed protobuf `CastMessage`s
//! carrying JSON, over TLS on port 8009. Written here directly (a few dozen lines) rather than pulling a Cast crate.
//!
//! What's cast is either a pavilion URL (https on the Gate's own host, fetched by the device itself) or an asset the
//! node fetched for this action (`…/actions/<act>/asset`) and serves to that one device from this computer, on the LAN,
//! at a random path, for at most 30 minutes.
//!
//! TLS: Cast devices present certificates from Google's Cast CA, not the web's, so the certificate isn't checked
//! against web roots; the address is pinned to the LAN instead (net.rs). Device authentication (the Cast
//! `deviceauth` challenge) isn't done.
use super::super::envelope::External;
use super::net;
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const NS_CONNECTION: &str = "urn:x-cast:com.google.cast.tp.connection";
pub const NS_HEARTBEAT: &str = "urn:x-cast:com.google.cast.tp.heartbeat";
pub const NS_RECEIVER: &str = "urn:x-cast:com.google.cast.receiver";
pub const NS_MEDIA: &str = "urn:x-cast:com.google.cast.media";
/// The Default Media Receiver.
pub const DEFAULT_RECEIVER: &str = "CC1AD845";
const SENDER: &str = "sender-pavilion";
const MAX_MESSAGE: usize = 64 * 1024;
pub const SERVE_FOR: Duration = Duration::from_secs(30 * 60);

/* ---------- CastMessage (protobuf) ---------- */

fn varint(mut n: u64, out: &mut Vec<u8>) { loop { let b = (n & 0x7F) as u8; n >>= 7; if n == 0 { out.push(b); return; } out.push(b | 0x80); } }
fn field_str(tag: u8, s: &str, out: &mut Vec<u8>) { out.push(tag); varint(s.len() as u64, out); out.extend_from_slice(s.as_bytes()); }

/// `CastMessage { protocol_version: CASTV2_1_0, source_id, destination_id, namespace, payload_type: STRING, payload_utf8 }`.
pub fn encode(source: &str, dest: &str, ns: &str, payload: &str) -> Vec<u8> {
    let mut m = vec![0x08, 0x00];
    field_str(0x12, source, &mut m);
    field_str(0x1A, dest, &mut m);
    field_str(0x22, ns, &mut m);
    m.extend([0x28, 0x00]);
    field_str(0x32, payload, &mut m);
    m
}

#[derive(Debug, Default, PartialEq)]
pub struct Msg { pub source: String, pub dest: String, pub ns: String, pub payload: String }

pub fn decode(b: &[u8]) -> Result<Msg, String> {
    let bad = || "the Cast device sent a malformed message".to_string();
    let mut m = Msg::default();
    let mut i = 0;
    let read_varint = |i: &mut usize| -> Result<u64, String> {
        let mut n = 0u64;
        for shift in (0..64).step_by(7) { let x = *b.get(*i).ok_or_else(bad)?; *i += 1; n |= ((x & 0x7F) as u64) << shift; if x & 0x80 == 0 { return Ok(n); } }
        Err(bad())
    };
    while i < b.len() {
        let key = read_varint(&mut i)?;
        match key & 7 {
            0 => { read_varint(&mut i)?; }
            2 => {
                let n = read_varint(&mut i)? as usize;
                let v = b.get(i..i + n).ok_or_else(bad)?;
                i += n;
                let s = || String::from_utf8_lossy(v).to_string();
                match key >> 3 { 2 => m.source = s(), 3 => m.dest = s(), 4 => m.ns = s(), 6 => m.payload = s(), _ => {} }
            }
            _ => return Err(bad()),
        }
    }
    Ok(m)
}

/* ---------- a session ---------- */

pub struct Session<S> { s: S, req: u64 }

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Session<S> {
    pub fn new(s: S) -> Session<S> { Session { s, req: 0 } }
    pub async fn send(&mut self, dest: &str, ns: &str, v: &Value) -> Result<(), String> {
        let m = encode(SENDER, dest, ns, &v.to_string());
        self.s.write_all(&(m.len() as u32).to_be_bytes()).await.map_err(|e| format!("Cast: {e}"))?;
        self.s.write_all(&m).await.map_err(|e| format!("Cast: {e}"))?;
        self.s.flush().await.map_err(|e| format!("Cast: {e}"))
    }
    async fn recv(&mut self) -> Result<Msg, String> {
        let mut len = [0u8; 4];
        self.s.read_exact(&mut len).await.map_err(|e| format!("Cast: {e}"))?;
        let n = u32::from_be_bytes(len) as usize;
        if n > MAX_MESSAGE { return Err("the Cast device sent a message that's too big".into()); }
        let mut b = vec![0u8; n];
        self.s.read_exact(&mut b).await.map_err(|e| format!("Cast: {e}"))?;
        decode(&b)
    }
    fn next_id(&mut self) -> u64 { self.req += 1; self.req }
    /// Waits for a message on `ns` matching `want`, answering heartbeats meanwhile.
    async fn wait(&mut self, ns: &str, timeout: Duration, want: impl Fn(&Value) -> bool) -> Result<Value, String> {
        let end = tokio::time::Instant::now() + timeout;
        loop {
            let m = tokio::time::timeout_at(end, self.recv()).await.map_err(|_| "the Cast device didn't answer in time".to_string())??;
            let v: Value = serde_json::from_str(&m.payload).unwrap_or(Value::Null);
            if m.ns == NS_HEARTBEAT && v["type"] == "PING" { self.send(&m.source, NS_HEARTBEAT, &json!({ "type": "PONG" })).await?; continue; }
            if m.ns == NS_CONNECTION && v["type"] == "CLOSE" { return Err("the Cast device closed the connection".into()); }
            if m.ns == ns && want(&v) { return Ok(v); }
        }
    }
    pub async fn connect(&mut self, dest: &str) -> Result<(), String> { self.send(dest, NS_CONNECTION, &json!({ "type": "CONNECT" })).await }
    pub async fn receiver_status(&mut self) -> Result<Value, String> {
        let id = self.next_id();
        self.send("receiver-0", NS_RECEIVER, &json!({ "type": "GET_STATUS", "requestId": id })).await?;
        self.wait(NS_RECEIVER, Duration::from_secs(10), |v| v["type"] == "RECEIVER_STATUS").await
    }

    /// Opens the Default Media Receiver and loads `url` in it.
    pub async fn play(&mut self, url: &str, content_type: &str, title: &str) -> Result<Value, String> {
        self.connect("receiver-0").await?;
        let id = self.next_id();
        self.send("receiver-0", NS_RECEIVER, &json!({ "type": "LAUNCH", "appId": DEFAULT_RECEIVER, "requestId": id })).await?;
        let st = self.wait(NS_RECEIVER, Duration::from_secs(20), |v| v["type"] == "LAUNCH_ERROR" || (v["type"] == "RECEIVER_STATUS" && app(v, DEFAULT_RECEIVER).is_some())).await?;
        if st["type"] == "LAUNCH_ERROR" { return Err(format!("the Cast device couldn't open its media player ({})", net::clean(st["reason"].as_str().unwrap_or("?"), 60))); }
        let a = app(&st, DEFAULT_RECEIVER).unwrap();
        let (transport, session) = (a["transportId"].as_str().unwrap_or("").to_string(), a["sessionId"].as_str().unwrap_or("").to_string());
        self.connect(&transport).await?;
        let id = self.next_id();
        self.send(&transport, NS_MEDIA, &json!({ "type": "LOAD", "requestId": id, "sessionId": session, "autoplay": true, "currentTime": 0,
            "media": { "contentId": url, "contentType": content_type, "streamType": "BUFFERED", "metadata": { "metadataType": 0, "title": title } } })).await?;
        let r = self.wait(NS_MEDIA, Duration::from_secs(30), |v| ["MEDIA_STATUS", "LOAD_FAILED", "LOAD_CANCELLED", "INVALID_REQUEST"].contains(&v["type"].as_str().unwrap_or("")) && v["requestId"].as_u64().map_or(true, |r| r == id || r == 0)).await?;
        if r["type"] != "MEDIA_STATUS" { return Err(format!("the Cast device didn't play it ({})", r["type"].as_str().unwrap_or("?"))); }
        Ok(json!({ "done": true, "state": r["status"][0]["playerState"] }))
    }

    /// Play, pause, stop or volume (0–100) on whatever the device is playing.
    pub async fn control(&mut self, command: &str, value: Option<f64>) -> Result<Value, String> {
        self.connect("receiver-0").await?;
        let st = self.receiver_status().await?;
        if command == "volume" {
            let level = value.filter(|v| (0.0..=100.0).contains(v)).ok_or("volume needs a value from 0 to 100")? / 100.0;
            let id = self.next_id();
            self.send("receiver-0", NS_RECEIVER, &json!({ "type": "SET_VOLUME", "volume": { "level": level }, "requestId": id })).await?;
            self.wait(NS_RECEIVER, Duration::from_secs(10), |v| v["type"] == "RECEIVER_STATUS").await?;
            return Ok(json!({ "done": true }));
        }
        let a = st["status"]["applications"].as_array().into_iter().flatten()
            .find(|a| a["namespaces"].as_array().map_or(false, |n| n.iter().any(|x| x["name"] == NS_MEDIA))).ok_or("nothing is playing on this Cast device")?;
        let transport = a["transportId"].as_str().unwrap_or("").to_string();
        self.connect(&transport).await?;
        let id = self.next_id();
        self.send(&transport, NS_MEDIA, &json!({ "type": "GET_STATUS", "requestId": id })).await?;
        let ms = self.wait(NS_MEDIA, Duration::from_secs(10), |v| v["type"] == "MEDIA_STATUS").await?;
        let session = ms["status"][0]["mediaSessionId"].as_u64().ok_or("nothing is playing on this Cast device")?;
        let t = match command { "play" => "PLAY", "pause" => "PAUSE", "stop" => "STOP", c => return Err(format!("{c} isn't play, pause, stop or volume")) };
        let id = self.next_id();
        self.send(&transport, NS_MEDIA, &json!({ "type": t, "mediaSessionId": session, "requestId": id })).await?;
        let r = self.wait(NS_MEDIA, Duration::from_secs(10), |v| v["type"] == "MEDIA_STATUS" || v["type"] == "INVALID_REQUEST").await?;
        if r["type"] == "INVALID_REQUEST" { return Err(format!("the Cast device refused {command}")); }
        Ok(json!({ "done": true }))
    }
}

fn app<'a>(status: &'a Value, id: &str) -> Option<&'a Value> { status["status"]["applications"].as_array()?.iter().find(|a| a["appId"] == id) }

/* ---------- TLS ---------- */

#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);
impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(&self, _e: &rustls::pki_types::CertificateDer<'_>, _i: &[rustls::pki_types::CertificateDer<'_>], _n: &rustls::pki_types::ServerName<'_>, _o: &[u8], _t: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> { self.0.signature_verification_algorithms.supported_schemes() }
}

pub async fn open(e: &External) -> Result<(Session<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>, SocketAddr), String> {
    let a = net::parse_addr(&e.address, &["cast", "tcp"], "cast", |_| 8009)?;
    let addr = net::resolve(&a.host, a.port).await?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().map_err(|e| e.to_string())?
        .dangerous().with_custom_certificate_verifier(Arc::new(AnyCert(provider))).with_no_client_auth();
    let tcp = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr)).await.map_err(|_| format!("{} didn't answer on {addr}", e.id))?.map_err(|err| format!("can't reach {}: {err}", e.id))?;
    let tls = tokio::time::timeout(Duration::from_secs(10), tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(rustls::pki_types::ServerName::IpAddress(addr.ip().into()), tcp)).await
        .map_err(|_| "the Cast device's TLS took too long".to_string())?.map_err(|err| format!("TLS with {}: {err}", e.id))?;
    Ok((Session::new(tls), addr))
}

/* ---------- what's cast ---------- */

/// A media type by the first bytes: images, audio and video a Default Media Receiver plays.
pub fn sniff(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(&[0xFF, 0xD8, 0xFF]) { return Some("image/jpeg"); }
    if b.starts_with(b"\x89PNG\r\n\x1a\n") { return Some("image/png"); }
    if b.starts_with(b"GIF8") { return Some("image/gif"); }
    if b.len() > 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WAVE" { return Some("audio/wav"); }
    if b.len() > 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" { return Some("image/webp"); }
    if b.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) { return Some("video/webm"); }
    if b.starts_with(b"OggS") { return Some("audio/ogg"); }
    if b.starts_with(b"ID3") || (b.len() > 1 && b[0] == 0xFF && b[1] & 0xE0 == 0xE0 && b[1] & 0x06 != 0) { return Some("audio/mpeg"); }
    if b.len() > 12 && &b[4..8] == b"ftyp" { return Some(if &b[8..11] == b"M4A" { "audio/mp4" } else { "video/mp4" }); }
    if b.starts_with(&[0xFF, 0xF1]) || b.starts_with(&[0xFF, 0xF9]) { return Some("audio/aac"); }
    None
}

/// A type by a URL's extension.
pub fn type_of_url(url: &str) -> Option<&'static str> {
    let p = url.split(['?', '#']).next().unwrap_or("").to_ascii_lowercase();
    Some(match p.rsplit('.').next()? { "mp4" | "m4v" => "video/mp4", "webm" => "video/webm", "mp3" => "audio/mpeg", "m4a" => "audio/mp4", "aac" => "audio/aac", "wav" => "audio/wav", "ogg" | "oga" => "audio/ogg",
        "jpg" | "jpeg" => "image/jpeg", "png" => "image/png", "gif" => "image/gif", "webp" => "image/webp", "m3u8" => "application/x-mpegURL", _ => return None })
}

/// The local address this computer uses to reach `peer` (no packet is sent).
fn local_ip_for(peer: IpAddr) -> Result<IpAddr, String> {
    let s = std::net::UdpSocket::bind(if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).map_err(|e| e.to_string())?;
    s.connect((peer, 9)).map_err(|e| format!("no route to {peer}: {e}"))?;
    Ok(s.local_addr().map_err(|e| e.to_string())?.ip())
}

/// Serves `bytes` at a random path to `peer` only, on the interface that reaches it, for `SERVE_FOR`. Returns the URL.
pub async fn serve(bytes: Vec<u8>, ctype: &'static str, peer: IpAddr) -> Result<String, String> {
    use http_body_util::Full;
    use hyper::{body::Incoming, Request, Response};
    let ip = local_ip_for(peer)?;
    let l = tokio::net::TcpListener::bind((ip, 0)).await.map_err(|e| format!("can't serve the media: {e}"))?;
    let port = l.local_addr().map_err(|e| e.to_string())?.port();
    let token = crate::signing::random_b64(18);
    let url = format!("{}/{token}", net::origin("http", &ip.to_string(), port));
    let bytes = bytes::Bytes::from(bytes);
    tokio::spawn(async move {
        let end = tokio::time::Instant::now() + SERVE_FOR;
        let mut served = 0;
        while served < 200 {
            let Ok(Ok((s, from))) = tokio::time::timeout_at(end, l.accept()).await else { return };
            if from.ip() != peer { continue; } // only the device the action names
            served += 1;
            let (bytes, token) = (bytes.clone(), token.clone());
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let (bytes, token) = (bytes.clone(), token.clone());
                    async move {
                        let r = Response::builder().header("content-type", ctype).header("accept-ranges", "bytes").header("access-control-allow-origin", "*");
                        if req.uri().path() != format!("/{token}") || !(req.method() == hyper::Method::GET || req.method() == hyper::Method::HEAD) {
                            return Ok::<_, hyper::Error>(Response::builder().status(404).body(Full::new(bytes::Bytes::new())).unwrap());
                        }
                        let n = bytes.len();
                        let range = req.headers().get("range").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("bytes=")).and_then(|v| v.split_once('-'))
                            .and_then(|(a, b)| { let a: usize = a.parse().ok()?; let b: usize = if b.is_empty() { n.saturating_sub(1) } else { b.parse::<usize>().ok()?.min(n.saturating_sub(1)) }; (a <= b && a < n).then_some((a, b)) });
                        let head = req.method() == hyper::Method::HEAD;
                        Ok(match range {
                            Some((a, b)) => r.status(206).header("content-range", format!("bytes {a}-{b}/{n}")).header("content-length", b - a + 1).body(Full::new(if head { bytes::Bytes::new() } else { bytes.slice(a..=b) })).unwrap(),
                            None => r.status(200).header("content-length", n).body(Full::new(if head { bytes::Bytes::new() } else { bytes })).unwrap(),
                        })
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
            });
        }
    });
    Ok(url)
}

/// `cast_media`: a pavilion URL as is, or the action's asset served from here to the device.
pub async fn cast(e: &External, url: Option<&str>, asset: Option<Vec<u8>>, content_type: Option<&str>, title: &str) -> Result<Value, String> {
    let (mut s, addr) = open(e).await?;
    let (url, ctype) = match (url, asset) {
        (Some(u), _) => (u.to_string(), content_type.or_else(|| type_of_url(u)).ok_or("say the media's content_type (its address has no known extension)")?.to_string()),
        (None, Some(b)) => { let t = sniff(&b).ok_or("the asset isn't an image, sound or video a Cast device plays")?; (serve(b, t, addr.ip()).await?, t.to_string()) }
        (None, None) => return Err("cast_media takes an asset or a pavilion URL".into()),
    };
    s.play(&url, &ctype, title).await
}

pub async fn control(e: &External, command: &str, value: Option<f64>) -> Result<Value, String> {
    let (mut s, _) = open(e).await?;
    s.control(command, value).await
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn messages_round_trip() {
        let b = encode("sender-0", "receiver-0", NS_CONNECTION, r#"{"type":"CONNECT"}"#);
        assert_eq!(&b[..4], &[0x08, 0x00, 0x12, 0x08]);
        assert_eq!(decode(&b).unwrap(), Msg { source: "sender-0".into(), dest: "receiver-0".into(), ns: NS_CONNECTION.into(), payload: r#"{"type":"CONNECT"}"#.into() });
        let long = "x".repeat(300); // a two-byte length
        assert_eq!(decode(&encode("a", "b", "c", &long)).unwrap().payload, long);
        assert!(decode(&[0x12, 0x50, 0x41]).is_err());
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n...."), Some("image/png"));
        assert_eq!(sniff(b"\0\0\0\x20ftypisom...."), Some("video/mp4"));
        assert_eq!(sniff(b"ID3\x04"), Some("audio/mpeg"));
        assert_eq!(sniff(b"%PDF"), None);
        assert_eq!(type_of_url("https://gate.example/p/a/media/x.mp3?t=1"), Some("audio/mpeg"));
    }

    /// A Cast receiver over TLS (a self-signed certificate, as real devices' aren't web certificates): launches the
    /// Default Media Receiver, loads media, plays and pauses, sets the volume. Records what it was asked.
    pub async fn receiver(log: Arc<std::sync::Mutex<Vec<Value>>>) -> String {
        use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
        let cert = CertificateDer::from_pem_slice(include_bytes!("testdata/cast-cert.pem")).unwrap();
        let key = PrivateKeyDer::from_pem_slice(include_bytes!("testdata/cast-key.pem")).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().unwrap()
            .with_no_client_auth().with_single_cert(vec![cert], key).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let launched = Arc::new(std::sync::atomic::AtomicBool::new(false));
            loop {
                let Ok((tcp, _)) = l.accept().await else { return };
                let (acceptor, log, launched) = (acceptor.clone(), log.clone(), launched.clone());
                tokio::spawn(async move {
                    let Ok(mut s) = acceptor.accept(tcp).await else { return };
                    // A heartbeat first, which the sender must answer.
                    let ping = encode("receiver-0", SENDER, NS_HEARTBEAT, r#"{"type":"PING"}"#);
                    let _ = s.write_all(&[(ping.len() as u32).to_be_bytes().to_vec(), ping].concat()).await;
                    loop {
                        let mut len = [0u8; 4];
                        if s.read_exact(&mut len).await.is_err() { return; }
                        let mut b = vec![0u8; u32::from_be_bytes(len) as usize];
                        if s.read_exact(&mut b).await.is_err() { return; }
                        let m = decode(&b).unwrap();
                        let v: Value = serde_json::from_str(&m.payload).unwrap();
                        log.lock().unwrap().push(json!({ "ns": m.ns, "dest": m.dest, "msg": v }));
                        let status = |l: bool| json!({ "type": "RECEIVER_STATUS", "requestId": v["requestId"], "status": { "volume": { "level": 0.5 }, "applications": if l { json!([{ "appId": DEFAULT_RECEIVER, "transportId": "web-7", "sessionId": "sess-1", "namespaces": [{ "name": NS_MEDIA }] }]) } else { json!([]) } } });
                        let reply = match (m.ns.as_str(), v["type"].as_str().unwrap_or("")) {
                            (NS_RECEIVER, "LAUNCH") => { launched.store(true, std::sync::atomic::Ordering::SeqCst); Some((NS_RECEIVER, status(true))) }
                            (NS_RECEIVER, "GET_STATUS") | (NS_RECEIVER, "SET_VOLUME") => Some((NS_RECEIVER, status(launched.load(std::sync::atomic::Ordering::SeqCst)))),
                            (NS_MEDIA, "LOAD") => Some((NS_MEDIA, json!({ "type": "MEDIA_STATUS", "requestId": v["requestId"], "status": [{ "mediaSessionId": 1, "playerState": "BUFFERING" }] }))),
                            (NS_MEDIA, "GET_STATUS") | (NS_MEDIA, "PLAY") | (NS_MEDIA, "PAUSE") | (NS_MEDIA, "STOP") => Some((NS_MEDIA, json!({ "type": "MEDIA_STATUS", "requestId": v["requestId"], "status": [{ "mediaSessionId": 1, "playerState": "PLAYING" }] }))),
                            _ => None,
                        };
                        if let Some((ns, r)) = reply {
                            let out = encode(&m.dest, &m.source, ns, &r.to_string());
                            if s.write_all(&[(out.len() as u32).to_be_bytes().to_vec(), out].concat()).await.is_err() { return; }
                        }
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn cast_an_asset_then_pause_and_set_the_volume() {
        let log = Arc::new(std::sync::Mutex::new(vec![]));
        let addr = receiver(log.clone()).await;
        let e = External { id: "ext_tv".into(), name: "Living room TV".into(), kind: "cast".into(), address: addr, ..Default::default() };
        let png = b"\x89PNG\r\n\x1a\nnot really a picture".to_vec();
        assert_eq!(cast(&e, None, Some(png.clone()), None, "Chart").await.unwrap(), json!({ "done": true, "state": "BUFFERING" }));
        let load = log.lock().unwrap().iter().find(|m| m["msg"]["type"] == "LOAD").cloned().unwrap();
        assert_eq!((load["dest"].as_str(), load["msg"]["media"]["contentType"].as_str(), load["msg"]["sessionId"].as_str()), (Some("web-7"), Some("image/png"), Some("sess-1")));
        assert!(log.lock().unwrap().iter().any(|m| m["msg"]["type"] == "PONG"));
        // The device (here: this test, from 127.0.0.1) fetches the asset from the node, with ranges.
        let url = load["msg"]["media"]["contentId"].as_str().unwrap().to_string();
        let r = reqwest::Client::new().get(&url).header("range", "bytes=0-3").send().await.unwrap();
        assert_eq!(r.status().as_u16(), 206);
        assert_eq!(r.bytes().await.unwrap().as_ref(), &png[..4]);
        assert_eq!(reqwest::get(format!("{}x", url)).await.unwrap().status().as_u16(), 404);
        assert_eq!(control(&e, "pause", None).await.unwrap(), json!({ "done": true }));
        assert!(log.lock().unwrap().iter().any(|m| m["msg"]["type"] == "PAUSE" && m["msg"]["mediaSessionId"] == 1));
        assert_eq!(control(&e, "volume", Some(30.0)).await.unwrap(), json!({ "done": true }));
        assert!(log.lock().unwrap().iter().any(|m| m["msg"]["type"] == "SET_VOLUME" && m["msg"]["volume"]["level"] == 0.3));
        assert!(control(&e, "volume", Some(130.0)).await.is_err());
        // A pavilion URL is passed as is.
        cast(&e, Some("https://gate.example/p/acme/share/x.mp3"), None, None, "Song").await.unwrap();
        assert!(log.lock().unwrap().iter().any(|m| m["msg"]["media"]["contentType"] == "audio/mpeg"));
    }
}
