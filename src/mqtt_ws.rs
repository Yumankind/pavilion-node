//! MQTT 3.1.1 over a WebSocket (docs/IOT.md §20f), for the node's bridge: a broker reachable only as
//! `ws://host:port/path` or `wss://…` — Mosquitto's `protocol websockets` listener, EMQX's and HiveMQ's 8083/8084.
//!
//! rumqttc can speak this only with its `websocket` feature, whose crates aren't in this tree (and the tests run
//! offline), so this is the little the bridge needs, over tokio-tungstenite, which the node already has: CONNECT with
//! the login, SUBSCRIBE at QoS 0, PUBLISH in, PINGREQ to keep it alive. It never publishes. The socket asks for the
//! `mqtt` subprotocol (MQTT 3.1.1 §6) and every packet goes in binary frames; packets may span frames, or share one.
//!
//! The TCP connection goes to the address the bridge already checked is this machine or the LAN (never a second
//! lookup), while the request — its Host and, for wss://, the name in the certificate it checks — keeps the name the
//! person gave. wss:// checks the certificate against the web's roots, or against the CA file the person named for a
//! broker with its own; never unchecked.
use anyhow::{anyhow, bail, Context, Result};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, protocol::WebSocketConfig, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// The biggest packet the bridge takes; a Tasmota or zigbee2mqtt message is a few hundred bytes.
pub const MAX_PACKET: usize = 64 * 1024;

fn string(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut v = Vec::with_capacity(b.len() + 2);
    v.extend_from_slice(&(b.len() as u16).to_be_bytes());
    v.extend_from_slice(b);
    v
}

fn packet(first: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![first];
    let mut n = body.len();
    loop {
        let mut b = (n % 128) as u8;
        n /= 128;
        if n > 0 { b |= 0x80; }
        v.push(b);
        if n == 0 { break; }
    }
    v.extend_from_slice(body);
    v
}

/// CONNECT: MQTT 3.1.1, a clean session, the login when there is one.
pub fn connect_packet(client_id: &str, login: Option<(&str, &str)>, keepalive_s: u16) -> Vec<u8> {
    let mut body = string("MQTT");
    body.push(4);
    body.push(0x02 | if login.is_some() { 0xC0 } else { 0 });
    body.extend_from_slice(&keepalive_s.to_be_bytes());
    body.extend(string(client_id));
    if let Some((u, p)) = login { body.extend(string(u)); body.extend(string(p)); }
    packet(0x10, &body)
}

/// SUBSCRIBE to `filters`, each at QoS 0 (so the broker never asks for an acknowledgement back).
pub fn subscribe_packet(pid: u16, filters: &[String]) -> Vec<u8> {
    let mut body = pid.to_be_bytes().to_vec();
    for f in filters { body.extend(string(f)); body.push(0); }
    packet(0x82, &body)
}

pub const PINGREQ: [u8; 2] = [0xC0, 0];

#[derive(Debug, PartialEq)]
pub enum Packet { ConnAck(u8), SubAck(u16, Vec<u8>), Publish(String, Vec<u8>), PingResp, Other(u8) }

/// One whole packet from the front of `buf`, if one is there yet (it is taken out); an error for a malformed one.
pub fn take(buf: &mut Vec<u8>) -> Result<Option<Packet>> {
    if buf.len() < 2 { return Ok(None); }
    let (mut n, mut mul, mut i) = (0usize, 1usize, 1usize);
    loop {
        let Some(&b) = buf.get(i) else { return Ok(None) };
        n += (b & 0x7F) as usize * mul;
        i += 1;
        if b & 0x80 == 0 { break; }
        mul *= 128;
        if i > 4 { bail!("a malformed MQTT length"); }
    }
    if n > MAX_PACKET { bail!("an MQTT packet over {} KB", MAX_PACKET / 1024); }
    if buf.len() < i + n { return Ok(None); }
    let first = buf[0];
    let body: Vec<u8> = buf[i..i + n].to_vec();
    buf.drain(..i + n);
    let short = || anyhow!("a short MQTT packet");
    Ok(Some(match first >> 4 {
        2 => Packet::ConnAck(*body.get(1).ok_or_else(short)?),
        9 => { if body.len() < 2 { return Err(short()); } Packet::SubAck(u16::from_be_bytes([body[0], body[1]]), body[2..].to_vec()) }
        3 => {
            if body.len() < 2 { return Err(short()); }
            let tl = u16::from_be_bytes([body[0], body[1]]) as usize;
            let mut at = 2 + tl;
            if body.len() < at { return Err(short()); }
            let topic = String::from_utf8_lossy(&body[2..at]).into_owned();
            if (first >> 1) & 3 > 0 { at += 2; }   // a packet id: only with QoS 1 or 2, which a QoS 0 subscription never gets
            if body.len() < at { return Err(short()); }
            Packet::Publish(topic, body[at..].to_vec())
        }
        13 => Packet::PingResp,
        k => Packet::Other(k),
    }))
}

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// One connection to a broker over a WebSocket, connected, logged in and subscribed.
pub struct Session { tx: SplitSink<Ws, Message>, rx: SplitStream<Ws>, buf: Vec<u8> }

/// A TLS connector for wss:// that trusts the roots in a PEM file (a LAN broker with a certificate of its own).
fn connector(ca_pem: &[u8]) -> Result<tokio_tungstenite::Connector> {
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(ca_pem) { roots.add(c.context("the CA file")?).context("the CA file")?; }
    if roots.is_empty() { bail!("the CA file holds no certificate"); }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions()?.with_root_certificates(roots).with_no_client_auth();
    Ok(tokio_tungstenite::Connector::Rustls(Arc::new(cfg)))
}

impl Session {
    /// Opens `url` (ws:// or wss://) over a TCP connection to `addr`, the address already checked, and logs in.
    pub async fn open(url: &str, addr: SocketAddr, ca_pem: Option<&[u8]>, client_id: &str, login: Option<(&str, &str)>, keepalive_s: u16) -> Result<Session> {
        let mut req = url.into_client_request().context("the broker's address")?;
        req.headers_mut().insert("Sec-WebSocket-Protocol", "mqtt".parse().unwrap());
        let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await.map_err(|_| anyhow!("{addr} didn't answer"))??;
        let conn = match ca_pem { Some(p) if url.starts_with("wss://") => Some(connector(p)?), _ => None };
        let cfg = WebSocketConfig { max_message_size: Some(MAX_PACKET * 2), max_frame_size: Some(MAX_PACKET * 2), ..Default::default() };
        let (ws, res) = tokio::time::timeout(Duration::from_secs(15), tokio_tungstenite::client_async_tls_with_config(req, tcp, Some(cfg), conn)).await
            .map_err(|_| anyhow!("the broker's WebSocket handshake took too long"))?.map_err(|e| anyhow!("the broker's WebSocket: {e}"))?;
        if let Some(p) = res.headers().get("sec-websocket-protocol") {
            if !p.to_str().unwrap_or("").eq_ignore_ascii_case("mqtt") { bail!("the broker chose the subprotocol {p:?}, not mqtt"); }
        }
        let (tx, rx) = ws.split();
        let mut s = Session { tx, rx, buf: Vec::new() };
        s.send(connect_packet(client_id, login, keepalive_s)).await?;
        match tokio::time::timeout(Duration::from_secs(10), s.packet()).await.map_err(|_| anyhow!("the broker didn't answer CONNECT"))?? {
            Some(Packet::ConnAck(0)) => Ok(s),
            Some(Packet::ConnAck(c)) => bail!("the broker refused the connection (code {c})"),
            other => bail!("the broker answered CONNECT with {other:?}"),
        }
    }

    async fn send(&mut self, p: Vec<u8>) -> Result<()> { self.tx.send(Message::Binary(p)).await.map_err(|e| anyhow!("the broker's WebSocket: {e}")) }

    /// The next whole MQTT packet; None when the broker closed the socket.
    async fn packet(&mut self) -> Result<Option<Packet>> {
        loop {
            if let Some(p) = take(&mut self.buf)? { return Ok(Some(p)); }
            match self.rx.next().await {
                Some(Ok(Message::Binary(b))) => {
                    if self.buf.len() + b.len() > MAX_PACKET * 2 { bail!("the broker sent more than one packet can hold"); }
                    self.buf.extend_from_slice(&b);
                }
                Some(Ok(Message::Close(_))) | None => return Ok(None),
                Some(Ok(_)) => {}   // pings are answered by tungstenite; text has no place in MQTT and is dropped
                Some(Err(e)) => bail!("the broker's WebSocket: {e}"),
            }
        }
    }

    /// Subscribes to the filters the person named, at QoS 0, and waits for the broker to grant them.
    pub async fn subscribe(&mut self, filters: &[String]) -> Result<()> {
        self.send(subscribe_packet(1, filters)).await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let p = tokio::time::timeout_at(deadline, self.packet()).await.map_err(|_| anyhow!("the broker didn't confirm the subscription"))??;
            match p {
                Some(Packet::SubAck(1, codes)) => { if codes.iter().any(|c| *c == 0x80) { bail!("the broker refused a subscription"); } return Ok(()); }
                Some(_) => {}
                None => bail!("the broker closed the connection"),
            }
        }
    }

    /// The next message on a topic it subscribed to: Ok(None) when the broker closed.
    #[cfg(test)]
    pub async fn next(&mut self) -> Result<Option<(String, Vec<u8>)>> { self.halves().0.next().await }

    /// Split halves for a select loop: messages in (Reader), pings out (`ping`).
    pub fn halves(&mut self) -> (Reader<'_>, &mut SplitSink<Ws, Message>) { (Reader { rx: &mut self.rx, buf: &mut self.buf }, &mut self.tx) }
}

pub struct Reader<'a> { rx: &'a mut SplitStream<Ws>, buf: &'a mut Vec<u8> }
impl Reader<'_> {
    /// The next PUBLISH, as Session::next.
    pub async fn next(&mut self) -> Result<Option<(String, Vec<u8>)>> {
        loop {
            if let Some(p) = take(self.buf)? { if let Packet::Publish(t, b) = p { return Ok(Some((t, b))); } continue; }
            match self.rx.next().await {
                Some(Ok(Message::Binary(b))) => {
                    if self.buf.len() + b.len() > MAX_PACKET * 2 { bail!("the broker sent more than one packet can hold"); }
                    self.buf.extend_from_slice(&b);
                }
                Some(Ok(Message::Close(_))) | None => return Ok(None),
                Some(Ok(_)) => {}
                Some(Err(e)) => bail!("the broker's WebSocket: {e}"),
            }
        }
    }
}

pub async fn ping(tx: &mut SplitSink<Ws, Message>) -> Result<()> { tx.send(Message::Binary(PINGREQ.to_vec())).await.map_err(|e| anyhow!("the broker's WebSocket: {e}")) }

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    #[test]
    fn packets_are_mqtt_3_1_1() {
        let c = connect_packet("pavilion-bridge-x", Some(("bridge", "pw")), 30);
        assert_eq!(&c[..2], &[0x10, (c.len() - 2) as u8]);
        assert_eq!(&c[2..10], &[0, 4, b'M', b'Q', b'T', b'T', 4, 0xC2]);
        assert_eq!(subscribe_packet(1, &["tele/+/SENSOR".into()]), [&[0x82u8, 18, 0, 1, 0, 13][..], b"tele/+/SENSOR", &[0]].concat());
        // A publish split across two frames, then two packets in one: each comes out whole, once.
        let p = packet(0x30, &[&string("tele/plug/SENSOR")[..], b"{\"ENERGY\":{}}"].concat());
        let mut buf = p[..5].to_vec();
        assert_eq!(take(&mut buf).unwrap(), None);
        buf.extend_from_slice(&p[5..]);
        buf.extend_from_slice(&[0xD0, 0]);
        assert_eq!(take(&mut buf).unwrap(), Some(Packet::Publish("tele/plug/SENSOR".into(), b"{\"ENERGY\":{}}".to_vec())));
        assert_eq!(take(&mut buf).unwrap(), Some(Packet::PingResp));
        assert!(buf.is_empty());
        // A length over the limit is refused before anything is buffered for it.
        let mut big = vec![0x30, 0xFF, 0xFF, 0x7F];
        assert!(take(&mut big).is_err());
        // A 300-byte payload needs two length bytes.
        let long = packet(0x30, &[&string("t")[..], &[b'x'; 300]].concat());
        assert_eq!(&long[1..3], &[0xAF, 0x02]);
    }

    /// A stand-in broker on 127.0.0.1 that speaks MQTT over a WebSocket, as Mosquitto's websockets listener does: it
    /// insists on the `mqtt` subprotocol and a path, checks the login, grants the subscription, and publishes.
    async fn standin(path: &'static str, login: (&'static str, &'static str)) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<String>) {
        standin_tls(path, login, None).await
    }

    /// The same over TLS (wss://), with the acceptor given.
    async fn standin_tls(path: &'static str, login: (&'static str, &'static str), tls: Option<tokio_rustls::TlsAcceptor>) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (seen_tx, seen) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let seen_tx = seen_tx.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    match tls {
                        Some(a) => match a.accept(s).await { Ok(t) => serve(t, path, login, seen_tx).await, Err(_) => { let _ = seen_tx.send("tls-refused".into()); } },
                        None => serve(s, path, login, seen_tx).await,
                    }
                });
            }
        });
        (addr, seen)
    }

    async fn serve<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(s: S, path: &'static str, login: (&'static str, &'static str), seen_tx: tokio::sync::mpsc::UnboundedSender<String>) {
                    let cb = |req: &Request, mut res: Response| {
                        let proto = req.headers().get("sec-websocket-protocol").and_then(|v| v.to_str().ok()).unwrap_or("");
                        if req.uri().path() != path || !proto.split(',').any(|p| p.trim() == "mqtt") {
                            return Err(tokio_tungstenite::tungstenite::http::Response::builder().status(400).body(None).unwrap());
                        }
                        res.headers_mut().insert("sec-websocket-protocol", "mqtt".parse().unwrap());
                        Ok(res)
                    };
                    let Ok(ws) = tokio_tungstenite::accept_hdr_async(s, cb).await else { let _ = seen_tx.send("refused-upgrade".into()); return };
                    let (mut tx, mut rx) = ws.split();
                    let mut buf = Vec::new();
                    while let Some(Ok(m)) = rx.next().await {
                        let Message::Binary(b) = m else { continue };
                        buf.extend_from_slice(&b);
                        while buf.len() >= 2 && buf.len() >= 2 + buf[1] as usize {
                            let (first, n) = (buf[0], buf[1] as usize);
                            let body: Vec<u8> = buf[2..2 + n].to_vec();
                            buf.drain(..2 + n);
                            match first >> 4 {
                                1 => {
                                    let cid_len = u16::from_be_bytes([body[10], body[11]]) as usize;
                                    let mut at = 12 + cid_len;
                                    let rd = |at: &mut usize| { let l = u16::from_be_bytes([body[*at], body[*at + 1]]) as usize; let s = String::from_utf8_lossy(&body[*at + 2..*at + 2 + l]).into_owned(); *at += 2 + l; s };
                                    let (u, p) = (rd(&mut at), rd(&mut at));
                                    let ok = (u.as_str(), p.as_str()) == login;
                                    let _ = seen_tx.send(format!("connect {u} {ok}"));
                                    let _ = tx.send(Message::Binary(vec![0x20, 2, 0, if ok { 0 } else { 5 }])).await;
                                    if !ok { return; }
                                }
                                8 => {
                                    let _ = seen_tx.send(format!("subscribe {}", String::from_utf8_lossy(&body[4..body.len() - 1])));
                                    let _ = tx.send(Message::Binary(vec![0x90, 3, body[0], body[1], 0])).await;
                                    // What the LAN would publish: split over two frames, then a second message and a ping answer in one.
                                    let p1 = packet(0x30, &[&string("tele/plug_desk/SENSOR")[..], br#"{"ENERGY":{"Power":47.5,"Total":1.24}}"#].concat());
                                    let _ = tx.send(Message::Binary(p1[..7].to_vec())).await;
                                    let _ = tx.send(Message::Binary(p1[7..].to_vec())).await;
                                    let p2 = packet(0x30, &[&string("stat/plug_desk/POWER")[..], b"ON"].concat());
                                    let _ = tx.send(Message::Binary([&p2[..], &[0xD0, 0][..]].concat())).await;
                                }
                                12 => { let _ = seen_tx.send("ping".into()); let _ = tx.send(Message::Binary(vec![0xD0, 0])).await; }
                                3 => { let _ = seen_tx.send("PUBLISHED".into()); }
                                _ => {}
                            }
                        }
                    }
    }

    #[tokio::test]
    async fn the_bridge_reaches_a_broker_over_a_websocket() {
        let (addr, mut seen) = standin("/mqtt", ("bridge", "s3cret")).await;
        let url = format!("ws://127.0.0.1:{}/mqtt", addr.port());
        let mut s = Session::open(&url, addr, None, "pavilion-bridge-test", Some(("bridge", "s3cret")), 30).await.unwrap();
        assert_eq!(seen.recv().await.unwrap(), "connect bridge true");
        s.subscribe(&["tele/+/SENSOR".into(), "stat/+/POWER".into()]).await.unwrap();
        assert_eq!(seen.recv().await.unwrap(), format!("subscribe {}", String::from_utf8_lossy(&[&b"tele/+/SENSOR"[..], &[0, 0, 12], b"stat/+/POWER"].concat())));
        let (t, p) = s.next().await.unwrap().unwrap();
        assert_eq!((t.as_str(), p.as_slice()), ("tele/plug_desk/SENSOR", &br#"{"ENERGY":{"Power":47.5,"Total":1.24}}"#[..]));
        let (t, p) = s.next().await.unwrap().unwrap();
        assert_eq!((t.as_str(), p.as_slice()), ("stat/plug_desk/POWER", &b"ON"[..]));
        {
            let (_r, tx) = s.halves();
            ping(tx).await.unwrap();
        }
        assert_eq!(seen.recv().await.unwrap(), "ping");
        drop(s);
        // Nothing it did was a PUBLISH: the bridge never publishes.
        while let Ok(x) = seen.try_recv() { assert_ne!(x, "PUBLISHED"); }

        // A wrong login, a path the broker doesn't serve: refused, and said so.
        let e = Session::open(&url, addr, None, "x", Some(("bridge", "wrong")), 30).await.err().unwrap().to_string();
        assert!(e.contains("refused the connection (code 5)"), "{e}");
        let e = Session::open(&format!("ws://127.0.0.1:{}/elsewhere", addr.port()), addr, None, "x", None, 30).await.err().unwrap().to_string();
        assert!(e.contains("400"), "{e}");
    }

    /// wss://: the broker's certificate is checked against the CA file the person named, and refused without it. The
    /// certificate is made for this run by the openssl on this machine (skipped, and said so, where there is none).
    /// It is marked a server's, not a CA's: OpenSSL 3's `req -x509` marks it `CA:TRUE` by default (LibreSSL does not),
    /// and rustls refuses a CA certificate as the peer's own (`CaUsedAsEndEntity`) — CI broke on that on 21 Nov 2026.
    #[tokio::test]
    async fn wss_checks_the_brokers_certificate() {
        let dir = std::env::temp_dir().join(format!("pav-mqtt-wss-{}", crate::signing::random_b64(6).replace(['-', '_'], "x")));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        let made = std::process::Command::new("openssl").args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "extendedKeyUsage=serverAuth", "-keyout"]).arg(&key).arg("-out").arg(&cert).output();
        if !made.as_ref().is_ok_and(|o| o.status.success()) { eprintln!("skipped: no openssl to make a test certificate"); return; }
        use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
        let pem = std::fs::read(&cert).unwrap();
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem).map(|c| c.unwrap()).collect();
        let pk = PrivateKeyDer::from_pem_slice(&std::fs::read(&key).unwrap()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let sc = rustls::ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(chain, pk).unwrap();
        let (addr, mut seen) = standin_tls("/mqtt", ("bridge", "s3cret"), Some(tokio_rustls::TlsAcceptor::from(Arc::new(sc)))).await;
        let url = format!("wss://localhost:{}/mqtt", addr.port());
        let mut s = Session::open(&url, addr, Some(&pem), "pavilion-bridge-test", Some(("bridge", "s3cret")), 30).await.unwrap();
        assert_eq!(seen.recv().await.unwrap(), "connect bridge true");
        s.subscribe(&["tele/+/SENSOR".into()]).await.unwrap();
        assert_eq!(s.next().await.unwrap().unwrap().0, "tele/plug_desk/SENSOR");
        drop(s);
        // Without the CA file the web's roots are used, and they never signed it: refused, never sent unchecked.
        let e = Session::open(&url, addr, None, "x", Some(("bridge", "s3cret")), 30).await.err().unwrap().to_string();
        assert!(e.to_lowercase().contains("certificate") || e.contains("UnknownIssuer"), "{e}");
    }

    #[test]
    fn a_ca_file_with_no_certificate_is_refused() {
        assert!(connector(b"not a certificate").is_err());
    }
}
