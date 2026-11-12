//! The broker for one job (docs/DESIGN.md). It's the sandbox's only way out: its host-only network reaches this
//! Mac and nothing else. It answers only peers on the job's own subnet, takes the explicit form
//! `http://<broker>/<SECRET>/<host>/<path>`, and forwards to the Gate's `/node/egress/<grant>/<host>/<path>`, signed by
//! this machine's key. The Gate adds the secret and scrubs it from the reply; the value never reaches this machine.
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use futures_util::TryStreamExt;
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response, StatusCode};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Clone)]
pub struct Grant { pub id: String, pub hosts: Vec<String> }

pub struct Broker {
    pub gate: String,
    pub pavilion: String,
    pub key: SigningKey,
    /// secret name → grant, for this job only.
    pub grants: HashMap<String, Grant>,
    /// e.g. 192.168.128.0/24: the job's host-only network.
    pub subnet: (u32, u32),
    pub http: reqwest::Client,
}

type Body = BoxBody<Bytes, std::io::Error>;
fn text(status: StatusCode, s: String) -> Response<Body> {
    Response::builder().status(status).header("content-type", "text/plain; charset=utf-8").header("x-pavilion-node", "blocked")
        .body(Full::new(Bytes::from(s)).map_err(|never| match never {}).boxed()).unwrap()
}

pub fn parse_subnet(cidr: &str) -> Option<(u32, u32)> {
    let (ip, bits) = cidr.split_once('/')?;
    let ip: std::net::Ipv4Addr = ip.parse().ok()?;
    let bits: u32 = bits.parse().ok()?;
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    Some((u32::from(ip) & mask, mask))
}
fn in_subnet(ip: IpAddr, (net, mask): (u32, u32)) -> bool { matches!(ip, IpAddr::V4(v4) if u32::from(v4) & mask == net) }

pub fn host_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") { Some(base) => host.len() > base.len() + 1 && host.ends_with(&format!(".{base}")), None => host == pattern }
}

impl Broker {
    /// Listens on all addresses (the job's bridge only exists once its VM runs) and answers only the job's subnet.
    /// Ports 47100-47199 only; the packet filter lets job VMs reach those and nothing else on this Mac.
    pub async fn serve(self: Arc<Self>) -> anyhow::Result<(u16, tokio::task::JoinHandle<()>)> {
        // A fixed range, so the packet filter can allow exactly these ports from job VMs (node/pf/pavilion.conf).
        let mut listener = None;
        for port in 47100..=47199u16 { if let Ok(l) = TcpListener::bind(("0.0.0.0", port)).await { listener = Some(l); break; } }
        let listener = listener.ok_or_else(|| anyhow::anyhow!("all broker ports 47100-47199 are busy"))?;
        let port = listener.local_addr()?.port();
        let h = tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else { continue };
                if !in_subnet(peer.ip(), self.subnet) { drop(stream); continue; }
                let me = self.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req| { let me = me.clone(); async move { Ok::<_, std::convert::Infallible>(me.handle(req, peer).await) } });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream), svc).await;
                });
            }
        });
        Ok((port, h))
    }

    async fn handle(&self, req: Request<Incoming>, _peer: SocketAddr) -> Response<Body> {
        let path = req.uri().path().to_string();
        let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
        let parts: Vec<&str> = path.trim_start_matches('/').splitn(3, '/').collect();
        if parts.len() < 2 || parts[0].is_empty() {
            let list: Vec<String> = self.grants.iter().map(|(s, g)| format!("{s} → {}", g.hosts.join(", "))).collect();
            return text(StatusCode::OK, format!("pavilion-node broker. Call http://<this address>/<SECRET>/<host>/<path>; the Gate adds the secret.\nThis job may use: {}\n", if list.is_empty() { "nothing".into() } else { list.join("; ") }));
        }
        let (secret, host, rest) = (parts[0], parts[1].to_lowercase(), format!("/{}", parts.get(2).unwrap_or(&"")));
        let Some(grant) = self.grants.get(secret) else { return text(StatusCode::FORBIDDEN, format!("Blocked by the node: this job has no grant for {secret}.\n")) };
        if !grant.hosts.iter().any(|h| host_matches(h, &host)) { return text(StatusCode::FORBIDDEN, format!("Blocked by the node: {secret} isn't granted for {host}.\n")); }

        let method = req.method().clone();
        let mut headers = vec![];
        for (k, v) in req.headers() {
            let k = k.as_str().to_lowercase();
            if ["host", "connection", "content-length", "transfer-encoding", "authorization", "proxy-authorization", "cookie", "x-api-key"].contains(&k.as_str()) || k.starts_with("x-pavilion-") { continue; }
            if let Ok(v) = v.to_str() { headers.push((k, v.to_string())); }
        }
        // Bodies are signed, so they're read whole (8 MB at most, like the Gate).
        let body = match Limited::new(req.into_body(), 8 * 1024 * 1024).collect().await { Ok(b) => b.to_bytes(), Err(_) => return text(StatusCode::PAYLOAD_TOO_LARGE, "Blocked by the node: request over 8 MB.\n".into()) };

        let gate_url = reqwest::Url::parse(&self.gate).unwrap();
        let gate_host = gate_url.host_str().unwrap_or_default().to_string() + &gate_url.port().map(|p| format!(":{p}")).unwrap_or_default();
        let gate_path = format!("/p/{}/node/egress/{}/{}{}{}", self.pavilion, grant.id, host, rest, query);
        let mut rb = self.http.request(method.clone(), format!("{}{}", self.gate.trim_end_matches('/'), gate_path));
        for (k, v) in headers { rb = rb.header(k, v); }
        for (k, v) in crate::signing::signed_headers(&self.key, &gate_host, method.as_str(), &gate_path, &body) { rb = rb.header(k, v); }
        let res = match rb.body(body).send().await { Ok(r) => r, Err(e) => return text(StatusCode::BAD_GATEWAY, format!("Blocked by the node: the Gate didn't answer: {e}\n")) };

        let mut out = Response::builder().status(res.status().as_u16());
        for (k, v) in res.headers() { if !["connection", "transfer-encoding", "content-length"].contains(&k.as_str()) { out = out.header(k, v); } }
        let stream = res.bytes_stream().map_ok(Frame::data).map_err(std::io::Error::other);
        out.body(BodyExt::boxed(StreamBody::new(stream))).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subnets() {
        let s = parse_subnet("192.168.128.0/24").unwrap();
        assert!(in_subnet("192.168.128.2".parse().unwrap(), s));
        assert!(!in_subnet("192.168.129.2".parse().unwrap(), s));
        assert!(!in_subnet("10.0.0.5".parse().unwrap(), s));
    }
    #[test]
    fn hosts() {
        assert!(host_matches("api.github.com", "api.github.com"));
        assert!(!host_matches("api.github.com", "api.github.com.evil.example"));
        assert!(host_matches("*.github.com", "api.github.com"));
        assert!(!host_matches("*.github.com", "github.com"));
    }
}
