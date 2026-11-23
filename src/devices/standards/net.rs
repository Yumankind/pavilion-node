//! The local network, for adapters: an adopted device's address is resolved once, checked to be on the LAN (never this
//! computer, never the internet: caps::lan::lan_ip) and pinned, so a name can't be pointed elsewhere between the check
//! and the call.
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// A device address: `[scheme://]host[:port][/path]`.
#[derive(Clone, Debug, PartialEq)]
pub struct Addr { pub scheme: String, pub host: String, pub port: u16, pub path: String }

/// Parses an adopted address. `default_scheme` and `default_port` fill what's missing; schemes outside `schemes` are
/// refused. No user info (`user@`), no query, no fragment.
pub fn parse_addr(a: &str, schemes: &[&str], default_scheme: &str, default_port: impl Fn(&str) -> u16) -> Result<Addr, String> {
    let a = a.trim();
    let (scheme, rest) = match a.split_once("://") { Some((s, r)) => (s.to_ascii_lowercase(), r), None => (default_scheme.to_string(), a) };
    if !schemes.contains(&scheme.as_str()) { return Err(format!("{a:?}: {scheme} isn't an address this kind of device can have ({})", schemes.join(", "))); }
    let (hostport, path) = match rest.find('/') { Some(i) => (&rest[..i], &rest[i..]), None => (rest, "") };
    if hostport.is_empty() || hostport.contains('@') || path.contains('?') || path.contains('#') || a.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("{a:?} isn't a device address"));
    }
    let (host, port) = if let Some(r) = hostport.strip_prefix('[') {
        let (h, p) = r.split_once(']').ok_or("bad IPv6 address")?;
        (h.to_string(), p.strip_prefix(':').map(|p| p.parse::<u16>().map_err(|_| "bad port")).transpose()?)
    } else if let Some((h, p)) = hostport.rsplit_once(':').filter(|_| hostport.matches(':').count() == 1) {
        (h.to_string(), Some(p.parse::<u16>().map_err(|_| "bad port")?))
    } else { (hostport.to_string(), None) };
    let port = port.unwrap_or_else(|| default_port(&scheme));
    Ok(Addr { scheme, host, port, path: path.to_string() })
}

/// Only private, link-local and unique-local addresses. Tests also reach their simulators on loopback.
pub fn allowed_ip(ip: &IpAddr) -> bool { crate::devices::caps::lan::lan_ip(ip) || (cfg!(test) && ip.is_loopback()) }

/// Resolves `host:port` once and checks every answer is on the local network.
pub async fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    let addrs: Vec<SocketAddr> = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host, port))).await
        .map_err(|_| format!("finding {host} took too long"))?.map_err(|e| format!("can't find {host}: {e}"))?.collect();
    let first = *addrs.first().ok_or_else(|| format!("{host} has no address"))?;
    if !addrs.iter().all(|a| allowed_ip(&a.ip())) { return Err(format!("{host} isn't on the local network ({}); only devices on the LAN can be reached", first.ip())); }
    Ok(first)
}

/// An HTTP client pinned to `addr` for `host`: no proxy, no redirects. `insecure_tls` for LAN devices with their own
/// self-signed certificates (printers over IPPS, hubs over https); the address is already pinned to the LAN.
pub fn client(host: &str, addr: SocketAddr, timeout: Duration, insecure_tls: bool) -> Result<reqwest::Client, String> {
    reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(timeout).connect_timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(insecure_tls).resolve(host, addr).build().map_err(|e| e.to_string())
}

/// `http://host:port` as a URL prefix (IPv6 hosts bracketed).
pub fn origin(scheme: &str, host: &str, port: u16) -> String {
    let h = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
    format!("{scheme}://{h}:{port}")
}

/// Reads a response body up to `max` bytes; more is an error (`what` names it).
pub async fn body_capped(r: reqwest::Response, max: usize, what: &str) -> Result<Vec<u8>, String> {
    use futures_util::StreamExt;
    let mut out = vec![];
    let mut s = r.bytes_stream();
    while let Some(c) = s.next().await {
        let c = c.map_err(|e| format!("reading {what}: {e}"))?;
        if out.len() + c.len() > max { return Err(format!("{what} is over {} KB", max / 1024)); }
        out.extend_from_slice(&c);
    }
    Ok(out)
}

/// Text from a device, cleaned for an agent: no control characters, at most `n` characters.
pub fn clean(s: &str, n: usize) -> String { s.chars().filter(|c| !c.is_control()).take(n).collect() }

/// Unix seconds of an ISO 8601 / RFC 3339 time (`2026-11-13T09:30:00.123+00:00`, `…Z`). None if it isn't one.
pub fn unix_time(s: &str) -> Option<u64> {
    let s = s.trim();
    let (date, rest) = s.split_once('T').or_else(|| s.split_once(' '))?;
    let mut d = date.split('-').map(|x| x.parse::<i64>().ok());
    let (y, m, dd) = (d.next()??, d.next()??, d.next()??);
    let (time, offset) = match rest.find(|c| c == 'Z' || c == '+' || (c == '-')) { Some(i) => (&rest[..i], &rest[i..]), None => (rest, "Z") };
    let mut t = time.split(':');
    let (h, mi) = (t.next()?.parse::<i64>().ok()?, t.next()?.parse::<i64>().ok()?);
    let sec = t.next().map(|x| x.split('.').next().unwrap_or("0").parse::<i64>().ok()).unwrap_or(Some(0))?;
    let off = if offset == "Z" || offset.is_empty() { 0 } else {
        let sign = if offset.starts_with('-') { -1 } else { 1 };
        let o = offset[1..].replace(':', "");
        if o.len() < 4 { return None; }
        sign * (o[..2].parse::<i64>().ok()? * 3600 + o[2..4].parse::<i64>().ok()? * 60)
    };
    // Days from civil (Howard Hinnant's algorithm).
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + dd - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let t = days * 86_400 + h * 3600 + mi * 60 + sec - off;
    u64::try_from(t).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        let d = |s: &str| if s == "https" || s == "ipps" { 443 } else { 80 };
        assert_eq!(parse_addr("homeassistant.local:8123", &["http", "https"], "http", d).unwrap(), Addr { scheme: "http".into(), host: "homeassistant.local".into(), port: 8123, path: "".into() });
        assert_eq!(parse_addr("ipp://192.168.1.9:631/ipp/print", &["ipp", "ipps", "http"], "ipp", |_| 631).unwrap().path, "/ipp/print");
        assert_eq!(parse_addr("[fe80::1]", &["http"], "http", d).unwrap().host, "fe80::1");
        assert!(parse_addr("ftp://x", &["http"], "http", d).is_err());
        assert!(parse_addr("http://user@evil.com/", &["http"], "http", d).is_err());
        assert!(parse_addr("http://x/a?b", &["http"], "http", d).is_err());
    }

    #[test]
    fn times() {
        assert_eq!(unix_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(unix_time("2026-11-13T09:30:00.123456+00:00"), Some(1_794_562_200));
        assert_eq!(unix_time("2026-11-13T10:30:00+01:00"), Some(1_794_562_200));
        assert_eq!(unix_time("nonsense"), None);
    }
}
