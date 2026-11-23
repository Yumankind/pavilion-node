//! MQTT (`rumqttc`) to an adopted broker on the LAN: `mqtt_read` listens to one topic (or a filter the adoption lists)
//! for a few seconds; `mqtt_publish` sends one message. Only topics the adoption's `allow.topics` covers, QoS 0 or 1,
//! payloads capped. A login, when the broker needs one, is a secret lent to this host (`user:password`).
use super::super::envelope::External;
use super::lent::Secret;
use super::net;
use rumqttc::{AsyncClient, Event, MqttOptions, Outgoing, Packet, QoS};
use serde_json::{json, Value};
use std::time::Duration;

pub const MAX_PUBLISH: usize = 16 * 1024;
pub const MAX_MESSAGE: usize = 64 * 1024;
const MAX_TOTAL: usize = 256 * 1024;

/// MQTT topic matching: `+` is one level, `#` the rest (only last).
pub fn matches(filter: &str, topic: &str) -> bool {
    let (f, t): (Vec<&str>, Vec<&str>) = (filter.split('/').collect(), topic.split('/').collect());
    // Topics starting with $ (broker internals) aren't matched by a leading wildcard.
    if topic.starts_with('$') && (filter.starts_with('+') || filter.starts_with('#')) { return false; }
    for (i, part) in f.iter().enumerate() {
        if *part == "#" { return i == f.len() - 1; }
        match t.get(i) { None => return false, Some(x) if *part != "+" && part != x => return false, _ => {} }
    }
    f.len() == t.len()
}

fn topic_ok(t: &str) -> bool { !t.is_empty() && t.len() <= 512 && !t.contains('\0') && !t.chars().any(|c| c.is_control()) }
fn filter_ok(f: &str) -> bool {
    topic_ok(f) && f.split('/').enumerate().all(|(i, p)| (p == "#" && i == f.split('/').count() - 1) || p == "+" || (!p.contains('+') && !p.contains('#')))
}

/// A topic or filter an agent may listen to: exactly a listed filter, or a plain topic a listed filter matches.
pub fn readable(e: &External, t: &str) -> Result<(), String> {
    if !filter_ok(t) { return Err(format!("{t:?} isn't an MQTT topic")); }
    let wild = t.contains('+') || t.contains('#');
    let listed: Vec<&String> = e.allow.topics.iter().filter(|f| filter_ok(f)).collect();
    if listed.iter().any(|f| f.as_str() == t || (!wild && matches(f, t))) { Ok(()) } else { Err(format!("{t} isn't a topic the adoption of {} lists", e.id)) }
}
/// A topic an agent may publish to: no wildcards, matched by a listed filter.
pub fn publishable(e: &External, t: &str) -> Result<(), String> {
    if !topic_ok(t) || t.contains('+') || t.contains('#') || t.starts_with('$') { return Err(format!("{t:?} isn't a topic one can publish to")); }
    if e.allow.topics.iter().any(|f| filter_ok(f) && matches(f, t)) { Ok(()) } else { Err(format!("{t} isn't a topic the adoption of {} lists", e.id)) }
}

async fn connect(e: &External, secret: Option<&Secret>) -> Result<(AsyncClient, rumqttc::EventLoop), String> {
    let a = net::parse_addr(&e.address, &["mqtt", "tcp"], "mqtt", |_| 1883)?;
    let addr = net::resolve(&a.host, a.port).await?;
    let mut o = MqttOptions::new(format!("pavilion-{}", crate::signing::random_b64(6).replace(['-', '_'], "x")), addr.ip().to_string(), addr.port());
    o.set_keep_alive(Duration::from_secs(30));
    o.set_clean_session(true);
    o.set_max_packet_size(MAX_MESSAGE + 1024, MAX_PUBLISH + 1024);
    if let Some(s) = secret { let (u, p) = s.login()?; o.set_credentials(u, p.as_str()); }
    Ok(AsyncClient::new(o, 16))
}

fn refused(err: rumqttc::ConnectionError) -> String {
    match err {
        rumqttc::ConnectionError::ConnectionRefused(c) => format!("the broker refused the connection ({c:?})"),
        e => format!("the broker: {e}"),
    }
}

fn qos(n: u8) -> QoS { if n == 0 { QoS::AtMostOnce } else { QoS::AtLeastOnce } }

pub async fn read(e: &External, secret: Option<&Secret>, topic: &str, seconds: u32, max: usize, q: u8) -> Result<Value, String> {
    readable(e, topic)?;
    let (c, mut ev) = connect(e, secret).await?;
    c.subscribe(topic, qos(q)).await.map_err(|e| e.to_string())?;
    let end = tokio::time::Instant::now() + Duration::from_secs(seconds as u64);
    let (mut messages, mut total) = (vec![], 0usize);
    while messages.len() < max && total < MAX_TOTAL {
        match tokio::time::timeout_at(end, ev.poll()).await {
            Err(_) => break,
            Ok(Err(err)) => return Err(refused(err)),
            Ok(Ok(Event::Incoming(Packet::SubAck(s)))) => {
                if s.return_codes.iter().any(|r| matches!(r, rumqttc::SubscribeReasonCode::Failure)) { return Err(format!("the broker refused the subscription to {topic}")); }
            }
            Ok(Ok(Event::Incoming(Packet::Publish(p)))) => {
                // Only what the subscription covers, whatever the broker sends.
                if !matches(topic, &p.topic) || !e.allow.topics.iter().any(|f| filter_ok(f) && matches(f, &p.topic)) { continue; }
                let truncated = p.payload.len() > MAX_MESSAGE;
                let body = &p.payload[..p.payload.len().min(MAX_MESSAGE)];
                total += body.len();
                let (payload, encoding) = match std::str::from_utf8(body) { Ok(t) => (json!(t), "text"), Err(_) => (json!(crate::signing::b64(body)), "b64") };
                messages.push(json!({ "topic": net::clean(&p.topic, 512), "payload": payload, "encoding": encoding, "retained": p.retain, "truncated": truncated, "at": super::super::now() }));
            }
            Ok(Ok(_)) => {}
        }
    }
    let _ = c.disconnect().await;
    let _ = tokio::time::timeout(Duration::from_millis(300), ev.poll()).await;
    Ok(json!({ "messages": messages }))
}

pub async fn publish(e: &External, secret: Option<&Secret>, topic: &str, payload: &str, q: u8, retain: bool) -> Result<Value, String> {
    publishable(e, topic)?;
    if payload.len() > MAX_PUBLISH { return Err(format!("the payload is over {} KB", MAX_PUBLISH / 1024)); }
    let (c, mut ev) = connect(e, secret).await?;
    c.publish(topic, qos(q), retain, payload.as_bytes().to_vec()).await.map_err(|e| e.to_string())?;
    let end = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::time::timeout_at(end, ev.poll()).await {
            Err(_) => return Err("the broker didn't confirm the message within 10 s".into()),
            Ok(Err(err)) => return Err(refused(err)),
            Ok(Ok(Event::Incoming(Packet::PubAck(_)))) if q == 1 => break,
            Ok(Ok(Event::Outgoing(Outgoing::Publish(_)))) if q == 0 => break,
            Ok(Ok(_)) => {}
        }
    }
    let _ = c.disconnect().await;
    let _ = tokio::time::timeout(Duration::from_millis(300), ev.poll()).await;
    Ok(json!({ "done": true }))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn topics() {
        assert!(matches("home/+/temp", "home/kitchen/temp"));
        assert!(!matches("home/+/temp", "home/kitchen/hall/temp"));
        assert!(matches("zigbee2mqtt/#", "zigbee2mqtt/lamp/set"));
        assert!(matches("zigbee2mqtt/#", "zigbee2mqtt"));
        assert!(!matches("#", "$SYS/broker/uptime"));
        assert!(!matches("a/b", "a/b/c"));
        let e = External { id: "ext_mq".into(), kind: "mqtt".into(), address: "x".into(),
            allow: crate::devices::envelope::Allow { topics: vec!["home/+/temp".into(), "zigbee2mqtt/lamp/set".into()], ..Default::default() }, ..Default::default() };
        assert!(readable(&e, "home/kitchen/temp").is_ok());
        assert!(readable(&e, "home/+/temp").is_ok());
        assert!(readable(&e, "home/#").is_err()); // wider than listed
        assert!(readable(&e, "#").is_err());
        assert!(publishable(&e, "zigbee2mqtt/lamp/set").is_ok());
        assert!(publishable(&e, "zigbee2mqtt/lock/set").is_err());
        assert!(publishable(&e, "home/+/temp").is_err());
    }

    fn remaining(n: usize) -> Vec<u8> {
        let mut out = vec![];
        let mut x = n;
        loop { let mut b = (x % 128) as u8; x /= 128; if x > 0 { b |= 0x80; } out.push(b); if x == 0 { return out; } }
    }
    fn packet(first: u8, body: &[u8]) -> Vec<u8> { [vec![first], remaining(body.len()), body.to_vec()].concat() }
    fn string(s: &str) -> Vec<u8> { [(s.len() as u16).to_be_bytes().to_vec(), s.as_bytes().to_vec()].concat() }

    /// A small MQTT 3.1.1 broker: one login, retained messages, QoS 0 and 1 in, QoS 0 out. Enough for the adapter.
    pub async fn broker(login: Option<(&'static str, &'static str)>) -> (String, std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<u8>, bool)>>>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let published = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let retained = std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::<String, Vec<u8>>::new()));
        let (tx, _) = tokio::sync::broadcast::channel::<(String, Vec<u8>)>(64);
        let p2 = published.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { return };
                let (published, retained, tx) = (p2.clone(), retained.clone(), tx.clone());
                let mut rx = tx.subscribe();
                tokio::spawn(async move {
                    let mut subs: Vec<String> = vec![];
                    loop {
                        let mut first = [0u8; 1];
                        tokio::select! {
                            r = s.read_exact(&mut first) => {
                                if r.is_err() { return; }
                                let (mut len, mut mul) = (0usize, 1usize);
                                loop { let mut b = [0u8; 1]; if s.read_exact(&mut b).await.is_err() { return; } len += (b[0] & 0x7F) as usize * mul; mul *= 128; if b[0] & 0x80 == 0 { break; } }
                                let mut body = vec![0u8; len];
                                if s.read_exact(&mut body).await.is_err() { return; }
                                let str_at = |b: &[u8], i: usize| -> (String, usize) { let n = u16::from_be_bytes([b[i], b[i + 1]]) as usize; (String::from_utf8_lossy(&b[i + 2..i + 2 + n]).to_string(), i + 2 + n) };
                                match first[0] >> 4 {
                                    1 => { // CONNECT
                                        let (_proto, i) = str_at(&body, 0);
                                        let flags = body[i + 1];
                                        let (_id, mut j) = str_at(&body, i + 4);
                                        let mut user = None; let mut pass = None;
                                        if flags & 0x80 != 0 { let (u, k) = str_at(&body, j); user = Some(u); j = k; }
                                        if flags & 0x40 != 0 { let (p, _) = str_at(&body, j); pass = Some(p); }
                                        let ok = login.map_or(true, |(u, p)| user.as_deref() == Some(u) && pass.as_deref() == Some(p));
                                        let _ = s.write_all(&[0x20, 0x02, 0x00, if ok { 0 } else { 5 }]).await;
                                        if !ok { return; }
                                    }
                                    3 => { // PUBLISH
                                        let q = (first[0] >> 1) & 3;
                                        let (topic, mut i) = str_at(&body, 0);
                                        let pid = if q > 0 { let p = [body[i], body[i + 1]]; i += 2; Some(p) } else { None };
                                        let payload = body[i..].to_vec();
                                        let retain = first[0] & 1 != 0;
                                        published.lock().unwrap().push((topic.clone(), payload.clone(), retain));
                                        if retain { retained.lock().unwrap().insert(topic.clone(), payload.clone()); }
                                        let _ = tx.send((topic, payload));
                                        if let Some(p) = pid { let _ = s.write_all(&[0x40, 0x02, p[0], p[1]]).await; }
                                    }
                                    8 => { // SUBSCRIBE
                                        let pid = [body[0], body[1]];
                                        let mut i = 2; let mut granted = vec![];
                                        while i < body.len() { let (f, k) = str_at(&body, i); granted.push(body[k].min(1)); subs.push(f); i = k + 1; }
                                        let _ = s.write_all(&packet(0x90, &[&pid[..], &granted].concat())).await;
                                        let ret: Vec<(String, Vec<u8>)> = retained.lock().unwrap().iter().map(|(t, p)| (t.clone(), p.clone())).collect();
                                        for (t, p) in ret { if subs.iter().any(|f| matches(f, &t)) { let _ = s.write_all(&packet(0x31, &[string(&t), p].concat())).await; } }
                                    }
                                    12 => { let _ = s.write_all(&[0xD0, 0x00]).await; }
                                    14 => return,
                                    _ => {}
                                }
                            }
                            m = rx.recv() => {
                                let Ok((t, p)) = m else { continue };
                                if subs.iter().any(|f| matches(f, &t)) { let _ = s.write_all(&packet(0x30, &[string(&t), p].concat())).await; }
                            }
                        }
                    }
                });
            }
        });
        (addr, published)
    }

    pub fn adoption(addr: &str) -> External {
        External { id: "ext_mq".into(), name: "Broker".into(), kind: "mqtt".into(), address: addr.into(), secret: Some("MQTT_LOGIN".into()),
            allow: crate::devices::envelope::Allow { topics: vec!["home/+/temp".into(), "zigbee2mqtt/lamp/set".into()], ..Default::default() }, ..Default::default() }
    }

    #[tokio::test]
    async fn read_and_publish_through_a_broker() {
        let (addr, published) = broker(Some(("pavilion", "s3cret"))).await;
        let e = adoption(&addr);
        let login = Secret::new("MQTT_LOGIN", "pavilion:s3cret");
        // Something retained, published by another client (the "sensor").
        publish(&External { allow: crate::devices::envelope::Allow { topics: vec!["#".into()], ..Default::default() }, ..e.clone() }, Some(&login), "home/kitchen/temp", "21.5", 1, true).await.unwrap();
        let r = read(&e, Some(&login), "home/kitchen/temp", 1, 10, 0).await.unwrap();
        assert_eq!(r["messages"][0]["payload"], "21.5");
        assert_eq!(r["messages"][0]["retained"], true);
        assert_eq!(publish(&e, Some(&login), "zigbee2mqtt/lamp/set", r#"{"state":"ON"}"#, 1, false).await.unwrap(), json!({ "done": true }));
        assert_eq!(published.lock().unwrap().last().unwrap().0, "zigbee2mqtt/lamp/set");
        assert_eq!(publish(&e, Some(&login), "zigbee2mqtt/lamp/set", "x", 0, false).await.unwrap(), json!({ "done": true }));
        // Not listed, too big, or the wrong login.
        assert!(publish(&e, Some(&login), "zigbee2mqtt/lock/set", "x", 1, false).await.unwrap_err().contains("isn't a topic"));
        assert!(publish(&e, Some(&login), "zigbee2mqtt/lamp/set", &"x".repeat(MAX_PUBLISH + 1), 1, false).await.unwrap_err().contains("over"));
        assert!(read(&e, Some(&Secret::new("MQTT_LOGIN", "pavilion:wrong")), "home/kitchen/temp", 1, 10, 0).await.unwrap_err().contains("refused"));
    }
}
