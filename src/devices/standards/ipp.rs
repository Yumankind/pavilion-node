//! IPP printing (RFC 8010 / 8011): `print` sends one asset (PDF or JPEG) to an adopted printer as a `Print-Job` with
//! its `document-format`, at most 5 copies and an optional page range. The printer's state is checked first
//! (`Get-Printer-Attributes`): a stopped printer, one not accepting jobs, or one that can't take the format is a
//! refusal, before any paper moves. The address is the printer's IPP URI: `ipp://printer.local:631/ipp/print`.
use super::super::envelope::External;
use super::net;
use std::collections::BTreeMap;
use std::time::Duration;

pub const MAX_COPIES: u32 = 5;
pub const MAX_DOCUMENT: usize = 25 << 20;

// Delimiter and value tags (RFC 8010 §3.5).
const OPERATION: u8 = 0x01;
const JOB: u8 = 0x02;
const END: u8 = 0x03;
const INTEGER: u8 = 0x21;
#[cfg_attr(not(test), allow(dead_code))]
const ENUM: u8 = 0x23;
const RANGE: u8 = 0x33;
const NAME: u8 = 0x42;
const KEYWORD: u8 = 0x44;
const URI: u8 = 0x45;
const CHARSET: u8 = 0x47;
const LANGUAGE: u8 = 0x48;
const MIME: u8 = 0x49;

pub const PRINT_JOB: u16 = 0x0002;
pub const GET_PRINTER_ATTRIBUTES: u16 = 0x000B;

/// An IPP request being written: version 2.0, the operation, a request id, then attribute groups.
pub struct Req { buf: Vec<u8> }
impl Req {
    pub fn new(op: u16, id: u32, printer_uri: &str) -> Req {
        let mut r = Req { buf: vec![0x02, 0x00] };
        r.buf.extend(op.to_be_bytes());
        r.buf.extend(id.to_be_bytes());
        r.buf.push(OPERATION);
        r.attr(CHARSET, "attributes-charset", b"utf-8");
        r.attr(LANGUAGE, "attributes-natural-language", b"en");
        r.attr(URI, "printer-uri", printer_uri.as_bytes());
        r
    }
    pub fn attr(&mut self, tag: u8, name: &str, value: &[u8]) -> &mut Req {
        self.buf.push(tag);
        self.buf.extend((name.len() as u16).to_be_bytes());
        self.buf.extend(name.as_bytes());
        self.buf.extend((value.len() as u16).to_be_bytes());
        self.buf.extend(value);
        self
    }
    /// Another value of the attribute just written (an empty name).
    pub fn more(&mut self, tag: u8, value: &[u8]) -> &mut Req { self.attr(tag, "", value) }
    pub fn group(&mut self, tag: u8) -> &mut Req { self.buf.push(tag); self }
    pub fn finish(mut self, document: &[u8]) -> Vec<u8> { self.buf.push(END); self.buf.extend_from_slice(document); self.buf }
}

/// `Get-Printer-Attributes` for what `print` checks first.
pub fn get_printer_attributes(id: u32, uri: &str) -> Vec<u8> {
    let mut r = Req::new(GET_PRINTER_ATTRIBUTES, id, uri);
    r.attr(KEYWORD, "requested-attributes", b"printer-state");
    for a in ["printer-state-reasons", "printer-is-accepting-jobs", "document-format-supported", "printer-make-and-model", "copies-supported"] { r.more(KEYWORD, a.as_bytes()); }
    r.finish(&[])
}

/// `Print-Job`: the document with its format, copies and page range.
pub fn print_job(id: u32, uri: &str, job_name: &str, format: &str, copies: u32, pages: Option<(u32, u32)>, document: &[u8]) -> Vec<u8> {
    let mut r = Req::new(PRINT_JOB, id, uri);
    r.attr(NAME, "requesting-user-name", b"pavilion");
    r.attr(NAME, "job-name", job_name.as_bytes());
    r.attr(MIME, "document-format", format.as_bytes());
    r.group(JOB);
    r.attr(INTEGER, "copies", &(copies as i32).to_be_bytes());
    if let Some((a, b)) = pages { r.attr(RANGE, "page-ranges", &[(a as i32).to_be_bytes(), (b as i32).to_be_bytes()].concat()); }
    r.finish(document)
}

/// A decoded response: its status code and every attribute's values (raw bytes, with their tags), by name.
#[derive(Debug, Default)]
pub struct Resp { pub status: u16, pub attrs: BTreeMap<String, Vec<(u8, Vec<u8>)>> }
impl Resp {
    pub fn int(&self, name: &str) -> Option<i32> { self.attrs.get(name)?.first().filter(|(_, v)| v.len() == 4).map(|(_, v)| i32::from_be_bytes([v[0], v[1], v[2], v[3]])) }
    pub fn strings(&self, name: &str) -> Vec<String> { self.attrs.get(name).map(|vs| vs.iter().map(|(_, v)| String::from_utf8_lossy(v).to_string()).collect()).unwrap_or_default() }
    pub fn boolean(&self, name: &str) -> Option<bool> { self.attrs.get(name)?.first().map(|(_, v)| v.first() == Some(&1)) }
}

pub fn parse(b: &[u8]) -> Result<Resp, String> {
    let bad = || "the printer sent a malformed IPP answer".to_string();
    if b.len() < 9 { return Err(bad()); }
    let mut r = Resp { status: u16::from_be_bytes([b[2], b[3]]), ..Default::default() };
    let mut i = 8;
    let mut last = String::new();
    while i < b.len() {
        let tag = b[i];
        i += 1;
        if tag == END { break; }
        if tag < 0x10 { continue; } // a group delimiter
        let nl = u16::from_be_bytes([*b.get(i).ok_or_else(bad)?, *b.get(i + 1).ok_or_else(bad)?]) as usize;
        let name = String::from_utf8_lossy(b.get(i + 2..i + 2 + nl).ok_or_else(bad)?).to_string();
        i += 2 + nl;
        let vl = u16::from_be_bytes([*b.get(i).ok_or_else(bad)?, *b.get(i + 1).ok_or_else(bad)?]) as usize;
        let value = b.get(i + 2..i + 2 + vl).ok_or_else(bad)?.to_vec();
        i += 2 + vl;
        if !name.is_empty() { last = name; }
        r.attrs.entry(last.clone()).or_default().push((tag, value));
    }
    Ok(r)
}

pub fn status_words(code: u16) -> &'static str {
    match code {
        0x0000..=0x00FF => "ok", 0x0400 => "bad request", 0x0401 => "forbidden", 0x0402 => "not authenticated", 0x0403 => "not authorized",
        0x040A => "document format not supported", 0x040B => "attributes or values not supported", 0x0500 => "internal error", 0x0506 => "printer busy",
        0x0507 => "job canceled", 0x0509 => "printer not accepting jobs", _ => "an error",
    }
}

/// What a document is, by its first bytes: only PDF and JPEG are printed.
pub fn format_of(doc: &[u8]) -> Option<&'static str> {
    if doc.starts_with(b"%PDF-") { Some("application/pdf") } else if doc.starts_with(&[0xFF, 0xD8, 0xFF]) { Some("image/jpeg") } else { None }
}

/// `"3"` or `"2-5"` → (first, last), 1-based, at most 999.
pub fn pages(s: &str) -> Result<(u32, u32), String> {
    let bad = || format!("pages {s:?} should look like 3 or 2-5");
    let (a, b) = s.trim().split_once('-').unwrap_or((s.trim(), s.trim()));
    let (a, b) = (a.trim().parse::<u32>().map_err(|_| bad())?, b.trim().parse::<u32>().map_err(|_| bad())?);
    if a == 0 || b < a || b > 999 { return Err(bad()); }
    Ok((a, b))
}

/// The printer's IPP URI and the HTTP URL it's reached at.
pub fn endpoint(e: &External) -> Result<(net::Addr, String), String> {
    let a = net::parse_addr(&e.address, &["ipp", "ipps", "http", "https"], "ipp", |s| if s == "https" { 443 } else { 631 })?;
    let path = if a.path.is_empty() { "/ipp/print".to_string() } else { a.path.clone() };
    let uri = format!("{}{path}", net::origin(if a.scheme == "ipps" || a.scheme == "https" { "ipps" } else { "ipp" }, &a.host, a.port));
    Ok((net::Addr { path, ..a }, uri))
}

async fn post(e: &External, body: Vec<u8>) -> Result<Resp, String> {
    let (a, _) = endpoint(e)?;
    let addr = net::resolve(&a.host, a.port).await?;
    let tls = a.scheme == "ipps" || a.scheme == "https";
    let http = net::client(&a.host, addr, Duration::from_secs(60), tls)?;
    let url = format!("{}{}", net::origin(if tls { "https" } else { "http" }, &a.host, a.port), a.path);
    let r = http.post(url).header("content-type", "application/ipp").body(body).send().await.map_err(|err| format!("the printer {} didn't answer: {err}", e.id))?;
    if !r.status().is_success() { return Err(format!("the printer answered HTTP {}", r.status().as_u16())); }
    parse(&net::body_capped(r, 1 << 20, "the printer's answer").await?)
}

/// The printer's state, in words, and whether it can take this format.
pub async fn check(e: &External, format: &str) -> Result<serde_json::Value, String> {
    let (_, uri) = endpoint(e)?;
    let r = post(e, get_printer_attributes(1, &uri)).await?;
    if r.status >= 0x0100 { return Err(format!("the printer refused the status request ({})", status_words(r.status))); }
    let state = r.int("printer-state");
    if state == Some(5) { return Err(format!("the printer is stopped ({})", r.strings("printer-state-reasons").join(", "))); }
    if r.boolean("printer-is-accepting-jobs") == Some(false) { return Err("the printer isn't accepting jobs".into()); }
    let formats = r.strings("document-format-supported");
    if !formats.is_empty() && !formats.iter().any(|f| f == format || f == "application/octet-stream") { return Err(format!("the printer can't print {format} (it takes {})", formats.join(", "))); }
    Ok(serde_json::json!({ "state": match state { Some(3) => "idle", Some(4) => "printing", _ => "unknown" }, "model": r.strings("printer-make-and-model").first() }))
}

pub async fn print(e: &External, act: &str, document: &[u8], copies: u32, page_range: Option<(u32, u32)>) -> Result<serde_json::Value, String> {
    if document.len() > MAX_DOCUMENT { return Err("the document is over 25 MB".into()); }
    let format = format_of(document).ok_or("only PDF and JPEG documents are printed")?;
    check(e, format).await?;
    let (_, uri) = endpoint(e)?;
    let r = post(e, print_job(2, &uri, &format!("Pavilion {act}"), format, copies.clamp(1, MAX_COPIES), page_range, document)).await?;
    if r.status >= 0x0100 { return Err(format!("the printer refused the job ({})", status_words(r.status))); }
    Ok(serde_json::json!({ "done": true, "job": r.int("job-id") }))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn requests_are_encoded_as_rfc_8010_says() {
        let b = print_job(7, "ipp://p.local:631/ipp/print", "J", "application/pdf", 2, Some((1, 3)), b"%PDF-1.4");
        assert_eq!(&b[..8], &[0x02, 0x00, 0x00, 0x02, 0, 0, 0, 7]);
        assert_eq!(b[8], OPERATION);
        // The first attribute: charset, "attributes-charset" (18), "utf-8" (5).
        assert_eq!(&b[9..12], &[CHARSET, 0, 18]);
        assert_eq!(&b[12..30], b"attributes-charset");
        assert_eq!(&b[30..37], b"\x00\x05utf-8");
        let r = parse(&b).unwrap(); // the same layout reads back
        assert_eq!(r.strings("printer-uri"), vec!["ipp://p.local:631/ipp/print"]);
        assert_eq!(r.strings("document-format"), vec!["application/pdf"]);
        assert_eq!(r.int("copies"), Some(2));
        assert_eq!(r.attrs["page-ranges"][0], (RANGE, vec![0, 0, 0, 1, 0, 0, 0, 3]));
        assert!(b.ends_with(b"\x03%PDF-1.4"));
        let g = parse(&get_printer_attributes(1, "ipp://p/ipp/print")).unwrap();
        assert_eq!(g.strings("requested-attributes").len(), 6);
        assert_eq!(pages("2-5").unwrap(), (2, 5));
        assert_eq!(pages("4").unwrap(), (4, 4));
        assert!(pages("5-2").is_err() && pages("0").is_err() && pages("a").is_err());
        assert_eq!(format_of(b"%PDF-1.7"), Some("application/pdf"));
        assert_eq!(format_of(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
        assert_eq!(format_of(b"PK\x03\x04"), None);
        let e = External { id: "ext_p".into(), kind: "printer".into(), address: "printer.local".into(), ..Default::default() };
        assert_eq!(endpoint(&e).unwrap().1, "ipp://printer.local:631/ipp/print");
    }

    /// An IPP printer: answers Get-Printer-Attributes with `state` and takes Print-Job. Records the jobs.
    pub async fn printer(state: i32, jobs: std::sync::Arc<std::sync::Mutex<Vec<Resp>>>, documents: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>) -> String {
        use http_body_util::{BodyExt, Full};
        use hyper::{body::Incoming, Request, Response};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { return };
                let (jobs, documents) = (jobs.clone(), documents.clone());
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let (jobs, documents) = (jobs.clone(), documents.clone());
                        async move {
                            let ok_type = req.headers().get("content-type").map_or(false, |v| v == "application/ipp");
                            let b = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default().to_vec();
                            let op = u16::from_be_bytes([b[2], b[3]]);
                            let mut out = vec![0x02, 0x00, 0x00, 0x00, b[4], b[5], b[6], b[7], OPERATION];
                            let a = |out: &mut Vec<u8>, tag: u8, name: &str, v: &[u8]| { out.push(tag); out.extend((name.len() as u16).to_be_bytes()); out.extend(name.as_bytes()); out.extend((v.len() as u16).to_be_bytes()); out.extend(v); };
                            a(&mut out, CHARSET, "attributes-charset", b"utf-8");
                            a(&mut out, LANGUAGE, "attributes-natural-language", b"en");
                            if !ok_type { out[2] = 0x04; }
                            if op == GET_PRINTER_ATTRIBUTES {
                                out.push(0x04);
                                a(&mut out, ENUM, "printer-state", &state.to_be_bytes());
                                a(&mut out, KEYWORD, "printer-state-reasons", if state == 5 { b"media-empty-error" } else { b"none" });
                                a(&mut out, 0x22, "printer-is-accepting-jobs", &[1]);
                                a(&mut out, MIME, "document-format-supported", b"application/pdf");
                                a(&mut out, MIME, "", b"image/jpeg");
                            } else if op == PRINT_JOB {
                                let r = parse(&b).unwrap();
                                // The document follows the end-of-attributes tag.
                                let mut i = 8; while i < b.len() && b[i] != END { i += 1; if b[i - 1] >= 0x10 { let nl = u16::from_be_bytes([b[i], b[i + 1]]) as usize; i += 2 + nl; let vl = u16::from_be_bytes([b[i], b[i + 1]]) as usize; i += 2 + vl; } }
                                documents.lock().unwrap().push(b[i + 1..].to_vec());
                                jobs.lock().unwrap().push(r);
                                out.push(JOB);
                                a(&mut out, INTEGER, "job-id", &42i32.to_be_bytes());
                            }
                            out.push(END);
                            Ok::<_, hyper::Error>(Response::builder().status(200).header("content-type", "application/ipp").body(Full::new(bytes::Bytes::from(out))).unwrap())
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn a_job_reaches_the_printer_with_its_attributes() {
        let (jobs, docs) = (std::sync::Arc::new(std::sync::Mutex::new(vec![])), std::sync::Arc::new(std::sync::Mutex::new(vec![])));
        let addr = printer(3, jobs.clone(), docs.clone()).await;
        let e = External { id: "ext_printer".into(), kind: "printer".into(), address: format!("ipp://{addr}/ipp/print"), ..Default::default() };
        let r = print(&e, "act_1", b"%PDF-1.4 hello", 9, Some((1, 2))).await.unwrap();
        assert_eq!(r, serde_json::json!({ "done": true, "job": 42 }));
        {
            let j = &jobs.lock().unwrap()[0];
            assert_eq!(j.int("copies"), Some(5)); // capped
            assert_eq!(j.strings("document-format"), vec!["application/pdf"]);
        }
        assert_eq!(docs.lock().unwrap()[0], b"%PDF-1.4 hello");
        assert!(print(&e, "act_2", b"<html>", 1, None).await.unwrap_err().contains("only PDF and JPEG"));
        // A stopped printer: refused before any job is sent.
        let addr = printer(5, jobs.clone(), docs.clone()).await;
        let e = External { address: format!("ipp://{addr}/ipp/print"), ..e };
        assert!(print(&e, "act_3", b"%PDF-1.4", 1, None).await.unwrap_err().contains("stopped (media-empty-error)"));
        assert_eq!(jobs.lock().unwrap().len(), 1);
    }
}
