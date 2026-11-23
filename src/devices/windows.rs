//! Windows: device actions on the Windows side, never in WSL (docs/DEVICES.md §3). Camera and microphone through WinRT
//! `MediaCapture`, the screen through GDI, location through `Geolocator`, speech and sounds through
//! `SpeechSynthesizer` / `MediaPlayer`, the person through a message box, and presence through Windows Hello
//! (`UserConsentVerifier`). Bluetooth LE and the local network are the shared code in caps.rs (btleplug's WinRT
//! backend, mdns-sd). Compile-checked from macOS, not run yet (node/windows/TESTING.md §devices).
use super::caps::{round_position, Op, Output};
use super::{Ask, Decision, Preview};
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use windows::core::{HSTRING, PCWSTR};
use windows::Devices::Enumeration::{DeviceClass, DeviceInformation, Panel};
use windows::Devices::Geolocation::{GeolocationAccessStatus, Geolocator};
use windows::Graphics::Imaging::{BitmapAlphaMode, BitmapDecoder, BitmapEncoder, BitmapInterpolationMode, BitmapPixelFormat};
use windows::Media::Capture::{MediaCapture, MediaCaptureInitializationSettings, StreamingCaptureMode};
use windows::Media::Core::MediaSource;
use windows::Media::MediaProperties::{AudioEncodingQuality, ImageEncodingProperties, MediaEncodingProfile, VideoEncodingQuality};
use windows::Media::Playback::{MediaPlaybackState, MediaPlayer};
use windows::Media::SpeechSynthesis::SpeechSynthesizer;
use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability};
use windows::Storage::Streams::{DataReader, DataWriter, IRandomAccessStream, InMemoryRandomAccessStream};
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::Graphics::Gdi::{BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC, GetDIBits, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, SRCCOPY};
use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, GetSystemMetrics, MessageBoxW, PostMessageW, IDOK, IDNO, IDYES, MB_DEFBUTTON2, MB_ICONQUESTION, MB_ICONINFORMATION, MB_OKCANCEL, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN, WM_COMMAND};

fn e(err: windows::core::Error) -> String {
    let s = err.message().to_string();
    if err.code().0 as u32 == 0x80070005 { format!("Windows refused access (Settings › Privacy & security: allow camera, microphone or location for desktop apps): {s}") } else { s }
}

/// Everything WinRT here blocks, so it runs on a blocking thread.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f).await.map_err(|err| err.to_string())?
}

fn read_all(stream: &InMemoryRandomAccessStream) -> Result<Vec<u8>, String> {
    let size = stream.Size().map_err(e)? as u32;
    let reader = DataReader::CreateDataReader(&stream.GetInputStreamAt(0).map_err(e)?).map_err(e)?;
    reader.LoadAsync(size).map_err(e)?.join().map_err(e)?;
    let mut buf = vec![0u8; size as usize];
    reader.ReadBytes(&mut buf).map_err(e)?;
    Ok(buf)
}

/// `front` / `back` (by the panel Windows reports) or a camera's id or name.
fn camera_id(which: &str) -> Result<HSTRING, String> {
    let all = DeviceInformation::FindAllAsyncDeviceClass(DeviceClass::VideoCapture).map_err(e)?.join().map_err(e)?;
    let mut list = vec![];
    for i in 0..all.Size().map_err(e)? { list.push(all.GetAt(i).map_err(e)?); }
    if list.is_empty() { return Err("this PC has no camera".into()); }
    let panel = |d: &DeviceInformation| d.EnclosureLocation().and_then(|l| l.Panel()).ok();
    let pick = match which {
        "front" => list.iter().find(|d| panel(d) == Some(Panel::Front)).or(list.first()),
        "back" => list.iter().find(|d| panel(d) == Some(Panel::Back)),
        id => list.iter().find(|d| d.Id().map_or(false, |x| x.to_string() == id) || d.Name().map_or(false, |x| x.to_string() == id)),
    };
    pick.map(|d| d.Id().map_err(e)).unwrap_or_else(|| Err(format!("no {which} camera on this PC")))
}

fn capture(mode: StreamingCaptureMode, camera: Option<&str>) -> Result<MediaCapture, String> {
    let s = MediaCaptureInitializationSettings::new().map_err(e)?;
    s.SetStreamingCaptureMode(mode).map_err(e)?;
    if let Some(c) = camera { s.SetVideoDeviceId(&camera_id(c)?).map_err(e)?; }
    let mc = MediaCapture::new().map_err(e)?;
    mc.InitializeWithSettingsAsync(&s).map_err(e)?.join().map_err(e)?;
    Ok(mc)
}

fn photo(camera: &str, max_px: u32) -> Result<Vec<u8>, String> {
    let mc = capture(StreamingCaptureMode::Video, Some(camera))?;
    std::thread::sleep(Duration::from_millis(1200)); // exposure settles
    let raw = InMemoryRandomAccessStream::new().map_err(e)?;
    mc.CapturePhotoToStreamAsync(&ImageEncodingProperties::CreateJpeg().map_err(e)?, &raw).map_err(e)?.join().map_err(e)?;
    let _ = mc.Close();
    // Scaled to max_px on the long side, re-encoded as a fresh JPEG.
    raw.Seek(0).map_err(e)?;
    let dec = BitmapDecoder::CreateAsync(&raw).map_err(e)?.join().map_err(e)?;
    let (w, h) = (dec.PixelWidth().map_err(e)?, dec.PixelHeight().map_err(e)?);
    let scale = (max_px as f64 / w.max(h) as f64).min(1.0);
    let px = dec.GetPixelDataAsync().map_err(e)?.join().map_err(e)?.DetachPixelData().map_err(e)?;
    let out = InMemoryRandomAccessStream::new().map_err(e)?;
    let enc = BitmapEncoder::CreateAsync(BitmapEncoder::JpegEncoderId().map_err(e)?, &out).map_err(e)?.join().map_err(e)?;
    enc.SetPixelData(dec.BitmapPixelFormat().map_err(e)?, dec.BitmapAlphaMode().map_err(e)?, w, h, 96.0, 96.0, &px).map_err(e)?;
    let t = enc.BitmapTransform().map_err(e)?;
    t.SetScaledWidth(((w as f64) * scale).round() as u32).map_err(e)?;
    t.SetScaledHeight(((h as f64) * scale).round() as u32).map_err(e)?;
    t.SetInterpolationMode(BitmapInterpolationMode::Fant).map_err(e)?;
    enc.FlushAsync().map_err(e)?.join().map_err(e)?;
    read_all(&out)
}

fn record(mode: StreamingCaptureMode, camera: Option<&str>, profile: MediaEncodingProfile, seconds: u32) -> Result<Vec<u8>, String> {
    let mc = capture(mode, camera)?;
    let out = InMemoryRandomAccessStream::new().map_err(e)?;
    mc.StartRecordToStreamAsync(&profile, &out).map_err(e)?.join().map_err(e)?;
    std::thread::sleep(Duration::from_secs(seconds as u64));
    mc.StopRecordAsync().map_err(e)?.join().map_err(e)?;
    let _ = mc.Close();
    read_all(&out)
}

/// The whole virtual screen (every monitor), through GDI, as PNG.
fn screen() -> Result<Vec<u8>, String> {
    unsafe {
        let (x, y, w, h) = (GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN), GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN));
        if w <= 0 || h <= 0 { return Err("no screen".into()); }
        let screen = GetDC(None);
        let mem = CreateCompatibleDC(Some(screen));
        let bmp = CreateCompatibleBitmap(screen, w, h);
        let old = SelectObject(mem, bmp.into());
        let ok = BitBlt(mem, 0, 0, w, h, Some(screen), x, y, SRCCOPY).is_ok();
        let mut info = BITMAPINFO { bmiHeader: BITMAPINFOHEADER { biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32, biWidth: w, biHeight: -h, biPlanes: 1, biBitCount: 32, biCompression: BI_RGB.0, ..Default::default() }, ..Default::default() };
        let mut px = vec![0u8; (w * h * 4) as usize];
        let lines = GetDIBits(mem, bmp, 0, h as u32, Some(px.as_mut_ptr() as *mut _), &mut info, DIB_RGB_COLORS);
        SelectObject(mem, old);
        let _ = DeleteObject(bmp.into());
        let _ = DeleteDC(mem);
        ReleaseDC(None, screen);
        if !ok || lines == 0 { return Err("couldn't copy the screen".into()); }
        let out = InMemoryRandomAccessStream::new().map_err(e)?;
        let enc = BitmapEncoder::CreateAsync(BitmapEncoder::PngEncoderId().map_err(e)?, &out).map_err(e)?.join().map_err(e)?;
        enc.SetPixelData(BitmapPixelFormat::Bgra8, BitmapAlphaMode::Ignore, w as u32, h as u32, 96.0, 96.0, &px).map_err(e)?;
        enc.FlushAsync().map_err(e)?.join().map_err(e)?;
        read_all(&out)
    }
}

fn locate(accuracy_m: u32) -> Result<serde_json::Value, String> {
    if Geolocator::RequestAccessAsync().map_err(e)?.join().map_err(e)? != GeolocationAccessStatus::Allowed {
        return Err("location isn't allowed for desktop apps: Settings › Privacy & security › Location".into());
    }
    let g = Geolocator::new().map_err(e)?;
    let pos = g.GetGeopositionAsync().map_err(e)?.join().map_err(e)?;
    let c = pos.Coordinate().map_err(e)?;
    let p = c.Point().map_err(e)?.Position().map_err(e)?;
    let (lat, lon) = round_position(p.Latitude, p.Longitude, accuracy_m);
    Ok(json!({ "lat": (lat * 1e6).round() / 1e6, "lon": (lon * 1e6).round() / 1e6, "accuracy_m": c.Accuracy().map_err(e)?.max(accuracy_m as f64).round(), "at": super::now() }))
}

fn play(text: Option<String>, bytes: Option<Vec<u8>>) -> Result<(), String> {
    let player = MediaPlayer::new().map_err(e)?;
    let source = if let Some(t) = text {
        let s = SpeechSynthesizer::new().map_err(e)?.SynthesizeTextToStreamAsync(&HSTRING::from(t)).map_err(e)?.join().map_err(e)?;
        MediaSource::CreateFromStream(&s, &s.ContentType().map_err(e)?).map_err(e)?
    } else {
        let b = bytes.ok_or("nothing to play")?;
        let s = InMemoryRandomAccessStream::new().map_err(e)?;
        let w = DataWriter::CreateDataWriter(&s).map_err(e)?;
        w.WriteBytes(&b).map_err(e)?;
        w.StoreAsync().map_err(e)?.join().map_err(e)?;
        let _ = w.DetachStream();
        s.Seek(0).map_err(e)?;
        let rs: IRandomAccessStream = windows::core::Interface::cast(&s).map_err(e)?;
        MediaSource::CreateFromStream(&rs, &HSTRING::from("")).map_err(e)?
    };
    player.SetSource(&source).map_err(e)?;
    player.Play().map_err(e)?;
    let session = player.PlaybackSession().map_err(e)?;
    let mut started = false;
    for _ in 0..1200 { // at most 2 minutes
        std::thread::sleep(Duration::from_millis(100));
        let st = session.PlaybackState().map_err(e)?;
        if st == MediaPlaybackState::Playing { started = true; } else if started { break; }
    }
    let _ = player.Close();
    Ok(())
}

pub async fn run(op: &Op, asset: Option<Vec<u8>>) -> Result<Output, String> {
    let op = op.clone();
    blocking(move || Ok(match op {
        Op::CameraSnapshot { camera, max_px } => Output::Bytes { ctype: "image/jpeg".into(), bytes: photo(&camera, max_px)? },
        Op::CameraClip { camera, seconds } => {
            let p = MediaEncodingProfile::CreateMp4(VideoEncodingQuality::HD720p).map_err(e)?;
            p.SetAudio(None).map_err(e)?; // video only: the microphone is its own capability
            Output::Bytes { ctype: "video/mp4".into(), bytes: record(StreamingCaptureMode::Video, Some(&camera), p, seconds)? }
        }
        Op::RecordAudio { seconds } => Output::Bytes { ctype: "audio/mp4".into(), bytes: record(StreamingCaptureMode::Audio, None, MediaEncodingProfile::CreateM4a(AudioEncodingQuality::Medium).map_err(e)?, seconds)? },
        Op::ScreenCapture => Output::Bytes { ctype: "image/png".into(), bytes: screen()? },
        Op::Location { accuracy_m } => Output::Json(locate(accuracy_m)?),
        Op::PlayAudio { text, .. } => { play(text, asset)?; Output::Json(json!({ "done": true })) }
        _ => return Err("not a platform operation".into()),
    })).await
}

/* ---------- the person ---------- */

fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }

/// A message box that answers itself with `auto` after `seconds` (and says so through the flag).
fn timed_box(title: &str, text: &str, style: windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE, seconds: u64, auto: i32) -> (i32, bool) {
    let title = format!("{title} ({:04x})", rand::random::<u16>()); // unique, so the timer finds this one
    let fired = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    {
        let (title, fired, done) = (title.clone(), fired.clone(), done.clone());
        std::thread::spawn(move || {
            let end = std::time::Instant::now() + Duration::from_secs(seconds);
            while std::time::Instant::now() < end { if done.load(Ordering::Relaxed) { return; } std::thread::sleep(Duration::from_millis(200)); }
            let t = wide(&title);
            unsafe {
                if let Ok(h) = FindWindowW(PCWSTR::null(), PCWSTR(t.as_ptr())) {
                    fired.store(true, Ordering::Relaxed);
                    let _ = PostMessageW(Some(h), WM_COMMAND, WPARAM(auto as usize), LPARAM(0));
                }
            }
        });
    }
    let (t, b) = (wide(&title), wide(text));
    let r = unsafe { MessageBoxW(None::<HWND>, PCWSTR(b.as_ptr()), PCWSTR(t.as_ptr()), style | MB_TOPMOST | MB_SETFOREGROUND) };
    done.store(true, Ordering::Relaxed);
    (r.0, fired.load(Ordering::Relaxed))
}

pub async fn ask(a: &Ask) -> Result<Decision, String> {
    let left = a.expires_at.saturating_sub(super::now());
    if left == 0 { return Ok(Decision::NoAnswer); }
    let mut text = format!("{}\n\n{}", a.text, a.detail);
    if let Some(d) = &a.device { text += &format!("\n\nDevice: {d}"); }
    if let Some(r) = &a.reason { text += &format!("\n\nThe agent ({}) says: \u{201c}{r}\u{201d}", a.agent); }
    if a.presence { text += "\n\nYes asks for Windows Hello (face, fingerprint or PIN)."; }
    text += "\n\nYes: allow it once.   No: deny it.";
    let (presence, agent, summary) = (a.presence, a.agent.clone(), a.text.clone());
    blocking(move || {
        let (r, timed_out) = timed_box("Pavilion Node: an agent is asking", &text, MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2, left, IDNO.0);
        if timed_out { return Ok(Decision::NoAnswer); }
        if r != IDYES.0 { return Ok(Decision::Deny); }
        if !presence { return Ok(Decision::Allow); }
        // Presence: Windows Hello, or nothing. A PC without it set up can't allow captures and acts.
        if UserConsentVerifier::CheckAvailabilityAsync().map_err(e)?.join().map_err(e)? != UserConsentVerifierAvailability::Available {
            return Err("Windows Hello isn't set up on this PC, so it can't confirm you're here (Settings › Accounts › Sign-in options)".into());
        }
        let msg: String = format!("Allow {agent}: {summary}").chars().take(150).collect();
        let r = UserConsentVerifier::RequestVerificationAsync(&HSTRING::from(msg)).map_err(e)?.join().map_err(e)?;
        Ok(if r == UserConsentVerificationResult::Verified { Decision::Allow } else { Decision::Deny })
    }).await
}

pub async fn preview(p: &Preview) -> Result<bool, String> {
    let what = match p.kind { "image" => "the photo or screenshot", "video" => "the video", "audio" => "the recording", _ => "this" };
    let mut text = format!("About to send {what} to the agent.");
    if let Some(t) = &p.text { text += &format!("\n\n{t}"); }
    if let Some(f) = &p.path { text += &format!("\n\nSaved for you to look at until it's sent: {}", f.display()); }
    text += &format!("\n\nOK: send now.   Cancel: send nothing.\nIt's sent by itself in {} seconds.", p.seconds);
    let secs = p.seconds as u64;
    blocking(move || { let (r, _) = timed_box("Pavilion Node: about to send", &text, MB_OKCANCEL | MB_ICONINFORMATION, secs, IDOK.0); Ok(r == IDOK.0) }).await
}

pub fn status() -> String {
    let hello = UserConsentVerifier::CheckAvailabilityAsync().and_then(|o| o.join()).map(|a| a == UserConsentVerifierAvailability::Available).unwrap_or(false);
    format!("This PC: Windows Hello {} (needed to allow captures and acts). Camera, microphone and location for desktop apps are in Settings › Privacy & security.",
        if hello { "is set up" } else { "is NOT set up" })
}
