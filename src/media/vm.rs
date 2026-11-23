//! Inputs are re-encoded in a VM before any host program reads them (docs/MEDIA.md §4, MACHINES.md §7): a crafted PNG,
//! WAV or MP4 meets ffmpeg inside a throwaway Apple `container` VM with no network, its input folder read-only, and
//! limits on memory, CPUs and time. Only what comes out (PNG, 16-bit WAV, H.264 MP4, with caps on pixels and length)
//! reaches mflux, mlx-audio or Whisper, and the host checks those files' headers before using them.
//! No VM here means jobs with files are refused (fail closed); jobs without files still run.
use crate::sandbox::{self, Runtime};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;

/// ffmpeg 7.1.1, static build, pinned by digest (an image index; the arm64 variant is used).
pub const FFMPEG_IMAGE: &str = "docker.io/mwader/static-ffmpeg@sha256:11a44711684c0b9f754c047dcd64235b8b52deab251bd0e0a86f22faa160749c";

/// Files are up to this big before re-encoding (the Gate's own limit).
pub const MAX_INPUT_BYTES: u64 = 50 * 1024 * 1024;
pub const MAX_SIDE: u32 = 2048;
pub const MAX_AUDIO_S: f64 = 600.0;
pub const MAX_VIDEO_S: f64 = 60.0;
pub const MAX_VIDEO_SIDE: u32 = 1920;
pub const MAX_VIDEO_FPS: u32 = 30;
/// Pixels ffmpeg agrees to decode in one frame, inside the VM (a decompression bomb stops there).
const DECODE_MAX_PIXELS: u64 = 100_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind { Image, Audio, Video }

impl Kind {
    pub fn of_media_type(t: &str) -> Option<Kind> {
        match t.split(';').next().unwrap_or("").trim().split('/').next() { Some("image") => Some(Kind::Image), Some("audio") => Some(Kind::Audio), Some("video") => Some(Kind::Video), _ => None }
    }
    pub fn ext(self) -> &'static str { match self { Kind::Image => "png", Kind::Audio => "wav", Kind::Video => "mp4" } }
    fn memory(self) -> &'static str { match self { Kind::Video => "2048M", _ => "1024M" } }
    fn timeout(self) -> Duration { Duration::from_secs(match self { Kind::Video => 300, _ => 120 }) }
}

/// ffmpeg's arguments inside the VM for input `i` (read from /in, written to /out). Nothing here comes from the job.
pub fn ffmpeg_args(kind: Kind, i: usize, mask: bool) -> Vec<String> {
    let mut a: Vec<String> = ["-hide_banner", "-loglevel", "error", "-nostdin", "-protocol_whitelist", "file", "-max_pixels", &DECODE_MAX_PIXELS.to_string(),
        "-i", &format!("/in/{i}"), "-map_metadata", "-1"].iter().map(|s| s.to_string()).collect();
    let rest: Vec<String> = match kind {
        Kind::Image => vec!["-map".into(), "0:v:0".into(), "-frames:v".into(), "1".into(),
            "-vf".into(), format!("scale=w='min({MAX_SIDE},iw)':h='min({MAX_SIDE},ih)':force_original_aspect_ratio=decrease"),
            "-pix_fmt".into(), if mask { "gray".into() } else { "rgb24".into() }, "-c:v".into(), "png".into(), "-f".into(), "image2".into(), format!("/out/{i}.png")],
        Kind::Audio => vec!["-map".into(), "0:a:0".into(), "-t".into(), format!("{MAX_AUDIO_S}"),
            "-af".into(), "aformat=sample_fmts=s16:sample_rates=16000|22050|24000|32000|44100|48000:channel_layouts=mono|stereo".into(),
            "-c:a".into(), "pcm_s16le".into(), "-f".into(), "wav".into(), format!("/out/{i}.wav")],
        Kind::Video => vec!["-map".into(), "0:v:0".into(), "-map".into(), "0:a:0?".into(), "-t".into(), format!("{MAX_VIDEO_S}"),
            "-vf".into(), format!("scale=w='min({MAX_VIDEO_SIDE},iw)':h='min({MAX_VIDEO_SIDE},ih)':force_original_aspect_ratio=decrease,scale=trunc(iw/2)*2:trunc(ih/2)*2"),
            "-fpsmax".into(), MAX_VIDEO_FPS.to_string(), "-c:v".into(), "libx264".into(), "-preset".into(), "veryfast".into(), "-crf".into(), "20".into(), "-pix_fmt".into(), "yuv420p".into(),
            "-c:a".into(), "aac".into(), "-ac".into(), "2".into(), "-b:a".into(), "128k".into(), "-movflags".into(), "+faststart".into(), "-f".into(), "mp4".into(), format!("/out/{i}.mp4")],
    };
    a.extend(rest);
    a
}

/// The VM runtime: Apple `container` on macOS, Podman with krun (a VM) or gVisor on Linux, and the same Podman inside
/// the WSL distro on Windows (sandbox.rs decides; plain containers are refused there too).
fn runtime() -> Result<Runtime, String> { sandbox::detect().map_err(|e| e.to_string()) }

/// Whether the VM path works here: the runtime is there (and running), and the pinned ffmpeg image is present (pulled
/// once if not).
pub async fn ready() -> Result<(), String> {
    let rt = runtime()?;
    let ok = |o: std::io::Result<std::process::Output>| o.map(|o| o.status.success()).unwrap_or(false);
    let (cli, has, pull): (&str, Vec<&str>, Vec<&str>) = match rt {
        Runtime::Apple => {
            if !ok(Command::new("container").args(["system", "status"]).output().await) { return Err("Apple container isn't running (container system start)".into()); }
            ("container", vec!["image", "inspect", FFMPEG_IMAGE], vec!["image", "pull", "--progress", "none", FFMPEG_IMAGE])
        }
        Runtime::Podman { .. } => ("podman", vec!["image", "exists", FFMPEG_IMAGE], vec!["pull", "--quiet", FFMPEG_IMAGE]),
    };
    if ok(sandbox::runtime_command(cli).args(&has).output().await) { return Ok(()); }
    eprintln!("media: pulling the pinned ffmpeg image for re-encoding inputs (once)");
    match tokio::time::timeout(Duration::from_secs(900), sandbox::runtime_command(cli).args(&pull).output()).await {
        Ok(o) if o.as_ref().map(|o| o.status.success()).unwrap_or(false) => Ok(()),
        _ => Err("couldn't get the ffmpeg image for re-encoding inputs".into()),
    }
}

/// The VM command for one input: no network, root file system read-only, no capabilities, the input folder read-only.
pub fn vm_args(rt: &Runtime, name: &str, job: &str, in_dir: &Path, out_dir: &Path, kind: Kind) -> Vec<String> {
    let label = format!("pavilion.job=media-{job}");
    let mut a: Vec<String> = match rt {
        Runtime::Apple => ["run", "--rm", "--progress", "none", "--name", name, "--label", &label, "--network", "none", "--no-dns", "--read-only", "--cap-drop", "ALL",
            "--arch", "arm64", "-m", kind.memory(), "-c", "2",
            "--mount", &format!("type=bind,source={},target=/in,readonly", in_dir.display()), "--mount", &format!("type=bind,source={},target=/out", out_dir.display())]
            .iter().map(|s| s.to_string()).collect(),
        Runtime::Podman { oci } => ["run", "--rm", "--name", name, "--label", &label, "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--runtime", oci, "--memory", &kind.memory().to_lowercase(), "--cpus", "2", "--pids-limit", "64",
            // Windows: the job folder is in the WSL distro, given to Podman as its Linux path.
            "-v", &format!("{}:/in:ro,Z", crate::platform::runtime_path(in_dir)), "-v", &format!("{}:/out:rw,Z", crate::platform::runtime_path(out_dir))]
            .iter().map(|s| s.to_string()).collect(),
    };
    a.push(FFMPEG_IMAGE.into());
    a
}

/// Re-encodes input `i` of `kind` from `in_dir/i` into `out_dir/i.<ext>` in a fresh VM, then checks the result's header.
/// Returns the file and, for audio and video, its length in seconds.
pub async fn reencode(job: &str, in_dir: &Path, out_dir: &Path, i: usize, kind: Kind, mask: bool) -> Result<(PathBuf, Option<f64>), String> {
    let rt = runtime()?;
    let name = format!("pav-media-{}-{i}", job.trim_start_matches("mj_"));
    let mut args = vm_args(&rt, &name, job, in_dir, out_dir, kind);
    args.extend(ffmpeg_args(kind, i, mask));
    let cli = if rt == Runtime::Apple { "container" } else { "podman" };
    let run = sandbox::runtime_command(cli).args(&args).stdin(std::process::Stdio::null()).kill_on_drop(true).output();
    let out = match tokio::time::timeout(kind.timeout(), run).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return Err(format!("couldn't start the re-encoding VM: {e}")),
        Err(_) => { stop(cli, &name).await; return Err(format!("re-encoding input {} took longer than {} s", i + 1, kind.timeout().as_secs())); }
    };
    if !out.status.success() {
        let why: String = String::from_utf8_lossy(&out.stderr).lines().filter(|l| !l.trim().is_empty()).last().unwrap_or("").chars().take(200).collect();
        return Err(format!("input {} isn't a readable {} file{}", i + 1, match kind { Kind::Image => "image", Kind::Audio => "audio", Kind::Video => "video" }, if why.is_empty() { String::new() } else { format!(" ({why})") }));
    }
    let f = out_dir.join(format!("{i}.{}", kind.ext()));
    let secs = match kind {
        Kind::Image => { check_png(&f, MAX_SIDE)?; None }
        Kind::Audio => Some(check_wav(&f, MAX_AUDIO_S + 1.0)?.seconds),
        Kind::Video => { check_mp4(&f)?; Some(MAX_VIDEO_S) }
    };
    Ok((f, secs))
}

async fn stop(cli: &str, name: &str) {
    if cli == "container" { let _ = Command::new(cli).args(["stop", name]).output().await; let _ = Command::new(cli).args(["delete", "--force", name]).output().await; }
    else { let _ = sandbox::runtime_command(cli).args(["rm", "--force", "--time", "2", name]).output().await; }
}

/* ---------- the host checks what came out, without decoding it ---------- */

fn read_head(p: &Path, n: usize, max_len: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let md = std::fs::symlink_metadata(p).map_err(|_| "the re-encoded file is missing".to_string())?;
    if !md.is_file() { return Err("the re-encoded file isn't a plain file".into()); }
    if md.len() > max_len { return Err(format!("the re-encoded file is too big ({} MB)", md.len() >> 20)); }
    let mut b = vec![0u8; n];
    let k = std::fs::File::open(p).and_then(|mut f| f.read(&mut b)).map_err(|e| e.to_string())?;
    b.truncate(k);
    Ok(b)
}

/// A PNG whose first chunk says it's at most `max_side` on each side. Returns (width, height).
pub fn check_png(p: &Path, max_side: u32) -> Result<(u32, u32), String> {
    let b = read_head(p, 33, 200 << 20)?;
    if b.len() < 33 || &b[..8] != b"\x89PNG\r\n\x1a\n" || &b[12..16] != b"IHDR" { return Err("the re-encoded image isn't a PNG".into()); }
    let (w, h) = (u32::from_be_bytes(b[16..20].try_into().unwrap()), u32::from_be_bytes(b[20..24].try_into().unwrap()));
    if w == 0 || h == 0 || w > max_side || h > max_side { return Err(format!("the re-encoded image is {w}x{h}, over the {max_side} px limit")); }
    Ok((w, h))
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Wav { pub rate: u32, pub channels: u16, pub data_at: usize, pub data_len: usize, pub seconds: f64 }

/// Reads a 16-bit PCM WAV's header.
pub fn parse_wav(b: &[u8]) -> Result<Wav, String> {
    if b.len() < 12 || &b[..4] != b"RIFF" || &b[8..12] != b"WAVE" { return Err("not a WAV file".into()); }
    let (mut at, mut fmt) = (12usize, None);
    while at + 8 <= b.len() {
        let id = &b[at..at + 4];
        let len = u32::from_le_bytes(b[at + 4..at + 8].try_into().unwrap()) as usize;
        let body = at + 8;
        if id == b"fmt " && len >= 16 && body + 16 <= b.len() {
            let f = &b[body..body + 16];
            let (format, ch, rate, bits) = (u16::from_le_bytes([f[0], f[1]]), u16::from_le_bytes([f[2], f[3]]), u32::from_le_bytes(f[4..8].try_into().unwrap()), u16::from_le_bytes([f[14], f[15]]));
            if format != 1 || bits != 16 || !(1..=2).contains(&ch) || !(8000..=48000).contains(&rate) { return Err("not 16-bit PCM, mono or stereo, up to 48 kHz".into()); }
            fmt = Some((rate, ch));
        } else if id == b"data" {
            let (rate, ch) = fmt.ok_or("a WAV's data came before its format")?;
            let len = len.min(b.len().saturating_sub(body)); // ffmpeg writing to a pipe leaves the length unset
            return Ok(Wav { rate, channels: ch, data_at: body, data_len: len, seconds: len as f64 / (rate as f64 * ch as f64 * 2.0) });
        }
        at = body + len + (len & 1);
    }
    Err("a WAV without audio data".into())
}

/// A 16-bit PCM WAV no longer than `max_s`.
pub fn check_wav(p: &Path, max_s: f64) -> Result<Wav, String> {
    read_head(p, 0, 400 << 20)?; // size and kind first
    let b = std::fs::read(p).map_err(|e| e.to_string())?;
    let w = parse_wav(&b).map_err(|e| format!("the re-encoded audio: {e}"))?;
    if w.seconds > max_s { return Err(format!("the re-encoded audio is {:.0} s, over the {max_s:.0} s limit", w.seconds)); }
    Ok(w)
}

pub fn check_mp4(p: &Path) -> Result<(), String> {
    let b = read_head(p, 12, 400 << 20)?;
    if b.len() < 12 || &b[4..8] != b"ftyp" { return Err("the re-encoded video isn't an MP4".into()); }
    Ok(())
}

/// A WAV header for 16-bit PCM.
pub fn wav_header(rate: u32, channels: u16, data_len: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(44);
    h.extend(b"RIFF"); h.extend((36 + data_len).to_le_bytes()); h.extend(b"WAVEfmt ");
    h.extend(16u32.to_le_bytes()); h.extend(1u16.to_le_bytes()); h.extend(channels.to_le_bytes()); h.extend(rate.to_le_bytes());
    h.extend((rate * channels as u32 * 2).to_le_bytes()); h.extend((channels * 2).to_le_bytes()); h.extend(16u16.to_le_bytes());
    h.extend(b"data"); h.extend(data_len.to_le_bytes());
    h
}

/// Splits a (re-encoded, checked) WAV into pieces of at most `chunk_s` seconds, in `dir`. A short one is used as it is.
pub fn split_wav(src: &Path, dir: &Path, chunk_s: f64) -> Result<Vec<(PathBuf, f64)>, String> {
    let b = std::fs::read(src).map_err(|e| e.to_string())?;
    let w = parse_wav(&b)?;
    if w.seconds <= chunk_s { return Ok(vec![(src.to_path_buf(), w.seconds)]); }
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let frame = w.channels as usize * 2;
    let per = (chunk_s * w.rate as f64) as usize * frame;
    let data = &b[w.data_at..w.data_at + w.data_len];
    data.chunks(per).enumerate().map(|(i, c)| {
        let p = dir.join(format!("{i:03}.wav"));
        let mut f = wav_header(w.rate, w.channels, c.len() as u32);
        f.extend_from_slice(c);
        std::fs::write(&p, f).map_err(|e| e.to_string())?;
        Ok((p, c.len() as f64 / (w.rate as f64 * frame as f64)))
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tmp() -> PathBuf { let d = std::env::temp_dir().join(format!("pavilion-vm-{}", rand::random::<u32>())); std::fs::create_dir_all(&d).unwrap(); d }
    fn wav(rate: u32, ch: u16, secs: f64) -> Vec<u8> {
        let n = (rate as f64 * secs) as usize * ch as usize * 2;
        let mut v = wav_header(rate, ch, n as u32); v.extend(vec![0u8; n]); v
    }

    #[test]
    fn the_vm_command_has_caps_and_nothing_from_the_job() {
        let a = ffmpeg_args(Kind::Image, 0, false).join(" ");
        assert!(a.contains("-protocol_whitelist file") && a.contains("-max_pixels 100000000") && a.contains("min(2048,iw)") && a.ends_with("/out/0.png"));
        assert!(ffmpeg_args(Kind::Image, 1, true).contains(&"gray".to_string()));
        let a = ffmpeg_args(Kind::Audio, 2, false).join(" ");
        assert!(a.contains("-t 600") && a.contains("pcm_s16le") && a.contains("-i /in/2") && a.ends_with("/out/2.wav"));
        let a = ffmpeg_args(Kind::Video, 0, false).join(" ");
        assert!(a.contains("-t 60") && a.contains("libx264") && a.contains("-fpsmax 30") && a.contains("min(1920,iw)"));
        assert!(FFMPEG_IMAGE.contains("@sha256:") && FFMPEG_IMAGE.len() > 80);
        // The VM: no network, read-only, the input folder read-only, on both runtimes.
        for rt in [Runtime::Apple, Runtime::Podman { oci: "krun" }] {
            let a = vm_args(&rt, "pav-media-x-0", "mj_x", Path::new("/j/in"), Path::new("/j/refs"), Kind::Audio).join(" ");
            assert!(a.contains("--network none") && a.contains("--read-only") && a.contains("--cap-drop ALL") && a.ends_with(FFMPEG_IMAGE), "{a}");
            assert!(a.contains("/j/in,target=/in,readonly") || a.contains("/j/in:/in:ro"), "{a}");
        }
        assert!(vm_args(&Runtime::Podman { oci: "runsc" }, "n", "j", Path::new("/a"), Path::new("/b"), Kind::Video).join(" ").contains("--runtime runsc --memory 2048m"));
        assert_eq!(Kind::of_media_type("image/png"), Some(Kind::Image));
        assert_eq!(Kind::of_media_type("audio/wav; codecs=1"), Some(Kind::Audio));
        assert_eq!(Kind::of_media_type("application/pdf"), None);
    }

    #[test]
    fn png_headers_are_checked_against_the_pixel_cap() {
        let d = tmp();
        let png = |w: u32, h: u32| { let mut v = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec(); v.extend(w.to_be_bytes()); v.extend(h.to_be_bytes()); v.extend([8, 2, 0, 0, 0, 0, 0, 0, 0]); v };
        std::fs::write(d.join("ok.png"), png(1024, 768)).unwrap();
        assert_eq!(check_png(&d.join("ok.png"), 2048), Ok((1024, 768)));
        std::fs::write(d.join("big.png"), png(4096, 10)).unwrap();
        assert!(check_png(&d.join("big.png"), 2048).unwrap_err().contains("over the 2048"));
        std::fs::write(d.join("fake.png"), b"GIF89a.......................................").unwrap();
        assert!(check_png(&d.join("fake.png"), 2048).is_err());
        std::os::unix::fs::symlink("/etc/hosts", d.join("link.png")).unwrap();
        assert!(check_png(&d.join("link.png"), 2048).unwrap_err().contains("plain file"));
        assert!(check_png(&d.join("none.png"), 2048).is_err());
        assert!(check_mp4(&d.join("ok.png")).is_err());
    }

    #[test]
    fn wav_headers_and_durations() {
        let d = tmp();
        std::fs::write(d.join("a.wav"), wav(24000, 1, 2.0)).unwrap();
        let w = check_wav(&d.join("a.wav"), 601.0).unwrap();
        assert_eq!((w.rate, w.channels), (24000, 1));
        assert!((w.seconds - 2.0).abs() < 1e-6);
        assert!(check_wav(&d.join("a.wav"), 1.0).unwrap_err().contains("over the 1 s"));
        let mut float = wav(24000, 1, 0.1); float[20] = 3; // IEEE float
        assert!(parse_wav(&float).is_err());
        let mut six = wav(48000, 6, 0.1); six[22] = 6;
        assert!(parse_wav(&six).is_err());
        assert!(parse_wav(b"RIFF\0\0\0\0WAVE").is_err());
    }

    #[test]
    fn long_audio_is_split_into_pieces() {
        let d = tmp();
        std::fs::write(d.join("long.wav"), wav(16000, 1, 25.0)).unwrap();
        let parts = split_wav(&d.join("long.wav"), &d.join("chunks"), 10.0).unwrap();
        assert_eq!(parts.len(), 3);
        assert!((parts[0].1 - 10.0).abs() < 1e-6 && (parts[2].1 - 5.0).abs() < 1e-6);
        let w = check_wav(&parts[2].0, 600.0).unwrap();
        assert!((w.seconds - 5.0).abs() < 1e-6);
        let short = split_wav(&d.join("long.wav"), &d.join("c2"), 60.0).unwrap();
        assert_eq!(short, vec![(d.join("long.wav"), 25.0)]);
    }
}
