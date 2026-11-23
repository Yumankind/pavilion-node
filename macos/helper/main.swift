// pavilion-devices: the part of Pavilion Node.app that uses Apple's frameworks for device actions
// (docs/DEVICES.md §4, node/src/devices/helper.rs).
//
// It reads ONE typed JSON request on stdin and writes ONE JSON answer on stdout, then exits. The `op` is one of a fixed
// list below; there is no generic "run this" request. Captures go to the file the node names (`out`), in the node's
// private folder. The node runs it inside the app bundle, so macOS asks for camera, microphone, screen and location
// permission once, for "Pavilion Node".
//
//   permissions                         what's granted, read without asking
//   ask {text, reason?, agent, device?, detail, presence, seconds}   Allow / Deny; Touch ID or password after Allow when presence
//   preview {kind, path?, text?, seconds}                            Cancel / Send now, sends itself after `seconds`
//   camera_snapshot {camera, max_px, out}   camera_clip {camera, seconds, out}   record_audio {seconds, out}
//   screen_capture {out}   location {accuracy_m}   play_audio {text? | path?}
import AppKit
import AVFoundation
import AVKit
import CoreBluetooth
import CoreLocation
import Foundation
import LocalAuthentication
import ScreenCaptureKit

setvbuf(stdout, nil, _IOLBF, 0)

func emit(_ v: [String: Any]) -> Never {
    let data = (try? JSONSerialization.data(withJSONObject: v, options: [])) ?? Data("{\"ok\":false,\"error\":\"unencodable answer\"}".utf8)
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
    exit(0)
}
func fail(_ why: String) -> Never { emit(["ok": false, "error": why]) }

struct HelperError: Error { let why: String; init(_ w: String) { why = w } }

guard let line = readLine(strippingNewline: true), let reqData = line.data(using: .utf8),
      let req = (try? JSONSerialization.jsonObject(with: reqData)) as? [String: Any], let op = req["op"] as? String else {
    fail("expected one JSON request on stdin")
}
func str(_ k: String) -> String? { req[k] as? String }
func int(_ k: String, _ lo: Int, _ hi: Int, _ d: Int) -> Int { let n = (req[k] as? NSNumber)?.intValue ?? d; return min(max(n, lo), hi) }
/// Output files only inside the node's own folder.
func outURL() throws -> URL {
    guard let p = str("out"), p.hasPrefix("/"), p.contains("/pavilion-node/devices/"), !p.contains("/../") else { throw HelperError("out must be a file in the node's devices folder") }
    return URL(fileURLWithPath: p)
}

/* ---------- permissions ---------- */

func avStatus(_ m: AVMediaType) -> String {
    switch AVCaptureDevice.authorizationStatus(for: m) { case .authorized: return "granted"; case .denied: return "denied"; case .restricted: return "restricted"; default: return "not asked yet" }
}
func permissions() -> [String: Any] {
    let loc: String
    switch CLLocationManager().authorizationStatus { case .authorizedAlways, .authorized: loc = "granted"; case .denied: loc = "denied"; case .restricted: loc = "restricted"; default: loc = "not asked yet" }
    let bt: String
    switch CBManager.authorization { case .allowedAlways: bt = "granted"; case .denied: bt = "denied"; case .restricted: bt = "restricted"; default: bt = "not asked yet" }
    return ["camera": avStatus(.video), "microphone": avStatus(.audio), "screen": CGPreflightScreenCaptureAccess() ? "granted" : "not granted",
            "location": loc, "bluetooth": bt, "local network": "asked by macOS on the first scan (not readable)",
            "bundle": Bundle.main.bundleIdentifier ?? "none (not inside Pavilion Node.app)"]
}

func needAccess(_ m: AVMediaType, _ name: String, _ pane: String) async throws {
    switch AVCaptureDevice.authorizationStatus(for: m) {
    case .authorized: return
    case .notDetermined:
        if await AVCaptureDevice.requestAccess(for: m) { return }
        throw HelperError("\(name) permission was declined for Pavilion Node")
    default: throw HelperError("\(name) permission is off for Pavilion Node: System Settings › Privacy & Security › \(pane)")
    }
}

/* ---------- the person: ask, presence, preview ---------- */

@MainActor func bringForward() { NSApp.setActivationPolicy(.accessory); NSApp.activate(ignoringOtherApps: true) }

@MainActor func askWindow(seconds: Int) -> String {
    bringForward()
    let a = NSAlert()
    a.alertStyle = .warning
    a.messageText = str("text") ?? "An agent is asking to use this computer"
    var info = str("detail") ?? ""
    if let d = str("device") { info += "\n\nDevice: \(d)" }
    if let r = str("reason"), !r.isEmpty { info += "\n\nThe agent (\(str("agent") ?? "?")) says: “\(r)”" }
    if req["presence"] as? Bool == true { info += "\n\nAllow asks for Touch ID or your password." }
    info += "\n\nThis question closes by itself in \(seconds / 60 > 0 ? "\(seconds / 60) min " : "")\(seconds % 60) s."
    a.informativeText = info
    a.addButton(withTitle: "Deny")   // the default (Return) is the safe answer
    a.addButton(withTitle: "Allow")
    a.window.level = .floating
    var timedOut = false
    let t = Timer(timeInterval: TimeInterval(seconds), repeats: false) { _ in timedOut = true; NSApp.abortModal() }
    RunLoop.main.add(t, forMode: .modalPanel)
    let r = a.runModal()
    t.invalidate()
    if timedOut { return "timeout" }
    return r == .alertSecondButtonReturn ? "allow" : "deny"
}

func presence(_ reason: String) async -> Bool {
    let ctx = LAContext()
    var err: NSError?
    guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else { return false }
    return (try? await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)) ?? false
}

final class PreviewController: NSObject {
    var left: Int
    let label = NSTextField(labelWithString: "")
    var timer: Timer?
    var player: AVPlayer?
    init(seconds: Int) { left = seconds }
    @objc func cancel() { NSApp.stopModal(withCode: .cancel) }
    @objc func send() { NSApp.stopModal(withCode: .OK) }
    func tick() { left -= 1; label.stringValue = "Sending in \(max(left, 0)) s"; if left <= 0 { send() } }
}

@MainActor func previewWindow() throws -> Bool {
    bringForward()
    let seconds = int("seconds", 1, 30, 3)
    let kind = str("kind") ?? "text"
    let c = PreviewController(seconds: seconds)
    let w = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 560, height: 470), styleMask: [.titled], backing: .buffered, defer: false)
    w.title = "Pavilion Node: about to send"
    w.level = .floating
    let v = NSView(frame: w.contentRect(forFrameRect: w.frame))
    w.contentView = v
    let media = NSRect(x: 20, y: 70, width: 520, height: 380)
    switch kind {
    case "image":
        guard let p = str("path"), let img = NSImage(contentsOfFile: p) else { throw HelperError("no image to show") }
        let iv = NSImageView(frame: media); iv.image = img; iv.imageScaling = .scaleProportionallyUpOrDown; v.addSubview(iv)
    case "video", "audio":
        guard let p = str("path") else { throw HelperError("nothing to play") }
        let pv = AVPlayerView(frame: media); let player = AVPlayer(url: URL(fileURLWithPath: p)); pv.player = player; c.player = player; v.addSubview(pv); player.play()
        if kind == "audio" { let l = NSTextField(labelWithString: "Recording from the microphone (playing now)"); l.frame = NSRect(x: 20, y: 420, width: 520, height: 20); v.addSubview(l) }
    default:
        let l = NSTextField(wrappingLabelWithString: str("text") ?? ""); l.frame = media; l.font = .systemFont(ofSize: 16); v.addSubview(l)
    }
    c.label.frame = NSRect(x: 20, y: 24, width: 260, height: 22)
    c.label.stringValue = "Sending in \(seconds) s"
    v.addSubview(c.label)
    let cancel = NSButton(title: "Cancel", target: c, action: #selector(PreviewController.cancel)); cancel.frame = NSRect(x: 330, y: 16, width: 100, height: 32); cancel.keyEquivalent = "\u{1b}"
    let send = NSButton(title: "Send now", target: c, action: #selector(PreviewController.send)); send.frame = NSRect(x: 440, y: 16, width: 100, height: 32)
    v.addSubview(cancel); v.addSubview(send)
    w.center()
    let t = Timer(timeInterval: 1, repeats: true) { _ in c.tick() }
    RunLoop.main.add(t, forMode: .modalPanel)
    let r = NSApp.runModal(for: w)
    t.invalidate(); c.player?.pause(); w.orderOut(nil)
    return r == .OK
}

/* ---------- capture ---------- */

func pickCamera(_ which: String) throws -> AVCaptureDevice {
    let s = AVCaptureDevice.DiscoverySession(deviceTypes: [.builtInWideAngleCamera, .external, .continuityCamera], mediaType: .video, position: .unspecified)
    let all = s.devices
    if all.isEmpty { throw HelperError("this Mac has no camera") }
    switch which {
    case "front":
        return all.first(where: { $0.deviceType == .builtInWideAngleCamera }) ?? AVCaptureDevice.default(for: .video) ?? all[0]
    case "back":
        if let d = all.first(where: { $0.deviceType == .continuityCamera || $0.position == .back }) { return d }
        throw HelperError("this Mac has no back camera (an iPhone as Continuity Camera would be one)")
    default:
        if let d = all.first(where: { $0.uniqueID == which || $0.localizedName == which }) { return d }
        throw HelperError("no camera named \(which); this Mac has: \(all.map { $0.localizedName }.joined(separator: ", "))")
    }
}

final class PhotoGrab: NSObject, AVCapturePhotoCaptureDelegate {
    var cont: CheckedContinuation<Data, Error>?
    func photoOutput(_ o: AVCapturePhotoOutput, didFinishProcessingPhoto p: AVCapturePhoto, error: Error?) {
        if let e = error { cont?.resume(throwing: e) } else if let d = p.fileDataRepresentation() { cont?.resume(returning: d) } else { cont?.resume(throwing: HelperError("the camera gave no picture")) }
        cont = nil
    }
}

func jpeg(_ data: Data, maxPx: Int, to url: URL) throws {
    guard let src = CGImageSourceCreateWithData(data as CFData, nil) else { throw HelperError("couldn't read the photo") }
    let opts: [CFString: Any] = [kCGImageSourceCreateThumbnailFromImageAlways: true, kCGImageSourceThumbnailMaxPixelSize: maxPx, kCGImageSourceCreateThumbnailWithTransform: true]
    guard let img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts as CFDictionary),
          let dst = CGImageDestinationCreateWithURL(url as CFURL, "public.jpeg" as CFString, 1, nil) else { throw HelperError("couldn't scale the photo") }
    // A fresh image: no EXIF, no location, nothing but pixels.
    CGImageDestinationAddImage(dst, img, [kCGImageDestinationLossyCompressionQuality: 0.85] as CFDictionary)
    if !CGImageDestinationFinalize(dst) { throw HelperError("couldn't write the photo") }
}

func snapshot() async throws -> [String: Any] {
    try await needAccess(.video, "Camera", "Camera")
    let dev = try pickCamera(str("camera") ?? "front")
    let session = AVCaptureSession()
    session.sessionPreset = .photo
    let input = try AVCaptureDeviceInput(device: dev)
    let output = AVCapturePhotoOutput()
    guard session.canAddInput(input), session.canAddOutput(output) else { throw HelperError("the camera can't take photos right now") }
    session.addInput(input); session.addOutput(output)
    session.startRunning()
    defer { session.stopRunning() }
    try await Task.sleep(nanoseconds: 1_200_000_000) // exposure and white balance settle
    let grab = PhotoGrab()
    let data: Data = try await withCheckedThrowingContinuation { cont in
        grab.cont = cont
        output.capturePhoto(with: AVCapturePhotoSettings(format: [AVVideoCodecKey: AVVideoCodecType.jpeg]), delegate: grab)
    }
    try jpeg(data, maxPx: int("max_px", 256, 4096, 2048), to: try outURL())
    return ["camera": dev.localizedName]
}

final class ClipGrab: NSObject, AVCaptureFileOutputRecordingDelegate {
    var cont: CheckedContinuation<Void, Error>?
    func fileOutput(_ o: AVCaptureFileOutput, didFinishRecordingTo u: URL, from c: [AVCaptureConnection], error: Error?) {
        // Stopping at the maximum duration also reports an "error" whose recording is complete.
        if let e = error as NSError?, (e.userInfo[AVErrorRecordingSuccessfullyFinishedKey] as? Bool) != true { cont?.resume(throwing: e) } else { cont?.resume() }
        cont = nil
    }
}

func clip() async throws -> [String: Any] {
    try await needAccess(.video, "Camera", "Camera")
    let dev = try pickCamera(str("camera") ?? "front")
    let seconds = int("seconds", 1, 30, 5)
    let session = AVCaptureSession()
    session.sessionPreset = .high
    let input = try AVCaptureDeviceInput(device: dev)
    let output = AVCaptureMovieFileOutput()
    guard session.canAddInput(input), session.canAddOutput(output) else { throw HelperError("the camera can't record right now") }
    session.addInput(input); session.addOutput(output)
    output.maxRecordedDuration = CMTime(seconds: Double(seconds), preferredTimescale: 600)
    session.startRunning()
    defer { session.stopRunning() }
    try await Task.sleep(nanoseconds: 800_000_000)
    let out = try outURL()
    let mov = out.deletingPathExtension().appendingPathExtension("mov")
    try? FileManager.default.removeItem(at: mov)
    let grab = ClipGrab()
    try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
        grab.cont = cont
        output.startRecording(to: mov, recordingDelegate: grab)
    }
    defer { try? FileManager.default.removeItem(at: mov) }
    let asset = AVURLAsset(url: mov)
    guard let ex = AVAssetExportSession(asset: asset, presetName: AVAssetExportPreset1280x720) else { throw HelperError("can't convert the clip") }
    ex.outputURL = out; ex.outputFileType = .mp4; ex.shouldOptimizeForNetworkUse = true
    ex.metadataItemFilter = .forSharing() // no location or device details in the file
    await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in ex.exportAsynchronously { c.resume() } }
    if ex.status != .completed { throw HelperError("converting the clip failed: \(ex.error?.localizedDescription ?? "?")") }
    return ["camera": dev.localizedName, "seconds": seconds]
}

func recordAudio() async throws -> [String: Any] {
    try await needAccess(.audio, "Microphone", "Microphone")
    let seconds = int("seconds", 1, 60, 5)
    let settings: [String: Any] = [AVFormatIDKey: kAudioFormatMPEG4AAC, AVSampleRateKey: 44100, AVNumberOfChannelsKey: 1, AVEncoderBitRateKey: 96000]
    let rec = try AVAudioRecorder(url: try outURL(), settings: settings)
    guard rec.record(forDuration: TimeInterval(seconds)) else { throw HelperError("the microphone didn't start") }
    try await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000 + 400_000_000)
    rec.stop()
    return ["seconds": seconds]
}

func screenshot() async throws -> [String: Any] {
    if !CGPreflightScreenCaptureAccess() {
        _ = CGRequestScreenCaptureAccess()
        throw HelperError("Screen Recording isn't allowed for Pavilion Node yet: System Settings › Privacy & Security › Screen & System Audio Recording")
    }
    let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
    let mainID = CGMainDisplayID()
    guard let display = content.displays.first(where: { $0.displayID == mainID }) ?? content.displays.first else { throw HelperError("no display") }
    let filter = SCContentFilter(display: display, excludingWindows: [])
    let cfg = SCStreamConfiguration()
    let scale = Int(filter.pointPixelScale)
    cfg.width = display.width * max(scale, 1); cfg.height = display.height * max(scale, 1); cfg.showsCursor = false
    let img = try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: cfg)
    guard let dst = CGImageDestinationCreateWithURL(try outURL() as CFURL, "public.png" as CFString, 1, nil) else { throw HelperError("can't write the screenshot") }
    CGImageDestinationAddImage(dst, img, nil)
    if !CGImageDestinationFinalize(dst) { throw HelperError("can't write the screenshot") }
    return ["width": img.width, "height": img.height]
}

final class Locator: NSObject, CLLocationManagerDelegate {
    let m = CLLocationManager()
    var authCont: CheckedContinuation<Void, Never>?
    var locCont: CheckedContinuation<CLLocation, Error>?
    override init() { super.init(); m.delegate = self }
    func locationManagerDidChangeAuthorization(_ m: CLLocationManager) { if m.authorizationStatus != .notDetermined { authCont?.resume(); authCont = nil } }
    func locationManager(_ m: CLLocationManager, didUpdateLocations l: [CLLocation]) { if let x = l.last { locCont?.resume(returning: x); locCont = nil } }
    func locationManager(_ m: CLLocationManager, didFailWithError e: Error) { locCont?.resume(throwing: e); locCont = nil }
}

@MainActor func location() async throws -> [String: Any] {
    let l = Locator()
    if l.m.authorizationStatus == .notDetermined {
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in l.authCont = c; l.m.requestWhenInUseAuthorization() }
    }
    switch l.m.authorizationStatus {
    case .authorizedAlways, .authorized: break
    default: throw HelperError("Location isn't allowed for Pavilion Node: System Settings › Privacy & Security › Location Services")
    }
    l.m.desiredAccuracy = Double(int("accuracy_m", 10, 100000, 1000)) >= 1000 ? kCLLocationAccuracyKilometer : kCLLocationAccuracyHundredMeters
    let loc = try await withCheckedThrowingContinuation { (c: CheckedContinuation<CLLocation, Error>) in l.locCont = c; l.m.requestLocation() }
    return ["lat": loc.coordinate.latitude, "lon": loc.coordinate.longitude, "accuracy_m": loc.horizontalAccuracy]
}

final class Speaker: NSObject, AVSpeechSynthesizerDelegate, AVAudioPlayerDelegate {
    var cont: CheckedContinuation<Void, Never>?
    func speechSynthesizer(_ s: AVSpeechSynthesizer, didFinish u: AVSpeechUtterance) { cont?.resume(); cont = nil }
    func audioPlayerDidFinishPlaying(_ p: AVAudioPlayer, successfully f: Bool) { cont?.resume(); cont = nil }
}

@MainActor func play() async throws -> [String: Any] {
    let sp = Speaker()
    if let t = str("text") {
        let synth = AVSpeechSynthesizer(); synth.delegate = sp
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in sp.cont = c; synth.speak(AVSpeechUtterance(string: String(t.prefix(500)))) }
        return ["done": true]
    }
    guard let p = str("path"), p.contains("/pavilion-node/devices/") else { throw HelperError("nothing to play") }
    let player = try AVAudioPlayer(contentsOf: URL(fileURLWithPath: p)); player.delegate = sp
    if player.duration > 120 { throw HelperError("the sound is longer than 2 minutes") }
    await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in sp.cont = c; if !player.play() { sp.cont?.resume(); sp.cont = nil } }
    return ["done": true]
}

/* ---------- run ---------- */

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
Task {
    do {
        var r: [String: Any]
        switch op {
        case "permissions": r = ["permissions": permissions()]
        case "ask":
            let seconds = int("seconds", 1, 600, 120)
            let d = await MainActor.run { askWindow(seconds: seconds) }
            r = ["decision": d]
            if d == "allow" && req["presence"] as? Bool == true {
                let why = "allow \(str("agent") ?? "an agent"): \(str("text") ?? "a device action")"
                let ok = await presence(String(why.prefix(150)))
                r["presence"] = ok
                if !ok { r["decision"] = "deny" }
            }
        case "preview": r = ["send": try await MainActor.run { try previewWindow() }]
        case "camera_snapshot": r = try await snapshot()
        case "camera_clip": r = try await clip()
        case "record_audio": r = try await recordAudio()
        case "screen_capture": r = try await screenshot()
        case "location": r = try await location()
        case "play_audio": r = try await play()
        default: fail("\(op) isn't something this helper does")
        }
        r["ok"] = true
        emit(r)
    } catch let e as HelperError {
        fail(e.why)
    } catch {
        fail(error.localizedDescription)
    }
}
app.run()
