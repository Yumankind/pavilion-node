//! macOS says when it is about to sleep (IOKit's system power notifications), and the node tells the pavilion first:
//! `machine.sleep` on the link, so the Gate marks this machine asleep and its model routes limited at once, instead
//! of waiting 90 s for the link to go quiet (docs/MODEL-ACCOUNTS.md §7.3). Running model calls end with
//! `machine_asleep`. Waking a Mac to serve a model is never done: the machine sleeps when its owner wants.
//!
//! One thread with its own run loop receives the notices. "May I sleep?" is always answered yes at once, and a
//! "will sleep" is acknowledged after at most half a second (the time to put one message on the socket), so the node
//! never holds the Mac awake: macOS would otherwise wait up to 30 s for it. Other systems: nothing here; a machine
//! that sleeps goes quiet and the pavilion marks it offline.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
use serde_json::Value;
use tokio::sync::mpsc;

/// The link's channel while its socket is up (link.rs sets and clears it).
static LINK: std::sync::Mutex<Option<mpsc::UnboundedSender<Value>>> = std::sync::Mutex::new(None);
pub fn link_up(tx: mpsc::UnboundedSender<Value>) { *LINK.lock().unwrap() = Some(tx); }
pub fn link_down() { LINK.lock().unwrap().take(); }

/// What the node does on a power notice: `true` when it is the "will sleep" one, after telling the pavilion.
pub fn on_notice(kind: Notice) -> bool {
    if kind != Notice::WillSleep { return false; }
    let n = crate::relay::cancel_all("machine_asleep", "the machine is going to sleep");
    if let Some(tx) = LINK.lock().unwrap().as_ref() { let _ = tx.send(serde_json::json!({ "t": "machine.sleep" })); }
    eprintln!("sleep: this Mac is going to sleep; told the pavilion{}", if n > 0 { format!(", stopped {n} model call(s)") } else { String::new() });
    true
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Notice { CanSleep, WillSleep, WillNotSleep, PoweredOn, Other }

/// IOKit's message numbers: `iokit_common_msg(n)` is `0xE0000000 | n` (IOMessage.h).
pub fn notice(message: u32) -> Notice {
    match message {
        0xE000_0270 => Notice::CanSleep,
        0xE000_0280 => Notice::WillSleep,
        0xE000_0290 => Notice::WillNotSleep,
        0xE000_0300 => Notice::PoweredOn,
        _ => Notice::Other,
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicU32, Ordering};
    type IoConnect = u32;
    type IoObject = u32;
    type Callback = extern "C" fn(*mut c_void, IoObject, u32, *mut c_void);
    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IORegisterForSystemPower(refcon: *mut c_void, port: *mut *mut c_void, callback: Callback, notifier: *mut IoObject) -> IoConnect;
        fn IONotificationPortGetRunLoopSource(port: *mut c_void) -> *mut c_void;
        fn IOAllowPowerChange(kernel_port: IoConnect, notification_id: isize) -> i32;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRunLoopGetCurrent() -> *mut c_void;
        fn CFRunLoopAddSource(rl: *mut c_void, source: *mut c_void, mode: *const c_void);
        fn CFRunLoopRun();
        static kCFRunLoopDefaultMode: *const c_void;
    }
    static ROOT: AtomicU32 = AtomicU32::new(0);

    extern "C" fn on_power(_refcon: *mut c_void, _service: IoObject, message: u32, arg: *mut c_void) {
        let root = ROOT.load(Ordering::SeqCst);
        match super::notice(message) {
            super::Notice::CanSleep => unsafe { IOAllowPowerChange(root, arg as isize); },
            super::Notice::WillSleep => {
                // Never let a panic cross into IOKit, and always acknowledge: the Mac must not wait on us.
                let _ = std::panic::catch_unwind(|| { super::on_notice(super::Notice::WillSleep); std::thread::sleep(std::time::Duration::from_millis(500)); });
                unsafe { IOAllowPowerChange(root, arg as isize); }
            }
            n => { let _ = std::panic::catch_unwind(|| super::on_notice(n)); }
        }
    }

    pub fn watch() {
        std::thread::Builder::new().name("sleep-watch".into()).spawn(|| unsafe {
            let mut port: *mut c_void = std::ptr::null_mut();
            let mut notifier: IoObject = 0;
            let root = IORegisterForSystemPower(std::ptr::null_mut(), &mut port, on_power, &mut notifier);
            if root == 0 || port.is_null() { eprintln!("sleep: couldn't register for power notices; a sleeping Mac shows as offline after 90 s"); return; }
            ROOT.store(root, Ordering::SeqCst);
            CFRunLoopAddSource(CFRunLoopGetCurrent(), IONotificationPortGetRunLoopSource(port), kCFRunLoopDefaultMode);
            CFRunLoopRun();
        }).ok();
    }
}

/// Starts watching for sleep (macOS); does nothing elsewhere.
pub fn watch() {
    #[cfg(target_os = "macos")]
    mac::watch();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn power_notices_and_the_sleep_message() {
        assert_eq!(notice(0xE000_0270), Notice::CanSleep);
        assert_eq!(notice(0xE000_0280), Notice::WillSleep);
        assert_eq!(notice(0xE000_0300), Notice::PoweredOn);
        assert_eq!(notice(0xE000_0123), Notice::Other);
        let (tx, mut rx) = mpsc::unbounded_channel();
        link_up(tx);
        assert!(!on_notice(Notice::CanSleep) && rx.try_recv().is_err(), "asking is not sleeping");
        assert!(on_notice(Notice::WillSleep));
        assert_eq!(rx.try_recv().unwrap(), serde_json::json!({ "t": "machine.sleep" }));
        link_down();
        assert!(on_notice(Notice::WillSleep) && rx.try_recv().is_err(), "no link, nothing sent");
    }
}
