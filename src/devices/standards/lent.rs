//! Secrets lent to this host for one device (DEVICES.md §4b "Secrets for local devices", MACHINES.md §6 tier 2): a
//! Home Assistant token, a camera's login, a broker's password. The adoption names the vault secret; for each action
//! that needs it the node makes a fresh X25519 key, asks the Gate for the value sealed to it
//! (`POST …/actions/<act>/secret {pub}` → `{name, sealed}`, DEVICES-PROTOCOL.md §4b), opens it, and keeps it in memory
//! for that one action only (zeroed when dropped). It is never written to disk, logged, or given to an agent.
//!
//! Sealing is HPKE (RFC 9180) base mode, the suite the phones already use for push details: DHKEM(X25519, HKDF-SHA256),
//! HKDF-SHA256, AES-256-GCM; `info` = `"pavilion-device-secret-v1\n" + act`, empty aad; `sealed` = `enc (32 B) ‖ ct`.
use crate::signing::{b64, unb64};
use curve25519_dalek::montgomery::MontgomeryPoint;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// A lent secret's value, in memory for one action.
pub struct Secret { pub name: String, value: Zeroizing<String> }

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "Secret({}, ****)", self.name) }
}

impl Secret {
    pub fn new(name: &str, value: &str) -> Secret { Secret { name: name.to_string(), value: Zeroizing::new(value.to_string()) } }
    /// The whole value, trimmed: a token (Home Assistant's long-lived access token).
    pub fn token(&self) -> &str { self.value.trim() }
    /// A login: `{"username": …, "password": …}`, or `user:password` (split at the first colon).
    pub fn login(&self) -> Result<(String, Zeroizing<String>), String> {
        let v = self.value.trim();
        if v.starts_with('{') {
            let j: serde_json::Value = serde_json::from_str(v).map_err(|_| format!("the lent secret {} isn't a login", self.name))?;
            let u = j["username"].as_str().or(j["user"].as_str()).ok_or_else(|| format!("the lent secret {} has no username", self.name))?;
            let p = j["password"].as_str().unwrap_or("");
            return Ok((u.to_string(), Zeroizing::new(p.to_string())));
        }
        let (u, p) = v.split_once(':').ok_or_else(|| format!("the lent secret {} should be user:password", self.name))?;
        Ok((u.to_string(), Zeroizing::new(p.to_string())))
    }
}

/// A receiving key made for one request. The private half never leaves this process and is zeroed when dropped.
pub struct Receiver { sk: Zeroizing<[u8; 32]>, pub public: [u8; 32] }

impl Receiver {
    pub fn new() -> Receiver {
        let mut sk = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(sk.as_mut());
        let public = MontgomeryPoint::mul_base_clamped(*sk).to_bytes();
        Receiver { sk, public }
    }
    #[cfg(test)]
    pub fn from_secret(sk: [u8; 32]) -> Receiver { let public = MontgomeryPoint::mul_base_clamped(sk).to_bytes(); Receiver { sk: Zeroizing::new(sk), public } }
    /// The request body: `{"pub": "<b64u 32 bytes>"}`.
    pub fn request(&self) -> Vec<u8> { serde_json::to_vec(&serde_json::json!({ "pub": b64(&self.public) })).unwrap() }
    /// Opens the Gate's answer `{name, sealed}` for this action.
    pub fn open_answer(&self, act: &str, body: &[u8]) -> Result<Secret, String> {
        let v: serde_json::Value = serde_json::from_slice(body).map_err(|_| "the Gate's secret answer isn't JSON".to_string())?;
        let name = v["name"].as_str().unwrap_or("secret").to_string();
        let sealed = unb64(v["sealed"].as_str().ok_or("the Gate's secret answer has nothing sealed")?).map_err(|_| "the sealed secret isn't base64url".to_string())?;
        let mut plain = self.open(&info(act), &sealed)?;
        let s = String::from_utf8(plain.clone()).map_err(|_| "the lent secret isn't text".to_string());
        plain.zeroize();
        let mut s = s?;
        let out = Secret::new(&name, &s);
        s.zeroize();
        Ok(out)
    }
    /// HPKE base-mode open (single shot, sequence 0).
    pub fn open(&self, info: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
        if sealed.len() < 32 + 16 { return Err("the sealed secret is too short".into()); }
        let (enc, ct) = sealed.split_at(32);
        let enc: [u8; 32] = enc.try_into().unwrap();
        let dh = Zeroizing::new(MontgomeryPoint(enc).mul_clamped(*self.sk).to_bytes());
        if dh.iter().all(|b| *b == 0) { return Err("the sealed secret's key is invalid".into()); }
        let shared = kem_shared(dh.as_slice(), &enc, &self.public);
        let (key, nonce) = key_schedule(&shared, info);
        aes_gcm_open(&key, &nonce, ct)
    }
}

pub fn info(act: &str) -> Vec<u8> { format!("pavilion-device-secret-v1\n{act}").into_bytes() }

const KEM_ID: u16 = 0x0020; // DHKEM(X25519, HKDF-SHA256)
const KDF_ID: u16 = 0x0001; // HKDF-SHA256
const AEAD_ID: u16 = 0x0002; // AES-256-GCM

fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(salt).unwrap();
    m.update(ikm);
    m.finalize().into_bytes().into()
}
fn expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![];
    let mut t: Vec<u8> = vec![];
    let mut i = 1u8;
    while out.len() < len {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(prk).unwrap();
        m.update(&t);
        m.update(info);
        m.update(&[i]);
        t = m.finalize().into_bytes().to_vec();
        out.extend_from_slice(&t);
        i += 1;
    }
    out.truncate(len);
    out
}
fn labeled_extract(suite: &[u8], salt: &[u8], label: &str, ikm: &[u8]) -> [u8; 32] {
    extract(salt, &[b"HPKE-v1".as_slice(), suite, label.as_bytes(), ikm].concat())
}
fn labeled_expand(suite: &[u8], prk: &[u8], label: &str, info: &[u8], len: usize) -> Vec<u8> {
    expand(prk, &[&(len as u16).to_be_bytes()[..], b"HPKE-v1", suite, label.as_bytes(), info].concat(), len)
}
fn kem_suite() -> Vec<u8> { [b"KEM".as_slice(), &KEM_ID.to_be_bytes()].concat() }
fn hpke_suite() -> Vec<u8> { [b"HPKE".as_slice(), &KEM_ID.to_be_bytes(), &KDF_ID.to_be_bytes(), &AEAD_ID.to_be_bytes()].concat() }

/// ExtractAndExpand(dh, enc ‖ pkR) → the 32-byte shared secret.
fn kem_shared(dh: &[u8], enc: &[u8; 32], pk_r: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let s = kem_suite();
    let prk = labeled_extract(&s, b"", "eae_prk", dh);
    Zeroizing::new(labeled_expand(&s, &prk, "shared_secret", &[&enc[..], &pk_r[..]].concat(), 32))
}
/// Base mode (no PSK): the AEAD key and base nonce.
fn key_schedule(shared: &[u8], info: &[u8]) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    let s = hpke_suite();
    let psk_id_hash = labeled_extract(&s, b"", "psk_id_hash", b"");
    let info_hash = labeled_extract(&s, b"", "info_hash", info);
    let ctx = [&[0u8][..], &psk_id_hash, &info_hash].concat();
    let secret = labeled_extract(&s, shared, "secret", b"");
    (Zeroizing::new(labeled_expand(&s, &secret, "key", &ctx, 32)), labeled_expand(&s, &secret, "base_nonce", &ctx, 12))
}
fn aes_gcm_open(key: &[u8], nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| "bad key")?);
    let mut buf = ct.to_vec();
    let n = Nonce::try_assume_unique_for_key(nonce).map_err(|_| "bad nonce")?;
    let plain = k.open_in_place(n, Aad::empty(), &mut buf).map_err(|_| "the sealed secret doesn't open with this host's key".to_string())?.to_vec();
    buf.zeroize();
    Ok(plain)
}

/// The Gate's side, for tests: seals `plain` to `pk_r` (what `gate/` does with the vault value).
#[cfg(test)]
pub fn seal(pk_r: &[u8; 32], info: &[u8], plain: &[u8]) -> Vec<u8> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    let mut sk_e = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sk_e);
    let enc = MontgomeryPoint::mul_base_clamped(sk_e).to_bytes();
    let dh = MontgomeryPoint(*pk_r).mul_clamped(sk_e).to_bytes();
    let shared = kem_shared(&dh, &enc, pk_r);
    let (key, nonce) = key_schedule(&shared, info);
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).unwrap());
    let mut buf = plain.to_vec();
    k.seal_in_place_append_tag(Nonce::try_assume_unique_for_key(&nonce).unwrap(), Aad::empty(), &mut buf).unwrap();
    [enc.to_vec(), buf].concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }

    #[test]
    fn hkdf_matches_rfc5869_case_1() {
        let prk = extract(&hex("000102030405060708090a0b0c"), &hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));
        assert_eq!(prk.to_vec(), hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
        assert_eq!(expand(&prk, &hex("f0f1f2f3f4f5f6f7f8f9"), 42), hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    }

    #[test]
    fn x25519_matches_rfc7748() {
        // RFC 7748 §6.1: Alice's private key and public key.
        let a = Receiver::from_secret(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").try_into().unwrap());
        assert_eq!(a.public.to_vec(), hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    }

    #[test]
    fn opens_what_another_hpke_implementation_sealed() {
        // Sealed by pyhpke 0.6.5 (Python, independent of this code) to the key 01 02 … 20, with this suite and info.
        let r = Receiver::from_secret((1..=32).collect::<Vec<u8>>().try_into().unwrap());
        assert_eq!(r.public.to_vec(), hex("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"));
        let sealed = hex("b89d02b18eadfd759bbbedf7702c8cecdfbcaa5b1f55508ba55e74f2540e7970255cdddb7c3f9d8f147ad87349dea9231ec8ca52c9157ccc7d9610b27a9a");
        assert_eq!(r.open(&info("act_0123456789abcdef0123"), &sealed).unwrap(), b"eyJ.test-token");
    }

    #[test]
    fn a_sealed_secret_opens_only_for_its_action_and_key() {
        let r = Receiver::new();
        let sealed = seal(&r.public, &info("act_0123456789abcdef0123"), b"user:pa:ss");
        let body = serde_json::to_vec(&serde_json::json!({ "name": "DOOR_CAMERA", "sealed": b64(&sealed) })).unwrap();
        let s = r.open_answer("act_0123456789abcdef0123", &body).unwrap();
        assert_eq!(s.name, "DOOR_CAMERA");
        let (u, p) = s.login().unwrap();
        assert_eq!((u.as_str(), p.as_str()), ("user", "pa:ss"));
        assert!(!format!("{s:?}").contains("pa:ss"));
        // Another action's info, or another key: it doesn't open.
        assert!(r.open_answer("act_ffffffffffffffffffff", &body).is_err());
        assert!(Receiver::new().open_answer("act_0123456789abcdef0123", &body).is_err());
        // A flipped byte: refused.
        let mut bad = sealed.clone();
        bad[40] ^= 1;
        assert!(r.open(&info("act_0123456789abcdef0123"), &bad).is_err());
        assert_eq!(Secret::new("T", r#"{"username":"admin","password":"x"}"#).login().unwrap().0, "admin");
        assert_eq!(Secret::new("T", " eyJtoken \n").token(), "eyJtoken");
    }
}
