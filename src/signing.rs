//! The machine's identity and signed requests. Same scheme as members' browsers (gate/src/auth.ts):
//! `pavilion-v1\nhost\nMETHOD\npath+query\ntime\nnonce\nb64url(sha256(body))`, Ed25519, single-use nonces.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn b64(b: &[u8]) -> String { B64.encode(b) }
pub fn unb64(s: &str) -> anyhow::Result<Vec<u8>> { Ok(B64.decode(s.trim_end_matches('='))?) }
pub fn sha256(b: &[u8]) -> [u8; 32] { Sha256::digest(b).into() }
pub fn random_b64(n: usize) -> String { let mut v = vec![0u8; n]; rand::thread_rng().fill_bytes(&mut v); b64(&v) }

/// base64url(SHA-256("Ed25519:" + raw public key)), 22 characters, as the Gate computes it.
pub fn key_id(public: &VerifyingKey) -> String {
    let mut h = Sha256::new();
    h.update(b"Ed25519:");
    h.update(public.as_bytes());
    b64(&h.finalize())[..22].to_string()
}

pub fn canonical(host: &str, method: &str, path_and_query: &str, time: &str, nonce: &str, body: &[u8]) -> String {
    format!("pavilion-v1\n{}\n{}\n{}\n{}\n{}\n{}", host.to_lowercase(), method.to_uppercase(), path_and_query, time, nonce, b64(&sha256(body)))
}

/// The four `X-Pavilion-*` headers for one request.
pub fn signed_headers(key: &SigningKey, host: &str, method: &str, path_and_query: &str, body: &[u8]) -> Vec<(&'static str, String)> {
    let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs().to_string();
    let nonce = random_b64(18);
    let msg = canonical(host, method, path_and_query, &time, &nonce, body);
    let sig = key.sign(msg.as_bytes());
    vec![
        ("x-pavilion-key", key_id(&key.verifying_key())),
        ("x-pavilion-time", time),
        ("x-pavilion-nonce", nonce),
        ("x-pavilion-signature", b64(&sig.to_bytes())),
    ]
}

/// Checks a signature made by a member's browser key (Ed25519, or P-256 where the browser has no Ed25519).
pub fn verify_member(alg: &str, public_key_b64: &str, message: &str, signature_b64: &str) -> bool {
    let (Ok(pk), Ok(sig)) = (unb64(public_key_b64), unb64(signature_b64)) else { return false };
    match alg {
        "Ed25519" => {
            let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(pk.as_slice()), ed25519_dalek::Signature::from_slice(&sig)) else { return false };
            VerifyingKey::from_bytes(&pk).map(|k| k.verify(message.as_bytes(), &sig).is_ok()).unwrap_or(false)
        }
        "P-256" => {
            use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey as PK};
            // WebCrypto signs ECDSA as raw r||s (64 bytes), which is what from_slice reads.
            let (Ok(k), Ok(s)) = (PK::from_sec1_bytes(&pk), Signature::from_slice(&sig)) else { return false };
            k.verify(message.as_bytes(), &s).is_ok()
        }
        _ => false,
    }
}

/// Checks a job envelope signed by the pavilion (gate/src/machine-proto.ts `signEnvelope`).
pub fn verify_pavilion(pavilion_key_b64: &str, payload_b64: &str, sig_b64: &str) -> bool {
    let (Ok(pk), Ok(sig)) = (unb64(pavilion_key_b64), unb64(sig_b64)) else { return false };
    let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(pk.as_slice()), ed25519_dalek::Signature::from_slice(&sig)) else { return false };
    let msg = format!("pavilion-job-v1\n{payload_b64}");
    VerifyingKey::from_bytes(&pk).map(|k| k.verify(msg.as_bytes(), &sig).is_ok()).unwrap_or(false)
}

/// What the node sends first when joining: it can't change its random value after seeing the pavilion's.
pub fn commit_to(node_nonce: &str) -> String { b64(&sha256(format!("pavilion-join-commit-v1\n{node_nonce}").as_bytes())) }

/// The 6 digits both sides show (gate/src/machine-proto.ts `joinCode`).
pub fn join_code(node_nonce: &str, pav_nonce: &str, node_key: &str, pavilion_key: &str, owner: &str) -> String {
    let h = sha256(["pavilion-join-code-v1", node_nonce, pav_nonce, node_key, pavilion_key, owner].join("\n").as_bytes());
    let n = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
    format!("{:06}", n % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_matches_the_gate_format() {
        let c = canonical("Gate.Example", "post", "/p/spike/x?a=1", "1800000000", "nnnn", b"{}");
        assert_eq!(c, "pavilion-v1\ngate.example\nPOST\n/p/spike/x?a=1\n1800000000\nnnnn\nRBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o");
    }
    #[test]
    fn join_code_is_six_digits_and_bound_to_every_input() {
        let a = join_code("n", "p", "k", "pk", "o");
        assert_eq!(a.len(), 6);
        assert_ne!(a, join_code("n", "p", "k2", "pk", "o"));
        assert_ne!(a, join_code("n", "p", "k", "pk", "o2"));
    }
    #[test]
    fn ed25519_signatures_round_trip() {
        let k = SigningKey::generate(&mut rand::thread_rng());
        let sig = k.sign(b"hello");
        assert!(verify_member("Ed25519", &b64(k.verifying_key().as_bytes()), "hello", &b64(&sig.to_bytes())));
        assert!(!verify_member("Ed25519", &b64(k.verifying_key().as_bytes()), "hellO", &b64(&sig.to_bytes())));
    }
}
