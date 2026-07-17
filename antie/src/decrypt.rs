//! ANTIE-side decryption of forward-direction UMP envelopes.
//!
//! See `docs/AXIOM_DESIGN_PublicMailCarriers.md` §3.3–§3.4.  At startup
//! ANTIE reads the validator's Ed25519 secret (the same file Lambda
//! reads for signing), derives an X25519 secret via the standard NaCl
//! conversion, and holds the result in RAM for the process lifetime.
//! Lambda is **unchanged**: it still signs witness responses with the
//! Ed25519 secret directly; ANTIE's X25519 derivative is a separate
//! in-memory artifact used only for inbound decryption.
//!
//! This module is the transport boundary, NOT protocol crypto — the
//! validator's identity, signing authority, and consensus correctness
//! are unaffected by anything that happens here.

use crate::error::AntieError;
use axiom_core_logic::envelope::UmpEnvelope;
use axiom_core_logic::transport_crypto::{
    ed25519_pk_to_x25519_pk, ed25519_sk_to_x25519_sk, open_for_validator,
};
use std::path::Path;

/// Holds the validator's Ed25519 pubkey + the derived X25519 secret.
///
/// Construction reads `<pdir>/config/ed25519.key` (32 raw bytes) — the
/// exact same file Lambda's `validator.private_key_path` already points
/// at.  The Ed25519 secret seed is hashed (SHA-512), clamped, and the
/// resulting X25519 secret is stored.  The Ed25519 seed is dropped from
/// memory immediately after derivation (hygiene; not load-bearing —
/// Lambda still has the file, and on disk permissions own access).
#[derive(Debug)]
pub struct EnvelopeDecryptor {
    /// Validator's Ed25519 pubkey (32 raw bytes).  Used both as the
    /// `recipient_id` we expect on incoming envelopes and to recompute
    /// the deterministic nonce on the decrypt side.
    pub ed25519_pk: [u8; 32],
    /// Derived X25519 secret.  Stored as raw bytes; the seal/unseal
    /// helpers in `axiom_core_logic::transport_crypto` reconstruct the
    /// dalek `StaticSecret` per call (cheap).
    x25519_sk: [u8; 32],
}

impl EnvelopeDecryptor {
    /// Load the Ed25519 seed from `ed25519_key_path`, derive the
    /// X25519 secret, return the decryptor.
    ///
    /// The file format matches Lambda's: 32 raw bytes (mode 0600).
    pub fn from_key_file(ed25519_key_path: &Path) -> Result<Self, AntieError> {
        let seed = std::fs::read(ed25519_key_path).map_err(|e| {
            AntieError::ConfigError(format!(
                "validator.private_key_path read failed at {:?}: {}",
                ed25519_key_path, e,
            ))
        })?;
        if seed.len() != 32 {
            return Err(AntieError::ConfigError(format!(
                "validator.private_key_path: expected 32-byte Ed25519 seed at {:?}, got {} bytes",
                ed25519_key_path,
                seed.len(),
            )));
        }
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);

        // Derive the Ed25519 verifying key from the seed so the
        // decryptor knows its own recipient_id without a separate
        // pubkey-file lookup.
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed_arr);
        let ed25519_pk = signing.verifying_key().to_bytes();

        let x25519_sk = ed25519_sk_to_x25519_sk(&seed_arr);

        // Best-effort: zero the Ed25519 seed before the function
        // returns.  The seed is still on disk and Lambda still uses
        // it — this just avoids keeping an extra copy in the ANTIE
        // stack frame.  Volatile write through `core::ptr` because
        // the compiler is otherwise allowed to elide a plain
        // assignment to a soon-to-go-out-of-scope local.
        for i in 0..seed_arr.len() {
            unsafe { core::ptr::write_volatile(seed_arr.as_mut_ptr().add(i), 0) };
        }

        Ok(Self { ed25519_pk, x25519_sk })
    }

    /// X25519 public key matching the held secret.  Used by ops scripts
    /// or one-off CLI diagnostics; the protocol itself never reads it.
    pub fn x25519_public_key(&self) -> [u8; 32] {
        ed25519_pk_to_x25519_pk(&self.ed25519_pk)
            .expect("our own Ed25519 pubkey must convert to X25519")
    }

    /// Try to unseal an envelope addressed to this validator.  Returns
    /// the inner UMP-CBOR bytes on success; an opaque error on failure.
    /// Callers should drop the message silently on failure and bump
    /// the `decrypt_fail` metric — leaking the failure reason to an
    /// internet sender is a small information leak (§3.3).
    ///
    /// The `Result<_, ()>` is deliberate: any typed error here would
    /// have to either be discarded by callers (defeating the type) or
    /// risk surfacing to the wire. The unit error encodes "you get
    /// nothing useful, by design." clippy::result_unit_err allowed.
    #[allow(clippy::result_unit_err)]
    pub fn open(&self, env: &UmpEnvelope) -> Result<Vec<u8>, ()> {
        open_for_validator(env, &self.ed25519_pk, &self.x25519_sk).map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_core_logic::transport_crypto::seal_to_validator;
    use ed25519_dalek::SigningKey;

    fn write_seed_to_temp(seed: &[u8; 32]) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(seed).expect("write seed");
        f
    }

    #[test]
    fn rejects_wrong_size_keyfile() {
        let f = write_seed_to_temp(&[0x42; 32]);
        // Truncate to 16 bytes by writing again with a smaller buffer.
        use std::io::Write;
        let mut shorter = tempfile::NamedTempFile::new().unwrap();
        shorter.write_all(&[0u8; 16]).unwrap();
        let err = EnvelopeDecryptor::from_key_file(shorter.path()).unwrap_err();
        assert!(format!("{:?}", err).contains("expected 32-byte Ed25519 seed"));
        // Sanity: the 32-byte file does load.
        EnvelopeDecryptor::from_key_file(f.path()).unwrap();
    }

    #[test]
    fn rejects_missing_keyfile() {
        let err = EnvelopeDecryptor::from_key_file(Path::new("/nonexistent/ed25519.key")).unwrap_err();
        assert!(format!("{:?}", err).contains("private_key_path read failed"));
    }

    #[test]
    fn loads_and_decrypts_envelope_sealed_to_us() {
        // Build a 32-byte seed and write to disk; then seal a message
        // to its public counterpart and unseal via the decryptor.
        let seed = [0x77u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let pk = signing.verifying_key().to_bytes();

        let f = write_seed_to_temp(&seed);
        let decryptor = EnvelopeDecryptor::from_key_file(f.path()).unwrap();
        assert_eq!(decryptor.ed25519_pk, pk);

        let plaintext = b"witness request body".to_vec();
        let env = seal_to_validator(&pk, &plaintext).unwrap();
        let opened = decryptor.open(&env).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn rejects_envelope_addressed_to_other_validator() {
        let our_seed = [0x77u8; 32];
        let f = write_seed_to_temp(&our_seed);
        let decryptor = EnvelopeDecryptor::from_key_file(f.path()).unwrap();

        // Seal to a different validator entirely.
        let other_seed = [0x12u8; 32];
        let other_pk = SigningKey::from_bytes(&other_seed).verifying_key().to_bytes();
        let env = seal_to_validator(&other_pk, b"not for us").unwrap();
        assert!(decryptor.open(&env).is_err());
    }

    #[test]
    fn rejects_plain_variant() {
        let seed = [0x77u8; 32];
        let f = write_seed_to_temp(&seed);
        let decryptor = EnvelopeDecryptor::from_key_file(f.path()).unwrap();
        let env = UmpEnvelope::Plain { ump_bytes: vec![1, 2, 3] };
        // Plain envelopes don't go through the decryptor — open() returns Err.
        assert!(decryptor.open(&env).is_err());
    }
}
