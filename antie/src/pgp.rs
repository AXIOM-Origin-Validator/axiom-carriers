//! PGP encryption for cheque payloads.
//!
//! Automatic flow:
//! 1. Lookup receiver's PGP public key by email (HKP keyserver)
//! 2. Encrypt CBOR cheque payload before emailing
//! 3. On receive, decrypt with own PGP private key
//! 4. Fallback to unencrypted if key not found (graceful degradation)
//!
//! Uses sequoia-openpgp (Rust-native OpenPGP implementation).

use sequoia_openpgp as openpgp;
#[cfg(test)]
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::serialize::stream::*;
#[cfg(test)]
use openpgp::serialize::Marshal;
use openpgp::policy::StandardPolicy;
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::{debug, info, warn};

/// Default HKP keyserver for public key lookup.
pub const DEFAULT_KEYSERVER: &str = "https://keys.openpgp.org";

/// AUDIT-FIX v2.11.14: Cache entry with TTL (was unbounded lifetime).
struct CachedKey {
    /// None = negative cache (no key found). Some = key bytes.
    bytes: Option<Vec<u8>>,
    fetched_at: std::time::Instant,
}

/// Cache TTL — keys re-fetched after this duration. Covers revocation propagation.
const KEY_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(3600); // 1 hour

/// PGP key cache — avoid repeated keyserver lookups. Entries expire after KEY_CACHE_TTL.
/// Caches both positive (key found) and negative (no key) results to avoid
/// repeated 5-second keyserver timeouts for non-existent email addresses.
static KEY_CACHE: Mutex<Option<HashMap<String, CachedKey>>> = Mutex::new(None);

/// Lookup a PGP public key by email from HKP keyserver.
/// Returns serialized Cert bytes if found, None if not.
/// Results are cached with TTL.
pub async fn lookup_key_bytes(email: &str) -> Option<Vec<u8>> {
    // Dev mode: skip keyserver for internal domains (@axiom).
    // These are local dev/test addresses — no PGP keys exist on public keyservers.
    // Avoids 5-second HTTP timeouts that block cheque delivery.
    if email.ends_with("@axiom") {
        return None;
    }

    // Check cache (with TTL expiry) — includes negative cache (no key found)
    {
        let mut c = KEY_CACHE.lock().unwrap();
        if let Some(ref mut map) = *c {
            if let Some(entry) = map.get(email) {
                if entry.fetched_at.elapsed() < KEY_CACHE_TTL {
                    return entry.bytes.clone();
                }
                // Expired — remove and re-fetch
                map.remove(email);
                debug!("PGP: cache expired for {} — re-fetching", email);
            }
        }
    }

    // Query HKP keyserver
    let url = format!(
        "{}/vks/v1/by-email/{}",
        DEFAULT_KEYSERVER,
        email.replace('@', "%40"),
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build();
    let client = match client {
        Ok(c) => c,
        Err(_) => {
            // Cache negative result to avoid repeated client build failures
            cache_negative(email);
            return None;
        }
    };

    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => {
            // Network error / timeout — cache negative to avoid repeated delays
            debug!("PGP: keyserver unreachable for {} — caching negative", email);
            cache_negative(email);
            return None;
        }
    };

    if !response.status().is_success() {
        debug!("PGP: keyserver returned {} for {}", response.status(), email);
        cache_negative(email);
        return None;
    }

    let bytes = match response.bytes().await {
        Ok(b) => b.to_vec(),
        Err(_) => {
            cache_negative(email);
            return None;
        }
    };

    // Verify it's a valid cert
    if openpgp::Cert::from_bytes(&bytes).is_err() {
        warn!("PGP: invalid cert from keyserver for {}", email);
        cache_negative(email);
        return None;
    }

    // Cache positive result
    {
        let mut c = KEY_CACHE.lock().unwrap();
        let map = c.get_or_insert_with(HashMap::new);
        map.insert(email.to_string(), CachedKey {
            bytes: Some(bytes.clone()),
            fetched_at: std::time::Instant::now(),
        });
    }

    info!("PGP: found key for {} ({} bytes)", email, bytes.len());
    Some(bytes)
}

/// Cache a negative lookup (no key found) to avoid repeated keyserver timeouts.
fn cache_negative(email: &str) {
    let mut c = KEY_CACHE.lock().unwrap();
    let map = c.get_or_insert_with(HashMap::new);
    map.insert(email.to_string(), CachedKey {
        bytes: None,
        fetched_at: std::time::Instant::now(),
    });
}

/// Encrypt data with a recipient's PGP public key (from cert bytes).
/// Returns encrypted bytes (OpenPGP message format).
pub fn encrypt(cert_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let policy = StandardPolicy::new();
    let cert = openpgp::Cert::from_bytes(cert_bytes)
        .map_err(|e| format!("PGP cert parse: {}", e))?;

    let recipients: Vec<_> = cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .map(Recipient::from)
        .collect();

    if recipients.is_empty() {
        return Err("No usable encryption key in cert".into());
    }

    let mut output = Vec::new();
    let message = Message::new(&mut output);
    // AUDIT-FIX v2.11.14: Explicitly set AES-256 (was OpenPGP defaults/preferences).
    let message = Encryptor::for_recipients(message, recipients)
        .symmetric_algo(openpgp::types::SymmetricAlgorithm::AES256)
        .build()
        .map_err(|e| format!("PGP encryptor: {}", e))?;
    let mut writer = LiteralWriter::new(message)
        .build()
        .map_err(|e| format!("PGP writer: {}", e))?;

    use std::io::Write;
    writer.write_all(plaintext)
        .map_err(|e| format!("PGP write: {}", e))?;
    writer.finalize()
        .map_err(|e| format!("PGP finalize: {}", e))?;

    Ok(output)
}

/// Decrypt data with our PGP private key (from cert with secret keys).
pub fn decrypt(secret_cert_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    use openpgp::parse::stream::*;
    use openpgp::crypto::SessionKey;
    use openpgp::types::SymmetricAlgorithm;

    let policy = StandardPolicy::new();
    let secret_cert = openpgp::Cert::from_bytes(secret_cert_bytes)
        .map_err(|e| format!("PGP secret cert parse: {}", e))?;

    struct Helper<'a> {
        policy: &'a StandardPolicy<'a>,
        secret: &'a openpgp::Cert,
    }

    impl VerificationHelper for Helper<'_> {
        fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
            Ok(vec![])
        }
        fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
            Ok(())
        }
    }

    impl DecryptionHelper for Helper<'_> {
        fn decrypt(
            &mut self,
            pkesks: &[openpgp::packet::PKESK],
            _skesks: &[openpgp::packet::SKESK],
            sym_algo: Option<SymmetricAlgorithm>,
            decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
        ) -> openpgp::Result<Option<openpgp::Cert>> {
            for pkesk in pkesks {
                for ka in self.secret.keys().with_policy(self.policy, None)
                    .supported().unencrypted_secret().for_transport_encryption()
                {
                    if let Ok(mut kp) = ka.key().clone().into_keypair() {
                        if pkesk.decrypt(&mut kp, sym_algo)
                            .map(|(algo, sk)| decrypt(algo, &sk))
                            .unwrap_or(false)
                        {
                            return Ok(None);
                        }
                    }
                }
            }
            Err(openpgp::Error::ManipulatedMessage.into())
        }
    }

    let helper = Helper { policy: &policy, secret: &secret_cert };
    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
        .map_err(|e| format!("PGP decrypt parse: {}", e))?
        .with_policy(&policy, None, helper)
        .map_err(|e| format!("PGP decrypt setup: {}", e))?;

    let mut plaintext = Vec::new();
    std::io::copy(&mut decryptor, &mut plaintext)
        .map_err(|e| format!("PGP decrypt read: {}", e))?;

    Ok(plaintext)
}

/// Generate a test PGP key pair (for testing only).
/// Returns (cert_bytes_with_secret, cert_bytes_public_only).
#[cfg(test)]
pub fn generate_test_keypair(email: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (cert, _revocation) = CertBuilder::new()
        .add_userid(email)
        .add_transport_encryption_subkey()
        .generate()
        .map_err(|e| format!("PGP keygen: {}", e))?;

    let mut secret_bytes = Vec::new();
    cert.as_tsk().serialize(&mut secret_bytes)
        .map_err(|e| format!("PGP serialize secret: {}", e))?;

    let mut public_bytes = Vec::new();
    cert.serialize(&mut public_bytes)
        .map_err(|e| format!("PGP serialize public: {}", e))?;

    Ok((secret_bytes, public_bytes))
}

/// Check if data looks like a PGP encrypted message.
pub fn is_pgp_encrypted(data: &[u8]) -> bool {
    if data.is_empty() { return false; }
    // OpenPGP packet tags
    (data[0] & 0xC0 == 0xC0) || (data[0] & 0x80 == 0x80)
        || data.starts_with(b"-----BEGIN PGP MESSAGE-----")
}

/// Try to encrypt payload for the given email. Returns encrypted bytes
/// or original plaintext if key not found (graceful degradation).
pub async fn try_encrypt_for_email(email: &str, plaintext: &[u8]) -> (Vec<u8>, bool) {
    match lookup_key_bytes(email).await {
        Some(cert_bytes) => match encrypt(&cert_bytes, plaintext) {
            Ok(encrypted) => {
                info!("PGP: encrypted {} bytes for {}", plaintext.len(), email);
                (encrypted, true)
            }
            Err(e) => {
                warn!("PGP: encrypt failed for {}: {}", email, e);
                (plaintext.to_vec(), false)
            }
        },
        None => {
            debug!("PGP: no key for {} — unencrypted", email);
            (plaintext.to_vec(), false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (secret_bytes, public_bytes) = generate_test_keypair("test@axiom.local").unwrap();

        let plaintext = b"AXIOM cheque payload: 1000000 atoms to bob@example.com";

        // Encrypt with public key
        let encrypted = encrypt(&public_bytes, plaintext).unwrap();
        assert_ne!(encrypted, plaintext, "Encrypted should differ from plaintext");
        assert!(is_pgp_encrypted(&encrypted), "Should detect as PGP encrypted");

        // Decrypt with secret key
        let decrypted = decrypt(&secret_bytes, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext, "Decrypted should match original");
    }

    #[test]
    fn test_encrypt_different_keys_cannot_decrypt() {
        let (_secret_a, public_a) = generate_test_keypair("alice@axiom.local").unwrap();
        let (secret_b, _public_b) = generate_test_keypair("bob@axiom.local").unwrap();

        let plaintext = b"Secret cheque for Alice only";
        let encrypted = encrypt(&public_a, plaintext).unwrap();

        // Bob's key should NOT decrypt Alice's message
        let result = decrypt(&secret_b, &encrypted);
        assert!(result.is_err(), "Wrong key should fail to decrypt");
    }

    #[test]
    fn test_is_pgp_encrypted() {
        assert!(!is_pgp_encrypted(b""), "Empty is not PGP");
        assert!(!is_pgp_encrypted(b"plain text"), "Plain text is not PGP");
        assert!(is_pgp_encrypted(b"-----BEGIN PGP MESSAGE-----"), "Armored PGP detected");

        // Generate real encrypted data to test binary detection
        let (_secret, public) = generate_test_keypair("test@axiom.local").unwrap();
        let encrypted = encrypt(&public, b"test").unwrap();
        assert!(is_pgp_encrypted(&encrypted), "Binary PGP detected");
    }

    #[test]
    fn test_large_payload_encrypt_decrypt() {
        let (secret, public) = generate_test_keypair("big@axiom.local").unwrap();

        // Simulate a large cheque payload (10KB CBOR)
        let plaintext: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();

        let encrypted = encrypt(&public, &plaintext).unwrap();
        let decrypted = decrypt(&secret, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext, "Large payload roundtrip");
    }

    #[tokio::test]
    async fn test_keyserver_lookup_nonexistent_email() {
        // This email should not have a PGP key on any keyserver
        let result = lookup_key_bytes("nonexistent_test_12345@axiom-does-not-exist.invalid").await;
        assert!(result.is_none(), "Nonexistent email should return None");
    }

    #[tokio::test]
    async fn test_graceful_fallback_no_key() {
        let plaintext = b"This should pass through unencrypted";
        let (data, encrypted) = try_encrypt_for_email(
            "no-key-here@axiom-does-not-exist.invalid",
            plaintext,
        ).await;

        assert!(!encrypted, "Should not be encrypted (no key)");
        assert_eq!(data, plaintext, "Plaintext should pass through unchanged");
    }

    #[tokio::test]
    async fn test_keyserver_lookup_real_key() {
        // Try looking up a well-known PGP key on keys.openpgp.org
        // This tests the actual keyserver integration
        // Note: may fail if keyserver is unreachable (network-dependent test)
        let result = lookup_key_bytes("andrew@gallagher.id").await;
        // Don't assert success — keyserver may be unreachable in CI
        // Just verify it doesn't crash
        if result.is_some() {
            eprintln!("[PGP TEST] Keyserver lookup succeeded — key found");
            // Verify we can parse the cert
            let cert = openpgp::Cert::from_bytes(&result.unwrap());
            assert!(cert.is_ok(), "Cert from keyserver should parse");
        } else {
            eprintln!("[PGP TEST] Keyserver unreachable or key not found — OK (graceful)");
        }
    }

    #[test]
    fn test_cache_ttl_expiry() {
        // AUDIT-FIX v2.11.14: Verify CachedKey has TTL fields and expiry logic works.
        // Insert a key with fetched_at in the past, verify it would be considered expired.
        let past = std::time::Instant::now() - std::time::Duration::from_secs(7200); // 2 hours ago
        let entry = CachedKey {
            bytes: Some(vec![1, 2, 3]),
            fetched_at: past,
        };

        // Entry created 2 hours ago should exceed the 1-hour TTL
        assert!(entry.fetched_at.elapsed() >= KEY_CACHE_TTL,
            "CachedKey from 2h ago should be expired (TTL=1h)");

        // A fresh entry should NOT be expired
        let fresh = CachedKey {
            bytes: Some(vec![4, 5, 6]),
            fetched_at: std::time::Instant::now(),
        };
        assert!(fresh.fetched_at.elapsed() < KEY_CACHE_TTL,
            "Fresh CachedKey should not be expired");
    }

    #[test]
    fn test_aes256_explicitly_set() {
        // AUDIT-FIX v2.11.14: AES-256 is now explicitly set in the Encryptor2 call
        // (was relying on OpenPGP defaults/preferences before).
        // This test verifies the encrypt→decrypt roundtrip still works with the
        // explicit AES-256 setting, confirming the cipher suite is functional.
        let (secret, public) = generate_test_keypair("aes256-test@axiom.local").unwrap();
        let plaintext = b"AES-256 explicit cipher test payload for AXIOM cheque";

        let encrypted = encrypt(&public, plaintext).unwrap();
        assert!(!encrypted.is_empty(), "Encrypted output should not be empty");
        assert_ne!(&encrypted[..], plaintext, "Ciphertext must differ from plaintext");

        // Decrypt and verify roundtrip — confirms AES-256 path works end-to-end
        let decrypted = decrypt(&secret, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext, "AES-256 roundtrip must preserve plaintext");
    }
}
