//! Email Parsing and Building
//!
//! Handles parsing incoming emails and building outgoing responses.
//!
//! AXIOM email format:
//! - Subject: AXIOM/<message_type>/<request_id>
//! - Body: Base64-encoded JSON payload
//! - Content-Type: application/x-axiom

use crate::error::AntieError;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use mail_parser::MessageParser;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Parsed AXIOM email
/// Custody header names ANTIE recognises (YPX-023 §3.3).
///
/// Recognising a name here only means "record it so the reply can be routed";
/// whether a row EXISTS for it is the config's business, and an unconfigured
/// name simply takes the ordinary mail path. Adding a path is a config row —
/// this list exists so a typo'd header is not silently treated as custody.
///
/// ⚠ `X-UNCLE-Correlate` is deliberately NOT here: it has its own field and
/// its own tee semantics (a COPY, mail still sent). Folding it in is YPX-023
/// §3.4 — decided, deferred, and it changes no wire bytes.
pub const CUSTODY_HEADERS: &[&str] = &["X-TOT-Session"];

#[derive(Debug, Clone)]
pub struct AntieEmail {
    /// Sender address
    pub from: String,
    
    /// Recipient address
    pub to: String,
    
    /// Message type (from subject)
    pub message_type: String,
    
    /// Request ID (from subject)
    pub request_id: String,
    
    /// Original Message-ID header
    pub message_id: Option<String>,
    
    /// Decoded payload
    pub payload: AntiePayload,
    
    /// Raw email content (for reference)
    pub raw: Vec<u8>,

    /// Optional UNCLE correlation id, extracted from the
    /// `X-UNCLE-Correlate` header if present.
    ///
    /// ⚠ **MIGRATION DECIDED 2026-08-24 (AXIOM Origin), code deferred:** this
    /// header folds into the unified `X-Custody: hop=uncle; class=…; id=…`
    /// stamp (`X-Custody: uncle; id=…`) — YPX-023 §3.4. Same 32-byte id, same
    /// strict 64-hex parse, so the
    /// value carries over unchanged. **Do not migrate ANTIE alone:** UNCLE
    /// stamps this header from `axiom-uncle::handlers::submit_send` in another
    /// repo, and changing only the parser makes the tee go silently quiet.
    /// Both sides land in one commit, together with `X-Custody` itself. UNCLE's SubmitSend
    /// handler stamps this header before dropping the UMP into the
    /// validator maildir; ANTIE preserves it as opaque 32 bytes and
    /// forwards it to `uncle_sink::tee` so the response file lands at
    /// `<witness_outbox>/<correlate_hex>.cbor` for UNCLE's
    /// `witness_observer` to pick up.
    ///
    /// `None` on any non-UNCLE-mediated email — the normal SMTP/maildir
    /// dispatch path is unchanged for those.
    pub uncle_correlate: Option<[u8; 32]>,

    /// Custody header this message arrived with, as `(header_name, id)` —
    /// YPX-023 §3.3. Set when the inbound envelope carried one of the custody
    /// headers ANTIE is configured to route on (e.g. `X-TOT-Session`), stamped
    /// by the carrier that owns the client's connection.
    ///
    /// `None` on every ordinary path, which is what keeps this additive: no
    /// header ⇒ ANTIE behaves exactly as before.
    ///
    /// The name is kept VERBATIM (not normalised to an enum) because the
    /// routing table matches on it and the vocabulary is deliberately open —
    /// a new path is a config row, not a code change.
    pub custody: Option<(String, String)>,
}

/// AXIOM message payload
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AntiePayload {
    /// Raw post-envelope CBOR body, captured by `decode_payload_inner`
    /// BEFORE any field-by-field parse.
    ///
    /// UMP enforcement — `axiom_core_logic::types` owns the canonical
    /// wire types (`RedeemRequestEnvelope`, `WitnessRequest`, …). For
    /// typed-wire requests the gateway should deserialize the typed
    /// struct DIRECTLY from these bytes via
    /// `ciborium::from_reader::<TypedT, _>(payload.raw_ump_body.as_slice())`
    /// — never field-by-field. Each per-field extractor is a place
    /// drift can land. See task #143 / `feedback_no_mirror_structs`.
    ///
    /// Always populated for envelope-required message types; empty
    /// vector for legacy paths that never set it.
    #[serde(skip)]
    pub raw_ump_body: Vec<u8>,

    // === Typed-wire protocol payload fields — DELETED 2026-06-05 ===
    //
    // The fields `transaction`, `overlapped_signatures`, `declared_balance`,
    // `offered_fee`, `prev_receipts`, `query_type`, `cheque_bundle`,
    // `receiver_pk`, `current_state`, `receiver_sig`, `txid_attestation`,
    // `cheque_claim_proof`, `group_member_index`, `sender_fact_chain`
    // used to live here as `Option<serde_json::Value>` (or similar) before
    // the UMP migration finished. Post-UMP the gateway decodes the typed
    // wire envelope (`WitnessRequest`, `RedeemRequestEnvelope`, …) DIRECTLY
    // from `raw_ump_body` via `ciborium::from_reader::<T, _>(…)` and never
    // reads these fields. They were dead weight kept on by the
    // CBOR→JSON→struct conversion in `decode_payload_inner` — exactly the
    // mirror-struct drift pattern catalogued in CLAUDE.md §12.
    //
    // [[feedback_no_json_in_protocol_path]]: removing them eliminated ~30
    // `serde_json::Value` fields from the protocol path.
    //
    // KI#242 (2026-10-02): the LAST `serde_json::Value` fields (`query_params`,
    // `group_members`, `peer_audit_request/_response/_not_held`, `fanout_message`)
    // are gone too. This struct is now decoded STRAIGHT from the CBOR body with
    // `ciborium` (`decode_payload_inner`) — no JSON intermediate — and the
    // peer-audit fields are the Core types themselves, so a field Core adds to
    // them is carried, not dropped.

    /// Query parameters (for the `query` handler). The only reader is
    /// `gateway.rs::handle_query`, which takes `wallet_pk` (bytes) out of the map.
    /// A CBOR value, not a Core type: no Core type owns this shape (the reply side
    /// is KI#179's deliberate privacy projection).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_params: Option<ciborium::Value>,

    // === Genesis dev fields ===

    /// Public key for genesis (init_genesis_dev)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<Vec<u8>>,

    /// Balance for genesis (init_genesis_dev)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<u64>,

    /// Group wallet members for genesis (init_genesis_dev)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_members: Option<Vec<axiom_core_logic::types::GroupMember>>,

    // === ACK fields ===
    
    /// Transaction ID (for ACK requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<Vec<u8>>,
    
    /// Validator public key (for ACK requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_pk: Option<Vec<u8>>,

    // fee_amount on ACK retired in Step 9A2 (YP §20.8 v3.x).

    /// Sender signature (for ACK requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_sig: Option<Vec<u8>>,
    
    /// Client public key (for ACK requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_pk: Option<Vec<u8>>,
    
    // === VBC Signing fields ===
    
    /// SPHINCS+ public key hex (for VBC sign requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sphincs_pk_hex: Option<String>,
    
    /// Dilithium public key hex (for VBC sign requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dilithium_pk_hex: Option<String>,
    
    /// Ed25519 public key hex (for VBC sign requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ed25519_pk_hex: Option<String>,
    
    /// PGP fingerprint hex (for VBC sign requests, optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pgp_fingerprint_hex: Option<String>,
    
    /// Issued timestamp (for VBC sign commit)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
    
    /// Expires timestamp (for VBC sign commit)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    
    /// Chain depth (for VBC sign commit)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_depth: Option<u8>,
    
    /// Issuer set hex (for VBC sign commit)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_set_hex: Vec<String>,

    // === Phase 3C: Onboarding fields (carrier passthrough) ===

    /// Proof capability for VBC sign requests: "dmap" or "zkvm"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_cap: Option<String>,

    /// Human-readable node name for VBC sign requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name_field: Option<String>,

    // === §4.5: auth_hash (NOT stolen-key protection — see KI#108) ===

    /// Ed25519 pubkey derived from the wallet private key — 32 bytes (v2.11.13).
    /// Stored by Lambda into `WalletState.auth_hash`; read by nothing in Core
    /// since `owner_proof` was deleted 2026-09-25 (KI#108).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_hash: Option<Vec<u8>>,

    // === §23.14.6: Peer Audit Protocol ===

    /// Peer audit request (inbound from remote validator).
    /// Contains txid + expected_hash. Lambda looks up DB, Core verifies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_audit_request: Option<axiom_core_logic::types::PeerAuditRequest>,

    /// Peer audit response (inbound from remote validator).
    /// Contains computed_hash from remote Core's verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_audit_response: Option<axiom_core_logic::types::PeerAuditResponse>,

    /// §23.14.6 (KI#213): the audited validator's SIGNED "I hold no record for
    /// that txid" — travels under the `peer_audit_response` message type in
    /// place of `peer_audit_response`, so A's audit handler sees an ANSWER, not
    /// silence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_audit_not_held: Option<axiom_core_logic::types::PeerAuditNotHeld>,

    // `fanout_message` DELETED 2026-10-02 (KI#242): it was never read — an
    // inbound `fanout_relay` is refused at the door by MESSAGE TYPE
    // (`gateway.rs::handle_fanout_relay`, KI#175), not by this field. A body
    // still carrying the key decodes (unknown keys are ignored).
}

/// Parse an email from raw bytes (no decryption — for tests / legacy callers).
/// Cheap, marker-free anti-spam heuristic for pull carriers (POP3/IMAP).
///
/// Shannon byte-entropy of the message BODY (the region after the header/body
/// separator), in bits/byte. A genuine UMP body is base64-encoded cryptographic
/// CBOR (Dilithium sigs, hashes, keys — and, for COUSIN cover traffic,
/// encrypted + random-padded), so it is HIGH, near-uniform entropy (~5.5–6).
/// Ordinary spam — welcome mail, newsletters, marketing — is natural-language
/// text/HTML: LOW, skewed entropy (~4–4.5). The caller deletes bodies BELOW a
/// configured threshold (recommended ~4.5, conservative).
///
/// Deliberately keys ONLY on what spam intrinsically lacks — randomness — never
/// on an added marker/magic (which would let a censor fingerprint AXIOM, the
/// opposite of the cover-traffic goal) and never on the subject (which will be
/// randomized for GFW padding). This is the FLOOR of hygiene, not a spam engine
/// (that is the MTA's job) and NOT a trust boundary (Core validates
/// authenticity). Bias is toward KEEP: a false-keep just parse-drops downstream;
/// a false-delete would lose a transaction — so short bodies return max entropy.
pub fn body_entropy_bits(raw_email: &[u8]) -> f32 {
    let body: &[u8] = raw_email
        .windows(4).position(|w| w == b"\r\n\r\n").map(|i| &raw_email[i + 4..])
        .or_else(|| raw_email.windows(2).position(|w| w == b"\n\n").map(|i| &raw_email[i + 2..]))
        .unwrap_or(raw_email);
    if body.len() < 64 {
        return 8.0; // too little to judge → KEEP
    }
    let mut hist = [0u32; 256];
    for &b in body { hist[b as usize] += 1; }
    let n = body.len() as f32;
    let mut h = 0.0f32;
    for &c in hist.iter() {
        if c > 0 {
            let p = c as f32 / n;
            h -= p * p.log2();
        }
    }
    h
}

#[cfg(test)]
mod entropy_spam_filter_tests {
    use super::body_entropy_bits;

    // A tiny xorshift so the "crypto-like" body is deterministic but flat.
    fn base64ish_random(len: usize) -> Vec<u8> {
        const ALPHABET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut x: u64 = 0x9e3779b97f4a7c15;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            out.push(ALPHABET[(x % 64) as usize]);
        }
        out
    }

    #[test]
    fn text_spam_low_entropy_umd_high_entropy() {
        // Natural-language newsletter/welcome spam.
        let spam = b"From: promo@shop.example\r\nSubject: hi\r\n\r\n\
            Hello and welcome to our newsletter! We are so excited to have you with \
            us today. Click here for amazing deals on shoes, hats and much more. You \
            can unsubscribe at any time. Best regards, the marketing team. Visit our \
            website for the very latest offers and save big this week only!";
        let e_spam = body_entropy_bits(spam);

        // A real UMP shape: base64 of high-entropy crypto bytes.
        let mut umd = b"Subject: whatever\r\n\r\n".to_vec();
        umd.extend_from_slice(&base64ish_random(2000));
        let e_umd = body_entropy_bits(&umd);

        assert!(e_spam < 4.5, "natural text should be low entropy, got {e_spam}");
        assert!(e_umd > 5.0, "base64 crypto body should be high entropy, got {e_umd}");
        assert!(e_umd > e_spam + 1.0,
                "UMP ({e_umd}) must be clearly higher entropy than spam ({e_spam})");

        // The recommended ~4.5 threshold separates them.
        let thr = 4.5f32;
        assert!(e_spam < thr && e_umd >= thr,
                "threshold {thr} must drop spam ({e_spam}) and keep UMP ({e_umd})");
    }

    #[test]
    fn short_body_is_kept() {
        // Too little to judge -> max entropy -> never dropped.
        assert_eq!(body_entropy_bits(b"Subject: x\r\n\r\nhi"), 8.0);
    }
}

pub fn parse_email(raw: &[u8]) -> Result<AntieEmail, AntieError> {
    parse_email_with_context(raw, None)
}

/// Outcome of a successful parse.  `Plain` is the normal path; the
/// caller (the gateway) uses `DecryptFailed` to bump the `decrypt_fail`
/// metric and drop the message silently per
/// `docs/AXIOM_DESIGN_PublicMailCarriers.md` §3.3.
///
/// `AntieEmail` is large (many string + byte fields); boxing keeps
/// the enum compact so the discriminant + Box pointer fit in a
/// register pair regardless of the Ok payload size.
#[derive(Debug)]
pub enum ParseOutcome {
    Ok(Box<AntieEmail>),
    DecryptFailed,
}

/// Message types that ship **raw CBOR** with no `UmpEnvelope` wrapper.
///
/// These are validator-to-validator gossip — signed inside the payload
/// already (peer_audit responder/requester pks; fanout originator_pk),
/// privacy is not a concern (validator state isn't secret from other
/// validators), and the recipient is identified by SMTP envelope.
/// Wrapping them in `UmpEnvelope` is just ceremony with no protocol
/// gain, so the wire format stays raw CBOR by design.
///
/// Any *other* message type (default branch) MUST be wrapped in a
/// `UmpEnvelope` — that's where forward-direction encryption applies
/// (AXIOM_DESIGN_PublicMailCarriers.md §3).  Mismatches are hard
/// errors per CLAUDE.md §13.
const RAW_CBOR_MESSAGE_TYPES: &[&str] = &[
    "peer_audit_request",
    "peer_audit_response",
    "fanout_relay",
];

fn requires_envelope(message_type: &str) -> bool {
    !RAW_CBOR_MESSAGE_TYPES.contains(&message_type)
}

/// Parse an email, optionally supplying an [`crate::decrypt::EnvelopeDecryptor`]
/// so encrypted UMP bodies can be unsealed before dispatch.
///
/// When `decryptor` is `None`, encrypted envelopes are simply passed
/// through to the inner parser, which then errors out — same outcome as
/// pre-encryption builds.  This keeps tests and any non-gateway callers
/// working without forcing a decryptor on them.
pub fn parse_email_with_context(
    raw: &[u8],
    decryptor: Option<&crate::decrypt::EnvelopeDecryptor>,
) -> Result<AntieEmail, AntieError> {
    match parse_email_outcome(raw, decryptor)? {
        ParseOutcome::Ok(email) => Ok(*email),
        ParseOutcome::DecryptFailed => Err(AntieError::EmailParseError(
            "envelope decryption failed".into(),
        )),
    }
}

/// Like [`parse_email_with_context`] but exposes the decrypt-failure
/// outcome so the gateway can bump the `decrypt_fail` metric instead of
/// surfacing it as a generic parse error.
pub fn parse_email_outcome(
    raw: &[u8],
    decryptor: Option<&crate::decrypt::EnvelopeDecryptor>,
) -> Result<ParseOutcome, AntieError> {
    let message = MessageParser::default()
        .parse(raw)
        .ok_or_else(|| AntieError::EmailParseError("Failed to parse email".into()))?;

    // Extract From
    let from = message.from()
        .and_then(|a| a.first())
        .and_then(|a| a.address())
        .map(|s| s.to_string())
        .unwrap_or_default();

    // Extract To
    let to = message.to()
        .and_then(|a| a.first())
        .and_then(|a| a.address())
        .map(|s| s.to_string())
        .unwrap_or_default();

    // Extract Message-ID
    let message_id = message.message_id()
        .map(|s| s.to_string());

    // Extract optional UNCLE correlation id (added by
    // axiom-uncle::handlers::submit_send when carrying a UMP through
    // the SubmitSend wire). `None` for any normal email path.
    let uncle_correlate = message
        .header_raw("X-UNCLE-Correlate")
        .and_then(|raw| {
            let trimmed = raw.trim();
            if trimmed.len() != 64 { return None; }
            let bytes = hex::decode(trimmed).ok()?;
            <[u8; 32]>::try_from(bytes.as_slice()).ok()
        });

    // Custody header (YPX-023 §3.3). ANTIE does not know what the names mean;
    // it records which one arrived so the reply can be routed by the table.
    // The id parse is deliberately the same strict rule as X-UNCLE-Correlate's
    // (exactly 64 hex) — an id names where a signed reply is deposited, so a
    // sloppy parse is a misdelivery.
    let custody = CUSTODY_HEADERS.iter().find_map(|name| {
        let raw = message.header_raw(*name)?;
        let id = raw.trim();
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(((*name).to_string(), id.to_ascii_lowercase()))
    });

    // Parse subject: AXIOM/<type>/<request_id>
    let subject = message.subject().unwrap_or("");
    let (message_type, request_id) = parse_subject(subject)?;

    // Extract body and decode
    let body = extract_body(&message)?;
    let payload = match decode_payload_with_context(&message_type, &body, decryptor) {
        Ok(p) => p,
        Err(DecodeError::DecryptFailed) => return Ok(ParseOutcome::DecryptFailed),
        Err(DecodeError::Other(e)) => return Err(e),
    };

    debug!("Parsed email: type={}, request_id={}, from={}",
           message_type, request_id, from);

    Ok(ParseOutcome::Ok(Box::new(AntieEmail {
        from,
        to,
        message_type,
        request_id,
        message_id,
        payload,
        raw: raw.to_vec(),
        uncle_correlate,
        custody,
    })))
}

/// Parse AXIOM subject line
/// AUDIT-FIX v2.11.14: Preserve full request_id when it contains extra '/' separators.
/// Previous code truncated at parts[2], dropping anything after a third '/'.
fn parse_subject(subject: &str) -> Result<(String, String), AntieError> {
    let parts: Vec<&str> = subject.split('/').collect();

    if parts.len() < 3 || parts[0] != "AXIOM" {
        return Err(AntieError::EmailParseError(
            format!("Invalid subject format: {}. Expected: AXIOM/<type>/<request_id>", subject)
        ));
    }

    Ok((parts[1].to_string(), parts[2..].join("/")))
}

/// Extract body from message
fn extract_body(message: &mail_parser::Message) -> Result<String, AntieError> {
    // Try text body first
    if let Some(body) = message.body_text(0) {
        return Ok(body.to_string());
    }
    
    // Try HTML body and strip tags (fallback)
    if let Some(body) = message.body_html(0) {
        // Simple tag stripping
        let text = body.replace('<', " <")
            .split('<')
            .map(|s| {
                if let Some(pos) = s.find('>') {
                    s[pos + 1..].trim()
                } else {
                    s.trim()
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        return Ok(text);
    }
    
    Err(AntieError::EmailParseError("No body found".into()))
}

/// Decode Base64 payload (CBOR only — YP §16.8.5.6).  Test path
/// without a decryptor; the gateway uses [`parse_email_with_context`]
/// instead so it can supply one.
///
/// Test caller supplies a `message_type` so the strict format check
/// (envelope-required vs raw-CBOR-V↔V) matches the production path.
#[cfg(test)]
fn decode_payload(message_type: &str, body: &str) -> Result<AntiePayload, AntieError> {
    match decode_payload_with_context(message_type, body, None) {
        Ok(p) => Ok(p),
        Err(DecodeError::DecryptFailed) => Err(AntieError::EmailParseError(
            "envelope decryption failed".into(),
        )),
        Err(DecodeError::Other(e)) => Err(e),
    }
}

/// Internal error from [`decode_payload_with_context`].  Splits decrypt
/// failures from generic parse errors so the gateway can bump the right
/// metric.
enum DecodeError {
    DecryptFailed,
    Other(AntieError),
}

impl From<AntieError> for DecodeError {
    fn from(e: AntieError) -> Self { DecodeError::Other(e) }
}

fn decode_payload_with_context(
    message_type: &str,
    body: &str,
    decryptor: Option<&crate::decrypt::EnvelopeDecryptor>,
) -> Result<AntiePayload, DecodeError> {
    // Remove whitespace
    let cleaned: String = body.chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    // Decode Base64
    let decoded = BASE64.decode(&cleaned)
        .map_err(|e| AntieError::EmailParseError(format!("Base64 decode failed: {}", e)))?;

    if decoded.is_empty() {
        return Err(DecodeError::Other(AntieError::EmailParseError(
            "Empty payload".into(),
        )));
    }

    // Format dispatch by message_type — CLAUDE.md §13 demands hard
    // errors on format mismatch.  Wire format is not auto-detected;
    // each message type has a *mandatory* shape:
    //   * client→validator (witness/redeem/query/heal/etc.) →
    //     UmpEnvelope (Plain or Encrypted), forward-direction
    //     encryption per AXIOM_DESIGN_PublicMailCarriers.md §3.
    //   * validator↔validator gossip (peer_audit_*, fanout_relay) →
    //     raw CBOR, no envelope (already signed, no privacy concern).
    let inner_bytes = unwrap_by_format(message_type, decoded, decryptor)?;
    Ok(decode_payload_inner(&inner_bytes)?)
}

/// Format-dispatch for the email body.
///
/// `RAW_CBOR_MESSAGE_TYPES` (peer_audit_*, fanout_relay) must arrive
/// as raw CBOR — an envelope-shaped body for one of those is a wire
/// violation and surfaces as `EmailParseError`.
///
/// All other message types must arrive as a `UmpEnvelope`:
///   - `Plain { ump_bytes }` → inner bytes.
///   - `Encrypted { .. }` → unseal with the decryptor; failure
///     becomes `DecryptFailed` (silent drop + metric bump per §3.3).
///   - Anything else (including raw CBOR or malformed bytes) → hard
///     error.  Stream B fix: no silent fallback.
fn unwrap_by_format(
    message_type: &str,
    decoded: Vec<u8>,
    decryptor: Option<&crate::decrypt::EnvelopeDecryptor>,
) -> Result<Vec<u8>, DecodeError> {
    use axiom_core_logic::envelope::UmpEnvelope;
    let parsed_envelope = UmpEnvelope::from_cbor(&decoded);

    if requires_envelope(message_type) {
        match parsed_envelope {
            Some(UmpEnvelope::Plain { ump_bytes }) => Ok(ump_bytes),
            Some(env @ UmpEnvelope::Encrypted { .. }) => {
                let d = decryptor.ok_or(DecodeError::DecryptFailed)?;
                d.open(&env).map_err(|_| DecodeError::DecryptFailed)
            }
            None => Err(DecodeError::Other(AntieError::EmailParseError(format!(
                "wire format violation: message type {:?} requires UmpEnvelope, \
                 body parses as raw CBOR ({} bytes, hex prefix {})",
                message_type,
                decoded.len(),
                hex::encode(&decoded[..decoded.len().min(32)]),
            )))),
        }
    } else {
        // V↔V: raw CBOR is the protocol-mandated shape.  Reject
        // envelope-shaped bodies so an accidental wrap from a future
        // refactor shows up as a hard error here, not as silent
        // corruption inside the inner parser.
        if parsed_envelope.is_some() {
            return Err(DecodeError::Other(AntieError::EmailParseError(format!(
                "wire format violation: message type {:?} ships raw CBOR but \
                 body parses as UmpEnvelope",
                message_type,
            ))));
        }
        Ok(decoded)
    }
}

/// Nesting limit for the inbound body decode — the number of nested CBOR
/// arrays/maps `ciborium` will enter (the top-level map counts). 33 is the
/// smallest limit that refuses NO body the former hand decoder accepted: that
/// decoder capped ITEM depth at 32 (`MAX_CBOR_DEPTH`), so 33 container levels
/// passed when the innermost was empty. It is one level more permissive when
/// the innermost container is non-empty (old: refused at 32 nested + a scalar;
/// new: accepted) — no limit matches both exactly, because the old cap counted
/// scalars and ciborium counts containers. Pinned (MEASURED, all depths 1..=40)
/// by `ki242_tests::depth_limit_never_refuses_what_the_old_decoder_took`.
const BODY_RECURSION_LIMIT: usize = 33;

/// Inner CBOR→AntiePayload parser (the post-envelope-unwrap path).
///
/// ⚠ KI#242 (RULE 0 §4, 2026-10-02) — the WRONG reading this replaced: the body
/// was decoded twice — once by `ciborium` into a `Value` that was then DISCARDED
/// (`let _ = cbor_val;`), and again by a hand decoder (`cbor.rs::cbor_to_json`)
/// into `serde_json::Value` → `serde_json::from_value::<AntiePayload>`. That was
/// a second codec in the protocol path: integer map keys stringified (`1` ≡
/// `"1"`), negative integers wrapping past i64, f16/f32/tags/indefinite lengths
/// refusing the WHOLE mail, and `Value` fields that silently dropped any field a
/// Core type added. The correct reading: the body IS CBOR of this struct, so it
/// is decoded ONCE, typed, with `ciborium` (the codec every other UMP reader
/// uses). Behaviour change, deliberate: a malformed `peer_audit_*` /
/// `group_members` now fails the whole decode (`EmailParseError`) instead of an
/// `InvalidPayload` inside the handler — refused either way.
fn decode_payload_inner(decoded: &[u8]) -> Result<AntiePayload, AntieError> {
    let mut payload: AntiePayload =
        ciborium::de::from_reader_with_recursion_limit(decoded, BODY_RECURSION_LIMIT)
            .map_err(|e| AntieError::EmailParseError(format!("CBOR decode failed: {}", e)))?;

    // UMP enforcement — `axiom_core_logic::types` owns the canonical
    // typed wires (`WitnessRequest`, `RedeemRequestEnvelope`, …). The
    // gateway deserializes the typed envelope DIRECTLY from
    // `payload.raw_ump_body` (the verbatim post-envelope-unwrap CBOR
    // body, captured here). Adding a per-field `raw_<x>` extractor for
    // a typed-wire field is the drift pattern this layer was rebuilt
    // to delete — see `scripts/check_layer_boundary.sh` Rule 9 and
    // `feedback_no_mirror_structs`.
    payload.raw_ump_body = decoded.to_vec();

    Ok(payload)
}

/// Sanitize a string for use in email headers.
/// Strips CR/LF to prevent header injection (RFC 5321 compliance).
fn sanitize_header(value: &str) -> String {
    value.chars().filter(|c| *c != '\r' && *c != '\n').collect()
}

/// Validate an email address has basic structure (no injection chars).
fn validate_email_addr(addr: &str) -> Result<(), AntieError> {
    if addr.contains('\r') || addr.contains('\n') {
        return Err(AntieError::EmailParseError(
            "Email address contains newline (header injection attempt)".into()
        ));
    }
    if addr.is_empty() || !addr.contains('@') {
        return Err(AntieError::EmailParseError(
            format!("Invalid email address: '{}'", addr)
        ));
    }
    Ok(())
}

/// Build a response email (CBOR-encoded for efficiency)
pub fn build_response(
    to: &str,
    from: &str,
    message_type: &str,
    request_id: &str,
    in_reply_to: Option<&str>,
    payload: &impl Serialize,
) -> Result<Vec<u8>, AntieError> {
    // Validate email addresses to prevent header injection
    validate_email_addr(to)?;
    validate_email_addr(from)?;

    // Encode payload directly to CBOR via ciborium (serde-based).
    // The previous JSON→CBOR path (serde_json::to_value → json_to_cbor)
    // corrupted FactWitness Dilithium signatures: Vec<u8> → JSON array →
    // json_to_cbor heuristic → CBOR Bytes usually works, but edge cases
    // (empty vecs, nested structure confusion) produced CBOR Array instead
    // of Bytes, causing verify_dilithium to fail on deserialization.
    // ⚠ RULE 0 §4 (KI#242, MEASURED 2026-10-02): the claim that stood here —
    // "direct ciborium serialization preserves Vec<u8> as CBOR Bytes always" —
    // is FALSE: serde gives `Vec<u8>` no bytes hint, so ciborium writes a CBOR
    // ARRAY (`ki242_tests::ciborium_writes_vec_u8_as_an_array`). What fixed the
    // FactWitness sigs is that the bytes are now written and read by ONE codec
    // (ciborium; its `deserialize_seq` accepts a byte string or an array), not
    // a heuristic second codec.
    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(payload, &mut cbor_bytes)
        .map_err(|e| AntieError::SerializationError(format!("CBOR encode: {}", e)))?;
    let encoded = BASE64.encode(&cbor_bytes);

    // Generate Message-ID
    let msg_id = format!("<{}.{}@axiom>",
        uuid::Uuid::new_v4(),
        chrono::Utc::now().timestamp()
    );

    // Build email manually (mail-builder has issues with body)
    // All header values sanitized to prevent CRLF injection
    let mut email = String::new();
    email.push_str(&format!("From: {}\r\n", sanitize_header(from)));
    email.push_str(&format!("To: {}\r\n", sanitize_header(to)));
    email.push_str(&format!("Subject: AXIOM/{}/{}\r\n",
        sanitize_header(message_type), sanitize_header(request_id)));
    email.push_str(&format!("Message-ID: {}\r\n", msg_id));
    email.push_str(&format!("Date: {}\r\n", chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000")));
    email.push_str("Content-Type: text/plain; charset=utf-8\r\n");

    if let Some(reply_to) = in_reply_to {
        email.push_str(&format!("In-Reply-To: {}\r\n", sanitize_header(reply_to)));
    }

    // Blank line separates headers from body
    email.push_str("\r\n");

    // Body (base64 encoded JSON)
    email.push_str(&encoded);
    email.push_str("\r\n");

    Ok(email.into_bytes())
}

/// Build a cheque delivery email (§17.9)
///
/// Sent from validator to receiver after successful witness.
/// Each of the k=3 validators sends its cheque independently.
/// Receiver collects k cheques, bundles them, submits for redemption (CL5).
///
/// Subject: AXIOM/cheque/<uuid>
/// Body: CBOR-encoded ValidatorCheque + optional sender FACT chain + the
/// cheque's `send_origin` (KI#241 F-2).
///
/// `send_origin` — the witnessed send's ORIGIN RECORD (`WitnessPreimage` +
/// epoch, kind `Send`), built by Core's ONE constructor
/// `nabla_wire::LegPreimage::origin_of(&tx)` from the transaction this
/// validator just witnessed. The receiver never otherwise learns the sender's
/// `client_pk` / `wallet_seq` / `nonce`; it verifies this record against the
/// k-signed cheque (`axiom_sdk_core::recv`, five equalities) and carries it on
/// its redeem leg (`LegPreimage::Redeem { cheque }`), which is how Nabla's
/// provenance burn exit learns the cheque's GROSS amount when the sender never
/// registered (Fable review 2026-10-01). A DELIVERY field between ANTIE and
/// the SDK — no Core input, CoreID-neutral (precedent: `VbcDelivery`).
/// REFUSED here (never shipped) unless it reproduces `cheque.txid`.
pub fn build_cheque_delivery_email(
    from: &str,
    to: &str,
    cheque: &axiom_core_logic::types::ValidatorCheque,
    sender_fact_chain: Option<&axiom_core_logic::types::FactChain>,
    send_origin: &axiom_core_logic::types::OriginRecord,
) -> Result<Vec<u8>, AntieError> {
    if !axiom_core_logic::nabla_wire::cheque_origin_matches(send_origin, &cheque.txid) {
        return Err(AntieError::InvalidPayload(format!(
            "cheque {}: send_origin does not reproduce the cheque txid — refusing to deliver a cheque \
             the receiver would reject (KI#241 F-2)",
            hex::encode(&cheque.txid[..4]),
        )));
    }
    // Serialize cheque delivery directly to CBOR (same fix as build_response).
    // The JSON→CBOR path corrupts Dilithium signatures in sender_fact_chain.
    #[derive(serde::Serialize)]
    struct ChequePayload<'a> {
        cheque: &'a axiom_core_logic::types::ValidatorCheque,
        #[serde(skip_serializing_if = "Option::is_none")]
        cheque_fact_chain: Option<&'a axiom_core_logic::types::FactChain>,
        /// KI#241 F-2 — mandatory, LAST (see the fn doc). Reuses Core's
        /// `OriginRecord` shape (no mirror struct).
        send_origin: &'a axiom_core_logic::types::OriginRecord,
    }
    let payload = ChequePayload {
        cheque,
        cheque_fact_chain: sender_fact_chain,
        send_origin,
    };
    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&payload, &mut cbor_bytes)
        .map_err(|e| AntieError::SerializationError(format!("cheque CBOR: {}", e)))?;
    let encoded = BASE64.encode(&cbor_bytes);

    let request_id = uuid::Uuid::new_v4().to_string();
    let msg_id = format!("<{}.{}@axiom>",
        uuid::Uuid::new_v4(),
        chrono::Utc::now().timestamp()
    );

    let mut email = String::new();
    email.push_str(&format!("From: {}\r\n", sanitize_header(from)));
    email.push_str(&format!("To: {}\r\n", sanitize_header(to)));
    email.push_str(&format!("Subject: AXIOM/cheque/{}\r\n", request_id));
    email.push_str(&format!("Message-ID: {}\r\n", msg_id));
    email.push_str(&format!("Date: {}\r\n", chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000")));
    email.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    email.push_str("\r\n");
    email.push_str(&encoded);
    email.push_str("\r\n");

    Ok(email.into_bytes())
}

/// Build a scar-consent notification email (YPX-001 §1.5.1)
///
/// Sent from the overlapped validator to the RECEIVER when the scar-passcode
/// gate pauses a scarred send. Carries the 6-digit consent passcode — the
/// receiver ACCEPTS by giving it to the sender out-of-band. This email goes
/// ONLY to the receiver; the sender leg carries just the rejection code.
///
/// Subject: AXIOM/scar_consent/<uuid>
/// Body: base64(CBOR { scar_consent: ScarConsentNotification })
/// §5.2.2f — THE CERTIFICATE IS A DELIVERY. Body = base64(CBOR `VbcDelivery`);
/// the subject is NOT part of the contract (it may be padded or randomised
/// against fingerprinting — the owner, 2026-09-09); receivers recognise the BODY.
/// Twin of `axiom_sdk::validator_join::VbcDelivery` (the SDK reads what this
/// writes; kept out of core/logic on purpose — no Core change, no rotation).
pub const VBC_DELIVERY_MAGIC: &str = "AXIOM-VBC-SIG/1";

#[derive(serde::Serialize, serde::Deserialize)]
pub struct VbcDelivery {
    pub magic: String,
    pub signature: axiom_core_logic::types::VbcIssuerSignature,
}

pub fn build_vbc_delivery_email(
    from: &str,
    to: &str,
    signature: &axiom_core_logic::types::VbcIssuerSignature,
) -> Result<Vec<u8>, AntieError> {
    let payload = VbcDelivery { magic: VBC_DELIVERY_MAGIC.into(), signature: signature.clone() };
    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&payload, &mut cbor_bytes)
        .map_err(|e| AntieError::SerializationError(format!("vbc delivery CBOR: {}", e)))?;
    let encoded = BASE64.encode(&cbor_bytes);
    let msg_id = format!("<{}.{}@axiom>", uuid::Uuid::new_v4(), chrono::Utc::now().timestamp());
    let mut email = String::new();
    email.push_str(&format!("From: {}\r\n", sanitize_header(from)));
    email.push_str(&format!("To: {}\r\n", sanitize_header(to)));
    // Free-form on purpose: nothing may key on it.
    email.push_str(&format!("Subject: AXIOM/vbc/{}\r\n", uuid::Uuid::new_v4()));
    email.push_str(&format!("Message-ID: {}\r\n", msg_id));
    email.push_str(&format!("Date: {}\r\n", chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000")));
    email.push_str("Content-Type: text/plain; charset=utf-8\r\n\r\n");
    email.push_str(&encoded);
    email.push_str("\r\n");
    Ok(email.into_bytes())
}

/// Body-shape recogniser: `Some` iff the message body decodes as a
/// `VbcDelivery` with the right magic. Cheap on everything else (base64 or
/// CBOR fails first). Subject and headers are ignored entirely.
pub fn try_parse_vbc_delivery(raw: &[u8]) -> Option<axiom_core_logic::types::VbcIssuerSignature> {
    let msg = MessageParser::default().parse(raw)?;
    let body = msg.body_text(0)?;
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = BASE64.decode(compact.as_bytes()).ok()?;
    let d: VbcDelivery = ciborium::from_reader(bytes.as_slice()).ok()?;
    (d.magic == VBC_DELIVERY_MAGIC).then_some(d.signature)
}

pub fn build_scar_consent_email(
    from: &str,
    to: &str,
    notification: &axiom_core_logic::types::ScarConsentNotification,
) -> Result<Vec<u8>, AntieError> {
    // Direct typed CBOR (same rule as build_cheque_delivery_email — the
    // JSON→CBOR path corrupts byte fields; rule #13).
    #[derive(serde::Serialize)]
    struct ScarConsentPayload<'a> {
        scar_consent: &'a axiom_core_logic::types::ScarConsentNotification,
    }
    let payload = ScarConsentPayload { scar_consent: notification };
    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&payload, &mut cbor_bytes)
        .map_err(|e| AntieError::SerializationError(format!("scar consent CBOR: {}", e)))?;
    let encoded = BASE64.encode(&cbor_bytes);

    let request_id = uuid::Uuid::new_v4().to_string();
    let msg_id = format!("<{}.{}@axiom>",
        uuid::Uuid::new_v4(),
        chrono::Utc::now().timestamp()
    );

    let mut email = String::new();
    email.push_str(&format!("From: {}\r\n", sanitize_header(from)));
    email.push_str(&format!("To: {}\r\n", sanitize_header(to)));
    email.push_str(&format!("Subject: AXIOM/scar_consent/{}\r\n", request_id));
    email.push_str(&format!("Message-ID: {}\r\n", msg_id));
    email.push_str(&format!("Date: {}\r\n", chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000")));
    email.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    email.push_str("\r\n");
    email.push_str(&encoded);
    email.push_str("\r\n");

    Ok(email.into_bytes())
}

/// §23.14.6 peer-audit mail body: CBOR of `AntiePayload` with exactly one
/// `peer_audit_*` field set — the SAME struct the receiving ANTIE decodes it as
/// (`decode_payload_inner`), so writer and reader cannot drift.
///
/// ⚠ KI#242 (2026-10-02): this was `serde_json::json!` → `cbor::json_to_cbor`,
/// whose "every element ≤ 255 ⇒ byte string" heuristic retyped arrays and whose
/// map keys came out sorted. The bytes now differ from the old ANTIE's (field
/// order = struct order; `[u8; 32]` / `Vec<u8>` as CBOR arrays, as `ciborium`
/// writes every other UMP) but DECODE to the same Core value in both the old and
/// the new ANTIE — measured in `ki242_tests::mixed_roll_*`. Nothing signs the mail
/// bytes: the request/response signatures cover field-derived payloads
/// (`audit::peer_audit_*_signing_payload`).
fn peer_audit_body_cbor(payload: &AntiePayload) -> Result<Vec<u8>, AntieError> {
    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(payload, &mut cbor_bytes)
        .map_err(|e| AntieError::SerializationError(format!("CBOR encode: {}", e)))?;
    Ok(cbor_bytes)
}

/// Build a peer audit request email (§23.14.6)
///
/// Sent to target validator when Core demands a peer audit.
/// Subject: AXIOM/peer_audit_request/<uuid>
/// Body: CBOR-encoded PeerAuditRequest (txid + expected_hash + challenge_nonce + requester_pk)
pub fn build_peer_audit_request_email(
    from: &str,
    to: &str,
    request: &axiom_core_logic::types::PeerAuditRequest,
) -> Result<Vec<u8>, AntieError> {
    let payload = AntiePayload { peer_audit_request: Some(request.clone()), ..Default::default() };
    let encoded = BASE64.encode(&peer_audit_body_cbor(&payload)?);

    let request_id = uuid::Uuid::new_v4().to_string();
    let msg_id = format!("<{}.{}@axiom>",
        uuid::Uuid::new_v4(),
        chrono::Utc::now().timestamp()
    );

    let mut email = String::new();
    email.push_str(&format!("From: {}\r\n", sanitize_header(from)));
    email.push_str(&format!("To: {}\r\n", sanitize_header(to)));
    email.push_str(&format!("Subject: AXIOM/peer_audit_request/{}\r\n", request_id));
    email.push_str(&format!("Message-ID: {}\r\n", msg_id));
    email.push_str(&format!("Date: {}\r\n", chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000")));
    email.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    email.push_str("\r\n");
    email.push_str(&encoded);
    email.push_str("\r\n");

    Ok(email.into_bytes())
}

/// Build a peer audit response email (§23.14.6)
///
/// Sent back from target validator after authenticating the audit request.
/// Subject: AXIOM/peer_audit_response/<uuid>
/// Body: CBOR-encoded PeerAuditResponse (txid + nonce + raw DB fields +
/// responder_pk + responder_sig — KI#207 raw-fields, KI#175 signed)
pub fn build_peer_audit_response_email(
    from: &str,
    to: &str,
    response: &axiom_core_logic::types::PeerAuditResponse,
) -> Result<Vec<u8>, AntieError> {
    let payload = AntiePayload { peer_audit_response: Some(response.clone()), ..Default::default() };
    let encoded = BASE64.encode(&peer_audit_body_cbor(&payload)?);

    let request_id = uuid::Uuid::new_v4().to_string();
    let msg_id = format!("<{}.{}@axiom>",
        uuid::Uuid::new_v4(),
        chrono::Utc::now().timestamp()
    );

    let mut email = String::new();
    email.push_str(&format!("From: {}\r\n", sanitize_header(from)));
    email.push_str(&format!("To: {}\r\n", sanitize_header(to)));
    email.push_str(&format!("Subject: AXIOM/peer_audit_response/{}\r\n", request_id));
    email.push_str(&format!("Message-ID: {}\r\n", msg_id));
    email.push_str(&format!("Date: {}\r\n", chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000")));
    email.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    email.push_str("\r\n");
    email.push_str(&encoded);
    email.push_str("\r\n");

    Ok(email.into_bytes())
}

/// §23.14.6 (KI#213): B → A, the signed NotHeld. Same message type as a
/// raw-fields reply (`peer_audit_response`, RAW CBOR, no envelope) with the
/// `peer_audit_not_held` payload key instead of `peer_audit_response`.
pub fn build_peer_audit_not_held_email(
    from: &str,
    to: &str,
    not_held: &axiom_core_logic::types::PeerAuditNotHeld,
) -> Result<Vec<u8>, AntieError> {
    let payload = AntiePayload { peer_audit_not_held: Some(not_held.clone()), ..Default::default() };
    let encoded = BASE64.encode(&peer_audit_body_cbor(&payload)?);

    let request_id = uuid::Uuid::new_v4().to_string();
    let msg_id = format!("<{}.{}@axiom>",
        uuid::Uuid::new_v4(),
        chrono::Utc::now().timestamp()
    );

    let mut email = String::new();
    email.push_str(&format!("From: {}\r\n", sanitize_header(from)));
    email.push_str(&format!("To: {}\r\n", sanitize_header(to)));
    email.push_str(&format!("Subject: AXIOM/peer_audit_response/{}\r\n", request_id));
    email.push_str(&format!("Message-ID: {}\r\n", msg_id));
    email.push_str(&format!("Date: {}\r\n", chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000")));
    email.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    email.push_str("\r\n");
    email.push_str(&encoded);
    email.push_str("\r\n");

    Ok(email.into_bytes())
}

// `build_fanout_relay_email` DELETED 2026-09-25 (KI#175): it was the direct
// ANTIE→ANTIE relay leg of `gateway.rs::handle_fanout_relay`, which now refuses the
// type at the door. Fan-out is rebuilt as a wallet-carried transaction, not mail.


/// ANTIE's mail-reply envelope — defined ONCE in Core (KI#173).
pub use axiom_core_logic::types::ResponsePayload;

#[cfg(test)]
mod tests {
    use super::*;

    /// KI#241 F-2 — the cheque delivery carries the witnessed send's ORIGIN
    /// (`send_origin`, Core's `LegPreimage::origin_of(&tx)`) beside the cheque,
    /// and a payload whose origin does not reproduce the cheque txid is never
    /// built. MUTATION (run 2026-10-01): delete the `cheque_origin_matches`
    /// refusal in `build_cheque_delivery_email` ⇒ the forged case builds ⇒ RED.
    #[test]
    fn ki241_cheque_delivery_carries_a_matching_send_origin() {
        use axiom_core_logic::nabla_wire::LegPreimage;
        let tx = axiom_core_logic::types::Transaction {
            consumed_state_id: [0x11; 32],
            client_pk: vec![0x22; 32],
            sender_wallet_id: "alice@axiom.internal/0011223344".into(),
            wallet_seq: 3,
            receiver_wallet_id: "bob@axiom.internal/5566778899".into(),
            amount: 4_200,
            nonce: 9,
            epoch: 1_790_000_000,
            ..Default::default()
        };
        let txid = axiom_core_logic::compute::compute_txid(&tx);
        let issuer = axiom_core_logic::cheque_build::ChequeIssuerContext {
            issuer_id: [0x33; 32], issuer_pk: vec![0x44; 32], vbc_bundle: None,
            carrier_type: "smtp".into(), carrier_address: String::new(), rate_bps: 0, created_at: 1,
        };
        let cheque = axiom_core_logic::cheque_build::build_cheque_unsigned(
            &tx, txid, [0u8; 32], [0u8; 32], None, b"", None, 1, [0u8; 32], [0u8; 32], None, None, Vec::new(), &issuer,
        );
        let origin = LegPreimage::origin_of(&tx).unwrap();
        let email = build_cheque_delivery_email("v@axiom.internal", "bob@axiom.internal", &cheque, None, &origin)
            .expect("a matching origin builds");
        let text = String::from_utf8(email).unwrap();
        let body = text.split("\r\n\r\n").nth(1).unwrap().trim();
        let cbor = BASE64.decode(body).unwrap();
        #[derive(serde::Deserialize)]
        struct Payload {
            cheque: axiom_core_logic::types::ValidatorCheque,
            send_origin: axiom_core_logic::types::OriginRecord,
        }
        let p: Payload = ciborium::from_reader(cbor.as_slice()).expect("payload decodes");
        assert_eq!(p.send_origin, origin, "the origin rides the delivery");
        assert_eq!(p.cheque.txid, txid);
        assert!(axiom_core_logic::nabla_wire::cheque_origin_matches(&p.send_origin, &p.cheque.txid));

        let mut forged = origin.clone();
        forged.preimage.amount += 1;
        assert!(build_cheque_delivery_email("v@axiom.internal", "bob@axiom.internal", &cheque, None, &forged).is_err(),
            "an origin that does not reproduce the cheque txid is never delivered");
    }

    #[test]
    fn test_parse_subject() {
        let (msg_type, req_id) = parse_subject("AXIOM/witness/req-12345").unwrap();
        assert_eq!(msg_type, "witness");
        assert_eq!(req_id, "req-12345");
    }
    
    #[test]
    fn test_parse_subject_invalid() {
        assert!(parse_subject("Invalid subject").is_err());
        assert!(parse_subject("AXIOM/only-one").is_err());
    }
    
    /// CBOR of a payload exactly as a sender writes it (`ciborium`, the UMP codec).
    fn cbor_of(payload: &AntiePayload) -> Vec<u8> {
        let mut v = Vec::new();
        ciborium::into_writer(payload, &mut v).unwrap();
        v
    }

    fn sample_request() -> axiom_core_logic::types::PeerAuditRequest {
        axiom_core_logic::types::PeerAuditRequest {
            txid: [0xA1; 32], challenge_nonce: [0x07; 32],
            requester_pk: vec![0x42; 32], requester_sig: vec![0x99; 64],
        }
    }

    #[test]
    fn test_decode_payload_roundtrip() {
        // Envelope-wrapped (every client-class message ships wrapped), Base64.
        use axiom_core_logic::envelope::UmpEnvelope;
        let payload = AntiePayload {
            public_key: Some(vec![1u8; 32]), balance: Some(7), txid: Some(vec![2u8; 32]),
            issuer_set_hex: vec!["ab".into()], ..Default::default()
        };
        let env = UmpEnvelope::Plain { ump_bytes: cbor_of(&payload) };
        let decoded = decode_payload("witness", &BASE64.encode(env.to_cbor().unwrap())).unwrap();
        assert_eq!(decoded.public_key, payload.public_key);
        assert_eq!(decoded.balance, Some(7));
        assert_eq!(decoded.txid, payload.txid);
        assert_eq!(decoded.issuer_set_hex, vec!["ab".to_string()]);
        assert_eq!(decoded.raw_ump_body, cbor_of(&payload), "raw body captured verbatim");
    }

    #[test]
    fn test_sanitize_header_strips_crlf() {
        assert_eq!(sanitize_header("normal@test.com"), "normal@test.com");
        assert_eq!(sanitize_header("bad\r\nBcc: attacker@evil.com"), "badBcc: attacker@evil.com");
        assert_eq!(sanitize_header("has\nnewline"), "hasnewline");
        assert_eq!(sanitize_header("has\rcarriage"), "hascarriage");
        assert_eq!(sanitize_header(""), "");
    }

    #[test]
    fn test_validate_email_addr_rejects_injection() {
        assert!(validate_email_addr("good@test.com").is_ok());
        assert!(validate_email_addr("user@host.example.org").is_ok());
        // Header injection attempts
        assert!(validate_email_addr("bad@test.com\r\nBcc: spy@evil.com").is_err());
        assert!(validate_email_addr("bad@test.com\nBcc: spy@evil.com").is_err());
        // Invalid addresses
        assert!(validate_email_addr("").is_err());
        assert!(validate_email_addr("no-at-sign").is_err());
    }

    #[test]
    fn test_build_response_rejects_injected_from() {
        let payload = serde_json::json!({"test": true});
        let result = build_response(
            "receiver@test.com",
            "attacker@evil.com\r\nBcc: spy@evil.com",
            "witness_response",
            "req-1",
            None,
            &payload,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_response_rejects_injected_to() {
        let payload = serde_json::json!({"test": true});
        let result = build_response(
            "victim@test.com\r\nBcc: spy@evil.com",
            "sender@test.com",
            "witness_response",
            "req-1",
            None,
            &payload,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_response_valid_email() {
        let payload = serde_json::json!({"success": true});
        let result = build_response(
            "to@test.com",
            "from@test.com",
            "witness_response",
            "req-123",
            Some("<original-msg-id@axiom>"),
            &payload,
        );
        assert!(result.is_ok());
        let email = String::from_utf8(result.unwrap()).unwrap();
        assert!(email.contains("From: from@test.com\r\n"));
        assert!(email.contains("To: to@test.com\r\n"));
        assert!(email.contains("Subject: AXIOM/witness_response/req-123\r\n"));
        assert!(email.contains("In-Reply-To: <original-msg-id@axiom>\r\n"));
        assert!(email.contains("\r\n\r\n")); // header/body separator
    }

    #[test]
    fn test_parse_subject_extra_slashes() {
        // request_id can contain slashes (UUID format doesn't, but be safe)
        let (msg_type, req_id) = parse_subject("AXIOM/fanout/abc-123").unwrap();
        assert_eq!(msg_type, "fanout");
        assert_eq!(req_id, "abc-123");

        // AUDIT-FIX v2.11.14: extra slashes in request_id are preserved, not truncated
        let (msg_type, req_id) = parse_subject("AXIOM/witness/abc/def/ghi").unwrap();
        assert_eq!(msg_type, "witness");
        assert_eq!(req_id, "abc/def/ghi");
    }

    #[test]
    fn test_parse_subject_empty_parts() {
        assert!(parse_subject("").is_err());
        assert!(parse_subject("AXIOM").is_err());
        assert!(parse_subject("AXIOM/").is_err());
        assert!(parse_subject("NOT_AXIOM/witness/123").is_err());
    }

    #[test]
    fn parse_email_extracts_x_uncle_correlate_header() {
        // Synthesise an email with the X-UNCLE-Correlate header
        // UNCLE's submit_send handler stamps. Confirms the header
        // round-trips into AntieEmail.uncle_correlate.
        let correlate_hex = "ab".repeat(32);
        let body_cbor = {
            // Minimal AntiePayload — empty payload encodes fine.
            let payload = AntiePayload::default();
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&payload, &mut buf).unwrap();
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&buf)
        };
        let email_bytes = format!(
            "X-UNCLE-Correlate: {correlate_hex}\r\n\
             From: sender@example.com\r\n\
             To: alpha@example.com\r\n\
             Subject: AXIOM/peer_audit_request/req-001\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             {body_cbor}",
        );
        let parsed = parse_email(email_bytes.as_bytes()).expect("parse");
        let got = parsed.uncle_correlate.expect("X-UNCLE-Correlate extracted");
        assert_eq!(got, [0xABu8; 32], "correlate matches stamped value");
    }

    #[test]
    fn parse_email_without_x_uncle_correlate_leaves_field_none() {
        let body_cbor = {
            let payload = AntiePayload::default();
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&payload, &mut buf).unwrap();
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&buf)
        };
        let email_bytes = format!(
            "From: sender@example.com\r\n\
             To: alpha@example.com\r\n\
             Subject: AXIOM/peer_audit_request/req-001\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             {body_cbor}",
        );
        let parsed = parse_email(email_bytes.as_bytes()).expect("parse");
        assert!(parsed.uncle_correlate.is_none(), "non-UNCLE email → field None");
    }

    #[test]
    fn parse_email_rejects_malformed_uncle_correlate_header() {
        // Wrong length / non-hex → field stays None rather than
        // erroring the whole parse. Defense against a malformed
        // stamp poisoning the routing path.
        let body_cbor = {
            let payload = AntiePayload::default();
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&payload, &mut buf).unwrap();
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&buf)
        };
        let email_bytes = format!(
            "X-UNCLE-Correlate: not-hex-at-all\r\n\
             From: sender@example.com\r\n\
             To: alpha@example.com\r\n\
             Subject: AXIOM/peer_audit_request/req-001\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             {body_cbor}",
        );
        let parsed = parse_email(email_bytes.as_bytes()).expect("parse still succeeds");
        assert!(parsed.uncle_correlate.is_none());
    }

    #[test]
    fn test_decode_payload_empty_body() {
        assert!(decode_payload("witness", "").is_err());
    }

    #[test]
    fn test_decode_payload_invalid_base64() {
        assert!(decode_payload("witness", "not!valid!base64!!!").is_err());
    }

    #[test]
    fn test_decode_payload_invalid_cbor() {
        // Valid base64 but not valid CBOR
        let bad_cbor = BASE64.encode(b"\xff\xff\xff");
        assert!(decode_payload("witness", &bad_cbor).is_err());
    }

    /// AXIOM_DESIGN_PublicMailCarriers.md §3 shadow-mode contract:
    /// a `UmpEnvelope::Plain` wrapping a CBOR-UMP body must decode to
    /// the same `AntiePayload` as the unwrapped (legacy) body.  The
    /// SDK build_email path emits envelope-wrapped UMP; this test pins
    /// that ANTIE's decode_payload peels the envelope before parsing.
    #[test]
    fn test_decode_payload_unwraps_plain_envelope() {
        use axiom_core_logic::envelope::UmpEnvelope;
        // Build a small AntiePayload, encode it as CBOR (inner UMP body).
        let payload = AntiePayload { balance: Some(3), ..Default::default() };
        let inner_cbor = cbor_of(&payload);
        let inner_cbor_copy = inner_cbor.clone();
        // Wrap in UmpEnvelope::Plain and base64-encode as the wire body.
        let env = UmpEnvelope::Plain { ump_bytes: inner_cbor };
        let outer_cbor = env.to_cbor().unwrap();
        let wire = BASE64.encode(&outer_cbor);
        // Decode and assert the inner payload survived round-trip.
        let decoded = decode_payload("witness", &wire).unwrap();
        assert_eq!(decoded.raw_ump_body, inner_cbor_copy, "the inner body is what the envelope carried");
    }

    /// V↔V message types (peer_audit_*, fanout_relay) ship raw CBOR,
    /// no envelope wrapper.  Mandatory shape after Stream B (2026-05-13).
    #[test]
    fn test_decode_payload_v_to_v_accepts_raw_cbor() {
        let payload = AntiePayload {
            peer_audit_request: Some(sample_request()),
            ..Default::default()
        };
        let inner_cbor = cbor_of(&payload);
        let wire = BASE64.encode(&inner_cbor);
        let decoded = decode_payload("peer_audit_request", &wire).unwrap();
        assert_eq!(decoded.peer_audit_request.unwrap().txid, [0xA1; 32]);
    }

    /// CLAUDE.md §13: a raw-CBOR body addressed to a client-class
    /// message type (witness/redeem/...) is a wire-format violation
    /// and must hard-error, not silently pass through.
    #[test]
    fn test_decode_payload_client_class_rejects_raw_cbor() {
        let payload = AntiePayload {
            ..Default::default()
        };
        let inner_cbor = cbor_of(&payload);
        let wire = BASE64.encode(&inner_cbor);
        let err = decode_payload("witness", &wire).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(msg.contains("wire format violation"),
            "expected wire-format-violation error, got: {}", msg);
        assert!(msg.contains("witness"), "error must name the message type: {}", msg);
    }

    /// CLAUDE.md §13 in reverse: an envelope-wrapped body addressed
    /// to a V↔V type (peer_audit/fanout) is also a wire violation —
    /// catches an accidental wrap added in a future refactor.
    #[test]
    fn test_decode_payload_v_to_v_rejects_envelope() {
        use axiom_core_logic::envelope::UmpEnvelope;
        let payload = AntiePayload {
            peer_audit_request: Some(sample_request()),
            ..Default::default()
        };
        let inner_cbor = cbor_of(&payload);
        let env = UmpEnvelope::Plain { ump_bytes: inner_cbor };
        let wire = BASE64.encode(env.to_cbor().unwrap());
        let err = decode_payload("peer_audit_request", &wire).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(msg.contains("wire format violation"),
            "expected wire-format-violation error, got: {}", msg);
        assert!(msg.contains("raw CBOR"), "error must name the expected shape: {}", msg);
    }

    /// Forward-direction encryption round-trip: seal a UMP body to a
    /// validator's Ed25519 pubkey, then unseal it via the same key the
    /// gateway holds.  Pins AXIOM_DESIGN_PublicMailCarriers.md §3.2's
    /// wire contract end-to-end inside ANTIE.
    #[test]
    fn test_decode_payload_unseals_encrypted_envelope() {
        use axiom_core_logic::transport_crypto::seal_to_validator;
        use ed25519_dalek::SigningKey;
        use std::io::Write;

        // Build a small AntiePayload, encode as inner CBOR-UMP.
        let payload = AntiePayload {
            ..Default::default()
        };
        let inner_cbor = cbor_of(&payload);

        // Validator's Ed25519 seed → load via EnvelopeDecryptor.
        let seed = [0x5a; 32];
        let pk = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let mut seed_file = tempfile::NamedTempFile::new().unwrap();
        seed_file.write_all(&seed).unwrap();
        let decryptor = crate::decrypt::EnvelopeDecryptor::from_key_file(seed_file.path()).unwrap();

        // Seal to the validator and wrap as wire email body.
        let env = seal_to_validator(&pk, &inner_cbor).unwrap();
        let outer_cbor = env.to_cbor().unwrap();
        let wire = BASE64.encode(&outer_cbor);

        // Decrypted decode round-trips to the original payload.
        let decoded = decode_payload_with_context("witness", &wire, Some(&decryptor))
            .map_err(|_| ()).unwrap();
        assert_eq!(decoded.raw_ump_body, cbor_of(&payload), "unsealed body is the sealed one");
    }

    /// Without a decryptor (e.g. a validator hasn't enabled the feature
    /// yet), an inbound Encrypted envelope surfaces a DecryptFailed
    /// outcome so the gateway can bump the decrypt_fail metric and drop
    /// the message silently — not leak the failure reason to the network.
    #[test]
    fn test_encrypted_envelope_without_decryptor_drops() {
        use axiom_core_logic::transport_crypto::seal_to_validator;
        use ed25519_dalek::SigningKey;

        let pk = SigningKey::from_bytes(&[0xC0; 32]).verifying_key().to_bytes();
        let inner = cbor_of(&AntiePayload { balance: Some(1), ..Default::default() });
        let env = seal_to_validator(&pk, &inner).unwrap();
        let wire = BASE64.encode(env.to_cbor().unwrap());

        let result = decode_payload_with_context("witness", &wire, None);
        assert!(matches!(result, Err(DecodeError::DecryptFailed)));
    }

    /// An Encrypted envelope sealed to validator X must NOT decrypt with
    /// validator Y's decryptor.  This is the cross-validator pollution
    /// defence from §3.5: Beta-bound UMP encrypted to Beta's key can't
    /// be decrypted by Alpha, Alpha drops at ANTIE without invoking Lambda.
    #[test]
    fn test_encrypted_envelope_for_other_validator_drops() {
        use axiom_core_logic::transport_crypto::seal_to_validator;
        use ed25519_dalek::SigningKey;
        use std::io::Write;

        // Beta gets the message; Alpha tries to open it.
        let beta_pk = SigningKey::from_bytes(&[0xBB; 32]).verifying_key().to_bytes();
        let inner = cbor_of(&AntiePayload { balance: Some(2), ..Default::default() });
        let env = seal_to_validator(&beta_pk, &inner).unwrap();
        let wire = BASE64.encode(env.to_cbor().unwrap());

        let alpha_seed = [0xAA; 32];
        let mut alpha_seed_file = tempfile::NamedTempFile::new().unwrap();
        alpha_seed_file.write_all(&alpha_seed).unwrap();
        let alpha = crate::decrypt::EnvelopeDecryptor::from_key_file(alpha_seed_file.path()).unwrap();

        let result = decode_payload_with_context("witness", &wire, Some(&alpha));
        assert!(matches!(result, Err(DecodeError::DecryptFailed)));
    }

    /// YPX-001 §1.5.1: the scar-consent email round-trips — subject marker
    /// present, body decodes to the exact `{scar_consent: …}` CBOR shape
    /// the SDK's `parse_scar_consent_file` consumes.
    #[test]
    fn scar_consent_email_roundtrip() {
        let n = axiom_core_logic::types::ScarConsentNotification {
            txid: [0xCD; 32],
            sender_wallet_id: "alice@example.com/a1b2c3d4".into(),
            receiver_wallet_id: "bob@example.com/deadbeef".into(),
            amount: 42_000_000,
            scar_count: 3,
            passcode: 917_244,
        };
        let bytes = build_scar_consent_email("validator@axiom", "bob@example.com", &n)
            .expect("build scar consent email");
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Subject: AXIOM/scar_consent/"),
                "subject marker missing: {}", text.lines().take(6).collect::<Vec<_>>().join(" | "));

        // Decode the base64 body back to CBOR and re-extract the payload.
        let body = text.split("\r\n\r\n").nth(1).unwrap().trim();
        let cbor = BASE64.decode(body).expect("body base64");
        #[derive(serde::Deserialize)]
        struct P { scar_consent: axiom_core_logic::types::ScarConsentNotification }
        let parsed: P = ciborium::from_reader(cbor.as_slice()).expect("body CBOR");
        assert_eq!(parsed.scar_consent.txid, n.txid);
        assert_eq!(parsed.scar_consent.passcode, n.passcode);
        assert_eq!(parsed.scar_consent.scar_count, n.scar_count);
        assert_eq!(parsed.scar_consent.amount, n.amount);
    }
}

#[cfg(test)]
mod vbc_delivery_tests {
    use super::*;
    fn sig() -> axiom_core_logic::types::VbcIssuerSignature {
        axiom_core_logic::types::VbcIssuerSignature { signature: vec![7u8; 64], signer_sphincs_pk: vec![9u8; 32], commitment: [3u8; 32] }
    }
    #[test]
    fn a_delivery_round_trips_by_body_and_ignores_the_subject() {
        let raw = build_vbc_delivery_email("alpha@axiom", "validator_x@axiom", &sig()).unwrap();
        let text = String::from_utf8(raw.clone()).unwrap();
        // pad/replace the subject: recognition must not care
        let padded = text.replacen("Subject: AXIOM/vbc/", "Subject: zzz padded ", 1);
        let got = try_parse_vbc_delivery(padded.as_bytes()).expect("recognised by body");
        assert_eq!(got.signer_sphincs_pk, vec![9u8; 32]);
        assert_eq!(got.commitment, [3u8; 32]);
    }
    #[test]
    fn a_transaction_mail_is_not_mistaken_for_a_delivery() {
        let raw = b"From: a@b\r\nTo: c@d\r\nSubject: AXIOM/witness/abc\r\n\r\nAAAA\r\n";
        assert!(try_parse_vbc_delivery(raw).is_none());
    }
}

/// KI#242 (2026-10-02) — the JSON intermediate is gone from ANTIE's inbound
/// decode and its outbound peer-audit mails. These tests pin that the change is
/// wire-compatible BOTH ways during a mixed roll (old ANTIE ↔ new ANTIE), using
/// the frozen pre-KI#242 codec as the oracle for what the OLD ANTIE wrote/read.
#[cfg(test)]
mod ki242_tests {
    use super::*;
    use axiom_core_logic::types::{GroupMember, PeerAuditNotHeld, PeerAuditRequest, PeerAuditResponse};

    /// FROZEN COPY of the pre-KI#242 `antie/src/cbor.rs` (`cbor_to_json` /
    /// `json_to_cbor`, verbatim as of `934a7ccd`). TEST-ONLY: it exists solely to
    /// produce the bytes an OLD ANTIE writes and to decode the way an OLD ANTIE
    /// reads, so the mixed-roll claim is MEASURED, not inferred. Never call it
    /// from production code — that would be the KI#242 detour again.
    mod legacy {
        use serde_json::Value;

        /// Decode CBOR bytes into a serde_json::Value.
        ///
        /// Byte strings (major type 2) are decoded as JSON arrays of integers
        /// to match the existing serde deserialization for Vec<u8> and [u8; N].
        /// Maximum CBOR nesting depth (DoS prevention).
        const MAX_CBOR_DEPTH: usize = 32;
        /// Maximum array/map element count.
        const MAX_CBOR_ELEMENTS: u64 = 100_000;

        pub fn cbor_to_json(data: &[u8]) -> Result<Value, String> {
            let (value, _) = decode_item(data, 0, 0)?;
            Ok(value)
        }

        fn decode_item(data: &[u8], mut pos: usize, depth: usize) -> Result<(Value, usize), String> {
            if depth > MAX_CBOR_DEPTH {
                return Err("CBOR nesting too deep (>32 levels)".into());
            }
            if pos >= data.len() {
                return Err("Unexpected end of CBOR data".into());
            }

            let initial = data[pos];
            let major = initial >> 5;
            let info = initial & 0x1f;
            pos += 1;

            // Decode argument
            let (arg, pos) = decode_arg(data, pos, info)?;

            match major {
                // Unsigned integer
                0 => Ok((Value::Number(arg.into()), pos)),

                // Negative integer
                1 => {
                    let val = -1i64 - arg as i64;
                    Ok((Value::Number(val.into()), pos))
                }

                // Byte string → JSON array of integers (for serde Vec<u8> compat)
                2 => {
                    let end = pos + arg as usize;
                    if end > data.len() {
                        return Err(format!("Byte string length {} exceeds data at pos {}", arg, pos));
                    }
                    let bytes = &data[pos..end];
                    let arr: Vec<Value> = bytes.iter().map(|&b| Value::Number(b.into())).collect();
                    Ok((Value::Array(arr), end))
                }

                // Text string
                3 => {
                    let end = pos + arg as usize;
                    if end > data.len() {
                        return Err(format!("Text string length {} exceeds data at pos {}", arg, pos));
                    }
                    let s = std::str::from_utf8(&data[pos..end])
                        .map_err(|e| format!("Invalid UTF-8 in text string: {}", e))?;
                    Ok((Value::String(s.to_string()), end))
                }

                // Array
                4 => {
                    if arg > MAX_CBOR_ELEMENTS {
                        return Err(format!("CBOR array too large: {} elements", arg));
                    }
                    let count = arg as usize;
                    let mut items = Vec::with_capacity(count.min(1024));
                    let mut p = pos;
                    for _ in 0..count {
                        let (item, next) = decode_item(data, p, depth + 1)?;
                        items.push(item);
                        p = next;
                    }
                    Ok((Value::Array(items), p))
                }

                // Map
                5 => {
                    if arg > MAX_CBOR_ELEMENTS {
                        return Err(format!("CBOR map too large: {} entries", arg));
                    }
                    let count = arg as usize;
                    let mut map = serde_json::Map::with_capacity(count.min(1024));
                    let mut p = pos;
                    for _ in 0..count {
                        let (key, next) = decode_item(data, p, depth + 1)?;
                        p = next;
                        let (value, next) = decode_item(data, p, depth + 1)?;
                        p = next;

                        // Map keys must be strings
                        let key_str = match key {
                            Value::String(s) => s,
                            Value::Number(n) => n.to_string(),
                            _ => return Err(format!("Non-string map key: {:?}", key)),
                        };
                        map.insert(key_str, value);
                    }
                    Ok((Value::Object(map), p))
                }

                // Simple values and floats (major type 7)
                7 => {
                    match initial {
                        0xf4 => Ok((Value::Bool(false), pos)),
                        0xf5 => Ok((Value::Bool(true), pos)),
                        0xf6 | 0xf7 => Ok((Value::Null, pos)),
                        0xfb => {
                            // Float64: decode_arg already read 8 bytes as u64 in `arg`
                            let val = f64::from_bits(arg);
                            let num = serde_json::Number::from_f64(val)
                                .ok_or_else(|| format!("Cannot represent float {} as JSON number", val))?;
                            Ok((Value::Number(num), pos))
                        }
                        _ => Err(format!("Unknown CBOR simple value: {:#x}", initial)),
                    }
                }

                _ => Err(format!("Unknown CBOR major type: {}", major)),
            }
        }

        fn decode_arg(data: &[u8], pos: usize, info: u8) -> Result<(u64, usize), String> {
            match info {
                0..=23 => Ok((info as u64, pos)),
                24 => {
                    if pos >= data.len() {
                        return Err("Truncated 1-byte arg".into());
                    }
                    Ok((data[pos] as u64, pos + 1))
                }
                25 => {
                    if pos + 2 > data.len() {
                        return Err("Truncated 2-byte arg".into());
                    }
                    let val = u16::from_be_bytes(data[pos..pos+2].try_into()
                        .map_err(|_| "Invalid 2-byte CBOR arg")?);
                    Ok((val as u64, pos + 2))
                }
                26 => {
                    if pos + 4 > data.len() {
                        return Err("Truncated 4-byte arg".into());
                    }
                    let val = u32::from_be_bytes(data[pos..pos+4].try_into()
                        .map_err(|_| "Invalid 4-byte CBOR arg")?);
                    Ok((val as u64, pos + 4))
                }
                27 => {
                    if pos + 8 > data.len() {
                        return Err("Truncated 8-byte arg".into());
                    }
                    let val = u64::from_be_bytes(data[pos..pos+8].try_into()
                        .map_err(|_| "Invalid 8-byte CBOR arg")?);
                    Ok((val, pos + 8))
                }
                31 => Err("Indefinite-length CBOR not supported".into()),
                _ => Err(format!("Reserved CBOR additional info: {}", info)),
            }
        }

        /// Encode serde_json::Value to CBOR bytes.
        ///
        /// Used for ANTIE → PMC responses.
        /// JSON arrays of small integers (0-255) are encoded as CBOR byte strings
        /// when they look like byte arrays (all elements 0-255).
        pub fn json_to_cbor(value: &Value) -> Vec<u8> {
            let mut buf = Vec::new();
            encode_value(value, &mut buf);
            buf
        }

        fn encode_value(value: &Value, buf: &mut Vec<u8>) {
            match value {
                Value::Null => buf.push(0xf6),
                Value::Bool(true) => buf.push(0xf5),
                Value::Bool(false) => buf.push(0xf4),
                Value::Number(n) => {
                    if let Some(u) = n.as_u64() {
                        encode_head(0, u, buf);
                    } else if let Some(i) = n.as_i64() {
                        if i < 0 {
                            encode_head(1, (-1 - i) as u64, buf);
                        } else {
                            encode_head(0, i as u64, buf);
                        }
                    } else if let Some(f) = n.as_f64() {
                        buf.push(0xfb);
                        buf.extend_from_slice(&f.to_bits().to_be_bytes());
                    }
                }
                Value::String(s) => {
                    let bytes = s.as_bytes();
                    encode_head(3, bytes.len() as u64, buf);
                    buf.extend_from_slice(bytes);
                }
                Value::Array(arr) => {
                    // Heuristic: if all elements are integers 0-255, encode as byte string
                    if is_byte_array(arr) {
                        let bytes: Vec<u8> = arr.iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect();
                        encode_head(2, bytes.len() as u64, buf);
                        buf.extend_from_slice(&bytes);
                    } else {
                        encode_head(4, arr.len() as u64, buf);
                        for item in arr {
                            encode_value(item, buf);
                        }
                    }
                }
                Value::Object(map) => {
                    encode_head(5, map.len() as u64, buf);
                    for (k, v) in map {
                        // Keys as text strings
                        let kb = k.as_bytes();
                        encode_head(3, kb.len() as u64, buf);
                        buf.extend_from_slice(kb);
                        encode_value(v, buf);
                    }
                }
            }
        }

        fn encode_head(major: u8, value: u64, buf: &mut Vec<u8>) {
            let mt = major << 5;
            if value < 24 {
                buf.push(mt | value as u8);
            } else if value < 0x100 {
                buf.push(mt | 24);
                buf.push(value as u8);
            } else if value < 0x10000 {
                buf.push(mt | 25);
                buf.extend_from_slice(&(value as u16).to_be_bytes());
            } else if value < 0x100000000 {
                buf.push(mt | 26);
                buf.extend_from_slice(&(value as u32).to_be_bytes());
            } else {
                buf.push(mt | 27);
                buf.extend_from_slice(&value.to_be_bytes());
            }
        }

        /// Check if a JSON array looks like a byte array (all integers 0-255).
        fn is_byte_array(arr: &[Value]) -> bool {
            if arr.is_empty() {
                return false; // Empty arrays stay as arrays
            }
            arr.iter().all(|v| {
                matches!(v, Value::Number(n) if n.as_u64().is_some_and(|u| u <= 255))
            })
        }
    }

    fn enc<T: serde::Serialize>(v: &T) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::into_writer(v, &mut b).unwrap();
        b
    }

    /// Body bytes of a built mail (header/body split, Base64-decoded).
    fn mail_body(mail: &[u8]) -> Vec<u8> {
        let text = std::str::from_utf8(mail).unwrap();
        BASE64.decode(text.split("\r\n\r\n").nth(1).unwrap().trim()).unwrap()
    }

    // Real shapes: 32-byte ids, an Ed25519-sized key and a 64-byte sig. Byte
    // values span 0x00..=0xff and include values < 24 / ≥ 24 (1- vs 2-byte CBOR
    // ints), so the byte-string-vs-array difference is exercised for real.
    fn req() -> PeerAuditRequest {
        PeerAuditRequest {
            txid: core::array::from_fn(|i| (i * 8) as u8),
            challenge_nonce: core::array::from_fn(|i| 255 - i as u8),
            requester_pk: (0..32u8).map(|i| i.wrapping_mul(37)).collect(),
            requester_sig: (0..64u8).map(|i| i.wrapping_mul(11).wrapping_add(3)).collect(),
        }
    }
    fn resp() -> PeerAuditResponse {
        PeerAuditResponse {
            txid: [0x00; 32], challenge_nonce: [0xff; 32],
            sender_balance: u64::MAX, receiver_balance: 0, state_id: core::array::from_fn(|i| i as u8),
            amount: 1_000_000_007,
            responder_pk: vec![0x17; 32], responder_sig: (0..64u8).collect(),
        }
    }
    fn not_held() -> PeerAuditNotHeld {
        PeerAuditNotHeld {
            txid: [0x18; 32], challenge_nonce: [0x01; 32],
            responder_pk: vec![0xAB; 32], responder_sig: vec![0x00; 64],
        }
    }

    /// The OLD ANTIE's outbound peer-audit body, exactly as its builders made it:
    /// `json!({key: to_value(x)})` → `json_to_cbor`.
    fn old_body<T: serde::Serialize>(key: &str, v: &T) -> Vec<u8> {
        let mut m = serde_json::Map::new();
        m.insert(key.to_string(), serde_json::to_value(v).unwrap());
        legacy::json_to_cbor(&serde_json::Value::Object(m))
    }

    /// The OLD ANTIE's read of a body: `cbor_to_json` → the `Value` field →
    /// `serde_json::from_value::<CoreType>` (what `gateway.rs` did).
    fn old_read<T: serde::de::DeserializeOwned>(body: &[u8], key: &str) -> Result<T, String> {
        let v = legacy::cbor_to_json(body)?;
        serde_json::from_value(v.get(key).cloned().ok_or("key absent")?).map_err(|e| e.to_string())
    }

    /// MIXED ROLL, direction 1: an OLD ANTIE's peer-audit mail decodes in the NEW
    /// ANTIE to the identical Core value (request, response, NotHeld).
    #[test]
    fn mixed_roll_old_antie_bytes_decode_in_new_antie() {
        let b = old_body("peer_audit_request", &req());
        let got = decode_payload("peer_audit_request", &BASE64.encode(&b)).unwrap();
        assert_eq!(enc(&got.peer_audit_request.unwrap()), enc(&req()));

        let b = old_body("peer_audit_response", &resp());
        let got = decode_payload("peer_audit_response", &BASE64.encode(&b)).unwrap();
        assert_eq!(enc(&got.peer_audit_response.unwrap()), enc(&resp()));
        assert!(got.peer_audit_not_held.is_none());

        let b = old_body("peer_audit_not_held", &not_held());
        let got = decode_payload("peer_audit_response", &BASE64.encode(&b)).unwrap();
        assert_eq!(enc(&got.peer_audit_not_held.unwrap()), enc(&not_held()));
        assert!(got.peer_audit_response.is_none());
    }

    /// MIXED ROLL, direction 2: the NEW ANTIE's peer-audit mails (the real
    /// builders) decode in an OLD ANTIE to the identical Core value. Also MEASURES
    /// that the bytes differ from the old ones (struct field order; `[u8; 32]` /
    /// `Vec<u8>` written as CBOR arrays) — compatibility rests on both decoders
    /// accepting both forms, not on identical bytes.
    #[test]
    fn mixed_roll_new_antie_bytes_decode_in_old_antie() {
        let m = build_peer_audit_request_email("a@axiom.internal", "b@axiom.internal", &req()).unwrap();
        let body = mail_body(&m);
        assert_ne!(body, old_body("peer_audit_request", &req()), "measured: the outbound bytes changed");
        let old: PeerAuditRequest = old_read(&body, "peer_audit_request").unwrap();
        assert_eq!(enc(&old), enc(&req()));
        // …and the new ANTIE reads its own mail.
        let new = decode_payload("peer_audit_request", &BASE64.encode(&body)).unwrap();
        assert_eq!(enc(&new.peer_audit_request.unwrap()), enc(&req()));

        let m = build_peer_audit_response_email("b@axiom.internal", "a@axiom.internal", &resp()).unwrap();
        let body = mail_body(&m);
        let old: PeerAuditResponse = old_read(&body, "peer_audit_response").unwrap();
        assert_eq!(enc(&old), enc(&resp()));
        assert!(legacy::cbor_to_json(&body).unwrap().get("peer_audit_not_held").is_none(),
            "an old ANTIE must not see a NotHeld key on a raw-fields reply");

        let m = build_peer_audit_not_held_email("b@axiom.internal", "a@axiom.internal", &not_held()).unwrap();
        let body = mail_body(&m);
        let old: PeerAuditNotHeld = old_read(&body, "peer_audit_not_held").unwrap();
        assert_eq!(enc(&old), enc(&not_held()));
        assert!(legacy::cbor_to_json(&body).unwrap().get("peer_audit_response").is_none(),
            "a NotHeld mail sets exactly one peer_audit_* key");
    }

    /// `init_genesis_dev` with group members + the dev payload the SDK really
    /// sends (`sdk/client/src/send.rs::build_genesis_dev_payload`: a CBOR map,
    /// `public_key` as a byte string). Old-path and new-path decode agree, for
    /// both a ciborium-native body and an old-codec body.
    #[test]
    fn group_members_and_genesis_dev_decode_identically() {
        use ciborium::Value as C;
        let members = vec![
            GroupMember { member_pk: vec![0x31; 32], share_bps: 6_000, available: 0 },
            GroupMember { member_pk: (0..32u8).collect(), share_bps: 4_000, available: 123_456_789_012 },
        ];
        let member_val = |m: &GroupMember| C::Map(vec![
            (C::Text("member_pk".into()), C::Bytes(m.member_pk.clone())),
            (C::Text("share_bps".into()), C::Integer(m.share_bps.into())),
            (C::Text("available".into()), C::Integer(m.available.into())),
        ]);
        let native = enc(&C::Map(vec![
            (C::Text("public_key".into()), C::Bytes(vec![0x09; 32])),
            (C::Text("balance".into()), C::Integer(500u64.into())),
            (C::Text("group_members".into()), C::Array(members.iter().map(member_val).collect())),
        ]));
        let mut m = serde_json::Map::new();
        m.insert("public_key".into(), serde_json::to_value(vec![0x09u8; 32]).unwrap());
        m.insert("balance".into(), 500.into());
        m.insert("group_members".into(), serde_json::to_value(&members).unwrap());
        let old_codec = legacy::json_to_cbor(&serde_json::Value::Object(m));

        for body in [native, old_codec] {
            let new = decode_payload_inner(&body).unwrap();
            assert_eq!(new.group_members.as_ref().unwrap(), &members);
            assert_eq!(new.public_key.as_deref(), Some(&[0x09u8; 32][..]));
            assert_eq!(new.balance, Some(500));
            let old: Vec<GroupMember> = old_read(&body, "group_members").unwrap();
            assert_eq!(old, members, "old and new decode agree");
        }
    }

    /// `query_params.wallet_pk` — byte string (ciborium-native sender) and
    /// integer array (old-codec sender, or an array writer) both yield the key,
    /// exactly as the old `from_value::<Vec<u8>>` did; a missing key is `None`.
    #[test]
    fn query_params_wallet_pk_decodes_identically() {
        use ciborium::Value as C;
        let pk: Vec<u8> = (0..32u8).map(|i| i * 7).collect();
        let as_bytes = enc(&C::Map(vec![(C::Text("query_params".into()),
            C::Map(vec![(C::Text("wallet_pk".into()), C::Bytes(pk.clone()))]))]));
        let as_array = enc(&C::Map(vec![(C::Text("query_params".into()),
            C::Map(vec![(C::Text("wallet_pk".into()),
                C::Array(pk.iter().map(|b| C::Integer((*b).into())).collect()))]))]));
        for body in [as_bytes, as_array] {
            let p = decode_payload_inner(&body).unwrap();
            assert_eq!(crate::gateway::query_wallet_pk(p.query_params.as_ref().unwrap()), Some(pk.clone()));
            let old = legacy::cbor_to_json(&body).unwrap();
            let old_pk: Vec<u8> = serde_json::from_value(old["query_params"]["wallet_pk"].clone()).unwrap();
            assert_eq!(old_pk, pk);
        }
        let no_key = enc(&C::Map(vec![(C::Text("query_params".into()),
            C::Map(vec![(C::Text("other".into()), C::Integer(1.into()))]))]));
        let p = decode_payload_inner(&no_key).unwrap();
        assert_eq!(crate::gateway::query_wallet_pk(p.query_params.as_ref().unwrap()), None);
    }

    /// The defect class itself: a field whose CBOR form the hand decoder could
    /// not represent (here a float32 — equally a tag or an indefinite length)
    /// made the OLD path drop the WHOLE mail, so the peer-audit answer beside it
    /// was silently lost (A then read silence and banned `NonResponds`). The
    /// typed decode carries the answer and ignores the field it does not know.
    #[test]
    fn a_new_field_no_longer_drops_the_mail() {
        use ciborium::Value as C;
        let body = enc(&C::Map(vec![
            (C::Text("peer_audit_response".into()), C::serialized(&resp()).unwrap()),
            (C::Text("future_field".into()), C::Float(0.5)),
        ]));
        // ciborium writes 0.5 in its shortest lossless form (f16), which the old
        // decoder refused.
        assert!(legacy::cbor_to_json(&body).is_err(), "old path: the whole mail is undecodable");
        let new = decode_payload("peer_audit_response", &BASE64.encode(&body)).unwrap();
        assert_eq!(enc(&new.peer_audit_response.unwrap()), enc(&resp()), "new path: carried intact");

        // Same for an integer map key the old decoder stringified into a
        // collision with a text key (`1` ≡ `"1"`): the old path merged them.
        let colliding = enc(&C::Map(vec![
            (C::Text("1".into()), C::Integer(1.into())),
            (C::Integer(1.into()), C::Integer(2.into())),
        ]));
        assert_eq!(legacy::cbor_to_json(&colliding).unwrap().as_object().unwrap().len(), 1,
            "old path: two distinct keys collapsed into one");
    }

    /// The nesting limit refuses nothing the old decoder took, and stays bounded:
    /// for every depth 1..=40, old-accepted ⇒ new-accepted, and the new decode
    /// refuses everything deeper than 33 containers. MEASURED difference: at
    /// exactly 32 nested arrays with a non-empty innermost, old refused, new
    /// accepts (the old cap counted the scalar).
    #[test]
    fn depth_limit_never_refuses_what_the_old_decoder_took() {
        use ciborium::Value as C;
        let mut checked = 0;
        let mut differ = Vec::new();
        for inner_empty in [true, false] {
            for n in 1..=40usize {
                let mut v = if inner_empty { C::Array(vec![]) } else { C::Array(vec![C::Integer(0.into())]) };
                for _ in 1..n { v = C::Array(vec![v]); }
                let body = enc(&C::Map(vec![(C::Text("x".into()), v)]));
                let old_ok = legacy::cbor_to_json(&body).is_ok();
                let new_ok = decode_payload_inner(&body).is_ok();
                assert!(!old_ok || new_ok, "depth {} (inner_empty={}): old accepted, new refused", n, inner_empty);
                assert_eq!(new_ok, n + 1 <= BODY_RECURSION_LIMIT, "depth {}: new decode bounded by the limit", n);
                if old_ok != new_ok { differ.push((n, inner_empty)); }
                checked += 1;
            }
        }
        assert_eq!(checked, 80);
        assert_eq!(differ, vec![(32, false)], "the one measured difference");
    }

    /// Measures the claim in `build_response`'s comment: ciborium writes a
    /// `Vec<u8>` as a CBOR ARRAY (major 4), not a byte string — serde gives
    /// `Vec<u8>` no bytes hint. Compatibility never relied on it: every ANTIE /
    /// SDK reader accepts both forms (`ciborium` `deserialize_seq` takes a byte
    /// string too).
    #[test]
    fn ciborium_writes_vec_u8_as_an_array() {
        let b = enc(&vec![1u8, 2, 3]);
        assert_eq!(b[0] >> 5, 4, "major type 4 (array)");
        let back: Vec<u8> = ciborium::from_reader(&enc(&ciborium::Value::Bytes(vec![1, 2, 3]))[..]).unwrap();
        assert_eq!(back, vec![1, 2, 3], "a byte string decodes into Vec<u8>");
    }
}
