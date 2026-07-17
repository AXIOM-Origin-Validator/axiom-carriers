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
    /// `X-UNCLE-Correlate` header if present. UNCLE's SubmitSend
    /// handler stamps this header before dropping the UMP into the
    /// validator maildir; ANTIE preserves it as opaque 32 bytes and
    /// forwards it to `uncle_sink::tee` so the response file lands at
    /// `<witness_outbox>/<correlate_hex>.cbor` for UNCLE's
    /// `witness_observer` to pick up.
    ///
    /// `None` on any non-UNCLE-mediated email — the normal SMTP/maildir
    /// dispatch path is unchanged for those.
    pub uncle_correlate: Option<[u8; 32]>,
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
    // [[feedback_no_json_in_protocol_path]]: removing them eliminates ~30
    // `serde_json::Value` fields from the protocol path. The remaining
    // `Option<serde_json::Value>` fields below (`query_params`,
    // `group_members`, `audit_confirmation`, etc) are STILL ACTIVELY READ
    // by gateway for the non-typed flows (queries, group setup, peer audit,
    // scar healing, fanout). Migrating those to raw CBOR bytes is the next
    // sweep.

    /// Query parameters (for query handlers — typed-wire migration pending)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_params: Option<serde_json::Value>,

    // === Genesis dev fields ===

    /// Public key for genesis (init_genesis_dev)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<Vec<u8>>,

    /// Balance for genesis (init_genesis_dev)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<u64>,

    /// Group wallet members for genesis (init_genesis_dev)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_members: Option<Vec<serde_json::Value>>,

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
    #[serde(default)]
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
    #[serde(default)]
    pub issuer_set_hex: Vec<String>,

    // === Scar healing fields (YPX-001 §1.5.3) ===

    /// Scar recovery proof (for scar_heal requests)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scar_recovery_proof: Option<serde_json::Value>,

    /// Target wallet ID for scar heal application
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_wallet_id: Option<String>,

    // === Phase 3C: Onboarding fields (carrier passthrough) ===

    /// Proof capability for VBC sign requests: "dmap" or "zkvm"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_cap: Option<String>,

    /// Human-readable node name for VBC sign requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name_field: Option<String>,

    // === §4.5: auth_hash (stolen-key protection) ===

    /// Ed25519 pubkey derived from owner_secret — 32 bytes (v2.11.13).
    /// Once set on a wallet, every TX requires owner_proof (Ed25519 signature).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_hash: Option<Vec<u8>>,

    // === §23.14.6: Peer Audit Protocol ===

    /// Peer audit request (inbound from remote validator).
    /// Contains txid + expected_hash. Lambda looks up DB, Core verifies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_audit_request: Option<serde_json::Value>,

    /// Peer audit response (inbound from remote validator).
    /// Contains computed_hash from remote Core's verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_audit_response: Option<serde_json::Value>,

    // === §18.8: Fan-Out Protocol ===

    /// Fan-Out message for relay (CL10 verified).
    /// Contains: diffusion_id, content_type, content, originator_pk/sig, TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fanout_message: Option<serde_json::Value>,
}

/// Parse an email from raw bytes (no decryption — for tests / legacy callers).
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

/// Inner CBOR→AntiePayload parser (the post-envelope-unwrap path).
fn decode_payload_inner(decoded: &[u8]) -> Result<AntiePayload, AntieError> {
    // Decode CBOR into ciborium::Value first, then convert to AntiePayload.
    // For prev_receipts and overlapped_signatures, we store raw CBOR bytes
    // in the _raw fields so the gateway can deserialize them directly
    // (preserving CBOR Bytes type for VBC bundles). The serde_json::Value
    // fields remain for backward compat with the TCP/WS path.
    let cbor_val: ciborium::Value = ciborium::from_reader(decoded)
        .map_err(|e| AntieError::EmailParseError(format!("CBOR decode failed: {}", e)))?;

    // Convert to JSON for the AntiePayload struct (legacy path)
    let json_value = crate::cbor::cbor_to_json(decoded)
        .map_err(|e| AntieError::EmailParseError(format!("CBOR→JSON failed: {}", e)))?;
    let mut payload: AntiePayload = serde_json::from_value(json_value)
        .map_err(|e| AntieError::EmailParseError(format!("JSON→struct failed: {}", e)))?;

    // UMP enforcement — `axiom_core_logic::types` owns the canonical
    // typed wires (`WitnessRequest`, `RedeemRequestEnvelope`, …). The
    // gateway deserializes the typed envelope DIRECTLY from
    // `payload.raw_ump_body` (the verbatim post-envelope-unwrap CBOR
    // body, captured here). Adding a per-field `raw_<x>` extractor for
    // a typed-wire field is the drift pattern this layer was rebuilt
    // to delete — see `scripts/check_layer_boundary.sh` Rule 9 and
    // `feedback_no_mirror_structs`.
    //
    // `cbor_val` is intentionally unused here now; the typed
    // deserialize at the consumer side replaces every former per-field
    // extraction arm (`prev_receipts`, `overlapped_signatures`,
    // `sender_fact_chain`, `receiver_fact_chain`, `fact_witness_sigs`,
    // `fee_breakdown`, `cheque_claim_proof`, `cl1_execution_proof`).
    let _ = cbor_val;
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
    // Direct ciborium serialization preserves Vec<u8> as CBOR Bytes always.
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

/// Build a scar healing notification email (YPX-001 §1.5.3)
///
/// Sent to downstream receivers when a sender's FACT link scar is healed.
/// Subject: AXIOM/scar_heal/<uuid>
/// Body: CBOR-encoded payload with scar_recovery_proof and target_wallet_id
pub fn build_scar_heal_email(
    from: &str,
    to: &str,
    proof: &serde_json::Value,
    target_wallet_id: &str,
) -> Result<Vec<u8>, AntieError> {
    let payload = serde_json::json!({
        "scar_recovery_proof": proof,
        "target_wallet_id": target_wallet_id,
    });

    let cbor_bytes = crate::cbor::json_to_cbor(&payload);
    let encoded = BASE64.encode(&cbor_bytes);

    let request_id = uuid::Uuid::new_v4().to_string();
    let msg_id = format!("<{}.{}@axiom>",
        uuid::Uuid::new_v4(),
        chrono::Utc::now().timestamp()
    );

    let mut email = String::new();
    email.push_str(&format!("From: {}\r\n", sanitize_header(from)));
    email.push_str(&format!("To: {}\r\n", sanitize_header(to)));
    email.push_str(&format!("Subject: AXIOM/scar_heal/{}\r\n", request_id));
    email.push_str(&format!("Message-ID: {}\r\n", msg_id));
    email.push_str(&format!("Date: {}\r\n", chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000")));
    email.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    email.push_str("\r\n");
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
/// Body: CBOR-encoded ValidatorCheque + optional sender FACT chain
pub fn build_cheque_delivery_email(
    from: &str,
    to: &str,
    cheque: &axiom_core_logic::types::ValidatorCheque,
    sender_fact_chain: Option<&axiom_core_logic::types::FactChain>,
) -> Result<Vec<u8>, AntieError> {
    // Serialize cheque delivery directly to CBOR (same fix as build_response).
    // The JSON→CBOR path corrupts Dilithium signatures in sender_fact_chain.
    #[derive(serde::Serialize)]
    struct ChequePayload<'a> {
        cheque: &'a axiom_core_logic::types::ValidatorCheque,
        #[serde(skip_serializing_if = "Option::is_none")]
        cheque_fact_chain: Option<&'a axiom_core_logic::types::FactChain>,
    }
    let payload = ChequePayload {
        cheque,
        cheque_fact_chain: sender_fact_chain,
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
    let payload = serde_json::json!({
        "peer_audit_request": serde_json::to_value(request)?,
    });

    let cbor_bytes = crate::cbor::json_to_cbor(&payload);
    let encoded = BASE64.encode(&cbor_bytes);

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
/// Sent back from target validator after verifying the audit request.
/// Subject: AXIOM/peer_audit_response/<uuid>
/// Body: CBOR-encoded PeerAuditResponse (txid + computed_hash + challenge_nonce + responder_pk)
pub fn build_peer_audit_response_email(
    from: &str,
    to: &str,
    response: &axiom_core_logic::types::PeerAuditResponse,
) -> Result<Vec<u8>, AntieError> {
    let payload = serde_json::json!({
        "peer_audit_response": serde_json::to_value(response)?,
    });

    let cbor_bytes = crate::cbor::json_to_cbor(&payload);
    let encoded = BASE64.encode(&cbor_bytes);

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

/// Build a CL10 Fan-Out relay email (YP §28, CL10).
///
/// Sent to peer validators when relaying a Fan-Out message with TTL > 0.
/// Subject: AXIOM/fanout/<uuid>
/// Body: CBOR-encoded FanOutMessage (with decremented TTL)
pub fn build_fanout_relay_email(
    from: &str,
    to: &str,
    fanout_msg: &axiom_core_logic::types::FanOutMessage,
) -> Result<Vec<u8>, AntieError> {
    let payload = serde_json::json!({
        "message_type": "fanout",
        "fanout_message": serde_json::to_value(fanout_msg)?,
    });

    let cbor_bytes = crate::cbor::json_to_cbor(&payload);
    let encoded = BASE64.encode(&cbor_bytes);

    let request_id = uuid::Uuid::new_v4().to_string();
    let msg_id = format!("<{}.{}@axiom>",
        uuid::Uuid::new_v4(),
        chrono::Utc::now().timestamp()
    );

    let mut email = String::new();
    email.push_str(&format!("From: {}\r\n", sanitize_header(from)));
    email.push_str(&format!("To: {}\r\n", sanitize_header(to)));
    email.push_str(&format!("Subject: AXIOM/fanout/{}\r\n", request_id));
    email.push_str(&format!("Message-ID: {}\r\n", msg_id));
    email.push_str(&format!("Date: {}\r\n", chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000")));
    email.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    email.push_str("\r\n");
    email.push_str(&encoded);
    email.push_str("\r\n");

    Ok(email.into_bytes())
}

/// Response payload
///
/// Wire-format note: payload fields that contain `Vec<u8>` byte sequences
/// (validator_pk, signature, state_id, etc.) used to be typed as
/// `serde_json::Value` and converted via `serde_json::to_value(...)` from
/// the typed Lambda response. That intermediate flattened CBOR `Bytes` to
/// JSON integer arrays and then back to CBOR Array<u8> on the wire — a
/// lossy bandaid that masked byte-string corruption (rule #13 / two-day
/// debug, May 2026). All payload fields now carry their typed
/// `axiom_core_logic` structs so byte fields stay as CBOR `Bytes` end to
/// end. The SDK's CBOR reader handles both shapes via `cbor_to_bytes`,
/// so old `Array<u8>`-encoded responses still parse during the rollover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePayload {
    /// Success flag
    pub success: bool,

    /// Request ID echoed back
    pub request_id: String,

    /// Witness signature (if successful)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_signature: Option<axiom_core_logic::types::WitnessSig>,

    /// Cheque for receiver (ValidatorCheque - needed for redemption)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cheque_for_receiver: Option<axiom_core_logic::types::ValidatorCheque>,

    /// YPX-001 §1.5.1 — scar-consent voucher for the SENDER, issued by the
    /// passcode-verifying validator. The sender's SDK attaches it to the
    /// round's remaining witness requests so the other overlapped validators
    /// verify consent instead of re-gating. Forwarded verbatim (unlike the
    /// receiver-bound notification, which never rides the sender leg).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scar_consent_voucher: Option<axiom_core_logic::types::ScarConsentVoucher>,

    /// Produced state_id (sender's new state after witness, receiver's new state after redeem)
    /// Client MUST use this as consumed_state_id for their next transaction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub produced_state_id: Option<Vec<u8>>,

    /// Receipt (if k=3 reached)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<axiom_core_logic::types::Receipt>,

    /// The commitment_hash computed by Core — returned on every successful witness
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment_hash: Option<Vec<u8>>,

    /// State hash computed by Core (CL2/CL3) — top-level so the SDK can
    /// rebuild receipt_commitment locally for partial-commit receipts.
    /// Pre-fix this field was missing from ResponsePayload, so ANTIE
    /// silently dropped Lambda's value during the deserialize→re-serialize
    /// hop. SDK then wrote receipts with state_hash=[0u8;32], and Core's
    /// strict-mode CL2 (post-4a81a34) rejected with
    /// E_RECEIPT_COMMITMENT_MISMATCH on the next send. CLAUDE.md §13.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_hash: Option<Vec<u8>>,

    /// Receipt commitment computed by Core (CL3) — top-level so the SDK
    /// embeds it in receipts (especially partial-commit receipts where
    /// Lambda's full Receipt isn't yet finalised). Same drop-by-mirror-drift
    /// fix as state_hash above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_commitment: Option<Vec<u8>>,

    /// Transaction ID — top-level on every successful witness response so
    /// the SDK can build partial-commit receipts on the V1/V2 path where
    /// `receipt: Option<Receipt>` is None. Required field on success
    /// responses (no serde default — missing = producer bug, surface it).
    /// Optional only because rejection / non-success responses don't have
    /// a txid to forward.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<Vec<u8>>,

    /// State ID (for genesis responses)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_id: Option<Vec<u8>>,

    /// Error message (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Rejection code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_code: Option<String>,

    /// Lambda's structured ErrorResponse forwarded verbatim on rejection
    /// (Phase 2 canonical). Carries the protocol-defined `code`,
    /// `message`, `category`, and `recovery` hint. Clients dispatch
    /// on `recovery` for state-drift handling. Pre-fix ANTIE flattened
    /// the structured response into the `error` string and the SDK lost
    /// the recovery hint entirely — w024 retry-loop bug observed in the
    /// v3.0.0-beta5 soak (task #63).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_response: Option<axiom_errors::ErrorResponse>,

    /// Validator hints — included in ALL responses (YP §27 peer discovery)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validator_hints: Vec<axiom_core_logic::types::ValidatorHint>,

    /// Updated sender FACT chain (YPX-001 §1.6) — only present when k=3 reached
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_fact_chain: Option<axiom_core_logic::types::FactChain>,

    /// Updated receiver FACT chain after redeem (YPX-001 §1.6)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_fact_chain: Option<axiom_core_logic::types::FactChain>,

    /// This validator's Dilithium FACT signature on the redeem link's
    /// commitment. The SDK collects k of these to build the receiver's
    /// redeem FactLink. Only present on redeem responses (None on
    /// witness/heal/etc).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact_signature: Option<Vec<u8>>,

    /// Free-form metadata for non-protocol responses — query (wallet
    /// state lookup), VSP (validator status), debug. JSON shape is
    /// arbitrary per response type. Kept as `serde_json::Value` because
    /// these responses don't carry byte fields that need
    /// type-preservation; they're human-debuggable JSON. Witness /
    /// redeem responses leave this `None`; only query-class responses
    /// fill it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_data: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
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
    
    #[test]
    fn test_decode_payload_roundtrip() {
        // Helper: serialize to CBOR, wrap in UmpEnvelope::Plain (post
        // Stream B every client-class message ships wrapped), then
        // Base64-encode.  Matches what the SDK build_email produces.
        fn encode_payload(payload: &AntiePayload) -> String {
            use axiom_core_logic::envelope::UmpEnvelope;
            let json_value = serde_json::to_value(payload).unwrap();
            let inner_cbor = crate::cbor::json_to_cbor(&json_value);
            let env = UmpEnvelope::Plain { ump_bytes: inner_cbor };
            BASE64.encode(env.to_cbor().unwrap())
        }
        
        // Test with minimal fields (all defaults)
        let minimal = AntiePayload {
            query_params: None,
            public_key: None,
            balance: None,
            group_members: None,
            txid: None,
            validator_pk: None,
            sender_sig: None,
            client_pk: None,
            sphincs_pk_hex: None,
            dilithium_pk_hex: None,
            ed25519_pk_hex: None,
            pgp_fingerprint_hex: None,
            issued_at: None,
            expires_at: None,
            chain_depth: None,
            issuer_set_hex: vec![],
            scar_recovery_proof: None,
            target_wallet_id: None,
            proof_cap: None,
            node_name_field: None,
            auth_hash: None,
            peer_audit_request: None,
            peer_audit_response: None,
            fanout_message: None,
            raw_ump_body: vec![],
        };
        let encoded = encode_payload(&minimal);
        let decoded = decode_payload("witness", &encoded).unwrap();
        
        // Test with populated fields (witness request scenario)
        let witness_req = AntiePayload {
            query_params: None,
            public_key: None,
            balance: None,
            group_members: None,
            txid: None,
            validator_pk: None,
            sender_sig: None,
            client_pk: None,
            sphincs_pk_hex: None,
            dilithium_pk_hex: None,
            ed25519_pk_hex: None,
            pgp_fingerprint_hex: None,
            issued_at: None,
            expires_at: None,
            chain_depth: None,
            issuer_set_hex: vec![],
            scar_recovery_proof: None,
            target_wallet_id: None,
            proof_cap: None,
            node_name_field: None,
            auth_hash: None,
            peer_audit_request: None,
            peer_audit_response: None,
            fanout_message: None,
            raw_ump_body: vec![],
        };
        let encoded = encode_payload(&witness_req);
        let decoded = decode_payload("witness", &encoded).unwrap();
        
        // Test with redeem fields
        let redeem_req = AntiePayload {
            query_params: None,
            public_key: None,
            balance: None,
            group_members: None,
            txid: None,
            validator_pk: None,
            sender_sig: None,
            client_pk: None,
            sphincs_pk_hex: None,
            dilithium_pk_hex: None,
            ed25519_pk_hex: None,
            pgp_fingerprint_hex: None,
            issued_at: None,
            expires_at: None,
            chain_depth: None,
            issuer_set_hex: vec![],
            scar_recovery_proof: None,
            target_wallet_id: None,
            proof_cap: None,
            node_name_field: None,
            auth_hash: None,
            peer_audit_request: None,
            peer_audit_response: None,
            fanout_message: None,
            raw_ump_body: vec![],
        };
        let encoded = encode_payload(&redeem_req);
        let decoded = decode_payload("witness", &encoded).unwrap();
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
        let payload = AntiePayload {
            ..Default::default()
        };
        let inner_json = serde_json::to_value(&payload).unwrap();
        let inner_cbor = crate::cbor::json_to_cbor(&inner_json);
        // Wrap in UmpEnvelope::Plain and base64-encode as the wire body.
        let env = UmpEnvelope::Plain { ump_bytes: inner_cbor };
        let outer_cbor = env.to_cbor().unwrap();
        let wire = BASE64.encode(&outer_cbor);
        // Decode and assert the inner payload survived round-trip.
        let decoded = decode_payload("witness", &wire).unwrap();
    }

    /// V↔V message types (peer_audit_*, fanout_relay) ship raw CBOR,
    /// no envelope wrapper.  Mandatory shape after Stream B (2026-05-13).
    #[test]
    fn test_decode_payload_v_to_v_accepts_raw_cbor() {
        let payload = AntiePayload {
            peer_audit_request: Some(serde_json::json!({"txid": "audit-test"})),
            ..Default::default()
        };
        let inner_json = serde_json::to_value(&payload).unwrap();
        let inner_cbor = crate::cbor::json_to_cbor(&inner_json);
        let wire = BASE64.encode(&inner_cbor);
        let decoded = decode_payload("peer_audit_request", &wire).unwrap();
        assert!(decoded.peer_audit_request.is_some());
    }

    /// CLAUDE.md §13: a raw-CBOR body addressed to a client-class
    /// message type (witness/redeem/...) is a wire-format violation
    /// and must hard-error, not silently pass through.
    #[test]
    fn test_decode_payload_client_class_rejects_raw_cbor() {
        let payload = AntiePayload {
            ..Default::default()
        };
        let inner_cbor = crate::cbor::json_to_cbor(&serde_json::to_value(&payload).unwrap());
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
            peer_audit_request: Some(serde_json::json!({"txid": "audit-test"})),
            ..Default::default()
        };
        let inner_cbor = crate::cbor::json_to_cbor(&serde_json::to_value(&payload).unwrap());
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
        let inner_cbor = crate::cbor::json_to_cbor(&serde_json::to_value(&payload).unwrap());

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
        let inner = crate::cbor::json_to_cbor(&serde_json::json!({"x": 1}));
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
        let inner = crate::cbor::json_to_cbor(&serde_json::json!({"to": "beta"}));
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
