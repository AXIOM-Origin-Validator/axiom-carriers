//! YPX-024 Care-of addressing (c/o) — the protocol's delivery extension point.
//!
//! `<inner-email>@<pickup-mailbox>/<fingerprint>` — identity FIRST, pickup
//! second, `/hex` tail (YPX-019 order). Every ANTIE UNDERSTANDS the form:
//! parse, then ALWAYS verify the inner email against the fingerprint BEFORE
//! any delivery decision (defence in depth — closes the previously-unverified
//! plain `receiver_address` override too). Whether this ANTIE SUPPORTS the
//! pickup behaviour is the operator's `[pickup]` declaration (default OFF):
//! unsupported ⇒ deliver to the VERIFIED inner by the default carrier;
//! supported ⇒ atomic deposit into `<dir>/<outer-domain>/new/` and ANTIE's
//! obligation ENDS — from that directory onward it is another carrier's
//! (MUMMY's) problem, by design.

use std::path::{Path, PathBuf};

/// Parsed care-of form. `pickup` may be a full mailbox (`user@fastlane.com`)
/// or a bare host (`node.example.com` — YPX-019 §5.2's FATMAMA wrap, now
/// just one instance of the general mechanism).
#[derive(Debug, PartialEq)]
pub struct CareOf {
    pub inner: String,
    pub pickup: String,
    pub fingerprint: String,
}

/// Parse `addr` (WITH its `/fingerprint` tail) as care-of. `None` when the
/// address is not care-of (a plain `email/hex` wallet id, or no tail at all).
///
/// Rule (YPX-024 §2, deterministic because a legal email has exactly one
/// `@`): strip the `/hex` tail, then the INNER is everything up to the
/// SECOND `@`; the remainder is the pickup mailbox.
pub fn parse_care_of(addr: &str) -> Option<CareOf> {
    let slash = addr.rfind('/')?;
    let (addressed, fp) = (&addr[..slash], &addr[slash + 1..]);
    let first_at = addressed.find('@')?;
    let second_at = addressed[first_at + 1..].find('@')? + first_at + 1;
    if fp.is_empty() || second_at + 1 >= addressed.len() {
        return None;
    }
    Some(CareOf {
        inner: addressed[..second_at].to_string(),
        pickup: addressed[second_at + 1..].to_string(),
        fingerprint: fp.to_string(),
    })
}

/// The pickup point's DOMAIN — the deposit directory key. The existing
/// `rfind('@')` routing convention: a full mailbox keys by its domain, a
/// bare host keys by itself.
pub fn pickup_domain(pickup: &str) -> String {
    match pickup.rfind('@') {
        Some(i) => pickup[i + 1..].to_ascii_lowercase(),
        None => pickup.to_ascii_lowercase(),
    }
}

/// A deposit directory key must be a plain lowercase host label — anything
/// else (traversal, separators, empties) is a malformed pickup and the
/// delivery falls back to the verified inner email (the receiver still gets
/// ordinary mail; support is never allowed to LOSE a delivery).
fn domain_is_depositable(domain: &str) -> bool {
    !domain.is_empty()
        && !domain.contains("..")
        && domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'
            || c == '[' || c == ']' || c == ':')
}

/// Where a receiver-bound artifact goes. Decided ONCE, before any carrier.
#[derive(Debug, PartialEq)]
pub enum DeliveryPlan {
    /// Deliver to this VERIFIED plain email by the default carrier.
    Email(String),
    /// Supported care-of: deposit into `<base>/<domain>/new/` and stop.
    /// `inner` rides along for PGP lookup and logging.
    Deposit { domain: String, inner: String },
    /// Fingerprint verification FAILED — the artifact is delivered NOWHERE
    /// (YPX-024 §3.1; the caller must bump the reject counter and log).
    Refuse { reason: String },
}

/// The single receiver-delivery decision (YPX-024 §3). `receiver_address`
/// takes priority; `receiver_wallet_id` is the fallback (already validated
/// by Core Step 8). `pickup_supported` = the operator's `[pickup]` presence.
pub fn plan_receiver_delivery(
    receiver_address: Option<&str>,
    receiver_wallet_id: &str,
    pickup_supported: bool,
) -> DeliveryPlan {
    let addr = match receiver_address {
        // An override without the `/hex` tail cannot be verified — same
        // fallback the pre-YPX-024 extraction used.
        Some(a) if a.contains('/') => a,
        _ => {
            return match receiver_wallet_id.rfind('/') {
                Some(pos) => DeliveryPlan::Email(receiver_wallet_id[..pos].to_string()),
                None => DeliveryPlan::Refuse {
                    reason: format!(
                        "no deliverable receiver: address={receiver_address:?}, \
                         wallet_id {receiver_wallet_id:?} has no '/'"
                    ),
                },
            };
        }
    };

    if let Some(co) = parse_care_of(addr) {
        // §3.1 rule 2: ALWAYS verify the inner email against the
        // fingerprint before any delivery decision.
        let inner_wallet_id = format!("{}/{}", co.inner, co.fingerprint);
        if axiom_core_logic::wallet_id::validate_wallet_id(&inner_wallet_id).is_err() {
            return DeliveryPlan::Refuse {
                reason: format!(
                    "care-of fingerprint mismatch: inner {:?} does not \
                     checksum to {:?} — not delivered anywhere",
                    co.inner, co.fingerprint
                ),
            };
        }
        if pickup_supported {
            let domain = pickup_domain(&co.pickup);
            if domain_is_depositable(&domain) {
                return DeliveryPlan::Deposit { domain, inner: co.inner };
            }
            // Malformed pickup: fall through to the verified inner —
            // never lose a delivery to a bad wrapper.
        }
        return DeliveryPlan::Email(co.inner);
    }

    // Plain `email/hex` override — verify it too (YPX-024 §3.1 note: this
    // check is NEW at the delivery point; previously the override was
    // delivered unverified unless the receiver was `-XX`).
    if axiom_core_logic::wallet_id::validate_wallet_id(addr).is_err() {
        return DeliveryPlan::Refuse {
            reason: format!(
                "receiver_address {addr:?} fails wallet-id checksum — \
                 not delivered anywhere"
            ),
        };
    }
    match addr.rfind('/') {
        Some(pos) => DeliveryPlan::Email(addr[..pos].to_string()),
        None => unreachable!("guarded by contains('/') above"),
    }
}

/// Atomic deposit (Maildir convention, tmp → new) of a receiver-bound
/// artifact into `<base>/<domain>/new/<filename>`. Returns the final path.
pub fn deposit_atomic(
    base: &Path,
    domain: &str,
    filename: &str,
    bytes: &[u8],
) -> std::io::Result<PathBuf> {
    let dir = base.join(domain);
    let tmp_dir = dir.join("tmp");
    let new_dir = dir.join("new");
    std::fs::create_dir_all(&tmp_dir)?;
    std::fs::create_dir_all(&new_dir)?;
    let tmp = tmp_dir.join(filename);
    let dst = new_dir.join(filename);
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &dst)?;
    Ok(dst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_core_logic::wallet_id::generate_wallet_id;

    fn real_wallet_id(email: &str) -> String {
        // Yields "email/checksum+pk_bind+salt" with a valid checksum (the
        // checksum does not fold pk, so a dummy pk suffices for parse tests).
        generate_wallet_id(email, "00", &[7u8; 32]).unwrap()
    }

    #[test]
    fn parse_plain_is_not_care_of() {
        assert_eq!(parse_care_of("wallet@example.com/a3f7b232"), None);
        assert_eq!(parse_care_of("no-at-sign/a3f7b232"), None);
        assert_eq!(parse_care_of("wallet@example.com@user@fastlane.com"), None); // no tail
    }

    #[test]
    fn parse_care_of_splits_at_second_at() {
        let co = parse_care_of("wallet@example.com@user@fastlane.com/a3f7b232").unwrap();
        assert_eq!(co.inner, "wallet@example.com");
        assert_eq!(co.pickup, "user@fastlane.com");
        assert_eq!(co.fingerprint, "a3f7b232");
    }

    #[test]
    fn parse_fatmama_host_wrap() {
        // YPX-019's bare-host wrap is one instance of the general form.
        let co = parse_care_of("alice@axiom.internal@node.example.com/deadbeef").unwrap();
        assert_eq!(co.inner, "alice@axiom.internal");
        assert_eq!(co.pickup, "node.example.com");
        assert_eq!(pickup_domain(&co.pickup), "node.example.com");
    }

    #[test]
    fn pickup_domain_of_mailbox() {
        assert_eq!(pickup_domain("user@FastLane.com"), "fastlane.com");
    }

    #[test]
    fn plan_verified_care_of_unsupported_delivers_inner() {
        let wid = real_wallet_id("wallet@example.com");
        let (inner, fp) = wid.split_once('/').unwrap();
        let addr = format!("{inner}@user@fastlane.com/{fp}");
        assert_eq!(
            plan_receiver_delivery(Some(&addr), "x@y/z", false),
            DeliveryPlan::Email(inner.to_string()),
        );
    }

    #[test]
    fn plan_verified_care_of_supported_deposits() {
        let wid = real_wallet_id("wallet@example.com");
        let (inner, fp) = wid.split_once('/').unwrap();
        let addr = format!("{inner}@user@fastlane.com/{fp}");
        assert_eq!(
            plan_receiver_delivery(Some(&addr), "x@y/z", true),
            DeliveryPlan::Deposit {
                domain: "fastlane.com".into(),
                inner: inner.to_string()
            },
        );
    }

    #[test]
    fn plan_mutated_inner_refused_everywhere() {
        // MUTATION TEST (design ruling: "verify the email against the hex first as
        // always... very important defence in depth"): an inner email
        // altered in transit must fail the fingerprint and go NOWHERE —
        // neither deposited nor emailed, supported or not.
        let wid = real_wallet_id("wallet@example.com");
        let (_, fp) = wid.split_once('/').unwrap();
        let addr = format!("EVIL@example.com@user@fastlane.com/{fp}");
        for supported in [false, true] {
            match plan_receiver_delivery(Some(&addr), "x@y/z", supported) {
                DeliveryPlan::Refuse { .. } => {}
                other => panic!("mutated inner must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn plan_plain_override_now_verified() {
        // The pre-existing gap: a plain receiver_address was delivered
        // unverified. Now a bad checksum refuses delivery...
        match plan_receiver_delivery(Some("evil@example.com/00000000"), "x@y/z", false) {
            DeliveryPlan::Refuse { .. } => {}
            other => panic!("bad plain override must be refused, got {other:?}"),
        }
        // ...and a valid one still delivers.
        let wid = real_wallet_id("wallet@example.com");
        let (inner, _) = wid.split_once('/').unwrap();
        assert_eq!(
            plan_receiver_delivery(Some(&wid), "x@y/z", false),
            DeliveryPlan::Email(inner.to_string()),
        );
    }

    #[test]
    fn plan_falls_back_to_wallet_id() {
        assert_eq!(
            plan_receiver_delivery(None, "wallet@example.com/a3f7b232", true),
            DeliveryPlan::Email("wallet@example.com".to_string()),
        );
    }

    #[test]
    fn hostile_pickup_domain_falls_back_to_inner_email() {
        let wid = real_wallet_id("wallet@example.com");
        let (inner, fp) = wid.split_once('/').unwrap();
        // ".." would traverse out of the pickup base — must NOT deposit,
        // must still deliver by email.
        let addr = format!("{inner}@user@../{fp}");
        // NB: rfind('/') strips at the LAST slash, so "../" merges into the
        // fingerprint here — construct via a domain with dots instead:
        let addr2 = format!("{inner}@user@a..b/{fp}");
        let _ = addr;
        assert_eq!(
            plan_receiver_delivery(Some(&addr2), "x@y/z", true),
            DeliveryPlan::Email(inner.to_string()),
        );
    }

    #[test]
    fn deposit_atomic_lands_in_new() {
        let base = std::env::temp_dir().join(format!("careof-test-{}", std::process::id()));
        let p = deposit_atomic(&base, "fastlane.com", "abc.cheque", b"bytes").unwrap();
        assert!(p.ends_with("fastlane.com/new/abc.cheque"));
        assert_eq!(std::fs::read(&p).unwrap(), b"bytes");
        let _ = std::fs::remove_dir_all(&base);
    }
}
