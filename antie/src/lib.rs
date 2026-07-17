//! AXIOM ANTIE Gateway
//!
//! Email-based transaction gateway.
//!
//! # Architecture
//!
//! ```text
//! Mail Carrier  →  ANTIE  →  Core (CL2)  →  Lambda  →  Core (CL3)  →  Mail Carrier
//! ```
//!
//! # Supported Carriers
//!
//! - **Maildir** (default, production-ready) - Filesystem-based, works with sendmail/postfix
//! - **POP3** (production-ready) - Pull emails from POP3 server
//! - **IMAP** (production-ready) - Pull emails from IMAP server
//! - **SMTP** (production-ready) - Send emails via SMTP (outbound only)
//!
//! ANTIE is the LISTENER. It:
//! 1. Watches for new emails (via carrier)
//! 2. Parses email to extract transaction payload
//! 3. Calls Core for decryption (future)
//! 4. Calls Core for CL2 validation (BEFORE Lambda) ← Gateway's job!
//! 5. Passes pre-validated transaction to Lambda
//! 6. Calls Core for CL3 witness (Lambda does this)
//! 7. Calls Core for encryption (future)
//! 8. Sends response email (via carrier)

pub mod config;
pub mod carrier;
pub mod malloc_trim;
pub mod maildir;
pub mod email;
pub mod cbor;
pub mod core_ipc;
pub mod lambda_client;
pub mod gateway;
pub mod error;
pub mod skip_list;
pub mod uncle_sink;
/// `From<&AntieError> for axiom_errors::ErrorResponse` — Phase 2c.3.
pub mod error_response;
pub mod rate_limit;
pub mod stats;
pub mod health;
pub mod pgp;
/// Forward-direction UMP envelope decryption (X25519 + ChaCha20Poly1305).
/// See `docs/AXIOM_DESIGN_PublicMailCarriers.md` §3.
pub mod decrypt;
