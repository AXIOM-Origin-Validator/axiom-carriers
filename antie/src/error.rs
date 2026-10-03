//! ANTIE Error Types

use std::fmt;

#[derive(Debug)]
pub enum AntieError {
    /// Maildir error
    MaildirError(String),
    
    /// Email parsing error
    EmailParseError(String),
    
    /// Invalid payload format
    InvalidPayload(String),
    
    /// Core IPC error
    CoreError(String),
    
    /// Core validation failed (CL2)
    ValidationFailed(String),
    
    /// Lambda communication error
    LambdaError(String),
    
    /// IO error
    IoError(std::io::Error),
    
    /// Config error
    ConfigError(String),
    
    /// Serialization error
    SerializationError(String),
    
    /// Core TTL expired (YP §23.13.11) — Gateway must spawn fresh Core
    CoreTTLExpired(String),

    /// Per-wallet witness rate limit (YPX-015 §2.3)
    RateLimited(String),

    /// Wallet banned by Nabla (YP §32-33) — pre-filter rejection
    WalletBanned(String),

    /// Lambda returned a TYPED verdict (`GatewayResponse::Error`). Carried
    /// verbatim so the gateway can forward the structured error stack to the
    /// client instead of flattening it to `INTERNAL_ERROR`.
    ///
    /// This distinction is load-bearing: a Lambda *rejection* (e.g.
    /// `E_INVALID_STATE_ID` refusing a double-spend, or a `RecoverableDrift`
    /// carrying `ClaraHealNextSend`) is a protocol verdict the client must
    /// dispatch on, NOT an ANTIE-internal fault. Stringifying it into
    /// `LambdaError` — as every parse_*_response did before 2026-07-27 —
    /// erased the code, the category, and the recovery hint, so clients (and
    /// the dsfork repro harness) saw correct protocol refusals as
    /// `INTERNAL_ERROR` infrastructure failures. ANTIE forwards; it does not
    /// reinterpret (layer rule: ANTIE never synthesizes what Lambda owns).
    LambdaRejected(axiom_errors::ErrorResponse),
}

impl fmt::Display for AntieError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaildirError(s) => write!(f, "Maildir error: {}", s),
            Self::EmailParseError(s) => write!(f, "Email parse error: {}", s),
            Self::InvalidPayload(s) => write!(f, "Invalid payload: {}", s),
            Self::CoreError(s) => write!(f, "Core error: {}", s),
            Self::ValidationFailed(s) => write!(f, "Validation failed: {}", s),
            Self::LambdaError(s) => write!(f, "Lambda error: {}", s),
            Self::LambdaRejected(er) => write!(f, "Lambda error: {}", er.message),
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::ConfigError(s) => write!(f, "Config error: {}", s),
            Self::SerializationError(s) => write!(f, "Serialization error: {}", s),
            Self::CoreTTLExpired(s) => write!(f, "Core TTL expired: {}", s),
            Self::RateLimited(s) => write!(f, "{}", s),
            Self::WalletBanned(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for AntieError {}

impl From<std::io::Error> for AntieError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}
