//! `From<&AntieError> for ErrorResponse` — ANTIE-level errors mapped
//! to the structured wire format defined in
//! `docs/AXIOM_YellowPaper_Errors.md`.
//!
//! # Phase 2c.3
//!
//! ANTIE's external wire surface is small — the health HTTP endpoint
//! and the Lambda IPC carrier — but its internal error type
//! (`AntieError`) flows through many modules (maildir watchers, email
//! parsers, SMTP senders, Lambda clients, Core IPC). This conversion
//! trait lets any of those sites emit a structured error when they
//! need to surface one to a remote consumer.
//!
//! The conversion is lossy by design: ANTIE's errors are mostly
//! operational (maildir, IO, config) and don't carry the discriminant
//! precision that Core's `ValidationError` does. Category assignment
//! reflects this — most variants map to `Operational` or `Internal`,
//! not `ProtocolReject`.

use axiom_errors::{error_code, ErrorCategory, ErrorCode, ErrorResponse};

use crate::error::AntieError;

impl From<&AntieError> for ErrorResponse {
    fn from(err: &AntieError) -> Self {
        let (code, category, message) = match err {
            AntieError::MaildirError(s) => (
                error_code::E_ANTIE_MAILDIR_ERROR,
                ErrorCategory::Operational,
                format!("Maildir error: {}", s),
            ),
            AntieError::EmailParseError(s) => (
                error_code::E_ANTIE_EMAIL_PARSE_ERROR,
                ErrorCategory::ClientBug,
                format!("Email parse error: {}", s),
            ),
            AntieError::InvalidPayload(s) => (
                error_code::E_ANTIE_INVALID_PAYLOAD,
                ErrorCategory::ClientBug,
                format!("Invalid payload: {}", s),
            ),
            AntieError::CoreError(s) => (
                error_code::E_ANTIE_CORE_ERROR,
                ErrorCategory::Internal,
                format!("Core IPC error: {}", s),
            ),
            AntieError::ValidationFailed(s) => (
                error_code::E_ANTIE_VALIDATION_FAILED,
                ErrorCategory::ProtocolReject,
                format!("Validation failed: {}", s),
            ),
            AntieError::LambdaError(s) => (
                error_code::E_ANTIE_LAMBDA_ERROR,
                ErrorCategory::Operational,
                format!("Lambda communication error: {}", s),
            ),
            AntieError::IoError(e) => (
                error_code::E_ANTIE_IO_ERROR,
                ErrorCategory::Internal,
                format!("IO error: {}", e),
            ),
            AntieError::ConfigError(s) => (
                error_code::E_ANTIE_CONFIG_ERROR,
                ErrorCategory::Internal,
                format!("Config error: {}", s),
            ),
            AntieError::SerializationError(s) => (
                error_code::E_ANTIE_SERIALIZATION,
                ErrorCategory::ClientBug,
                format!("Serialization error: {}", s),
            ),
            AntieError::CoreTTLExpired(s) => (
                error_code::E_ANTIE_CORE_TTL_EXPIRED,
                ErrorCategory::Operational,
                format!("Core TTL expired: {}", s),
            ),
            AntieError::RateLimited(s) => (
                error_code::E_ANTIE_RATE_LIMITED,
                ErrorCategory::Operational,
                s.clone(),
            ),
            AntieError::WalletBanned(s) => (
                error_code::E_ANTIE_WALLET_BANNED,
                ErrorCategory::ProtocolReject,
                s.clone(),
            ),
        };
        ErrorResponse::new(ErrorCode::from_static(code), category, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_failed_maps_to_protocol_reject() {
        let err = AntieError::ValidationFailed("bad sig".into());
        let resp: ErrorResponse = (&err).into();
        assert_eq!(resp.code.as_str(), "E_ANTIE_VALIDATION_FAILED");
        assert_eq!(resp.category, ErrorCategory::ProtocolReject);
    }

    #[test]
    fn rate_limited_is_operational() {
        let err = AntieError::RateLimited("too many requests".into());
        let resp: ErrorResponse = (&err).into();
        assert_eq!(resp.code.as_str(), "E_ANTIE_RATE_LIMITED");
        assert_eq!(resp.category, ErrorCategory::Operational);
    }

    #[test]
    fn core_ttl_expired_preserves_message() {
        let err = AntieError::CoreTTLExpired("tick 12345".into());
        let resp: ErrorResponse = (&err).into();
        assert!(resp.message.contains("12345"));
    }

    #[test]
    fn io_error_is_internal() {
        let err = AntieError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file missing",
        ));
        let resp: ErrorResponse = (&err).into();
        assert_eq!(resp.category, ErrorCategory::Internal);
    }

    #[test]
    fn wallet_banned_maps_to_protocol_reject() {
        let err = AntieError::WalletBanned("E_WALLET_BANNED: wallet abc123 is banned (YP §32)".into());
        let resp: ErrorResponse = (&err).into();
        assert_eq!(resp.code.as_str(), "E_ANTIE_WALLET_BANNED");
        assert_eq!(resp.category, ErrorCategory::ProtocolReject);
        assert!(resp.message.contains("abc123"));
    }
}
