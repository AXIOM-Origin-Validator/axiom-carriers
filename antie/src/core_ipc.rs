//! Core IPC — ANTIE's interface to Core via AVM interpreter
//!
//! ANTIE executes CL2 validation through the AVM interpreter directly.
//! No subprocess, no IPC — same execution path as Lambda.
//!
//! ```text
//! ANTIE (CL2) ── AvmInterpreter ── axiom-core.elf (RISC-V)
//! ```

use crate::error::AntieError;
use axiom_dmap_vm::AvmInterpreter;
use axiom_core_logic::types::{Transaction, Receipt, WitnessSig, VBCProofBundle, FactChain};
use axiom_core_logic::{PublicInputs, CoreLogicMode, ValidationResult};
use tracing::{info, warn};

/// CL2 validation — ANTIE's Core call.
///
/// Prepares PublicInputs with mode=CL2, executes via AVM interpreter.
#[allow(clippy::too_many_arguments)]
pub fn validate_transaction_cl2(
    avm: &AvmInterpreter,
    transaction: &Transaction,
    _declared_balance: u64,
    prev_receipts: &[Receipt],
    overlapped_signatures: Vec<WitnessSig>,
    vbc_bundle: Option<VBCProofBundle>,
    my_validator_pk: Option<Vec<u8>>,
    sender_fact_chain: Option<FactChain>,
) -> Result<ValidationOutput, AntieError> {
    // CLAUDE.md §8 — ANTIE never synthesizes what Lambda should verify.
    //
    // Pre-fix this call ran in `CoreLogicMode::CL2` with a fabricated
    // `WalletState` (`state_id = tx.consumed_state_id`,
    // `wallet_seq = tx.wallet_seq - 1`, `balance = declared_balance`).
    // Even though every field was tautological, the code was a *claim* —
    // and the tautology fell apart on YPX-018 heal-forward, where setting
    // `stored.state_id = tx.consumed_state_id` made `verify_state_id_valid`
    // pass at ANTIE but skipped no real check, while every reader of this
    // function still had to think "is this stored state real?". The
    // architectural correction is to stop claiming altogether.
    //
    // We now use `CoreLogicMode::CL2_PREFILTER` with `current_state = None`.
    // Core's prefilter mode runs every state-INDEPENDENT check that ANTIE
    // can honestly perform from the request alone (signatures, dust, Ark
    // rules, oracle rules, genesis lockup, fact-chain integrity, burn
    // target, frozen wallets, version, reference length) and skips every
    // state-DEPENDENT check (balance, wallet_seq chain, owner_proof
    // against stored auth_hash, produced state hashes). Lambda's own CL2
    // pass owns the authoritative checks against real stored state where
    // they belong.
    //
    // Reference: YPX-018 §2.1.2, CLAUDE.md §8 ("Layer roles are strict"),
    // `feedback_layer_roles.md` in project auto-memory.
    let inputs = PublicInputs {
        recall_attestation: None,
        mode: CoreLogicMode::CL2_PREFILTER,
        // YPX-021: the prefilter validates the TX shape only; no receipt is
        // built here, so no OODS reading is threaded (Lambda's CL2/CL3 pass
        // carries the request's attestation).
        oods_attestation: None,
        // ANTIE pre-filter disables the core_id gate (both sides zero =
        // skip). Authoritative check happens in Lambda's CL2 pass where
        // the validator's real ELF hash is plumbed via avm_config.
        local_core_id: [0u8; 32],
        withdrawal_inputs: None,
        receiver_current_hibernation: None,
        transaction: transaction.clone(),
        prev_receipts: prev_receipts.to_vec(),
        current_state: None,
        vbc_bundle,
        my_validator_pk,
        overlapped_signatures,
        cheque_bundle: None,
        receiver_pk: None,
        receiver_current_balance: None,
        receiver_wallet_seq: None,
        receiver_new_balance: None,
        receiver_new_state_id: None,
        group_member_index: None,
        sender_fact_chain,
        max_fact_links: None,
            receiver_fact_chain: None,
        my_dilithium_sk: None,
        my_dilithium_pk: None,
        my_validator_id: None,
        fact_witness_sigs: vec![],
        issuer_sphincs_sk: None,
        cl1_execution_proof: None,
        zkp_nonce: None,
            audit_confirmation: None,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            scar_heal_tx_id: None,
            scar_heal_nabla_id: None,
            scar_heal_root_hash: None,
            candidate_balance: None,
            nabla_stake_proof: None,
            frozen_wallets: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None, txid_attestation: None,
        cheque_claim_proof: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
    
    };

    // Execute via AVM interpreter
    let outputs = avm.execute(inputs)
        .map_err(|e| AntieError::CoreError(format!("AVM: {}", e)))?;

    match outputs.result {
        ValidationResult::Accept => {
            let overlap_status = match outputs.is_overlapped {
                Some(true) => "OVERLAPPED",
                Some(false) => "NEW",
                None => "UNKNOWN",
            };
            info!("CL2: ACCEPTED [S-ABR: {}]", overlap_status);
            Ok(ValidationOutput {
                accepted: true,
                new_state_id: outputs.produced_state_id,
                new_wallet_seq: outputs.new_wallet_seq,
                commitment_hash: outputs.commitment_hash,
                rejection_reason: None,
            })
        }
        ValidationResult::Fatal => {
            let reason = outputs.rejection_reason
                .map(|r| r.to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            eprintln!("╔══════════════════════════════════════════════════════════════╗");
            eprintln!("║  FATAL from Core — own VBC chain verification failed.        ║");
            eprintln!("║  Reason: {:50} ║", reason);
            eprintln!("║  Validator MUST shut down. Fix config and rebuild Core.       ║");
            eprintln!("╚══════════════════════════════════════════════════════════════╝");
            std::process::exit(78);
        }
        ValidationResult::Reject => {
            let reason = outputs.rejection_reason
                .map(|r| r.to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            let receipt_info: Vec<String> = prev_receipts.iter().enumerate()
                .map(|(i, r)| format!("r[{}]={} sigs", i, r.witness_sigs.len()))
                .collect();
            warn!("CL2: Transaction REJECTED by Core: {} (wallet_seq={}, receipts: [{}])",
                  reason, transaction.wallet_seq, receipt_info.join(", "));
            Ok(ValidationOutput {
                accepted: false,
                new_state_id: None,
                new_wallet_seq: None,
                commitment_hash: None,
                rejection_reason: Some(reason),
            })
        }
    }
}

// `build_wallet_state` removed: ANTIE does not synthesize a WalletState.
// Any stored-state check lives in Lambda, which has the real data.
// `validate_transaction_cl2` uses `CoreLogicMode::CL2_PREFILTER` with
// `current_state = None`. See CLAUDE.md §8.

/// Output from CL2 validation
#[derive(Debug, Clone)]
pub struct ValidationOutput {
    pub accepted: bool,
    pub new_state_id: Option<[u8; 32]>,
    pub new_wallet_seq: Option<u64>,
    pub commitment_hash: Option<[u8; 32]>,
    pub rejection_reason: Option<String>,
}

/// CL10 Fan-Out verification — verify a Fan-Out message before relaying.
///
/// Checks: TTL, signature, content_type, timestamp, originator VBC.
/// Returns: accepted + new TTL (decremented by Core).
pub fn verify_fanout_cl10(
    avm: &AvmInterpreter,
    fanout_message: &axiom_core_logic::types::FanOutMessage,
    vbc_bundle: Option<VBCProofBundle>,
) -> Result<FanOutVerifyResult, AntieError> {
    let inputs = PublicInputs {
        recall_attestation: None,
        mode: CoreLogicMode::CL10,
        oods_attestation: None,
        local_core_id: [0u8; 32],
        withdrawal_inputs: None,
        receiver_current_hibernation: None,
        // CL10 doesn't use the transaction; pass an explicit default rather
        // than parsing a JSON string literal at runtime (no JSON on the
        // protocol path — see AXIOM_GUIDE_Contributor.md Q5).
        transaction: axiom_core_logic::types::Transaction::default(),
        prev_receipts: vec![],
        current_state: None,
        vbc_bundle,
        my_validator_pk: None,
        overlapped_signatures: vec![],
        cheque_bundle: None,
        receiver_pk: None,
        receiver_current_balance: None,
        receiver_wallet_seq: None,
        receiver_new_balance: None,
        receiver_new_state_id: None,
        group_member_index: None,
        sender_fact_chain: None,
        max_fact_links: None,
        receiver_fact_chain: None,
        my_dilithium_sk: None,
        my_dilithium_pk: None,
        my_validator_id: None,
        fact_witness_sigs: vec![],
        issuer_sphincs_sk: None,
        cl1_execution_proof: None,
        zkp_nonce: None,
        audit_confirmation: None,
        nonce_response: None,
        audit_response: None,
        wallet_secret: None,
        fanout_message: Some(fanout_message.clone()),
        scar_heal_tx_id: None,
        scar_heal_nabla_id: None,
        scar_heal_root_hash: None,
        candidate_balance: None,
        nabla_stake_proof: None,
        frozen_wallets: None,
        console_current_cert: None,
        console_new_cert: None,
        console_selector_picks: None,
        console_nominations: None, txid_attestation: None,
        cheque_claim_proof: None,
        clara_attestation: None,
        phase_out_payload: None,
        phase_out_era_end_ticks: vec![],
        phase_out_blocked_era_ids: vec![],
        current_tick: 0,
    
    };

    let outputs = avm.execute(inputs)
        .map_err(|e| AntieError::CoreError(format!("CL10 AVM: {}", e)))?;

    match outputs.result {
        ValidationResult::Accept => {
            let new_ttl = outputs.fanout_new_ttl.unwrap_or(0);
            info!("CL10: Fan-Out ACCEPTED (content_type=0x{:04x}, ttl {} → {})",
                  fanout_message.content_type, fanout_message.ttl_current, new_ttl);
            Ok(FanOutVerifyResult {
                accepted: true,
                new_ttl,
                rejection_reason: None,
            })
        }
        ValidationResult::Reject => {
            let reason = outputs.rejection_reason
                .map(|r| format!("{}", r))
                .unwrap_or_else(|| "Unknown".into());
            warn!("CL10: Fan-Out REJECTED: {}", reason);
            Ok(FanOutVerifyResult {
                accepted: false,
                new_ttl: 0,
                rejection_reason: Some(reason),
            })
        }
        ValidationResult::Fatal => {
            warn!("CL10: Fan-Out FATAL");
            Ok(FanOutVerifyResult {
                accepted: false,
                new_ttl: 0,
                rejection_reason: Some("Fatal error in CL10".into()),
            })
        }
    }
}

/// Output from CL10 Fan-Out verification
#[derive(Debug, Clone)]
pub struct FanOutVerifyResult {
    pub accepted: bool,
    pub new_ttl: u8,
    pub rejection_reason: Option<String>,
}
