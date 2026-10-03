# antie/ — AI Assistant Orientation

**ANTIE** (Advanced Normalised Transmission Intermedia Extension) is AXIOM's
survival-grade email-transport gateway: a **carrier + executor**, nothing
more. It moves UMP bytes between the outside world (email / FATMAMA / HTTP)
and Lambda, and summons Core (embedded DMAP-VM) or Lambda (IPC) to do work.

**Naming culture** (`CLAUDE.md` "Naming Conventions"): the Transport layer
uses Extended Family names — ANTIE, UNCLE, COUSIN, FATMAMA. If a process
carries data from A to B, it's a family member. This is a style signal, not
decoration — a pop-culture name in a crypto verification step would be an
architectural violation; ANTIE has none, because ANTIE does no crypto
verification of its own (Core does).

## THE binding rule — ANTIE never synthesizes what Lambda should verify

Any code here that reads transaction fields to build fake state (a
`WalletState`, a forged `prev_seq`, a synthetic genesis) is a bug. Pass
honestly to Core and Lambda; let each layer do its job.

- `antie/src/core_ipc.rs:167-170` carries the do-not-reintroduce marker where
  `build_wallet_state` used to live.
- Both Core pre-execution sites run `current_state: None` — `core_ipc.rs:71`
  (`validate_transaction_cl2`, `CoreLogicMode::CL2_PREFILTER`) and the CL10
  Fan-Out path further down the same file. State checks are no-ops at these
  sites; Lambda's own CL2/CL3 pass supplies the real stored state.
- **Regression watch:** the pre-v2.11.15-beta4 `build_wallet_state` synthesized
  a `WalletState` from `declared_balance + last_receipt.produced_state_id`. It
  accidentally worked for normal TXs but broke heal-forward catastrophically —
  TX_HEAL's `consumed_state_id` is a partial-commit state only Lambda's
  storage has; the fake `WalletState` caused Core to reject at the ANTIE
  pre-filter before Lambda got a chance. Do not reintroduce it.
- The one payload-adjacent thing ANTIE legitimately reads is
  **performance/backpressure signals** (YPX-015 §2), never transaction
  fields: the Lambda `/stats` poller + busy gate at `gateway.rs:838-849` /
  `878-931` (`process_carrier_messages`'s `should_reject_busy` gate,
  `poll_lambda_stats`), per-wallet cooldown at `gateway.rs:72-86` +
  `1231-1242`, config at `config.rs:319`.

## Inbound funnel — everything stages to `maildir/inbox/new/`

Owning doc: `docs/AXIOM_DESIGN_AntieInboxFunnel.md` (status: **LANDED**, not
merely a direction). Every inbound transport — FATMAMA-SMTP, TOT, POP3-fetch,
IMAP-fetch — writes into `inbox/new/`; the **Maildir carrier is the sole
reader** that ever dispatches to Lambda (`process_carrier_messages`, now
called only from `run_maildir_carrier`). `CarriersConfig::validate()` enforces
"pop3/imap ⇒ maildir required" fail-closed (`carrier.rs:162-167`).
**Write-before-delete**: a successful `inbox.write_message` triggers
`mark_processed`; a failed write triggers `mark_failed` and leaves the
message on the server for retry (`gateway.rs:810-825`) — never delete from
server before the local write is confirmed. Exception the doc discloses: the
opt-in low-entropy spam-drop on pull carriers (`gateway.rs:795-810`) deletes
without staging — hygiene-only, Core still adjudicates everything actually
staged.

## Outbound truth — SplitCarrier is what's live, not RoutedCarrier

Owning doc: `docs/AXIOM_DESIGN_AntieOutboundSplit.md`. As of 2026-08-31 the
**whole fleet runs `SplitCarrier`** — ANTIE itself opens both SMTP legs
(local FATMAMA 2525 plain; external 465 implicit-TLS). `RoutedCarrier`
(write-a-file, agent-collects) was rolled back 2026-08-27 — its external-leg
collector was never built — and runs nowhere in production, though both live
in code and the selector (`gateway.rs:286-316`) still checks the route table
first. **`default_outbox` does not exist and must never be re-added** —
removed deliberately as worse-than-fallback (misrouted real-domain mail).
AUTH implies TLS: refused, never downgraded (`carrier.rs:922-926`). SMTP is
**hand-rolled** — one full EHLO/[AUTH LOGIN]/MAIL/RCPT/DATA session per send
over raw TCP or implicit TLS (`carrier.rs:832-1002`); no `lettre`, no
connection reuse, precisely because `lettre` once returned `Ok` while
silently dropping DATA.

## Delivery-layer order at both gateway delivery sites

Two layers sit on top of routing, in this order (`gateway.rs:1463`,
`gateway.rs:1623`):

1. **Care-of (YPX-024)** — `care_of::plan_receiver_delivery`
   (`antie/src/care_of.rs:84`) runs FIRST. A `Deposit` plan writes atomically
   to `pickup/<domain>/new/` and **never reaches the outbound sender** — do
   not assume every cheque goes through `SplitCarrier`/`RoutedCarrier`.
2. **Skip list** — owning doc `docs/AXIOM_DESIGN_AntieSkipList.md`.
   Cheque-scoped divert to sibling carriers (UNCLE/COUSIN); **OFF by
   default** (`skip_list_path`/`skipped_dir_path` both default `None`,
   `config.rs:663-664`); reload is **SIGHUP-only** — no fs-watch exists
   despite comments claiming otherwise (`skip_list.rs:207-226`). A successful
   care-of deposit pre-empts the skip-list check entirely (double-delivery
   avoidance); a failed `skipped/` write falls back to email (liveness over
   "don't email this receiver"). Only cheque delivery consults it — scar
   consent notifications do not.

## Peer-audit mail gets NO generic reply (2026-09-26)

`peer_audit_request` / `peer_audit_response` are validator↔validator and their handlers mail
their own answer (response / NotHeld). The dispatcher used to add a generic `witness_response`
(raw CBOR, no UmpEnvelope) on top, which the other validator's ANTIE dropped every time
(`ANTIE-DROP-PARSE`, 35 on trustmesh). `answers_out_of_band()` now suppresses it; the outcome is
logged locally. A new validator↔validator type that answers by its own mail belongs in that list.

## Overload protection must be READ (YPX-015 §2.1 AS BUILT, 2026-09-26)

The busy gate needs Lambda's `/stats`. The token comes from `[performance] lambda_admin_token` or, in
subprocess mode, the spawned Lambda's own `admin_token` (`AntieConfig::resolve_lambda_admin_token`). Every
failed read is counted (`lambda_stats_poll_failures` on `/status`) and WARNed — a refused read once looked
exactly like "no load data yet" and left backpressure silently off on a whole network. The PORT is this
validator's own Lambda too: `[performance] lambda_admin_port` or the spawned Lambda's `admin_port`
(`AntieConfig::resolve_lambda_admin_port`) — there is NO default (7780 was alpha's, and nine of ten co-hosted
validators read alpha's load with zero failures). Unknown ⇒ not armed, ERROR, `/status lambda_stats_port: 0`. Tier A gate
`fleet.backpressure_armed`, tier C `overload.busy_rejects` (`tests/backpressure_gate.py`).

## Typed-error rule at reply boundaries

`AntieError::LambdaRejected` carries Lambda's `ErrorResponse` through
**verbatim** (`error_response.rs:90`) — the comment there states the reason:
"re-coding it under an ANTIE error code would re-introduce the flattening
this variant exists to prevent." The stringification hazard is confined to
`Display` at `error.rs:68` (`write!(f, "Lambda error: {}", er.message)`) —
that's for logs/UI text, never for dispatch. Any new reply path must forward
the typed object, never the formatted string.

## Read normative docs and their preambles first

- `docs/AXIOM_DESIGN_ANTIE.md` — the umbrella protocol doc; its own preamble
  defers to the three sibling docs below for their specific contracts.
- `docs/AXIOM_DESIGN_AntieInboxFunnel.md`, `AntieOutboundSplit.md`,
  `AntieSkipList.md` — each is the SINGLE owning document for its invariant.
- Every preamble (top-of-file, before the first `---`) carries VERIFIED code
  citations, dated corrections against earlier drafts, and explicit
  "this claim is stale" flags. Read the preamble before the body; it is the
  fast, load-bearing part.

## Top traps

- **No TCP inbound carrier exists.** `carrier.rs:1060-1062` — TCP + WebSocket
  carriers were removed 2026-05-21; `[carriers.tcp]` is not a config section.
  Don't design around it or resurrect it without a real requirement.
- **An unreadable skip-list file silently EMPTIES the set** — read failure
  loads as empty and `reload()` swaps unconditionally (`skip_list.rs:94-99`,
  `114-117`); cheques then go to email until the next successful reload.
  Never treat a stale/corrupt skip-list read as "leave the old set in place."
- Config validation for the inbound funnel and outbound routing both
  fail-closed at load time, not deep in a spawned task — check
  `carrier.rs`/`config.rs` validation functions before assuming a runtime
  guard is missing.

## VERIFIED

- `core_ipc.rs`: `build_wallet_state` marker at 167-170; `current_state: None`
  at line 71 (`validate_transaction_cl2`) and in the CL10 path.
- `gateway.rs`: backpressure gate `process_carrier_messages`/
  `should_reject_busy` 838-931; write-before-delete 810-825; care-of call
  sites 1463/1623 (line numbers approximate to file state at time of survey).
- `error_response.rs:90` (`LambdaRejected` verbatim forward),
  `error.rs:68` (`Display` stringification site).
- `carrier.rs:162-167` (maildir-required validation), `:832-1002`
  (hand-rolled SMTP), `:922-926` (AUTH⟹TLS refused-not-downgraded),
  `:1060-1062` (TCP carrier removal comment).
- `skip_list.rs:94-99,114-117` (unreadable-file-empties-set),
  `:207-226` (SIGHUP-only reload); `config.rs:663-664` (both keys default
  `None`).
- `care_of.rs:84` (`plan_receiver_delivery`).
- Preambles of `AXIOM_DESIGN_ANTIE.md`, `AXIOM_DESIGN_AntieInboxFunnel.md`,
  `AXIOM_DESIGN_AntieOutboundSplit.md`, `AXIOM_DESIGN_AntieSkipList.md` read
  in full; content above cross-checked against their cited line numbers.
- `CLAUDE.md` §8 (Layer roles), the ANTIE `build_wallet_state` regression
  paragraph, and RULE 3 (ghost implementations) — used to frame "binding
  rule" and "top traps" sections.
