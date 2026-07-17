# axiom-carriers

AXIOM native carriers: ANTIE (email gateway), TOT (Tiny Outbound Tunnel), FATMAMA (dev SMTP tool).

Part of the AXIOM protocol family — specifications live in
[axiom-docs](https://github.com/AXIOM-Origin-Validator/axiom-docs), research in
[axiom-papers](https://github.com/AXIOM-Origin-Validator/axiom-papers), binaries in
[axiom-dist](https://github.com/AXIOM-Origin-Validator/axiom-dist).

## Contents

AXIOM carriers move UMP envelopes and decide nothing — they verify no
signatures and hold no protocol state. Delivery is the carrier's job;
verification is Core's. A validator advertises the carriers it accepts as
URIs in its hints (`email:…`, `tot:…`, `fatmama:…` — Yellow Paper §27.5.2),
and clients try them in the validator's order of preference.

The carrier family is named after relatives — each handling a different kind
of correspondence: ANTIE for the everyday mail; UNCLE (Universal Non-linear
Clearing Layer Extension) for the banks — its own repo:
[axiom-uncle](https://github.com/AXIOM-Origin-Validator/axiom-uncle);
COUSIN reserved in the specs for whatever turns up next.

### `antie/` — ANTIE (Advanced Normalised Transmission Intermedia Extension)

The email gateway. ANTIE makes a validator reachable through ordinary email infrastructure:
UMP envelopes travel as mail (SMTP in, maildir spool, MTA out). This is the
survival transport — when the only thing that still moves between two
networks is email, AXIOM still settles. Optional two-layer PGP protection
comes from `axiom-pgp-envelope` (in the
[axiom-uncle](https://github.com/AXIOM-Origin-Validator/axiom-uncle) repo).

### `tot/` — Tiny Outbound Tunnel

The production client intake: one port per validator carrying raw-TCP
(length-prefixed CBOR) for native clients and WebSocket for browsers.
Deliberately standalone — it links no protocol crates, runs sandboxed, and
is never trusted: there is no transport TLS by design, because all security
rides on the UMP envelope itself (TLS, if wanted, is a front-proxy concern).

### `fatmama/` — FATMAMA (Fast ANTIE Transport MTA/MDA Agent)

The development SMTP gateway (port 2525): route table with hot-reload,
maildir delivery, loopback simulation — it drives ANTIE's mail path
end-to-end in a dev environment. Dev tool only; the production client
intake is TOT. Carrier-scheme spec: YPX-019 in
[axiom-docs](https://github.com/AXIOM-Origin-Validator/axiom-docs).

## Protocol pin

This repo builds standalone: its protocol dependencies are git-pinned to
[axiom-core](https://github.com/AXIOM-Origin-Validator/axiom-core) tag `core-b77fd28a`
(and [axiom-lib](https://github.com/AXIOM-Origin-Validator/axiom-lib) tag `lib-v3.3.0`).
Upgrading the pin is a deliberate act — the protocol evolves slowly by design.

## Releases

This repository receives one snapshot commit per AXIOM release, exported from
the project's working tree (3.3.0 at export). Its git log is the release
history. License: GPL-3.0.

> AXIOM is pre-mainnet software. Do not use it to custody real value.
