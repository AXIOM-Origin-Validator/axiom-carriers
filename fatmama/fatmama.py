#!/usr/bin/env python3
"""
FATMAMA — Fast ANTIE Transport MTA/MDA Agent

Dumb SMTP file router. Speaks just enough SMTP for smtplib/lettre to
connect, then writes raw bytes to the recipient's maildir. No email
parsing, no content inspection. Just: who is this for → write to inbox.

Three listeners:
  - SMTP  (2525) — inbound delivery. Validators send TO recipients.
  - HTTP  (2526) — monitoring/admin ONLY (/health, /stats, /routes,
                   /events, /per-recipient). NO mail over HTTP — reading
                   mail is POP3 only (the no-HTTP-to-validators rule).
  - POP3  (2527) — standard RFC 1939 pull. The macOS AxiomKiddo.app
                   speaks this; any POP3 mail client also works.

In production, replace with postfix/sendmail + dovecot/cyrus. Same
wire protocols, same maildir output. Only config change: dev ports
→ standard ports (25 / 80 / 110).

Usage:
    python3 fatmama.py --port 2525 --routes /path/to/routes.json
"""

import asyncio
import argparse
import json
import logging
import os
import re
import shutil
import signal
import socket
import sys
import time
import urllib.parse
import urllib.request
import uuid
from collections import Counter, deque
from datetime import datetime
from pathlib import Path

log = logging.getLogger("fatmama")

DEFAULT_PORT = 2525
DEFAULT_HTTP_PORT = 2526
DEFAULT_POP3_PORT = 2527
DEFAULT_ROUTES_FILE = Path.home() / "axiom/fatmama-routes.json"
DEFAULT_LOG_FILE = Path.home() / "axiom/logs/fatmama.log"
HOSTNAME = socket.gethostname()


def deliver_to_maildir(maildir_inbox: Path, message_data: bytes) -> str:
    """Atomic write to maildir: tmp → rename → new."""
    for sub in ["new", "cur", "tmp"]:
        (maildir_inbox / sub).mkdir(parents=True, exist_ok=True)
    filename = f"{time.time():.6f}.{os.getpid()}.{HOSTNAME}.{uuid.uuid4()}"
    tmp_path = maildir_inbox / "tmp" / filename
    new_path = maildir_inbox / "new" / filename
    tmp_path.write_bytes(message_data)
    os.rename(str(tmp_path), str(new_path))
    return filename


# ── FATMAMA IS DEV-ONLY AND CLUSTER-SCOPED (YPX-019 §3.1, NORMATIVE) ──────────
# Design ruling, 2026-08-20: "FATMAMA is a dev only system. It should only takes in
# @axiom or @axiom.internal mail ONLY, anything else will reject immediately."
#
# Before this guard the ONLY thing stopping external mail was the absence of a
# route — accidental protection, not designed. The live log shows it working by
# luck: `DROP spammer@freemail.example`, `DROP leslie32@karabotan.com` were
# refused for being UNKNOWN, not for being external.
#
# ⚠ AND THAT LUCK RUNS OUT UNDER `--auto-create`, which is exactly how the three
# remote FATMAMAs run, bound to 0.0.0.0. In that mode an unknown recipient is
# CREATED rather than dropped, so `attacker@evil.com` would have minted
# `fatmama-mailbox-attacker-evil-com/` and been accepted. The check therefore
# MUST run BEFORE auto-create, not after.
CLUSTER_DOMAINS = ("axiom", "axiom.internal")

# Test-domain list (YPX-019 §3.1, amended 2026-09-26): extra domains a developer
# wants FATMAMA to take like @axiom mail — e.g. `trustmesh.org` on a test network.
# Plain text beside the routes file, one domain per line, `#` comments. Re-read on
# every check, so adding or removing a line takes effect without a restart.
# CARRIER ROUTING ONLY — Core's dev class (`is_dev_wallet`) is untouched, so a
# listed domain's wallets stay REAL class. Set by `serve`; None = no list.
DOMAINS_FILE_NAME = "fatmama-domains.list"
_domains_file = None


def extra_domains() -> set:
    """The listed test domains (lower-case, no leading '@'); empty if no file."""
    if _domains_file is None:
        return set()
    try:
        text = _domains_file.read_text()
    except OSError:
        return set()
    out = set()
    for line in text.splitlines():
        d = line.split("#", 1)[0].strip().lower().lstrip("@")
        if d:
            out.add(d)
    return out


def is_cluster_recipient(addr: str) -> bool:
    """True iff `addr` is inside the dev cluster or a listed test domain. EXACT
    domain match only — no subdomains, no suffix matching (`evil-axiom.com` must
    not pass)."""
    if not addr or "@" not in addr:
        return False
    local, _, domain = addr.rpartition("@")
    domain = domain.strip().lower()
    return bool(local) and (domain in CLUSTER_DOMAINS or domain in extra_domains())


def my_domains(routes: dict = None) -> set:
    """The domains this FATMAMA answers to, for unwrapping delivery addresses.

    `socket.gethostname()` is the SHORT local name (`iota`), not the public
    name a wallet publishes (`mail.example.org`, or a bare IP). The public name is
    therefore DERIVED from what this site already advertises — see
    `_advertised_hosts` — and is never hand-configured.

    Getting this set wrong is costly in both directions: too small and we
    refuse our own wallets' cheques, too large and we open mail addressed to
    another site. It therefore FAILS CLOSED — an unrecognised domain is simply
    "not mine", which routes the message onward instead of filing it here.
    """
    names = {HOSTNAME.strip().lower(), socket.getfqdn().strip().lower()}
    names |= _advertised_hosts(routes)
    return {canonical_host(n) for n in names if n}


def _advertised_hosts(routes: dict = None) -> set:
    """The public names this site ALREADY advertises, read from `antie.toml`.

    DO NOT HAND-CONFIGURE THIS (design ruling, 2026-08-20: *"Don't hand roll
    fatmama_my_domains"*). The node already records its own public name: ANTIE's
    `advertise` list carries `fatmama:<host>:2525`, and `deploy/deploy.py`
    rewrites it per-node at deploy time (`SELF_ADVERTISE`). A separate
    hand-maintained variable is a SECOND SOURCE OF TRUTH for a value the deploy
    pipeline already owns — and two sources eventually disagree, silently, at the
    only moment that matters.

    Every route target is a maildir, and the config sits beside it in BOTH
    layouts, so one relative path serves both:

        <base>/maildir/inbox   ->   <base>/config/antie.toml
        local : /home/user/axiom/axiom-first-penguin-alpha/{maildir,config}
        remote: /home/user/axiom-node/{maildir,config}

    Parsed textually rather than with a TOML reader: this needs one token from a
    file ANTIE owns, and a parse error here must not stop mail being delivered.
    """
    hosts = set()
    for maildir in (routes or {}).values():
        try:
            cfg = Path(maildir).parent.parent / "config" / "antie.toml"
            if not cfg.is_file():
                continue
            for m in re.finditer(r"fatmama:([^:\"\']+):\d+", cfg.read_text()):
                h = canonical_host(m.group(1))
                if h:
                    hosts.add(h)
        except Exception:
            continue          # a broken config must not stop delivery
    return hosts


def canonical_host(host: str) -> str:
    """One spelling per host, so self-comparison cannot be fooled by form.

    A FATMAMA host may be ANY name the operator picked, or a bare IP — never
    assume a pattern (AXIOM_YPX-019 §5.2.1). RFC 5321 writes a bare IP as an
    ADDRESS LITERAL in brackets, `user@[203.0.113.5]`, and IPv6 with a tag,
    `user@[IPv6:2001:db8::1]`. `@[203.0.113.5]` and `@203.0.113.5` name the same
    host and MUST compare equal, or a site fails to recognise its own mail.
    """
    h = host.strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if h.startswith("ipv6:"):
        h = h[5:]
    return h


def unwrap_delivery_address(addr: str, mine: set) -> str:
    """Unwrap a dual-@ delivery address to the cluster address inside it.

        alice@axiom.internal@mail.example.org  ->  alice@axiom.internal
        alice@axiom.internal@[203.0.113.5]     ->  alice@axiom.internal

    This is how a wallet's registered delivery address reaches it from ANOTHER
    site: the outer domain routes the SMTP hop, the local part names the wallet.
    The form is deliberately NOT a legal email address: a bare second '@' is
    refused by every standard MTA, and that is the containment — this mail is
    FATMAMA-to-FATMAMA only and must never enter real mail infrastructure
    (AXIOM_YPX-019 §5.2.1).

    Returns "" when `addr` is not a delivery address for THIS site. Four rules,
    each load-bearing:

      1. UNWRAP ONLY WHAT IS OURS. If the outer domain is not in `mine`, this is
         another site's mail — return "" so it routes onward. Without this,
         zeta would open and store a cheque addressed to a wallet at theta.
      2. THE INNER ADDRESS STILL FACES THE DOOR. `is_cluster_recipient` applies
         unchanged, so only @axiom / @axiom.internal pass. Unwrapping is a step
         BEFORE the admission check, never an exemption from it.
      3. EXACTLY ONCE. No recursion, so a nested wrap cannot be walked into a
         loop or made to resolve somewhere unintended.
      4. The CALLER must slug the returned INNER address. Slugging the wrapped
         form would invent `fatmama-mailbox-alice-axiom-internal-node-example-...`,
         a directory the wallet never polls — the cheque would be delivered,
         acknowledged, and silently invisible.
    """
    inner, host = parse_delivery_address(addr)
    # Rule 1 — not ours, not our business.
    if not inner or host not in mine:
        return ""
    return inner


async def handshake_ok(reader, writer, host: str, port: int) -> bool:
    """Verify the peer advertises FATMAMA capability. Sender-side gate.

    Design ruling, 2026-08-20: *"a sender need to receive special handshake before
    send."* So this runs BEFORE `MAIL FROM` — nothing is transferred until the
    peer has proved it is a FATMAMA.

    A real mail server answers EHLO without `XAXIOM-FATMAMA`, so a forged
    homebase pointed at one ends here: we disconnect having sent no message.
    That is precisely what keeps our addresses off blocklists.
    """
    writer.write(f"EHLO {HOSTNAME}\r\n".encode())
    await writer.drain()
    saw = False
    for _ in range(20):                       # bounded: never read forever
        line = await asyncio.wait_for(reader.readline(), timeout=8)
        if not line:
            break
        if FATMAMA_CAPABILITY.encode() in line.upper():
            saw = True
        if line[3:4] != b"-":                 # last line of the EHLO reply
            break
    if not saw:
        log.warning(f"[cross-site] {host}:{port} did NOT advertise "
                    f"{FATMAMA_CAPABILITY} — NOT a FATMAMA. Aborting WITHOUT "
                    f"sending (§5.2.1). This is the guard that stops a forged "
                    f"homebase turning us into a spam source.")
    return saw


async def cross_site_deliver(host: str, sender: str, rcpt: str,
                             raw: bytes) -> bool:
    """Deliver to another FATMAMA. Returns True only if it was accepted.

    ORDER MATTERS and is the whole security property:
      1. refuse forbidden ports   — never touch real mail infrastructure
      2. connect
      3. HANDSHAKE — peer must advertise FATMAMA capability
      4. only then MAIL FROM / RCPT TO / DATA
    A forged homebase therefore costs an attacker a TCP connect and an EHLO on a
    non-mail port. It cannot deliver AXIOM mail into a third party's server,
    which is the outcome that gets our addresses blocklisted.
    """
    # Always the protocol port; never anything the message asked for.
    port = FATMAMA_PORT
    # Kept as defence in depth even though `port` is now a constant — a layered
    # guard is not retired just because one layer currently makes it
    # unreachable ([[feedback_defense_in_depth_by_design]]).
    if port in FORBIDDEN_SMTP_PORTS:
        log.error(f"[cross-site] REFUSING to dial {host}:{port} — port is real "
                  f"SMTP ({sorted(FORBIDDEN_SMTP_PORTS)}). A forged homebase "
                  f"must never reach real mail infrastructure (§5.2.1).")
        return False
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10)
    except Exception as e:
        log.warning(f"[cross-site] {host}:{port} unreachable: {e!r} — message KEPT")
        return False
    try:
        greet = await asyncio.wait_for(reader.readline(), timeout=8)
        if not greet.startswith(b"220"):
            log.warning(f"[cross-site] {host}:{port} bad greeting {greet[:40]!r} — abort")
            return False
        # ── THE GATE: nothing is sent until the peer proves it is a FATMAMA ──
        if not await handshake_ok(reader, writer, host, port):
            return False
        async def cmd(c: str, expect: bytes = b"250") -> bool:
            writer.write((c + "\r\n").encode()); await writer.drain()
            r = await asyncio.wait_for(reader.readline(), timeout=15)
            return r.startswith(expect)
        if not await cmd(f"MAIL FROM:<{sender}>"): return False
        if not await cmd(f"RCPT TO:<{rcpt}>"):     return False
        if not await cmd("DATA", b"354"):          return False
        body = raw.replace(b"\r\n.", b"\r\n..")        # dot-stuffing
        writer.write(body)
        if not body.endswith(b"\r\n"):
            writer.write(b"\r\n")
        writer.write(b".\r\n"); await writer.drain()
        ok = (await asyncio.wait_for(reader.readline(), timeout=30)).startswith(b"250")
        try:
            writer.write(b"QUIT\r\n"); await writer.drain()
        except Exception:
            pass
        if ok:
            log.info(f"[cross-site] → {rcpt} via {host}:{port} ({len(raw)} bytes) ACCEPTED")
        else:
            log.warning(f"[cross-site] {rcpt} via {host}:{port} REFUSED — message KEPT")
        return ok
    except Exception as e:
        log.warning(f"[cross-site] {host}:{port} error {e!r} — message KEPT")
        return False
    finally:
        try:
            writer.close()
        except Exception:
            pass


def parse_delivery_address(addr: str):
    """Split a dual-@ delivery address into `(inner_cluster_address, host)`.

    THE ONE PARSER for the wrapped form. The SMTP intake and the outbound
    collector both go through here so they cannot disagree about what a delivery
    address is — the intake decides whether to ACCEPT one, the collector decides
    where to SEND one, and a disagreement would strand mail at one end.

    Returns `("", "")` for anything that is not a delivery address. Does NOT
    decide ownership: the caller compares `host` against its own names, because
    the two callers want opposite answers (intake wants "is it mine", the
    collector wants "whose is it").
    """
    if not addr or "@" not in addr:
        return ("", "")
    local, _, domain = addr.rpartition("@")
    domain = canonical_host(domain)
    local = local.strip()
    # DUAL-@ form: the local part IS the inner address, verbatim.
    #
    #     alice@axiom.internal@node.example.com  ->  alice@axiom.internal
    #
    # ⚠ THIS IS DELIBERATELY NOT A LEGAL EMAIL ADDRESS, and that is the point
    # (design ruling, 2026-08-20): *"Yes it will reject by MTA but it's only for fatmama
    # to fatmama. Rejecting by other MTA is good thing."*
    #
    # `@axiom.internal` mail is FATMAMA-to-FATMAMA only and must NEVER enter real
    # mail infrastructure. A bare second '@' is refused by every standard MTA, so
    # the form CANNOT be relayed, cannot leak, and cannot get this site
    # blocklisted — the containment is structural rather than a rule someone has
    # to remember. An earlier draft used a VERP `=` separator precisely BECAUSE it
    # survives any MTA; that was the wrong goal, inverted.
    #
    # A local part with no '@' is a plain mailbox on that host, not a delivery
    # address — so this cannot swallow ordinary recipients.
    if "@" not in local:
        return ("", "")
    inner = local.lower()
    # The inner address faces the same admission check as any other recipient.
    if not is_cluster_recipient(inner):
        return ("", "")
    return (inner, domain)


def _mailbox_is_empty(maildir: Path) -> bool:
    """True iff a maildir holds no MESSAGES.

    ⚠ Test `new/` and `cur/`, NOT the maildir itself. A maildir always contains
    the `new`/`cur`/`tmp` subdirectories, so `any(maildir.glob("*"))` is ALWAYS
    true and a reclaim guarded on it can never fire — which is exactly what the
    first version of §5.1 did (caught by test, 2026-08-20: a drained dev account
    was not reclaimed). `new/` is what POP3 itself enumerates; `cur/` is checked
    too so a partially-read mailbox is never reclaimed out from under a client.
    """
    try:
        for sub in ("new", "cur"):
            d = Path(maildir) / sub
            if d.exists() and any(f.is_file() for f in d.iterdir()):
                return False
        return True
    except Exception:
        return False        # unreadable ⇒ do NOT reclaim


# YPX-019 §5.2.1 — the capability a FATMAMA advertises in EHLO and a SENDING
# FATMAMA REQUIRES before transferring anything. Proves capability, not
# identity: a shared secret would also stop a fake FATMAMA catching misdirected
# mail, but that yields an attacker only their own traffic, and a secret in a
# public codebase leaks by construction.
FATMAMA_CAPABILITY = "XAXIOM-FATMAMA"

# NEVER dial these. A forged homebase must not be able to reach real mail
# infrastructure — that is the outcome that gets a site blocklisted, and the
# blocklist kills OUR OWN outbound mail, not the attacker's.
FORBIDDEN_SMTP_PORTS = {25, 465, 587}

# THE ONLY PORT A FATMAMA EVER SPEAKS ON. Not configurable, by ruling:
# Design ruling 2026-08-20 — "we just force it 2525 no need to allow to change fatmama
# port... It is not a public SMTP anyway."
#
# Note which half is fixed: the HOST is arbitrary (any name an operator picks,
# or a bare IP — AXIOM_YPX-019 §5.2.1), the PORT is a protocol constant. Getting
# that split backwards is the usual error. A fixed port is also what lets a plain
# email address — which cannot carry a port — be a COMPLETE delivery address.
#
# Critically, this means the destination port NEVER comes from the message. A
# message-supplied port would be an attacker-chosen dial target; there is no such
# input any more.
FATMAMA_PORT = 2525
assert FATMAMA_PORT not in FORBIDDEN_SMTP_PORTS, "protocol port must never be real-SMTP"

# Bound amplification: one message must not become sustained traffic at a
# stranger's host.
CROSS_SITE_MIN_INTERVAL_S = 2.0


def parse_recipient(raw: bytes) -> str:
    """Recipient from an ANTIE outbox message's `To:` header.

    ANTIE's MaildirCarrier::send writes the raw RFC822 and IGNORES its `to`
    argument, so the header is the only carrier of the recipient. Header-only is
    acceptable here because this message never crossed a network — ANTIE wrote it
    to a local directory that only this collector reads.
    """
    for line in raw.split(b"\n", 200)[:200]:
        low = line.strip().lower()
        if low.startswith(b"to:"):
            v = line.split(b":", 1)[1].strip().decode("utf-8", "replace")
            if "<" in v and ">" in v:
                v = v[v.find("<") + 1:v.find(">")]
            return v.strip().lower()
        if not line.strip():
            break          # end of headers
    return ""


def load_routes(routes_file: Path) -> dict:
    if not routes_file.exists():
        return {}
    data = json.loads(routes_file.read_text())
    return {addr.lower(): Path(path) for addr, path in data.items()}


class FatmamaServer:
    def __init__(self, routes, routes_file=None, port=DEFAULT_PORT,
                 http_port=DEFAULT_HTTP_PORT, pop3_port=DEFAULT_POP3_PORT,
                 bind="127.0.0.1", mode="dev", ring_capacity=10000,
                 auto_create=False, outboxes=None, pop3_bind=None,
                 pickup_base=None):
        self.routes = routes
        self.routes_file = routes_file
        self._routes_mtime = routes_file.stat().st_mtime if routes_file else 0
        self.port = port
        self.http_port = http_port
        self.pop3_port = pop3_port
        self.bind = bind
        # KI#105: POP3 is unauthenticated BY DESIGN (dumb dev router), so its
        # reachability is the entire access control. SMTP 2525 must stay on the
        # public bind on remotes (cross-site FATMAMA->FATMAMA delivery rides
        # it), but nothing external needs POP3 — remote clients use real
        # provider mailboxes. Default: POP3 binds LOOPBACK unless explicitly
        # widened, so a public deployment closes the open mailbox instead of
        # inheriting it.
        self.pop3_bind = pop3_bind if pop3_bind is not None else "127.0.0.1"
        # When True, an inbound message for an unregistered recipient
        # auto-creates its mailbox (register-on-encounter) instead of being
        # dropped. OFF by default so the local shared FATMAMA keeps its
        # drop-unknown behaviour unchanged; a per-validator FATMAMA (e.g.
        # zeta's) enables it via --auto-create so a wallet gets a mailbox on
        # first contact with no separate registration step.
        self.auto_create = auto_create
        # ANTIE outbox directories this FATMAMA collects from (YPX-019 §6).
        # Empty = collector disabled, i.e. today's behaviour unchanged.
        self.outboxes = [Path(o) for o in (outboxes or [])]
        # YPX-024: ANTIE's [pickup] base directory. When set, FATMAMA is a
        # pickup AGENT (the first MUMMY deployment): it consumes
        # `<base>/<domain>/new/` — the domain is the DIRECTORY NAME, so no
        # header parsing decides routing. This SUPERSEDES the handrolled
        # cross-site path's role for care-of mail; the To:-header unwrap in
        # `_collect_outboxes` remains only as the receive-door for wrapped
        # mail arriving FROM other sites.
        self.pickup_base = Path(pickup_base) if pickup_base else None
        # Per-destination dial timestamps — amplification bound (§5.2.1).
        self._xsite_last = {}
        # "dev" allows the XAXIOM-REGISTER SMTP verb (Kiddo's
        # tester-onboarding shortcut). "production" rejects it with a
        # 502 — operator-curated routes only; new mailboxes are added
        # by editing routes.json out-of-band. Routing, delivery, and
        # POP3/HTTP pull behaviour are identical in both modes.
        self.mode = mode
        self.stats = Counter()
        self.total_delivered = 0
        self.total_dropped = 0
        self.total_pop3_retrieved = 0
        self.bytes_total = 0
        self.bytes_by_recipient = Counter()
        self.last_delivery_ts = None
        # Ring buffer of recent events for the dashboard `/events` endpoint.
        # ~200 B per dict × 10000 = ~2 MB. At current soak rate (0.57/s)
        # this is ~5 h of history; the dashboard tails this for its sparkline
        # and the CLI uses it as a richer source than log-scan.
        self.event_ring = deque(maxlen=ring_capacity)
        self.start_time = time.time()

    def _record_event(self, kind: str, addr: str, bytes_count=None, reason=None):
        ev = {"ts": time.time(), "kind": kind, "addr": addr}
        if bytes_count is not None:
            ev["bytes"] = bytes_count
        if reason is not None:
            ev["reason"] = reason
        self.event_ring.append(ev)

    def _maybe_reload_routes(self):
        if not self.routes_file:
            return
        try:
            mtime = self.routes_file.stat().st_mtime
            if mtime > self._routes_mtime:
                new_routes = load_routes(self.routes_file)
                added = set(new_routes.keys()) - set(self.routes.keys())
                if added:
                    log.info(f"Routes reloaded: +{len(added)} new ({', '.join(list(added)[:10])})")
                self.routes = new_routes
                self._routes_mtime = mtime
        except Exception:
            pass

    def _persist_routes(self):
        """Atomically write the current `self.routes` to `routes_file`.
        tmp-then-rename so a reader never sees a torn JSON. Updates the
        mtime watch baseline so the next reload doesn't redundantly fire."""
        if not self.routes_file:
            return
        data = {addr: str(path) for addr, path in self.routes.items()}
        tmp = self.routes_file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        os.rename(str(tmp), str(self.routes_file))
        self._routes_mtime = self.routes_file.stat().st_mtime

    def _is_fatmama_managed_mailbox(self, maildir: Path) -> bool:
        """A maildir is fatmama-managed (safe to wholly rm) if its parent
        directory is named `fatmama-mailbox-<slug>`. Wallet maildirs and
        validator (penguin) maildirs are NOT managed by fatmama — for
        those we only ever clear inbox contents, never the parent."""
        try:
            return maildir.parent.name.startswith("fatmama-mailbox-")
        except Exception:
            return False

    def _clear_maildir_contents(self, maildir: Path) -> int:
        """Delete all files under inbox/{new,cur,tmp}. Returns count deleted.
        Used for the non-fatmama-managed cases (wallets, validators) where
        we don't own the parent dir but the operator wants the mail gone."""
        n = 0
        for sub in ("new", "cur", "tmp"):
            d = maildir / sub
            if not d.exists():
                continue
            for f in d.iterdir():
                if f.is_file() or f.is_symlink():
                    try:
                        f.unlink()
                        n += 1
                    except Exception:
                        pass
        return n

    # ── PROVENANCE: a marker FILE inside the mailbox, not a sidecar ──
    # Design ruling, 2026-08-20: "perhaps you can have some sort of simple flag, or a
    # way to identify the directory when auto create".
    #
    # Better than a separate index for four reasons: the provenance lives WITH
    # the thing it describes; it survives independently of any other file;
    # removing the directory removes the marker, so there is no orphan state to
    # drift; and an operator can see it with `ls -a`. A sidecar is a second
    # source of truth, and two sources eventually disagree (RULE 1).
    AUTO_MARKER = ".fatmama-auto"

    def _marker_path(self, maildir) -> Path:
        # Marker sits beside `new/cur/tmp`, i.e. in the inbox dir itself.
        return Path(maildir) / self.AUTO_MARKER

    def _mark_auto(self, addr: str) -> None:
        """Record that WE minted this account, so it MAY later be reclaimed."""
        md = self.routes.get(addr.lower())
        if not md:
            return
        try:
            self._marker_path(md).write_text(
                "auto-created by FATMAMA; safe to reclaim once drained (YPX-019 §5.1)\n")
        except Exception as e:
            log.warning(f"auto-marker write {addr}: {e}")

    def _mark_registered(self, addr: str) -> None:
        """PROMOTE to persistent by REMOVING the marker. An explicit
        XAXIOM-REGISTER means a client depends on this route surviving — e.g. a
        client app testing against the co-located FATMAMA, which pulls by POP3
        and would lose routing if the account were reclaimed under it."""
        md = self.routes.get(addr.lower())
        if not md:
            return
        try:
            self._marker_path(md).unlink(missing_ok=True)
        except Exception as e:
            log.warning(f"auto-marker clear {addr}: {e}")

    def _is_auto_created(self, addr: str) -> bool:
        """No marker ⇒ treated as REGISTERED ⇒ never reclaimed. That is the safe
        default, and it is why every account predating this marker survives
        untouched (design ruling: "when unsure, don't delete")."""
        md = self.routes.get(addr.lower())
        try:
            return bool(md) and self._marker_path(md).exists()
        except Exception:
            return False

    def _register_route(self, email: str) -> bool:
        """Idempotently register `email` with a fresh maildir. Returns True
        if a new route was added, False if already registered.

        Raises ValueError on a malformed email (missing local-part,
        missing domain, or no '@'). This is the single canonical guard
        — every caller (SMTP XAXIOM-REGISTER today, any future HTTP
        endpoint, direct programmatic use) hits the same check.

        Used by the SMTP XAXIOM-REGISTER verb (dev-environment Kiddo
        onboarding). Creates `<routes-file-parent>/fatmama-mailbox-<slug>/
        inbox/{new,cur,tmp}` and persists the route to the JSON file so
        the change survives FATMAMA restart and gets picked up by the
        next mtime-watch reload.

        Why the local-part check: a client that lands `"@axiom.internal"`
        (or similar empty-local-part input) used to produce a ghost
        mailbox `fatmama-mailbox-axiom-internal` whose slug looked like
        a legitimate per-tester mailbox but actually swallowed all mail
        for a whole domain. The SMTP handler at line 333 catches the
        literal `"@axiom.internal"` shape, but if a client (or autofill)
        ends up sending a well-formed-but-wrong address like
        `crabspace314159@axiom.internal` we can't catch that here —
        upstream validation owns that case.
        """
        addr = (email or "").strip().lower()
        if "@" not in addr:
            raise ValueError(f"register: missing '@' in {email!r}")
        local, _, domain = addr.partition("@")
        if not local:
            raise ValueError(f"register: empty local-part in {email!r}")
        if not domain:
            raise ValueError(f"register: empty domain in {email!r}")
        # Defence in depth: the callers above reject first, but this is the
        # documented canonical guard, so any FUTURE caller inherits the rule
        # rather than reintroducing the hole.
        if not is_cluster_recipient(addr):
            raise ValueError(
                f"register: {email!r} is outside the cluster domains "
                f"{CLUSTER_DOMAINS} — FATMAMA is dev-only (YPX-019 §3.1)")
        if addr in self.routes:
            return False
        slug = re.sub(r"[^a-z0-9]+", "-", addr).strip("-") or "anon"
        base = self.routes_file.parent if self.routes_file else Path.home() / "axiom"
        inbox = base / f"fatmama-mailbox-{slug}" / "inbox"
        for sub in ("new", "cur", "tmp"):
            (inbox / sub).mkdir(parents=True, exist_ok=True)
        self.routes[addr] = inbox
        self._persist_routes()
        log.info(f"REGISTER ok addr={addr} slug={slug}")
        return True

    def _is_protected_route(self, maildir: Path) -> bool:
        """Hard-protect validator routes from deletion. The validator
        maildir lives under `<env>/axiom-first-penguin-<name>/maildir/inbox`
        and is owned by the running validator process — removing the route
        from fatmama would block all inbound mail to that validator and
        the operator almost certainly does not intend that. Even a raw
        POST /routes/delete cannot bypass this; the protection is enforced
        here, not in the UI."""
        try:
            if "axiom-first-penguin-" in str(maildir):
                return True
            # ⚠ LAYOUT-INDEPENDENT RULE (2026-08-20). The substring above only
            # matches the LOCAL dev layout. On a remote box the validator's own
            # route is `<deploy>/maildir/inbox` (e.g.
            # /home/user/axiom-node/maildir/inbox), which contains no
            # "axiom-first-penguin-" — so a remote validator's route was
            # DELETABLE, and deleting it stops all inbound mail to that
            # validator even though the directory survives.
            #
            # The durable rule: IF FATMAMA DID NOT CREATE THE MAILBOX, FATMAMA
            # DOES NOT REMOVE ITS ROUTE. Only `fatmama-mailbox-<slug>` dirs are
            # ours; everything else belongs to a validator or a wallet.
            return not self._is_fatmama_managed_mailbox(maildir)
        except Exception:
            return False

    def _delete_routes(self, addrs, with_maildir: bool):
        """Remove `addrs` from the route table. If `with_maildir`, also
        delete file contents under each route's inbox/{new,cur,tmp};
        for fatmama-managed mailboxes (parent dir `fatmama-mailbox-*`)
        also remove the whole mailbox directory.

        Validator routes (maildir under `axiom-first-penguin-*`) are
        skipped entirely — they appear in the `protected` list of the
        returned summary instead of `deleted`."""
        deleted = []
        not_found = []
        protected = []
        errors = []
        files_deleted = 0
        dirs_removed = 0
        for raw in addrs:
            addr = str(raw).strip().lower()
            if not addr or addr not in self.routes:
                not_found.append(raw)
                continue
            maildir = self.routes[addr]
            if self._is_protected_route(maildir):
                protected.append({"addr": addr, "maildir": str(maildir),
                                  "reason": "validator route (axiom-first-penguin)"})
                continue
            del self.routes[addr]
            deleted.append({"addr": addr, "maildir": str(maildir)})
            if with_maildir:
                try:
                    files_deleted += self._clear_maildir_contents(maildir)
                    if self._is_fatmama_managed_mailbox(maildir):
                        shutil.rmtree(str(maildir.parent), ignore_errors=True)
                        dirs_removed += 1
                except Exception as e:
                    errors.append({"addr": addr, "reason": f"maildir cleanup: {e}"})
        if deleted:
            self._persist_routes()
            log.warning(
                f"ROUTE_DELETE {len(deleted)} route(s)"
                + (f" + {files_deleted} files / {dirs_removed} mbox dirs" if with_maildir else "")
                + (f" · {len(protected)} validator route(s) protected" if protected else "")
            )
        return {
            "deleted": deleted,
            "not_found": not_found,
            "protected": protected,
            "errors": errors,
            "files_deleted": files_deleted,
            "dirs_removed": dirs_removed,
            "remaining": len(self.routes),
        }

    def _wipe_all_routes(self, with_maildirs: bool):
        """Remove every route. Returns a summary dict. with_maildirs follows
        the same safety rules as _delete_routes (only fatmama-managed
        mailbox parent dirs are rm-rf'd; wallet/validator maildirs get
        their inbox contents cleared but the parent stays)."""
        all_addrs = list(self.routes.keys())
        return self._delete_routes(all_addrs, with_maildir=with_maildirs)

    async def start(self):
        smtp_server = await asyncio.start_server(
            self._handle_client, self.bind, self.port,
            limit=8 * 1024 * 1024)  # 8MB buffer for DMAP proofs
        log.info(f"FATMAMA SMTP listening on {self.bind}:{self.port} ({len(self.routes)} routes)")

        # HTTP pull listener — lets cross-machine wallet clients drain
        # their pending cheques without filesystem access to the env's
        # maildir. See `_handle_http_client` below for the wire shape.
        http_server = await asyncio.start_server(
            self._handle_http_client, self.bind, self.http_port,
            limit=8 * 1024 * 1024)
        log.info(f"FATMAMA HTTP listening on {self.bind}:{self.http_port}")

        # POP3 listener — standard RFC 1939 protocol for inbound pull.
        # Lets the macOS AxiomKiddo reference app (and any real POP3
        # mail client) drain the env's maildir using the same wire
        # protocol they'd use against a real mail server. POP3 is the
        # ONLY mail-read path — reading mail over HTTP was removed
        # (no-HTTP-to-validators rule; HTTP now serves monitoring only).
        pop3_server = await asyncio.start_server(
            self._handle_pop3_client, self.pop3_bind, self.pop3_port,
            limit=8 * 1024 * 1024)
        log.info(f"FATMAMA POP3 listening on {self.pop3_bind}:{self.pop3_port}")

        if self.outboxes:
            log.info(f"FATMAMA outbox collector watching {len(self.outboxes)} dir(s): "
                     + ", ".join(str(o) for o in self.outboxes))
            asyncio.create_task(self._collect_outboxes())
        if self.pickup_base:
            log.info(f"FATMAMA pickup agent (YPX-024 / MUMMY) watching {self.pickup_base}")
            asyncio.create_task(self._collect_pickup())
        async with smtp_server, http_server, pop3_server:
            await asyncio.gather(
                smtp_server.serve_forever(),
                http_server.serve_forever(),
                pop3_server.serve_forever(),
            )

    async def _handle_client(self, reader, writer):
        """Minimal SMTP: just enough handshake, then dump bytes to maildir."""
        self._maybe_reload_routes()
        rcpt_to = None
        mail_from = None   # logged on a DROP so an unroutable sender can be found
        peer = writer.get_extra_info("peername")

        try:
            writer.write(f"220 {HOSTNAME} FATMAMA\r\n".encode())
            await writer.drain()

            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=300)
                if not line:
                    break
                cmd = line.decode("utf-8", errors="replace").strip()
                if not cmd:
                    continue

                upper = cmd.split()[0].upper() if cmd.split() else ""

                if upper in ("EHLO", "HELO"):
                    # §5.2.1 — advertise so a sending FATMAMA can verify it is
                    # talking to a FATMAMA BEFORE transferring. A real MTA never
                    # advertises this, so a forged homebase aimed at someone's
                    # mail server is disconnected before any message is sent.
                    # HELO has no extension mechanism, so only EHLO carries it.
                    if upper == "EHLO":
                        writer.write(f"250-{HOSTNAME}\r\n".encode())
                        writer.write(f"250 {FATMAMA_CAPABILITY}\r\n".encode())
                    else:
                        writer.write(f"250 {HOSTNAME}\r\n".encode())
                    await writer.drain()

                elif upper == "XAXIOM-REGISTER":
                    # Dev-environment wallet onboarding (Kiddo "Register
                    # with FATMAMA" button). Adds <email> to routes so
                    # subsequent SMTP delivery queues for POP3 polling.
                    # No auth. ⚠ The "single-tenant dev-LAN" premise this rested
                    # on is CURRENTLY FALSE — see KI#105: FATMAMA is bound
                    # 0.0.0.0 on internet-facing boxes. Registration is
                    # therefore reachable by strangers wherever 2525 is open.
                    #
                    # Production mode rejects this verb. Routes in
                    # production are operator-curated (edited in
                    # routes.json out-of-band); allowing arbitrary SMTP
                    # peers to provision mailboxes would let any caller
                    # mint addresses on a live edge gateway.
                    if self.mode == "production":
                        writer.write(b"502 5.5.1 XAXIOM-REGISTER not enabled in production mode\r\n")
                        await writer.drain()
                        continue
                    parts = cmd.split(maxsplit=1)
                    raw = parts[1].strip().strip("<>").lower() if len(parts) > 1 else ""
                    if not raw or "@" not in raw or raw.startswith("@") or raw.endswith("@"):
                        writer.write(b"501 syntax error: XAXIOM-REGISTER <email>\r\n")
                        await writer.drain()
                        continue
                    if not is_cluster_recipient(raw):
                        log.warning(f"REJECT REGISTER {raw} (not @axiom/@axiom.internal)")
                        writer.write(b"550 5.7.1 cluster domain only "
                                     b"(@axiom / @axiom.internal)\r\n")
                        await writer.drain()
                        continue
                    try:
                        added = self._register_route(raw)
                        self._mark_registered(raw)     # persistent — never reclaimed
                        if added:
                            log.info(f"REGISTER {raw} → {self.routes[raw]}")
                        writer.write(f"250 OK {raw} registered\r\n".encode())
                    except Exception as e:
                        log.error(f"REGISTER FAILED {raw}: {e}")
                        writer.write(f"451 register failed: {e}\r\n".encode())
                    await writer.drain()

                elif upper == "MAIL":
                    a, b = cmd.find("<"), cmd.find(">")
                    mail_from = cmd[a + 1:b].strip().lower() if 0 <= a < b else None
                    writer.write(b"250 OK\r\n")
                    await writer.drain()

                elif upper == "RCPT":
                    # Extract address from RCPT TO:<addr>
                    start = cmd.find("<")
                    end = cmd.find(">")
                    if start >= 0 and end > start:
                        rcpt_to = cmd[start + 1:end].strip().lower()
                    elif ":" in cmd:
                        rcpt_to = cmd.split(":", 1)[1].strip().strip("<>").lower()
                    # YPX-019 §3.1 — reject a non-cluster recipient IMMEDIATELY,
                    # before routing and before any auto-create.
                    # A delivery address wrapped for THIS site unwraps to the
                    # wallet's real mailbox (YPX-019 §5.2.1). Done BEFORE the
                    # cluster check, because the wrapped form's outer domain is
                    # this host — it would otherwise be refused at the door as
                    # "not @axiom.internal", which is how a cross-site cheque
                    # bounces off the site that was supposed to receive it.
                    if rcpt_to and not is_cluster_recipient(rcpt_to):
                        unwrapped = unwrap_delivery_address(rcpt_to, my_domains(self.routes))
                        if unwrapped:
                            log.info(f"[delivery-address] {rcpt_to} → {unwrapped}")
                            rcpt_to = unwrapped
                    if rcpt_to and not is_cluster_recipient(rcpt_to):
                        log.warning(f"REJECT {rcpt_to} (not @axiom/@axiom.internal — "
                                    f"FATMAMA is dev-only, cluster-scoped)")
                        writer.write(b"550 5.7.1 recipient not in cluster domain "
                                     b"(@axiom / @axiom.internal only)\r\n")
                        await writer.drain()
                        rcpt_to = None
                        continue
                    writer.write(b"250 OK\r\n")
                    await writer.drain()

                elif upper == "DATA":
                    writer.write(b"354 Go\r\n")
                    await writer.drain()

                    # Read DATA using readuntil — precise, no over-read.
                    # readuntil stops exactly at the separator, leaving
                    # subsequent bytes (QUIT) in the buffer for readline.
                    terminator = b"\r\n.\r\n"
                    try:
                        raw = await asyncio.wait_for(
                            reader.readuntil(terminator), timeout=120)
                        message_data = raw[:-len(terminator)]
                    except asyncio.IncompleteReadError as e:
                        message_data = e.partial
                    except asyncio.LimitOverrunError:
                        # Payload exceeds buffer — read in chunks as fallback
                        buf = bytearray()
                        while True:
                            chunk = await asyncio.wait_for(reader.read(262144), timeout=60)
                            if not chunk:
                                break
                            buf.extend(chunk)
                            if terminator in buf:
                                idx = buf.index(terminator)
                                buf = buf[:idx]
                                break
                        message_data = bytes(buf)

                    # RFC 5321 §4.5.2 — reverse dot-stuffing
                    lines = message_data.split(b"\r\n")
                    for i, line in enumerate(lines):
                        if line.startswith(b".."):
                            lines[i] = line[1:]
                    message_data = b"\r\n".join(lines)

                    # Route to recipient. With --auto-create, an unregistered
                    # recipient's mailbox is created on first encounter (no
                    # separate registration step); otherwise unknown recipients
                    # are dropped — default, so the local shared FATMAMA is
                    # unchanged.
                    if self.auto_create and rcpt_to and rcpt_to not in self.routes:
                        try:
                            self._register_route(rcpt_to)
                            self._mark_auto(rcpt_to)   # transient — reclaimable
                        except Exception as e:
                            log.error(f"AUTO-CREATE FAILED {rcpt_to}: {e}")
                    if rcpt_to and rcpt_to in self.routes:
                        try:
                            fname = deliver_to_maildir(self.routes[rcpt_to], message_data)
                            self.stats[rcpt_to] += 1
                            self.total_delivered += 1
                            n = len(message_data)
                            self.bytes_total += n
                            self.bytes_by_recipient[rcpt_to] += n
                            self.last_delivery_ts = time.time()
                            self._record_event("DELIVER", rcpt_to, bytes_count=n)
                            log.info(f"DELIVER → {rcpt_to} ({n} bytes)")
                        except Exception as e:
                            self._record_event("DELIVER_FAILED", rcpt_to, reason=str(e))
                            log.error(f"DELIVER FAILED {rcpt_to}: {e}")
                    elif rcpt_to:
                        self.total_dropped += 1
                        self._record_event("REJECT", rcpt_to, reason="no-route")
                        # Sender + Subject on the DROP line (2026-09-26): 83 mails to
                        # `<validator>@axiom` were dropped on trustmesh and nothing
                        # logged who sent them. `_DROP_RX` still matches (prefix).
                        log.warning(drop_line(rcpt_to, mail_from, message_data))

                    writer.write(b"250 OK\r\n")
                    await writer.drain()
                    rcpt_to = None

                elif upper == "QUIT":
                    writer.write(b"221 Bye\r\n")
                    await writer.drain()
                    break

                elif upper in ("NOOP", "RSET"):
                    writer.write(b"250 OK\r\n")
                    await writer.drain()

                else:
                    writer.write(b"250 OK\r\n")
                    await writer.drain()

        except (ConnectionResetError, BrokenPipeError) as e:
            log.warning(f"Connection lost: {e}")
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            log.error(f"Connection error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── HTTP pull endpoint ─────────────────────────────────────────────
    #
    # Cross-machine clients (typically the macOS wallet against a Linux-
    # box env) can't read the env's maildir directly. They pull pending
    # cheques over HTTP instead.
    #
    # Endpoints (monitoring/admin ONLY — mail is NOT served over HTTP;
    # reading mail is POP3 (2527), per the no-HTTP-to-validators rule):
    #   GET  /health   {"status":"ok","uptime_secs":N,"routes":M}
    #   GET  /stats, /routes, /events, /per-recipient[-lifetime]
    #   POST /routes/delete, /routes/wipe  (route management)
    #
    # No authentication. ⚠ "The dev env is single-tenant" is the SAME expired
    # premise as the POP3 handler's — see KI#105. Wherever this HTTP port (2526)
    # is publicly bound, route management is unauthenticated to the internet.
    # It happens to be firewalled on all three remotes TODAY, which is luck, not
    # design. Production deployments would put this behind a reverse proxy or
    # add token auth here.
    # ───────────────────────────────────────────────────────────────────

    async def _handle_http_client(self, reader, writer):
        self._maybe_reload_routes()
        peer = writer.get_extra_info("peername")
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=10)
            if not request_line:
                return
            line = request_line.decode("utf-8", errors="replace").strip()
            parts = line.split()
            if len(parts) < 3:
                await self._http_send(writer, 400, {"error": "malformed request"})
                return
            method = parts[0].upper()
            if method not in ("GET", "POST"):
                await self._http_send(writer, 405, {"error": "method not allowed"})
                return

            # Parse headers — capture Content-Length for POST bodies.
            content_length = 0
            while True:
                hdr = await asyncio.wait_for(reader.readline(), timeout=10)
                if hdr in (b"\r\n", b"\n", b""):
                    break
                hdr_str = hdr.decode("utf-8", errors="replace").strip()
                if ":" in hdr_str:
                    hk, hv = hdr_str.split(":", 1)
                    if hk.strip().lower() == "content-length":
                        try:
                            content_length = int(hv.strip())
                        except ValueError:
                            content_length = 0

            body_bytes = b""
            if method == "POST" and content_length > 0:
                # Cap body size — JSON management requests are tiny
                # (a list of addrs + flags). 256 KB is way more than enough.
                if content_length > 256 * 1024:
                    await self._http_send(writer, 413, {"error": "body too large"})
                    return
                body_bytes = await asyncio.wait_for(
                    reader.readexactly(content_length), timeout=10)

            url = urllib.parse.urlparse(parts[1])
            qs = urllib.parse.parse_qs(url.query)
            path = url.path

            # ── POST endpoints (route management — destructive) ──────
            if method == "POST":
                try:
                    body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
                except json.JSONDecodeError as e:
                    await self._http_send(writer, 400, {"error": f"bad JSON: {e}"})
                    return

                if path == "/routes/delete":
                    addrs = body.get("addrs")
                    if not isinstance(addrs, list) or not addrs:
                        await self._http_send(writer, 400,
                            {"error": "addrs (non-empty list) required"})
                        return
                    with_maildir = bool(body.get("with_maildir", False))
                    summary = self._delete_routes(addrs, with_maildir)
                    await self._http_send(writer, 200, summary)
                    return

                if path == "/routes/wipe":
                    confirm = body.get("confirm")
                    if confirm != "WIPE_ALL":
                        await self._http_send(writer, 400, {
                            "error": "explicit confirmation required",
                            "hint": 'send body {"confirm":"WIPE_ALL", "with_maildirs":bool}',
                        })
                        return
                    with_maildirs = bool(body.get("with_maildirs", False))
                    summary = self._wipe_all_routes(with_maildirs)
                    await self._http_send(writer, 200, summary)
                    return

                await self._http_send(writer, 404, {"error": "no such POST endpoint"})
                return

            # ── GET endpoints ────────────────────────────────────────
            if path == "/health":
                uptime = int(time.time() - self.start_time)
                await self._http_send(writer, 200, {
                    "status": "ok",
                    "uptime_secs": uptime,
                    "routes": len(self.routes),
                    "delivered": self.total_delivered,
                })
                return

            # ── Dashboard endpoints (step 2) ──────────────────────────
            # /stats          full counter dump (uptime, totals, bytes, ring depth)
            # /routes         current route table (one source of truth for the dashboard)
            # /events         tail of the in-memory ring buffer (DELIVER/REJECT/POP/...)
            # /per-recipient  per-addr {count,bytes} aggregated over a time window

            if path == "/stats":
                await self._http_send(writer, 200, {
                    "uptime_secs": int(time.time() - self.start_time),
                    "routes": len(self.routes),
                    "delivered": self.total_delivered,
                    "dropped": self.total_dropped,
                    "pop3_retrieved": self.total_pop3_retrieved,
                    "bytes_total": self.bytes_total,
                    "last_delivery_ts": self.last_delivery_ts,
                    "ring_size": len(self.event_ring),
                    "ring_capacity": self.event_ring.maxlen,
                    "mode": self.mode,
                })
                return

            if path == "/routes":
                await self._http_send(writer, 200, {
                    "count": len(self.routes),
                    "routes": [
                        {"addr": a, "maildir": str(p)}
                        for a, p in sorted(self.routes.items())
                    ],
                })
                return

            if path == "/events":
                try:
                    since = float(qs.get("since", ["0"])[0] or "0")
                except ValueError:
                    since = 0.0
                try:
                    limit = int(qs.get("limit", ["200"])[0] or "200")
                except ValueError:
                    limit = 200
                if limit < 1:
                    limit = 1
                if limit > 2000:
                    limit = 2000
                kind_filter = qs.get("kind", [None])[0]
                addr_filter = qs.get("addr", [None])[0]
                # Iterate newest → oldest, take up to `limit` matches newer than `since`,
                # return chronologically (oldest → newest) for caller convenience.
                buf = list(self.event_ring)
                out = []
                for ev in reversed(buf):
                    if ev["ts"] <= since:
                        break
                    if kind_filter and ev.get("kind") != kind_filter:
                        continue
                    if addr_filter and ev.get("addr", "") != addr_filter:
                        continue
                    out.append(ev)
                    if len(out) >= limit:
                        break
                out.reverse()
                await self._http_send(writer, 200, {
                    "count": len(out),
                    "events": out,
                    "ring_oldest_ts": buf[0]["ts"] if buf else None,
                    "ring_newest_ts": buf[-1]["ts"] if buf else None,
                })
                return

            if path == "/per-recipient-lifetime":
                # Lifetime here means "since this fatmama process started"
                # (the in-memory bytes_by_recipient + stats counters). Survives
                # for the duration of the fatmama process; resets on restart.
                # Cheap — just dumps the two Counters, no ring or log scan.
                addrs = set(self.stats.keys()) | set(self.bytes_by_recipient.keys())
                recipients = {
                    a: {"count": self.stats.get(a, 0),
                        "bytes": self.bytes_by_recipient.get(a, 0)}
                    for a in addrs
                }
                await self._http_send(writer, 200, {
                    "recipients": recipients,
                    "uptime_secs": int(time.time() - self.start_time),
                    "total_delivered": self.total_delivered,
                    "bytes_total": self.bytes_total,
                })
                return

            if path == "/per-recipient":
                try:
                    window = int(qs.get("window", ["300"])[0] or "300")
                except ValueError:
                    window = 300
                cutoff = time.time() - window
                recipients = {}
                ring_window_truncated = False
                for ev in self.event_ring:
                    if ev["ts"] < cutoff:
                        continue
                    if ev.get("kind") != "DELIVER":
                        continue
                    addr = ev.get("addr") or ""
                    if not addr:
                        continue
                    d = recipients.setdefault(addr, {"count": 0, "bytes": 0})
                    d["count"] += 1
                    d["bytes"] += ev.get("bytes", 0) or 0
                # Only flag truncation when the ring is FULL and we still
                # don't reach back to the cutoff — that's real data loss.
                # A non-full ring whose oldest ts is younger than the cutoff
                # just means the daemon started after the window — caller
                # should compare `window_secs` against `daemon_uptime_secs`.
                if (self.event_ring
                        and len(self.event_ring) == self.event_ring.maxlen
                        and self.event_ring[0]["ts"] > cutoff):
                    ring_window_truncated = True
                await self._http_send(writer, 200, {
                    "window_secs": window,
                    "recipients": recipients,
                    "ring_window_truncated": ring_window_truncated,
                    "daemon_uptime_secs": int(time.time() - self.start_time),
                })
                return

            # Mail is NOT served over HTTP (no /pop, no /peek) — reading mail
            # is POP3 (2527) only (no-HTTP-to-validators rule). Anything else
            # is an unknown endpoint.
            await self._http_send(writer, 404, {"error": "no such endpoint"})

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            log.error(f"HTTP error: {e}")
            try:
                await self._http_send(writer, 500, {"error": str(e)})
            except Exception:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── POP3 endpoint ──────────────────────────────────────────────────
    #
    # Minimal RFC 1939 implementation. Supports:
    #
    #   USER <addr>     — declare mailbox (the AXIOM email address)
    #   PASS <anything> — auth (no-auth in dev; any password accepted)
    #   STAT            — count + total octets
    #   LIST [n]        — list messages with index + size
    #   RETR <n>        — retrieve message n
    #   DELE <n>        — mark message n for delete
    #   RSET            — undo all pending deletes
    #   NOOP            — no-op
    #   QUIT            — commit deletes + close
    #   CAPA            — capability list (USER, TOP, UIDL etc.)
    #   UIDL [n]        — unique-id listing (filename, since mtime-based
    #                     names are unique by construction)
    #   TOP <n> <lines> — headers + N body lines (we return full
    #                     message — clients use TOP to preview; the
    #                     dev env's payloads are small enough that
    #                     returning everything is fine)
    #
    # Session state: a snapshot of `inbox/new/*` taken at USER time.
    # DELE marks an index for deletion; QUIT actually unlinks the files.
    # If the connection drops before QUIT, no deletes happen — exactly
    # RFC 1939 behaviour.
    #
    # ⚠ NO TLS, NO APOP, NO AUTHENTICATION — and the "single-tenant dev env"
    # assumption this rested on HAS EXPIRED (KI#105, 2026-08-20).
    #
    # It was true when FATMAMA was one process on one workstation. It stopped
    # being true when the same process was deployed to internet-facing boxes
    # with `--bind 0.0.0.0`: POP3 2527 answers from the open internet on zeta,
    # theta and iota, and a login with a DELIBERATELY WRONG password was
    # ACCEPTED and served LIST. Any dev mailbox on any remote is world-readable.
    #
    # Nobody changed the auth model — the deployment moved out from under it.
    # That is the failure mode to watch for: an assumption stated as a comment,
    # left behind by an environment that changed around it.
    #
    # ⚠ TLS IS NOT THE FIX and would be actively misleading: encrypting a
    # channel that accepts any password only makes an open mailbox private in
    # transit. The gaps are (a) no authentication and (b) public reachability.
    # See KI#105 for the three fix directions; the cheapest is to firewall 2527
    # rather than to add crypto here.
    #
    # NOT fund-safety: Core validates every transaction and rejects anything
    # injected (RULE 5 — the protocol is the security boundary, not the
    # carrier). It IS information disclosure and DoS surface.
    # ───────────────────────────────────────────────────────────────────

    async def _collect_outboxes(self):
        """YPX-019 §6 / AntieOutboundSplit — collect what ANTIE wrote.

        ANTIE's outbound job ends at writing a file; THIS is the other half.
        Without a collector the outbox is a DEAD END: gateway.rs records replies
        stranding on 7 of 10 validators, SILENTLY, because nothing drained it.

        Local delivery only for now. A recipient this box does not host is LEFT
        IN PLACE and logged once — never deleted — so cross-site delivery
        (YPX-019 §5.2, homebase + mandatory handshake) can take it in the next
        step without having lost anything.
        """
        warned = set()
        while True:
            # ⚠ RELOAD ROUTES HERE. Until 2026-08-20 the collector used the map
            # captured at STARTUP, because `_maybe_reload_routes()` was called
            # only from the SMTP/HTTP/POP3 handlers. That was invisible while any
            # validator still PUSHED SMTP — each push incidentally refreshed the
            # map, so the collector saw new wallet routes by side effect.
            #
            # The moment all validators moved to write-a-file, the last SMTP
            # push disappeared and with it the only thing refreshing this view:
            # replies to newly-registered wallets could never be matched, the
            # outbox backed up, and soak funding stalled. A canary could NOT
            # have caught this — it needs the LAST pusher to go away.
            self._maybe_reload_routes()
            moved = 0
            for outbox in self.outboxes:
                newdir = Path(outbox) / "new"
                if not newdir.exists():
                    continue
                for f in sorted(newdir.iterdir()):
                    if not f.is_file():
                        continue
                    try:
                        raw = f.read_bytes()
                    except FileNotFoundError:
                        continue          # another pass took it
                    rcpt = parse_recipient(raw)
                    if not rcpt:
                        if f.name not in warned:
                            log.warning(f"[collect] {f.name}: no To: header — LEFT in place "
                                        f"(never dropped); inspect it")
                            warned.add(f.name)
                        continue
                    dest = self.routes.get(rcpt)
                    if dest is None:
                        # ── CROSS-SITE (YPX-019 §5.2) ──
                        # Not hosted here. @axiom.internal ONLY: every other
                        # domain routes by destination address
                        # (PublicMailCarriers §2), and @axiom is soak-local.
                        # ROUTE FROM THE DESTINATION ADDRESS (§5.2). The
                        # receiver's own registered delivery address carries the
                        # site; nothing is read from the subject, and the sender
                        # cannot name where a third party's cheque goes.
                        inner, host = parse_delivery_address(rcpt)
                        if not inner:
                            if f.name not in warned:
                                log.warning(f"[collect] {rcpt}: not hosted here and not a "
                                            f"delivery address (user@domain@host) — cannot "
                                            f"route (§5.2). KEPT, not dropped.")
                                warned.add(f.name)
                            continue
                        if host in my_domains(self.routes):
                            # Wrapped for US — this is a local mailbox after all.
                            local_dest = self.routes.get(inner)
                            if local_dest is None:
                                if f.name not in warned:
                                    log.warning(f"[collect] {rcpt} unwraps to {inner}, which "
                                                f"has no mailbox here. KEPT, not dropped.")
                                    warned.add(f.name)
                                continue
                            try:
                                deliver_to_maildir(local_dest, raw)
                                f.unlink(); moved += 1; self.total_delivered += 1
                                log.info(f"[collect] → {inner} (unwrapped from {rcpt}) "
                                         f"delivered locally")
                            except Exception as e:
                                log.error(f"[collect] {inner}: delivery FAILED ({e}) — kept")
                            continue
                        # Rate-limit per destination: one message must not become
                        # sustained traffic at a stranger's host.
                        last = self._xsite_last.get(host, 0.0)
                        if time.time() - last < CROSS_SITE_MIN_INTERVAL_S:
                            continue                       # try again next pass
                        self._xsite_last[host] = time.time()
                        # ⚠ Do NOT log "dialing" here — the port guard and the
                        # handshake both run INSIDE cross_site_deliver, and a
                        # refused port never opens a socket. Claiming a dial we
                        # did not make would read, in a log review, as though we
                        # had connected to a stranger's mail server.
                        log.info(f"[cross-site] routing {rcpt} via {host}:{FATMAMA_PORT} "
                                 f"(a HINT from the subject — port guard and handshake "
                                 f"decide whether anything is sent)")
                        if await cross_site_deliver(host, f"fatmama@{HOSTNAME}",
                                                    rcpt, raw):
                            f.unlink()
                            moved += 1
                            self.total_delivered += 1
                        # Not accepted ⇒ file stays. Never dropped.
                        continue
                    try:
                        deliver_to_maildir(dest, raw)
                        f.unlink()
                        moved += 1
                        self.total_delivered += 1
                        log.info(f"[collect] → {rcpt} ({len(raw)} bytes) delivered locally")
                    except Exception as e:
                        log.error(f"[collect] {rcpt}: delivery FAILED ({e}) — left in place")
            await asyncio.sleep(0.5 if moved else 2.0)

    async def _collect_pickup(self):
        """YPX-024: consume the ANTIE `[pickup]` directory — MUMMY, first cut.

        ANTIE deposited a VERIFIED receiver-bound artifact at
        `<base>/<domain>/new/<file>` and its job ended. This agent's whole
        contract is that directory: the DOMAIN IS THE DIRECTORY NAME (no
        header parsing chooses a destination — the sender-signed address
        already did, and ANTIE verified it against the fingerprint).

          - domain hosted HERE  → deliver into the recipient's local mailbox
            (`To:` names the verified inner — the same header ANTIE built).
          - domain elsewhere    → the existing cross-site leg: port guard +
            mandatory XAXIOM-FATMAMA handshake + per-destination rate limit
            (§5.2.1) decide whether anything is sent. Not accepted ⇒ the
            file STAYS. Never dropped.

        This supersedes the handrolled cross-site routing for care-of mail
        (YPX-019 §5.2's To:-parse now only guards the RECEIVE door).
        """
        warned = set()
        while True:
            self._maybe_reload_routes()
            moved = 0
            base = self.pickup_base
            if base and base.exists():
                for domdir in sorted(p for p in base.iterdir() if p.is_dir()):
                    domain = canonical_host(domdir.name)
                    newdir = domdir / "new"
                    if not newdir.exists():
                        continue
                    for f in sorted(newdir.iterdir()):
                        if not f.is_file():
                            continue
                        try:
                            raw = f.read_bytes()
                        except FileNotFoundError:
                            continue      # another pass took it
                        if domain in my_domains(self.routes) \
                                or domain in _advertised_hosts(self.routes):
                            rcpt = parse_recipient(raw)
                            dest = self.routes.get(rcpt) if rcpt else None
                            if dest is None:
                                if f.name not in warned:
                                    log.warning(f"[pickup] {f.name}: recipient "
                                                f"{rcpt!r} has no mailbox here — "
                                                f"KEPT, not dropped")
                                    warned.add(f.name)
                                continue
                            try:
                                deliver_to_maildir(dest, raw)
                                f.unlink(); moved += 1; self.total_delivered += 1
                                log.info(f"[pickup] → {rcpt} delivered locally "
                                         f"({domain}/{f.name})")
                            except Exception as e:
                                log.error(f"[pickup] {rcpt}: delivery FAILED ({e}) — kept")
                            continue
                        # Remote pickup domain — same amplification bound as
                        # the outbox collector's cross-site leg.
                        last = self._xsite_last.get(domain, 0.0)
                        if time.time() - last < CROSS_SITE_MIN_INTERVAL_S:
                            continue
                        self._xsite_last[domain] = time.time()
                        rcpt = parse_recipient(raw) or f"pickup@{domain}"
                        if await cross_site_deliver(domain, f"fatmama@{HOSTNAME}",
                                                    rcpt, raw):
                            f.unlink(); moved += 1; self.total_delivered += 1
                            log.info(f"[pickup] → {domain} cross-site ({f.name})")
                        # Not accepted ⇒ file stays. Never dropped.
            await asyncio.sleep(0.5 if moved else 2.0)

    async def _handle_pop3_client(self, reader, writer):
        self._maybe_reload_routes()
        peer = writer.get_extra_info("peername")
        mailbox = None       # routes key once USER lands
        inbox = None         # Path to inbox/new/ for that mailbox
        snapshot = []        # [(Path, size_bytes)] frozen at USER time
        deleted = set()      # indices (1-based) marked for delete
        authed = False       # USER + PASS both seen

        async def send(line: str):
            writer.write((line + "\r\n").encode("utf-8"))
            await writer.drain()

        try:
            await send(f"+OK FATMAMA POP3 ready ({HOSTNAME})")
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=300)
                if not line:
                    break
                cmd_line = line.decode("utf-8", errors="replace").rstrip("\r\n")
                if not cmd_line:
                    continue
                parts = cmd_line.split()
                cmd = parts[0].upper()
                args = parts[1:]

                if cmd == "USER":
                    if not args:
                        await send("-ERR USER requires argument")
                        continue
                    mailbox = args[0].lower()
                    if mailbox in self.routes:
                        inbox_dir = self.routes[mailbox] / "new"
                        snapshot = []
                        if inbox_dir.exists():
                            for f in sorted(inbox_dir.iterdir()):
                                try:
                                    snapshot.append((f, f.stat().st_size))
                                except FileNotFoundError:
                                    pass
                        inbox = inbox_dir
                        await send(f"+OK mailbox {mailbox}")
                    else:
                        # Unknown route — accept anyway, deliver empty
                        # mailbox. Avoids leaking which addresses are
                        # registered.
                        inbox = None
                        snapshot = []
                        await send(f"+OK mailbox {mailbox}")

                elif cmd == "PASS":
                    if mailbox is None:
                        await send("-ERR USER first")
                        continue
                    authed = True
                    await send(f"+OK {len(snapshot)} messages")

                elif cmd == "CAPA":
                    await send("+OK Capability list follows")
                    for line in ("USER", "TOP", "UIDL", "PIPELINING"):
                        await send(line)
                    await send(".")

                elif cmd == "QUIT":
                    if authed:
                        for idx in deleted:
                            i = idx - 1
                            if 0 <= i < len(snapshot):
                                f, _ = snapshot[i]
                                try:
                                    f.unlink()
                                    self.total_pop3_retrieved += 1
                                except FileNotFoundError:
                                    pass
                                except Exception as e:
                                    log.warning(f"POP3 unlink {f.name}: {e}")
                        # ── §5.1 ACCOUNT RECLAMATION (multi-site) ──
                        # Auto-created dev accounts are TRANSIENT: created on
                        # first qualifying message, reclaimed once their owner
                        # has pulled the mail. Without this, a receiver
                        # accumulates routes and empty mailboxes forever — zeta
                        # already held 17 dead soak accounts on 2026-08-20.
                        #
                        # FOUR conditions, all required:
                        #  (a) we actually DELETED something this session. An
                        #      idle poll must never reclaim, or a routine empty
                        #      check would churn a route that is about to
                        #      receive mail.
                        #  (b) the mailbox is now EMPTY.
                        #  (c) it is fatmama-managed (`fatmama-mailbox-<slug>`),
                        #      i.e. we created it.
                        #  (d) it is not protected.
                        # (c) and (d) are the SAME predicates the admin delete
                        # path uses — one set of safety rules, not two (RULE 1).
                        #
                        # Co-located validators are unaffected: their maildirs
                        # are read DIRECTLY FROM DISK, never over POP3, so this
                        # path cannot reach them. Remote wallet accounts are the
                        # only population it touches.
                        if deleted:
                            try:
                                _md = self.routes.get(mailbox)
                                if (_md and self._is_auto_created(mailbox)
                                        and self._is_fatmama_managed_mailbox(_md)
                                        and not self._is_protected_route(_md)
                                        and _mailbox_is_empty(_md)):
                                    self._delete_routes([mailbox], with_maildir=True)
                                    log.info(f"POP3 → {mailbox}: drained and EMPTY — "
                                             f"route + mailbox reclaimed (§5.1)")
                            except Exception as _re:
                                log.warning(f"POP3 reclaim {mailbox}: {_re!r}")
                        if deleted:
                            log.info(f"POP3 → {mailbox}: {len(deleted)} msg deleted on QUIT")
                    await send("+OK bye")
                    break

                elif not authed:
                    await send("-ERR authenticate first")

                elif cmd == "STAT":
                    live = [(i, sz) for i, (_, sz) in enumerate(snapshot, 1)
                            if i not in deleted]
                    total = sum(sz for _, sz in live)
                    await send(f"+OK {len(live)} {total}")

                elif cmd == "LIST":
                    if args:
                        try:
                            n = int(args[0])
                        except ValueError:
                            await send("-ERR bad index")
                            continue
                        if not (1 <= n <= len(snapshot)) or n in deleted:
                            await send(f"-ERR no such message")
                        else:
                            _, sz = snapshot[n - 1]
                            await send(f"+OK {n} {sz}")
                    else:
                        live = [(i, sz) for i, (_, sz) in enumerate(snapshot, 1)
                                if i not in deleted]
                        await send(f"+OK {len(live)} messages")
                        for i, sz in live:
                            await send(f"{i} {sz}")
                        await send(".")

                elif cmd == "UIDL":
                    if args:
                        try:
                            n = int(args[0])
                        except ValueError:
                            await send("-ERR bad index")
                            continue
                        if not (1 <= n <= len(snapshot)) or n in deleted:
                            await send("-ERR no such message")
                        else:
                            f, _ = snapshot[n - 1]
                            await send(f"+OK {n} {f.name}")
                    else:
                        await send("+OK")
                        for i, (f, _) in enumerate(snapshot, 1):
                            if i in deleted:
                                continue
                            await send(f"{i} {f.name}")
                        await send(".")

                elif cmd in ("RETR", "TOP"):
                    # TOP <n> <lines>: per RFC 1939 should return
                    # headers + N body lines. The dev env's payloads
                    # are small and self-contained, so we return the
                    # full message for both commands — clients then
                    # decide what to display.
                    if not args:
                        await send(f"-ERR {cmd} requires argument")
                        continue
                    try:
                        n = int(args[0])
                    except ValueError:
                        await send("-ERR bad index")
                        continue
                    if not (1 <= n <= len(snapshot)) or n in deleted:
                        await send("-ERR no such message")
                        continue
                    f, sz = snapshot[n - 1]
                    try:
                        data = f.read_bytes()
                    except FileNotFoundError:
                        await send("-ERR message disappeared")
                        continue
                    await send(f"+OK {sz} octets")
                    # RFC 1939 §3 — byte-stuff lines starting with "."
                    # to "..", terminate response with "\r\n.\r\n".
                    stuffed = data.replace(b"\r\n.", b"\r\n..")
                    if stuffed.startswith(b"."):
                        stuffed = b"." + stuffed
                    writer.write(stuffed)
                    if not stuffed.endswith(b"\r\n"):
                        writer.write(b"\r\n")
                    writer.write(b".\r\n")
                    await writer.drain()

                elif cmd == "DELE":
                    if not args:
                        await send("-ERR DELE requires argument")
                        continue
                    try:
                        n = int(args[0])
                    except ValueError:
                        await send("-ERR bad index")
                        continue
                    if not (1 <= n <= len(snapshot)) or n in deleted:
                        await send("-ERR no such message")
                    else:
                        deleted.add(n)
                        await send(f"+OK message {n} marked")

                elif cmd == "RSET":
                    deleted.clear()
                    await send(f"+OK {len(snapshot)} messages")

                elif cmd == "NOOP":
                    await send("+OK")

                else:
                    await send(f"-ERR unknown command {cmd}")

        except (ConnectionResetError, BrokenPipeError) as e:
            log.warning(f"POP3 conn lost: {e}")
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            log.error(f"POP3 error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    async def _http_send(writer, status: int, body: dict):
        body_bytes = json.dumps(body).encode("utf-8")
        reason = {200: "OK", 400: "Bad Request", 404: "Not Found",
                  405: "Method Not Allowed", 500: "Internal Server Error"}.get(status, "OK")
        writer.write(
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            f"Connection: close\r\n"
            f"\r\n".encode("utf-8")
        )
        writer.write(body_bytes)
        await writer.drain()

    def print_stats(self):
        uptime = time.time() - self.start_time
        print(f"\nFATMAMA Stats (uptime: {uptime:.0f}s)")
        print(f"  Total delivered: {self.total_delivered}")
        print(f"  Total dropped:   {self.total_dropped}")
        print(f"  POP3 retrieved:  {self.total_pop3_retrieved}")


# ── Read-only dev CLI helpers ────────────────────────────────────────────
#
# Pure read-only inspection of FATMAMA state. Reads:
#   - fatmama-routes.json (routes table)
#   - fatmama.log (append-only event log)
#   - <maildir>/new/ (pending message counts)
#   - http://127.0.0.1:2526/health (live counters from running daemon)
#
# Does NOT touch the running daemon's in-memory state. Safe to run during
# soak / production traffic. For richer stats (per-recipient counters in
# memory, rejection-reason breakdown), see step 2 of the dashboard plan
# (companion HTTP endpoints on the daemon itself).

_LOG_HDR_RX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<level>INFO|WARNING|ERROR|DEBUG)\s+"
    r"(?P<msg>.*)$"
)
_DELIVER_RX = re.compile(r"^DELIVER → (?P<addr>\S+) \((?P<bytes>\d+) bytes\)")
def drop_line(rcpt_to, mail_from, message_data):
    """The DROP log line: recipient, SMTP sender and Subject, so an unroutable
    sender can be traced (added 2026-09-26). Starts with the `_DROP_RX` prefix."""
    subj = next((l[8:].decode("utf-8", "replace").strip()[:80]
                 for l in message_data.split(b"\r\n")[:40]
                 if l[:8].lower() == b"subject:"), "")
    return f"DROP {rcpt_to} (no route) from={mail_from or '?'} subject={subj!r}"


_DROP_RX = re.compile(r"^DROP (?P<addr>\S+) \(no route\)")
_POP_RX = re.compile(r"^POP → (?P<addr>\S+) \((?P<count>\d+) msg")
_REGISTER_RX = re.compile(r"^REGISTER (?P<addr>\S+) →")


def _fetch_health(host="127.0.0.1", port=DEFAULT_HTTP_PORT, timeout=2.0):
    """GET /health from the running daemon. Returns dict or None on failure."""
    return _fetch_endpoint("health", host, port, timeout)


def _fetch_endpoint(path, host="127.0.0.1", port=DEFAULT_HTTP_PORT, timeout=2.0, query=""):
    """GET /<path>[?<query>] from the daemon. Returns dict or None on failure."""
    qs = f"?{query}" if query else ""
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/{path}{qs}", timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def _format_duration(secs):
    if secs is None:
        return "—"
    secs = int(secs)
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60:02d}s"
    if secs < 86400:
        return f"{secs // 3600}h {(secs % 3600) // 60:02d}m"
    return f"{secs // 86400}d {(secs % 86400) // 3600:02d}h"


def _format_bytes(n):
    if n is None:
        return "—"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


def _parse_window(s):
    """Parse '5m', '1h', '30s', '2d' to seconds. Returns int or None."""
    m = re.match(r"^(\d+)\s*([smhd])$", s.strip().lower())
    if m:
        return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    try:
        return int(s)
    except ValueError:
        return None


def _count_pending(maildir_inbox):
    """Count files in <maildir_inbox>/new/. Cheap via os.scandir."""
    new = maildir_inbox / "new"
    if not new.exists():
        return 0
    try:
        return sum(1 for _ in os.scandir(str(new)))
    except OSError:
        return 0


def _parse_log_line(line):
    """Returns dict with ts/level/kind/addr/bytes or None if unparseable."""
    m = _LOG_HDR_RX.match(line.rstrip())
    if not m:
        return None
    out = {"ts": m.group("ts"), "level": m.group("level"),
           "msg": m.group("msg"), "kind": None, "addr": None, "bytes": None}
    md = _DELIVER_RX.match(out["msg"])
    if md:
        out["kind"] = "DELIVER"
        out["addr"] = md.group("addr")
        out["bytes"] = int(md.group("bytes"))
        return out
    md = _DROP_RX.match(out["msg"])
    if md:
        out["kind"] = "DROP"
        out["addr"] = md.group("addr")
        return out
    md = _POP_RX.match(out["msg"])
    if md:
        out["kind"] = "POP"
        out["addr"] = md.group("addr")
        out["count"] = int(md.group("count"))
        return out
    md = _REGISTER_RX.match(out["msg"])
    if md:
        out["kind"] = "REGISTER"
        out["addr"] = md.group("addr")
        return out
    return out  # header parsed, payload not classified


def _read_tail_bytes(path, n_bytes):
    size = os.path.getsize(str(path))
    n = min(size, n_bytes)
    with open(str(path), "rb") as f:
        f.seek(size - n)
        return f.read().decode("utf-8", errors="replace")


def cmd_serve(args):
    """Run the FATMAMA daemon (legacy default mode)."""
    log_level = logging.WARNING if args.quiet else logging.INFO
    if args.log_file:
        logging.basicConfig(filename=str(args.log_file), level=log_level,
                            format="%(asctime)s %(levelname)s %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    else:
        logging.basicConfig(level=log_level,
                            format="%(asctime)s %(levelname)s %(message)s",
                            datefmt="%H:%M:%S")

    routes = load_routes(args.routes)
    if not routes:
        print(f"ERROR: No routes in {args.routes}", file=sys.stderr)
        return 1

    log.info(f"Routes: {len(routes)} · mode={args.mode} · ring={args.ring_capacity}")
    global _domains_file
    _domains_file = args.routes.parent / DOMAINS_FILE_NAME
    _extra = sorted(extra_domains())
    if _extra:
        log.warning(f"Test-domain list {_domains_file}: also accepting {', '.join(_extra)} "
                    f"(carrier only — keep empty where these domains get REAL mail)")
    server = FatmamaServer(
        routes,
        routes_file=args.routes,
        # Forced, by ruling (2026-08-20): a FATMAMA listens on 2525 and
        # nowhere else. Cross-site delivery dials FATMAMA_PORT unconditionally,
        # so a site listening anywhere else is simply unreachable — silently, and
        # only from other sites. Refusing at startup makes that a loud failure
        # instead of a mystery. The flag is kept so existing launchers passing
        # `--port 2525` keep working.
        port=FATMAMA_PORT,
        http_port=args.http_port,
        pop3_port=args.pop3_port,
        bind=args.bind,
        pop3_bind=args.pop3_bind,
        mode=args.mode,
        ring_capacity=args.ring_capacity,
        auto_create=args.auto_create,
        outboxes=args.outbox,
        pickup_base=args.pickup_base,
    )

    def handle_signal(sig, frame):
        log.info("Shutting down...")
        server.print_stats()
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    pid_file = args.routes.parent / "fatmama.pid"
    pid_file.write_text(str(os.getpid()))

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        server.print_stats()
    finally:
        pid_file.unlink(missing_ok=True)
    return 0


def cmd_status(args):
    """Show daemon liveness + counters + recent activity."""
    print("FATMAMA Status")
    print("─" * 64)

    pid_file = args.routes.parent / "fatmama.pid"
    pid = None
    alive = False
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, 0)
            alive = True
        except (ValueError, ProcessLookupError, PermissionError):
            alive = False

    if alive:
        print(f"  Process:    PID {pid} (running)")
    elif pid is not None:
        print(f"  Process:    PID {pid} STALE (pid file present, process gone)")
    else:
        print(f"  Process:    no PID file at {pid_file}")

    # Prefer /stats (step 2 richer endpoint); fall back to /health for the
    # case where someone is running an older fatmama binary.
    stats = _fetch_endpoint("stats", port=args.http_port)
    if stats:
        print(f"  Uptime:     {_format_duration(stats.get('uptime_secs'))}")
        print(f"  HTTP:       127.0.0.1:{args.http_port} OK · mode={stats.get('mode', '?')}")
        print(f"  Counters:   delivered={stats.get('delivered', 0):,}  "
              f"dropped={stats.get('dropped', 0):,}  "
              f"popped={stats.get('popped', 0):,}  "
              f"pop3={stats.get('pop3_retrieved', 0):,}")
        print(f"  Bytes:      {_format_bytes(stats.get('bytes_total', 0))} delivered total")
        print(f"  Ring buf:   {stats.get('ring_size', 0):,} / {stats.get('ring_capacity', 0):,} events "
              f"({100 * stats.get('ring_size', 0) // max(stats.get('ring_capacity', 1), 1)}% full)")
        last_ts = stats.get('last_delivery_ts')
        if last_ts:
            age = time.time() - last_ts
            print(f"  Last DELIVER: {_format_duration(age)} ago")
    else:
        # Try /health for older daemons
        health = _fetch_health(port=args.http_port)
        if health:
            print(f"  Uptime:     {_format_duration(health.get('uptime_secs'))}")
            print(f"  HTTP/health: 127.0.0.1:{args.http_port} OK (legacy /stats unavailable)")
            print(f"  Counters:   delivered={health.get('delivered', 0):,}  "
                  f"popped={health.get('popped', 0):,}  "
                  f"routes={health.get('routes', 0)}")
        else:
            print(f"  HTTP:       127.0.0.1:{args.http_port} UNREACHABLE")

    if not args.routes.exists():
        print(f"  Routes:     file not found at {args.routes}")
        return 1
    try:
        routes = load_routes(args.routes)
    except Exception as e:
        print(f"  Routes:     PARSE ERROR ({e})")
        return 1
    rsz = args.routes.stat().st_size
    print(f"  Routes:     {args.routes} ({len(routes)} entries, {_format_bytes(rsz)})")

    pending = []
    for addr, path in routes.items():
        n = _count_pending(path)
        if n > 0:
            pending.append((addr, n))
    pending.sort(key=lambda kv: -kv[1])
    total_pending = sum(n for _, n in pending)
    if pending:
        top = ", ".join(f"{a}={n}" for a, n in pending[:5])
        more = f" +{len(pending) - 5} more" if len(pending) > 5 else ""
        print(f"  Pending:    {total_pending} messages across {len(pending)} mailboxes")
        print(f"              top: {top}{more}")
    else:
        print(f"  Pending:    0 messages (all mailboxes drained)")

    if args.log_file.exists():
        size = args.log_file.stat().st_size
        print(f"  Log file:   {args.log_file} ({_format_bytes(size)})")
        try:
            tail = _read_tail_bytes(args.log_file, 8192)
            last = None
            for line in reversed(tail.splitlines()):
                p = _parse_log_line(line)
                if p and p.get("kind"):
                    last = p
                    break
            if last:
                ts_dt = datetime.strptime(last["ts"], "%Y-%m-%d %H:%M:%S")
                age = (datetime.now() - ts_dt).total_seconds()
                summary = last["msg"][:60]
                print(f"  Last event: {last['ts']} ({_format_duration(age)} ago) — {summary}")
            else:
                print(f"  Last event: (no parseable entries in last 8 KB of log)")
        except Exception as e:
            print(f"  Last event: read error ({e})")
    else:
        print(f"  Log file:   not found at {args.log_file}")

    return 0


def cmd_routes(args):
    """List the route table, optionally filtered."""
    if not args.routes.exists():
        print(f"ERROR: routes file not found: {args.routes}", file=sys.stderr)
        return 1
    try:
        routes = load_routes(args.routes)
    except Exception as e:
        print(f"ERROR: parse failed: {e}", file=sys.stderr)
        return 1

    filt = args.filter.lower() if args.filter else None
    rows = []
    for addr in sorted(routes.keys()):
        path = routes[addr]
        if filt and filt not in addr.lower() and filt not in str(path).lower():
            continue
        rows.append((addr, path, _count_pending(path)))

    if args.json:
        print(json.dumps(
            [{"addr": a, "maildir": str(p), "pending": n} for a, p, n in rows],
            indent=2,
        ))
        return 0

    if not rows:
        msg = f"No routes matched filter '{args.filter}'" if filt else "No routes"
        print(msg)
        return 0

    addr_w = max(20, max(len(a) for a, _, _ in rows))
    print(f"{'ADDR':<{addr_w}}  {'PENDING':>7}  MAILDIR")
    print(f"{'─' * addr_w}  {'─' * 7}  {'─' * 50}")
    for addr, path, n in rows:
        path_str = str(path)
        if len(path_str) > 60:
            path_str = "…" + path_str[-59:]
        print(f"{addr:<{addr_w}}  {n:>7}  {path_str}")
    total = len(routes)
    if filt:
        print(f"\n{len(rows)} route(s) matched, {total} total")
    else:
        print(f"\n{total} route(s)")
    return 0


def cmd_tail(args):
    """Tail the FATMAMA log with optional filters."""
    if not args.log_file.exists():
        print(f"ERROR: log file not found: {args.log_file}", file=sys.stderr)
        return 1

    try:
        addr_rx = re.compile(args.addr) if args.addr else None
    except re.error as e:
        print(f"ERROR: bad --addr regex: {e}", file=sys.stderr)
        return 1

    def emit(line):
        line = line.rstrip()
        if not line:
            return
        p = _parse_log_line(line)
        if args.errors and (not p or p["level"] not in ("WARNING", "ERROR")):
            return
        if addr_rx:
            if not p or not p.get("addr") or not addr_rx.search(p["addr"]):
                return
        print(line)

    if args.lines > 0:
        # Cheap last-N via tail-read; 256B/line is generous for our log
        tail = _read_tail_bytes(args.log_file, max(args.lines * 256, 4096))
        for line in tail.splitlines()[-args.lines:]:
            emit(line)

    if args.follow:
        try:
            with open(str(args.log_file), "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if line:
                        emit(line)
                    else:
                        time.sleep(0.5)
        except KeyboardInterrupt:
            pass
    return 0


def cmd_routes_delete(args):
    """Delete one or more routes via POST /routes/delete on the running daemon."""
    addrs = [a.strip().lower() for a in args.addrs if a.strip()]
    if not addrs:
        print("ERROR: no addrs given", file=sys.stderr)
        return 1
    body = {"addrs": addrs, "with_maildir": args.with_maildir}
    summary = _post_endpoint("routes/delete", body, port=args.http_port)
    if summary is None:
        print(f"ERROR: POST /routes/delete failed (daemon down on :{args.http_port}?)",
              file=sys.stderr)
        return 1
    if "error" in summary:
        print(f"ERROR: {summary['error']}", file=sys.stderr)
        return 1
    deleted = summary.get("deleted", [])
    not_found = summary.get("not_found", [])
    protected = summary.get("protected", [])
    errors = summary.get("errors", [])
    print(f"Deleted {len(deleted)} route(s)" + (
        f" + {summary.get('files_deleted', 0)} files / "
        f"{summary.get('dirs_removed', 0)} mbox dirs" if args.with_maildir else ""
    ) + f" · {summary.get('remaining', '?')} remaining")
    for d in deleted:
        print(f"  - {d['addr']:<32} {d['maildir']}")
    if protected:
        print(f"\nProtected (refused — validator routes) ({len(protected)}):")
        for p in protected:
            print(f"  ✗ {p['addr']:<32} {p.get('reason','')}")
    if not_found:
        print(f"\nNot found ({len(not_found)}):")
        for a in not_found:
            print(f"  ? {a}")
    if errors:
        print(f"\nErrors ({len(errors)}):")
        for e in errors:
            print(f"  ! {e}")
    return 0


def cmd_routes_wipe(args):
    """Wipe ALL routes via POST /routes/wipe. Requires --yes; --with-maildirs
    also cleans inbox contents (fatmama-managed mailboxes are rm'd entirely;
    wallet/validator maildirs have their inbox/{new,cur,tmp} cleared)."""
    if not args.yes:
        print("ERROR: refusing to wipe without --yes (this deletes all routes)",
              file=sys.stderr)
        return 1
    body = {"confirm": "WIPE_ALL", "with_maildirs": args.with_maildirs}
    summary = _post_endpoint("routes/wipe", body, port=args.http_port)
    if summary is None:
        print(f"ERROR: POST /routes/wipe failed (daemon down on :{args.http_port}?)",
              file=sys.stderr)
        return 1
    if "error" in summary:
        print(f"ERROR: {summary['error']}", file=sys.stderr)
        return 1
    deleted = summary.get("deleted", [])
    protected = summary.get("protected", [])
    print(f"Wiped {len(deleted)} route(s)" + (
        f" + {summary.get('files_deleted', 0)} files / "
        f"{summary.get('dirs_removed', 0)} mbox dirs" if args.with_maildirs else ""
    ) + (f" · {len(protected)} validator route(s) kept (protected)" if protected else ""))
    return 0


def _post_endpoint(path, body, host="127.0.0.1", port=DEFAULT_HTTP_PORT, timeout=5.0):
    """POST JSON to /<path>. Returns parsed response dict or None on failure."""
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"http://{host}:{port}/{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode("utf-8"))
        except Exception:
            return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return None


def cmd_stats(args):
    """Aggregate stats from log over a time window."""
    if not args.log_file.exists():
        print(f"ERROR: log file not found: {args.log_file}", file=sys.stderr)
        return 1
    window_s = _parse_window(args.window)
    if window_s is None or window_s <= 0:
        print(f"ERROR: bad --window '{args.window}' (use e.g. 30s, 5m, 1h, 2d)",
              file=sys.stderr)
        return 1
    cutoff = datetime.now().timestamp() - window_s

    deliveries = 0
    drops = 0
    pops = 0
    registers = 0
    bytes_total = 0
    by_recipient = Counter()
    bytes_by_recipient = Counter()
    warn_count = 0
    error_count = 0
    earliest_ts = None
    latest_ts = None

    with open(str(args.log_file), "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            p = _parse_log_line(line)
            if not p:
                continue
            try:
                ts = datetime.strptime(p["ts"], "%Y-%m-%d %H:%M:%S").timestamp()
            except ValueError:
                continue
            if ts < cutoff:
                continue
            if earliest_ts is None or ts < earliest_ts:
                earliest_ts = ts
            if latest_ts is None or ts > latest_ts:
                latest_ts = ts
            if p["level"] == "WARNING":
                warn_count += 1
            elif p["level"] == "ERROR":
                error_count += 1
            kind = p.get("kind")
            if kind == "DELIVER":
                deliveries += 1
                bytes_total += p["bytes"] or 0
                by_recipient[p["addr"]] += 1
                bytes_by_recipient[p["addr"]] += p["bytes"] or 0
            elif kind == "DROP":
                drops += 1
            elif kind == "POP":
                pops += 1
            elif kind == "REGISTER":
                registers += 1

    span = (latest_ts - earliest_ts) if (latest_ts and earliest_ts) else 0
    rate = (deliveries / span) if span > 0 else 0.0
    avg = (bytes_total / deliveries) if deliveries > 0 else 0

    print(f"FATMAMA Stats — last {args.window}")
    print("─" * 64)
    if earliest_ts:
        print(f"  Span:        {datetime.fromtimestamp(earliest_ts).strftime('%H:%M:%S')} "
              f"→ {datetime.fromtimestamp(latest_ts).strftime('%H:%M:%S')} "
              f"({_format_duration(span)} of data)")
    else:
        print(f"  Span:        (no events in window)")
    print(f"  Deliveries:  {deliveries:,}  ({rate:.2f}/s · "
          f"{_format_bytes(bytes_total)} total · avg {_format_bytes(avg)})")
    print(f"  Pops:        {pops:,}")
    print(f"  Drops:       {drops:,}  (no-route)")
    print(f"  Registers:   {registers:,}")
    if warn_count or error_count:
        print(f"  Log levels:  WARNING={warn_count}  ERROR={error_count}")
    if by_recipient:
        print()
        print("  Top recipients:")
        for addr, cnt in by_recipient.most_common(10):
            bts = bytes_by_recipient[addr]
            print(f"    {addr:<36} {cnt:>6}  {_format_bytes(bts):>10}")
    return 0


def main():
    KNOWN = {"serve", "status", "routes", "routes-delete", "routes-wipe", "tail", "stats"}
    argv = sys.argv[1:]

    # If the first arg is a flag (and not -h/--help), assume legacy serve-mode
    # invocation and prepend "serve" so the existing daemon command line keeps
    # working unchanged.
    if argv and argv[0].startswith("-") and argv[0] not in ("-h", "--help"):
        argv = ["serve"] + argv

    parser = argparse.ArgumentParser(
        prog="fatmama.py",
        description="FATMAMA — Fast ANTIE Transport MTA/MDA Agent + dev CLI",
    )
    sub = parser.add_subparsers(dest="cmd", metavar="<command>")

    # serve (daemon — legacy default)
    p_serve = sub.add_parser("serve", help="run the FATMAMA daemon")
    p_serve.add_argument("--port", type=int, default=FATMAMA_PORT,
                         help=f"SMTP listen port — MUST be {FATMAMA_PORT} (protocol constant)")
    p_serve.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT,
                         help=f"HTTP pull-endpoint port (default {DEFAULT_HTTP_PORT})")
    p_serve.add_argument("--pop3-port", type=int, default=DEFAULT_POP3_PORT,
                         help=f"POP3 listen port (default {DEFAULT_POP3_PORT})")
    p_serve.add_argument("--bind", default="127.0.0.1")
    # KI#105: POP3 has NO authentication (dumb dev router), so its bind IS the
    # access control. It defaults to loopback regardless of --bind; pass
    # --pop3-bind explicitly to widen it (the local test box does, remotes
    # must not — their clients use real provider mailboxes).
    p_serve.add_argument("--pop3-bind", default=None, metavar="ADDR",
                         help="POP3 bind address (default 127.0.0.1 — POP3 is "
                              "unauthenticated; loopback is the access control)")
    p_serve.add_argument("--routes", type=Path, required=True)
    p_serve.add_argument("--outbox", action="append", default=[], metavar="DIR",
                         help="ANTIE outbox maildir to COLLECT from (repeatable). "
                              "ANTIE writes there and stops; this drains it. Without "
                              "a collector the outbox is a dead end — see YPX-019 §6.")
    p_serve.add_argument("--pickup-base", type=Path, default=None, metavar="DIR",
                         help="YPX-024: ANTIE's [pickup] base directory. When set, "
                              "FATMAMA runs as the pickup agent (MUMMY, first cut): "
                              "consumes <DIR>/<domain>/new/ — local domains deliver "
                              "to mailboxes, remote domains ride the guarded "
                              "cross-site leg.")
    p_serve.add_argument("--log-file", type=Path, default=None)
    p_serve.add_argument("--quiet", "-q", action="store_true")
    p_serve.add_argument(
        "--mode", choices=["dev", "production"], default="dev",
        help="dev (default) honours the XAXIOM-REGISTER SMTP verb for "
             "Kiddo's tester-onboarding shortcut. production rejects it.",
    )
    p_serve.add_argument(
        "--ring-capacity", type=int, default=10000,
        help="In-memory event ring buffer size for /events endpoint "
             "(default 10000, ~2MB at ~200B/event)",
    )
    p_serve.add_argument(
        "--auto-create", action="store_true",
        help="Auto-create a mailbox for an unregistered recipient on first "
             "inbound message (register-on-encounter) instead of dropping it. "
             "OFF by default (local shared FATMAMA drops unknowns unchanged); "
             "enabled by a per-validator FATMAMA such as zeta's.",
    )

    # status
    p_status = sub.add_parser("status", help="show daemon status + counters")
    p_status.add_argument("--routes", type=Path, default=DEFAULT_ROUTES_FILE)
    p_status.add_argument("--log-file", type=Path, default=DEFAULT_LOG_FILE)
    p_status.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT)

    # routes (list)
    p_routes = sub.add_parser("routes", help="list the route table")
    p_routes.add_argument("--routes", type=Path, default=DEFAULT_ROUTES_FILE)
    p_routes.add_argument("--filter", help="substring match on addr or path")
    p_routes.add_argument("--json", action="store_true", help="emit JSON")

    # routes-delete
    p_rd = sub.add_parser("routes-delete",
        help="delete one or more routes (hits the running daemon)")
    p_rd.add_argument("addrs", nargs="+", help="addresses to remove")
    p_rd.add_argument("--with-maildir", action="store_true",
        help="also delete mail (fatmama-managed mailboxes rm'd; "
             "wallet/validator inboxes have their files cleared)")
    p_rd.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT)

    # routes-wipe
    p_rw = sub.add_parser("routes-wipe",
        help="WIPE ALL routes (hits the running daemon)")
    p_rw.add_argument("--yes", action="store_true",
        help="required — without this the wipe refuses")
    p_rw.add_argument("--with-maildirs", action="store_true",
        help="also delete mail (see routes-delete --with-maildir)")
    p_rw.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT)

    # tail
    p_tail = sub.add_parser("tail", help="tail the FATMAMA log")
    p_tail.add_argument("--log-file", type=Path, default=DEFAULT_LOG_FILE)
    p_tail.add_argument("-n", "--lines", type=int, default=20,
                        help="show last N lines before any follow (default 20)")
    p_tail.add_argument("-f", "--follow", action="store_true",
                        help="follow the log (Ctrl-C to stop)")
    p_tail.add_argument("--errors", action="store_true",
                        help="only WARNING/ERROR lines")
    p_tail.add_argument("--addr", help="regex filter on recipient address")

    # stats
    p_stats = sub.add_parser("stats", help="aggregate stats over a time window")
    p_stats.add_argument("--log-file", type=Path, default=DEFAULT_LOG_FILE)
    p_stats.add_argument("--window", default="5m",
                         help="time window (e.g. 30s, 5m, 1h, 2d; default 5m)")

    args = parser.parse_args(argv)

    if args.cmd is None:
        parser.print_help()
        return 0
    # Loud, not silent: a site listening anywhere but 2525 is unreachable from
    # every other site, because cross-site delivery dials the constant.
    if getattr(args, "port", FATMAMA_PORT) != FATMAMA_PORT:
        parser.error(f"--port must be {FATMAMA_PORT} — FATMAMA's port is a protocol "
                     f"constant, not an operator choice. (The HOST is yours to pick; "
                     f"the port is not.)")
    if args.cmd == "serve":
        return cmd_serve(args)
    if args.cmd == "status":
        return cmd_status(args)
    if args.cmd == "routes":
        return cmd_routes(args)
    if args.cmd == "routes-delete":
        return cmd_routes_delete(args)
    if args.cmd == "routes-wipe":
        return cmd_routes_wipe(args)
    if args.cmd == "tail":
        return cmd_tail(args)
    if args.cmd == "stats":
        return cmd_stats(args)
    return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
