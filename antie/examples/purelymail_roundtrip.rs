//! Phase-1 smoke — does an AXIOM email survive a REAL MTA (Purelymail)
//! byte-identical?
//!
//! Sends a ~200 KB base64 body (single-line, exactly email.rs's current on-wire
//! format) via the Step-A `SmtpCarrier` (implicit TLS + AUTH LOGIN,
//! smtp.purelymail.com:465) from a validator mailbox to a wallet mailbox, pulls
//! it back via `Pop3Carrier` (pop3.purelymail.com:995), and asserts the decoded
//! payload is identical. Reads creds from ~/axiom/mail-test-creds.txt.
//!
//! Touches NO mesh state — it just talks to Purelymail with the two test boxes.
//!
//! Run:
//!   cargo run -p axiom-antie --features disable-audit --example purelymail_roundtrip

use axiom_antie::carrier::MailCarrier;
use axiom_antie::carrier::pop3_carrier::Pop3Carrier;
use axiom_antie::carrier::smtp_carrier::SmtpCarrier;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::time::Duration;

fn field(creds: &str, key: &str) -> String {
    creds
        .lines()
        .find(|l| l.split_whitespace().next() == Some(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or_else(|| panic!("missing {key} in creds file"))
        .to_string()
}

#[tokio::main]
async fn main() {
    let creds_path = format!(
        "{}/axiom/mail-test-creds.txt",
        std::env::var("HOME").expect("HOME not set")
    );
    let creds = std::fs::read_to_string(&creds_path)
        .expect("read ~/axiom/mail-test-creds.txt");
    let val_pw = field(&creds, "VALIDATOR_PASSWORD");
    // Validator→validator: the wallet mailboxes' password fails auth (SMTP+POP3),
    // so use two working boxes to prove the byte-identical FORMAT survival. Swap
    // the receiver back to a wallet once those creds are fixed.
    let sender = "axiom000alpha@purelymail.com";
    let receiver = "axiom000beta@purelymail.com";
    let recv_pw = val_pw.clone();

    // Realistic payload: ~200 KB pseudo-random bytes (cheque-sized), base64 as a
    // SINGLE line — exactly email.rs's current on-wire shape.
    let payload: Vec<u8> = (0..200_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let marker = format!("rt{}", std::process::id());
    let b64 = BASE64.encode(&payload);
    let raw_email = format!(
        "From: {sender}\r\n\
         To: {receiver}\r\n\
         Subject: AXIOM/cheque/{marker}\r\n\
         Message-ID: <{marker}@axiom>\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         {b64}\r\n"
    )
    .into_bytes();
    println!(
        "payload {} bytes | base64 body {} bytes (single line) | marker {marker}",
        payload.len(),
        b64.len()
    );

    // SEND — Step-A SmtpCarrier: implicit TLS on 465 + AUTH LOGIN.
    let smtp = SmtpCarrier::new(
        "smtp.purelymail.com".into(),
        465,
        Some(sender.to_string()),
        Some(val_pw),
        true,
        sender.to_string(),
    );
    println!("→ SMTP send via smtp.purelymail.com:465 (TLS+AUTH as {sender}) ...");
    match smtp.send(receiver, &raw_email).await {
        Ok(()) => println!("  sent."),
        Err(e) => {
            println!("  ✗ SMTP SEND REJECTED: {e:?}");
            println!("    (a line-length / body rejection here IS the Step-B signal — MIME/wrapped base64)");
            std::process::exit(3);
        }
    }

    // RECEIVE — Pop3Carrier: implicit TLS on 995 + AUTH. Poll ~90s.
    let pop = Pop3Carrier::new(
        "pop3.purelymail.com".into(),
        995,
        receiver.to_string(),
        recv_pw,
        true,
    );
    println!("← POP3 pull from pop3.purelymail.com:995 (as {receiver}) ...");
    let mut raw_recv: Option<Vec<u8>> = None;
    for attempt in 1..=18 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let msgs = pop.check_new().await.expect("POP3 check_new failed");
        println!("  poll {attempt}: {} message(s)", msgs.len());
        for m in &msgs {
            if String::from_utf8_lossy(&m.raw).contains(&marker) {
                raw_recv = Some(m.raw.clone());
                break;
            }
        }
        if raw_recv.is_some() {
            break;
        }
    }
    let raw_recv = raw_recv.expect("message never arrived after ~90s");

    // Extract body (after the header/body blank line), strip whitespace (matches
    // email.rs's decoder, which is immune to MTA re-wrapping), base64-decode, compare.
    let s = String::from_utf8_lossy(&raw_recv);
    let body = s
        .split("\r\n\r\n")
        .nth(1)
        .or_else(|| s.split("\n\n").nth(1))
        .expect("no header/body separator in received email");
    let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let recv_payload = BASE64
        .decode(cleaned.as_bytes())
        .expect("base64 decode of received body");

    println!("\n=== RESULT ===");
    println!("  sent     {} bytes", payload.len());
    println!("  received {} bytes", recv_payload.len());
    if recv_payload == payload {
        println!("  ✓ BYTE-IDENTICAL — the cheque survived Purelymail intact. Format proven; Step B not needed.");
    } else {
        let n = payload
            .iter()
            .zip(&recv_payload)
            .take_while(|(a, b)| a == b)
            .count();
        println!(
            "  ✗ MANGLED — diverges at byte {n}/{}. The real MTA altered the body → Step B (MIME/attachment) needed.",
            payload.len()
        );
        std::process::exit(2);
    }
}
