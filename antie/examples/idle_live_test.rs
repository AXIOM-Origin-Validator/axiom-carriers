// One live IDLE round against the real provider: connect, idle, have a second
// task send a mail mid-idle, assert the EXISTS push wakes us, fetch it.
use axiom_antie::carrier::imap_carrier::ImapCarrier;
use axiom_antie::carrier::MailCarrier;

#[tokio::main]
async fn main() {
    let user = std::env::var("M_USER").unwrap();
    let pass = std::env::var("M_PASS").unwrap();
    let c = ImapCarrier::new("imap.purelymail.com".into(), 993,
                             user.clone(), pass.clone(), true, "INBOX".into());
    // drain anything stale first
    let stale = c.check_new().await.expect("drain");
    for m in &stale { let _ = c.mark_processed(&m.id).await; }
    println!("drained {} stale", stale.len());

    // sender fires 8s after we enter idle
    let su = user.clone(); let sp = pass.clone();
    let sender = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(8)).await;
        // plain SMTP send via lettre-free path: reuse std smtp through python is
        // overkill — just do it with a raw TLS socket? Simplest: shell out.
        let msg = format!("From: {su}\r\nTo: {su}\r\nSubject: idle-live-test\r\n\r\nping\r\n");
        let script = format!(
            "import smtplib;c=smtplib.SMTP_SSL('smtp.purelymail.com',465,timeout=30);\
             c.login('{su}','{sp}');c.sendmail('{su}',['{su}'],{msg:?}.encode());c.quit();print('sent')");
        let out = std::process::Command::new("python3").arg("-c").arg(script).output().unwrap();
        println!("sender: {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    });

    let t0 = std::time::Instant::now();
    let saw = c.idle_wait(std::time::Duration::from_secs(120), &|| {}).await.expect("idle_wait");
    println!("idle returned saw_mail={saw} after {:.1}s", t0.elapsed().as_secs_f32());
    sender.await.unwrap();
    assert!(saw, "IDLE must wake on the mid-idle send");

    let msgs = c.check_new().await.expect("fetch after wake");
    println!("fetched {} message(s)", msgs.len());
    assert!(msgs.iter().any(|m| String::from_utf8_lossy(&m.raw).contains("idle-live-test")));
    for m in &msgs { c.mark_processed(&m.id).await.expect("cleanup"); }
    println!("LIVE IDLE ROUND: PASS");
}
