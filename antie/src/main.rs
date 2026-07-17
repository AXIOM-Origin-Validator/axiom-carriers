//! AXIOM ANTIE Gateway
//!
//! Email-based transaction gateway.
//!
//! # Supported Carriers
//!
//! - **Maildir** (default) - Filesystem-based, works with sendmail/postfix
//! - **POP3** - Pull emails from POP3 server
//! - **IMAP** - Pull emails from IMAP server
//!
//! # Usage
//!
//! ```bash
//! # Run with default config (Maildir)
//! antie
//!
//! # Run with custom config
//! antie --config /path/to/config.toml
//!
//! # Generate default config
//! antie --generate-config
//!
//! # Generate POP3 example config
//! antie --generate-config --pop3
//!
//! # Generate IMAP example config
//! antie --generate-config --imap
//!
//! # Initialize test maildir
//! antie --init-maildir ./test-maildir
//! ```

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use axiom_antie::config::{AntieConfig, LambdaConfig};
use axiom_antie::carrier::{CarriersConfig, MaildirConfig};
use axiom_antie::gateway::Gateway;
use clap::Parser;
use colored::*;
use std::path::PathBuf;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "antie")]
#[command(about = "AXIOM ANTIE Gateway - Email-based transaction gateway")]
#[command(version)]
struct Cli {
    /// Path to config file
    #[arg(short, long)]
    config: Option<PathBuf>,
    
    /// Generate default config and exit
    #[arg(long)]
    generate_config: bool,
    
    /// Generate POP3 example config (use with --generate-config)
    #[arg(long)]
    pop3: bool,
    
    /// Generate IMAP example config (use with --generate-config)
    #[arg(long)]
    imap: bool,

    /// Generate TCP + Maildir example config (use with --generate-config)
    #[arg(long)]
    tcp: bool,

    /// Generate all-carriers example config (use with --generate-config)
    #[arg(long)]
    all: bool,

    /// Initialize maildir structure at path
    #[arg(long)]
    init_maildir: Option<PathBuf>,
    
    /// Lambda address (overrides config, sets TCP mode)
    #[arg(long)]
    lambda: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Decorative boot charm. TTY-gated, no-op under systemd/journald.
    // Lives in axiom-denomination so every native binary that links
    // the AXC/L$/atom conversion lib also gets the canary — see
    // denomination/src/lib.rs. Purely for luck; zero functional effect.
    axiom_denomination::print_if_tty("antie");

    // ── FIRST: verify this environment has 64-bit unix time (§31.3) ──
    // Core is the sole authority for platform safety. Since ANTIE
    // executes core-logic directly via AVM, the check must run here.
    axiom_core_logic::verify_time_safety();

    let cli = Cli::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("axiom_antie=info".parse().unwrap())
        )
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();
    
    // Handle --generate-config
    if cli.generate_config {
        if cli.imap {
            println!("# ANTIE IMAP + SMTP Config Example");
            println!("{}", AntieConfig::generate_imap_example());
        } else if cli.pop3 {
            println!("# ANTIE POP3 + SMTP Config Example");
            println!("{}", AntieConfig::generate_pop3_example());
        } else if cli.tcp {
            // --tcp flag kept for back-compat CLI surface; ANTIE no
            // longer runs a TCP listener (removed 2026-05-21). Falls
            // through to the maildir+advertise example.
            println!("# ANTIE Maildir + Advertise (TOT/FATMAMA) Config Example");
            println!("{}", AntieConfig::generate_advertise_example());
        } else if cli.all {
            println!("# ANTIE All-Carriers Config Example (kappa node)");
            println!("{}", AntieConfig::generate_all_carriers_example());
        } else {
            println!("# ANTIE Default Configuration (Maildir)");
            println!("{}", AntieConfig::generate_default());
        }
        return Ok(());
    }
    
    // Handle --init-maildir
    if let Some(path) = cli.init_maildir {
        init_maildir(&path).await?;
        return Ok(());
    }
    
    // Load config
    let mut config = if let Some(config_path) = cli.config {
        AntieConfig::load(&config_path)?
    } else {
        AntieConfig::default()
    };
    
    // Apply CLI overrides
    if let Some(lambda) = cli.lambda {
        // CLI --lambda flag sets TCP mode
        config.lambda = LambdaConfig::Tcp {
            address: lambda,
            timeout_secs: 30,
            tls_server_name: None,
            tls_ca_cert_path: None,
        };
    }
    
    // Print banner
    print_banner(&config);
    
    // Create and run gateway
    let gateway = Gateway::new(config).await?;

    // KI#23 mitigation — periodic glibc malloc_trim + SIGUSR1 handler.
    // See axiom_antie::malloc_trim for the why. Combined with the
    // MALLOC_ARENA_MAX=2 env var that axiom-env.py sets on spawn, this
    // is the in-process half of the glibc-arena-retention fix.
    axiom_antie::malloc_trim::spawn_periodic();
    if let Err(e) = axiom_antie::malloc_trim::install_sigusr1_handler() {
        warn!("malloc_trim SIGUSR1 handler failed to install: {e}");
    }

    // Handle Ctrl+C
    let gateway_ref = std::sync::Arc::new(gateway);
    let gateway_for_signal = gateway_ref.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Received Ctrl+C, shutting down...");
        gateway_for_signal.stop().await;
    });

    // Run gateway (multi-carrier JoinSet — consumes one Arc clone)
    gateway_ref.run().await?;
    
    Ok(())
}

fn print_banner(config: &AntieConfig) {
    println!();
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║               AXIOM ANTIE Gateway                         ║".cyan());
    println!("{}", "║         Multi-Carrier Transaction Gateway                 ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();

    println!("  {} Active carriers:", "Inbound:".green());
    if let Some(c) = &config.carriers.maildir {
        println!("    Maildir   inbox={}", c.inbox.display());
    }
    if let Some(c) = &config.carriers.imap {
        println!("    IMAP      {}:{} user={}", c.server, c.port, c.username);
    }
    if let Some(c) = &config.carriers.pop3 {
        println!("    POP3      {}:{} user={}", c.server, c.port, c.username);
    }
    if !config.carriers.advertise.is_empty() {
        println!("  {} Advertised (discovery URIs only — ANTIE doesn't parse):", "Hints:".green());
        for uri in &config.carriers.advertise {
            println!("    {}", uri);
        }
    }

    if let Some(s) = &config.outbound.smtp {
        println!("  {} SMTP {}:{} from={}",
            "Outbound:".green(), s.server, s.port, s.from_address);
    }

    match &config.lambda {
        LambdaConfig::Tcp { address, .. } => {
            println!("  {} {} (TCP)", "Lambda:".green(), address);
        }
        LambdaConfig::Subprocess { binary_path, .. } => {
            println!("  {} {:?} (Subprocess)", "Lambda:".green(), binary_path);
        }
    }
    println!("  {} {}", "Identity:".green(), config.identity.email);
    println!();
    println!("{}", "Architecture:".yellow());
    println!("  Carrier(s) → ANTIE → Core(CL2) → Lambda → Core(CL3) → Carrier(s)");
    println!();
    println!("{}", "Press Ctrl+C to stop".dimmed());
    println!();
}

async fn init_maildir(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "Initializing maildir structure...".cyan());
    
    // Create inbox
    let inbox = path.join("inbox");
    tokio::fs::create_dir_all(inbox.join("new")).await?;
    tokio::fs::create_dir_all(inbox.join("cur")).await?;
    tokio::fs::create_dir_all(inbox.join("tmp")).await?;
    println!("  {} {}", "✓".green(), inbox.display());
    
    // Create outbox
    let outbox = path.join("outbox");
    tokio::fs::create_dir_all(outbox.join("new")).await?;
    tokio::fs::create_dir_all(outbox.join("cur")).await?;
    tokio::fs::create_dir_all(outbox.join("tmp")).await?;
    println!("  {} {}", "✓".green(), outbox.display());
    
    // Find Lambda binary (try release first, then debug)
    let lambda_path = if std::path::Path::new("./axiom-lambda/target/release/lambda").exists() {
        std::path::PathBuf::from("./axiom-lambda/target/release/lambda")
    } else if std::path::Path::new("../axiom-lambda/target/release/lambda").exists() {
        std::path::PathBuf::from("../axiom-lambda/target/release/lambda")
    } else if std::path::Path::new("./target/release/lambda").exists() {
        std::path::PathBuf::from("./target/release/lambda")
    } else {
        std::path::PathBuf::from("./axiom-lambda/target/debug/lambda")
    };
    
    // Default Lambda config path (relative to project root, ANTIE runs from axiom-ANTIE/)
    let lambda_config_path = std::path::PathBuf::from("../config/lambda-config.toml");
    
    // Generate ANTIE config
    let config_path = path.join("antie.toml");
    let config = AntieConfig {
        carriers: CarriersConfig {
            maildir: Some(MaildirConfig {
                inbox,
                outbox,
            }),
            ..Default::default()
        },
        lambda: LambdaConfig::Subprocess {
            binary_path: lambda_path.clone(),
            config_path: lambda_config_path.clone(),
        },
        ..Default::default()
    };
    config.save(&config_path)?;
    println!("  {} {}", "✓".green(), config_path.display());
    println!("  {} Lambda binary: {:?}", "→".dimmed(), lambda_path);
    println!("  {} Lambda config: {:?}", "→".dimmed(), lambda_config_path);
    
    // Check if Lambda config exists
    if !lambda_config_path.exists() {
        println!();
        println!("{}", "⚠ Lambda config not found!".yellow());
        println!("  Please create: {}", lambda_config_path.display());
        println!("  See: config/lambda-config.toml for example");
    }
    
    println!();
    println!("{}", "Done! Run with:".green());
    println!("  antie --config {}", config_path.display());
    
    Ok(())
}
