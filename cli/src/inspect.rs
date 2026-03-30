// inspect.rs
use std::path::PathBuf;
use colored::Colorize;
use mindlock_core::format::MindLockFile;

pub struct InspectArgs {
    pub input: PathBuf,
    pub format: String,
}

pub async fn run(args: InspectArgs) -> anyhow::Result<()> {
    let file = MindLockFile::load(&args.input)?;
    let h = &file.header;

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&h)?);
        return Ok(());
    }

    println!("{}", "── MindLock File ─────────────────────────────".bold());
    println!("  File ID      : {}", h.file_id);
    println!("  Label        : {}", h.label);
    println!("  Original     : {} ({})", h.original_filename, h.mime_type);
    println!("  Size         : {} bytes (plaintext)", h.plaintext_size);
    println!("  Created      : {} by {}", h.created_at.format("%Y-%m-%d %H:%M UTC"), h.created_by);
    println!("  Wiped        : {}", if h.wiped { "YES".red().to_string() } else { "no".green().to_string() });
    println!("  Has decoy    : {}", if h.has_decoy { "yes".yellow().to_string() } else { "no".dimmed().to_string() });
    println!("  Control srv  : {}", h.control_server.as_deref().unwrap_or("none (offline mode)"));

    println!("{}", "── Policy ────────────────────────────────────".bold());
    let p = &h.policy;
    println!("  Sensitivity  : {:?}", p.sensitivity);
    println!("  Max opens    : {}", p.max_opens.map(|n| n.to_string()).unwrap_or("unlimited".into()));
    println!("  Open count   : {}", p.open_count);
    println!("  Expires      : {}", p.expires_at.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or("never".into()));
    println!("  Device lock  : {}", p.enforce_device_trust);
    println!("  Trusted devs : {}", h.trusted_devices.len());
    println!("  Max failures : {}", p.max_failed_attempts.map(|n| n.to_string()).unwrap_or("unlimited".into()));
    println!("  Failed count : {}", p.failed_attempts);
    println!("  Decoy on fail: {}", p.decoy_on_fail);
    println!("  Behavior auth: {}", p.require_behavior_auth);
    println!("  Token gate   : {}", p.require_token_gate);

    if let Some(tg) = &h.token_gate {
        println!("{}", "── Token Gate ────────────────────────────────".bold());
        println!("  Chain ID     : {}", tg.chain_id);
        println!("  Contract     : {}", tg.token_contract);
        println!("  Min balance  : {}", tg.min_balance);
        println!("  Pay to open  : {}", tg.pay_to_open_wei.map(|n| format!("{n} wei")).unwrap_or("none".into()));
    }

    Ok(())
}
