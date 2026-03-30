use std::path::PathBuf;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use mindlock_core::{
    crypto::{encrypt, DeviceFingerprint},
    decoy::create_decoy_blob,
    format::{MindLockFile, MindLockHeader, TokenGateConfig, ShardPolicy},
    rules::{PolicyBuilder, SensitivityLevel},
    wipe::shred_file,
};
use mindlock_core::crypto::shamir::split_key;
use hex;
use chrono::{NaiveDate, TimeZone, Utc};

pub struct LockArgs {
    pub input: PathBuf,
    pub output: Option<PathBuf>,
    pub label: String,
    pub max_opens: Option<u32>,
    pub expires: Option<String>,
    pub device_lock: bool,
    pub max_fails: Option<u32>,
    pub decoy: bool,
    pub sensitivity: String,
    pub server: Option<String>,
    pub token_contract: Option<String>,
    pub min_balance: Option<u128>,
    pub rpc_url: Option<String>,
    pub threshold: Option<u8>,
    pub shards: Option<u8>,
    pub shred: bool,
    pub password: Option<String>,
}

pub async fn run(args: LockArgs) -> anyhow::Result<()> {
    // Read input
    let plaintext = std::fs::read(&args.input)?;
    let input_name = args.input.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let mime = mime_from_extension(&args.input);
    let size = plaintext.len() as u64;

    // Password
    let password = if let Some(p) = &args.password {
        p.clone()
    } else {
        let p = crate::prompt_password("Set lock password: ")?;
        let confirm  = crate::prompt_password("Confirm password: ")?;
        if p != confirm { anyhow::bail!("Passwords do not match"); }
        p
    };

    // Parse sensitivity
    let sensitivity = match args.sensitivity.to_lowercase().as_str() {
        "internal"     => SensitivityLevel::Internal,
        "confidential" => SensitivityLevel::Confidential,
        "topsecret"    => SensitivityLevel::TopSecret,
        _              => SensitivityLevel::Public,
    };

    // Build policy
    let mut pb = PolicyBuilder::default()
        .sensitivity(sensitivity)
        .decoy_on_fail(args.decoy)
        .enforce_device_trust(args.device_lock);

    if let Some(n) = args.max_opens {
        pb = pb.max_opens(n);
    }
    if let Some(n) = args.max_fails {
        pb = pb.max_failed_attempts(n);
    }
    if let Some(exp) = &args.expires {
        let date = NaiveDate::parse_from_str(exp, "%Y-%m-%d")
            .map_err(|_| anyhow::anyhow!("Invalid date format, use YYYY-MM-DD"))?;
        let dt = Utc.from_utc_datetime(&date.and_hms_opt(23, 59, 59).unwrap());
        pb = pb.expires_at(dt);
    }
    let policy = pb.build();

    // Build header
    let label = if args.label.is_empty() {
        input_name.to_string()
    } else {
        args.label.clone()
    };
    let mut header = MindLockHeader::new(label, input_name, &mime, size, whoami(), policy);
    header.control_server = args.server;

    // Token gate (Phase 4)
    if let (Some(contract), Some(min), Some(rpc)) = (args.token_contract, args.min_balance, args.rpc_url) {
        header.token_gate = Some(TokenGateConfig {
            chain_id: 137, // Default Polygon for Phase 4
            token_contract: contract,
            min_balance: min,
            pay_to_open_wei: None,
            rpc_url: rpc,
        });
        header.policy.require_token_gate = true;
    }

    // Shard policy (Phase 5)
    if let (Some(n), Some(k)) = (args.shards, args.threshold) {
        header.shard_policy = Some(ShardPolicy {
            total_shards: n,
            threshold: k,
        });
    }

    // Trust current device if requested
    if args.device_lock {
        header.trusted_devices.push(DeviceFingerprint::current());
    }

    // Progress bar
    let pb_bar = ProgressBar::new(3);
    pb_bar.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{bar:40.cyan/blue}] {msg}")
        .unwrap()
        .progress_chars("=>-"));

    pb_bar.set_message("Encrypting payload…");
    let blob = encrypt(&plaintext, password.as_bytes())?;
    pb_bar.inc(1);

    // Decoy blob
    let decoy_blob = if args.decoy {
        pb_bar.set_message("Generating decoy…");
        let decoy_pass = format!("{}-decoy-{}", &password[..password.len().min(8)], uuid::Uuid::new_v4());
        Some(create_decoy_blob(&mime, size, decoy_pass.as_bytes())?)
    } else {
        None
    };
    pb_bar.inc(1);

    // Assemble file
    let mut ml_file = MindLockFile::new(header, blob);
    if let Some(d) = decoy_blob {
        ml_file = ml_file.with_decoy(d);
    }

    // Output path
    let output_path = args.output.unwrap_or_else(|| {
        let mut p = args.input.clone();
        let new_name = format!("{}.mindlock", input_name);
        p.set_file_name(new_name);
        p
    });

    pb_bar.set_message("Writing .mindlock file…");
    ml_file.save(&output_path)?;
    pb_bar.inc(1);
    pb_bar.finish_and_clear();

    // If shredding was requested, securely wipe the original
    if args.shred {
        println!("{} Shredding original file: {}…", "SHRED".red().bold(), args.input.display());
        shred_file(&args.input)?;
        println!("{} Original file securely wiped.", "✓".green());
    }

    // If sharding was requested, generate and show shards
    if let (Some(n), Some(k)) = (args.shards, args.threshold) {
        // We need the raw DerivedKey to shard it.
        // For simplicity, we re-derive it here using the password.
        let salt: [u8; 32] = ml_file.payload.salt.clone().try_into()
            .map_err(|_| anyhow::anyhow!("Invalid salt length in .mindlock file"))?;
        let dk = mindlock_core::crypto::DerivedKey::from_password_and_salt(
            password.as_bytes(), 
            &salt
        )?;
        let shards = split_key(&dk, k, n)?;

        println!("\n{}", "── MPC Key Shards Generated ──────────────────".bold().yellow());
        println!("  Threshold: {} of {} shards required", k, n);
        for s in shards {
            println!("\n{} {}:", "Shard".bold(), s.index);
            println!("{}", hex::encode(s.data).cyan());
        }
        println!("\n{}", "Keep these shards safe! You will need them to unlock.".bold());
    }

    println!("{} Locked: {}", "✓".green().bold(), output_path.display());
    println!("  File ID : {}", ml_file.file_id());
    println!("  Size    : {} → {} bytes (encrypted)",
        size,
        std::fs::metadata(&output_path)?.len());
    if args.decoy { println!("  Decoy   : {}", "enabled".yellow()); }
    if args.device_lock { println!("  Device  : {}", "locked to current device".yellow()); }

    Ok(())
}

fn mime_from_extension(path: &PathBuf) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("pdf")  => "application/pdf",
        Some("txt")  => "text/plain",
        Some("json") => "application/json",
        Some("csv")  => "text/csv",
        Some("png")  => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Some("zip")  => "application/zip",
        _            => "application/octet-stream",
    }.to_string()
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into())
}
