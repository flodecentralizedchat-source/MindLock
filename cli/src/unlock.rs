use std::path::PathBuf;
use std::io::Write;
use colored::Colorize;
use hex;
use mindlock_core::{
    format::MindLockFile,
    rules::{AccessContext, AccessDecision, RulesEngine},
    wipe::wipe_file_payload,
};

pub struct UnlockArgs {
    pub input: PathBuf,
    pub output: Option<PathBuf>,
    pub stdout: bool,
    pub rpc: Option<String>,
    pub password: Option<String>,
}

pub async fn run(args: UnlockArgs) -> anyhow::Result<()> {
    let mut ml_file = MindLockFile::load(&args.input)?;

    // Wiped check — fast fail before any I/O
    if ml_file.is_wiped() {
        anyhow::bail!("This file has been permanently wiped. No data can be recovered.");
    }

    // Build access context
    let mut ctx = AccessContext::new(ml_file.header.trusted_devices.clone());

    // Phase 4: Token Gate
    if let Some(gate) = &ml_file.header.token_gate {
        println!("\n{}", "── Web3 Token Gate Check ─────────────────────".bold().cyan());
        println!("Contract: {}", gate.token_contract);
        println!("Min Balance: {}", gate.min_balance);
        
        print!("Enter your Ethereum wallet address: ");
        std::io::stdout().flush()?;
        let mut wallet = String::new();
        std::io::stdin().read_line(&mut wallet)?;
        let wallet = wallet.trim();

        if !wallet.is_empty() {
            let rpc_url = args.rpc.as_ref().unwrap_or(&gate.rpc_url);
            println!("Verifying on-chain balance via {}...", rpc_url);
            
            let mut gate_cfg = gate.clone();
            gate_cfg.rpc_url = rpc_url.clone();

            let ok = mindlock_web3::verify_web3_access(&gate_cfg, wallet, None, None).await?;
            if ok {
                println!("{} Token gate passed.", "✓".green());
                ctx.token_gate_ok = Some(true);
            } else {
                println!("{} Token gate failed (insufficient balance).", "✗".red());
                ctx.token_gate_ok = Some(false);
            }
        } else {
            ctx.token_gate_ok = Some(false);
        }
    }

    // Evaluate policy
    let decision = RulesEngine::evaluate(&ml_file.header.policy, &ctx);
    match decision {
        AccessDecision::Deny(reason) => {
            // Record failed attempt
            let should_wipe = ml_file.header.policy.record_failed();
            ml_file.save(&args.input)?;

            if should_wipe {
                eprintln!("{} Too many failed attempts — triggering self-destruct…", "WIPE".red().bold());
                wipe_file_payload(&args.input)?;
                eprintln!("{} File permanently wiped.", "DESTROYED".red().bold());
            }

            anyhow::bail!("Access denied: {reason}");
        }

        AccessDecision::Decoy => {
            eprintln!("{} (decoy mode active)", "◈".yellow());
            // Serve decoy content — attacker sees no difference
            if let Some(_decoy_blob) = &ml_file.decoy_payload {
                // Decoy password is not known to this unlock path (by design).
                // In Phase 3 the daemon provides it via the control server.
                // For now: serve generic decoy content.
                let content = mindlock_core::decoy::generate_decoy_content(
                    &ml_file.header.mime_type,
                    ml_file.header.plaintext_size,
                );
                write_output(&args, &ml_file.header.original_filename, &content)?;
            } else {
                anyhow::bail!("Access denied");
            }
            return Ok(());
        }

        AccessDecision::SelfDestruct => {
            wipe_file_payload(&args.input)?;
            anyhow::bail!("Self-destruct triggered. File has been wiped.");
        }

        AccessDecision::Grant => {} // proceed below
    }

    // ── Key Reconstruction ────────────────────────────────────────────────────
    
    let dk = if let Some(policy) = &ml_file.header.shard_policy {
        println!("\n{}", "── MPC Shard Collection ──────────────────────".bold().yellow());
        println!("This file is protected by Shamir's Secret Sharing.");
        println!("Requirement: {} of {} shards must be provided.", policy.threshold, policy.total_shards);
        
        let mut shards = Vec::new();
        for i in 1..=policy.threshold {
            let input = crate::prompt_password(&format!("Enter Shard {}/{} (hex): ", i, policy.threshold))?;
            let data = hex::decode(input.trim())
                .map_err(|_| anyhow::anyhow!("Invalid hex shard data"))?;
            
            // In a real implementation, we'd need to know the index of each shard.
            // For this CLI: we assume the user provides shard 1, 2... or we ask for the index.
            // Let's ask for the index too for robustness.
            println!("Enter index for this shard (1-{}): ", policy.total_shards);
            let mut idx_buf = String::new();
            std::io::stdin().read_line(&mut idx_buf)?;
            let index: u8 = idx_buf.trim().parse()?;

            shards.push(mindlock_core::format::KeyShard {
                index,
                data,
            });
        }

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&ml_file.payload.salt);
        
        mindlock_core::crypto::shamir::combine_shards(&shards, policy.threshold, salt)?
    } else {
        // Standard password flow
        let password = if let Some(p) = &args.password {
            p.clone()
        } else {
            crate::prompt_password("Password: ")?
        };
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&ml_file.payload.salt);
        mindlock_core::crypto::DerivedKey::from_password_and_salt(password.as_bytes(), &salt)?
    };

    // Attempt decrypt
    let plaintext = match mindlock_core::crypto::decrypt_with_key(&ml_file.payload, &dk) {
        Ok(p) => p,
        Err(_) => {
            // ... (rest of the error handling)
            let should_wipe = ml_file.header.policy.record_failed();
            ml_file.save(&args.input)?;

            if should_wipe {
                eprintln!("{} Self-destruct triggered.", "WIPE".red().bold());
                wipe_file_payload(&args.input)?;
            } else {
                eprintln!("{} {} attempts remaining before wipe",
                    "!".yellow(),
                    ml_file.header.policy.max_failed_attempts
                        .map(|m| m.saturating_sub(ml_file.header.policy.failed_attempts))
                        .unwrap_or(u32::MAX));
            }
            anyhow::bail!("Wrong password");
        }
    };

    // Record successful open
    ml_file.header.policy.record_open();
    ml_file.save(&args.input)?;

    // Write output
    write_output(&args, &ml_file.header.original_filename, &plaintext)?;

    eprintln!("{} Unlocked — open {} of {}",
        "✓".green().bold(),
        ml_file.header.policy.open_count,
        ml_file.header.policy.max_opens
            .map(|n| n.to_string())
            .unwrap_or("∞".into()));

    Ok(())
}

fn write_output(args: &UnlockArgs, original_filename: &str, data: &[u8]) -> anyhow::Result<()> {
    if args.stdout {
        std::io::stdout().write_all(data)?;
        return Ok(());
    }

    let out_path = args.output.clone().unwrap_or_else(|| {
        PathBuf::from(original_filename)
    });

    std::fs::write(&out_path, data)?;
    eprintln!("  Written: {}", out_path.display());
    Ok(())
}
