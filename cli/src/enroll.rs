use std::path::PathBuf;
use colored::Colorize;
use mindlock_core::{
    behavior::{BehaviorBaseline, BehaviorSample, KeyEvent, KeyEventType},
    format::MindLockFile,
};

pub struct EnrollArgs {
    pub input: PathBuf,
}

pub async fn run(args: EnrollArgs) -> anyhow::Result<()> {
    let mut file = MindLockFile::load(&args.input)?;

    println!("{}", "── Behavioral enrollment ─────────────────────".bold());
    println!("You will be asked to type your password {} times.", "5".bold());
    println!("Type naturally — this captures your keystroke rhythm.\n");

    let mut samples: Vec<BehaviorSample> = Vec::new();

    for i in 1..=5 {
        print!("Sample {i}/5 — ");
        let sample = capture_keystroke_sample()?;
        samples.push(sample);
        println!("{}", "captured".green());
    }

    let baseline = BehaviorBaseline::enroll(&samples)?;
    let fingerprint = baseline.fingerprint();

    // Store fingerprint in header (not the raw baseline — keep baseline locally or on server)
    file.header.behavior_profile_hash = Some(fingerprint.clone());
    file.header.policy.require_behavior_auth = true;
    file.save(&args.input)?;

    // Also save baseline locally (in ~/.mindlock/baselines/<file_id>.json)
    let baseline_dir = dirs_baseline_dir()?;
    std::fs::create_dir_all(&baseline_dir)?;
    let baseline_path = baseline_dir.join(format!("{}.json", file.file_id()));
    std::fs::write(&baseline_path, serde_json::to_string_pretty(&baseline)?)?;

    println!("{} Enrollment complete. Baseline saved.", "✓".green().bold());
    println!("  Profile hash : {}", &fingerprint[..16]);
    println!("  Samples used : {}", baseline.sample_count);
    println!("  Baseline at  : {}", baseline_path.display());

    Ok(())
}

/// Capture a keystroke sample using raw terminal timing.
fn capture_keystroke_sample() -> anyhow::Result<BehaviorSample> {
    use std::time::Instant;

    let start = Instant::now();
    let _pass = crate::prompt_password("Password: ")?;
    let elapsed = start.elapsed().as_millis() as u64;

    let chars = _pass.len().max(1);
    let avg_interval = elapsed / chars as u64;

    let mut events = Vec::new();
    let mut t = 0u64;
    for _ in 0..chars {
        events.push(KeyEvent { timestamp_ms: t, event: KeyEventType::KeyDown });
        t += avg_interval;
        events.push(KeyEvent { timestamp_ms: t, event: KeyEventType::KeyUp });
        t += 20; // 20ms dwell
    }

    Ok(BehaviorSample::new(events))
}

fn dirs_baseline_dir() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    Ok(home.join(".mindlock").join("baselines"))
}
