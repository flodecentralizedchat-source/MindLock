use std::path::PathBuf;
use std::io::{self, BufRead};
use colored::Colorize;
use mindlock_core::wipe::wipe_file_payload;

pub struct WipeArgs {
    pub input: PathBuf,
    pub yes: bool,
}

pub async fn run(args: WipeArgs) -> anyhow::Result<()> {
    if !args.yes {
        eprint!("{} This will permanently destroy all content in {}. Type 'WIPE' to confirm: ",
            "WARNING".red().bold(),
            args.input.display());
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        if line.trim() != "WIPE" {
            println!("Aborted.");
            return Ok(());
        }
    }

    let report = wipe_file_payload(&args.input)?;
    println!("{} {report}", "WIPED".red().bold());
    Ok(())
}
