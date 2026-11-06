use clap::{Parser, Subcommand};
use forge_command::{cmd, load_config};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    name = "forge",
    version,
    about = "Local-first developer security assessments"
)]
struct Cli {
    #[arg(long, global = true, default_value = ".forgerc.yaml")]
    config: PathBuf,
    #[command(subcommand)]
    command: TopCommand,
}
#[derive(Subcommand)]
enum TopCommand {
    Run {
        #[command(subcommand)]
        action: RunCommand,
    },
    Grade {
        #[command(subcommand)]
        action: GradeCommand,
    },
    Policy {
        #[command(subcommand)]
        action: PolicyCommand,
    },
}
#[derive(Subcommand)]
enum RunCommand {
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Ptest {
        url: String,
        #[arg(long)]
        json: bool,
    },
}
#[derive(Subcommand)]
enum GradeCommand {
    Risk {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
}
#[derive(Subcommand)]
enum PolicyCommand {
    Check {
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        command: Option<String>,
    },
}
fn main() {
    let cli = Cli::parse();
    let result = (|| -> Result<(), String> {
        let cfg = load_config(&cli.config)?;
        match cli.command {
            TopCommand::Run {
                action: RunCommand::Scan { path, json },
            } => cmd::scan::run(&path, &cfg.scan, json),
            TopCommand::Run {
                action: RunCommand::Ptest { url, json },
            } => cmd::ptest::run(&url, &cfg.dast, json),
            TopCommand::Grade {
                action: GradeCommand::Risk { path, json },
            } => cmd::grade::run(&path, &cfg.scan, json),
            TopCommand::Policy {
                action: PolicyCommand::Check { file, command },
            } => {
                if file.is_none() && command.is_none() {
                    return Err("specify --file and/or --command".into());
                }
                forge_command::governance::check(
                    file.as_deref(),
                    command.as_deref(),
                    &cfg.governance,
                )?;
                println!("ALLOW: policy checks passed");
                Ok(())
            }
        }
    })();
    if let Err(e) = result {
        eprintln!("forge: {e}");
        std::process::exit(1);
    }
}
