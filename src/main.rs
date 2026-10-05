mod browser_login;
mod client;
mod commands;
mod config;
mod credentials;
mod features;
mod interactive;
mod surface_patch;
mod surface_validate;
mod tables;
mod tool_gate_preview;

use anyhow::Result;
use clap::{CommandFactory, FromArgMatches};

use commands::{Cli, exit_code, run};

#[tokio::main]
async fn main() {
    if let Err(error) = execute().await {
        eprintln!("error: {error:#}");
        std::process::exit(exit_code(&error));
    }
}

async fn execute() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    for warning in commands::inline_secret_warnings(&args) {
        eprintln!("{warning}");
    }
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    // Once per run, here, because the interactive shell hands every line its
    // host and token as typed flags.
    if let Some(note) = commands::env_token_and_host_note(&matches) {
        eprintln!("{note}");
    }
    if cli.is_interactive() {
        interactive::run(cli).await
    } else {
        run(cli).await
    }
}
