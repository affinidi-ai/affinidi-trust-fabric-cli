mod browser_login;
mod client;
mod commands;
mod config;
mod credentials;
mod features;
mod interactive;
mod surface_patch;
mod surface_validate;

use anyhow::Result;
use clap::Parser;

use commands::{Cli, exit_code, run};

#[tokio::main]
async fn main() {
    if let Err(error) = execute().await {
        eprintln!("error: {error:#}");
        std::process::exit(exit_code(&error));
    }
}

async fn execute() -> Result<()> {
    let cli = Cli::parse();
    if cli.is_interactive() {
        interactive::run(cli).await
    } else {
        run(cli).await
    }
}
