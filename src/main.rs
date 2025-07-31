mod backup;
mod cli;
mod commands;
mod crypto;
mod security;
mod storage;
mod totp;
mod transactions;
mod wallet;

use clap::Parser;
use anyhow::{Result, Context};

use cli::{Cli, print_banner, print_security_warning, clear_terminal};
use commands::CommandHandler;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Only show banner for wallet creation or when no specific command
    match &cli.command {
        cli::Commands::Create { .. } => {
            clear_terminal();
            print_banner();
            print_security_warning();
        }
        _ => {
            // For other commands, just clear without banner
            clear_terminal();
        }
    }
    
    let mut handler = CommandHandler::new()
        .context("Failed to initialize Ryzan wallet")?;
    
    handler.execute(cli.command)
        .await
        .context("Command execution failed")?;
    
    Ok(())
}
