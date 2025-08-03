use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ryzan")]
#[command(
    about = "Enterprise-grade security with zero-trust architecture - Professional crypto management made simple"
)]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(author = "Ryzan Team")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new secure wallet
    Create {
        /// Name for the wallet
        #[arg(long)]
        name: String,

        /// Enable TOTP authentication
        #[arg(long, default_value = "true")]
        totp: bool,

        /// Daily spending limit in lamports (default: 0.1 SOL)
        #[arg(long, default_value = "100000000")]
        daily_limit: u64,

        /// Time lock hours for large transactions
        #[arg(long)]
        time_lock: Option<u8>,
    },

    /// Unlock and use an existing wallet
    Unlock {
        /// Name of the wallet to unlock
        #[arg(long)]
        name: String,

        /// TOTP code for authentication
        #[arg(long)]
        totp: Option<String>,
    },

    /// Send SOL or SPL tokens to an address
    Send {
        /// Recipient address
        address: String,

        /// Amount to send
        amount: f64,

        /// TOTP code for transaction authorization
        #[arg(long)]
        totp: String,

        /// Optional memo
        #[arg(long)]
        memo: Option<String>,

        /// Use ephemeral keypair for privacy
        #[arg(long, default_value = "true")]
        ephemeral: bool,

        /// SPL token mint address (if sending tokens instead of SOL)
        #[arg(long)]
        token: Option<String>,
    },

    /// Generate a receive address
    Receive {
        /// Amount to request (optional)
        #[arg(long)]
        amount: Option<f64>,

        /// Generate QR code for payment
        #[arg(long, default_value = "false")]
        qr: bool,

        /// Use new ephemeral address
        #[arg(long, default_value = "true")]
        new_address: bool,
    },

    /// Send multiple transactions from a file
    BatchSend {
        /// Path to JSON file with transaction list
        #[arg(long)]
        file: String,

        /// TOTP code for batch authorization
        #[arg(long)]
        totp: String,
    },

    /// Stake SOL with a validator
    Stake {
        /// Validator vote account address
        validator: String,

        /// Amount to stake in SOL
        amount: f64,

        /// TOTP code for staking authorization
        #[arg(long)]
        totp: String,
    },

    /// Create encrypted backup of wallet
    Backup {
        /// Output file path
        #[arg(long)]
        output: String,

        /// TOTP code for backup authorization
        #[arg(long)]
        totp: String,
    },

    /// Recover wallet from backup file
    Recover {
        /// Backup file path
        #[arg(long)]
        file: String,

        /// New name for recovered wallet
        #[arg(long)]
        name: Option<String>,
    },

    /// Export private key (DANGEROUS)
    ExportKey {
        /// TOTP code for export authorization
        #[arg(long)]
        totp: String,

        /// Confirmation (must type "YES" exactly)
        #[arg(long)]
        confirm: String,
    },

    /// Set daily spending limit
    SetLimit {
        /// New daily limit in SOL
        #[arg(long)]
        daily: f64,

        /// TOTP code for limit change authorization
        #[arg(long)]
        totp: String,
    },

    /// Show wallet balance and information
    Balance {
        /// Name of the wallet to check balance for
        #[arg(long)]
        name: String,

        /// TOTP code for authentication
        #[arg(long)]
        totp: String,

        /// Show detailed breakdown
        #[arg(long, default_value = "false")]
        detailed: bool,
    },

    /// Show transaction history
    History {
        /// Number of transactions to show
        #[arg(long, default_value = "10")]
        limit: u32,

        /// Export to CSV file
        #[arg(long)]
        export: Option<String>,
    },

    /// Show portfolio information
    Portfolio {
        /// Show token balances
        #[arg(long, default_value = "false")]
        tokens: bool,

        /// Show staking information
        #[arg(long, default_value = "false")]
        staking: bool,
    },

    /// Swap tokens (DeFi integration)
    Swap {
        /// Token to swap from (e.g., "USDC")
        from: String,

        /// Token to swap to (e.g., "SOL")
        to: String,

        /// Amount to swap
        amount: f64,

        /// TOTP code for swap authorization
        #[arg(long)]
        totp: String,
    },

    /// List all wallets
    List,

    /// Delete a wallet (DANGEROUS)
    Delete {
        /// Name of wallet to delete
        #[arg(long)]
        name: String,

        /// TOTP code for deletion authorization
        #[arg(long)]
        totp: String,

        /// Confirmation (must type "DELETE" exactly)
        #[arg(long)]
        confirm: String,
    },

    /// Update ryzan to latest version
    Update,

    /// Panic mode - wipe all wallet data
    Panic {
        /// Emergency confirmation code
        #[arg(long)]
        emergency_code: String,
    },

    /// Configure settings
    Config {
        /// Set default RPC endpoint
        #[arg(long)]
        rpc: Option<String>,

        /// Set auto-lock timeout in minutes
        #[arg(long)]
        auto_lock: Option<u16>,

        /// Show current configuration
        #[arg(long, default_value = "false")]
        show: bool,
    },
}

pub fn print_banner() {
    println!(
        "\x1b[38;5;208m{}",
        r#"
██████╗ ██╗   ██╗███████╗ █████╗ ███╗   ██╗
██╔══██╗╚██╗ ██╔╝╚══███╔╝██╔══██╗████╗  ██║
██████╔╝ ╚████╔╝   ███╔╝ ███████║██╔██╗ ██║
██╔══██╗  ╚██╔╝   ███╔╝  ██╔══██║██║╚██╗██║
██║  ██║   ██║   ███████╗██║  ██║██║ ╚████║  
╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝  "#
    );
    println!("\x1b[38;5;214m⚡\x1b[0m");
    println!("\x1b[90m                                              \x1b[0m");
    println!("\x1b[38;5;208m    ⚡ Ultra-Secure Solana Wallet ⚡\x1b[0m");
    println!("\x1b[90m   Military-grade security with zero-trust architecture\x1b[0m");
    println!("\x1b[90m              Unbreakable crypto at $0 cost\x1b[0m");
    println!();
}

pub fn print_security_warning() {
    println!(
        "\x1b[38;5;240m┌─────────────────────────────────────────────────────────────┐\x1b[0m"
    );
    println!("\x1b[38;5;240m│\x1b[38;5;214m                    ⚠️  SECURITY NOTICE                     \x1b[38;5;240m│\x1b[0m");
    println!(
        "\x1b[38;5;240m├─────────────────────────────────────────────────────────────┤\x1b[0m"
    );
    println!(
        "\x1b[38;5;240m│                                                             │\x1b[0m"
    );
    println!("\x1b[38;5;240m│\x1b[38;5;208m •\x1b[0m Never share your password or TOTP codes                  \x1b[38;5;240m│\x1b[0m");
    println!("\x1b[38;5;240m│\x1b[38;5;208m •\x1b[0m Always verify recipient addresses                         \x1b[38;5;240m│\x1b[0m");
    println!("\x1b[38;5;240m│\x1b[38;5;208m •\x1b[0m Keep multiple backups in secure locations                \x1b[38;5;240m│\x1b[0m");
    println!("\x1b[38;5;240m│\x1b[38;5;208m •\x1b[0m This software is in early development                    \x1b[38;5;240m│\x1b[0m");
    println!(
        "\x1b[38;5;240m│                                                             │\x1b[0m"
    );
    println!(
        "\x1b[38;5;240m└─────────────────────────────────────────────────────────────┘\x1b[0m"
    );
    println!();
}

pub fn clear_terminal() {
    print!("\x1B[2J\x1B[1;1H");
    use std::io::{self, Write};
    let _ = io::stdout().flush();
}

pub fn print_operation_status(operation: &str, status: &str) {
    let (status_symbol, color) = match status {
        "success" => ("✅", "\x1b[38;5;82m"),
        "warning" => ("⚠️", "\x1b[38;5;214m"),
        "error" => ("❌", "\x1b[38;5;196m"),
        "info" => ("ℹ️", "\x1b[38;5;75m"),
        _ => ("🔄", "\x1b[38;5;208m"),
    };

    println!("{}{} {}\x1b[0m", color, status_symbol, operation);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        // Test create command
        let args = vec![
            "ryzan",
            "create",
            "--name",
            "test",
            "--daily-limit",
            "200000000",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Commands::Create {
                name, daily_limit, ..
            } => {
                assert_eq!(name, "test");
                assert_eq!(daily_limit, 200000000);
            }
            _ => panic!("Wrong command parsed"),
        }
    }
}
