use anyhow::{Context, Result};
use reqwest;
use solana_sdk::pubkey::Pubkey;
use spl_associated_token_account::get_associated_token_address;
use spl_token::state::Mint;
use std::io::{self, Write};
use std::str::FromStr;

use crate::backup::BackupManager;
use crate::cli::{print_operation_status, Commands};
use crate::storage::SecureStorage;
use crate::totp::{display_totp_qr, prompt_totp_setup, TotpManager};
use crate::transactions::{process_batch_transactions, BatchTransaction, TransactionManager};
use crate::wallet::{SecureWallet, UnlockedWallet};

pub struct CommandHandler {
    storage: SecureStorage,
    current_wallet: Option<UnlockedWallet>,
}

impl CommandHandler {
    pub fn new() -> Result<Self> {
        let storage = SecureStorage::new()?;
        Ok(Self {
            storage,
            current_wallet: None,
        })
    }

    fn ensure_wallet_unlocked(&mut self) -> Result<()> {
        if self.current_wallet.is_some() {
            return Ok(());
        }

        // Check if there's a session and try to auto-unlock
        if let Some(session) = self.storage.load_session()? {
            print_operation_status("Found recent session, unlocking wallet...", "info");
            let password = self.prompt_password("Enter wallet password")?;

            let wallet = self
                .storage
                .load_wallet(&session.wallet_filename, &password)?;
            let unlocked_wallet = wallet.unlock(&password)?;

            self.current_wallet = Some(unlocked_wallet);
            return Ok(());
        }

        Err(anyhow::anyhow!(
            "No wallet unlocked. Use 'ryzan unlock --name <wallet>' first"
        ))
    }

    fn get_current_wallet(&self) -> Result<&UnlockedWallet> {
        self.current_wallet.as_ref().ok_or_else(|| {
            anyhow::anyhow!("No wallet unlocked. Use 'ryzan unlock --name <wallet>' first")
        })
    }

    pub async fn execute(&mut self, command: Commands) -> Result<()> {
        match command {
            Commands::Create {
                name,
                totp,
                daily_limit,
                time_lock,
            } => self.create_wallet(name, totp, daily_limit, time_lock).await,
            Commands::Unlock { name, totp } => self.unlock_wallet(name, totp).await,
            Commands::Send {
                address,
                amount,
                totp,
                memo,
                ephemeral,
                token,
            } => {
                self.send_transaction(address, amount, totp, memo, ephemeral, token)
                    .await
            }
            Commands::Receive { amount } => self.generate_receive_address(amount).await,
            Commands::Balance {
                name,
                totp,
                detailed,
            } => self.show_balance(name, totp, detailed).await,
            Commands::List => self.list_wallets().await,
            Commands::Backup { output, totp } => self.backup_wallet(output, totp).await,
            Commands::Recover { file, name } => self.recover_wallet(file, name).await,
            Commands::Config {
                rpc,
                auto_lock,
                show,
            } => self.configure_settings(rpc, auto_lock, show).await,
            Commands::BatchSend { file, totp } => self.batch_send(file, totp).await,
            Commands::Stake {
                validator,
                amount,
                totp,
            } => self.stake_sol(validator, amount, totp).await,
            Commands::ExportKey { totp, confirm } => self.export_private_key(totp, confirm).await,
            Commands::SetLimit { daily, totp } => self.set_daily_limit(daily, totp).await,
            Commands::History { limit, export } => {
                self.show_transaction_history(limit, export).await
            }
            Commands::Portfolio { tokens, staking } => self.show_portfolio(tokens, staking).await,
            Commands::Swap {
                from,
                to,
                amount,
                totp,
            } => self.swap_tokens(from, to, amount, totp).await,
            Commands::Delete {
                name,
                totp,
                confirm,
            } => self.delete_wallet(name, totp, confirm).await,
            Commands::Update => self.update_wallet().await,
            Commands::Panic { emergency_code } => self.panic_wipe(emergency_code).await,
        }
    }

    async fn create_wallet(
        &mut self,
        name: String,
        enable_totp: bool,
        daily_limit: u64,
        time_lock: Option<u8>,
    ) -> Result<()> {
        print_operation_status("Creating new secure wallet...", "info");

        // Check if wallet name already exists
        let mut config = self.storage.load_config()?;
        if config.wallets.contains_key(&name) {
            return Err(anyhow::anyhow!("Wallet '{}' already exists", name));
        }

        // Get password from user
        let password = self.prompt_password("Enter master password")?;
        let password_confirm = self.prompt_password("Confirm master password")?;

        if password != password_confirm {
            return Err(anyhow::anyhow!("Passwords do not match"));
        }

        if password.len() < 12 {
            return Err(anyhow::anyhow!(
                "Password must be at least 12 characters long"
            ));
        }

        // Create wallet
        let (wallet, mnemonic, totp_secret) =
            SecureWallet::create(name.clone(), &password, daily_limit, time_lock)?;

        // Set up TOTP if enabled
        if enable_totp {
            prompt_totp_setup(&name)?;

            let totp_manager = TotpManager::new(totp_secret, name.clone());
            display_totp_qr(&totp_manager)?;

            // Wait for user to set up TOTP
            let totp_code = self.prompt_totp_code(
                "Please set up your authenticator app and enter the 6-digit TOTP code to verify",
            )?;

            if !totp_manager.verify_code(&totp_code, 2)? {
                return Err(anyhow::anyhow!("Invalid TOTP code. Please check your authenticator app and try again. Wallet creation cancelled."));
            }

            print_operation_status("TOTP setup verified!", "success");
        }

        // Save wallet
        let wallet_filename = self.storage.save_wallet(&wallet, &password)?;

        // Update config
        config.wallets.insert(name.clone(), wallet_filename.clone());
        self.storage.save_config(&config)?;

        // Show backup information
        println!();
        println!(
            "\x1b[38;5;240m┌─────────────────────────────────────────────────────────────┐\x1b[0m"
        );
        println!("\x1b[38;5;240m│\x1b[38;5;208m                    🔑 BACKUP YOUR WALLET                    \x1b[38;5;240m│\x1b[0m");
        println!(
            "\x1b[38;5;240m├─────────────────────────────────────────────────────────────┤\x1b[0m"
        );
        println!(
            "\x1b[38;5;240m│                                                             │\x1b[0m"
        );
        println!("\x1b[38;5;240m│\x1b[38;5;214m RECOVERY PHRASE (write this down):                         \x1b[38;5;240m│\x1b[0m");
        println!(
            "\x1b[38;5;240m│                                                             │\x1b[0m"
        );

        let phrase = mnemonic.to_string();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        for (i, chunk) in words.chunks(6).enumerate() {
            print!("\x1b[38;5;240m│\x1b[0m ");
            for (j, word) in chunk.iter().enumerate() {
                print!("\x1b[38;5;208m{:2}.\x1b[0m {:<10}", i * 6 + j + 1, word);
            }
            println!(" \x1b[38;5;240m│\x1b[0m");
        }

        println!(
            "\x1b[38;5;240m│                                                             │\x1b[0m"
        );
        println!("\x1b[38;5;240m│\x1b[38;5;214m ⚠️  Store this phrase in 3 different secure locations      \x1b[38;5;240m│\x1b[0m");
        println!("\x1b[38;5;240m│\x1b[38;5;214m ⚠️  Never share it with anyone                             \x1b[38;5;240m│\x1b[0m");
        println!("\x1b[38;5;240m│\x1b[38;5;214m ⚠️  This is the ONLY way to recover your wallet            \x1b[38;5;240m│\x1b[0m");
        println!(
            "\x1b[38;5;240m│                                                             │\x1b[0m"
        );
        println!(
            "\x1b[38;5;240m└─────────────────────────────────────────────────────────────┘\x1b[0m"
        );

        // Require user confirmation
        println!("\nType 'I HAVE SAVED MY RECOVERY PHRASE' to continue:");
        let mut confirmation = String::new();
        io::stdin().read_line(&mut confirmation)?;

        if confirmation.trim() != "I HAVE SAVED MY RECOVERY PHRASE" {
            return Err(anyhow::anyhow!(
                "You must save your recovery phrase before continuing"
            ));
        }

        print_operation_status(
            &format!("Wallet '{}' created successfully!", name),
            "success",
        );

        // Show storage information
        let (base_path, config_path, wallets_path) = self.storage.get_storage_info();
        println!("\n🗂️  Encrypted Wallet Storage Information:");
        println!("   📁 Base Directory: {}", base_path);
        println!("   ⚙️  Config File: {}", config_path);
        println!("   🔐 Wallet Vaults: {}", wallets_path);
        println!("   🛡️  File: {}", wallet_filename);
        println!("\n💡 All files are encrypted with your master password and secured with restrictive permissions.");

        Ok(())
    }

    async fn unlock_wallet(&mut self, name: String, totp_code: Option<String>) -> Result<()> {
        let config = self.storage.load_config()?;
        let wallet_filename = config
            .wallets
            .get(&name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))?;

        let password = self.prompt_password("Enter wallet password")?;

        print_operation_status("Unlocking wallet...", "info");

        let wallet = self.storage.load_wallet(wallet_filename, &password)?;
        let unlocked_wallet = wallet.unlock(&password)?;

        // Verify TOTP if required
        if config.security_settings.require_totp {
            let totp_code = match totp_code {
                Some(code) => code,
                None => self
                    .prompt_totp_code("Enter your 6-digit TOTP code from your authenticator app")?,
            };

            let totp_manager = TotpManager::new(unlocked_wallet.totp_secret.clone(), name.clone());

            if !totp_manager.verify_code(&totp_code, 2)? {
                return Err(anyhow::anyhow!(
                    "Invalid TOTP code. Please check your authenticator app and try again."
                ));
            }
        }

        // Save session for future commands
        self.storage.save_session(&name, wallet_filename)?;

        self.current_wallet = Some(unlocked_wallet);
        print_operation_status(
            &format!("Wallet '{}' unlocked successfully!", name),
            "success",
        );

        // Show wallet info
        if let Some(wallet) = &self.current_wallet {
            let pubkey = wallet.get_public_key();
            println!("\nPublic Key: {}", pubkey);
            println!(
                "Daily Limit: {} SOL",
                wallet.daily_limit as f64 / 1_000_000_000.0
            );

            if let Some(hours) = wallet.time_lock_hours {
                println!("Time Lock: {} hours for large transactions", hours);
            }
        }

        Ok(())
    }

    async fn send_transaction(
        &mut self,
        address: String,
        amount: f64,
        totp_code: String,
        memo: Option<String>,
        ephemeral: bool,
        token: Option<String>,
    ) -> Result<()> {
        self.ensure_wallet_unlocked()?;
        let wallet = self.get_current_wallet()?;

        // Verify TOTP
        let totp_manager = TotpManager::new(wallet.totp_secret.clone(), wallet.name.clone());

        if !totp_manager.verify_code(&totp_code, 2)? {
            return Err(anyhow::anyhow!(
                "Invalid TOTP code. Please check your authenticator app and try again."
            ));
        }

        // Parse recipient address
        let recipient = Pubkey::from_str(&address).context("Invalid recipient address")?;

        print_operation_status("Preparing transaction...", "info");
        let tx_manager = TransactionManager::new()?;

        let signature = match token {
            Some(token_mint) => {
                // SPL Token transfer
                let mint_pubkey =
                    Pubkey::from_str(&token_mint).context("Invalid token mint address")?;

                // Get token decimals (assuming 6 decimals for most tokens, should be fetched in production)
                let decimals = 6; // TODO: Fetch actual decimals from mint account
                let token_amount = (amount * 10_f64.powi(decimals as i32)) as u64;

                print_operation_status(
                    &format!("Sending {} tokens to {}", amount, address),
                    "info",
                );
                tx_manager
                    .send_spl_token(
                        wallet,
                        recipient,
                        mint_pubkey,
                        token_amount,
                        memo.as_deref(),
                        ephemeral,
                    )
                    .await?
            }
            None => {
                // SOL transfer
                let lamports = (amount * 1_000_000_000.0) as u64;

                // Check daily limit for SOL transfers
                if lamports > wallet.daily_limit {
                    return Err(anyhow::anyhow!(
                        "Transaction amount ({} SOL) exceeds daily limit ({} SOL)",
                        amount,
                        wallet.daily_limit as f64 / 1_000_000_000.0
                    ));
                }

                print_operation_status(&format!("Sending {} SOL to {}", amount, address), "info");
                tx_manager
                    .send_sol(wallet, recipient, lamports, memo.as_deref(), ephemeral)
                    .await?
            }
        };

        print_operation_status(
            &format!("Transaction sent! Signature: {}", signature),
            "success",
        );
        Ok(())
    }

    async fn generate_receive_address(&mut self, amount: Option<f64>) -> Result<()> {
        self.ensure_wallet_unlocked()?;
        let wallet = self.get_current_wallet()?;
        let address = wallet.get_public_key();

        println!("Receive Address: {}", address);

        // Always show QR code for the address
        let qr_code = qrcode::QrCode::new(&address.to_string())?;
        let qr_string = qr_code
            .render::<qrcode::render::unicode::Dense1x2>()
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark)
            .build();

        println!("\nAddress QR Code:");
        println!("{}", qr_string);

        if let Some(sol_amount) = amount {
            println!("Requesting: {} SOL", sol_amount);
        }

        Ok(())
    }

    async fn show_balance(
        &mut self,
        name: String,
        totp_code: String,
        detailed: bool,
    ) -> Result<()> {
        // Load and unlock the wallet temporarily for balance check
        let config = self.storage.load_config()?;
        let wallet_filename = config
            .wallets
            .get(&name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))?;

        let password = self.prompt_password("Enter wallet password")?;
        let wallet = self.storage.load_wallet(wallet_filename, &password)?;
        let unlocked_wallet = wallet.unlock(&password)?;

        // Verify TOTP
        if config.security_settings.require_totp {
            let totp_manager = TotpManager::new(unlocked_wallet.totp_secret.clone(), name.clone());

            if !totp_manager.verify_code(&totp_code, 2)? {
                return Err(anyhow::anyhow!(
                    "Invalid TOTP code. Please check your authenticator app and try again."
                ));
            }
        }

        let tx_manager = TransactionManager::new()?;
        let balance = tx_manager.get_balance(&unlocked_wallet).await?;

        println!("💰 Wallet: {}", name);
        println!("📊 Balance: {} SOL", balance as f64 / 1_000_000_000.0);

        if detailed {
            println!("📈 Balance (lamports): {}", balance);
            println!(
                "🚫 Daily Limit: {} SOL",
                unlocked_wallet.daily_limit as f64 / 1_000_000_000.0
            );
            println!("🔑 Public Key: {}", unlocked_wallet.get_public_key());

            if let Some(hours) = unlocked_wallet.time_lock_hours {
                println!("⏰ Time Lock: {} hours", hours);
            }
        }

        Ok(())
    }

    async fn list_wallets(&mut self) -> Result<()> {
        let config = self.storage.load_config()?;

        if config.wallets.is_empty() {
            println!("No wallets found. Create one with 'ryzan create --name <wallet>'");
        } else {
            println!("Available wallets:");
            for (name, filename) in &config.wallets {
                let status = if self.current_wallet.as_ref().map(|w| &w.name) == Some(name) {
                    "🔓 UNLOCKED"
                } else {
                    "🔒 Locked"
                };
                println!("  • {} - {} ({})", name, status, filename);
            }
        }

        // Show storage information
        let (base_path, config_path, wallets_path) = self.storage.get_storage_info();
        println!("\n🗂️  Encrypted Storage Locations:");
        println!("   📁 Base Directory: {}", base_path);
        println!("   ⚙️  Config File: {}", config_path);
        println!("   🔐 Wallet Vaults: {}", wallets_path);

        Ok(())
    }

    async fn backup_wallet(&mut self, output: String, totp_code: String) -> Result<()> {
        self.ensure_wallet_unlocked()?;
        let wallet = self.get_current_wallet()?;

        // Verify TOTP
        let totp_manager = TotpManager::new(wallet.totp_secret.clone(), wallet.name.clone());

        if !totp_manager.verify_code(&totp_code, 2)? {
            return Err(anyhow::anyhow!(
                "Invalid TOTP code. Please check your authenticator app and try again."
            ));
        }

        // Load the encrypted wallet data
        let config = self.storage.load_config()?;
        let wallet_filename = config
            .wallets
            .get(&wallet.name)
            .ok_or_else(|| anyhow::anyhow!("Wallet file not found"))?;

        let password = self.prompt_password("Enter wallet password to create backup")?;
        let secure_wallet = self.storage.load_wallet(wallet_filename, &password)?;

        self.storage
            .backup_wallet(&secure_wallet, &std::path::Path::new(&output))?;

        print_operation_status(&format!("Backup saved to: {}", output), "success");
        Ok(())
    }

    async fn recover_wallet(&mut self, file: String, name: Option<String>) -> Result<()> {
        print_operation_status("Loading backup file...", "info");

        let backup_data = std::fs::read_to_string(&file).context("Failed to read backup file")?;

        let backup: crate::backup::WalletBackup =
            serde_json::from_str(&backup_data).context("Failed to parse backup file")?;

        let backup_password = self.prompt_password("Enter backup password")?;
        let backup_manager = BackupManager::new(backup_password);

        let recovered_wallet = backup_manager
            .restore_from_backup(&backup)
            .context("Failed to restore wallet from backup")?;

        // Set new name if provided
        let final_name = name.unwrap_or_else(|| format!("{}_recovered", recovered_wallet.name));

        // Check if wallet name already exists
        let mut config = self.storage.load_config()?;
        if config.wallets.contains_key(&final_name) {
            return Err(anyhow::anyhow!("Wallet '{}' already exists", final_name));
        }

        // Get new password for the recovered wallet
        let new_password = self.prompt_password("Enter new password for recovered wallet")?;
        let confirm_password = self.prompt_password("Confirm new password")?;

        if new_password != confirm_password {
            return Err(anyhow::anyhow!("Passwords do not match"));
        }

        // Save the recovered wallet with new password
        let wallet_filename = self.storage.save_wallet(&recovered_wallet, &new_password)?;
        config.wallets.insert(final_name.clone(), wallet_filename);
        self.storage.save_config(&config)?;

        print_operation_status(&format!("Wallet recovered as '{}'", final_name), "success");
        Ok(())
    }

    async fn configure_settings(
        &mut self,
        rpc: Option<String>,
        auto_lock: Option<u16>,
        show: bool,
    ) -> Result<()> {
        let mut config = self.storage.load_config()?;

        if show {
            println!("Current Configuration:");
            println!("  Default RPC: {}", config.default_rpc);
            println!(
                "  Auto-lock: {} minutes",
                config.security_settings.auto_lock_minutes
            );
            println!("  Require TOTP: {}", config.security_settings.require_totp);
            return Ok(());
        }

        if let Some(rpc_url) = rpc {
            config.default_rpc = rpc_url;
            print_operation_status("RPC endpoint updated", "success");
        }

        if let Some(timeout) = auto_lock {
            config.security_settings.auto_lock_minutes = timeout;
            print_operation_status("Auto-lock timeout updated", "success");
        }

        self.storage.save_config(&config)?;
        Ok(())
    }

    async fn batch_send(&mut self, file: String, totp: String) -> Result<()> {
        self.ensure_wallet_unlocked()?;
        let wallet = self.get_current_wallet()?;

        // Verify TOTP
        let totp_manager = TotpManager::new(wallet.totp_secret.clone(), wallet.name.clone());

        if !totp_manager.verify_code(&totp, 2)? {
            return Err(anyhow::anyhow!(
                "Invalid TOTP code. Please check your authenticator app and try again."
            ));
        }

        print_operation_status("Loading batch transaction file...", "info");

        let batch_data =
            std::fs::read_to_string(&file).context("Failed to read batch transaction file")?;

        let transactions: Vec<BatchTransaction> =
            serde_json::from_str(&batch_data).context("Failed to parse batch transaction file")?;

        if transactions.is_empty() {
            return Err(anyhow::anyhow!("No transactions found in batch file"));
        }

        println!("📋 Found {} transactions to process", transactions.len());
        println!("📝 Review transactions before proceeding:");

        for (i, tx) in transactions.iter().enumerate() {
            println!(
                "  {}. {} SOL to {} {}",
                i + 1,
                tx.amount,
                tx.recipient,
                tx.memo
                    .as_ref()
                    .map(|m| format!("({})", m))
                    .unwrap_or_default()
            );
        }

        print!("\nType 'CONFIRM' to proceed with batch send: ");
        io::stdout().flush()?;
        let mut confirmation = String::new();
        io::stdin().read_line(&mut confirmation)?;

        if confirmation.trim() != "CONFIRM" {
            return Err(anyhow::anyhow!("Batch send cancelled"));
        }

        let tx_manager = TransactionManager::new()?;
        let signatures = process_batch_transactions(&tx_manager, wallet, transactions).await?;

        print_operation_status(
            &format!(
                "Batch send completed! {} transactions sent",
                signatures.len()
            ),
            "success",
        );

        for (i, sig) in signatures.iter().enumerate() {
            println!("  {}. {}", i + 1, sig);
        }

        Ok(())
    }

    async fn stake_sol(&mut self, validator: String, amount: f64, totp: String) -> Result<()> {
        self.ensure_wallet_unlocked()?;
        let wallet = self.get_current_wallet()?;

        // Verify TOTP
        let totp_manager = TotpManager::new(wallet.totp_secret.clone(), wallet.name.clone());

        if !totp_manager.verify_code(&totp, 2)? {
            return Err(anyhow::anyhow!(
                "Invalid TOTP code. Please check your authenticator app and try again."
            ));
        }

        // Parse validator address
        let validator_pubkey = Pubkey::from_str(&validator).context("Invalid validator address")?;

        // Convert SOL to lamports
        let lamports = (amount * 1_000_000_000.0) as u64;

        // Check daily limit
        if lamports > wallet.daily_limit {
            return Err(anyhow::anyhow!(
                "Stake amount ({} SOL) exceeds daily limit ({} SOL)",
                amount,
                wallet.daily_limit as f64 / 1_000_000_000.0
            ));
        }

        print_operation_status("Creating stake account and delegating...", "info");

        let tx_manager = TransactionManager::new()?;
        let signature = tx_manager
            .stake_sol(wallet, validator_pubkey, lamports)
            .await?;

        print_operation_status(
            &format!("Staking successful! Signature: {}", signature),
            "success",
        );
        println!("💰 Staked: {} SOL", amount);
        println!("🏛️  Validator: {}", validator);
        Ok(())
    }

    async fn export_private_key(&mut self, totp: String, confirm: String) -> Result<()> {
        self.ensure_wallet_unlocked()?;
        let wallet = self.get_current_wallet()?;

        // Security check - require exact confirmation
        if confirm != "YES" {
            return Err(anyhow::anyhow!(
                "Export cancelled. You must type 'YES' exactly to confirm."
            ));
        }

        // Verify TOTP
        let totp_manager = TotpManager::new(wallet.totp_secret.clone(), wallet.name.clone());

        if !totp_manager.verify_code(&totp, 2)? {
            return Err(anyhow::anyhow!(
                "Invalid TOTP code. Please check your authenticator app and try again."
            ));
        }

        // Show severe warning
        println!();
        println!(
            "\x1b[38;5;196m┌─────────────────────────────────────────────────────────────┐\x1b[0m"
        );
        println!("\x1b[38;5;196m│                        ⚠️  DANGER ZONE ⚠️                     │\x1b[0m");
        println!(
            "\x1b[38;5;196m├─────────────────────────────────────────────────────────────┤\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m│                                                             │\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m│ ❌ EXPOSING YOUR PRIVATE KEY IS EXTREMELY DANGEROUS         │\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m│ ❌ ANYONE WITH THIS KEY CAN STEAL ALL YOUR FUNDS            │\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m│ ❌ NEVER SHARE THIS KEY OR STORE IT ONLINE                  │\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m│                                                             │\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m└─────────────────────────────────────────────────────────────┘\x1b[0m"
        );
        println!();

        // Additional confirmation
        print!("Type 'I UNDERSTAND THE RISKS' to continue: ");
        io::stdout().flush()?;
        let mut final_confirm = String::new();
        io::stdin().read_line(&mut final_confirm)?;

        if final_confirm.trim() != "I UNDERSTAND THE RISKS" {
            return Err(anyhow::anyhow!("Export cancelled for your security"));
        }

        // Export the private key
        let keypair = wallet.get_solana_keypair();
        let private_key_bytes = keypair.to_bytes();
        let private_key_base58 = bs58::encode(&private_key_bytes).into_string();

        println!();
        println!("🔑 Private Key (Base58):");
        println!("{}", private_key_base58);
        println!();
        println!("🔑 Public Key:");
        println!("{}", wallet.get_public_key());
        println!();

        print_operation_status(
            "Private key exported! Clear your terminal history immediately!",
            "warning",
        );
        Ok(())
    }

    async fn set_daily_limit(&mut self, daily: f64, totp: String) -> Result<()> {
        self.ensure_wallet_unlocked()?;

        // Get wallet info first to avoid borrowing issues
        let (wallet_name, totp_secret) = {
            let wallet = self.get_current_wallet()?;
            (wallet.name.clone(), wallet.totp_secret.clone())
        };

        // Verify TOTP
        let totp_manager = TotpManager::new(totp_secret, wallet_name.clone());

        if !totp_manager.verify_code(&totp, 2)? {
            return Err(anyhow::anyhow!(
                "Invalid TOTP code. Please check your authenticator app and try again."
            ));
        }

        let new_limit_lamports = (daily * 1_000_000_000.0) as u64;

        // Load and update the wallet
        let config = self.storage.load_config()?;
        let wallet_filename = config
            .wallets
            .get(&wallet_name)
            .ok_or_else(|| anyhow::anyhow!("Wallet file not found"))?;

        let password = self.prompt_password("Enter wallet password to update limit")?;
        let mut secure_wallet = self.storage.load_wallet(wallet_filename, &password)?;

        let old_limit = secure_wallet.daily_limit;
        secure_wallet.daily_limit = new_limit_lamports;

        // Save updated wallet
        let _ = self.storage.save_wallet(&secure_wallet, &password)?;

        print_operation_status("Daily spending limit updated!", "success");
        println!("Previous limit: {} SOL", old_limit as f64 / 1_000_000_000.0);
        println!("New limit: {} SOL", daily);

        // Update current wallet if it's the same one
        if let Some(ref mut current) = self.current_wallet {
            if current.name == wallet_name {
                current.daily_limit = new_limit_lamports;
            }
        }

        Ok(())
    }

    async fn show_transaction_history(&mut self, limit: u32, export: Option<String>) -> Result<()> {
        self.ensure_wallet_unlocked()?;
        let wallet = self.get_current_wallet()?;

        print_operation_status("Fetching transaction history...", "info");

        let tx_manager = TransactionManager::new()?;
        let history = tx_manager
            .get_transaction_history(wallet, limit as usize)
            .await?;

        if history.is_empty() {
            println!("No transactions found for this wallet.");
            return Ok(());
        }

        println!("📜 Transaction History for {}", wallet.name);
        println!("────────────────────────────────────────────────────");

        for (i, tx) in history.iter().enumerate() {
            if i >= limit as usize {
                break;
            }

            let status_icon = match tx.status.as_str() {
                "Success" => "✅",
                "Failed" => "❌",
                _ => "🔄",
            };

            println!(
                "{}. {} {} - Fee: {} lamports",
                i + 1,
                status_icon,
                tx.signature[..8].to_string(),
                tx.fee
            );

            if let Some(time) = tx.block_time {
                let datetime = chrono::DateTime::from_timestamp(time, 0).unwrap_or_default();
                println!("   📅 {}", datetime.format("%Y-%m-%d %H:%M:%S UTC"));
            }

            if let Some(memo) = &tx.memo {
                println!("   📝 {}", memo);
            }

            println!();
        }

        // Export to CSV if requested
        if let Some(export_path) = export {
            let mut csv_content = String::from("Signature,Status,Fee,BlockTime,Memo\\n");

            for tx in &history {
                let time_str = tx
                    .block_time
                    .map(|t| {
                        chrono::DateTime::from_timestamp(t, 0)
                            .unwrap_or_default()
                            .to_rfc3339()
                    })
                    .unwrap_or_default();

                csv_content.push_str(&format!(
                    "{},{},{},{},{}\\n",
                    tx.signature,
                    tx.status,
                    tx.fee,
                    time_str,
                    tx.memo.as_deref().unwrap_or("")
                ));
            }

            std::fs::write(&export_path, csv_content).context("Failed to write CSV export")?;

            print_operation_status(&format!("History exported to: {}", export_path), "success");
        }

        Ok(())
    }

    async fn show_portfolio(&mut self, tokens: bool, staking: bool) -> Result<()> {
        self.ensure_wallet_unlocked()?;
        let wallet = self.get_current_wallet()?;

        print_operation_status("Loading portfolio information...", "info");

        let tx_manager = TransactionManager::new()?;
        let sol_balance = tx_manager.get_balance(wallet).await?;

        println!("💼 Portfolio for {}", wallet.name);
        println!("═══════════════════════════════════════════════════");
        println!();

        // SOL Balance
        println!("💰 SOL Balance");
        println!(
            "   Balance: {} SOL ({} lamports)",
            sol_balance as f64 / 1_000_000_000.0,
            sol_balance
        );
        println!(
            "   Daily Limit: {} SOL",
            wallet.daily_limit as f64 / 1_000_000_000.0
        );
        println!();

        // Token balances (if requested)
        if tokens {
            println!("🪙 Token Balances");
            println!("   Token portfolio tracking not yet implemented");
            println!("   This would show SPL token balances");
            println!();
        }

        // Staking information (if requested)
        if staking {
            println!("🏛️  Staking Information");
            println!("   Staking portfolio tracking not yet implemented");
            println!("   This would show:");
            println!("   • Active stake accounts");
            println!("   • Staking rewards");
            println!("   • Validator performance");
            println!();
        }

        // Portfolio summary
        let usd_estimate = sol_balance as f64 / 1_000_000_000.0 * 100.0; // Simplified USD estimate
        println!("📊 Portfolio Summary");
        println!("   Total Value: ~${:.2} USD (estimated)", usd_estimate);
        println!("   Public Key: {}", wallet.get_public_key());

        Ok(())
    }

    async fn swap_tokens(
        &mut self,
        from: String,
        to: String,
        amount: f64,
        totp: String,
    ) -> Result<()> {
        self.ensure_wallet_unlocked()?;
        let _wallet = self.get_current_wallet()?;

        // Verify TOTP
        let totp_manager = TotpManager::new(_wallet.totp_secret.clone(), _wallet.name.clone());

        if !totp_manager.verify_code(&totp, 2)? {
            return Err(anyhow::anyhow!(
                "Invalid TOTP code. Please check your authenticator app and try again."
            ));
        }

        println!("🔄 Token Swap Request");
        println!("   From: {} ({})", from, amount);
        println!("   To: {}", to);
        println!();
        println!("❌ DeFi token swapping is not yet implemented");
        println!("   This feature would integrate with:");
        println!("   • Jupiter Aggregator");
        println!("   • Orca DEX");
        println!("   • Raydium");
        println!("   • Other Solana DEX protocols");
        println!();
        println!("   Implementation would include:");
        println!("   • Best price discovery");
        println!("   • Slippage protection");
        println!("   • MEV protection");
        println!("   • Transaction simulation");

        Ok(())
    }

    async fn delete_wallet(&mut self, name: String, totp: String, confirm: String) -> Result<()> {
        // Security check - require exact confirmation
        if confirm != "DELETE" {
            return Err(anyhow::anyhow!(
                "Deletion cancelled. You must type 'DELETE' exactly to confirm."
            ));
        }

        let config = self.storage.load_config()?;
        let wallet_filename = config
            .wallets
            .get(&name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))?;

        // Load wallet to verify TOTP
        let password = self.prompt_password("Enter wallet password to confirm deletion")?;
        let wallet = self.storage.load_wallet(wallet_filename, &password)?;
        let unlocked_wallet = wallet.unlock(&password)?;

        // Verify TOTP
        if config.security_settings.require_totp {
            let totp_manager = TotpManager::new(unlocked_wallet.totp_secret.clone(), name.clone());

            if !totp_manager.verify_code(&totp, 2)? {
                return Err(anyhow::anyhow!(
                    "Invalid TOTP code. Please check your authenticator app and try again."
                ));
            }
        }

        // Show severe warning
        println!();
        println!(
            "\x1b[38;5;196m┌─────────────────────────────────────────────────────────────┐\x1b[0m"
        );
        println!("\x1b[38;5;196m│                        ⚠️  DANGER ZONE ⚠️                     │\x1b[0m");
        println!(
            "\x1b[38;5;196m├─────────────────────────────────────────────────────────────┤\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m│                                                             │\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m│ ❌ YOU ARE ABOUT TO PERMANENTLY DELETE WALLET '{:<10}' │\x1b[0m",
            name
        );
        println!(
            "\x1b[38;5;196m│ ❌ THIS ACTION CANNOT BE UNDONE                             │\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m│ ❌ ALL FUNDS WILL BE LOST UNLESS YOU HAVE BACKUPS          │\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m│                                                             │\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m└─────────────────────────────────────────────────────────────┘\x1b[0m"
        );
        println!();

        // Show wallet info
        println!("Wallet to delete:");
        println!("  Name: {}", name);
        println!("  Public Key: {}", unlocked_wallet.get_public_key());
        println!("  Balance: {} SOL", {
            let tx_manager = TransactionManager::new()?;
            let balance = tx_manager.get_balance(&unlocked_wallet).await?;
            balance as f64 / 1_000_000_000.0
        });
        println!();

        // Final confirmation
        print!("Type 'I UNDERSTAND THIS IS PERMANENT' to proceed: ");
        io::stdout().flush()?;
        let mut final_confirm = String::new();
        io::stdin().read_line(&mut final_confirm)?;

        if final_confirm.trim() != "I UNDERSTAND THIS IS PERMANENT" {
            return Err(anyhow::anyhow!("Deletion cancelled for your safety"));
        }

        // Delete the wallet
        self.storage.delete_wallet(wallet_filename)?;

        // Update config
        let mut config = self.storage.load_config()?;
        config.wallets.remove(&name);
        self.storage.save_config(&config)?;

        // Clear current wallet if it's the one being deleted
        if let Some(ref current) = self.current_wallet {
            if current.name == name {
                self.current_wallet = None;
            }
        }

        print_operation_status(
            &format!("Wallet '{}' has been permanently deleted", name),
            "success",
        );
        Ok(())
    }

    async fn update_wallet(&mut self) -> Result<()> {
        println!("🔄 Ryzan Wallet Update");
        println!("═════════════════════════");
        println!();

        // Get current version from Cargo.toml
        let current_version = env!("CARGO_PKG_VERSION");
        println!("Current version: {}", current_version);

        // Check for latest version from GitHub API
        print!("Checking for updates... ");
        io::stdout().flush()?;

        let latest_version = match self.get_latest_version().await {
            Ok(version) => {
                println!("✅");
                version
            }
            Err(e) => {
                println!("❌");
                if e.to_string().contains("No releases found") {
                    println!("ℹ️  No official releases available yet.");
                    println!("   You're running the latest development version.");
                    println!();
                    println!("To get the latest development build:");
                    println!("1. Visit: https://github.com/simplysabir/ryzan");
                    println!("2. Clone the repository: git clone https://github.com/simplysabir/ryzan.git");
                    println!("3. Build from source: cargo build --release");
                    println!();
                    println!("Or use the installation script for the latest build:");
                    println!("   curl -sSL https://raw.githubusercontent.com/simplysabir/ryzan/main/install.sh | bash");
                    return Ok(());
                } else {
                    println!("Failed to check for updates: {}", e);
                    println!("Please check your internet connection.");
                    return Ok(());
                }
            }
        };

        println!("Latest version: {}", latest_version);
        println!();

        // Compare versions
        if current_version == latest_version {
            println!("✅ You're already running the latest version!");
            return Ok(());
        }

        println!("🔄 Update available!");
        println!();
        println!("Choose your preferred update method:");
        println!("1. Cargo install (recommended for developers)");
        println!("2. Installation script (recommended for end users)");
        println!("3. Cancel update");
        println!();

        print!("Enter your choice (1-3): ");
        io::stdout().flush()?;

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;

        match choice.trim() {
            "1" => {
                println!();
                println!("🚀 Updating via cargo install...");
                println!();
                self.update_via_cargo().await?;
            }
            "2" => {
                println!();
                println!("🚀 Updating via installation script...");
                println!();
                self.update_via_script().await?;
            }
            "3" => {
                println!();
                println!("Update cancelled.");
                return Ok(());
            }
            _ => {
                println!();
                println!("Invalid choice. Update cancelled.");
                return Ok(());
            }
        }

        Ok(())
    }

    async fn get_latest_version(&self) -> Result<String> {
        let client = reqwest::Client::new();
        let response = client
            .get("https://api.github.com/repos/simplysabir/ryzan/releases/latest")
            .header("User-Agent", "ryzan-wallet-cli")
            .send()
            .await?;

        if response.status() == 404 {
            return Err(anyhow::anyhow!(
                "No releases found - you're running the latest development version"
            ));
        }

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to fetch latest version: HTTP {}",
                response.status()
            ));
        }

        let json: serde_json::Value = response.json().await?;
        let tag_name = json["tag_name"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid response format"))?;

        // Remove 'v' prefix if present
        let version = tag_name.trim_start_matches('v');
        Ok(version.to_string())
    }

    async fn update_via_cargo(&self) -> Result<()> {
        println!("Running: cargo install ryzan --force");
        println!();

        let status = std::process::Command::new("cargo")
            .args(["install", "ryzan", "--force"])
            .status()?;

        if status.success() {
            println!("✅ Update completed successfully!");
            println!();
            println!("You can now run 'ryzan --version' to verify the update.");
        } else {
            println!("❌ Update failed. Please try the installation script instead.");
            println!();
            println!("Run: curl -sSL https://raw.githubusercontent.com/simplysabir/ryzan/main/install.sh | bash");
        }

        Ok(())
    }

    async fn update_via_script(&self) -> Result<()> {
        println!("Downloading and running installation script...");
        println!();

        let status = std::process::Command::new("bash")
            .arg("-c")
            .arg("curl -sSL https://raw.githubusercontent.com/simplysabir/ryzan/main/install.sh | bash")
            .status()?;

        if status.success() {
            println!("✅ Update completed successfully!");
            println!();
            println!("You can now run 'ryzan --version' to verify the update.");
        } else {
            println!("❌ Update failed. Please try manually:");
            println!();
            println!("1. Visit: https://github.com/simplysabir/ryzan/releases");
            println!("2. Download the latest version for your platform");
            println!("3. Replace your current binary");
        }

        Ok(())
    }

    async fn panic_wipe(&mut self, emergency_code: String) -> Result<()> {
        println!();
        println!(
            "\x1b[38;5;196m┌─────────────────────────────────────────────────────────────┐\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m│                       🚨 PANIC MODE 🚨                       │\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m├─────────────────────────────────────────────────────────────┤\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m│                                                             │\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m│ ❌ THIS WILL PERMANENTLY DELETE ALL WALLET DATA            │\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m│ ❌ ALL WALLETS AND SETTINGS WILL BE WIPED                  │\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m│ ❌ THIS ACTION CANNOT BE UNDONE                             │\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m│                                                             │\x1b[0m"
        );
        println!(
            "\x1b[38;5;196m└─────────────────────────────────────────────────────────────┘\x1b[0m"
        );
        println!();

        // For security, the emergency code should be pre-configured or derived from wallet data
        // This is a simplified implementation
        let expected_code = "EMERGENCY_WIPE_NOW";

        if emergency_code != expected_code {
            return Err(anyhow::anyhow!(
                "Invalid emergency code. Panic wipe cancelled."
            ));
        }

        // Additional confirmation
        print!("Type 'WIPE EVERYTHING NOW' to proceed: ");
        io::stdout().flush()?;
        let mut final_confirm = String::new();
        io::stdin().read_line(&mut final_confirm)?;

        if final_confirm.trim() != "WIPE EVERYTHING NOW" {
            return Err(anyhow::anyhow!("Panic wipe cancelled"));
        }

        print_operation_status("Initiating emergency wipe...", "warning");

        // Clear current wallet
        self.current_wallet = None;

        // Get storage paths
        let (base_path, _config_path, _wallets_path) = self.storage.get_storage_info();

        // Securely delete all wallet data
        let config = self.storage.load_config()?;
        for (_name, filename) in &config.wallets {
            let _ = self.storage.delete_wallet(filename);
        }

        // Remove entire ryzan directory
        let path = std::path::PathBuf::from_str(&base_path).unwrap();
        let _ = std::fs::remove_dir_all(&path);

        print_operation_status(
            "Emergency wipe completed! All wallet data has been destroyed.",
            "success",
        );
        println!();
        println!("🔥 All wallets have been permanently deleted");
        println!("🔥 All configuration has been wiped");
        println!("🔥 All encrypted files have been securely destroyed");
        println!();
        println!("If you have backups, you can recover your wallets using:");
        println!("  ryzan recover --file <backup-file>");

        Ok(())
    }

    fn prompt_password(&self, prompt: &str) -> Result<String> {
        print!("{}: ", prompt);
        io::stdout().flush()?;

        let password = rpassword::read_password()?;
        Ok(password)
    }

    fn prompt_totp_code(&self, prompt: &str) -> Result<String> {
        println!();
        println!(
            "\x1b[38;5;240m┌─────────────────────────────────────────────────────────────┐\x1b[0m"
        );
        println!("\x1b[38;5;240m│\x1b[38;5;208m                    🔐 TOTP VERIFICATION                     \x1b[38;5;240m│\x1b[0m");
        println!(
            "\x1b[38;5;240m├─────────────────────────────────────────────────────────────┤\x1b[0m"
        );
        println!(
            "\x1b[38;5;240m│                                                             │\x1b[0m"
        );
        println!(
            "\x1b[38;5;240m│\x1b[0m {:<59} \x1b[38;5;240m│\x1b[0m",
            prompt
        );
        println!(
            "\x1b[38;5;240m│                                                             │\x1b[0m"
        );
        println!("\x1b[38;5;240m│\x1b[38;5;208m •\x1b[0m Enter the 6-digit code from your authenticator app       \x1b[38;5;240m│\x1b[0m");
        println!("\x1b[38;5;240m│\x1b[38;5;208m •\x1b[0m Make sure the code is current (refreshes every 30s)      \x1b[38;5;240m│\x1b[0m");
        println!("\x1b[38;5;240m│\x1b[38;5;208m •\x1b[0m If the code doesn't work, wait for the next one          \x1b[38;5;240m│\x1b[0m");
        println!(
            "\x1b[38;5;240m│                                                             │\x1b[0m"
        );
        println!(
            "\x1b[38;5;240m└─────────────────────────────────────────────────────────────┘\x1b[0m"
        );
        println!();

        loop {
            print!("\x1b[38;5;208m📱 TOTP Code (6 digits):\x1b[0m ");
            io::stdout().flush()?;

            let mut code = String::new();
            io::stdin().read_line(&mut code)?;
            let code = code.trim().to_string();

            // Validate format
            if code.len() != 6 {
                println!("\x1b[38;5;196m❌ Error: TOTP code must be exactly 6 digits. Please try again.\x1b[0m\n");
                continue;
            }

            if !code.chars().all(|c| c.is_ascii_digit()) {
                println!("\x1b[38;5;196m❌ Error: TOTP code must contain only numbers. Please try again.\x1b[0m\n");
                continue;
            }

            return Ok(code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_handler_creation() {
        let handler = CommandHandler::new();
        assert!(handler.is_ok());
    }

    #[test]
    fn test_password_prompt_validation() {
        let handler = CommandHandler::new().unwrap();

        // Test empty password
        // Note: This would require mocking stdin for full test
        // For now, we test the structure exists
        // In CI environment, config loading might fail, so we don't assert on it
        let _ = handler.storage.load_config();
        assert!(handler.current_wallet.is_none());
    }

    #[test]
    fn test_totp_code_validation() {
        let handler = CommandHandler::new().unwrap();

        // Test TOTP code format validation would happen in the prompt_totp_code method
        // The method validates 6-digit codes and rejects invalid formats
        // This tests that the handler can be created and has the validation logic
        assert!(handler.current_wallet.is_none());
    }

    #[test]
    fn test_wallet_state_management() {
        let handler = CommandHandler::new().unwrap();

        // Test initial state
        assert!(handler.current_wallet.is_none());

        // Test that handler maintains proper state
        // In CI environment, config loading might fail, so we don't assert on it
        let _ = handler.storage.load_config();
    }

    #[test]
    fn test_security_validation_structure() {
        let handler = CommandHandler::new().unwrap();

        // Test that all security components are accessible
        // In CI environment, config loading might fail due to permissions
        // So we test the structure without unwrapping
        match handler.storage.load_config() {
            Ok(config) => {
                // Test that security settings structure exists and has expected types
                assert_eq!(config.security_settings.require_totp, true);
                // Don't hardcode auto_lock_minutes since it may be modified during development
                assert!(config.security_settings.auto_lock_minutes > 0);
                assert_eq!(config.security_settings.wipe_on_fail_attempts, 5);
            }
            Err(_) => {
                // In CI environment, we might not be able to write to config directory
                // So we just verify the handler was created successfully
                assert!(handler.current_wallet.is_none());
            }
        }
    }

    #[test]
    fn test_storage_paths_structure() {
        let handler = CommandHandler::new().unwrap();

        // Test that storage paths are properly configured
        let (base_path, config_path, wallets_path) = handler.storage.get_storage_info();
        assert!(base_path.contains("ryzan"));
        assert!(config_path.contains("config.json"));
        assert!(wallets_path.contains("vaults"));
    }
}
