use std::io::{self, Write};
use anyhow::{Result, Context};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

use crate::cli::{Commands, print_operation_status};
use crate::storage::SecureStorage;
use crate::wallet::{SecureWallet, UnlockedWallet};
use crate::totp::{TotpManager, display_totp_qr, prompt_totp_setup};
use crate::transactions::TransactionManager;

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
    
    pub async fn execute(&mut self, command: Commands) -> Result<()> {
        match command {
            Commands::Create { name, totp, daily_limit, time_lock } => {
                self.create_wallet(name, totp, daily_limit, time_lock).await
            }
            Commands::Unlock { name, totp } => {
                self.unlock_wallet(name, totp).await
            }
            Commands::Send { address, amount, totp, memo, ephemeral } => {
                self.send_transaction(address, amount, totp, memo, ephemeral).await
            }
            Commands::Receive { amount, qr, new_address } => {
                self.generate_receive_address(amount, qr, new_address).await
            }
            Commands::Balance { name, totp, detailed } => {
                self.show_balance(name, totp, detailed).await
            }
            Commands::List => {
                self.list_wallets().await
            }
            Commands::Backup { output, totp } => {
                self.backup_wallet(output, totp).await
            }
            Commands::Recover { file, name } => {
                self.recover_wallet(file, name).await
            }
            Commands::Config { rpc, auto_lock, show } => {
                self.configure_settings(rpc, auto_lock, show).await
            }
            _ => {
                println!("Command not yet implemented");
                Ok(())
            }
        }
    }
    
    async fn create_wallet(&mut self, name: String, enable_totp: bool, daily_limit: u64, time_lock: Option<u8>) -> Result<()> {
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
            return Err(anyhow::anyhow!("Password must be at least 12 characters long"));
        }
        
        // Create wallet
        let (wallet, mnemonic, totp_secret) = SecureWallet::create(
            name.clone(),
            &password,
            daily_limit,
            time_lock,
        )?;
        
        // Set up TOTP if enabled
        if enable_totp {
            prompt_totp_setup(&name)?;
            
            let totp_manager = TotpManager::new(totp_secret, name.clone());
            display_totp_qr(&totp_manager)?;
            
            
            // Wait for user to set up TOTP
            let totp_code = self.prompt_totp_code("Please set up your authenticator app and enter the 6-digit TOTP code to verify")?;
            
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
        println!("\x1b[38;5;240m┌─────────────────────────────────────────────────────────────┐\x1b[0m");
        println!("\x1b[38;5;240m│\x1b[38;5;208m                    🔑 BACKUP YOUR WALLET                    \x1b[38;5;240m│\x1b[0m");
        println!("\x1b[38;5;240m├─────────────────────────────────────────────────────────────┤\x1b[0m");
        println!("\x1b[38;5;240m│                                                             │\x1b[0m");
        println!("\x1b[38;5;240m│\x1b[38;5;214m RECOVERY PHRASE (write this down):                         \x1b[38;5;240m│\x1b[0m");
        println!("\x1b[38;5;240m│                                                             │\x1b[0m");
        
        let phrase = mnemonic.to_string();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        for (i, chunk) in words.chunks(6).enumerate() {
            print!("\x1b[38;5;240m│\x1b[0m ");
            for (j, word) in chunk.iter().enumerate() {
                print!("\x1b[38;5;208m{:2}.\x1b[0m {:<10}", i * 6 + j + 1, word);
            }
            println!(" \x1b[38;5;240m│\x1b[0m");
        }
        
        println!("\x1b[38;5;240m│                                                             │\x1b[0m");
        println!("\x1b[38;5;240m│\x1b[38;5;214m ⚠️  Store this phrase in 3 different secure locations      \x1b[38;5;240m│\x1b[0m");
        println!("\x1b[38;5;240m│\x1b[38;5;214m ⚠️  Never share it with anyone                             \x1b[38;5;240m│\x1b[0m");
        println!("\x1b[38;5;240m│\x1b[38;5;214m ⚠️  This is the ONLY way to recover your wallet            \x1b[38;5;240m│\x1b[0m");
        println!("\x1b[38;5;240m│                                                             │\x1b[0m");
        println!("\x1b[38;5;240m└─────────────────────────────────────────────────────────────┘\x1b[0m");
        
        // Require user confirmation
        println!("\nType 'I HAVE SAVED MY RECOVERY PHRASE' to continue:");
        let mut confirmation = String::new();
        io::stdin().read_line(&mut confirmation)?;
        
        if confirmation.trim() != "I HAVE SAVED MY RECOVERY PHRASE" {
            return Err(anyhow::anyhow!("You must save your recovery phrase before continuing"));
        }
        
        print_operation_status(&format!("Wallet '{}' created successfully!", name), "success");
        
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
        let wallet_filename = config.wallets.get(&name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))?;
        
        let password = self.prompt_password("Enter wallet password")?;
        
        print_operation_status("Unlocking wallet...", "info");
        
        let wallet = self.storage.load_wallet(wallet_filename, &password)?;
        let unlocked_wallet = wallet.unlock(&password)?;
        
        // Verify TOTP if required
        if config.security_settings.require_totp {
            let totp_code = match totp_code {
                Some(code) => code,
                None => self.prompt_totp_code("Enter your 6-digit TOTP code from your authenticator app")?
            };
            
            let totp_manager = TotpManager::new(
                unlocked_wallet.totp_secret.clone(),
                name.clone()
            );
            
            if !totp_manager.verify_code(&totp_code, 2)? {
                return Err(anyhow::anyhow!("Invalid TOTP code. Please check your authenticator app and try again."));
            }
        }
        
        self.current_wallet = Some(unlocked_wallet);
        print_operation_status(&format!("Wallet '{}' unlocked successfully!", name), "success");
        
        // Show wallet info
        if let Some(wallet) = &self.current_wallet {
            let pubkey = wallet.get_public_key();
            println!("\nPublic Key: {}", pubkey);
            println!("Daily Limit: {} SOL", wallet.daily_limit as f64 / 1_000_000_000.0);
            
            if let Some(hours) = wallet.time_lock_hours {
                println!("Time Lock: {} hours for large transactions", hours);
            }
        }
        
        Ok(())
    }
    
    async fn send_transaction(&mut self, address: String, amount: f64, totp_code: String, memo: Option<String>, ephemeral: bool) -> Result<()> {
        let wallet = self.current_wallet.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No wallet unlocked. Use 'ryzan unlock --name <wallet>' first"))?;
        
        // Verify TOTP
        let totp_manager = TotpManager::new(
            wallet.totp_secret.clone(),
            wallet.name.clone()
        );
        
        if !totp_manager.verify_code(&totp_code, 2)? {
            return Err(anyhow::anyhow!("Invalid TOTP code. Please check your authenticator app and try again."));
        }
        
        // Parse recipient address
        let recipient = Pubkey::from_str(&address)
            .context("Invalid recipient address")?;
        
        // Convert SOL to lamports
        let lamports = (amount * 1_000_000_000.0) as u64;
        
        // Check daily limit
        if lamports > wallet.daily_limit {
            return Err(anyhow::anyhow!(
                "Transaction amount ({} SOL) exceeds daily limit ({} SOL)",
                amount,
                wallet.daily_limit as f64 / 1_000_000_000.0
            ));
        }
        
        print_operation_status("Preparing transaction...", "info");
        
        let tx_manager = TransactionManager::new()?;
        let signature = tx_manager.send_sol(wallet, recipient, lamports, memo.as_deref(), ephemeral).await?;
        
        print_operation_status(&format!("Transaction sent! Signature: {}", signature), "success");
        Ok(())
    }
    
    async fn generate_receive_address(&mut self, amount: Option<f64>, qr: bool, new_address: bool) -> Result<()> {
        let wallet = self.current_wallet.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No wallet unlocked. Use 'ryzan unlock --name <wallet>' first"))?;
        
        let address = if new_address {
            // Generate new ephemeral address for privacy
            let index = rand::random::<u32>() % 1000;
            wallet.generate_receive_address(index)?
        } else {
            wallet.get_public_key()
        };
        
        println!("Receive Address: {}", address);
        
        if let Some(sol_amount) = amount {
            let lamports = (sol_amount * 1_000_000_000.0) as u64;
            let payment_url = format!("solpay:{}?amount={}", address, lamports);
            
            if qr {
                let qr_code = qrcode::QrCode::new(&payment_url)?;
                let qr_string = qr_code
                    .render::<qrcode::render::unicode::Dense1x2>()
                    .dark_color(qrcode::render::unicode::Dense1x2::Light)
                    .light_color(qrcode::render::unicode::Dense1x2::Dark)
                    .build();
                
                println!("\nPayment QR Code:");
                println!("{}", qr_string);
            }
            
            println!("Payment URL: {}", payment_url);
            println!("Requesting: {} SOL", sol_amount);
        }
        
        Ok(())
    }
    
    async fn show_balance(&mut self, name: String, totp_code: String, detailed: bool) -> Result<()> {
        // Load and unlock the wallet temporarily for balance check
        let config = self.storage.load_config()?;
        let wallet_filename = config.wallets.get(&name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))?;
        
        let password = self.prompt_password("Enter wallet password")?;
        let wallet = self.storage.load_wallet(wallet_filename, &password)?;
        let unlocked_wallet = wallet.unlock(&password)?;
        
        // Verify TOTP
        if config.security_settings.require_totp {
            let totp_manager = TotpManager::new(
                unlocked_wallet.totp_secret.clone(),
                name.clone()
            );
            
            if !totp_manager.verify_code(&totp_code, 2)? {
                return Err(anyhow::anyhow!("Invalid TOTP code. Please check your authenticator app and try again."));
            }
        }
        
        let tx_manager = TransactionManager::new()?;
        let balance = tx_manager.get_balance(&unlocked_wallet).await?;
        
        println!("💰 Wallet: {}", name);
        println!("📊 Balance: {} SOL", balance as f64 / 1_000_000_000.0);
        
        if detailed {
            println!("📈 Balance (lamports): {}", balance);
            println!("🚫 Daily Limit: {} SOL", unlocked_wallet.daily_limit as f64 / 1_000_000_000.0);
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
        let wallet = self.current_wallet.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No wallet unlocked. Use 'ryzan unlock --name <wallet>' first"))?;
        
        // Verify TOTP
        let totp_manager = TotpManager::new(
            wallet.totp_secret.clone(),
            wallet.name.clone()
        );
        
        if !totp_manager.verify_code(&totp_code, 2)? {
            return Err(anyhow::anyhow!("Invalid TOTP code. Please check your authenticator app and try again."));
        }
        
        // Load the encrypted wallet data
        let config = self.storage.load_config()?;
        let wallet_filename = config.wallets.get(&wallet.name)
            .ok_or_else(|| anyhow::anyhow!("Wallet file not found"))?;
        
        let password = self.prompt_password("Enter wallet password to create backup")?;
        let secure_wallet = self.storage.load_wallet(wallet_filename, &password)?;
        
        self.storage.backup_wallet(&secure_wallet, &std::path::Path::new(&output))?;
        
        print_operation_status(&format!("Backup saved to: {}", output), "success");
        Ok(())
    }
    
    async fn recover_wallet(&mut self, file: String, name: Option<String>) -> Result<()> {
        println!("Wallet recovery not yet implemented");
        Ok(())
    }
    
    async fn configure_settings(&mut self, rpc: Option<String>, auto_lock: Option<u16>, show: bool) -> Result<()> {
        let mut config = self.storage.load_config()?;
        
        if show {
            println!("Current Configuration:");
            println!("  Default RPC: {}", config.default_rpc);
            println!("  Auto-lock: {} minutes", config.security_settings.auto_lock_minutes);
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
    
    fn prompt_password(&self, prompt: &str) -> Result<String> {
        print!("{}: ", prompt);
        io::stdout().flush()?;
        
        let password = rpassword::read_password()?;
        Ok(password)
    }
    
    fn prompt_totp_code(&self, prompt: &str) -> Result<String> {
        println!();
        println!("\x1b[38;5;240m┌─────────────────────────────────────────────────────────────┐\x1b[0m");
        println!("\x1b[38;5;240m│\x1b[38;5;208m                    🔐 TOTP VERIFICATION                     \x1b[38;5;240m│\x1b[0m");
        println!("\x1b[38;5;240m├─────────────────────────────────────────────────────────────┤\x1b[0m");
        println!("\x1b[38;5;240m│                                                             │\x1b[0m");
        println!("\x1b[38;5;240m│\x1b[0m {:<59} \x1b[38;5;240m│\x1b[0m", prompt);
        println!("\x1b[38;5;240m│                                                             │\x1b[0m");
        println!("\x1b[38;5;240m│\x1b[38;5;208m •\x1b[0m Enter the 6-digit code from your authenticator app       \x1b[38;5;240m│\x1b[0m");
        println!("\x1b[38;5;240m│\x1b[38;5;208m •\x1b[0m Make sure the code is current (refreshes every 30s)      \x1b[38;5;240m│\x1b[0m");
        println!("\x1b[38;5;240m│\x1b[38;5;208m •\x1b[0m If the code doesn't work, wait for the next one          \x1b[38;5;240m│\x1b[0m");
        println!("\x1b[38;5;240m│                                                             │\x1b[0m");
        println!("\x1b[38;5;240m└─────────────────────────────────────────────────────────────┘\x1b[0m");
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
}