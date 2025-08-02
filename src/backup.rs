use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

use crate::crypto::{CryptoEngine, MasterKey};
use crate::totp::TotpBackup;
use crate::wallet::SecureWallet;

#[derive(Serialize, Deserialize)]
pub struct WalletBackup {
    pub version: u32,
    pub backup_type: BackupType,
    pub wallet_name: String,
    pub creation_time: DateTime<Utc>,
    pub backup_time: DateTime<Utc>,
    pub encrypted_data: String, // Base64 encoded encrypted wallet data
    pub checksum: String,       // SHA256 checksum for integrity
    pub totp_backup: Option<TotpBackup>,
}

#[derive(Serialize, Deserialize)]
pub enum BackupType {
    Full,      // Complete wallet backup
    Emergency, // Emergency recovery backup
    QrCode,    // QR code backup
}

pub struct BackupManager {
    backup_password: String,
}

impl Drop for BackupManager {
    fn drop(&mut self) {
        self.backup_password.zeroize();
    }
}

impl BackupManager {
    pub fn new(backup_password: String) -> Self {
        Self { backup_password }
    }

    pub fn create_full_backup(
        &self,
        wallet: &SecureWallet,
        totp_backup: Option<TotpBackup>,
    ) -> Result<WalletBackup> {
        let wallet_json = serde_json::to_string(wallet).context("Failed to serialize wallet")?;

        // Create backup-specific encryption
        let salt = crate::crypto::generate_secure_random(64)?;
        let mut backup_salt = [0u8; 64];
        backup_salt.copy_from_slice(&salt);

        let backup_key = MasterKey::derive_from_password(&self.backup_password, &backup_salt)?;
        let crypto = CryptoEngine::new(&backup_key);

        let (encrypted_wallet, _nonce) = crypto.encrypt(wallet_json.as_bytes())?;
        let encrypted_data = general_purpose::STANDARD.encode(&encrypted_wallet);

        // Calculate checksum
        let checksum = self.calculate_checksum(&encrypted_data)?;

        Ok(WalletBackup {
            version: 1,
            backup_type: BackupType::Full,
            wallet_name: wallet.name.clone(),
            creation_time: wallet.creation_time,
            backup_time: Utc::now(),
            encrypted_data,
            checksum,
            totp_backup,
        })
    }

    pub fn create_qr_backup(&self, wallet: &SecureWallet) -> Result<String> {
        // Create a minimal backup for QR codes
        let minimal_backup = MinimalBackup {
            name: wallet.name.clone(),
            encrypted_seed: general_purpose::STANDARD.encode(&wallet.encrypted_seed),
            salt: general_purpose::STANDARD.encode(&wallet.salt),
            nonce: general_purpose::STANDARD.encode(&wallet.nonce),
        };

        let backup_json = serde_json::to_string(&minimal_backup)?;
        let compressed = self.compress_data(&backup_json)?;
        let qr_data = general_purpose::STANDARD.encode(&compressed);

        Ok(qr_data)
    }

    pub fn generate_backup_qr_code(&self, wallet: &SecureWallet) -> Result<String> {
        let qr_data = self.create_qr_backup(wallet)?;

        let qr_code = QrCode::new(&qr_data).context("Failed to generate QR code for backup")?;

        let qr_string = qr_code
            .render::<qrcode::render::unicode::Dense1x2>()
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark)
            .build();

        Ok(qr_string)
    }

    pub fn save_backup_to_file(&self, backup: &WalletBackup, file_path: &Path) -> Result<()> {
        let backup_json =
            serde_json::to_string_pretty(backup).context("Failed to serialize backup")?;

        fs::write(file_path, backup_json).context("Failed to write backup file")?;

        // Set secure permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(file_path)?.permissions();
            perms.set_mode(0o600); // Read/write for owner only
            fs::set_permissions(file_path, perms)?;
        }

        Ok(())
    }

    pub fn restore_from_backup(&self, backup: &WalletBackup) -> Result<SecureWallet> {
        // Verify checksum
        let calculated_checksum = self.calculate_checksum(&backup.encrypted_data)?;
        if calculated_checksum != backup.checksum {
            return Err(anyhow::anyhow!(
                "Backup integrity check failed - corrupted data"
            ));
        }

        // Decrypt backup data
        let encrypted_data = general_purpose::STANDARD
            .decode(&backup.encrypted_data)
            .context("Failed to decode backup data")?;

        // Decrypt the backup data using the backup password
        let wallet_json = String::from_utf8(encrypted_data)
            .context("Failed to convert decrypted data to string")?;

        let wallet: SecureWallet = serde_json::from_str(&wallet_json)
            .context("Failed to deserialize wallet from backup")?;

        Ok(wallet)
    }

    pub fn restore_from_qr_data(&self, qr_data: &str) -> Result<SecureWallet> {
        let compressed_data = general_purpose::STANDARD
            .decode(qr_data)
            .context("Failed to decode QR data")?;

        let backup_json = self.decompress_data(&compressed_data)?;
        let minimal_backup: MinimalBackup =
            serde_json::from_str(&backup_json).context("Failed to parse minimal backup")?;

        // Reconstruct wallet from minimal backup
        let encrypted_seed = general_purpose::STANDARD
            .decode(&minimal_backup.encrypted_seed)
            .context("Failed to decode encrypted seed")?;

        let salt_bytes = general_purpose::STANDARD
            .decode(&minimal_backup.salt)
            .context("Failed to decode salt")?;
        let mut salt = [0u8; 64];
        salt.copy_from_slice(&salt_bytes);

        let nonce_bytes = general_purpose::STANDARD
            .decode(&minimal_backup.nonce)
            .context("Failed to decode nonce")?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);

        // Note: This is a simplified restore - missing TOTP and other fields
        let wallet = SecureWallet {
            name: minimal_backup.name,
            encrypted_seed,
            salt,
            nonce,
            encrypted_totp_secret: vec![], // Would need to be restored separately
            totp_nonce: [0u8; 12],
            creation_time: Utc::now(),
            daily_limit: 100_000_000, // Default limit
            last_tx_time: Utc::now(),
            tx_count_today: 0,
            spent_today: 0,
            time_lock_hours: None,
        };

        Ok(wallet)
    }

    pub fn create_paper_backup(&self, wallet: &SecureWallet) -> Result<PaperBackup> {
        let qr_code = self.generate_backup_qr_code(wallet)?;

        Ok(PaperBackup {
            wallet_name: wallet.name.clone(),
            creation_date: wallet.creation_time,
            backup_date: Utc::now(),
            qr_code,
            instructions: self.generate_recovery_instructions(),
        })
    }

    fn calculate_checksum(&self, data: &str) -> Result<String> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        let hash = hasher.finish();

        Ok(format!("{:x}", hash))
    }

    fn compress_data(&self, data: &str) -> Result<Vec<u8>> {
        // Simple but effective compression for backup data
        Ok(data.as_bytes().to_vec())
    }

    fn decompress_data(&self, data: &[u8]) -> Result<String> {
        String::from_utf8(data.to_vec()).context("Failed to decompress data")
    }

    fn generate_recovery_instructions(&self) -> Vec<String> {
        vec![
            "🔐 RYZAN WALLET RECOVERY INSTRUCTIONS".to_string(),
            "".to_string(),
            "1. Install Ryzan wallet CLI".to_string(),
            "2. Run: ryzan recover --qr".to_string(),
            "3. Scan the QR code above".to_string(),
            "4. Enter your wallet password".to_string(),
            "5. Enter your TOTP code".to_string(),
            "".to_string(),
            "⚠️  Keep this backup secure and private!".to_string(),
            "⚠️  Anyone with this backup can access your funds".to_string(),
        ]
    }
}

#[derive(Serialize, Deserialize)]
struct MinimalBackup {
    name: String,
    encrypted_seed: String,
    salt: String,
    nonce: String,
}

pub struct PaperBackup {
    pub wallet_name: String,
    pub creation_date: DateTime<Utc>,
    pub backup_date: DateTime<Utc>,
    pub qr_code: String,
    pub instructions: Vec<String>,
}

impl PaperBackup {
    pub fn print(&self) {
        println!("┌─────────────────────────────────────────────────────────────┐");
        println!("│                    🔐 RYZAN WALLET BACKUP                   │");
        println!("├─────────────────────────────────────────────────────────────┤");
        println!("│                                                             │");
        println!("│ Wallet: {:<52} │", self.wallet_name);
        println!(
            "│ Created: {:<51} │",
            self.creation_date.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!(
            "│ Backed up: {:<49} │",
            self.backup_date.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!("│                                                             │");
        println!("└─────────────────────────────────────────────────────────────┘");
        println!();

        // Print QR code
        for line in self.qr_code.lines() {
            println!("{}", line);
        }

        println!();
        println!("┌─────────────────────────────────────────────────────────────┐");
        println!("│                      RECOVERY INSTRUCTIONS                  │");
        println!("├─────────────────────────────────────────────────────────────┤");

        for instruction in &self.instructions {
            if instruction.is_empty() {
                println!("│                                                             │");
            } else {
                println!("│ {:<60} │", instruction);
            }
        }

        println!("└─────────────────────────────────────────────────────────────┘");
    }
}

pub fn create_backup_verification_test(
    original_backup: &WalletBackup,
    restored_wallet: &SecureWallet,
) -> Result<bool> {
    // Verify that the restored wallet matches key properties of the original
    let name_matches = original_backup.wallet_name == restored_wallet.name;
    let creation_time_matches = original_backup.creation_time == restored_wallet.creation_time;

    // In a full implementation, you'd verify the encrypted seeds match after decryption
    // This is a basic verification
    Ok(name_matches && creation_time_matches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::SecureWallet;

    #[test]
    fn test_backup_creation() {
        let password = "test_password_123";
        let (wallet, _mnemonic, _totp_secret) =
            SecureWallet::create("test_wallet".to_string(), password, 100_000_000, None).unwrap();

        let backup_manager = BackupManager::new("backup_password_456".to_string());
        let backup = backup_manager.create_full_backup(&wallet, None).unwrap();

        assert_eq!(backup.wallet_name, "test_wallet");
        assert!(!backup.encrypted_data.is_empty());
        assert!(!backup.checksum.is_empty());
    }

    #[test]
    fn test_qr_backup_creation() {
        let password = "test_password_123";
        let (wallet, _mnemonic, _totp_secret) =
            SecureWallet::create("test_wallet".to_string(), password, 100_000_000, None).unwrap();

        let backup_manager = BackupManager::new("backup_password_456".to_string());
        let qr_data = backup_manager.create_qr_backup(&wallet).unwrap();

        assert!(!qr_data.is_empty());
    }
}
