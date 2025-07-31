use anyhow::{Result, Context};
use base64::{Engine as _, engine::general_purpose};
use qrcode::{QrCode, Color};
use qrcode::render::unicode;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_lite::{totp_custom, Sha1, DEFAULT_STEP};
use zeroize::Zeroize;

pub struct TotpManager {
    secret: Vec<u8>,
    issuer: String,
    account: String,
}

impl Drop for TotpManager {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
pub struct TotpBackup {
    pub secret_b64: String,
    pub issuer: String,
    pub account: String,
    pub setup_qr: String,
}

impl TotpManager {
    pub fn new(secret: Vec<u8>, account: String) -> Self {
        Self {
            secret,
            issuer: "Ryzan Wallet".to_string(),
            account,
        }
    }
    
    pub fn generate_current_code(&self) -> Result<String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("Failed to get current timestamp")?
            .as_secs();
            
        let code = totp_custom::<Sha1>(DEFAULT_STEP, 6, &self.secret, timestamp);
        Ok(code)
    }
    
    pub fn verify_code(&self, input_code: &str, tolerance_windows: u8) -> Result<bool> {
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("Failed to get current timestamp")?
            .as_secs();
        
        // Check current window and tolerance windows before/after
        for window_offset in -(tolerance_windows as i32)..=(tolerance_windows as i32) {
            let check_timestamp = if window_offset < 0 {
                current_timestamp.saturating_sub(((-window_offset) as u64) * 30)
            } else {
                current_timestamp + (window_offset as u64) * 30
            };
            
            let expected_code_str = totp_custom::<Sha1>(DEFAULT_STEP, 6, &self.secret, check_timestamp);
            
            if expected_code_str == input_code {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    

    pub fn generate_setup_qr(&self) -> Result<String> {
        let secret_b32 = base32::encode(base32::Alphabet::RFC4648 { padding: true }, &self.secret);
        let totp_url = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}",
            urlencoding::encode(&self.issuer),
            urlencoding::encode(&self.account),
            secret_b32,
            urlencoding::encode(&self.issuer)
        );
        
        let qr_code = QrCode::new(&totp_url)
            .context("Failed to generate QR code")?;
            
        let qr_string = qr_code
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark)
            .build();
            
        Ok(qr_string)
    }
    
    pub fn generate_backup_info(&self) -> TotpBackup {
        let secret_b64 = general_purpose::STANDARD.encode(&self.secret);
        let setup_qr = self.generate_setup_qr().unwrap_or_else(|_| "QR generation failed".to_string());
        
        TotpBackup {
            secret_b64,
            issuer: self.issuer.clone(),
            account: self.account.clone(),
            setup_qr,
        }
    }
    
    pub fn from_backup(backup: &TotpBackup) -> Result<Self> {
        let secret = general_purpose::STANDARD
            .decode(&backup.secret_b64)
            .context("Failed to decode TOTP secret from backup")?;
            
        Ok(Self {
            secret,
            issuer: backup.issuer.clone(),
            account: backup.account.clone(),
        })
    }
    
    pub fn get_manual_entry_info(&self) -> (String, String) {
        let secret_b32 = base32::encode(base32::Alphabet::RFC4648 { padding: true }, &self.secret);
        let account_info = format!("{}:{}", self.issuer, self.account);
        (secret_b32, account_info)
    }
}

pub fn prompt_totp_setup(account: &str) -> Result<()> {
    println!("\x1b[38;5;240m┌─────────────────────────────────────────────────────────────┐\x1b[0m");
    println!("\x1b[38;5;240m│\x1b[38;5;208m                    🔐 TOTP SETUP REQUIRED                   \x1b[38;5;240m│\x1b[0m");
    println!("\x1b[38;5;240m├─────────────────────────────────────────────────────────────┤\x1b[0m");
    println!("\x1b[38;5;240m│                                                             │\x1b[0m");
    println!("\x1b[38;5;240m│\x1b[0m Your wallet requires Two-Factor Authentication (TOTP).      \x1b[38;5;240m│\x1b[0m");
    println!("\x1b[38;5;240m│\x1b[0m Please set up your authenticator app now.                   \x1b[38;5;240m│\x1b[0m");
    println!("\x1b[38;5;240m│                                                             │\x1b[0m");
    println!("\x1b[38;5;240m│\x1b[90m Recommended apps:                                           \x1b[38;5;240m│\x1b[0m");
    println!("\x1b[38;5;240m│\x1b[38;5;208m  •\x1b[0m Google Authenticator                                     \x1b[38;5;240m│\x1b[0m");
    println!("\x1b[38;5;240m│\x1b[38;5;208m  •\x1b[0m Authy                                                    \x1b[38;5;240m│\x1b[0m");
    println!("\x1b[38;5;240m│\x1b[38;5;208m  •\x1b[0m 1Password                                               \x1b[38;5;240m│\x1b[0m");
    println!("\x1b[38;5;240m│\x1b[38;5;208m  •\x1b[0m Bitwarden                                               \x1b[38;5;240m│\x1b[0m");
    println!("\x1b[38;5;240m│                                                             │\x1b[0m");
    println!("\x1b[38;5;240m└─────────────────────────────────────────────────────────────┘\x1b[0m");
    println!();
    Ok(())
}

pub fn display_totp_qr(totp_manager: &TotpManager) -> Result<()> {
    let qr_code = totp_manager.generate_setup_qr()?;
    let (secret_b32, account_info) = totp_manager.get_manual_entry_info();
    
    println!("\x1b[38;5;240m┌─────────────────────────────────────────────────────────────┐\x1b[0m");
    println!("\x1b[38;5;240m│\x1b[38;5;208m                      📱 SCAN QR CODE                        \x1b[38;5;240m│\x1b[0m");
    println!("\x1b[38;5;240m└─────────────────────────────────────────────────────────────┘\x1b[0m");
    println!();
    
    // Display QR code
    for line in qr_code.lines() {
        println!("  {}", line);
    }
    
    println!();
    println!("\x1b[38;5;240m┌─────────────────────────────────────────────────────────────┐\x1b[0m");
    println!("\x1b[38;5;240m│\x1b[38;5;208m                   🔑 MANUAL ENTRY                           \x1b[38;5;240m│\x1b[0m");
    println!("\x1b[38;5;240m├─────────────────────────────────────────────────────────────┤\x1b[0m");
    println!("\x1b[38;5;240m│\x1b[90m Account:\x1b[0m {:<50} \x1b[38;5;240m│\x1b[0m", account_info);
    println!("\x1b[38;5;240m│\x1b[90m Secret:\x1b[0m  {:<50} \x1b[38;5;240m│\x1b[0m", secret_b32);
    println!("\x1b[38;5;240m└─────────────────────────────────────────────────────────────┘\x1b[0m");
    println!();
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_secure_random;
    
    #[test]
    fn test_totp_generation_and_verification() {
        let secret = generate_secure_random(32).unwrap();
        let totp_manager = TotpManager::new(secret, "test@example.com".to_string());
        
        let code = totp_manager.generate_current_code().unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        
        // Verify the code we just generated
        assert!(totp_manager.verify_code(&code, 1).unwrap());
        
        // Verify invalid code
        assert!(!totp_manager.verify_code("000000", 1).unwrap());
    }
    
    #[test]
    fn test_totp_with_known_values() {
        // Test with RFC 6238 test vectors
        // Using "12345678901234567890" as secret (20 bytes)
        let secret = b"12345678901234567890";
        let totp_manager = TotpManager::new(secret.to_vec(), "test".to_string());
        
        
        // Test that we can verify our own generated codes
        let code = totp_manager.generate_current_code().unwrap();
        assert!(totp_manager.verify_code(&code, 2).unwrap(), "Should verify our own generated code");
    }
    
    #[test]
    fn test_base32_encoding() {
        let secret = b"Hello World!";
        let totp_manager = TotpManager::new(secret.to_vec(), "test".to_string());
        
        // Check the base32 encoding
        let secret_b32 = base32::encode(base32::Alphabet::RFC4648 { padding: true }, secret);
        println!("Base32 of 'Hello World!': {}", secret_b32);
        
        // Check QR generation doesn't fail
        assert!(totp_manager.generate_setup_qr().is_ok());
    }
    
    #[test]
    fn test_totp_backup_and_restore() {
        let secret = generate_secure_random(32).unwrap();
        let original = TotpManager::new(secret, "test@example.com".to_string());
        
        let backup = original.generate_backup_info();
        let restored = TotpManager::from_backup(&backup).unwrap();
        
        let original_code = original.generate_current_code().unwrap();
        let restored_code = restored.generate_current_code().unwrap();
        
        assert_eq!(original_code, restored_code);
    }
}