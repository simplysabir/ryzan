use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use zeroize::Zeroize;
use chrono::{DateTime, Utc};
use anyhow::{Result, Context};
use bip39::{Mnemonic, Language};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair as SolanaKeypair, Signer},
};

use crate::crypto::{CryptoEngine, MasterKey, generate_entropy_with_timing, derive_keypair_from_seed};

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SecureWallet {
    pub name: String,
    pub encrypted_seed: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub salt: [u8; 64],
    #[serde_as(as = "Bytes")]
    pub nonce: [u8; 12],
    pub encrypted_totp_secret: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub totp_nonce: [u8; 12],
    pub creation_time: DateTime<Utc>,
    pub daily_limit: u64,
    pub last_tx_time: DateTime<Utc>,
    pub tx_count_today: u32,
    pub spent_today: u64,
    pub time_lock_hours: Option<u8>, // For high-value transactions
}

pub struct UnlockedWallet {
    pub name: String,
    pub mnemonic: Mnemonic,
    pub totp_secret: Vec<u8>,
    pub master_keypair: solana_sdk::signature::Keypair,
    pub daily_limit: u64,
    pub time_lock_hours: Option<u8>,
}

impl Drop for UnlockedWallet {
    fn drop(&mut self) {
        self.totp_secret.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
pub struct WalletConfig {
    pub default_rpc: String,
    pub wallets: HashMap<String, String>, // name -> encrypted_file_path
    pub security_settings: SecuritySettings,
}

#[derive(Serialize, Deserialize)]
pub struct SecuritySettings {
    pub require_totp: bool,
    pub auto_lock_minutes: u16,
    pub wipe_on_fail_attempts: u8,
    pub failed_attempts: u8,
    pub last_activity: DateTime<Utc>,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            default_rpc: "https://api.mainnet-beta.solana.com".to_string(),
            wallets: HashMap::new(),
            security_settings: SecuritySettings {
                require_totp: true,
                auto_lock_minutes: 15,
                wipe_on_fail_attempts: 5,
                failed_attempts: 0,
                last_activity: Utc::now(),
            },
        }
    }
}

impl SecureWallet {
    pub fn create(
        name: String,
        password: &str,
        daily_limit: u64,
        time_lock_hours: Option<u8>,
    ) -> Result<(Self, Mnemonic, Vec<u8>)> {
        // Generate entropy for mnemonic
        let entropy = generate_entropy_with_timing()?;
        let mnemonic = Mnemonic::from_entropy(&entropy)
            .context("Failed to generate mnemonic")?;
        
        // Generate TOTP secret
        let totp_secret = crate::crypto::generate_secure_random(32)?;
        
        // Generate salt for key derivation
        let salt = {
            let mut salt = [0u8; 64];
            let random_salt = crate::crypto::generate_secure_random(64)?;
            salt.copy_from_slice(&random_salt);
            salt
        };
        
        // Derive master key from password
        let master_key = MasterKey::derive_from_password(password, &salt)?;
        let crypto = CryptoEngine::new(&master_key);
        
        // Encrypt mnemonic
        let mnemonic_bytes = mnemonic.to_entropy();
        let (encrypted_seed, nonce) = crypto.encrypt(&mnemonic_bytes)?;
        
        // Encrypt TOTP secret
        let (encrypted_totp_secret, totp_nonce) = crypto.encrypt(&totp_secret)?;
        
        let wallet = Self {
            name: name.clone(),
            encrypted_seed,
            salt,
            nonce,
            encrypted_totp_secret,
            totp_nonce,
            creation_time: Utc::now(),
            daily_limit,
            last_tx_time: Utc::now(),
            tx_count_today: 0,
            spent_today: 0,
            time_lock_hours,
        };
        
        Ok((wallet, mnemonic, totp_secret))
    }
    
    pub fn unlock(&self, password: &str) -> Result<UnlockedWallet> {
        // Derive master key
        let master_key = MasterKey::derive_from_password(password, &self.salt)?;
        let crypto = CryptoEngine::new(&master_key);
        
        // Decrypt mnemonic
        let decrypted_seed = crypto.decrypt(&self.encrypted_seed, &self.nonce)?;
        let mnemonic = Mnemonic::from_entropy(&decrypted_seed)
            .context("Failed to recreate mnemonic from decrypted seed")?;
        
        // Decrypt TOTP secret
        let totp_secret = crypto.decrypt(&self.encrypted_totp_secret, &self.totp_nonce)?;
        
        // Derive master keypair from mnemonic
        let seed = mnemonic.to_seed("");
        let master_keypair = derive_keypair_from_seed(&seed[..32])?;
        
        Ok(UnlockedWallet {
            name: self.name.clone(),
            mnemonic,
            totp_secret,
            master_keypair,
            daily_limit: self.daily_limit,
            time_lock_hours: self.time_lock_hours,
        })
    }
}

impl UnlockedWallet {
    pub fn get_solana_keypair(&self) -> SolanaKeypair {
        SolanaKeypair::from_bytes(&self.master_keypair.to_bytes()).expect("Valid keypair")
    }
    
    pub fn get_public_key(&self) -> Pubkey {
        self.master_keypair.pubkey()
    }
    
    pub fn derive_ephemeral_keypair(&self, index: u32) -> Result<SolanaKeypair> {
        // Derive ephemeral keypair for transaction privacy
        let mut derivation_seed = self.master_keypair.to_bytes().to_vec();
        derivation_seed.extend_from_slice(&index.to_le_bytes());
        
        // Hash the extended seed for deterministic derivation
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        derivation_seed.hash(&mut hasher);
        let hash = hasher.finish();
        
        let mut ephemeral_seed = [0u8; 32];
        ephemeral_seed[..8].copy_from_slice(&hash.to_le_bytes());
        ephemeral_seed[8..].copy_from_slice(&derivation_seed[..24]);
        
        let ephemeral_keypair = derive_keypair_from_seed(&ephemeral_seed)?;
        Ok(ephemeral_keypair)
    }
    
    pub fn generate_receive_address(&self, index: u32) -> Result<Pubkey> {
        Ok(self.derive_ephemeral_keypair(index)?.pubkey())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_wallet_creation_and_unlock() {
        let password = "test_password_123";
        let (wallet, _mnemonic, _totp_secret) = SecureWallet::create(
            "test_wallet".to_string(),
            password,
            100_000_000, // 0.1 SOL daily limit
            Some(24), // 24 hour time lock
        ).unwrap();
        
        let unlocked = wallet.unlock(password).unwrap();
        assert_eq!(unlocked.name, "test_wallet");
        assert_eq!(unlocked.daily_limit, 100_000_000);
    }
    
    #[test]
    fn test_ephemeral_keypair_derivation() {
        let password = "test_password_123";
        let (wallet, _mnemonic, _totp_secret) = SecureWallet::create(
            "test_wallet".to_string(),
            password,
            100_000_000,
            None,
        ).unwrap();
        
        let unlocked = wallet.unlock(password).unwrap();
        
        // Generate multiple ephemeral keypairs
        let keypair1 = unlocked.derive_ephemeral_keypair(0).unwrap();
        let keypair2 = unlocked.derive_ephemeral_keypair(1).unwrap();
        
        // Should be different
        assert_ne!(keypair1.pubkey(), keypair2.pubkey());
        
        // Should be deterministic
        let keypair1_again = unlocked.derive_ephemeral_keypair(0).unwrap();
        assert_eq!(keypair1.pubkey(), keypair1_again.pubkey());
    }
}