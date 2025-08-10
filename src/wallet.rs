use anyhow::{Context, Result};
use bip39::{Language, Mnemonic};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair as SolanaKeypair, Signer},
};
use std::collections::HashMap;
use zeroize::Zeroize;

use crate::crypto::{
    derive_keypair_from_seed, generate_entropy_with_timing, CryptoEngine, MasterKey,
};

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

impl Clone for UnlockedWallet {
    fn clone(&self) -> Self {
        // Manual clone since Keypair doesn't implement Clone
        let keypair_bytes = self.master_keypair.to_bytes();
        let cloned_keypair = solana_sdk::signature::Keypair::from_bytes(&keypair_bytes).unwrap();

        Self {
            name: self.name.clone(),
            mnemonic: self.mnemonic.clone(),
            totp_secret: self.totp_secret.clone(),
            master_keypair: cloned_keypair,
            daily_limit: self.daily_limit,
            time_lock_hours: self.time_lock_hours,
        }
    }
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
        let mnemonic = Mnemonic::from_entropy(&entropy).context("Failed to generate mnemonic")?;

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
            Some(24),    // 24 hour time lock
        )
        .unwrap();

        let unlocked = wallet.unlock(password).unwrap();
        assert_eq!(unlocked.name, "test_wallet");
        assert_eq!(unlocked.daily_limit, 100_000_000);
    }
}
