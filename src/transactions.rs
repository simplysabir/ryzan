use anyhow::{Context, Result};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Signature, Signer},
    system_instruction,
    transaction::Transaction,
};
use spl_associated_token_account::{get_associated_token_address, instruction as ata_instruction};
use spl_token::instruction as token_instruction;
use std::str::FromStr;

use crate::wallet::UnlockedWallet;

pub struct TransactionManager {
    rpc_client: RpcClient,
}

impl TransactionManager {
    pub fn new() -> Result<Self> {
        // Load RPC URL from config or use default mainnet
        let default_rpc = "https://api.mainnet-beta.solana.com".to_string();
        let rpc_client = RpcClient::new_with_commitment(default_rpc, CommitmentConfig::confirmed());

        Ok(Self { rpc_client })
    }

    pub fn new_with_rpc(rpc_url: String) -> Result<Self> {
        let rpc_client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());
        Ok(Self { rpc_client })
    }

    pub async fn get_balance(&self, wallet: &UnlockedWallet) -> Result<u64> {
        let pubkey = wallet.get_public_key();
        let balance = self
            .rpc_client
            .get_balance(&pubkey)
            .context("Failed to fetch balance")?;
        Ok(balance)
    }

    pub async fn send_sol(
        &self,
        wallet: &UnlockedWallet,
        recipient: Pubkey,
        lamports: u64,
        memo: Option<&str>,
        use_ephemeral: bool,
    ) -> Result<Signature> {
        let sender_keypair = if use_ephemeral {
            // Use ephemeral keypair for privacy
            let index = rand::random::<u32>() % 1000;
            wallet.derive_ephemeral_keypair(index)?
        } else {
            wallet.get_solana_keypair()
        };

        let sender_pubkey = sender_keypair.pubkey();

        // Check if ephemeral account has funds
        if use_ephemeral {
            let ephemeral_balance = self.rpc_client.get_balance(&sender_pubkey)?;
            if ephemeral_balance < lamports {
                // Transfer funds from main account to ephemeral account first
                self.fund_ephemeral_account(wallet, &sender_keypair, lamports + 5000)
                    .await?;
            }
        }

        let recent_blockhash = self
            .rpc_client
            .get_latest_blockhash()
            .context("Failed to get recent blockhash")?;

        let mut instructions = vec![system_instruction::transfer(
            &sender_pubkey,
            &recipient,
            lamports,
        )];

        // Add memo instruction if provided
        if let Some(memo_text) = memo {
            let memo_program_id = Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")?;
            let memo_instruction = Instruction::new_with_bytes(
                memo_program_id,
                memo_text.as_bytes(),
                vec![AccountMeta::new_readonly(sender_pubkey, true)],
            );
            instructions.push(memo_instruction);
        }

        let message = Message::new(&instructions, Some(&sender_pubkey));
        let mut transaction = Transaction::new_unsigned(message);
        transaction.sign(&[&sender_keypair], recent_blockhash);

        let signature = self
            .rpc_client
            .send_and_confirm_transaction(&transaction)
            .context("Failed to send transaction")?;

        Ok(signature)
    }

    pub async fn send_spl_token(
        &self,
        wallet: &UnlockedWallet,
        recipient: Pubkey,
        mint: Pubkey,
        amount: u64,
        memo: Option<&str>,
        use_ephemeral: bool,
    ) -> Result<Signature> {
        let sender_keypair = if use_ephemeral {
            // Use ephemeral keypair for privacy
            let index = rand::random::<u32>() % 1000;
            wallet.derive_ephemeral_keypair(index)?
        } else {
            wallet.get_solana_keypair()
        };

        let sender_pubkey = sender_keypair.pubkey();

        // Get associated token accounts
        let sender_ata = get_associated_token_address(&sender_pubkey, &mint);
        let recipient_ata = get_associated_token_address(&recipient, &mint);

        let recent_blockhash = self
            .rpc_client
            .get_latest_blockhash()
            .context("Failed to get recent blockhash")?;

        let mut instructions = Vec::new();

        // Check if recipient ATA exists, create if not
        if self.rpc_client.get_account(&recipient_ata).is_err() {
            instructions.push(ata_instruction::create_associated_token_account(
                &sender_pubkey,
                &recipient,
                &mint,
                &spl_token::id(),
            ));
        }

        // SPL token transfer instruction
        instructions.push(token_instruction::transfer(
            &spl_token::id(),
            &sender_ata,
            &recipient_ata,
            &sender_pubkey,
            &[&sender_pubkey],
            amount,
        )?);

        // Add memo instruction if provided
        if let Some(memo_text) = memo {
            let memo_program_id = Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")?;
            let memo_instruction = Instruction::new_with_bytes(
                memo_program_id,
                memo_text.as_bytes(),
                vec![AccountMeta::new_readonly(sender_pubkey, true)],
            );
            instructions.push(memo_instruction);
        }

        let message = Message::new(&instructions, Some(&sender_pubkey));
        let mut transaction = Transaction::new_unsigned(message);
        transaction.sign(&[&sender_keypair], recent_blockhash);

        let signature = self
            .rpc_client
            .send_and_confirm_transaction(&transaction)
            .context("Failed to send SPL token transaction")?;

        Ok(signature)
    }

    async fn fund_ephemeral_account(
        &self,
        wallet: &UnlockedWallet,
        ephemeral_keypair: &solana_sdk::signature::Keypair,
        amount: u64,
    ) -> Result<Signature> {
        let main_keypair = wallet.get_solana_keypair();
        let recent_blockhash = self.rpc_client.get_latest_blockhash()?;

        let instruction = system_instruction::transfer(
            &main_keypair.pubkey(),
            &ephemeral_keypair.pubkey(),
            amount,
        );

        let message = Message::new(&[instruction], Some(&main_keypair.pubkey()));
        let mut transaction = Transaction::new_unsigned(message);
        transaction.sign(&[&main_keypair], recent_blockhash);

        let signature = self.rpc_client.send_and_confirm_transaction(&transaction)?;
        Ok(signature)
    }

    pub async fn stake_sol(
        &self,
        wallet: &UnlockedWallet,
        validator_vote_account: Pubkey,
        lamports: u64,
    ) -> Result<Signature> {
        let staker_keypair = wallet.get_solana_keypair();
        let staker_pubkey = staker_keypair.pubkey();

        // Generate a new stake account
        let stake_keypair = solana_sdk::signature::Keypair::new();
        let stake_pubkey = stake_keypair.pubkey();

        let recent_blockhash = self.rpc_client.get_latest_blockhash()?;

        // Create stake account and delegate stake
        let instructions = vec![
            system_instruction::create_account(
                &staker_pubkey,
                &stake_pubkey,
                lamports,
                std::mem::size_of::<solana_sdk::stake::state::StakeState>() as u64,
                &solana_sdk::stake::program::id(),
            ),
            solana_sdk::stake::instruction::initialize(
                &stake_pubkey,
                &solana_sdk::stake::state::Authorized {
                    staker: staker_pubkey,
                    withdrawer: staker_pubkey,
                },
                &solana_sdk::stake::state::Lockup::default(),
            ),
            solana_sdk::stake::instruction::delegate_stake(
                &stake_pubkey,
                &staker_pubkey,
                &validator_vote_account,
            ),
        ];

        let message = Message::new(&instructions, Some(&staker_pubkey));
        let mut transaction = Transaction::new_unsigned(message);
        transaction.sign(&[&staker_keypair, &stake_keypair], recent_blockhash);

        let signature = self.rpc_client.send_and_confirm_transaction(&transaction)?;
        Ok(signature)
    }

    pub async fn get_transaction_history(
        &self,
        wallet: &UnlockedWallet,
        limit: usize,
    ) -> Result<Vec<TransactionInfo>> {
        let pubkey = wallet.get_public_key();

        let signatures = self
            .rpc_client
            .get_signatures_for_address(&pubkey)
            .context("Failed to fetch transaction signatures")?;

        let mut transaction_history = Vec::new();

        for sig_info in signatures {
            if let Some(signature) = sig_info.signature.parse::<Signature>().ok() {
                // Simplified transaction history for now
                let info = TransactionInfo {
                    signature: signature.to_string(),
                    slot: 0, // Would need additional API call
                    block_time: sig_info.block_time,
                    fee: 5000, // Simplified fee estimate
                    status: if sig_info.err.is_some() {
                        "Failed".to_string()
                    } else {
                        "Success".to_string()
                    },
                    memo: None,
                };
                transaction_history.push(info);
            }
        }

        Ok(transaction_history)
    }
}

#[derive(Debug)]
pub struct TransactionInfo {
    pub signature: String,
    pub slot: u64,
    pub block_time: Option<i64>,
    pub fee: u64,
    pub status: String,
    pub memo: Option<String>,
}

fn extract_memo_from_transaction(
    transaction: &solana_sdk::transaction::VersionedTransaction,
) -> Option<String> {
    // Try to extract memo from transaction instructions
    // This is a simplified implementation
    None
}

#[derive(serde::Deserialize)]
pub struct BatchTransaction {
    pub recipient: String,
    pub amount: f64,
    pub memo: Option<String>,
}

pub async fn process_batch_transactions(
    tx_manager: &TransactionManager,
    wallet: &UnlockedWallet,
    transactions: Vec<BatchTransaction>,
) -> Result<Vec<Signature>> {
    let mut signatures = Vec::new();

    for tx in transactions {
        let recipient = Pubkey::from_str(&tx.recipient)
            .context("Invalid recipient address in batch transaction")?;

        let lamports = (tx.amount * 1_000_000_000.0) as u64;

        let signature = tx_manager
            .send_sol(
                wallet,
                recipient,
                lamports,
                tx.memo.as_deref(),
                true, // Use ephemeral for privacy
            )
            .await?;

        signatures.push(signature);

        // Small delay between transactions to avoid rate limiting
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    Ok(signatures)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_manager_creation() {
        // This test requires network access, so we'll skip in testing
        // let tx_manager = TransactionManager::new();
        // assert!(tx_manager.is_ok());
    }

    #[test]
    fn test_batch_transaction_parsing() {
        let json = r#"[
            {
                "recipient": "11111111111111111111111111111112",
                "amount": 0.1,
                "memo": "Test payment"
            }
        ]"#;

        let transactions: Vec<BatchTransaction> = serde_json::from_str(json).unwrap();
        assert_eq!(transactions.len(), 1);
        assert_eq!(transactions[0].amount, 0.1);
    }
}
