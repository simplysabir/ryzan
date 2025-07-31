# Ryzan Wallet Usage Guide

## Quick Start

### 1. Create a Wallet
```bash
cargo run -- create --name my-wallet
```
- Set up TOTP with your authenticator app
- Save the recovery phrase securely
- The wallet name will appear in your authenticator as `my-wallet` (not `ryzan:my-wallet`)

### 2. Check Balance
```bash
cargo run -- balance --name my-wallet --totp 123456
```

### 3. List Wallets
```bash
cargo run -- list
```

### 4. Send SOL
```bash
cargo run -- send ADDRESS AMOUNT --totp 123456
```

## Detailed Commands

### Wallet Management

#### Create Wallet
```bash
cargo run -- create --name WALLET_NAME [OPTIONS]
```
Options:
- `--daily-limit AMOUNT` - Daily spending limit in lamports (default: 0.1 SOL)
- `--time-lock HOURS` - Time lock for large transactions

#### List Wallets
```bash
cargo run -- list
```
Shows all wallets with their status and storage locations.

#### Check Balance
```bash
cargo run -- balance --name WALLET_NAME --totp TOTP_CODE [--detailed]
```
- `--detailed` - Shows additional information like daily limits and public key

### Transactions

#### Send SOL
```bash
cargo run -- send ADDRESS AMOUNT --totp TOTP_CODE [OPTIONS]
```
Options:
- `--memo "MESSAGE"` - Add a memo to the transaction
- `--ephemeral true/false` - Use ephemeral keypair for privacy (default: true)

#### Generate Receive Address
```bash
cargo run -- receive [OPTIONS]
```
Options:
- `--amount AMOUNT` - Request specific amount
- `--qr` - Generate QR code for payment
- `--new-address` - Generate new ephemeral address (default: true)

### Security & Backup

#### Create Backup
```bash
cargo run -- backup --output backup.json --totp TOTP_CODE
```

#### Configure Settings
```bash
cargo run -- config [OPTIONS]
```
Options:
- `--rpc URL` - Set custom RPC endpoint
- `--auto-lock MINUTES` - Set auto-lock timeout
- `--show` - Display current configuration

## Important Notes

### Security Model
- Each command runs independently for security
- Wallets don't stay "unlocked" between commands
- Each operation requires TOTP authentication
- All data is encrypted with your master password

### TOTP Authentication
- Each wallet has its own TOTP entry in your authenticator app
- The wallet name appears directly (e.g., "my-wallet", not "ryzan:my-wallet")
- TOTP is required for all sensitive operations

### File Storage
Encrypted files are stored in:
- **Base Directory**: `~/.config/ryzan/`
- **Config File**: `~/.config/ryzan/config.json`
- **Wallet Vaults**: `~/.config/ryzan/vaults/`

All files have restrictive permissions (700) and are encrypted.

### Testing
Run the comprehensive test suite:
```bash
./test_ryzan.sh
```

This tests all major features end-to-end.

## Troubleshooting

### Banner Appearing Multiple Times
Fixed! The banner now only appears during wallet creation.

### "No wallet unlocked" Error
This is expected behavior. Each command requires fresh authentication:
```bash
# Instead of:
cargo run -- unlock --name my-wallet
cargo run -- balance  # ❌ This will fail

# Do this:
cargo run -- balance --name my-wallet --totp 123456  # ✅ This works
```

### TOTP Issues
- Make sure you're using the current 6-digit code
- Wait for the next code if the current one doesn't work
- Each wallet has its own TOTP entry in your authenticator app

### Storage Location
Check where your encrypted wallets are stored:
```bash
ls -la ~/.config/ryzan/
ls -la ~/.config/ryzan/vaults/
```

## Advanced Usage

### Custom RPC Endpoint
```bash
cargo run -- config --rpc "https://api.devnet.solana.com"
```

### High-Value Transaction with Time Lock
```bash
cargo run -- create --name secure-wallet --time-lock 24
```

### Detailed Balance with All Information
```bash
cargo run -- balance --name my-wallet --totp 123456 --detailed
```

### Send with Privacy Features
```bash
cargo run -- send ADDRESS 0.1 --totp 123456 --ephemeral true --memo "Private payment"
```

## Example Workflow

1. **Create Wallet**
   ```bash
   cargo run -- create --name personal --daily-limit 1000000000
   ```

2. **Check Balance**
   ```bash
   cargo run -- balance --name personal --totp 123456
   ```

3. **Generate Receive Address**
   ```bash
   cargo run -- receive --amount 0.5 --qr
   ```

4. **Send Transaction**
   ```bash
   cargo run -- send 11111111111111111111111111111112 0.01 --totp 456789
   ```

5. **Create Backup**
   ```bash
   cargo run -- backup --output personal_backup.json --totp 789012
   ```

## Security Best Practices

- ✅ Use strong master passwords
- ✅ Save recovery phrases in multiple secure locations
- ✅ Keep TOTP device secure
- ✅ Regularly create backups
- ✅ Verify recipient addresses carefully
- ✅ Use appropriate daily limits
- ❌ Never share passwords or TOTP codes
- ❌ Don't store recovery phrases digitally
- ❌ Don't use the same password for multiple wallets