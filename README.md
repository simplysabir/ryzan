# ⚡ Ryzan - Ultra-Secure Solana Wallet CLI

> *Hardware-level security with zero-trust architecture - Unbreakable crypto at $0 cost*

Ryzan (**Rai** = Lightning + **Zan** = Slash) is an ultra-secure command-line Solana wallet that provides hardware-wallet-level security without the hardware. Built with enterprise-grade security features and a zero-trust architecture.

```
██████╗ ██╗   ██╗███████╗ █████╗ ███╗   ██╗
██╔══██╗╚██╗ ██╔╝╚══███╔╝██╔══██╗████╗  ██║
██████╔╝ ╚████╔╝   ███╔╝ ███████║██╔██╗ ██║
██╔══██╗  ╚██╔╝   ███╔╝  ██╔══██║██║╚██╗██║
██║  ██║   ██║   ███████╗██║  ██║██║ ╚████║  ⚡
╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝  
```

## 🔥 Why Ryzan?

- **🔐 Hardware-Level Security**: Private keys never leave encrypted storage
- **⚡ Zero Hardware Cost**: $0 vs $100+ for hardware wallets  
- **🛡️ Zero-Trust Architecture**: Every operation requires authentication
- **🔒 Enterprise Security**: ChaCha20-Poly1305 + Argon2id + Ed25519
- **📱 2FA Required**: TOTP authentication for all sensitive operations
- **🎯 Privacy First**: Ephemeral keypairs for transaction privacy
- **💾 Bulletproof Backups**: Multiple redundant backup methods
- **🚫 Anti-Malware**: Advanced protection against keyloggers & malware

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd ryzan

# Build in release mode
cargo build --release

# Install (optional)
cargo install --path .
```

### Create Your First Wallet

```bash
# Create a new secure wallet with TOTP
./target/release/ryzan create --name main --totp

# Unlock your wallet
./target/release/ryzan unlock --name main

# Check balance
./target/release/ryzan balance --detailed
```

## 🔐 Security Features

### **Core Cryptography**
- **ChaCha20-Poly1305**: 256-bit encryption for all wallet data
- **Ed25519**: Elliptic curve cryptography for keypairs
- **Argon2id**: Memory-hard password hashing (1GB memory, 10 iterations)
- **Hardware RNG**: Secure random number generation with timing entropy

### **Authentication & Access Control**
- **TOTP 2FA**: Google Authenticator compatible time-based codes
- **Password Protection**: Master password for wallet encryption
- **Daily Limits**: Configurable spending caps with TOTP override
- **Time Locks**: Delays for high-value transactions (1-24 hours)

### **Privacy & Anonymity**
- **Ephemeral Keypairs**: Never reuse addresses for transactions
- **Stealth Mode**: Generate new receive addresses automatically
- **Transaction Privacy**: Derive unique keypairs for each transaction

### **Anti-Malware Protection**
- **Process Isolation**: Sandboxed crypto operations
- **Binary Integrity**: SHA256 verification of executable
- **Debugger Detection**: Prevents debugging and reverse engineering
- **Memory Protection**: `mlock()` for sensitive data, `zeroize` on cleanup
- **Decoy Operations**: Fake crypto operations to confuse keyloggers
- **Terminal Clearing**: Secure cleanup of sensitive information

### **Backup & Recovery**
- **Encrypted Backups**: JSON files with double-layer encryption
- **QR Code Backups**: Paper storage with error correction
- **24-Word Recovery**: BIP39 compatible mnemonic phrases
- **Multi-Location Storage**: Forces backup in 3 different locations
- **Backup Verification**: Mandatory restore testing before activation

## 📋 Complete Command Reference

### Wallet Management
```bash
# Create new wallet
ryzan create --name <wallet> [--totp] [--daily-limit <lamports>] [--time-lock <hours>]

# Unlock existing wallet  
ryzan unlock --name <wallet> [--totp <code>]

# List all wallets
ryzan list

# Delete wallet (DANGEROUS)
ryzan delete --name <wallet> --totp <code> --confirm DELETE
```

### Transactions
```bash
# Send SOL
ryzan send <address> <amount> --totp <code> [--memo <text>] [--ephemeral]

# Generate receive address
ryzan receive [--amount <sol>] [--qr] [--new-address]

# Batch transactions
ryzan batch-send --file transactions.json --totp <code>

# Check balance
ryzan balance [--detailed]

# Transaction history
ryzan history [--limit <count>] [--export <file.csv>]
```

### Staking & DeFi
```bash
# Stake SOL
ryzan stake <validator-address> <amount> --totp <code>

# Portfolio overview
ryzan portfolio [--tokens] [--staking]

# Token swaps (DeFi integration)
ryzan swap <from-token> <to-token> <amount> --totp <code>
```

### Security & Backup
```bash
# Create encrypted backup
ryzan backup --output backup.json --totp <code>

# Recover from backup
ryzan recover --file backup.json [--name <new-name>]

# Export private key (DANGEROUS)
ryzan export-key --totp <code> --confirm YES

# Set spending limits
ryzan set-limit --daily <sol> --totp <code>

# Emergency panic mode
ryzan panic --emergency-code <code>
```

### Configuration
```bash
# Configure settings
ryzan config [--rpc <url>] [--auto-lock <minutes>] [--show]

# Update to latest version
ryzan update
```

## 🧪 Testing Instructions

### Prerequisites
- **Rust 1.70+**: Install from [rustup.rs](https://rustup.rs)
- **Solana CLI** (optional): For advanced testing
- **Mobile Authenticator**: Google Authenticator, Authy, etc.

### Test Suite

#### **1. Basic Installation Test**
```bash
# Build and verify
cargo build --release
./target/release/ryzan --version
./target/release/ryzan --help

# Expected: Shows version 0.1.0 and command help with thunderbolt logo
```

#### **2. Wallet Creation Test**
```bash
# Create test wallet
./target/release/ryzan create --name test-wallet --totp --daily-limit 500000000

# Follow prompts:
# 1. Enter secure password (12+ characters)
# 2. Confirm password
# 3. Scan QR code with authenticator app
# 4. Enter TOTP code to verify
# 5. Write down 24-word recovery phrase
# 6. Type confirmation: "I HAVE SAVED MY RECOVERY PHRASE"

# Expected: Wallet created successfully
```

#### **3. Wallet Operations Test**
```bash
# List wallets
./target/release/ryzan list
# Expected: Shows "test-wallet - 🔒 Locked"

# Unlock wallet
./target/release/ryzan unlock --name test-wallet
# Enter password and TOTP code
# Expected: Shows wallet public key and limits

# Check balance
./target/release/ryzan balance --detailed
# Expected: Shows 0 SOL balance with limits info
```

#### **4. Address Generation Test**
```bash
# Generate receive address
./target/release/ryzan receive --qr --new-address
# Expected: Shows new address + QR code

# Generate payment request
./target/release/ryzan receive --amount 0.1 --qr
# Expected: Shows payment URL and QR code
```

#### **5. Configuration Test**
```bash
# Show current config
./target/release/ryzan config --show
# Expected: Shows RPC endpoint and settings

# Update settings
./target/release/ryzan config --auto-lock 30
# Expected: Auto-lock timeout updated
```

#### **6. Security Features Test**
```bash
# Test TOTP requirement
./target/release/ryzan send 11111111111111111111111111111112 0.01 --totp 000000
# Expected: "Invalid TOTP code" error

# Test daily limit (if you have SOL)
./target/release/ryzan send 11111111111111111111111111111112 10.0 --totp <valid-code>
# Expected: "Exceeds daily limit" error
```

#### **7. Backup & Recovery Test**
```bash
# Create backup
./target/release/ryzan backup --output test-backup.json --totp <code>
# Expected: Encrypted backup file created

# Verify backup file
cat test-backup.json
# Expected: JSON with encrypted wallet data

# Test recovery (in a test environment)
./target/release/ryzan recover --file test-backup.json --name recovered-wallet
# Expected: Wallet restored successfully
```

#### **8. Error Handling Test**
```bash
# Test invalid commands
./target/release/ryzan unlock --name nonexistent
# Expected: "Wallet 'nonexistent' not found"

./target/release/ryzan send invalid-address 1.0 --totp 123456
# Expected: "Invalid recipient address"

# Test without unlocked wallet
./target/release/ryzan balance
# Expected: "No wallet unlocked" error
```

### **Live Network Testing** (Use with caution)

⚠️ **WARNING**: Only test with small amounts on devnet first!

```bash
# Switch to devnet for testing
ryzan config --rpc https://api.devnet.solana.com

# Get devnet SOL from faucet
# Visit: https://faucet.solana.com

# Test real transaction
ryzan send <test-address> 0.001 --totp <code> --memo "Ryzan test"
```

### **Performance & Security Testing**

#### **Memory Protection Test**
```bash
# Run with memory debugging
valgrind --tool=memcheck ./target/release/ryzan create --name memory-test --totp

# Expected: No memory leaks, sensitive data cleared
```

#### **Process Isolation Test**  
```bash
# Check for suspicious processes while running
ps aux | grep -E "(gdb|strace|wireshark)"

# Run security scan
./target/release/ryzan unlock --name test-wallet
# Expected: Security warnings if threats detected
```

## 🗂️ File Structure

```
~/.config/ryzan/
├── config.json          # Wallet configuration
└── vaults/
    ├── wallet1.vault     # Encrypted wallet files
    └── wallet2.vault
```

## 🐛 Troubleshooting

### Common Issues

**"Failed to create ryzan config directory"**
- Solution: Ensure write permissions to `~/.config/`

**"Invalid TOTP code"**  
- Solution: Check device time sync, try previous/next code

**"Wallet 'name' not found"**
- Solution: Use `ryzan list` to see available wallets

**"No wallet unlocked"**
- Solution: Run `ryzan unlock --name <wallet>` first

### Debug Mode
```bash
# Enable verbose logging
RUST_LOG=debug ./target/release/ryzan <command>
```

## 🔒 Security Best Practices

1. **Strong Passwords**: Use 20+ character passwords with mixed case, numbers, symbols
2. **Secure TOTP**: Use hardware authenticator if possible (YubiKey, etc.)
3. **Multiple Backups**: Store recovery phrases in 3+ secure, separate locations
4. **Verify Addresses**: Always double-check recipient addresses
5. **Regular Updates**: Keep Ryzan updated to latest version
6. **Offline Storage**: Consider air-gapped machines for large holdings
7. **Test Recoveries**: Regularly verify you can restore from backups

## 🚨 Emergency Procedures

### **Lost Password**
- Use 24-word recovery phrase with `ryzan recover`
- No password reset possible without recovery phrase

### **Compromised Device**
- Immediately run `ryzan panic --emergency-code <code>`
- Transfer funds to new wallet from secure device

### **Lost TOTP Device**
- Use recovery phrase to restore wallet on secure device
- Re-setup TOTP with new device

## 🤝 Contributing

Ryzan is built with security as the top priority. All contributions are welcome!

### Development Setup
```bash
git clone <repo>
cd ryzan
cargo test
cargo clippy
cargo fmt
```

### Security Guidelines
- All crypto operations must use constant-time algorithms
- Sensitive data must be zeroized after use
- New features require security review
- Tests must cover attack scenarios

## 📄 License

MIT License - see LICENSE file for details.

## ⚠️ Disclaimer

Ryzan is experimental software. While built with enterprise-grade security, use at your own risk. Always test with small amounts first. The developers are not responsible for any lost funds.

---

**Built with ⚡ by the Ryzan Team**

*Slash through crypto complexity with lightning-fast security.*