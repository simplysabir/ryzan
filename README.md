# ⚡ Ryzan - Ultra-Secure Solana Wallet CLI

> *Enterprise-grade security with zero-trust architecture - Professional crypto management made simple*

```
██████╗ ██╗   ██╗███████╗ █████╗ ███╗   ██╗
██╔══██╗╚██╗ ██╔╝╚══███╔╝██╔══██╗████╗  ██║
██████╔╝ ╚████╔╝   ███╔╝ ███████║██╔██╗ ██║
██╔══██╗  ╚██╔╝   ███╔╝  ██╔══██║██║╚██╗██║
██║  ██║   ██║   ███████╗██║  ██║██║ ╚████║  ⚡
╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝  
```

**Ryzan** is the most secure Solana wallet you'll ever use. Built for professionals who demand military-grade security without sacrificing speed.

## Why Ryzan?

✅ **Military-grade encryption** with ChaCha20-Poly1305  
✅ **Mandatory 2FA** for every transaction  
✅ **Ephemeral keys** for maximum privacy  
✅ **SOL + SPL tokens** support  
✅ **Enterprise backup** system  
✅ **Lightning-fast CLI** interface  

## Quick Install

### Option 1: Cargo Install (Recommended)
```bash
cargo install ryzan
```

### Option 2: Install Script
```bash
curl -sSL https://raw.githubusercontent.com/simplysabir/ryzan/main/install.sh | bash
```

### Option 3: Download from Releases
Go to [Releases](https://github.com/simplysabir/ryzan/releases) and download for your platform.

### Option 4: Build from Source
```bash
git clone https://github.com/simplysabir/ryzan
cd ryzan
cargo build --release
```

## Quick Start

```bash
# Create your first wallet
ryzan create --name main

# Unlock and check balance
ryzan unlock --name main
ryzan balance

# Send SOL
ryzan send <address> 0.1 --totp <code>

# Send SPL tokens
ryzan send <address> 100 --totp <code> --token <mint-address>
```

## Core Commands

| Command | Description |
|---------|-------------|
| `ryzan create --name <wallet>` | Create new secure wallet |
| `ryzan unlock --name <wallet>` | Unlock wallet for use |
| `ryzan send <address> <amount> --totp <code>` | Send SOL |
| `ryzan send <address> <amount> --totp <code> --token <mint>` | Send SPL tokens |
| `ryzan balance` | Check wallet balance |
| `ryzan backup --output backup.json --totp <code>` | Create encrypted backup |
| `ryzan recover --file backup.json` | Restore from backup |

## Security Features

- **🔐 ChaCha20-Poly1305 Encryption**: Military-grade cryptography
- **📱 TOTP 2FA**: Required for all transactions
- **👻 Ephemeral Keys**: New address for every transaction
- **🛡️ Zero-Trust**: Verify everything, trust nothing
- **💾 Secure Backups**: Encrypted recovery files
- **🚫 Anti-Malware**: Process isolation and memory protection

## Docker Support

```bash
# Run with Docker
docker run -it simplysabir/ryzan:latest

# Or use docker-compose
docker-compose up -d
```

## Need Help?

- **Documentation**: Full docs in this repository
- **Issues**: [Report bugs here](https://github.com/simplysabir/ryzan/issues)
- **Security**: Report vulnerabilities privately

## License

MIT License - Use at your own risk. Always test with small amounts first.

---

**Built with ⚡ by professionals, for professionals.**