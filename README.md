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
| `ryzan update` | Auto-update to latest version |

## Auto-Update Feature

Ryzan includes a production-ready auto-update system that checks for the latest version and offers multiple update methods:

```bash
# Check for updates and choose your preferred method
ryzan update
```

The update system will:
- ✅ Check for the latest version from GitHub releases
- 🔄 Compare with your current version
- 🎯 Offer choice between cargo install and installation script
- 🛡️ Preserve all wallet data during updates
- 📱 Provide fallback options if no releases are available

**Update Methods:**
1. **Cargo Install** (recommended for developers): `cargo install ryzan --force`
2. **Installation Script** (recommended for end users): Downloads and runs the latest install script
3. **Manual Update**: Provides instructions for manual installation

## Security Features

- **🔐 ChaCha20-Poly1305 Encryption**: Military-grade cryptography
- **📱 TOTP 2FA**: Required for all transactions
- **👻 Ephemeral Keys**: New address for every transaction
- **🛡️ Zero-Trust**: Verify everything, trust nothing
- **💾 Secure Backups**: Encrypted recovery files
- **🚫 Anti-Malware**: Process isolation and memory protection

## Docker Support

### Build and Run Locally

```bash
# Build the Docker image
docker build -t ryzan:latest .

# Run interactively
docker run -it --rm ryzan:latest

# Run with persistent storage
docker run -it --rm \
  -v ryzan_config:/home/ryzan/.config/ryzan \
  ryzan:latest

# Or use docker-compose for easier management
docker compose up -d
docker compose exec ryzan ryzan --help
```

### Development with Docker

```bash
# Build and run in development mode
docker compose up --build

# Access the container shell
docker compose exec ryzan bash

# Run specific commands
docker compose exec ryzan ryzan create --name test

# Use the convenience script
./docker-run.sh build
./docker-run.sh run --help
./docker-run.sh start
```

### Development Environment

For active development with live code changes:

```bash
# Use development compose file
docker compose -f docker-compose.dev.yml up --build

# This mounts your source code and enables live development
```

## Need Help?

- **Documentation**: Full docs in this repository
- **Issues**: [Report bugs here](https://github.com/simplysabir/ryzan/issues)
- **Security**: Report vulnerabilities privately

## License

MIT License - Use at your own risk. Always test with small amounts first.

---

**Built with ⚡ by professionals, for professionals.**