# ⚡ Ryzan

**Secure Solana wallet with 2FA protection**

```
██████╗ ██╗   ██╗███████╗ █████╗ ███╗   ██╗
██╔══██╗╚██╗ ██╔╝╚══███╔╝██╔══██╗████╗  ██║
██████╔╝ ╚████╔╝   ███╔╝ ███████║██╔██╗ ██║
██╔══██╗  ╚██╔╝   ███╔╝  ██╔══██║██║╚██╗██║
██║  ██║   ██║   ███████╗██║  ██║██║ ╚████║
╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

A CLI wallet for Solana with built-in security features including mandatory TOTP 2FA, encrypted storage, and secure transaction handling.

## Quick Install

**Option 1: Cargo Install (Recommended)**
```bash
cargo install ryzan
```

**Option 2: Install Script**
```bash
curl -sSL https://raw.githubusercontent.com/simplysabir/ryzan/main/install.sh | bash
```

**Option 3: Download from Releases**
Go to [Releases](https://github.com/simplysabir/ryzan/releases) and download for your platform.

**Option 4: Build from Source**
```bash
git clone https://github.com/simplysabir/ryzan
cd ryzan
cargo build --release
```

## Quick Start

```bash
# Create wallet
ryzan create --name main

# Unlock wallet  
ryzan unlock --name main --totp 123456

# Get receive address + QR code
ryzan receive

# Send SOL
ryzan send <address> 0.1 --totp 123456

# Check balance
ryzan portfolio
```

## Commands

| Command | Usage |
|---------|-------|
| `create` | Create new wallet |
| `unlock` | Unlock wallet with TOTP |
| `receive` | Show address + QR code |
| `send` | Send SOL to address |
| `portfolio` | Show balance |
| `backup` | Export encrypted backup |
| `recover` | Restore from backup |

## Security

- **TOTP 2FA** - Required for all transactions
- **ChaCha20-Poly1305** - Encrypted wallet storage  
- **Session timeout** - Auto-lock after 15 minutes
- **Secure backups** - Encrypted recovery files

## Development with Docker

**Build and run in development mode**
```bash
docker compose up --build
```

**Access the container shell**
```bash
docker compose exec ryzan bash
```

**Run specific commands**
```bash
docker compose exec ryzan ryzan create --name test
```

**Use the convenience script**
```bash
./docker-run.sh build
./docker-run.sh run --help
./docker-run.sh start
```

## Development Environment

For active development with live code changes:

```bash
# Use development compose file
docker compose -f docker-compose.dev.yml up --build

# This mounts your source code and enables live development
```

## License

MIT - Use at your own risk. Always test with small amounts first.
