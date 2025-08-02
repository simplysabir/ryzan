const ENTER_KEY = 13
const fileSystem = {
  'README.md': `██████╗ ██╗   ██╗███████╗ █████╗ ███╗   ██╗
██╔══██╗╚██╗ ██╔╝╚══███╔╝██╔══██╗████╗  ██║
██████╔╝ ╚████╔╝   ███╔╝ ███████║██╔██╗ ██║
██╔══██╗  ╚██╔╝   ███╔╝  ██╔══██║██║╚██╗██║
██║  ██║   ██║   ███████╗██║  ██║██║ ╚████║  ⚡
╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝

⚡ RYZAN - Ultra-Secure Solana Wallet CLI

Enterprise-grade security with zero-trust architecture.
Built for professionals who demand maximum security.

Supported commands are:
  - ls: list directory contents
  - cat: concatenate and print files
  - clear: clear the terminal screen
  - help: show available commands
  - install: installation instructions
  - demo: see wallet commands in action
`,
  'install.txt': `🚀 RYZAN INSTALLATION

Option 1: Cargo Install (Recommended)
  cargo install ryzan

Option 2: Install Script
  curl -sSL https://raw.githubusercontent.com/simplysabir/ryzan/main/install.sh | bash

Option 3: Download from Releases
  Visit: https://github.com/simplysabir/ryzan/releases

Quick Start:
  ryzan create --name main
  ryzan unlock --name main
  ryzan balance`,

  'demo.txt': `🎯 RYZAN WALLET COMMANDS

# Create your first wallet
ryzan create --name main --totp

# Unlock wallet for use  
ryzan unlock --name main --totp 123456

# Check balance
ryzan balance --detailed

# Send SOL
ryzan send <address> 0.1 --totp 123456

# Send SPL tokens
ryzan send <address> 100 --totp 123456 --token <mint-address>

# Generate receive address
ryzan receive --qr --new-address

# Create encrypted backup
ryzan backup --output backup.json --totp 123456

All operations require TOTP verification for security.`,

  'security.txt': `🔐 RYZAN SECURITY FEATURES

• Military-grade ChaCha20-Poly1305 encryption
• Mandatory TOTP 2FA for all transactions  
• 10,000-round key derivation for passwords
• Ephemeral keypairs for maximum privacy
• Zero-trust architecture - verify everything
• Memory protection with mlock/munlock
• Anti-malware process isolation
• Secure backup system with encryption

Security is not optional - it's built into every operation.`,

  'features.txt': `⚡ RYZAN CORE FEATURES

💰 WALLET OPERATIONS:
  • Create secure wallets with TOTP setup
  • Multi-wallet support with encrypted storage
  • Backup & recovery with encrypted files

💸 TRANSACTIONS:
  • Send SOL with TOTP verification
  • Send SPL tokens with automatic ATA creation
  • Batch transactions from JSON files
  • Privacy mode with ephemeral keypairs

🏛️ STAKING & DeFi:
  • SOL staking with validator selection
  • Portfolio tracking with token balances

Built for professionals who demand security.`,

  'whitepaper.txt': `📖 RYZAN TECHNICAL WHITEPAPER

ABSTRACT:
Ryzan is an ultra-secure Solana wallet CLI designed for enterprise 
and professional users who require maximum security.

ARCHITECTURE:
• Zero-trust security model
• ChaCha20-Poly1305 authenticated encryption
• RFC 6238 compliant TOTP implementation
• Ephemeral key derivation for privacy

CRYPTOGRAPHIC PRIMITIVES:
• Encryption: ChaCha20-Poly1305 (256-bit keys)
• Authentication: TOTP with SHA-1 (RFC 6238)
• Memory Protection: Secure allocation with zeroization

Repository: https://github.com/simplysabir/ryzan`,
}

new class Terminal {
  constructor() {
    this.onKeyDown = this.onKeyDown.bind(this)
    this.clearHistory = this.clearHistory.bind(this)
    this.addHistory = this.addHistory.bind(this)
    this.listFiles = this.listFiles.bind(this)
    this.catFile = this.catFile.bind(this)
    this.scrollToBottom = this.scrollToBottom.bind(this)

    this.history = []
    this.elements = {
      input: document.querySelector('.input'),
      terminal: document.querySelector('.terminal'),
      outputContainer: document.querySelector('.outputContainer')
    }
    this.prompt = '$'
    this.commands = {
      clear: this.clearHistory,
      ls: this.listFiles,
      cat: this.catFile,
      help: () => this.catFile('README.md'),
      install: () => this.catFile('install.txt'),
      demo: () => this.catFile('demo.txt'),
      security: () => this.catFile('security.txt'),
      features: () => this.catFile('features.txt'),
      whitepaper: () => this.catFile('whitepaper.txt'),
    }
    this.elements.input.addEventListener('keydown', this.onKeyDown)
    this.catFile('README.md')
  }
  
  clearHistory() {
    this.history = []
    this.elements.outputContainer.innerHTML = ''
  }
  
  catFile(fileName) {
    if (fileName in fileSystem) 
      this.addHistory(fileSystem[fileName])
    else 
      this.addHistory(`cat: ${fileName}: No such file or directory`)
  }
  
  scrollToBottom() {
    this.elements.terminal.scrollTop = this.elements.terminal.scrollHeight
  }
  
  addHistory(output) {
    this.history.push(output)
   
    var outputText = document.createTextNode(output)
    let outputEl = document.createElement('pre')
    
    outputEl.classList.add('output')
    outputEl.appendChild(outputText)
    
    this.elements.outputContainer.appendChild(outputEl)
  }
  
  listFiles(dir) {
    const output = Object.keys(fileSystem).reduce((acc, curr, index) => {
      const deliminator = index % 3 === 0 && index !== 0 ? '\n' : '\t'
      return `${acc}${curr}${deliminator}`
    }, '')
    
    this.addHistory(output)
  }

  clearInput() { this.elements.input.value = '' }

  onKeyDown(e) {
    // Only respond to Enter key presses
    if (e.keyCode !== ENTER_KEY) return
    
    const inputText = this.elements.input.value
    const inputArray = inputText.split(' ')
    const inputCommand = inputArray[0]
    const arg = inputArray[1]
    
    this.addHistory(`${this.prompt} ${inputText}`)
    this.clearInput()
    
    /* If the command line was empty, stop. 
       We don't want to interpret it as a command.
       It's fine to feed a line to the terminal */
    if (inputCommand === '') return

    const command = this.commands[inputCommand]
    
    if (command)
      command(arg)
    else
      this.addHistory(`sh: command not found: ${inputCommand}`)
      
    this.scrollToBottom()
  }
  
}