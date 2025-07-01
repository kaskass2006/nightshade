# NightShade

**NightShade** by EvilWhales is a next-level Rust-based encryption and in-memory loader crafted for red team operators who live in the shadows. This beast encrypts your payloads (think Cobalt Strike shellcode or raw binaries) with bulletproof ChaCha20-Poly1305 or XChaCha20, throws in hardcore obfuscation, and spits out a stealthy Windows EXE that decrypts and runs your payload straight in memory — no disk, no trace, no mercy.

---

## Features

- Quantum-resistant ChaCha20-Poly1305 or XChaCha20 encryption for ultimate security
- Multi-layer key, nonce, and password obfuscation with XOR masking
- PBKDF2-SHA256 key derivation with 150,000 iterations for rock-solid keys
- In-memory payload execution via `VirtualAlloc` and `CreateThread` — nothing touches disk
- Advanced anti-analysis: anti-debugging, sandbox detection, and memory anomaly checks
- Slick CLI menu for quick setup:
  - Input raw hex payloads or load from files
  - Set output EXE name
  - Toggle XChaCha20 mode for extra nonce strength
  - Build a standalone Windows loader EXE
- Built with lean, safe Rust for speed and minimal footprint
- Supports x86/x64 Windows targets

---

## Requirements

- Rust toolchain (get it via [rustup](https://rustup.rs/))
- Windows target for cross-compilation (if building on Linux/macOS)
- Cargo (Rust’s package manager)

---

## Installation

Clone the repo and build the tool:

```bash
git clone https://github.com/EvilWhales/nightshade.git
cd nightshade
cargo build --release
```

For Windows EXE output, use the Windows target:

```bash
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

---

## Usage

Fire up the CLI (works on Linux/Windows):

```bash
./target/release/nightshade
```

You’ll get a badass menu by EvilWhales:

```
=== NightShade CLI by EvilWhales 2025 ===
1) Set raw payload (hex string, e.g. 90 90 90 CC)
2) Set path to payload file (file.bin)
3) Set output EXE name
4) Set encryption password
5) Toggle XChaCha20 mode (current: OFF)
6) Build stealth loader
7) Show current config
Ctrl+C to exit
Enter choice:
```

- **1**: Drop raw shellcode as hex bytes.
- **2**: Point to a payload file.
- **3**: Name your output EXE (must end with `.exe`).
- **4**: Set a strong password (12+ chars).
- **5**: Switch between ChaCha20 and XChaCha20.
- **6**: Build the stealth EXE with your encrypted payload.
- **7**: Check your current setup.

---

## How It Works

1. You feed NightShade a payload (shellcode, binary, whatever).
2. It encrypts it with ChaCha20-Poly1305 or XChaCha20, using a key derived from your password.
3. Keys, nonces, and passwords get scrambled with XOR for extra stealth.
4. A custom Rust loader is generated, embedding the encrypted payload and decryption logic.
5. The loader is compiled into a standalone Windows EXE.
6. When run, the EXE decrypts and executes the payload in memory, dodging disk-based detection.

---

## Security & Stealth

- ChaCha20-Poly1305 or XChaCha20 for ironclad encryption and integrity
- Heavy-duty obfuscation to throw off static analysis
- In-memory execution to bypass disk scans
- Anti-debugging via PEB `BeingDebugged` flag
- Sandbox detection through CPU, RAM, and sleep timing checks
- Memory anomaly detection to spot EDRs
- PBKDF2-SHA256 with high iterations for secure key derivation

---

## Development

- `main.rs` handles the CLI, encryption, and loader generation.
- Uses `winapi` for low-level Windows memory and thread ops.
- Tweak the loader template in `generate_loader_source()` for custom stealth tricks.
- Anti-analysis logic lives in the `anti_analysis` module.

---


## License

[MIT License](LICENSE)

---

## Disclaimer

NightShade is for **authorized security research, red teaming, and pentesting only**. Unauthorized use is a no-go and could land you in hot water. Stay legal, stay sharp.

---

Need help with cross-compilation or want to level up NightShade? Hit me up!

*Stay stealthy,*
**EvilWhales**

Contact: t.me/EvilWhales
