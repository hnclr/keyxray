# KeyXray Command Reference 📖

This document provides a detailed explanation of every command and flag available in KeyXray.

## Global Flags
These flags are available for all commands:
- `-j, --json`: Output results in structured JSON format.
- `-o, --output string`: Save JSON results to a specified file.
- `-h, --help`: Display colorized help information.

---

## Commands

### 1. `inspect [file/dir]`
Technical analysis of private keys.
- **Origin Fingerprinting:** Guesses the source (e.g., Modern OpenSSH, Legacy OpenSSL, macOS) based on PEM headers and algorithms.
- **Passphrase Detection:** Checks if the key is encrypted.
- **Technical Specs:** Displays Key Type, Bit Length, and Fingerprint.

### 2. `audit [file/dir]`
Security posture assessment.
- **Permissions:** Flags any file not set to `0600`.
- **Strength:** Warns about RSA keys < 2048 bits and recommends modern alternatives like ED25519.

### 3. `clean [file/dir]`
Forensic reconstruction of malformed keys.
- **Deep Clean:** Strips ALL internal whitespace (spaces, tabs, newlines) from the Base64 body.
- **Reconstruction:** Re-wraps the payload to standard 64-character lines and ensures valid PEM markers.

### 4. `hunt [directory]`
Recursive search for hidden keys.
- **Standard Mode:** Scans the first 512 bytes for PEM markers.
- **`-d, --deep`**: Streams the entire content of every file to find embedded PEM markers.
- **`-s, --stego`**: Uses Shannon Entropy analysis to find hidden cryptographic material (blobs) without standard headers.
- **`-e, --extract`**: Automatically carves out and saves found keys/blobs to disk.

### 5. `score [file/dir]`
Mathematical randomness analysis.
- **Shannon Entropy:** Measures the entropy of the key material.
- **Trust Score:** Provides a 0-100 score based on randomness quality, flagging potential weak PRNG usage.

### 6. `match [directory]`
Management of key pairs.
- **Pairing:** Groups private and public keys based on matching fingerprints.
- **Orphan Report:** Lists keys that do not have a corresponding pair in the directory.

### 7. `convert [file]`
PEM format transformation.
- **`-f, --format string`**: Target format: `pkcs1` (Legacy RSA) or `pkcs8` (Modern Default).

### 8. `public [file/dir]`
Public key extraction.
- Regenerates the OpenSSH `.pub` authorized key string directly from the private key.

### 9. `comment [file.pub]`
Public key metadata management.
- **`-s, --set string`**: Updates the comment field (e.g., `user@host`) of a `.pub` file.

### 10. `generate`
Secure key pair creation.
- **`-n, --name string`**: Filename (default: `id_keyxray`).
- **`-t, --type string`**: Algorithm: `ed25519` (default) or `rsa` (4096-bit).
- Sets correct permissions (0600) automatically.
