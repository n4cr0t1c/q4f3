# q4f3

This project provides file encryption and decryption using a hybrid post-quantum cryptographic approach. It combines:

- Kyber512 (post-quantum KEM) for key encapsulation
- AES-256-GCM for symmetric authenticated encryption

---

## Features
- Generate Kyber public/private keypairs
- Encrypt files with a hybrid PQC + AES construction
- Decrypt files using the Kyber private key
- Authenticated encryption to ensure integrity

---

## Dependencies
- [pqcrypto-kyber](https://crates.io/crates/pqcrypto-kyber)
- [aes-gcm](https://crates.io/crates/aes-gcm)
- [rand](https://crates.io/crates/rand)

---

## Usage
```bash
cd q4f3/src
cargo run
```
The tool allows the user to generate 2 corresponding keys. 
```bash
private.key
public.key
```
The public key will be used to encrypt a file and the private key to decrypt it.

## Project Structure
```bash
- main.rs        # Main CLI
- Cargo.toml     # Dependencies
```

