use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use pqcrypto_kyber::kyber512::*;
use pqcrypto_traits::kem::{Ciphertext, SecretKey, SharedSecret, PublicKey};
use rand::RngCore;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

fn genkey() -> io::Result<()> {
    let (public_key, secret_key) = keypair();
    fs::write("public.key", public_key.as_bytes())?;
    fs::write("private.key", secret_key.as_bytes())?;
    println!("Keypair generated: public.key and private.key");
    Ok(())
}

fn encrypt_file(input_path: &Path, output_path: &Path, public_key_path: &Path) -> io::Result<()> {
    let public_key_bytes = fs::read(public_key_path)?;
    let public_key = PublicKey::from_bytes(&public_key_bytes).unwrap();

    let mut file = fs::File::open(input_path)?;
    let mut plaintext = Vec::new();
    file.read_to_end(&mut plaintext)?;

    let (shared_secret, ciphertext) = encapsulate(&public_key);

    let aes_key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted_data = cipher
        .encrypt(nonce, plaintext.as_ref())
        .expect("AES-GCM encryption failed");

    let mut output_file = fs::File::create(output_path)?;
    output_file.write_all(ciphertext.as_bytes())?;
    output_file.write_all(nonce.as_slice())?;
    output_file.write_all(&encrypted_data)?;

    println!("File encrypted successfully!");
    Ok(())
}

fn decrypt_file(input_path: &Path, output_path: &Path, private_key_path: &Path) -> io::Result<()> {
    let secret_key_bytes = fs::read(private_key_path)?;
    let secret_key = SecretKey::from_bytes(&secret_key_bytes).unwrap();

    let mut file = fs::File::open(input_path)?;
    let mut encrypted_content = Vec::new();
    file.read_to_end(&mut encrypted_content)?;

    let pqc_ciphertext_len = ciphertext_bytes();
    let nonce_len = 12;

    let pqc_ciphertext_bytes = &encrypted_content[..pqc_ciphertext_len];
    let nonce_bytes = &encrypted_content[pqc_ciphertext_len..pqc_ciphertext_len + nonce_len];
    let encrypted_data_with_tag = &encrypted_content[pqc_ciphertext_len + nonce_len..];

    let pqc_ciphertext = Ciphertext::from_bytes(pqc_ciphertext_bytes).unwrap();
    let shared_secret = decapsulate(&pqc_ciphertext, &secret_key);

    let aes_key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let decrypted_data = cipher
        .decrypt(nonce, encrypted_data_with_tag)
        .expect("AES-GCM decryption failed");

    fs::write(output_path, &decrypted_data)?;
    println!("File decrypted successfully!");
    Ok(())
}

fn main() {
    println!("What do you want to do?");
    println!("1. Generate new keypair");
    println!("2. Encrypt a file");
    println!("3. Decrypt a file");
    print!("Enter choice (1/2/3): ");
    io::stdout().flush().unwrap();

    let mut choice = String::new();
    io::stdin().read_line(&mut choice).unwrap();
    let choice = choice.trim();

    match choice {
        "1" => {
            if let Err(e) = genkey() {
                eprintln!("Key generation failed: {}", e);
            }
        }
        "2" => {
            print!("Enter path to file to encrypt: ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            let input = input.trim();

            print!("Enter path to public key file: ");
            io::stdout().flush().unwrap();
            let mut key = String::new();
            io::stdin().read_line(&mut key).unwrap();
            let key = key.trim();

            print!("Enter output encrypted file path: ");
            io::stdout().flush().unwrap();
            let mut output = String::new();
            io::stdin().read_line(&mut output).unwrap();
            let output = output.trim();

            if let Err(e) = encrypt_file(Path::new(input), Path::new(output), Path::new(key)) {
                eprintln!("Encryption failed: {}", e);
            }
        }
        "3" => {
            print!("Enter path to file to decrypt: ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            let input = input.trim();

            print!("Enter path to private key file: ");
            io::stdout().flush().unwrap();
            let mut key = String::new();
            io::stdin().read_line(&mut key).unwrap();
            let key = key.trim();

            print!("Enter output decrypted file path: ");
            io::stdout().flush().unwrap();
            let mut output = String::new();
            io::stdin().read_line(&mut output).unwrap();
            let output = output.trim();

            if let Err(e) = decrypt_file(Path::new(input), Path::new(output), Path::new(key)) {
                eprintln!("Decryption failed: {}", e);
            }
        }
        _ => {
            println!("Invalid choice.");
        }
    }
}