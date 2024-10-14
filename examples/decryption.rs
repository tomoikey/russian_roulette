use std::fs::File;
use std::io;
use aesstream::AesReader;
use crypto::aessafe::AesSafe256Decryptor;
use pbkdf2::hmac::Hmac;
use sha2::Sha256;

const AES_KEY_LENGTH: usize = 32;

fn main() {
    let encrypted_file = File::open("./examples/encryption_test/file_1.txt.rr").unwrap();
    let mut decrypted_file = File::create("./examples/encryption_test/file_1_decrypted.txt").unwrap();
    let key = generate_key("password");
    let decryptor = AesSafe256Decryptor::new(&key);
    let mut reader = AesReader::new(encrypted_file, decryptor).unwrap();
    io::copy(&mut reader, &mut decrypted_file).unwrap();
}

fn generate_key<STRING: Into<String>>(password: STRING) -> [u8; AES_KEY_LENGTH] {
    let mut key = [0u8; AES_KEY_LENGTH];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(password.into().as_bytes(), b"salt", 10000, &mut key).unwrap();
    key
}