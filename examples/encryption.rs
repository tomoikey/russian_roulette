use aesstream::AesWriter;
use crypto::aessafe::AesSafe256Encryptor;
use pbkdf2::hmac::Hmac;
use sha2::Sha256;
use std::fs::File;
use std::io;

const AES_KEY_LENGTH: usize = 32;

fn main() {
    let mut plain_file = File::open("./examples/encryption_test/file_1.txt").unwrap();
    let encrypted_file = File::create("./examples/encryption_test/file_1.txt.rr").unwrap();
    let key = generate_key("password");
    let encryptor = AesSafe256Encryptor::new(&key);
    let mut writer = AesWriter::new(encrypted_file, encryptor).unwrap();
    io::copy(&mut plain_file, &mut writer).unwrap();
}

fn generate_key<STRING: Into<String>>(password: STRING) -> [u8; AES_KEY_LENGTH] {
    let mut key = [0u8; AES_KEY_LENGTH];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(password.into().as_bytes(), b"salt", 10000, &mut key).unwrap();
    key
}
