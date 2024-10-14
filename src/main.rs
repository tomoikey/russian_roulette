use aesstream::{AesReader, AesWriter};
use clap::{Parser, Subcommand, ValueEnum};
use crypto::aessafe::{AesSafe256Decryptor, AesSafe256Encryptor};
use dialoguer::Confirm;
use indicatif::{ProgressBar, ProgressStyle};
use pbkdf2::hmac::Hmac;
use rand::Rng;
use sha2::Sha256;
use std::fs::{remove_file, File};
use std::io;
use std::path::Path;
use walkdir::WalkDir;

const AES_KEY_LENGTH: usize = 32;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    r#type: Type,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TargetDirectory {
    Home,
    Current,
}

#[derive(Debug, Clone, Copy, Subcommand)]
enum Type {
    Encrypt {
        #[arg(long, value_parser = clap::value_parser!(u8).range(0..=100))]
        probability: u8,
        #[arg(long = "target")]
        target_directory: Option<TargetDirectory>,
    },
    Decrypt {
        #[arg(long = "target")]
        target_directory: Option<TargetDirectory>,
    },
}

impl Type {
    pub fn target_directory(&self) -> Option<TargetDirectory> {
        match self {
            Self::Encrypt {
                target_directory, ..
            } => *target_directory,
            Self::Decrypt { target_directory } => *target_directory,
        }
    }
}

const PASSWORD: &str = "password";

fn main() -> Result<(), String> {
    let args = Args::parse();
    let target_directory = args.r#type.target_directory().unwrap_or_else(|| {
        let choice = dialoguer::Select::new()
            .with_prompt("Select the target directory")
            .items(&["Home", "Current"])
            .default(0)
            .interact()
            .expect("Failed to get the choice");
        match choice {
            0 => TargetDirectory::Home,
            1 => TargetDirectory::Current,
            _ => unreachable!(),
        }
    });
    let target_directory = match target_directory {
        TargetDirectory::Home => dirs::home_dir(),
        TargetDirectory::Current => std::env::current_dir().ok(),
    }
    .ok_or_else(|| "Failed to get the directory".to_string())?;
    let dir_entries = WalkDir::new(&target_directory)
        .into_iter()
        .flatten()
        .filter(|n| n.path().is_file())
        .collect::<Vec<_>>();

    match args.r#type {
        Type::Encrypt { probability, .. } => {
            show_logo();
            let confirm = Confirm::new()
                .with_prompt("ARE YOU READY?")
                .interact()
                .expect("Failed to get the confirmation");
            if confirm {
                if rand::thread_rng().gen_range::<u8, _>(0..=100) <= probability {
                    println!("{} files will be encrypted...", dir_entries.len());
                    let progress_bar = initialize_progress_bar(dir_entries.len() as u64);
                    show_unlucky();
                    for dir_entry in dir_entries {
                        progress_bar.inc(1);
                        let path = dir_entry.path();
                        encrypt_file(
                            PASSWORD,
                            &mut File::open(path).map_err(|e| e.to_string())?,
                            path,
                        )
                        .map_err(|e| e.to_string())?;
                        remove_file(path).map_err(|e| e.to_string())?
                    }
                    println!("All files have been encrypted!");
                } else {
                    show_safe();
                }
            }
        }
        Type::Decrypt { .. } => {
            let dir_entries = dir_entries
                .into_iter()
                .filter(|n| n.path().extension().is_some_and(|ext| ext == "rr"))
                .collect::<Vec<_>>();
            println!("{} files will be decrypted...", dir_entries.len());
            let progress_bar = initialize_progress_bar(dir_entries.len() as u64);
            for dir_entry in dir_entries {
                progress_bar.inc(1);
                let path = dir_entry.path();
                decrypt_file(PASSWORD, File::open(path).map_err(|e| e.to_string())?, path)
                    .map_err(|e| e.to_string())?;
                remove_file(path).unwrap();
            }

            println!("All files have been decrypted!");
        }
    }

    Ok(())
}

fn encrypt_file<STRING: Into<String>>(
    password: STRING,
    file: &mut File,
    path: &Path,
) -> io::Result<u64> {
    let encrypted_file = File::create(format!("{}.rr", path.display()))?;
    let encryptor = AesSafe256Encryptor::new(&generate_key(password));
    let mut writer = AesWriter::new(encrypted_file, encryptor)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    io::copy(file, &mut writer)
}

fn decrypt_file<STRING: Into<String>>(
    password: STRING,
    file: File,
    path: &Path,
) -> io::Result<u64> {
    let decrypted_file_name = path
        .file_stem()
        .expect("Failed to strip the extension")
        .to_str()
        .expect("Failed to convert to string");
    let mut decrypted_file = File::create(decrypted_file_name)?;
    let mut reader = AesReader::new(file, AesSafe256Decryptor::new(&generate_key(password)))?;
    io::copy(&mut reader, &mut decrypted_file)
}

fn generate_key<STRING: Into<String>>(password: STRING) -> [u8; AES_KEY_LENGTH] {
    let mut key = [0u8; AES_KEY_LENGTH];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(password.into().as_bytes(), b"salt", 10000, &mut key)
        .expect("Failed to generate the key");
    key
}

fn initialize_progress_bar(length: u64) -> ProgressBar {
    let progress_bar = ProgressBar::new(length);
    progress_bar.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] {msg} {percent:>3}% [{bar:20.cyan/blue}] {pos}/{len}",
        )
            .expect("Failed to set the style")
            .progress_chars("##-"),
    );
    progress_bar
}

fn show_logo() {
    println!(
        r#"
    _____               _               _____             _      _   _       
   |  __ \             (_)             |  __ \           | |    | | | |      
   | |__) |   _ ___ ___ _  __ _ _ __   | |__) |___  _   _| | ___| |_| |_ ___ 
   |  _  / | | / __/ __| |/ _` | '_ \  |  _  // _ \| | | | |/ _ \ __| __/ _ \
   | | \ \ |_| \__ \__ \ | (_| | | | | | | \ \ (_) | |_| | |  __/ |_| ||  __/
   |_|  \_\__,_|___/___/_|\__,_|_| |_| |_|  \_\___/ \__,_|_|\___|\__|\__\___|
"#
    );
}

fn show_safe() {
    println!(
        r#"
      _____         ______ ______ 
    / ____|  /\   |  ____|  ____|
   | (___   /  \  | |__  | |__   
    \___ \ / /\ \ |  __| |  __|  
    ____) / ____ \| |    | |____ 
   |_____/_/    \_\_|    |______|
"#
    );
}

fn show_unlucky() {
    println!(
        r#"
     _    _ _   _ _     _    _  _____ _  ____     __
    | |  | | \ | | |   | |  | |/ ____| |/ /\ \   / /
    | |  | |  \| | |   | |  | | |    | ' /  \ \_/ / 
    | |  | | . ` | |   | |  | | |    |  <    \   /  
    | |__| | |\  | |___| |__| | |____| . \    | |   
     \____/|_| \_|______\____/ \_____|_|\_\   |_|   
"#
    );
}
