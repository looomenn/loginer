use std::env;
use std::path::{Component, PathBuf};

use whoami;
use sysinfo::{Disks, System};
use winapi::um::winuser::GetSystemMetrics;

use argon2::{Argon2};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use keyring::Entry;
use winreg::{enums::HKEY_CURRENT_USER, RegKey, RegValue};

use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::{SigningKey, VerifyingKey, Signature};
use rsa::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::signature::{RandomizedSigner, Verifier, Keypair, SignatureEncoding};
use rsa::sha2::{Sha256, Digest};
use crate::config::{argon2_params, ARGON2_ALGO, ARGON2_VERSION};
use crate::globals::{PEPPER, Secret};

use crate::config::{SERVICE_NAME, PUB_KEY, REG_PATH, REG_VALUE};
use crate::error::{AppError, Result};
use log::info;

fn get_sysinfo(install_dir: &PathBuf) -> String {
    let mut sys = System::new_all();
    sys.refresh_all();

    let root_str = install_dir
        .components()
        .find_map(|c| match c {
            Component::Prefix(prefix) => {
                if let std::path::Prefix::Disk(d) = prefix.kind() {
                    Some(format!("{}:\\", d as char))
                } else {
                    None
                }
            }
            _ => None,
        })
        .unwrap_or_default();

    let disks = Disks::new_with_refreshed_list();
    let disk_volume = disks
        .iter()
        .find(|d| d.mount_point().to_string_lossy().to_lowercase() == root_str.to_lowercase())
        .map(|d| d.total_space())
        .unwrap_or(0);

    format!(
        "username:{}\n\
         computer:{}\n\
         windows:{}\n\
         system32:{}\n\
         mouse_buttons:{}\n\
         screen_height:{}\n\
         memory:{}\n\
         disk_volume:{}",
        whoami::username(),
        whoami::fallible::hostname().unwrap_or_default(),
        env::var("WINDIR").unwrap_or_default(),
        env::var("WINDIR")
            .map(|w| format!("{}\\System32", w))
            .unwrap_or_default(),
        unsafe { GetSystemMetrics(43) }, // SM_CMOUSEBUTTONS
        unsafe { GetSystemMetrics(1) },  // SM_CYSCREEN
        sys.total_memory(),
        disk_volume
    )
}

fn hasher(install_dir: &PathBuf) -> Result<Vec<u8>> {
    let info_str = get_sysinfo(install_dir);

    let info_bytes = info_str.as_bytes();

    let pepper = Secret::global(&PEPPER)?;
    let params = argon2_params();
    let argon2 = Argon2::new_with_secret(pepper, ARGON2_ALGO, ARGON2_VERSION, params);

    let mut out = vec![0u8; 32];
    const SALT_RAW: &[u8] = b"LoginerMachineSalt";

    argon2?.hash_password_into(info_bytes, SALT_RAW, &mut out)?;

    Ok(out)
}

fn reg_write(sig: &[u8]) -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (subk, _) = hkcu.create_subkey(REG_PATH)?;
    let rv = RegValue {
        vtype: winreg::enums::RegType::REG_BINARY,
        bytes: sig.to_vec(),
    };
    subk.set_raw_value(REG_VALUE, &rv)?;
    Ok(())
}

fn reg_read() -> Result<Vec<u8>> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let subk = hkcu.open_subkey(REG_PATH)?;
    let rv = subk.get_raw_value(REG_VALUE)?;
    Ok(rv.bytes)
}


pub fn gen_key(install_dir: &PathBuf) -> Result<()> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let public_key = RsaPublicKey::from(&private_key);
    let pub_pem = public_key.to_public_key_pem(Default::default())?;

    let entry = Entry::new(SERVICE_NAME, PUB_KEY)?;
    entry.set_password(&pub_pem)?;

    let hash = hasher(install_dir)?;
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let signature = signing_key.sign_with_rng(&mut rng, &hash);

    let mut private_key_bytes = private_key.to_pkcs8_der()?.to_bytes().to_vec();
    private_key_bytes.zeroize();

    drop(private_key);
    drop(signing_key);

    reg_write(&signature.to_bytes())?;
    Ok(())
}


pub fn check_rsa(install_dir: &PathBuf) -> Result<()> {
    let entry = Entry::new(SERVICE_NAME, PUB_KEY)?;

    match entry.get_password() {
        Err(_) => gen_key(install_dir),

        Ok(pub_pem) => {
            let pubkey = RsaPublicKey::from_public_key_pem(&pub_pem)
                .map_err(|_| AppError::Internal("Failed to parse public key".to_string()))?;

            let sig_bytes = reg_read()
                .map_err(|_| AppError::Internal("Failed to read signature".to_string()))?;

            let hash = hasher(install_dir)?;

            let verifying_key = VerifyingKey::<Sha256>::new(pubkey);
            let signature = Signature::try_from(&sig_bytes[..])
                .map_err(|_| AppError::Internal("Failed to parse signature".to_string()))?;

            verifying_key
                .verify(&hash, &signature)
                .map_err(|_| AppError::Internal("Failed to verify signature".to_string()))?;

            Ok(())
        }
    }
}
