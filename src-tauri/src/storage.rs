use base64::{engine::general_purpose::STANDARD as b64_engine, Engine as _};
use keyring::Entry;
use rand::RngCore;

use crate::config::SERVICE_NAME;
use crate::error::Result;

pub fn get_secret(key_name: &str) -> Result<String> {
    let entry = Entry::new(SERVICE_NAME, key_name)?;

    match entry.get_password() {
        Ok(secret) if !secret.is_empty() => Ok(secret),
        _ => {
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            let new_secret = b64_engine.encode(&bytes);
            entry.set_password(&new_secret)?;

            Ok(new_secret)
        }
    }
}
