use base64::{engine::general_purpose::STANDARD as b64_engine, Engine as _};
use once_cell::sync::Lazy;
use std::error::Error;

use crate::config::{JWT_KEY, PEPPER_KEY, SQLCIPHER_KEY};
use crate::error::{AppError, Result};
use crate::storage::get_secret;

pub struct Secret(Vec<u8>);

impl Secret {
    pub fn from_base64(s: &str) -> Result<Self> {
        let decoded = b64_engine.decode(s)?;
        Ok(Secret(decoded))
    }

    pub fn to_base64(&self) -> String {
        b64_engine.encode(&self.0)
    }

    pub fn global(lazy: &'static Lazy<Result<Secret>>) -> Result<&'static [u8]> {
        let inner = lazy.as_ref();

        match inner {
            Ok(secret) => Ok(secret.as_ref()),
            Err(e) => Err(AppError::Other(format!("Required secret unavailable: {}", e))),
        }
    }
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub static PEPPER: Lazy<Result<Secret>> = Lazy::new(|| {
    let secret = get_secret(PEPPER_KEY)?;
    let decoded = Secret::from_base64(&secret)?;
    Ok(decoded)
});

pub static SQLCIPHER: Lazy<Result<Secret>> = Lazy::new(|| {
    let secret = get_secret(SQLCIPHER_KEY)?;
    let decoded = Secret::from_base64(&secret)?;
    Ok(decoded)
});

pub static JWT_SECRET: Lazy<Result<Secret>> = Lazy::new(|| {
    let secret = get_secret(JWT_KEY)?;
    let decoded = Secret::from_base64(&secret)?;
    Ok(decoded)
});

// pub static SQLCIPHER: Lazy<Result<Password, storage::error::Error>> = Lazy::new(|| {get_secret(SQLCIPHER_KEY)});
// pub static PEPPER: Lazy<Result<Password, storage::error::Error>> = Lazy::new(|| {get_secret(PEPPER_KEY)});
