use std::sync::Mutex;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use keyring::Entry;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use crate::config::{SERVICE_NAME, SESSION_KEY};
use crate::error::{AppError, Result};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionClaims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
}

static SESSION: Lazy<Mutex<Option<SessionClaims>>> = Lazy::new(|| Mutex::new(None));

pub fn generate_token(username: &str, role: &str, secret: &[u8]) -> Result<String> {
    let exp = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .ok_or_else(|| AppError::Other("Expiration error".into()))?
        .timestamp() as usize;
    let claims = SessionClaims {
        sub: username.to_owned(),
        role: role.to_owned(),
        exp,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )?;
    Ok(token)
}

pub fn verify_token(token: &str, secret: &[u8]) -> Result<SessionClaims> {
    let token_data = decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(secret),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

pub fn save_token(token: &str) -> Result<()> {
    let entry = Entry::new(SERVICE_NAME, SESSION_KEY)?;
    entry.set_password(token)?;
    Ok(())
}

pub fn get_token() -> Result<String> {
    let entry = Entry::new(SERVICE_NAME, SESSION_KEY)?;
    let token = entry.get_password()?;
    Ok(token)
}

pub fn delete_token() -> Result<()> {
    let entry = Entry::new(SERVICE_NAME, SESSION_KEY)?;
    entry.delete_credential()?;
    Ok(())
}


pub fn get_session_claims() -> Result<SessionClaims> {
    let guard = SESSION
        .lock()
        .map_err(|_| AppError::Internal("Session mutex error".into()))?;

    guard.clone().ok_or_else(|| AppError::Authentication("Not logged in".into()))
}

pub fn clear_session() {
    if let Ok(mut s) = SESSION.lock() {
        *s = None;
    }
}