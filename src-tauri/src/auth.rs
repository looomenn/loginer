use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::rngs::OsRng;

use crate::config::{argon2_params, ARGON2_ALGO, ARGON2_VERSION};
use crate::error::{AppError, Result};
use crate::globals::{Secret, PEPPER};

#[derive(Debug, Clone)]
pub struct Argon {
    pepper: Vec<u8>,
    algo: argon2::Algorithm,
    version: argon2::Version,
    params: argon2::Params,
}

impl Argon {

}

pub fn hash_password(password: &str) -> Result<String> {
    // let pepper = match PEPPER.as_ref() {
    //     Ok(pepper) => pepper.as_ref(),
    //     Err(err) => {
    //         return Err(AppError::Internal(format!("Required secret unavailable: {}", err)));
    //     }
    // };

    let pepper = Secret::global(&PEPPER)?;

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new_with_secret(pepper, ARGON2_ALGO, ARGON2_VERSION, argon2_params())?;

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();
    Ok(password_hash)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    // let pepper = match PEPPER.as_ref() {
    //     Ok(pepper) => pepper.as_ref(),
    //     Err(err) => {
    //         return Err(AppError::Internal(format!("Required secret unavailable: {}", err)));
    //     }
    // };

    let pepper = Secret::global(&PEPPER)?;

    let password_hash = PasswordHash::new(&hash)?;

    let argon2 = Argon2::new_with_secret(pepper, ARGON2_ALGO, ARGON2_VERSION, argon2_params())?;

    let is_valid = argon2
        .verify_password(password.as_bytes(), &password_hash)
        .is_ok();
    Ok(is_valid)
}
