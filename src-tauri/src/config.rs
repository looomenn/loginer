use argon2::{Algorithm, Params, Version};

pub const SERVICE_NAME: &str = "loginer";

pub const ARGON2_ALGO: Algorithm = Algorithm::Argon2id;
pub const ARGON2_MEM_COST: u32 = 19456; // 19 MiB
pub const ARGON2_TIME_COST: u32 = 2;
pub const ARGON2_LANES: u32 = 1;
pub const ARGON2_VERSION: Version = Version::V0x13;
pub const ARGON2_OUTPUT_LENGTH: usize = 32;

pub fn argon2_params() -> argon2::Params {
    Params::new(
        ARGON2_MEM_COST,
        ARGON2_TIME_COST,
        ARGON2_LANES,
        Some(ARGON2_OUTPUT_LENGTH),
    )
    .unwrap()
}

pub const PEPPER_KEY: &str = "logger_pepper_key_yo";
pub const SQLCIPHER_KEY: &str = "sqlcipher_cipher_key_yo";

pub const JWT_KEY: &str = "jwt_signing_key_yo";

pub const SESSION_KEY: &str = "jwt_session_token";

pub const PUB_KEY: &str = "pub_key_yo";

pub const REG_PATH: &str = r"Software\Loginer";

pub const REG_VALUE: &str = "Signature";

pub const KEY_LIFETIME_SECONDS: u64 = 60 * 60 * 24 * 30; // 30 days
