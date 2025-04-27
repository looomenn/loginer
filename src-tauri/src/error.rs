use tauri::ipc::InvokeError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    // Crate errors
    #[error("Database connection failed: {0}")]
    Connection(#[from] rusqlite::Error),

    #[error("Keyring access failed: {0}")]
    Keyring(#[from] keyring::Error),

    #[error("Base64 decoding failed: {0}")]
    Decode(#[from] base64::DecodeError),

    #[error("Hasher setup error: {0}")]
    HasherSetupError(String),

    #[error("Hashing error: {0}")]
    HashError(String),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    // Additional errors
    #[error("Authentication failed: {0}")]
    Authentication(String),

    #[error("User not found with ID: {0}")]
    UserNotFound(i64),

    #[error("Other error: {0}")]
    Other(String),


    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, AppError>;

impl From<argon2::Error> for AppError {
    fn from(e: argon2::Error) -> Self {
        AppError::HasherSetupError(e.to_string())
    }
}
impl From<argon2::password_hash::Error> for AppError {
    fn from(e: argon2::password_hash::Error) -> Self {
        AppError::HashError(e.to_string())
    }
}

impl From<AppError> for InvokeError {
    fn from(e: AppError) -> Self {
        InvokeError::from(e.to_string())
    }
}
