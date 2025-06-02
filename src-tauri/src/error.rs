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

    #[error("Error: {0}")]
    Error(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("IO error: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, AppError>;


impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e.to_string())
    }
}

impl From<rsa::errors::Error> for AppError {
    fn from(e: rsa::errors::Error) -> Self {
        AppError::Internal(format!("RSA error: {}", e))
    }
}

impl From<String> for AppError {
    fn from(e: String) -> Self {
        AppError::Other(e)
    }
}

impl From<AppError> for InvokeError {
    fn from(e: AppError) -> Self {
        InvokeError::from(e.to_string())
    }
}


impl From<rsa::pkcs1::Error> for AppError {
    fn from(e: rsa::pkcs1::Error) -> Self {
        AppError::Internal(format!("RSA PKCS1 error: {}", e))
    }
}

impl From<rsa::pkcs8::spki::Error> for AppError {
    fn from(e: rsa::pkcs8::spki::Error) -> Self {
        AppError::Internal(format!("RSA PKCS8 error: {}", e))
    }
}

impl From<rsa::pkcs8::Error> for AppError {
    fn from(e: rsa::pkcs8::Error) -> Self {
        AppError::Internal(format!("RSA PKCS8 error: {}", e))
    }
}



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
