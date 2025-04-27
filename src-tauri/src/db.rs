use crate::auth::{hash_password, verify_password};
use crate::error::{AppError, Result};
use crate::globals::{Secret, SQLCIPHER};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::sync::Mutex;
use base64::{engine::general_purpose::STANDARD as b64_engine, Engine as _};


#[derive(Debug, Serialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub role: String,
    pub blocked: bool,
    pub min_password_length: Option<u32>,
}

// Repo for user-related db operations.
pub struct UserRepo {
    conn: Mutex<Connection>,
}

impl UserRepo {
    pub fn new() -> Result<Self> {
        let conn = Connection::open("users.db")?;

        let key_bytes = Secret::global(&SQLCIPHER)?;
        // let key_str = SQLCIPHER.as_ref()?.as_ref();

        let key_b64 = b64_engine.encode(key_bytes);

        conn.pragma_update(None, "key", &key_b64)?;
        Ok(UserRepo { conn: Mutex::new(conn) })
    }

    fn map_poison_err<T>(_: T) -> AppError {
        AppError::Internal("Mutex poisoned during DB access".into())
    }

    pub fn init_db(&self) -> Result<()> {

        let conn_guard = self.conn.lock().map_err(Self::map_poison_err)?;

        conn_guard.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                blocked INTEGER NOT NULL DEFAULT 0,
                min_password_length INTEGER
             )",
            [],
        )?;

        let admin_hash = hash_password("admin")?;

        conn_guard.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role, blocked)\
             VALUES (?1, ?2, ?3, ?4)",
            params!["ADMIN", admin_hash, "admin", 0],
        )?;
        Ok(())
    }

    pub fn login_user(&self, username: &str, password: &str) -> Result<Option<String>> {

        let conn_guard = self.conn.lock().map_err(Self::map_poison_err)?;

        let mut stmt = conn_guard.prepare(
            "SELECT password_hash, role, blocked, min_password_length FROM users WHERE username = ?1"
        )?;

        let row = stmt
            .query_row(params![username], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i32>(2)?,
                    row.get::<_, Option<u32>>(3)?,
                ))
            })
            .optional()?;

        if let Some((stored_hash, role, blocked, min_length)) = row {
            if blocked != 0 || !Self::is_valid_password(password, min_length) {
                return Ok(None);
            }
            if verify_password(password, &stored_hash)? {
                return Ok(Some(role));
            }
            Ok(None)
        } else {
            Ok(None)
        }
    }

    pub fn change_pass(
        &self,
        username: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<bool> {

        let conn_guard = self.conn.lock().map_err(Self::map_poison_err)?;

        let mut stmt = conn_guard
            .prepare("SELECT password_hash, min_password_length FROM users WHERE username = ?1")?;

        let (stored_hash, min_length) = stmt.query_row(params![username], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<u32>>(1)?))
        })?;
        if !verify_password(current_password, &stored_hash)? {
            return Ok(false);
        }
        if !Self::is_valid_password(new_password, min_length) {
            return Ok(false);
        }
        let new_hash = hash_password(new_password)?;
        conn_guard.execute(
            "UPDATE users SET password_hash = ?1 WHERE username = ?2",
            params![new_hash, username],
        )?;
        Ok(true)
    }

    pub fn get_users(&self) -> Result<Vec<User>> {
        let conn_guard = self.conn.lock().map_err(Self::map_poison_err)?;

        let mut stmt = conn_guard
            .prepare("SELECT id, username, role, blocked, min_password_length FROM users")?;
        let users = stmt
            .query_map([], |row| {
                Ok(User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    role: row.get(2)?,
                    blocked: row.get::<_, i32>(3)? != 0,
                    min_password_length: row.get(4)?,
                })
            })?
            .collect::<std::result::Result<Vec<User>, rusqlite::Error>>()?;
        Ok(users)
    }

    pub fn add_new_user(&self, username: &str) -> Result<bool> {
        let conn_guard = self.conn.lock().map_err(Self::map_poison_err)?;

        let hash = hash_password("")?;
        let affected = conn_guard.execute(
            "INSERT OR IGNORE INTO users (username, password, role, blocked)\
           VALUES (?1, ?2, ?3, ?4)",
            params![username, hash, "user", 0],
        )?;
        Ok(affected == 1)
    }

    pub fn update_user_block_status(&self, username: &str, block: bool) -> Result<bool> {
        let conn_guard = self.conn.lock().map_err(Self::map_poison_err)?;

        let affected = conn_guard.execute(
            "UPDATE users SET block = ?1 WHERE username = ?2",
            params![if block { 1 } else { 0 }, username],
        )?;
        Ok(affected == 1)
    }

    pub fn update_user_restriction(&self, username: &str, min_length: Option<u32>) -> Result<bool> {
        let conn_guard = self.conn.lock().map_err(Self::map_poison_err)?;

        let affected = conn_guard.execute(
            "UPDATE users SET min_password_length = ?1 WHERE username = ?2",
            params![min_length, username],
        )?;
        Ok(affected == 1)
    }

    fn is_valid_password(password: &str, min_length: Option<u32>) -> bool {
        if let Some(min_length) = min_length {
            password.len() >= min_length as usize
        } else {
            true
        }
    }
}
