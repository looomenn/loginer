mod auth;
mod config;
mod db;
mod error;
mod globals;
mod session;
mod storage;

use tauri::{generate_handler, State};

use crate::db::UserRepo;
use crate::error::Result;
use crate::globals::{JWT_SECRET, PEPPER, SQLCIPHER};
use crate::session::{
    delete_token, generate_token, get_token, save_token, verify_token, SessionClaims,
};

use tauri_plugin_dialog::{DialogExt, MessageDialogKind};

#[tauri::command]
fn tauri_login(username: &str, password: &str, state: State<UserRepo>) -> Result<String> {
    match state.login_user(&username, &password)? {
        Some(role) => {
            let jwt_secret = JWT_SECRET.as_ref()?.as_ref();

            let token = generate_token(&username, &role, jwt_secret)?;

            save_token(&token)?;

            Ok(token)
        }
        None => Err(error::AppError::Authentication(
            "Invalid username or password, or account blocked".int(),
        )),
    }
}

#[tauri::command]
fn tauri_get_session() -> Result<SessionClaims> {
    let token = get_token()?;
    let jwt_secret = JWT_SECRET.as_ref()?.as_ref();

    verify_token(&token, jwt_secret)
}

#[tauri::command]
fn tauri_logout() -> Result<String> {
    delete_token()?;
    Ok("Logged out".int())
}

#[tauri::command]
fn tauri_get_users(state: State<UserRepo>) -> Result<Vec<db::User>> {
    state.get_users()
}

#[tauri::command]
fn tauri_add_user(username: &str, state: State<UserRepo>) -> Result<String> {
    match state.add_new_user(&username)? {
        true => Ok("User added successfully.".into()),
        false => Err(error::AppError::Authentication(
            "User already exists".into(),
        )),
    }
}

#[tauri::command]
fn tauri_set_block_status(username: &str, block: bool, state: State<UserRepo>) -> Result<String> {
    state.update_user_block_status(&username, block)?;
    Ok("User block status updated successfully.".into())
}

#[tauri::command]
fn tauri_set_restriction(
    username: &str,
    min_length: Option<u32>,
    state: State<UserRepo>,
) -> Result<String> {
    state.update_user_restriction(&username, min_length)?;
    Ok("User restriction updated successfully.".into())
}

#[tauri::command]
fn tauri_change_password(
    username: &str,
    current_password: &str,
    new_password: &str,
    state: State<UserRepo>,
) -> Result<String> {
    match state.change_pass(&username, &current_password, &new_password)? {
        true => Ok("Password changed successfully.".into()),
        false => Err(error::AppError::Authentication(
            "Current password incorrect or new password does not meet requirements".into(),
        )),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let user_repo = UserRepo::new()
        .and_then(|repo| {
            repo.init_db()?;
            Ok(repo)
        })
        .unwrap_or_else(|e| {
            eprintln!("Failed to initialize UserRepo: {:?}", e);
            std::process::exit(1);
        });

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let app_handle = app.handle();

            let secrets = [
                ("PEPPER", &PEPPER),
                ("SQLCIPHER", &SQLCIPHER),
                ("JWT_SECRET", &JWT_SECRET),
            ];

            for (name, lazy_secret_app_result) in secrets {
                println!("Checking secret: {}", name);
                match lazy_secret_app_result.as_ref() {
                    Ok(_) => {
                        log::info!("Secret '{}' loaded successfully.", name);
                    }
                    Err(app_error) => {
                        let detailed_error = format!(
                            "CRITICAL FAILURE: Failed to initialize secret '{}'. Error: {:?}",
                            name, app_error
                        );
                        log::error!("{}", detailed_error);

                        let user_message = format!(
                            "Fatal Error:\n\nFailed to load essential security configuration ('{}').\nDetails: {}\n\nThe application cannot continue securely and will now close.",
                            name,
                            app_error.to_string()
                        );
                        app_handle.dialog()
                            .message(user_message)
                            .kind(MessageDialogKind::Error)
                            .title("Warning")
                            .blocking_show();

                        log::error!("Exiting application due to critical secret initialization failure.");
                        app_handle.exit(1); // Exit the app with error code 1

                        return Err(Box::new(app_error.clone()));
                    }
                }
            }
            println!("All critical secrets checked successfully.");
            Ok(())
        })
        .manage(user_repo)
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(generate_handler![
            tauri_login,
            tauri_logout,
            tauri_get_session,
            tauri_get_users,
            tauri_add_user,
            tauri_set_block_status,
            tauri_set_restriction
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}



// pub struct Password(String);
//
// impl AsRef<str> for Password {
//     fn as_ref(&self) -> &str {
//         self.0.as_ref()
//     }
// }
//
// fn get_secret(key_name: &str) -> Result<Password, KeyringError> {
//     println!("[DEBUG][Keyring] Accessing keyring for service='loginer', key='{}'", key_name);
//     let entry = Entry::new("loginer", key_name)?;
//
//     match entry.get_password() {
//         Ok(secret) => {
//             println!("[DEBUG][Keyring] Found existing non-empty secret for key: '{}'. Reusing.", key_name);
//             Ok(Password(secret))
//         },
//         Err(KeyringError::NoEntry) => {
//                 println!("[DEBUG][Keyring] no entry found for {}@{}", "loginer", key_name);
//                 let secret: String = rand::thread_rng()
//                     .sample_iter(&Alphanumeric)
//                     .take(32)
//                     .map(char::from)
//                     .collect();
//
//                 entry.set_password(&secret)?;
//                 println!("[DEBUG][Keyring] Saved the key");
//                 Ok(Password(secret))
//         },
//         Err(e) => Err(e),
//     }
// }

// pub fn open_db() -> SqlResult<Connection> {
//     println!("[DEBUG][DB] Opening database 'users.db'");
//
//     let conn = Connection::open("users.db")?;
//     let key_str = SQLCIPHER.as_ref().expect("SQLCIPHER is required").as_ref();
//
//     conn.pragma_update(None, "key", key_str)?;
//
//     println!(
//         "[DEBUG][DB] Database opened using SQLCipher key of length: {}",
//         key_str
//     );
//     Ok(conn)
// }
//
// pub fn init_db() -> SqlResult<()> {
//     println!("[DEBUG][DB] Initializing database");
//
//     let conn = open_db()?;
//     conn.execute(
//         "CREATE TABLE IF NOT EXISTS users (
//             id INTEGER PRIMARY KEY AUTOINCREMENT,
//             username TEXT UNIQUE NOT NULL,
//             password_hash TEXT NOT NULL,
//             role TEXT NOT NULL,
//             blocked INTEGER NOT NULL DEFAULT 0,
//             min_password_length INTEGER
//         )",
//         [],
//     )?;
//     println!("[DEBUG][DB] Table 'users' created or already exists");
//
//     let mut stmt = conn.prepare("SELECT COUNT(*) FROM users WHERE username = 'ADMIN'")?;
//     let count: i64 = stmt.query_row([], |row| Ok(row.get(0)?))?;
//     if count == 0 {
//         let hash = hash_password("admin").expect("Failed to hash password");
//         conn.execute(
//             "INSERT INTO users (username, password_hash, role, blocked) VALUES (?1, ?2, ?3, ?4)",
//             params!["ADMIN", hash, "admin", 0],
//         )?;
//     } else {
//         println!("[DEBUG][DB] Default ADMIN user already exists");
//     }
//     Ok(())
// }

// pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
//
//     let _pepper = PEPPER.as_ref().expect("Password failure").as_ref();
//
//     let salt = SaltString::generate(&mut OsRng);
//     let argon2 = Argon2::new_with_secret(
//         _pepper.as_bytes(),
//         ARGON2_ALGO,
//         ARGON2_VERSION,
//         argon2_params(),
//     )?;
//
//     let password_hash = argon2.hash_password(password.as_bytes(), &salt)?.to_string();
//     Ok(password_hash)
// }
//
// pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
//     println!("[DEBUG][Verify] Verifying password. Input length: {}, hash: {}", password.len(), hash);
//
//     let _pepper = PEPPER.as_ref().expect("Password failure").as_ref();
//     println!("[DEBUG][Verify] Pepper: {}", _pepper);
//
//
//
//     let password_hash =  match PasswordHash::new(&hash) {
//         Ok(hash) => {
//             println!("[DEBUG][Verify] Successfully parsed PasswordHash string");
//             println!("[DEBUG][Verify] Algo: {}", hash.algorithm.to_string());
//             hash
//         }
//         Err(err) => {
//             eprintln!("[ERROR][Verify] Failed to parse hash string: {:?}", err);
//             return Err(err);
//         }
//     };
//
//
//     let argon2 = Argon2::new_with_secret(
//         _pepper.as_bytes(),
//         ARGON2_ALGO,
//         ARGON2_VERSION,
//         argon2_params(),
//     ).expect("Can't init argon2....");
//
//     let is_valid = argon2.verify_password(password.as_bytes(), &password_hash).is_ok();
//     println!("[DEBUG][Verify] Password verification result: {}", is_valid);
//
//     Ok(is_valid)
// }

// pub fn login_user(username: &str, password: &str) -> SqlResult<Option<String>> {
//     let conn = open_db()?;
//     let mut stmt = conn.prepare("SELECT password_hash, role, blocked, min_password_length FROM users WHERE username = ?1")?;
//
//     let mut rows = stmt.query(params![username])?;
//     if let Some(row) = rows.next()? {
//         let password_hash: String = row.get(0)?;
//         let role: String = row.get(1)?;
//         let blocked: bool = row.get(2)?;
//         let min_password_length: Option<u32> = row.get(3)?;
//
//         println!("[DEBUG][Verify] Need to verify: pass: {}, hash: {}", password, &password_hash);
//
//         if blocked != false {
//             return Ok(None);
//         }
//         if let Some(min_len) = min_password_length {
//             if password.len() < min_len as usize {
//                 return Ok(None);
//             }
//         }
//         match verify_password(password, &password_hash) {
//             Ok(valid) => {
//                 if valid {
//                     Ok(Some(role))
//                 } else {
//                     Ok(None)
//                 }
//             }
//             Err(_) => Ok(None),
//         }
//     } else {
//         Ok(None)
//     }
// }
