mod auth;
mod config;
mod db;
mod error;
mod globals;
mod session;
mod storage;
mod sysinfo;

use std::fmt::format;
use tauri::{generate_handler, State, Manager, Window};
use tauri::menu::MenuBuilder;
use crate::db::{User, UserRepo};
use crate::error::Result;
use crate::globals::{Secret, JWT_SECRET, PEPPER, SQLCIPHER};
use crate::session::{
    clear_session,
    delete_token,
    generate_token,
    get_token,
    save_token,
    verify_token,
    SessionClaims,
    get_session_claims
};

use crate::sysinfo::{check_rsa};

use tauri_plugin_dialog::{DialogExt, MessageDialogKind};


#[tauri::command]
fn tauri_get_own_info(state: State<UserRepo>) -> Result<User> {
    let claims = tauri_get_session()?;
    let user = state.get_user_by_username(&claims.sub)?;
    user.ok_or_else(|| error::AppError::Internal(format!("User '{}' not found", &claims.sub)))
}

#[tauri::command]
fn tauri_login(username: &str, password: &str, state: State<UserRepo>) -> Result<String> {
    match state.login_user(&username, &password)? {
        Some(role) => {

            let jwt_secret = Secret::global(&JWT_SECRET)?;
            let token = generate_token(&username, &role, jwt_secret)?;
            save_token(&token)?;

            Ok(token)
        }
        None => Err(error::AppError::Authentication(
            "Invalid username or password, or account blocked".into(),
        )),
    }
}

#[tauri::command]
fn tauri_get_session() -> Result<SessionClaims> {
    let token = get_token()?;
    let jwt_secret = Secret::global(&JWT_SECRET)?;

    verify_token(&token, jwt_secret)
}

#[tauri::command]
fn tauri_logout() -> Result<String> {
    clear_session();
    delete_token()?;
    Ok("Logged out".into())
}

fn check_admin() -> Result<SessionClaims> {
    let claims = tauri_get_session()?;
    if claims.role != "admin" {
        return Err(error::AppError::Authentication("Unauthorized".into()));
    }
    Ok(claims)
}

fn check_user(user_id: i32, state: &State<UserRepo>) -> Result<User> {
    let user = state.get_user_by_id(user_id)?
        .ok_or_else(|| error::AppError::Authentication("User not found".into()))?;
    Ok(user)
}

#[tauri::command]
fn tauri_get_users(state: State<UserRepo>) -> Result<Vec<User>> {
    check_admin()?;
    state.get_users()
}

#[tauri::command]
fn tauri_add_user(username: &str, state: State<UserRepo>) -> Result<String> {
    check_admin()?;
    match state.add_new_user(&username)? {
        true => Ok("User added successfully.".into()),
        false => Err(error::AppError::Authentication(
            "User already exists".into(),
        )),
    }
}

#[tauri::command]
fn tauri_set_block_status(user_id: i32, block: bool, state: State<UserRepo>) -> Result<String> {
    check_admin()?;
    let user = check_user(user_id, &state)?;
    state.update_user_block_status(&user.username, block)?;
    Ok("User block status updated successfully.".into())
}

#[tauri::command]
fn tauri_set_restriction(
    user_id: i32,
    min_length: Option<u32>,
    state: State<UserRepo>,
) -> Result<String> {
    check_admin()?;
    let user = check_user(user_id, &state)?;
    state.update_user_restriction(&user.username, min_length)?;
    Ok("User restriction updated successfully.".into())
}

#[tauri::command]
fn tauri_change_password(
    user_id: i32,
    current_password: &str,
    new_password: &str,
    state: State<UserRepo>,
) -> Result<String> {

    let claims = tauri_get_session()?;
    let user = check_user(user_id, &state)?;

    if claims.sub != user.username {
        return Err(error::AppError::Authentication("Unauthorized".into()));
    }

    match state.change_pass(&user.username, &current_password, &new_password)? {
        true => Ok("Password changed successfully.".into()),
        false => Err(error::AppError::Authentication(
            "Current password incorrect or new password does not meet requirements".into(),
        )),
    }
}

#[tauri::command]
fn tauri_override_password(user_id: i32, new_password: &str, state: State<UserRepo>) -> Result<String> {
    check_admin()?;
    let user = check_user(user_id, &state)?;

    state.override_password(&user.id, new_password)?;
    Ok("Password changed successfully.".into())
}

#[tauri::command]
fn tauri_delete_user(user_id: i32, state: State<UserRepo>) -> Result<String> {
    let claims = check_admin()?;
    let user = check_user(user_id, &state)?;

    if user.username == claims.sub {
        return Err(error::AppError::Authentication("Cannot delete yourself".into()));
    }

    state.delete_user(&user.username)?;
    Ok("User deleted successfully.".into())
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

            let install_dir = std::env::current_exe()
                .map_err(|e| format!("failed to locate executable: {}", e))?
                .parent()
                .ok_or("cannot determine install directory")?
                .to_path_buf();

            if let Err(e) = check_rsa(&install_dir) {
                let user_message = format!("Unable to verify system fingerprint! The application will not continue to work for security reasons.\n\nClick OK to exit the application.\n\nError description: ({})", e);
                app.handle()
                    .dialog()
                    .message(user_message)
                    .kind(MessageDialogKind::Error)
                    .title("Error")
                    .blocking_show();
                app.handle().exit(1);
            }

            log::info!("Fingerprint checked!");

            let menu = MenuBuilder::new(app)
                .text("about", "About")
                .build()?;

            app.set_menu(menu)?;

            app.on_menu_event(move |app_handle, event| {
                if event.id().0.as_str() == "about" {
                    let window = app_handle.get_webview_window("main").unwrap();

                    let pkg = app_handle.package_info();

                    let title         = &pkg.name;
                    let description     = pkg.description;
                    let authors         = pkg.authors;
                    let version     = &pkg.version;
                    let date                 = "(c) 2025";

                    let msg = format!(
                        "{title}\n{description}\n\nAuthor(s): {authors}\nBuild: {version}\nDate: {date}"
                    );

                    let _ = window
                        .dialog()
                        .message(&msg)
                        .kind(MessageDialogKind::Info)
                        .title("About")
                        .blocking_show();
                }
            });

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

                        return Err(Box::new(app_error));
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
            tauri_override_password,
            tauri_change_password,
            tauri_add_user,
            tauri_get_own_info,
            tauri_set_block_status,
            tauri_set_restriction,
            tauri_delete_user
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

