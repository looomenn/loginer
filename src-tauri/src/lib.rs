mod auth;
mod config;
mod db;
mod error;
mod globals;
mod session;
mod storage;

use tauri::{generate_handler, State, Manager, Window};
use tauri::menu::MenuBuilder;

use crate::db::UserRepo;
use crate::error::Result;
use crate::globals::{Secret, JWT_SECRET, PEPPER, SQLCIPHER};
use crate::session::{
    delete_token, generate_token, get_token, save_token, verify_token, SessionClaims,
};

use tauri_plugin_dialog::{DialogExt, MessageDialogKind};

#[tauri::command]
fn tauri_login(username: &str, password: &str, state: State<UserRepo>) -> Result<String> {
    match state.login_user(&username, &password)? {
        Some(role) => {
            // let jwt_secret = JWT_SECRET.as_ref()?.as_ref();
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
    // let jwt_secret = JWT_SECRET.as_ref()?.as_ref();
    let jwt_secret = Secret::global(&JWT_SECRET)?;

    verify_token(&token, jwt_secret)
}

#[tauri::command]
fn tauri_logout() -> Result<String> {
    delete_token()?;
    Ok("Logged out".into())
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
            tauri_add_user,
            tauri_set_block_status,
            tauri_set_restriction
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

