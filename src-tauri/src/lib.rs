mod process_list;
mod pid_lookup;
mod divert;
mod nat;
mod socks5;
mod proxy;
mod state;

use process_list::ProcessInfo;
use state::{AppState, ProxyConfig};
use tauri::State;

#[tauri::command]
async fn get_running_apps() -> Result<Vec<ProcessInfo>, String> {
    Ok(process_list::get_processes())
}

#[tauri::command]
async fn get_proxy_config(state: State<'_, AppState>) -> Result<ProxyConfig, String> {
    Ok(state.proxy_config.lock().clone())
}

pub fn run() {
    tauri::Builder::default()
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![get_running_apps, get_proxy_config])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
