mod process_list;
mod pid_lookup;
use process_list::ProcessInfo;

#[tauri::command]
async fn get_running_apps() -> Result<Vec<ProcessInfo>, String> {
    Ok(process_list::get_processes())
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_running_apps])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
