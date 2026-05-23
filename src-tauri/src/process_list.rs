// lists running processes

use serde::Serialize;
use sysinfo::System;
use std::sync::LazyLock;
use parking_lot::Mutex;
use std::collections::HashMap;

// cache icons to avoid disk reads
static ICON_CACHE: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| {
    Mutex::new(HashMap::new())
});

/// process details for frontend
#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
    pub icon: Option<String>,
}

/// returns sorted list of active processes
pub fn get_processes() -> Vec<ProcessInfo> {
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let mut processes: Vec<ProcessInfo> = sys
        .processes()
        .iter()
        .filter_map(|(pid, proc_info)| {
            let name = proc_info.name().to_string_lossy().into_owned();


            if name.is_empty() {
                return None;
            }

            let exe_path = proc_info
                .exe()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();

            // get icon from cache or extract it
            let icon = if exe_path.is_empty() {
                None
            } else {
                let mut cache = ICON_CACHE.lock();
                if let Some(cached_icon) = cache.get(&exe_path) {
                    Some(cached_icon.clone())
                } else {
                    let resolved = windows_icons::get_icon_base64_by_path(&exe_path).ok();
                    if let Some(ref icon_b64) = resolved {
                        cache.insert(exe_path.clone(), icon_b64.clone());
                    }
                    resolved
                }
            };

            Some(ProcessInfo {
                pid: pid.as_u32(),
                name,
                exe_path,
                icon,
            })
        })
        .collect();


    processes.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    processes
}

/// resolves name and path for pid
pub fn get_process_by_pid(pid: u32) -> Option<(String, String)> {
    let mut sys = System::new();
    let sys_pid = sysinfo::Pid::from(pid as usize);
    sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[sys_pid]), true);
    let proc = sys.process(sys_pid)?;
    let name = proc.name().to_string_lossy().into_owned();
    let exe_path = proc.exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    Some((name, exe_path))
}

