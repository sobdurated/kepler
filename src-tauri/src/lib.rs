#[cfg(target_os = "windows")]
mod divert;
mod nat;
#[cfg(target_os = "windows")]
mod pid_lookup;
#[cfg(target_os = "windows")]
mod process_list;
mod proxy;
mod socks5;
mod state;
#[cfg(target_os = "windows")]
mod tunnel;



#[cfg(target_os = "windows")]
use process_list::ProcessInfo;
use state::{AppState, ProxyConfig};
use std::sync::Arc;
use tauri::{Manager, State};
#[cfg(target_os = "windows")]
use tauri::menu::{MenuBuilder, MenuItemBuilder};
#[cfg(target_os = "windows")]
use tauri::tray::{TrayIconBuilder, TrayIconEvent, MouseButton, MouseButtonState};
#[cfg(target_os = "windows")]
use tauri::image::Image;
use tracing::{error, info};



/// returns running processes
#[cfg(target_os = "windows")]
#[tauri::command]
async fn get_running_apps() -> Result<Vec<ProcessInfo>, String> {
    Ok(process_list::get_processes())
}


/// starts proxies and engine if not running
#[cfg(target_os = "windows")]
async fn ensure_engine_started(state: &AppState) -> Result<(), String> {
    let mut engine_guard = state.tunnel_engine.lock();
    if engine_guard.is_some() {
        return Ok(());
    }

    // check if global tunnel is active
    if !*state.tunnel_started.lock() {
        return Ok(());
    }

    // clear stale nat entries
    state.nat_table.clear();

    // shutdown channel
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // start tcp proxy
    {
        let nat = Arc::clone(&state.nat_table);
        let cfg = Arc::clone(&state.proxy_config);
        let rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            proxy::start_tcp_proxy(nat, cfg, rx).await;
        });
    }

    // start udp relay
    {
        let nat = Arc::clone(&state.nat_table);
        let cfg = Arc::clone(&state.proxy_config);
        let rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            proxy::start_udp_relay(nat, cfg, rx).await;
        });
    }

    // start windivert engine
    let engine = {
        let pids = Arc::clone(&state.active_pids);
        let nat = Arc::clone(&state.nat_table);
        let auto_names = Arc::clone(&state.auto_tunnel_names);
        tunnel::TunnelEngine::start(pids, nat, auto_names).map_err(|e| {
            error!(%e, "WinDivert failed to start");
            format!(
                "Failed to start WinDivert: {}. \
                 Are you running as Administrator? \
                 Is WinDivert.dll in the application directory?",
                e
            )
        })?
    };

    *state.shutdown_tx.lock() = Some(shutdown_tx);
    *engine_guard = Some(engine);

    info!("Tunnel engine started");
    Ok(())
}

/// tunnels a pid
#[cfg(target_os = "windows")]
async fn start_tunnel_internal(pid: u32, state: &AppState) -> Result<(), String> {
    // already tunneling this pid?
    if state.active_pids.lock().contains(&pid) {
        return Ok(());
    }

    // ensure engine is running
    if let Err(e) = ensure_engine_started(state).await {
        return Err(e);
    }

    state.active_pids.lock().insert(pid);
    info!(pid, "PID added to tunnel session");
    Ok(())
}

/// tunnels a single pid
#[cfg(target_os = "windows")]
#[tauri::command]
async fn start_tunnel(pid: u32, state: State<'_, AppState>) -> Result<String, String> {
    info!(pid, "Adding PID to tunnel set");
    start_tunnel_internal(pid, &state).await?;
    let count = state.active_pids.lock().len();
    Ok(format!("Tunneling {} app(s)", count))
}

/// tunnels multiple pids
#[cfg(target_os = "windows")]
#[tauri::command]
async fn start_tunnels(pids: Vec<u32>, state: State<'_, AppState>) -> Result<String, String> {
    info!(?pids, "Adding multiple PIDs to tunnel set");
    for pid in pids {
        if let Err(e) = start_tunnel_internal(pid, &state).await {
            error!(pid, %e, "Failed to start tunnel for PID in batch");
        }
    }
    let count = state.active_pids.lock().len();
    Ok(format!("Tunneling {} app(s)", count))
}

/// stops tunneling a pid
#[cfg(target_os = "windows")]
#[tauri::command]
async fn stop_tunnel(pid: u32, state: State<'_, AppState>) -> Result<String, String> {
    info!(pid, "Removing PID from tunnel set");

    let mut pids = state.active_pids.lock();

    if !pids.remove(&pid) {
        return Err(format!("PID {} is not being tunneled", pid));
    }

    let now_empty = pids.is_empty();
    drop(pids);

    if now_empty {
        shutdown_engine(&state);
        info!("All PIDs removed — tunnel engine stopped");
    }

    let count = state.active_pids.lock().len();
    Ok(format!("Tunneling {} app(s)", count))
}

/// stops tunneling multiple pids
#[cfg(target_os = "windows")]
#[tauri::command]
async fn stop_tunnels(pids: Vec<u32>, state: State<'_, AppState>) -> Result<String, String> {
    info!(?pids, "Removing multiple PIDs from tunnel set");
    for pid in pids {
        let mut active = state.active_pids.lock();
        if active.remove(&pid) {
            let now_empty = active.is_empty();
            drop(active);
            if now_empty {
                shutdown_engine(&state);
                info!("All PIDs removed — tunnel engine stopped");
            }
        }
    }
    let count = state.active_pids.lock().len();
    Ok(format!("Tunneling {} app(s)", count))
}

/// returns auto-tunnel names
#[tauri::command]
async fn get_auto_tunnel_names(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let names = state.auto_tunnel_names.lock().iter().cloned().collect();
    Ok(names)
}

/// updates auto-tunnel names and saves config
#[tauri::command]
async fn set_auto_tunnel_names(
    names: Vec<String>,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut targets = state.auto_tunnel_names.lock();
    targets.clear();
    for name in names {
        if !name.trim().is_empty() {
            targets.insert(name.trim().to_string());
        }
    }
    info!("Updated auto-tunnel names: {:?}", *targets);
    drop(targets); // drop lock to prevent deadlock
    save_config(&app, &state);
    Ok(())
}



/// updates global tunnel state and tray icon
async fn set_global_tunnel_active_internal(active: bool, app: &tauri::AppHandle, state: &AppState) {
    let old_state = {
        let mut started = state.tunnel_started.lock();
        let old = *started;
        *started = active;

        // update tray menu item
        #[cfg(target_os = "windows")]
        {
            if let Some(item) = &*state.tray_toggle_item.lock() {
                let text = if active { "Stop Tunnel" } else { "Start Tunnel" };
                let _ = item.set_text(text);
            }
        }
        old
    };

    // update tray icon
    #[cfg(target_os = "windows")]
    {
        if let Some(tray) = app.tray_by_id("main") {
            let icon_bytes = if active {
                include_bytes!("../icons/icon-active.png") as &[u8]
            } else {
                include_bytes!("../icons/icon-inactive.png") as &[u8]
            };
            if let Ok(icon) = Image::from_bytes(icon_bytes) {
                let _ = tray.set_icon(Some(icon));
            }
        }
    }

    save_config(app, state);

    if old_state != active {
        if !active {
            #[cfg(target_os = "windows")]
            shutdown_engine(state);
            info!("Global tunnel stopped — engine shut down");
        } else {
            #[cfg(target_os = "windows")]
            {
                let should_start = !state.active_pids.lock().is_empty() || !state.auto_tunnel_names.lock().is_empty();
                if should_start {
                    info!("Global tunnel started — starting engine immediately");
                    if let Err(e) = ensure_engine_started(state).await {
                        error!(%e, "Failed to start tunnel engine immediately");
                    }
                }
            }
        }
    }
}


/// toggles global tunnel switch
#[tauri::command]
async fn set_global_tunnel_active(active: bool, app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    set_global_tunnel_active_internal(active, &app, &state).await;
    Ok(())
}

/// returns current tunnel status
#[tauri::command]
async fn get_tunnel_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let is_started = *state.tunnel_started.lock();
    
    #[cfg(target_os = "windows")]
    {
        let pids: Vec<u32> = state.active_pids.lock().iter().copied().collect();
        let is_engine_running = state.tunnel_engine.lock().is_some();
        Ok(serde_json::json!({
            "active": is_started && !pids.is_empty(),
            "active_pids": pids,
            "nat_entries": state.nat_table.len(),
            "tunnel_started": is_started,
            "engine_running": is_engine_running,
        }))
    }

    #[cfg(not(target_os = "windows"))]
    {
        Ok(serde_json::json!({
            "active": is_started,
            "active_pids": Vec::<u32>::new(),
            "nat_entries": state.nat_table.len(),
            "tunnel_started": is_started,
            "engine_running": is_started,
        }))
    }
}

/// returns socks5 proxy config
#[tauri::command]
async fn get_proxy_config(state: State<'_, AppState>) -> Result<ProxyConfig, String> {
    Ok(state.proxy_config.lock().clone())
}

/// updates socks5 proxy config
#[tauri::command]
async fn set_proxy_config(
    config: ProxyConfig,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    info!(
        enabled = config.enabled,
        host = %config.host,
        port = config.port,
        has_auth = config.username.is_some(),
        "Updating proxy config"
    );

    *state.proxy_config.lock() = config;
    save_config(&app, &state);
    Ok("Proxy configuration updated".into())
}

/// tests socks5 proxy connection
#[tauri::command]
async fn test_proxy_connection(config: ProxyConfig) -> Result<serde_json::Value, String> {
    use std::time::Instant;

    if config.host.is_empty() {
        return Ok(serde_json::json!({
            "ok": false,
            "error": "Proxy host is empty",
        }));
    }

    let proxy_addr = config.addr();
    info!(proxy = %proxy_addr, "Testing proxy connection");

    let start = Instant::now();

    // connect to 1.1.1.1:80 to test
    let target_ip = std::net::Ipv4Addr::new(1, 1, 1, 1);
    let target_port: u16 = 80;

    match socks5::socks5_connect(
        &proxy_addr,
        target_ip,
        target_port,
        config.username.as_deref(),
        config.password.as_deref(),
    )
    .await
    {
        Ok(_stream) => {
            let latency = start.elapsed().as_millis() as u64;
            info!(latency_ms = latency, "Proxy test succeeded");
            Ok(serde_json::json!({
                "ok": true,
                "latency_ms": latency,
            }))
        }
        Err(e) => {
            let msg = format!("{}", e);
            error!(error = %msg, "Proxy test failed");
            Ok(serde_json::json!({
                "ok": false,
                "error": msg,
            }))
        }
    }
}



#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedConfig {
    proxy_config: ProxyConfig,
    auto_tunnel_names: Vec<String>,
    tunnel_started: bool,
}

fn save_config(app: &tauri::AppHandle, state: &AppState) {
    let config_dir = match app.path().app_config_dir() {
        Ok(dir) => dir,
        Err(e) => {
            error!(%e, "Failed to get app config dir");
            return;
        }
    };

    if let Err(e) = std::fs::create_dir_all(&config_dir) {
        error!(%e, "Failed to create config dir");
        return;
    }

    let config_path = config_dir.join("config.json");
    
    let p_config = PersistedConfig {
        proxy_config: state.proxy_config.lock().clone(),
        auto_tunnel_names: state.auto_tunnel_names.lock().iter().cloned().collect(),
        tunnel_started: *state.tunnel_started.lock(),
    };

    match serde_json::to_string_pretty(&p_config) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&config_path, json) {
                error!(%e, "Failed to write config file");
            } else {
                info!(path = ?config_path, "Saved configuration successfully");
            }
        }
        Err(e) => {
            error!(%e, "Failed to serialize config");
        }
    }
}

#[cfg(target_os = "windows")]
fn cleanup_windivert_service() {
    use std::process::Command;
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    info!("Cleaning up WinDivert services...");
    let _ = Command::new("cmd")
        .args(&["/C", "sc stop WinDivert1.4 && sc delete WinDivert1.4"])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
    let _ = Command::new("cmd")
        .args(&["/C", "sc stop WinDivert && sc delete WinDivert"])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}

/// stops engine and proxy tasks
fn shutdown_engine(state: &AppState) {
    // signal proxy/relay shutdown
    if let Some(tx) = state.shutdown_tx.lock().take() {
        let _ = tx.send(());
    }

    // stop windivert engine
    #[cfg(target_os = "windows")]
    {
        if let Some(engine) = state.tunnel_engine.lock().take() {
            engine.stop();
        }
        cleanup_windivert_service();
    }

    // clear nat table
    state.nat_table.clear();
}



pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    "kepler_lib=debug,info"
                        .parse()
                        .expect("valid env filter")
                }),
        )
        .init();

    info!("Kepler Tunnel starting");

    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::new());

    #[cfg(target_os = "windows")]
    {
        builder = builder
            .on_window_event(|window, event| {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            })
            .invoke_handler(tauri::generate_handler![
                get_running_apps,
                start_tunnel,
                stop_tunnel,
                start_tunnels,
                stop_tunnels,
                get_tunnel_status,
                get_proxy_config,
                set_proxy_config,
                test_proxy_connection,
                get_auto_tunnel_names,
                set_auto_tunnel_names,
                set_global_tunnel_active,
            ])
            .setup(|app| {
                let state = app.state::<AppState>();

                // Clean up any dangling services from previous crash
                cleanup_windivert_service();

                // load config
                if let Ok(config_dir) = app.path().app_config_dir() {
                    let config_path = config_dir.join("config.json");
                    if config_path.exists() {
                        if let Ok(json) = std::fs::read_to_string(&config_path) {
                            if let Ok(p_config) = serde_json::from_str::<PersistedConfig>(&json) {
                                info!("Loaded configuration from disk");
                                *state.proxy_config.lock() = p_config.proxy_config;
                                *state.auto_tunnel_names.lock() = p_config.auto_tunnel_names.into_iter().collect();
                                *state.tunnel_started.lock() = p_config.tunnel_started;
                            }
                        }
                    }
                }

                let is_started = *state.tunnel_started.lock();

                // setup system tray menu
                let show_i = MenuItemBuilder::new("Show Kepler").id("show").build(app)?;
                let toggle_text = if is_started { "Stop Tunnel" } else { "Start Tunnel" };
                let toggle_i = MenuItemBuilder::new(toggle_text).id("toggle").build(app)?;
                let quit_i = MenuItemBuilder::new("Quit").id("quit").build(app)?;

                *state.tray_toggle_item.lock() = Some(toggle_i.clone());

                let menu = MenuBuilder::new(app)
                    .items(&[&show_i, &toggle_i, &quit_i])
                    .build()?;

                let icon_bytes = if is_started {
                    include_bytes!("../icons/icon-active.png") as &[u8]
                } else {
                    include_bytes!("../icons/icon-inactive.png") as &[u8]
                };
                let icon = Image::from_bytes(icon_bytes).map_err(|e| {
                    error!(error = %e, "Failed to decode icon-inactive.png for system tray");
                    format!("Failed to decode icon: {}", e)
                })?;

                let _tray = TrayIconBuilder::with_id("main")
                    .icon(icon)
                    .menu(&menu)
                    .show_menu_on_left_click(false)
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event {
                            let app = tray.app_handle();
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                    })
                    .on_menu_event(|app, event| {
                        match event.id.as_ref() {
                            "show" => {
                                if let Some(window) = app.get_webview_window("main") {
                                    let _ = window.show();
                                    let _ = window.set_focus();
                                }
                            }
                            "toggle" => {
                                let app_handle = app.clone();
                                tauri::async_runtime::spawn(async move {
                                    let state = app_handle.state::<AppState>();
                                    let active = !*state.tunnel_started.lock();
                                    set_global_tunnel_active_internal(active, &app_handle, &state).await;
                                });
                            }
                            "quit" => {
                                app.exit(0);
                            }
                            _ => {}
                        }
                    })
                    .build(app)?;

                // nat reaper task
                let nat = Arc::clone(&state.nat_table);
                tauri::async_runtime::spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                    loop {
                        interval.tick().await;
                        nat.reap_stale(std::time::Duration::from_secs(120), std::time::Duration::from_secs(1800));
                    }
                });

                // process monitor and auto-tunnel task
                let active_pids = Arc::clone(&state.active_pids);
                let auto_names = Arc::clone(&state.auto_tunnel_names);
                let shutdown_tx = Arc::clone(&state.shutdown_tx);
                let tunnel_engine = Arc::clone(&state.tunnel_engine);
                let nat_table = Arc::clone(&state.nat_table);
                let proxy_config = Arc::clone(&state.proxy_config);
                let tunnel_started = Arc::clone(&state.tunnel_started);
                let tray_toggle_item = Arc::clone(&state.tray_toggle_item);

                tauri::async_runtime::spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
                    loop {
                        interval.tick().await;

                        let running_procs = process_list::get_processes();
                        let running_pids_set: std::collections::HashSet<u32> = running_procs.iter().map(|p| p.pid).collect();

                        {
                            let mut pids = active_pids.lock();
                            let initial_len = pids.len();
                            pids.retain(|pid| running_pids_set.contains(pid));
                            if pids.len() != initial_len {
                                info!("Reaped dead PIDs. Active count: {}", pids.len());
                            }
                        }

                        let is_started = *tunnel_started.lock();
                        let should_run = is_started && (!active_pids.lock().is_empty() || !auto_names.lock().is_empty());
                        if should_run {
                            let is_running = tunnel_engine.lock().is_some();
                            if !is_running {
                                info!("Auto-tunnel rules or active PIDs present but engine not running — starting tunnel engine");
                                let state_ref = AppState {
                                    active_pids: Arc::clone(&active_pids),
                                    shutdown_tx: Arc::clone(&shutdown_tx),
                                    tunnel_engine: Arc::clone(&tunnel_engine),
                                    nat_table: Arc::clone(&nat_table),
                                    proxy_config: Arc::clone(&proxy_config),
                                    auto_tunnel_names: Arc::clone(&auto_names),
                                    tunnel_started: Arc::clone(&tunnel_started),
                                    tray_toggle_item: Arc::clone(&tray_toggle_item),
                                };
                                if let Err(e) = ensure_engine_started(&state_ref).await {
                                    error!(%e, "Failed to start tunnel engine for auto-tunnel");
                                }
                            }
                        } else {
                            let mut engine_guard = tunnel_engine.lock();
                            if engine_guard.is_some() {
                                info!("No active PIDs or auto-tunnel rules remaining — stopping tunnel engine");
                                if let Some(tx) = shutdown_tx.lock().take() {
                                    let _ = tx.send(());
                                }
                                if let Some(engine) = engine_guard.take() {
                                    engine.stop();
                                }
                                nat_table.clear();
                            }
                        }

                        let targets = auto_names.lock().clone();
                        if !targets.is_empty() {
                            for proc in &running_procs {
                                let name_lower = proc.name.to_lowercase();
                                let path_lower = proc.exe_path.to_lowercase();
                                let is_match = targets.iter().any(|target| {
                                    let target_lower = target.to_lowercase();
                                    name_lower == target_lower || 
                                    name_lower == format!("{}.exe", target_lower) ||
                                    target_lower == format!("{}.exe", name_lower) ||
                                    path_lower.contains(&target_lower)
                                });

                                if is_match {
                                    let is_already_tunneled = active_pids.lock().contains(&proc.pid);
                                    if !is_already_tunneled {
                                        info!(pid = proc.pid, name = %proc.name, "Auto-tunnel matched process. Starting tunnel.");
                                        let state_ref = AppState {
                                            active_pids: Arc::clone(&active_pids),
                                            shutdown_tx: Arc::clone(&shutdown_tx),
                                            tunnel_engine: Arc::clone(&tunnel_engine),
                                            nat_table: Arc::clone(&nat_table),
                                            proxy_config: Arc::clone(&proxy_config),
                                            auto_tunnel_names: Arc::clone(&auto_names),
                                            tunnel_started: Arc::clone(&tunnel_started),
                                            tray_toggle_item: Arc::clone(&tray_toggle_item),
                                        };
                                        if let Err(e) = start_tunnel_internal(proc.pid, &state_ref).await {
                                            error!(pid = proc.pid, %e, "Failed to auto-tunnel process");
                                        }
                                    }
                                }
                            }
                        }
                    }
                });

                Ok(())
            });
    }

    let app = builder
        .build(tauri::generate_context!())
        .expect("Fatal: Tauri application failed to build");

    app.run(|app_handle, event| {
        if let tauri::RunEvent::Exit = event {
            let state = app_handle.state::<AppState>();
            shutdown_engine(&state);
            info!("Application exiting — shut down WinDivert engine and proxy tasks");
        }
    });
}
