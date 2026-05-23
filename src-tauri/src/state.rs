use crate::nat::NatTable;
use crate::tunnel::TunnelEngine;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: String::new(),
            port: 1080,
            username: None,
            password: None,
        }
    }
}

impl ProxyConfig {
    // proxy address string
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

pub struct AppState {
    pub active_pids: Arc<Mutex<HashSet<u32>>>,
    pub shutdown_tx: Arc<Mutex<Option<broadcast::Sender<()>>>>,
    pub tunnel_engine: Arc<Mutex<Option<TunnelEngine>>>,
    pub nat_table: Arc<NatTable>,
    pub proxy_config: Arc<Mutex<ProxyConfig>>,
    pub auto_tunnel_names: Arc<Mutex<HashSet<String>>>,
    pub tunnel_started: Arc<Mutex<bool>>,
    pub tray_toggle_item: Arc<Mutex<Option<tauri::menu::MenuItem<tauri::Wry>>>>,
}

impl AppState {

    pub fn new() -> Self {
        Self {
            active_pids: Arc::new(Mutex::new(HashSet::new())),
            shutdown_tx: Arc::new(Mutex::new(None)),
            tunnel_engine: Arc::new(Mutex::new(None)),
            nat_table: Arc::new(NatTable::new()),
            proxy_config: Arc::new(Mutex::new(ProxyConfig::default())),
            auto_tunnel_names: Arc::new(Mutex::new(HashSet::new())),
            tunnel_started: Arc::new(Mutex::new(false)),
            tray_toggle_item: Arc::new(Mutex::new(None)),
        }
    }
}
