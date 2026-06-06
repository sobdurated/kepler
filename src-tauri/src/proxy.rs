// local tcp/udp proxies

use crate::nat::{NatKey, NatTable};
use crate::socks5;
use crate::state::ProxyConfig;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};



/// tcp proxy listener
pub async fn start_tcp_proxy(
    nat_table: Arc<NatTable>,
    proxy_config: Arc<Mutex<ProxyConfig>>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let listener = match TcpListener::bind("0.0.0.0:1080").await {
        Ok(l) => {
            info!("TCP proxy listening on 0.0.0.0:1080");
            l
        }
        Err(e) => {
            error!(%e, "Failed to bind TCP proxy on 0.0.0.0:1080");
            return;
        }
    };

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("TCP proxy shutting down");
                break;
            }
            result = listener.accept() => {
                match result {
                    Ok((stream, peer_addr)) => {
                        let nat = Arc::clone(&nat_table);
                        let cfg = Arc::clone(&proxy_config);
                        tokio::spawn(async move {
                            handle_tcp_connection(stream, peer_addr, nat, cfg).await;
                        });
                    }
                    Err(e) => {
                        error!(%e, "TCP accept error");
                    }
                }
            }
        }
    }
}

struct NatGuard {
    nat: Arc<NatTable>,
    key: NatKey,
    removed: bool,
}

impl Drop for NatGuard {
    fn drop(&mut self) {
        if !self.removed {
            self.nat.remove(&self.key);
        }
    }
}

#[cfg(target_os = "windows")]
fn set_keepalive(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    use socket2::{SockRef, TcpKeepalive};
    let sock_ref = SockRef::from(stream);
    let ka = TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(10));
    sock_ref.set_tcp_keepalive(&ka)?;
    Ok(())
}

/// handles tcp connection
async fn handle_tcp_connection(
    mut inbound: TcpStream,
    peer_addr: SocketAddr,
    nat: Arc<NatTable>,
    proxy_config: Arc<Mutex<ProxyConfig>>,
) {
    // get original destination from nat
    let key = NatKey::tcp(peer_addr.port());
    let orig = match nat.lookup(&key) {
        Some(dest) => dest,
        None => {
            warn!(peer_port = peer_addr.port(), "No NAT entry for TCP — dropping");
            return;
        }
    };

    let mut nat_guard = NatGuard {
        nat: Arc::clone(&nat),
        key,
        removed: false,
    };

    #[cfg(target_os = "windows")]
    if let Err(e) = set_keepalive(&inbound) {
        debug!(%e, "Failed to set keepalive on inbound TCP socket");
    }

    info!(
        peer = %peer_addr,
        dest = %format!("{}:{}", orig.ip, orig.port),
        "TCP proxy: connecting to destination"
    );

    // connect directly or via socks5
    let config = proxy_config.lock().clone();

    let mut outbound = if config.enabled && !config.host.is_empty() {

        match socks5::socks5_connect(
            &config.addr(),
            orig.ip,
            orig.port,
            config.username.as_deref(),
            config.password.as_deref(),
        )
        .await
        {
            Ok(stream) => stream,
            Err(e) => {
                error!(
                    dest = %format!("{}:{}", orig.ip, orig.port),
                    proxy = config.addr(),
                    %e,
                    "SOCKS5 CONNECT failed"
                );
                return;
            }
        }
    } else {

        match TcpStream::connect((orig.ip, orig.port)).await {
            Ok(s) => s,
            Err(e) => {
                error!(
                    dest = %format!("{}:{}", orig.ip, orig.port),
                    %e,
                    "Failed to connect to destination"
                );
                return;
            }
        }
    };

    #[cfg(target_os = "windows")]
    if let Err(e) = set_keepalive(&outbound) {
        debug!(%e, "Failed to set keepalive on outbound TCP socket");
    }

    // copy data both ways
    let (mut in_read, mut in_write) = inbound.split();
    let (mut out_read, mut out_write) = outbound.split();

    let client_to_server = tokio::io::copy(&mut in_read, &mut out_write);
    let server_to_client = tokio::io::copy(&mut out_read, &mut in_write);

    tokio::select! {
        result = client_to_server => {
            if let Err(e) = result {
                debug!(%e, "TCP client→server copy ended");
            }
            let _ = out_write.shutdown().await;
        }
        result = server_to_client => {
            if let Err(e) = result {
                debug!(%e, "TCP server→client copy ended");
            }
            let _ = in_write.shutdown().await;
        }
    }

    // clean up nat entry
    nat_guard.removed = true;
    nat.remove(&key);
    debug!(peer_port = peer_addr.port(), "TCP connection closed, NAT entry removed");
}



enum UdpSessionBackend {
    Direct {
        socket: Arc<UdpSocket>,
    },
    Socks5 {
        socket: Arc<UdpSocket>,
        relay_addr: SocketAddrV4,
        _control_stream: TcpStream,
    },
}

struct UdpSession {
    backend: UdpSessionBackend,
    last_activity: parking_lot::Mutex<std::time::Instant>,
    cancel_tx: parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

struct UdpSessionManager {
    sessions: Arc<RwLock<HashMap<u16, Arc<UdpSession>>>>,
}

impl UdpSessionManager {
    fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}



/// udp relay
pub async fn start_udp_relay(
    nat_table: Arc<NatTable>,
    proxy_config: Arc<Mutex<ProxyConfig>>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let socket = match UdpSocket::bind("0.0.0.0:1081").await {
        Ok(s) => {
            info!("UDP relay listening on 0.0.0.0:1081");
            Arc::new(s)
        }
        Err(e) => {
            error!(%e, "Failed to bind UDP relay on 0.0.0.0:1081");
            return;
        }
    };

    let manager = Arc::new(UdpSessionManager::new());

    // reap idle sessions periodically
    let manager_clone = Arc::clone(&manager);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let now = std::time::Instant::now();
            let mut to_remove = Vec::new();
            {
                let sessions = manager_clone.sessions.read();
                for (&port, session) in sessions.iter() {
                    if now.duration_since(*session.last_activity.lock()) > Duration::from_secs(30) {
                        to_remove.push(port);
                    }
                }
            }
            if !to_remove.is_empty() {
                let mut sessions = manager_clone.sessions.write();
                for port in to_remove {
                    if let Some(session) = sessions.remove(&port) {
                        debug!(port, "Reaping stale UDP session");
                        if let Some(tx) = session.cancel_tx.lock().take() {
                            let _ = tx.send(());
                        }
                    }
                }
            }
        }
    });

    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("UDP relay shutting down");

                {
                    let mut sessions = manager.sessions.write();
                    for (port, session) in sessions.drain() {
                        debug!(port, "Canceling UDP session on shutdown");
                        if let Some(tx) = session.cancel_tx.lock().take() {
                            let _ = tx.send(());
                        }
                    }
                }
                
                break;
            }
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, peer_addr)) => {
                        let key = NatKey::udp(peer_addr.port());

                        let orig = match nat_table.lookup(&key) {
                            Some(dest) => dest,
                            None => {
                                warn!(peer_port = peer_addr.port(), "No NAT entry for UDP — dropping");
                                continue;
                            }
                        };

                        debug!(
                            peer = %peer_addr,
                            dest = %format!("{}:{}", orig.ip, orig.port),
                            bytes = len,
                            "UDP relay: forwarding datagram"
                        );

                        let data = buf[..len].to_vec();
                        let relay_socket = Arc::clone(&socket);
                        let cfg = Arc::clone(&proxy_config);
                        let mgr = Arc::clone(&manager);

                        tokio::spawn(async move {
                            handle_udp_packet(data, peer_addr, orig.ip, orig.port, relay_socket, cfg, mgr).await;
                        });
                    }
                    Err(e) => {
                        error!(%e, "UDP recv error");
                    }
                }
            }
        }
    }
}

/// routes udp packet
async fn handle_udp_packet(
    data: Vec<u8>,
    peer_addr: SocketAddr,
    dest_ip: std::net::Ipv4Addr,
    dest_port: u16,
    relay_socket: Arc<UdpSocket>,
    proxy_config: Arc<Mutex<ProxyConfig>>,
    manager: Arc<UdpSessionManager>,
) {
    let peer_port = peer_addr.port();

    // direct dns query to avoid loops/leaks
    if dest_port == 53 {
        debug!("Routing DNS query directly to {}", dest_ip);
        let temp_socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                error!(%e, "Failed to bind temporary UDP socket for direct DNS");
                return;
            }
        };

        if let Err(e) = temp_socket.send_to(&data, (dest_ip, 53)).await {
            warn!(%e, %dest_ip, "Failed to send direct DNS query via temp socket");
            return;
        }

        let mut response_buf = vec![0u8; 65535];
        let recv_result = tokio::time::timeout(
            Duration::from_secs(2),
            temp_socket.recv_from(&mut response_buf)
        ).await;

        match recv_result {
            Ok(Ok((len, _from))) => {
                if let Err(e) = relay_socket.send_to(&response_buf[..len], peer_addr).await {
                    warn!(%e, %peer_addr, "Failed to send direct DNS response back to client");
                }
            }
            Ok(Err(e)) => {
                debug!(%e, "Error receiving direct DNS response");
            }
            Err(_) => {
                debug!("Timeout waiting for direct DNS response");
            }
        }
        return;
    }

    // check if session exists
    let existing_session = {
        let sessions = manager.sessions.read();
        sessions.get(&peer_port).cloned()
    };
    
    if let Some(session) = existing_session {
        // update activity and forward data
        *session.last_activity.lock() = std::time::Instant::now();
        match &session.backend {
            UdpSessionBackend::Direct { socket } => {
                if let Err(e) = socket.send_to(&data, (dest_ip, dest_port)).await {
                    warn!(%e, "Failed to send direct UDP datagram");
                }
            }
            UdpSessionBackend::Socks5 { socket, relay_addr, .. } => {
                let encapsulated = socks5::encapsulate_udp(dest_ip, dest_port, &data);
                if let Err(e) = socket.send_to(&encapsulated, *relay_addr).await {
                    warn!(%e, "Failed to send SOCKS5 UDP datagram");
                }
            }
        }
        return;
    }
    
    // create new session
    debug!(peer_port, "Creating new UDP session");
    let config = proxy_config.lock().clone();
    let now = std::time::Instant::now();
    let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
    
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!(%e, "Failed to bind outbound UDP socket for session");
            return;
        }
    };
    
    // bypass socks5 for dns cuz udp limits
    let backend = if config.enabled && !config.host.is_empty() && dest_port != 53 {
        match socks5::socks5_udp_associate(
            &config.addr(),
            config.username.as_deref(),
            config.password.as_deref(),
        )
        .await
        {
            Ok(assoc) => {
                UdpSessionBackend::Socks5 {
                    socket: Arc::clone(&socket),
                    relay_addr: assoc.relay_addr,
                    _control_stream: assoc.control_stream,
                }
            }
            Err(e) => {
                warn!(%e, "SOCKS5 UDP ASSOCIATE failed for new session");
                return;
            }
        }
    } else {
        UdpSessionBackend::Direct {
            socket: Arc::clone(&socket),
        }
    };
    
    let session = Arc::new(UdpSession {
        backend,
        last_activity: parking_lot::Mutex::new(now),
        cancel_tx: parking_lot::Mutex::new(Some(cancel_tx)),
    });
    
    // spawn task to read responses
    let socket_clone = Arc::clone(&socket);
    let relay_socket_clone = Arc::clone(&relay_socket);
    let is_socks5 = match &session.backend {
        UdpSessionBackend::Socks5 { .. } => true,
        _ => false,
    };
    
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                _ = &mut cancel_rx => {
                    debug!(peer_port, "UDP session listener canceled");
                    break;
                }
                res = socket_clone.recv_from(&mut buf) => {
                    match res {
                        Ok((len, _from)) => {
                            if is_socks5 {
                                if let Some((_src_ip, _src_port, payload)) = socks5::decapsulate_udp(&buf[..len]) {
                                    if let Err(e) = relay_socket_clone.send_to(payload, peer_addr).await {
                                        warn!(%e, peer_port, "Failed to send decapsulated UDP response to client");
                                    }
                                }
                            } else {
                                if let Err(e) = relay_socket_clone.send_to(&buf[..len], peer_addr).await {
                                    warn!(%e, peer_port, "Failed to send direct UDP response to client");
                                }
                            }
                        }
                        Err(e) => {
                            debug!(%e, peer_port, "UDP session socket read error (expected on close)");
                            break;
                        }
                    }
                }
            }
        }
    });
    

    match &session.backend {
        UdpSessionBackend::Direct { socket } => {
            if let Err(e) = socket.send_to(&data, (dest_ip, dest_port)).await {
                warn!(%e, "Failed to send first direct UDP datagram");
            }
        }
        UdpSessionBackend::Socks5 { socket, relay_addr, .. } => {
            let encapsulated = socks5::encapsulate_udp(dest_ip, dest_port, &data);
            if let Err(e) = socket.send_to(&encapsulated, *relay_addr).await {
                warn!(%e, "Failed to send first SOCKS5 UDP datagram");
            }
        }
    }
    

    manager.sessions.write().insert(peer_port, session);
}
