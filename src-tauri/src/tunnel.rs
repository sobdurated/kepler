use crate::divert::DivertHandle;
use crate::nat::{NatKey, NatTable, OriginalDest};
use crate::pid_lookup;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};



const PROXY_TCP_PORT: u16 = 1080;
const PROXY_UDP_PORT: u16 = 1081;
const MAX_PACKET: usize = 65535;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

// dns load-balancing toggle
static USE_PRIMARY_DNS: AtomicBool = AtomicBool::new(true);



pub struct TunnelEngine {
    running: Arc<AtomicBool>,
    outbound_handle: Arc<DivertHandle>,
    return_handle: Arc<DivertHandle>,
}

impl TunnelEngine {
    pub fn start(
        target_pids: Arc<Mutex<HashSet<u32>>>,
        nat_table: Arc<NatTable>,
        auto_tunnel_names: Arc<Mutex<HashSet<String>>>,
    ) -> std::io::Result<Self> {
        let running = Arc::new(AtomicBool::new(true));


        // captures outbound tcp/udp except loopback/local proxy
        let outbound_filter = format!(
            "outbound and ip.DstAddr != 127.0.0.1 and \
             ((tcp and tcp.DstPort != {}) or (udp and udp.DstPort != {}))",
            PROXY_TCP_PORT, PROXY_UDP_PORT
        );

        // captures return packets from proxy
        let return_filter = format!(
            "(tcp and tcp.SrcPort == {}) or (udp and udp.SrcPort == {})",
            PROXY_TCP_PORT, PROXY_UDP_PORT
        );

        info!(%outbound_filter, "Opening outbound WinDivert handle");
        let outbound_handle = Arc::new(DivertHandle::open(&outbound_filter, 0)?);

        info!(%return_filter, "Opening return WinDivert handle");
        let return_handle = Arc::new(DivertHandle::open(&return_filter, 1)?);


        {
            let handle = Arc::clone(&outbound_handle);
            let nat = Arc::clone(&nat_table);
            let run = Arc::clone(&running);
            let pids = Arc::clone(&target_pids);
            let auto_names = Arc::clone(&auto_tunnel_names);

            std::thread::Builder::new()
                .name("wd-outbound".into())
                .spawn(move || {
                    outbound_loop(&handle, &nat, &run, &pids, &auto_names);
                })?;
        }


        {
            let handle = Arc::clone(&return_handle);
            let nat = Arc::clone(&nat_table);
            let run = Arc::clone(&running);

            std::thread::Builder::new()
                .name("wd-return".into())
                .spawn(move || {
                    return_loop(&handle, &nat, &run);
                })?;
        }

        info!("Tunnel engine started (multi-PID mode)");

        Ok(Self {
            running,
            outbound_handle,
            return_handle,
        })
    }

    pub fn stop(self) {
        info!("Stopping tunnel engine");
        self.running.store(false, Ordering::SeqCst);

        // closes handles to unblock recv
        self.outbound_handle.close();
        self.return_handle.close();
    }
}



fn outbound_loop(
    handle: &DivertHandle,
    nat: &NatTable,
    running: &AtomicBool,
    target_pids: &Mutex<HashSet<u32>>,
    auto_tunnel_names: &Mutex<HashSet<String>>,
) {
    let mut buf = vec![0u8; MAX_PACKET];

    // caches pid lookups
    let mut tcp_port_cache: std::collections::HashMap<u16, (u32, Instant)> = std::collections::HashMap::new();
    let mut udp_port_cache: std::collections::HashMap<u16, (u32, Instant)> = std::collections::HashMap::new();

    // local pid copy to avoid lock contention
    let mut local_target_pids: HashSet<u32> = HashSet::new();
    let mut last_pid_set_refresh = Instant::now() - Duration::from_secs(10);
    let pid_set_refresh_interval = Duration::from_millis(200);

    let mut last_cleanup = Instant::now();

    while running.load(Ordering::Relaxed) {

        let (len, mut addr) = match handle.recv(&mut buf) {
            Ok(result) => result,
            Err(e) => {
                if running.load(Ordering::Relaxed) {
                    error!(%e, "WinDivert recv error (outbound)");
                }
                break;
            }
        };

        let pkt = &mut buf[..len];


        if last_pid_set_refresh.elapsed() >= pid_set_refresh_interval {
            local_target_pids = target_pids.lock().clone();
            last_pid_set_refresh = Instant::now();
        }

        // cleanup expired cache
        if last_cleanup.elapsed() >= Duration::from_secs(10) {
            let now = Instant::now();
            // tcp inactive 5m, udp 30s
            tcp_port_cache.retain(|_, (_, last_seen)| now.duration_since(*last_seen) < Duration::from_secs(300));
            udp_port_cache.retain(|_, (_, last_seen)| now.duration_since(*last_seen) < Duration::from_secs(30));
            last_cleanup = now;
        }


        if len < 20 {
            let _ = handle.send(pkt, &addr);
            continue;
        }

        let version = (pkt[0] >> 4) & 0x0F;
        if version != 4 {
            let _ = handle.send(pkt, &addr);
            continue;
        }

        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        let protocol = pkt[9];

        if len < ihl + 4 {
            let _ = handle.send(pkt, &addr);
            continue;
        }


        let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
        let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);

        // tcp connection state check
        let mut is_tcp_syn = false;
        let mut is_tcp_teardown = false;
        if protocol == PROTO_TCP && len >= ihl + 14 {
            let flags = pkt[ihl + 13];
            is_tcp_syn = (flags & 0x02) != 0;
            is_tcp_teardown = (flags & 0x05) != 0;
        }


        let now = Instant::now();
        let is_target = match protocol {
            PROTO_TCP => {
                if dst_port == 53 {
                    let mut is_self = false;
                    if let Some(pid) = pid_lookup::get_pid_for_port(src_port, true) {
                        if pid == std::process::id() {
                            debug!(src_port, "Bypassing TCP DNS query from self");
                            is_self = true;
                        }
                    }
                    !is_self
                } else {
                    let mut cache_hit = false;
                    let mut pid = 0;

                    // query os directly for new connections (syn)
                    if !is_tcp_syn {
                        if let Some(&(cached_pid, _)) = tcp_port_cache.get(&src_port) {
                            pid = cached_pid;
                            cache_hit = true;
                        }
                    }

                    if !cache_hit {
                        if let Some(os_pid) = pid_lookup::get_pid_for_port(src_port, true) {
                            pid = os_pid;
                            if pid == std::process::id() {
                                tcp_port_cache.insert(src_port, (0, now));
                                pid = 0;
                            } else {
                                tcp_port_cache.insert(src_port, (pid, now));
                                debug!(src_port, pid, is_target = local_target_pids.contains(&pid), "Resolved new TCP port");
                                
                                // check auto-tunnel rules
                                if pid != 0 && !local_target_pids.contains(&pid) {
                                    if let Some((proc_name, exe_path)) = crate::process_list::get_process_by_pid(pid) {
                                        let name_lower = proc_name.to_lowercase();
                                        let path_lower = exe_path.to_lowercase();
                                        let auto_rules = auto_tunnel_names.lock();
                                        let is_match = auto_rules.iter().any(|target| {
                                            let target_lower = target.to_lowercase();
                                            name_lower == target_lower ||
                                            name_lower == format!("{}.exe", target_lower) ||
                                            target_lower == format!("{}.exe", name_lower) ||
                                            path_lower.contains(&target_lower)
                                        });
                                        if is_match {
                                            info!(pid, name = %proc_name, "Real-time match: Auto-tunnel matched process (TCP). Adding PID to tunnel set.");
                                            target_pids.lock().insert(pid);
                                            local_target_pids.insert(pid);
                                        }
                                    }
                                }
                            }
                        } else {

                            tcp_port_cache.insert(src_port, (0, now));
                        }
                    } else if let Some(entry) = tcp_port_cache.get_mut(&src_port) {
                        entry.1 = now;
                    }

                    if is_tcp_teardown {
                        tcp_port_cache.remove(&src_port);
                    }

                    local_target_pids.contains(&pid)
                }
            }
            PROTO_UDP => {
                if dst_port == 53 {
                    let mut is_self = false;
                    if let Some(pid) = pid_lookup::get_pid_for_port(src_port, false) {
                        if pid == std::process::id() {
                            debug!(src_port, "Bypassing UDP DNS query from self");
                            is_self = true;
                        }
                    }
                    !is_self
                } else {
                    let mut cache_hit = false;
                    let mut pid = 0;

                    if let Some(&(cached_pid, _)) = udp_port_cache.get(&src_port) {
                        pid = cached_pid;
                        cache_hit = true;
                    }

                    if !cache_hit {
                        if let Some(os_pid) = pid_lookup::get_pid_for_port(src_port, false) {
                            pid = os_pid;
                            if pid == std::process::id() {
                                udp_port_cache.insert(src_port, (0, now));
                                pid = 0;
                            } else {
                                udp_port_cache.insert(src_port, (pid, now));
                                debug!(src_port, pid, is_target = local_target_pids.contains(&pid), "Resolved new UDP port");
                                
                                // check auto-tunnel rules
                                if pid != 0 && !local_target_pids.contains(&pid) {
                                    if let Some((proc_name, exe_path)) = crate::process_list::get_process_by_pid(pid) {
                                        let name_lower = proc_name.to_lowercase();
                                        let path_lower = exe_path.to_lowercase();
                                        let auto_rules = auto_tunnel_names.lock();
                                        let is_match = auto_rules.iter().any(|target| {
                                            let target_lower = target.to_lowercase();
                                            name_lower == target_lower ||
                                            name_lower == format!("{}.exe", target_lower) ||
                                            target_lower == format!("{}.exe", name_lower) ||
                                            path_lower.contains(&target_lower)
                                        });
                                        if is_match {
                                            info!(pid, name = %proc_name, "Real-time match: Auto-tunnel matched process (UDP). Adding PID to tunnel set.");
                                            target_pids.lock().insert(pid);
                                            local_target_pids.insert(pid);
                                        }
                                    }
                                }
                            }
                        } else {
                            udp_port_cache.insert(src_port, (0, now));
                        }
                    } else if let Some(entry) = udp_port_cache.get_mut(&src_port) {
                        entry.1 = now;
                    }

                    local_target_pids.contains(&pid)
                }
            }
            _ => false,
        };

        if !is_target {
            // Not from any target PID — reinject unchanged
            let _ = handle.send(pkt, &addr);
            continue;
        }


        let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);

        // skip loopback
        if dst_ip.is_loopback() {
            let _ = handle.send(pkt, &addr);
            continue;
        }


        match protocol {
            PROTO_TCP => {
                debug!(
                    src_port,
                    %dst_ip,
                    dst_port,
                    "Outbound TCP → rewriting to proxy"
                );

                // check for dns query
                let (target_ip, dns_restore) = if dst_port == 53 {
                    let dns_ip = if USE_PRIMARY_DNS.fetch_xor(true, Ordering::Relaxed) {
                        Ipv4Addr::new(1, 1, 1, 1)
                    } else {
                        Ipv4Addr::new(1, 0, 0, 1)
                    };
                    (dns_ip, Some(dst_ip))
                } else {
                    (dst_ip, None)
                };

                // save original destination
                let mut orig_dest = OriginalDest::new(target_ip, dst_port, src_ip);
                orig_dest.dns_restore_ip = dns_restore;
                nat.insert(
                    NatKey::tcp(src_port),
                    orig_dest,
                );

                // rewrite destination to local proxy
                pkt[16] = pkt[12];
                pkt[17] = pkt[13];
                pkt[18] = pkt[14];
                pkt[19] = pkt[15];

                let port_be = PROXY_TCP_PORT.to_be_bytes();
                pkt[ihl + 2] = port_be[0];
                pkt[ihl + 3] = port_be[1];
            }

            PROTO_UDP => {
                debug!(
                    src_port,
                    %dst_ip,
                    dst_port,
                    "Outbound UDP → rewriting to relay"
                );

                let (target_ip, dns_restore) = if dst_port == 53 {
                    let dns_ip = if USE_PRIMARY_DNS.fetch_xor(true, Ordering::Relaxed) {
                        Ipv4Addr::new(1, 1, 1, 1)
                    } else {
                        Ipv4Addr::new(1, 0, 0, 1)
                    };
                    (dns_ip, Some(dst_ip))
                } else {
                    (dst_ip, None)
                };

                let mut orig_dest = OriginalDest::new(target_ip, dst_port, src_ip);
                orig_dest.dns_restore_ip = dns_restore;
                nat.insert(
                    NatKey::udp(src_port),
                    orig_dest,
                );

                pkt[16] = pkt[12];
                pkt[17] = pkt[13];
                pkt[18] = pkt[14];
                pkt[19] = pkt[15];

                let port_be = PROXY_UDP_PORT.to_be_bytes();
                pkt[ihl + 2] = port_be[0];
                pkt[ihl + 3] = port_be[1];
            }

            _ => {
                // Unknown protocol (ICMP, etc.) — pass through
                let _ = handle.send(pkt, &addr);
                continue;
            }
        }


        DivertHandle::calc_checksums(pkt, &mut addr);


        if let Err(e) = handle.send(pkt, &addr) {
            warn!(%e, "WinDivert send error (outbound)");
        }
    }

    info!("Outbound interception thread exited");
}




fn return_loop(handle: &DivertHandle, nat: &NatTable, running: &AtomicBool) {
    let mut buf = vec![0u8; MAX_PACKET];

    while running.load(Ordering::Relaxed) {
        let (len, mut addr) = match handle.recv(&mut buf) {
            Ok(result) => result,
            Err(e) => {
                if running.load(Ordering::Relaxed) {
                    error!(%e, "WinDivert recv error (return)");
                }
                break;
            }
        };

        let pkt = &mut buf[..len];

        if len < 20 {
            let _ = handle.send(pkt, &addr);
            continue;
        }

        let version = (pkt[0] >> 4) & 0x0F;
        if version != 4 {
            let _ = handle.send(pkt, &addr);
            continue;
        }

        // filter non-local packets
        if pkt[12..16] != pkt[16..20] {
            let _ = handle.send(pkt, &addr);
            continue;
        }

        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        let protocol = pkt[9];

        if len < ihl + 4 {
            let _ = handle.send(pkt, &addr);
            continue;
        }

        let app_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);

        let nat_key = match protocol {
            PROTO_TCP => NatKey::tcp(app_port),
            PROTO_UDP => NatKey::udp(app_port),
            _ => {
                let _ = handle.send(pkt, &addr);
                continue;
            }
        };

        if let Some(orig) = nat.lookup(&nat_key) {
            debug!(
                app_port,
                orig_ip = %orig.ip,
                orig_port = orig.port,
                "Return → restoring source to original server"
            );

            // restore original server ip
            let restore_ip = orig.dns_restore_ip.unwrap_or(orig.ip);
            let octets = restore_ip.octets();
            pkt[12] = octets[0];
            pkt[13] = octets[1];
            pkt[14] = octets[2];
            pkt[15] = octets[3];

            let port_be = orig.port.to_be_bytes();
            pkt[ihl] = port_be[0];
            pkt[ihl + 1] = port_be[1];

            // restore original source ip
            let dest_octets = orig.src_ip.octets();
            pkt[16] = dest_octets[0];
            pkt[17] = dest_octets[1];
            pkt[18] = dest_octets[2];
            pkt[19] = dest_octets[3];

            nat.touch(&nat_key);

            if protocol == PROTO_TCP && len >= ihl + 14 {
                let flags_byte = pkt[ihl + 13];
                let fin = flags_byte & 0x01 != 0;
                let rst = flags_byte & 0x04 != 0;

                if fin || rst {
                    debug!(app_port, fin, rst, "TCP teardown, removing NAT entry");
                    nat.remove(&nat_key);
                }
            }

            DivertHandle::calc_checksums(pkt, &mut addr);

            if let Err(e) = handle.send(pkt, &addr) {
                warn!(%e, "WinDivert send error (return)");
            }
        } else {
            warn!(app_port, "No NAT entry for return packet — passing through");
            let _ = handle.send(pkt, &addr);
        }
    }

    info!("Return interception thread exited");
}
