// resolves port -> pid via iphlpapi

use std::mem;
use tracing::{debug, warn};



const AF_INET: u32 = 2;
const TCP_TABLE_OWNER_PID_ALL: u32 = 5; // MIB_TCP_TABLE_OWNER_PID_ALL
const UDP_TABLE_OWNER_PID: u32 = 1; // MIB_UDP_TABLE_OWNER_PID
const NO_ERROR: u32 = 0;




#[repr(C)]
#[allow(dead_code)]
struct MibTcpRowOwnerPid {
    state: u32,
    local_addr: u32,
    // network byte order
    local_port: u32,
    remote_addr: u32,
    remote_port: u32,
    owning_pid: u32,
}


#[repr(C)]
struct MibUdpRowOwnerPid {
    local_addr: u32,
    // network byte order
    local_port: u32,
    owning_pid: u32,
}



#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(
        table: *mut u8,
        size: *mut u32,
        order: i32,
        af: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32;

    fn GetExtendedUdpTable(
        table: *mut u8,
        size: *mut u32,
        order: i32,
        af: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32;
}





/// returns pid owning the port
pub fn get_pid_for_port(target_port: u16, is_tcp: bool) -> Option<u32> {
    let table_class = if is_tcp { TCP_TABLE_OWNER_PID_ALL } else { UDP_TABLE_OWNER_PID };
    let max_attempts = if is_tcp { 3 } else { 1 };

    // retry TCP queries up to 3 times because of transient registration delays.
    // UDP queries are connectionless and should not be retried to avoid adding latency.
    for attempt in 1..=max_attempts {
        let mut size: u32 = 0;
        unsafe {
            if is_tcp {
                GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, AF_INET, table_class, 0);
            } else {
                GetExtendedUdpTable(std::ptr::null_mut(), &mut size, 0, AF_INET, table_class, 0);
            }
        }

        if size == 0 {
            if attempt < max_attempts {
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            return None;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = unsafe {
            if is_tcp {
                GetExtendedTcpTable(buf.as_mut_ptr(), &mut size, 0, AF_INET, table_class, 0)
            } else {
                GetExtendedUdpTable(buf.as_mut_ptr(), &mut size, 0, AF_INET, table_class, 0)
            }
        };

        if ret != NO_ERROR {
            if attempt < max_attempts {
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            return None;
        }

        if buf.len() < mem::size_of::<u32>() {
            return None;
        }
        let num_entries = unsafe { *(buf.as_ptr() as *const u32) } as usize;
        let header_size = mem::size_of::<u32>();

        if is_tcp {
            let row_size = mem::size_of::<MibTcpRowOwnerPid>();
            for i in 0..num_entries {
                let offset = header_size + i * row_size;
                if offset + row_size > buf.len() {
                    break;
                }
                let row = unsafe { &*(buf.as_ptr().add(offset) as *const MibTcpRowOwnerPid) };
                let port = u16::from_be((row.local_port & 0xFFFF) as u16);
                if port == target_port {
                    debug!(target_port, pid = row.owning_pid, attempt, "get_pid_for_port resolved TCP");
                    return Some(row.owning_pid);
                }
            }
        } else {
            let row_size = mem::size_of::<MibUdpRowOwnerPid>();
            for i in 0..num_entries {
                let offset = header_size + i * row_size;
                if offset + row_size > buf.len() {
                    break;
                }
                let row = unsafe { &*(buf.as_ptr().add(offset) as *const MibUdpRowOwnerPid) };
                let port = u16::from_be((row.local_port & 0xFFFF) as u16);
                if port == target_port {
                    debug!(target_port, pid = row.owning_pid, attempt, "get_pid_for_port resolved UDP");
                    return Some(row.owning_pid);
                }
            }
        }


        if attempt < max_attempts {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    warn!(target_port, is_tcp, "get_pid_for_port failed to resolve port to PID after {} attempts", max_attempts);
    None
}


