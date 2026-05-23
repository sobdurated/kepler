// nat table mapping src_port -> original_destination

use dashmap::DashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};



/// protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// key for nat lookups
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NatKey {
    pub protocol: Protocol,
    pub src_port: u16,
}

impl NatKey {
    /// tcp nat key
    #[inline]
    pub fn tcp(port: u16) -> Self {
        Self {
            protocol: Protocol::Tcp,
            src_port: port,
        }
    }

    /// udp nat key
    #[inline]
    pub fn udp(port: u16) -> Self {
        Self {
            protocol: Protocol::Udp,
            src_port: port,
        }
    }
}

/// tracks original destination and source ip
#[derive(Debug, Clone)]
pub struct OriginalDest {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub src_ip: Ipv4Addr,
    /// original resolver if redirected
    pub dns_restore_ip: Option<Ipv4Addr>,
    pub last_seen: Instant,
}

impl OriginalDest {
    pub fn new(ip: Ipv4Addr, port: u16, src_ip: Ipv4Addr) -> Self {
        Self {
            ip,
            port,
            src_ip,
            dns_restore_ip: None,
            last_seen: Instant::now(),
        }
    }
}



/// thread-safe nat table
pub struct NatTable {
    inner: DashMap<NatKey, OriginalDest>,
}

impl NatTable {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    /// inserts or updates mapping
    pub fn insert(&self, key: NatKey, dest: OriginalDest) {
        self.inner.insert(key, dest);
    }

    /// lookup original destination
    pub fn lookup(&self, key: &NatKey) -> Option<OriginalDest> {
        self.inner.get(key).map(|entry| entry.clone())
    }

    /// remove mapping
    pub fn remove(&self, key: &NatKey) -> Option<OriginalDest> {
        self.inner.remove(key).map(|(_, v)| v)
    }

    /// touches entry to keep udp alive
    pub fn touch(&self, key: &NatKey) {
        if let Some(mut entry) = self.inner.get_mut(key) {
            entry.last_seen = Instant::now();
        }
    }

    /// reaps stale udp entries
    pub fn reap_stale(&self, max_age: Duration) {
        self.inner.retain(|key, dest| {
            if key.protocol == Protocol::Udp && dest.last_seen.elapsed() > max_age {
                tracing::debug!(
                    port = key.src_port,
                    "Reaping stale UDP NAT entry"
                );
                false
            } else {
                true
            }
        });
    }

    /// clear all entries
    pub fn clear(&self) {
        self.inner.clear();
    }

    /// number of tracked connections
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}
