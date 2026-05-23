// safe wrapper for windivert api. requires admin.

use std::ffi::CString;
use std::io;
use std::sync::atomic::{AtomicIsize, Ordering};



const WINDIVERT_LAYER_NETWORK: i32 = 0;

const WINDIVERT_FLAG_NONE: u64 = 0;

const INVALID_HANDLE_VALUE: isize = -1;



/// opaque representation of windivert_address (80 bytes)
#[repr(C, align(8))]
pub struct WinDivertAddress {
    data: [u8; 80],
}

impl WinDivertAddress {
    /// zero-initialized address
    #[inline]
    pub fn zeroed() -> Self {
        Self { data: [0u8; 80] }
    }
}



#[link(name = "WinDivert")]
extern "C" {
    // open handle with filter
    fn WinDivertOpen(
        filter: *const u8,
        layer: i32,
        priority: i16,
        flags: u64,
    ) -> isize;

    // read packet (blocking)
    fn WinDivertRecv(
        handle: isize,
        packet: *mut u8,
        packet_len: u32,
        recv_len: *mut u32,
        addr: *mut WinDivertAddress,
    ) -> i32;

    // write packet back
    fn WinDivertSend(
        handle: isize,
        packet: *const u8,
        packet_len: u32,
        send_len: *mut u32,
        addr: *const WinDivertAddress,
    ) -> i32;

    // fix checksums in-place
    fn WinDivertHelperCalcChecksums(
        packet: *mut u8,
        packet_len: u32,
        addr: *mut WinDivertAddress,
        flags: u64,
    ) -> i32;

    // close handle
    fn WinDivertClose(handle: isize) -> i32;
}



/// safe wrapper for a windivert handle
pub struct DivertHandle {
    handle: AtomicIsize,
}

// safe to share, kernel serializes calls
unsafe impl Send for DivertHandle {}
unsafe impl Sync for DivertHandle {}

impl DivertHandle {
    /// opens a network layer handle
    pub fn open(filter: &str, priority: i16) -> io::Result<Self> {
        let filter_c = CString::new(filter).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "filter string contains null byte")
        })?;

        let raw = unsafe {
            WinDivertOpen(
                filter_c.as_ptr() as *const u8,
                WINDIVERT_LAYER_NETWORK,
                priority,
                WINDIVERT_FLAG_NONE,
            )
        };

        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            handle: AtomicIsize::new(raw),
        })
    }

    /// reads a packet
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, WinDivertAddress)> {
        let raw = self.handle.load(Ordering::SeqCst);
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WinDivert handle already closed",
            ));
        }

        let mut recv_len: u32 = 0;
        let mut addr = WinDivertAddress::zeroed();

        let ok = unsafe {
            WinDivertRecv(
                raw,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut recv_len,
                &mut addr,
            )
        };

        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok((recv_len as usize, addr))
    }

    /// writes packet back
    pub fn send(&self, buf: &[u8], addr: &WinDivertAddress) -> io::Result<usize> {
        let raw = self.handle.load(Ordering::SeqCst);
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WinDivert handle already closed",
            ));
        }

        let mut send_len: u32 = 0;

        let ok = unsafe {
            WinDivertSend(raw, buf.as_ptr(), buf.len() as u32, &mut send_len, addr)
        };

        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(send_len as usize)
    }

    /// updates checksums
    pub fn calc_checksums(buf: &mut [u8], addr: &mut WinDivertAddress) {
        unsafe {
            WinDivertHelperCalcChecksums(
                buf.as_mut_ptr(),
                buf.len() as u32,
                addr,
                0, // 0 = recalculate all
            );
        }
    }

    /// closes handle to unblock read
    pub fn close(&self) {
        let raw = self.handle.swap(INVALID_HANDLE_VALUE, Ordering::SeqCst);
        if raw != INVALID_HANDLE_VALUE {
            unsafe {
                WinDivertClose(raw);
            }
        }
    }
}

impl Drop for DivertHandle {
    fn drop(&mut self) {
        self.close();
    }
}
