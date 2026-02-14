use sha2::{Digest, Sha256};

use crate::base64::base64url_encode;

pub(super) fn device_id_hash() -> Option<String> {
    let id = device_id_bytes()?;
    let mut hasher = Sha256::new();
    hasher.update(&id);
    let digest = hasher.finalize();
    Some(base64url_encode(&digest))
}

#[cfg(target_os = "windows")]
fn device_id_bytes() -> Option<Vec<u8>> {
    use std::ffi::{OsString, c_void};
    use std::os::windows::ffi::OsStringExt;
    use std::ptr;

    type HKEY = *mut c_void;

    const HKEY_LOCAL_MACHINE: HKEY = 0x80000002 as HKEY;
    const KEY_QUERY_VALUE: u32 = 0x0001;
    const KEY_WOW64_64KEY: u32 = 0x0100;
    const REG_SZ: u32 = 1;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            hKey: HKEY,
            lpSubKey: *const u16,
            ulOptions: u32,
            samDesired: u32,
            phkResult: *mut HKEY,
        ) -> i32;
        fn RegQueryValueExW(
            hKey: HKEY,
            lpValueName: *const u16,
            lpReserved: *mut u32,
            lpType: *mut u32,
            lpData: *mut u8,
            lpcbData: *mut u32,
        ) -> i32;
        fn RegCloseKey(hKey: HKEY) -> i32;
    }

    let subkey: Vec<u16> = "Software\\Microsoft\\Cryptography\0".encode_utf16().collect();
    let mut hkey: HKEY = ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut hkey,
        )
    };
    if status != 0 {
        return None;
    }

    let value: Vec<u16> = "MachineGuid\0".encode_utf16().collect();
    let mut data_type: u32 = 0;
    let mut data_len: u32 = 0;
    let status = unsafe {
        RegQueryValueExW(
            hkey,
            value.as_ptr(),
            ptr::null_mut(),
            &mut data_type,
            ptr::null_mut(),
            &mut data_len,
        )
    };
    if status != 0 || data_len == 0 {
        unsafe {
            RegCloseKey(hkey);
        }
        return None;
    }

    let mut buf: Vec<u16> = vec![0u16; (data_len as usize + 1) / 2];
    let status = unsafe {
        RegQueryValueExW(
            hkey,
            value.as_ptr(),
            ptr::null_mut(),
            &mut data_type,
            buf.as_mut_ptr() as *mut u8,
            &mut data_len,
        )
    };
    unsafe {
        RegCloseKey(hkey);
    }
    if status != 0 || data_type != REG_SZ {
        return None;
    }

    let len_u16 = (data_len as usize) / 2;
    let mut slice = &buf[..len_u16];
    if slice.last() == Some(&0) {
        slice = &slice[..slice.len() - 1];
    }
    let os = OsString::from_wide(slice);
    let s = os.to_string_lossy();
    if s.is_empty() {
        None
    } else {
        Some(s.as_bytes().to_vec())
    }
}

#[cfg(target_os = "macos")]
fn device_id_bytes() -> Option<Vec<u8>> {
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }

    unsafe extern "C" {
        fn gethostuuid(uuid: *mut u8, timeout: *const Timespec) -> i32;
    }

    let mut uuid = [0u8; 16];
    let ts = Timespec { tv_sec: 1, tv_nsec: 0 };
    let rc = unsafe { gethostuuid(uuid.as_mut_ptr(), &ts) };
    if rc != 0 {
        return None;
    }
    let s = format_uuid(&uuid);
    if s.is_empty() {
        None
    } else {
        Some(s.into_bytes())
    }
}

#[cfg(target_os = "macos")]
fn format_uuid(uuid: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0],
        uuid[1],
        uuid[2],
        uuid[3],
        uuid[4],
        uuid[5],
        uuid[6],
        uuid[7],
        uuid[8],
        uuid[9],
        uuid[10],
        uuid[11],
        uuid[12],
        uuid[13],
        uuid[14],
        uuid[15]
    )
}

#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "android")
))]
fn device_id_bytes() -> Option<Vec<u8>> {
    let mut data = std::fs::read("/etc/machine-id")
        .or_else(|_| std::fs::read("/var/lib/dbus/machine-id"))
        .ok()?;
    if data.last() == Some(&b'\n') {
        data.pop();
    }
    if data.is_empty() {
        None
    } else {
        Some(data)
    }
}

#[cfg(any(target_os = "ios", target_os = "android"))]
fn device_id_bytes() -> Option<Vec<u8>> {
    None
}
