use sha2::{Digest, Sha256};

use crate::base64::base64url_encode;

#[cfg(target_os = "windows")]
use winreg::RegKey;
#[cfg(target_os = "windows")]
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};

pub(super) fn device_id_hash() -> Option<String> {
    let id = device_id_bytes()?;
    let mut hasher = Sha256::new();
    hasher.update(&id);
    let digest = hasher.finalize();
    Some(base64url_encode(&digest))
}

#[cfg(target_os = "windows")]
fn device_id_bytes() -> Option<Vec<u8>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm
        .open_subkey_with_flags("Software\\Microsoft\\Cryptography", KEY_READ | KEY_WOW64_64KEY)
        .ok()?;
    let s: String = key.get_value("MachineGuid").ok()?;
    if s.is_empty() {
        None
    } else {
        Some(s.into_bytes())
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
