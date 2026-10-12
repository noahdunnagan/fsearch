use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};

#[repr(C)]
struct Tp {
    count: u32,
    luid: LUID,
    attrs: u32,
}

pub fn enable(names: &[&str]) {
    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) } == 0 {
        return;
    }
    for name in names {
        let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut luid = LUID { LowPart: 0, HighPart: 0 };
        if unsafe { LookupPrivilegeValueW(std::ptr::null(), w.as_ptr(), &mut luid) } == 0 {
            continue;
        }
        let mut tp = Tp { count: 1, luid, attrs: SE_PRIVILEGE_ENABLED };
        unsafe {
            AdjustTokenPrivileges(token, 0, &mut tp as *mut _ as *mut TOKEN_PRIVILEGES, 0, std::ptr::null_mut(), std::ptr::null_mut());
        }
    }
    unsafe { CloseHandle(token) };
}

pub fn is_elevated() -> bool {
    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut n = 0u32;
    let ok = unsafe {
        GetTokenInformation(token, TokenElevation, &mut elev as *mut _ as *mut _, std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut n)
    };
    unsafe { CloseHandle(token) };
    ok != 0 && elev.TokenIsElevated != 0
}

/// Relaunch this exe with a UAC prompt. Returns true if the elevated process was started.
pub fn relaunch_elevated(args: &[String]) -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    let exe_w: Vec<u16> = exe.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
    let params = args.join(" ");
    let params_w: Vec<u16> = params.encode_utf16().chain(std::iter::once(0)).collect();
    let verb: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = exe_w.as_ptr();
    info.lpParameters = params_w.as_ptr();
    info.nShow = 0; // SW_HIDE
    unsafe { ShellExecuteExW(&mut info) != 0 }
}

pub fn try_lock_file(f: &std::fs::File) -> bool {
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LockFileEx(h: *mut core::ffi::c_void, flags: u32, reserved: u32, low: u32, high: u32, overlapped: *mut core::ffi::c_void) -> i32;
    }
    let mut ov = [0u8; 32];
    unsafe { LockFileEx(f.as_raw_handle() as _, 0x3, 0, 1, 0, ov.as_mut_ptr().cast()) != 0 }
}

