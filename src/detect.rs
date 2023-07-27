use crate::error::{Error, ErrorKind};
use crate::WindowsVersion;
use core::ffi::c_void;
use core::ptr::null_mut;
use std::alloc::{self, Layout};
use std::mem;
use windows::core::{Error as WinError, BSTR, PCWSTR};
use windows::Win32::Foundation::{MAX_PATH, RPC_E_TOO_LATE};
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoInitializeSecurity, CoSetProxyBlanket,
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
    RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, VARIANT, VT_BSTR,
};
use windows::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOW};
use windows::Win32::System::Wmi::{
    IWbemLocator, WbemLocator, WBEM_FLAG_CONNECT_USE_MAX_WAIT, WBEM_FLAG_FORWARD_ONLY,
    WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE,
};
use windows::{s, w};

struct Buffer {
    ptr: *mut u8,
    layout: Layout,
}

impl Buffer {
    fn allocate(size: usize) -> Result<Self, Error> {
        let layout = Layout::array::<u8>(size)?;
        let ptr = unsafe { alloc::alloc(layout) };
        Ok(Self { ptr, layout })
    }

    fn deallocate(&self) {
        unsafe { alloc::dealloc(self.ptr, self.layout) };
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        self.deallocate();
    }
}

impl WindowsVersion {
    // https://github.com/python/cpython/blob/a1a3193990cd6658c1fe859b88a2bc03971a16df/Python/sysmodule.c#L1533
    pub fn from_kernel32_dll() -> Result<Self, Error> {
        let handle = unsafe { GetModuleHandleW(w!("kernel32.dll"))? };

        let mut path = [0u16; MAX_PATH as usize];

        let size = unsafe { GetModuleFileNameW(handle, &mut path) };
        if size == 0 {
            return Err(WinError::from_win32().into());
        }

        let path = PCWSTR::from_raw(&path as *const _);

        let size = unsafe { GetFileVersionInfoSizeW(path, None) };
        if size == 0 {
            return Err(WinError::from_win32().into());
        }

        let buf = Buffer::allocate(size as usize)?;

        let success = unsafe { GetFileVersionInfoW(path, 0, size, buf.ptr as *mut c_void) };
        if !success.as_bool() {
            return Err(WinError::from_win32().into());
        }

        let mut info = null_mut() as *mut c_void;
        let mut info_len = 0u32;

        let success = unsafe {
            VerQueryValueW(
                buf.ptr as *const c_void,
                w!(""),
                &mut info as *mut *mut c_void,
                &mut info_len as *mut u32,
            )
        };
        if !success.as_bool() {
            return Err(WinError::from_win32().into());
        }

        if info_len == 0 || info.is_null() {
            return Err(ErrorKind::Kernel32VerNotFound.into());
        }

        let info = unsafe { &*(info as *const VS_FIXEDFILEINFO) };

        Ok(Self {
            major: info.dwProductVersionMS >> 16,
            minor: info.dwProductVersionMS & 0xffff,
            build: info.dwProductVersionLS >> 16,
        })
    }

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetversion
    pub fn from_ntdll_dll() -> Result<Self, Error> {
        let handle = unsafe { GetModuleHandleW(w!("ntdll.dll"))? };

        let Some(proc) = (unsafe { GetProcAddress(handle, s!("RtlGetVersion")) }) else {
            return Err(ErrorKind::NoRtlGetVersion.into());
        };

        type RtlGetVersionFunc = unsafe extern "system" fn(*mut OSVERSIONINFOW) -> i32;
        let proc: RtlGetVersionFunc = unsafe { mem::transmute(proc) };

        let mut info: OSVERSIONINFOW = unsafe { mem::zeroed() };
        info.dwOSVersionInfoSize = mem::size_of::<OSVERSIONINFOW>() as u32;

        let status = unsafe { proc(&mut info as *mut _) };
        if status != 0 {
            return Err(ErrorKind::RtlGetVersionFailure(status).into());
        }

        Ok(Self {
            major: info.dwMajorVersion,
            minor: info.dwMinorVersion,
            build: info.dwBuildNumber,
        })
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexw
    pub fn from_get_version_ex() -> Result<Self, Error> {
        let mut info: OSVERSIONINFOW = unsafe { mem::zeroed() };
        info.dwOSVersionInfoSize = mem::size_of::<OSVERSIONINFOW>() as u32;

        let success = unsafe { GetVersionExW(&mut info as *mut _) };
        if !success.as_bool() {
            return Err(WinError::from_win32().into());
        }

        Ok(Self {
            major: info.dwMajorVersion,
            minor: info.dwMinorVersion,
            build: info.dwBuildNumber,
        })
    }

    // https://learn.microsoft.com/en-us/windows/win32/wmisdk/wql-sql-for-wmi
    pub fn from_wmi_os_provider() -> Result<Self, Error> {
        // XXX: Do not call CoUninitialize() at the end
        unsafe {
            CoInitializeEx(None, COINIT_APARTMENTTHREADED)?;
        }

        if let Err(err) = unsafe {
            CoInitializeSecurity(
                None,
                -1,
                None,
                None,
                RPC_C_AUTHN_LEVEL_DEFAULT,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
                None,
            )
        } {
            // RPC_E_TOO_LATE happens when someone else already configured security
            if err.code() != RPC_E_TOO_LATE {
                return Err(err.into());
            }
        }

        let locator: IWbemLocator =
            unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)? };

        let service = unsafe {
            locator.ConnectServer(
                &BSTR::from("ROOT\\CIMV2"),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                WBEM_FLAG_CONNECT_USE_MAX_WAIT.0,
                &BSTR::new(),
                None,
            )?
        };

        unsafe {
            CoSetProxyBlanket(
                &service,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                None,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
            )?;
        }

        let enumerator = unsafe {
            service.ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from("SELECT Version FROM Win32_OperatingSystem"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )?
        };

        loop {
            let mut classes = [None; 1];
            let mut count = 0u32;

            unsafe {
                enumerator
                    .Next(WBEM_INFINITE, &mut classes, &mut count)
                    .ok()?
            };

            if count == 0 {
                break;
            }

            let Some(class) = &classes[0] else {
                break;
            };

            let mut var = VARIANT::default();
            unsafe { class.Get(w!("Version"), 0, &mut var, None, None)? };

            let ty = unsafe { var.Anonymous.Anonymous.vt };
            if ty.0 != VT_BSTR.0 {
                continue;
            }

            let val: &BSTR = unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal };
            let val: String = val.try_into()?;

            let mut s = val.split('.');
            let Some(major) = s.next().and_then(|s| s.parse().ok()) else {
                return Err(ErrorKind::WmiUnexpectedVersion(val).into());
            };
            let Some(minor) = s.next().and_then(|s| s.parse().ok()) else {
                return Err(ErrorKind::WmiUnexpectedVersion(val).into());
            };
            let Some(build) = s.next().and_then(|s| s.parse().ok()) else {
                return Err(ErrorKind::WmiUnexpectedVersion(val).into());
            };

            return Ok(Self {
                major,
                minor,
                build,
            });
        }

        Err(ErrorKind::WmiNotFound.into())
    }

    pub fn detect() -> Option<Self> {
        if let Ok(version) = Self::from_ntdll_dll() {
            return Some(version);
        }
        if let Ok(version) = Self::from_wmi_os_provider() {
            return Some(version);
        }
        if let Ok(version) = Self::from_kernel32_dll() {
            return Some(version);
        }
        if let Ok(version) = Self::from_get_version_ex() {
            return Some(version);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_kernel32_dll() {
        let v = WindowsVersion::from_kernel32_dll().unwrap();
        assert_eq!(v.major, 10, "{:?}", v);
        assert_eq!(v.minor, 0, "{:?}", v);
        assert!(v.build > 0, "{:?}", v);
    }

    #[test]
    fn test_from_ntdll_dll() {
        let v = WindowsVersion::from_ntdll_dll().unwrap();
        assert_eq!(v.major, 10, "{:?}", v);
        assert_eq!(v.minor, 0, "{:?}", v);
        assert!(v.build > 0, "{:?}", v);
    }

    #[test]
    fn test_from_get_version() {
        let v = WindowsVersion::from_get_version_ex().unwrap();
        // `GetVersionExW` may return wrong version
        assert!(v.major >= 6, "{:?}", v);
    }

    #[test]
    fn test_from_wmi_os_provider() {
        let v = WindowsVersion::from_wmi_os_provider().unwrap();
        assert_eq!(v.major, 10, "{:?}", v);
        assert_eq!(v.minor, 0, "{:?}", v);
        assert!(v.build > 0, "{:?}", v);

        // Initializing security fails on the second call. Check if the failure is handled correctly.
        let _ = WindowsVersion::from_wmi_os_provider().unwrap();
    }

    #[test]
    fn test_detect() {
        let v = WindowsVersion::detect().unwrap();
        assert_eq!(v.major, 10, "{:?}", v);
        assert_eq!(v.minor, 0, "{:?}", v);
        assert!(v.build > 0, "{:?}", v);
    }

    #[test]
    fn test_accurate_version_from_ntdll_and_wmi() {
        let v1 = WindowsVersion::from_ntdll_dll().unwrap();
        let v2 = WindowsVersion::from_wmi_os_provider().unwrap();
        assert_eq!(v1, v2);
    }
}
