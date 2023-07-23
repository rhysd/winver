use core::ffi::c_void;
use core::ptr::null_mut;
use std::alloc::{self, Layout, LayoutError};
use std::error::Error as StdError;
use std::fmt;
use std::mem;
use windows::core::{Error as WinError, PCWSTR};
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
};
use windows::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW, GetProcAddress};
use windows::Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOW};
use windows::{s, w};

#[derive(Debug)]
enum ErrorKind {
    Windows(WinError),
    Layout(LayoutError),
    Kernel32VerNotFound,
    NoRtlGetVersion,
    RtlGetVersionFailure(i32),
}

#[derive(Debug)]
pub struct Error(Box<ErrorKind>);

impl Error {
    fn kind(&self) -> &ErrorKind {
        &*self.0
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind() {
            ErrorKind::Windows(err) => write!(f, "Error while calling Windows API: {}", err),
            ErrorKind::Layout(err) => write!(f, "Error while calculating memory layout: {}", err),
            ErrorKind::Kernel32VerNotFound => {
                write!(f, "Version information is not found in kernel32.dll")
            }
            ErrorKind::NoRtlGetVersion => {
                write!(f, "RtlGetVersion function does not exist in ntdll.dll")
            }
            ErrorKind::RtlGetVersionFailure(status) => write!(
                f,
                "RtlGetVersion function call failed with status {:x}",
                *status,
            ),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self.kind() {
            ErrorKind::Windows(err) => Some(err),
            ErrorKind::Layout(err) => Some(err),
            _ => None,
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self(Box::new(kind))
    }
}

impl From<WinError> for Error {
    fn from(err: WinError) -> Self {
        ErrorKind::Windows(err).into()
    }
}

impl From<LayoutError> for Error {
    fn from(err: LayoutError) -> Self {
        ErrorKind::Layout(err).into()
    }
}

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

#[derive(Debug)]
pub struct WindowsVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
}

impl WindowsVersion {
    // https://github.com/python/cpython/blob/a1a3193990cd6658c1fe859b88a2bc03971a16df/Python/sysmodule.c#L1533
    pub fn from_kernel32() -> Result<WindowsVersion, Error> {
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
    pub fn from_ntdll() -> Result<WindowsVersion, Error> {
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
    pub fn from_get_version_ex() -> Result<WindowsVersion, Error> {
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

    pub fn detect() -> Option<WindowsVersion> {
        if let Ok(version) = Self::from_ntdll() {
            return Some(version);
        }
        if let Ok(version) = Self::from_kernel32() {
            return Some(version);
        }
        if let Ok(version) = Self::from_get_version_ex() {
            return Some(version);
        }
        None
    }
}

impl fmt::Display for WindowsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_kernel32_dll() {
        let v = WindowsVersion::from_kernel32().unwrap();
        assert_eq!(v.major, 10, "{:?}", v);
        assert_eq!(v.minor, 0, "{:?}", v);
        assert!(v.build > 0, "{:?}", v);
    }

    #[test]
    fn test_from_ntdll() {
        let v = WindowsVersion::from_ntdll().unwrap();
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
    fn test_detect() {
        let v = WindowsVersion::detect().unwrap();
        assert_eq!(v.major, 10, "{:?}", v);
        assert_eq!(v.minor, 0, "{:?}", v);
        assert!(v.build > 0, "{:?}", v);
    }
}
