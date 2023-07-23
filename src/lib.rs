use core::ffi::c_void;
use core::ptr::null_mut;
use std::alloc::{self, Layout, LayoutError};
use std::error::Error as StdError;
use std::fmt;
use windows::core::{Error as WinError, PCWSTR};
use windows::w;
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
};
use windows::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};

#[derive(Debug)]
enum ErrorKind {
    Windows(WinError),
    Layout(LayoutError),
    Kernel32VerNotFound,
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

impl From<WinError> for Error {
    fn from(err: WinError) -> Self {
        Self(Box::new(ErrorKind::Windows(err)))
    }
}

impl From<LayoutError> for Error {
    fn from(err: LayoutError) -> Self {
        Self(Box::new(ErrorKind::Layout(err)))
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
    pub major: u16,
    pub minor: u16,
    pub build: u16,
}

impl WindowsVersion {
    pub fn from_kernel32_dll() -> Result<WindowsVersion, Error> {
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
            return Err(Error(Box::new(ErrorKind::Kernel32VerNotFound)));
        }

        let info = info as *const VS_FIXEDFILEINFO;

        let info = unsafe { &*info };
        let major = (info.dwProductVersionMS >> 16) as u16;
        let minor = (info.dwProductVersionMS & 0xffff) as u16;
        let build = (info.dwProductVersionLS >> 16) as u16;

        Ok(Self {
            major,
            minor,
            build,
        })
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
}
