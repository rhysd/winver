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

    fn ptr(&self) -> *mut c_void {
        self.ptr as *mut _
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        self.deallocate();
    }
}

impl WindowsVersion {
    /// Detect the OS version of current Windows system using [`RtlGetVersion`][getver] function in `ntdll.dll` DLL.
    ///
    /// The obtained version is accurate. And this method is faster than [`WindowsVersion::from_wmi_os_provider`].
    /// However `ntdll.dll` does not always exist in your system and `RtlGetVersion` is a kernel-mode function.
    ///
    /// This method loads `ntdll.dll` dynamically and tries to call `RtlGetVersion` function in it with
    /// [`GetProcAddress`][getproc]. If the dynamic call fails, this method returns an error.
    ///
    /// [getver]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetversion
    /// [getproc]: https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
    pub fn from_ntdll_dll() -> Result<Self, Error> {
        let handle = unsafe { GetModuleHandleW(w!("ntdll.dll"))? };

        let Some(proc) = (unsafe { GetProcAddress(handle, s!("RtlGetVersion")) }) else {
            return Err(ErrorKind::NoRtlGetVersion.into());
        };

        type RtlGetVersionFunc = unsafe extern "system" fn(*mut OSVERSIONINFOW) -> i32;
        let proc: RtlGetVersionFunc = unsafe { mem::transmute(proc) };

        let mut info: OSVERSIONINFOW = unsafe { mem::zeroed() };
        info.dwOSVersionInfoSize = mem::size_of::<OSVERSIONINFOW>() as u32;

        let status = unsafe { proc(&mut info) };
        if status != 0 {
            return Err(ErrorKind::RtlGetVersionFailure(status).into());
        }

        Ok(Self {
            major: info.dwMajorVersion,
            minor: info.dwMinorVersion,
            build: info.dwBuildNumber,
        })
    }

    /// Detect the OS version of current Windows system using [WMI][wmi]'s [`Win32_OperatingSystem` provider][win32prov]
    /// via [WQL][wql].
    ///
    /// The obtained version is accurate. However WMI may not be available due to the process security level setting.
    /// When it is not possible to access the provider, this method returns an error.
    ///
    /// Note that this method is slow (it took 100ms on my machine). So [`WindowsVersion::from_ntdll_dll`] should be
    /// tried at first.
    ///
    /// [wmi]: https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page
    /// [win32prov]: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem
    /// [wql]: https://learn.microsoft.com/en-us/windows/win32/wmisdk/querying-with-wql
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
                    .ok()?;
            }

            if count == 0 {
                break;
            }

            let Some(class) = &classes[0] else {
                break;
            };

            let mut var = VARIANT::default();
            // Note: All properties are listed here: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem
            unsafe { class.Get(w!("Version"), 0, &mut var, None, None)? };

            if unsafe { var.Anonymous.Anonymous.vt } != VT_BSTR {
                continue;
            }

            let val: &BSTR = unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal };
            let val: String = val.try_into()?;

            fn parse(s: &str) -> Option<WindowsVersion> {
                let mut s = s.split('.');
                Some(WindowsVersion {
                    major: s.next()?.parse().ok()?,
                    minor: s.next()?.parse().ok()?,
                    build: s.next()?.parse().ok()?,
                })
            }

            return parse(&val).ok_or_else(|| ErrorKind::WmiUnexpectedVersion(val).into());
        }

        Err(ErrorKind::WmiNotFound.into())
    }

    /// Detect the OS version of current Windows system from `kernel32.dll` file's version information.
    ///
    /// The version actually represents the OS version where the `kernel32.dll` file was built. The build number may be
    /// slightly different from the actual OS version. This method should be used as fallback of other methods.
    ///
    /// This method was implemented referring to [Python's `sys.getwindowsversion` implementation][py].
    ///
    /// [py]: https://github.com/python/cpython/blob/a1a3193990cd6658c1fe859b88a2bc03971a16df/Python/sysmodule.c#L1533
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

        let success = unsafe { GetFileVersionInfoW(path, 0, size, buf.ptr()) };
        if !success.as_bool() {
            return Err(WinError::from_win32().into());
        }

        let mut info: *mut c_void = null_mut();
        let mut info_len = 0u32;

        let success = unsafe { VerQueryValueW(buf.ptr(), w!(""), &mut info, &mut info_len) };
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

    /// Detect the OS version of current Windows system using [`GetVersionEx` Win32 API][api].
    ///
    /// You need to embed a compatibility manifest into your executable. Otherwise, this method always returns version
    /// 6.2 (Windows 8) even if you're on Windows 10 or later. So this method should be used as fallback of other
    /// methods.
    ///
    /// This behavior is a limitation of the `GetVersionEx` function. Please read
    /// [the Remarks section of `VerifyVersionInfo` document][remarks].
    ///
    /// [api]: https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexw
    /// [remarks]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-verifyversioninfoa#remarks
    pub fn from_get_version_ex() -> Result<Self, Error> {
        let mut info: OSVERSIONINFOW = unsafe { mem::zeroed() };
        info.dwOSVersionInfoSize = mem::size_of::<OSVERSIONINFOW>() as u32;

        let success = unsafe { GetVersionExW(&mut info) };
        if !success.as_bool() {
            return Err(WinError::from_win32().into());
        }

        Ok(Self {
            major: info.dwMajorVersion,
            minor: info.dwMinorVersion,
            build: info.dwBuildNumber,
        })
    }

    /// Return the OS version of the current Windows system. This method tries to get the version with the following steps.
    /// When no version could not be detected on all steps, this method returns `None`.
    ///
    /// 1. Try to detect the OS version with [`WindowsVersion::from_ntdll_dll`]
    /// 2. Try to detect the OS version with [`WindowsVersion::from_wmi_os_provider`]
    /// 3. Try to detect the OS version with [`WindowsVersion::from_kernel32_dll`]
    /// 4. Try to detect the OS version with [`WindowsVersion::from_get_version_ex`]
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
