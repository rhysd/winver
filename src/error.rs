use std::alloc::LayoutError;
use std::error::Error as StdError;
use std::fmt;
use std::string::FromUtf16Error;
use windows::core::Error as WinError;

/// Kinds of errors returned from `WindowsVersion` methods.
#[derive(Debug)]
pub enum ErrorKind {
    /// Error on calling Win32 APIs with windows-rs crate.
    Windows(WinError),
    /// Layout error on allocating a memory buffer on heap.
    Layout(LayoutError),
    /// Version information is not found in kernel32.dll file.
    Kernel32VerNotFound,
    /// `RtlGetVersion` symbol is not found in ntdll.dll when dynamically loading the DLL file.
    NoRtlGetVersion,
    /// Failure with error code returned from `RtlGetVersion` call.
    RtlGetVersionFailure(i32),
    /// UTF-16 to UTF-8 conversion failure when converting `BSTR` into `String`.
    Utf16ToUtf8(FromUtf16Error),
    /// No version information is found in WMI's Win32 OS system provider.
    WmiNotFound,
    /// Version string obtained from WMI's Win32 OS system provider is in unexpected format.
    WmiUnexpectedVersion(String),
}

/// The single error type for all errors returned from this crate.
#[derive(Debug)]
pub struct Error(Box<ErrorKind>);

impl Error {
    /// Return the kind of the error to know the details and to get the underlying errors.
    pub fn kind(&self) -> &ErrorKind {
        &self.0
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
            ErrorKind::Utf16ToUtf8(err) => write!(
                f,
                "Error while converting UTF-16 string into UTF-8: {}",
                err,
            ),
            ErrorKind::WmiNotFound => write!(
                f,
                "No 'Version' property is found in 'Win32_OperatingSystem' class queried via WQL",
            ),
            ErrorKind::WmiUnexpectedVersion(ver) => write!(
                f,
                "Unexpected version string at 'Version' property of 'Win32_OperatingSystem' WMI provider: {:?}",
                ver,
            ),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self.kind() {
            ErrorKind::Windows(err) => Some(err),
            ErrorKind::Layout(err) => Some(err),
            ErrorKind::Utf16ToUtf8(err) => Some(err),
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

impl From<FromUtf16Error> for Error {
    fn from(err: FromUtf16Error) -> Self {
        ErrorKind::Utf16ToUtf8(err).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format() {
        let err: Error = WinError::OK.into();
        let msg = format!("{}", err);
        assert!(msg.contains("Error while calling Windows API"), "{:?}", msg);
    }

    #[test]
    fn test_kind() {
        let err: Error = ErrorKind::Kernel32VerNotFound.into();
        assert!(
            matches!(err.kind(), ErrorKind::Kernel32VerNotFound),
            "{:?}",
            err,
        );
    }

    #[test]
    fn test_source() {
        let err: Error = WinError::OK.into();
        let inner = err.source().unwrap();
        let msg = format!("{}", inner);
        assert!(msg.contains("(0x00000000)"), "{:?}", msg);
    }
}
