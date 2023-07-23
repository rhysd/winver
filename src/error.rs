use std::alloc::LayoutError;
use std::error::Error as StdError;
use std::fmt;
use windows::core::Error as WinError;

#[derive(Debug)]
pub(crate) enum ErrorKind {
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
