#[cfg(not(windows))]
compile_error!("windows_ver crate is only available on Windows");

mod detect;
mod error;
mod version;

pub use error::Error;
pub use version::WindowsVersion;
