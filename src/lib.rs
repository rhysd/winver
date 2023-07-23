#[cfg(not(windows))]
compile_error!("'winver' crate is only available on Windows");

mod detect;
mod error;
mod version;

pub use error::Error;
pub use version::WindowsVersion;
