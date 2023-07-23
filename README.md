`winver` crate
==============

`winver` is a Rust crate to detect real Windows OS version.

```rust
use winver::WindowsVersion;

let version = WindowsVersion::detect()?;
if version >= WindowsVersion::new(10, 0, 15063) {
    println!("OS version is 10.0.15063 or later");
}
```

There are several ways to get Windows OS version and each of them has its pitfall. This crate provides API to get the version more
easily and safely avoiding the pitfalls.

The above `WindowsVersion::detect` function works as follows:

1. Try to get OS version from [`RtlGetVersion`](https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlgetversion) function
   in ntdll.dll. However it is a kernel mode function and ntdll.dll does not always exist.
2. Try to get OS version from a file version information of kernel32.dll. However there is no guarantee to have permission to
   access the file.
3. Try to get OS version from [`GetVersionExW`](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexw)
   function as fallback. This is an official way to get OS version but it lies if the program is running in compatibility mode
   and it requires to [embed compatibility manifest in your executable](https://learn.microsoft.com/en-us/windows/win32/sysinfo/targeting-your-application-at-windows-8-1).
4. Give up getting OS version and return `None`.

This logic was implemented referring to the implementation of [Python's `sys.getwindowsversion`](https://docs.python.org/3/library/sys.html#sys.getwindowsversion).

## Installation

Add the following lines to your project's Cargo.toml. Note that `winver` crate is available only on Windows.

```toml
[target."cfg(windows)".dependencies]
winver = "0.1.0"
```

## License

Distributed under [the MIT license](./LICENSE).
