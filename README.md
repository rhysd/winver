`winver` crate
==============
[![CI][ci-badge]][ci]
[![crate][crates-io-badge]][crate]
[![docs][doc-badge]][doc]

[`winver`][crate] is a tiny Rust crate to detect real Windows OS version depending on [`windows` crate][windows] only.

```rust
use winver::WindowsVersion;

let version = WindowsVersion::detect().unwrap();
if version >= WindowsVersion::new(10, 0, 15063) {
    println!("OS version is 10.0.15063 or later");
}
```

There are several ways to get Windows OS version and each of them has its pitfall. This crate provides API to get the version more
easily and safely avoiding the pitfalls.

The above `WindowsVersion::detect` function works as follows:

1. Try to get OS version from [`RtlGetVersion`][wtlgetver] function in ntdll.dll. However it is a kernel mode function and
   ntdll.dll does not always exist.
2. Try to get OS version from [WMI][wmi]'s [`Win32_OperatingSystem` provider][win32prov] via [WQL][wql]. WMI may not be available
   due to the process security level setting.
3. Try to get OS version from a file version information of kernel32.dll. However the version information in file might be slightly
   different from the actual OS version.
4. Try to get OS version from [`GetVersionExW`][getver] function as fallback. This is an official way to get OS version but it
   lies if the program is running in compatibility mode and it requires to [embed compatibility manifest in your executable][manifest].
5. Give up getting OS version and return `None`.

Each steps are implemented as isolated funcitons in `WindowsVersion`. For example, the step 1. is equivalent to
`WindowsVersion::from_ntdll_dll`.

This logic was implemented referring to the implementation of Python's [`sys.getwindowsversion`][getwindowsversion] and
[`platform.win32_ver`][win32_ver].

See [the API documentation][doc] for more details.

## Installation

Add the following lines to your project's Cargo.toml. Note that `winver` crate is available only on Windows.

```toml
[target."cfg(windows)".dependencies]
winver = "0.1.0"
```

Minimum supported Rust version is 1.65.0 for using let-else statement.

## License

Distributed under [the MIT license](./LICENSE).

[ci-badge]: https://github.com/rhysd/winver/actions/workflows/ci.yaml/badge.svg
[ci]: https://github.com/rhysd/winver/actions/workflows/ci.yaml
[crates-io-badge]: https://img.shields.io/crates/v/winver.svg
[crate]: https://crates.io/crates/winver
[doc-badge]: https://docs.rs/winver/badge.svg
[doc]: https://docs.rs/winver/latest/winver/
[windows]: https://crates.io/crates/windows
[wtlgetver]: https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlgetversion
[wmi]: https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page
[win32prov]: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem
[wql]: https://learn.microsoft.com/en-us/windows/win32/wmisdk/querying-with-wql
[getver]: https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexw
[manifest]: https://learn.microsoft.com/en-us/windows/win32/sysinfo/targeting-your-application-at-windows-8-1
[getwindowsversion]: https://docs.python.org/3/library/sys.html#sys.getwindowsversion
[win32_ver]: https://docs.python.org/3/library/platform.html#platform.win32_ver
