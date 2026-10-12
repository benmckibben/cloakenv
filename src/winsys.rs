//! Windows counterparts of the few operations that have no safe wrapper in std,
//! and so need `unsafe`. Windows-only; the Unix ones live in `sys`.
//!
//! * [`lock_file`]: an exclusive, advisory byte-range lock (`LockFileEx`) on
//!   the vault's lock file. The lock belongs to the handle, so a second open of
//!   the same file contends exactly like another process would, and it is
//!   released when the handle is closed or the process dies.
//! * [`replace_file`]: `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING |
//!   MOVEFILE_WRITE_THROUGH`, so the rename that publishes a new vault does not
//!   return before it has reached the disk (the equivalent of the directory
//!   `fsync` after the rename on Unix).

use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

/// Takes an exclusive lock on the first byte of `file`. With `block` false, a
/// lock held elsewhere is reported as [`io::ErrorKind::WouldBlock`], as the
/// Unix `flock` path does.
#[allow(unsafe_code)]
pub fn lock_file(file: &File, block: bool) -> io::Result<()> {
    let flags = if block {
        LOCKFILE_EXCLUSIVE_LOCK
    } else {
        LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY
    };
    // SAFETY: an all-zero OVERLAPPED is the documented way to lock at offset 0
    // of a handle opened without FILE_FLAG_OVERLAPPED. It lives for the whole
    // call, which is synchronous. The handle is valid because `file` is
    // borrowed for the call.
    let ok = unsafe {
        let mut overlapped: OVERLAPPED = std::mem::zeroed();
        LockFileEx(file.as_raw_handle(), flags, 0, 1, 0, &mut overlapped)
    };
    if ok != 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Err(err)
}

/// Renames `from` over `to` (replacing it) and waits until the move is on disk.
///
/// Another process (an antivirus scanner, an indexer, a reader that did not
/// open the file with delete sharing) can briefly hold the destination open, in
/// which case the move fails with a sharing violation or `ACCESS_DENIED`. That
/// is retried for about a quarter of a second before it is reported.
#[allow(unsafe_code)]
pub fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    let wide = |p: &Path| -> Vec<u16> { p.as_os_str().encode_wide().chain([0]).collect() };
    let (from_w, to_w) = (wide(from), wide(to));
    let mut last = None;
    for attempt in 0..10 {
        // SAFETY: both buffers are NUL-terminated UTF-16 that outlive the call.
        let ok = unsafe {
            MoveFileExW(
                from_w.as_ptr(),
                to_w.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        let transient = matches!(
            err.raw_os_error().map(|c| c as u32),
            Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION)
        );
        if !transient {
            return Err(err);
        }
        last = Some(err);
        if attempt < 9 {
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("replace failed")))
}
