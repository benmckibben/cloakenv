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
//! * [`spawn_confined`] and [`Job`]: start the command inside a job object that
//!   kills every process in it when cloakenv goes away, however it goes (the
//!   counterpart of `PR_SET_PDEATHSIG` on Linux, and stronger: it covers the
//!   command's descendants too).
//! * [`ConsoleModeGuard`]: puts the console's input mode back if cloakenv is
//!   killed by Ctrl-C (or the window is closed) while a hidden prompt has echo
//!   switched off.
//! * [`InterruptGuard`]: keeps cloakenv alive through Ctrl-C and Ctrl-Break
//!   while the command runs, so the command (which gets them from the console
//!   itself) decides what to do and cloakenv reports its exit status.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows_sys::Win32::System::Console::{
    CTRL_BREAK_EVENT, CTRL_C_EVENT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE,
    SetConsoleCtrlHandler, SetConsoleMode,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
};

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

/// A job object that kills every process in it when its last handle is closed
/// (which also happens if cloakenv is killed or crashes).
pub struct Job {
    handle: OwnedHandle,
}

impl Job {
    #[allow(unsafe_code)]
    fn new() -> io::Result<Self> {
        // SAFETY: no security attributes and no name; the returned handle, if
        // not null, is a new job object that nothing else owns.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a valid handle that we own and wrap exactly once.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let job = Self { handle };
        job.set_kill_on_close(true)?;
        Ok(job)
    }

    #[allow(unsafe_code)]
    fn set_kill_on_close(&self, on: bool) -> io::Result<()> {
        // SAFETY: the struct is plain data for which all-zero is a valid value.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        if on {
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        }
        // SAFETY: `info` outlives the call and the size passed is its size;
        // the handle is a live job object owned by `self`.
        let ok = unsafe {
            SetInformationJobObject(
                self.handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&info).cast::<c_void>(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn assign(&self, child: &Child) -> io::Result<()> {
        // SAFETY: both handles are live and owned by `self` and `child`.
        let ok =
            unsafe { AssignProcessToJobObject(self.handle.as_raw_handle(), child.as_raw_handle()) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Stops the job from killing anything when it is closed: the command has
    /// exited normally, and a background process it left behind is none of our
    /// business (on Unix such a process is left alone too). Without this call,
    /// dropping the job kills everything still in it.
    pub fn release(self) {
        let _ = self.set_kill_on_close(false);
    }
}

/// Starts `cmd` inside a new job object that kills the whole process tree if
/// cloakenv dies, and returns the child and the job.
///
/// The process is created suspended, put in the job, and only then resumed, so
/// that nothing it starts can run before it is confined. If the job cannot be
/// created or joined (an old Windows, or a parent job that forbids it) this says
/// so on stderr and starts the command without one: cloakenv worked that way
/// before, and refusing to run would be worse. If the process cannot be
/// resumed it is killed and the error returned.
pub fn spawn_confined(cmd: &mut Command) -> io::Result<(Child, Option<Job>)> {
    let job = match Job::new() {
        Ok(job) => job,
        Err(e) => {
            crate::elog!(
                "cloakenv: warning: cannot create a job object ({e}); the command will keep running if cloakenv is killed"
            );
            return Ok((cmd.spawn()?, None));
        }
    };
    cmd.creation_flags(CREATE_SUSPENDED);
    let mut child = cmd.spawn()?;
    let job = match job.assign(&child) {
        Ok(()) => Some(job),
        Err(e) => {
            crate::elog!(
                "cloakenv: warning: cannot put the command in a job object ({e}); it will keep running if cloakenv is killed"
            );
            None
        }
    };
    if let Err(e) = resume_process(child.id()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    Ok((child, job))
}

/// Resumes the (single) thread of a process created with `CREATE_SUSPENDED`.
/// std does not hand out the primary thread's handle, so find it by process id.
#[allow(unsafe_code)]
fn resume_process(pid: u32) -> io::Result<()> {
    // SAFETY: a thread snapshot of the whole system; no pointers involved.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: valid handle returned just above, wrapped exactly once.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
    // SAFETY: plain data for which all-zero is valid; dwSize is set below as
    // the API requires.
    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    let mut resumed = false;
    // SAFETY: the snapshot handle is live and `entry` is a valid, sized struct.
    let mut more = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) };
    while more != 0 {
        if entry.th32OwnerProcessID == pid {
            // SAFETY: opening a thread by id; the result is checked.
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if !thread.is_null() {
                // SAFETY: valid handle, wrapped exactly once (closed on drop).
                let thread = unsafe { OwnedHandle::from_raw_handle(thread) };
                // SAFETY: live thread handle opened with suspend/resume access.
                if unsafe { ResumeThread(thread.as_raw_handle()) } != u32::MAX {
                    resumed = true;
                }
            }
        }
        // SAFETY: as for Thread32First.
        more = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) };
    }
    if resumed {
        Ok(())
    } else {
        Err(io::Error::other(
            "cannot start the command (its main thread could not be resumed)",
        ))
    }
}

/// The console control handler: swallow Ctrl-C and Ctrl-Break, pass everything
/// else (console close, logoff, shutdown) to the next handler, which ends
/// cloakenv and, through the job object, the command.
#[allow(unsafe_code)]
unsafe extern "system" fn swallow_interrupts(ctrl_type: u32) -> i32 {
    i32::from(ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT)
}

/// While alive, cloakenv does not die from Ctrl-C or Ctrl-Break.
///
/// Both are delivered to every process attached to the console, so the command
/// receives them directly and handles them (or dies of them) on its own. If
/// cloakenv died first, the job object would kill the command before it could
/// clean up. The handler is a routine, not the "ignore" flag, so the command
/// does not inherit it.
pub struct InterruptGuard;

impl InterruptGuard {
    #[allow(unsafe_code)]
    pub fn install() -> Self {
        // SAFETY: registers a plain function with no state.
        unsafe { SetConsoleCtrlHandler(Some(swallow_interrupts), 1) };
        Self
    }
}

impl Drop for InterruptGuard {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: removes the routine registered by `install`.
        unsafe { SetConsoleCtrlHandler(Some(swallow_interrupts), 0) };
    }
}

// What the console control handler below needs to restore the input mode. It
// runs on a thread the system creates, so it can only read statics.
static SAVED_ACTIVE: AtomicBool = AtomicBool::new(false);
static SAVED_HANDLE: AtomicUsize = AtomicUsize::new(0);
static SAVED_MODE: AtomicU32 = AtomicU32::new(0);

fn restore_saved_mode() {
    if SAVED_ACTIVE.load(Ordering::SeqCst) {
        set_input_mode(
            SAVED_HANDLE.load(Ordering::SeqCst),
            SAVED_MODE.load(Ordering::SeqCst),
        );
    }
}

#[allow(unsafe_code)]
fn set_input_mode(handle: usize, mode: u32) {
    // SAFETY: `handle` is the standard input handle read by `capture` and the
    // process keeps it open; a failure is ignored (nothing else can be done).
    unsafe { SetConsoleMode(handle as *mut c_void, mode) };
}

/// On any console event (Ctrl-C, Ctrl-Break, window close, logoff, shutdown):
/// restore the input mode, then return "not handled" so the next handler, and
/// finally the default one that ends the process, still runs.
#[allow(unsafe_code)]
unsafe extern "system" fn restore_on_ctrl(_ctrl_type: u32) -> i32 {
    restore_saved_mode();
    0
}

/// Remembers the console's input mode for the duration of a hidden prompt and
/// puts it back afterwards, **including when Ctrl-C kills the process**.
///
/// The prompt switches echo off. If cloakenv then dies without the library's own
/// cleanup running (Ctrl-C terminates the process on the spot), the console is
/// left without echo and without line input, and the next program that reads
/// a line gets no echo and never sees Enter as a line end. PowerShell hides it
/// from its own prompt, which draws what you type itself.
pub struct ConsoleModeGuard {
    active: bool,
}

impl ConsoleModeGuard {
    /// A guard that does nothing when standard input is not a console.
    #[allow(unsafe_code)]
    pub fn capture() -> Self {
        // SAFETY: GetStdHandle takes no pointers; the result is checked below.
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Self { active: false };
        }
        let mut mode = 0u32;
        // SAFETY: `mode` is a valid out-pointer for the call; a non-console
        // handle makes it fail, which is handled just below.
        if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
            return Self { active: false };
        }
        SAVED_HANDLE.store(handle as usize, Ordering::SeqCst);
        SAVED_MODE.store(mode, Ordering::SeqCst);
        SAVED_ACTIVE.store(true, Ordering::SeqCst);
        // SAFETY: registers a plain function that only reads statics.
        unsafe { SetConsoleCtrlHandler(Some(restore_on_ctrl), 1) };
        Self { active: true }
    }
}

impl Drop for ConsoleModeGuard {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        restore_saved_mode();
        SAVED_ACTIVE.store(false, Ordering::SeqCst);
        // SAFETY: removes the routine registered by `capture`.
        unsafe { SetConsoleCtrlHandler(Some(restore_on_ctrl), 0) };
    }
}
