use crate::Valkyrie;
use crate::common::{last_errno, neg_errno, read_word};
use crate::error::Result;
use crate::fs::*;
use crate::logger::Logger;
use crate::os::register_syscall::SubCtx;

use libc::{c_char, c_int};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::mem;
#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::PathBuf;

#[cfg(target_os = "linux")]
unsafe fn open_at(dirfd: c_int, c_path: *const c_char, flags: c_int, mode: u32) -> c_int {
    unsafe { libc::openat(dirfd, c_path, flags, mode as libc::c_uint) }
}

#[cfg(not(target_os = "linux"))]
unsafe fn open_at(dirfd: c_int, c_path: *const c_char, flags: c_int, mode: u32) -> c_int {
    if dirfd != AT_FDCWD {
        Logger::error("openat with dirfd not supported on this platform");
        return -1;
    }
    Logger::warning(
        "openat not supported on this platform, falling back to open() only with AT_FDCWD",
    );
    unsafe { libc::open(c_path, flags, mode as libc::c_uint) }
}

#[cfg(target_os = "linux")]
const IOC_NRBITS: libc::c_ulong = 8;
#[cfg(target_os = "linux")]
const IOC_TYPEBITS: libc::c_ulong = 8;
#[cfg(target_os = "linux")]
const IOC_SIZEBITS: libc::c_ulong = 14;
#[cfg(target_os = "linux")]
const IOC_DIRBITS: libc::c_ulong = 2;
#[cfg(target_os = "linux")]
const IOC_TYPESHIFT: libc::c_ulong = IOC_NRBITS;
#[cfg(target_os = "linux")]
const IOC_SIZESHIFT: libc::c_ulong = IOC_TYPESHIFT + IOC_TYPEBITS;
#[cfg(target_os = "linux")]
const IOC_DIRSHIFT: libc::c_ulong = IOC_SIZESHIFT + IOC_SIZEBITS;
#[cfg(target_os = "linux")]
const IOC_SIZEMASK: libc::c_ulong = (1 << IOC_SIZEBITS) - 1;
#[cfg(target_os = "linux")]
const IOC_DIRMASK: libc::c_ulong = (1 << IOC_DIRBITS) - 1;
#[cfg(target_os = "linux")]
const IOC_WRITE: libc::c_ulong = 1;
#[cfg(target_os = "linux")]
const IOC_READ: libc::c_ulong = 2;

#[cfg(target_os = "linux")]
#[repr(C, packed)]
struct LinuxX86StatFs64 {
    f_type: u32,
    f_bsize: u32,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [u8; 8],
    f_namelen: u32,
    f_frsize: u32,
    f_flags: u32,
    f_spare: [u32; 4],
}

#[cfg(target_os = "linux")]
fn ioctl_request_size(request: libc::c_ulong) -> usize {
    ((request >> IOC_SIZESHIFT) & IOC_SIZEMASK) as usize
}

#[cfg(target_os = "linux")]
fn ioctl_request_dir(request: libc::c_ulong) -> libc::c_ulong {
    (request >> IOC_DIRSHIFT) & IOC_DIRMASK
}

#[cfg(target_os = "linux")]
fn host_fd_for_guest(fd: u64) -> Option<c_int> {
    if fd <= 2 {
        return Some(fd as c_int);
    }

    let table = fd_table().lock().ok()?;
    table.files.get(&fd).map(|vkf| vkf.file.as_raw_fd())
}

#[cfg(target_os = "linux")]
fn fsid_bytes(fsid: &libc::fsid_t) -> [u8; 8] {
    let raw = unsafe {
        std::slice::from_raw_parts(
            (fsid as *const libc::fsid_t).cast::<u8>(),
            mem::size_of::<libc::fsid_t>(),
        )
    };
    let mut out = [0u8; 8];
    out.copy_from_slice(raw);
    out
}

#[cfg(target_os = "linux")]
fn pack_linux_x86_statfs_le(st: &libc::statfs64) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    push_u32_le(&mut out, st.f_type as u32);
    push_u32_le(&mut out, st.f_bsize as u32);
    push_u32_le(&mut out, st.f_blocks as u32);
    push_u32_le(&mut out, st.f_bfree as u32);
    push_u32_le(&mut out, st.f_bavail as u32);
    push_u32_le(&mut out, st.f_files as u32);
    push_u32_le(&mut out, st.f_ffree as u32);
    out.extend_from_slice(&fsid_bytes(&st.f_fsid));
    push_u32_le(&mut out, st.f_namelen as u32);
    push_u32_le(&mut out, st.f_frsize as u32);
    push_u32_le(&mut out, st.f_flags as u32);
    for spare in [0u32; 4] {
        push_u32_le(&mut out, spare);
    }
    out
}

#[cfg(target_os = "linux")]
fn pack_linux_x86_statfs64_le(st: &libc::statfs64) -> Vec<u8> {
    let packed = LinuxX86StatFs64 {
        f_type: st.f_type as u32,
        f_bsize: st.f_bsize as u32,
        f_blocks: st.f_blocks,
        f_bfree: st.f_bfree,
        f_bavail: st.f_bavail,
        f_files: st.f_files,
        f_ffree: st.f_ffree,
        f_fsid: fsid_bytes(&st.f_fsid),
        f_namelen: st.f_namelen as u32,
        f_frsize: st.f_frsize as u32,
        f_flags: st.f_flags as u32,
        f_spare: [0; 4],
    };

    unsafe {
        std::slice::from_raw_parts(
            (&packed as *const LinuxX86StatFs64).cast::<u8>(),
            mem::size_of::<LinuxX86StatFs64>(),
        )
        .to_vec()
    }
}

#[cfg(target_os = "linux")]
fn statfs_for_path(vk: &Valkyrie, path: &str) -> Result<libc::statfs64> {
    let abs_path = match get_path_at(vk, AT_FDCWD, path) {
        Some(path) => path,
        None => {
            return Err(crate::error::ValkyrieError::Io(
                io::Error::from_raw_os_error(libc::EBADF),
            ));
        }
    };

    let c_path = match CString::new(abs_path.to_string_lossy().as_bytes()) {
        Ok(path) => path,
        Err(_) => {
            return Err(crate::error::ValkyrieError::Io(
                io::Error::from_raw_os_error(libc::EINVAL),
            ));
        }
    };

    Logger::debug(
        format!("sys_statfs(path={})", abs_path.display()),
        vk.cfg.verbose,
    );

    let mut st: libc::statfs64 = unsafe { mem::zeroed() };
    let ret = unsafe { libc::statfs64(c_path.as_ptr(), &mut st as *mut libc::statfs64) };
    if ret == -1 {
        return Err(crate::error::ValkyrieError::Io(io::Error::last_os_error()));
    }

    Ok(st)
}

fn guest_path_at(vk: &Valkyrie, dirfd: c_int, path: &str) -> Result<PathBuf> {
    get_path_at(vk, dirfd, path)
        .ok_or_else(|| crate::error::ValkyrieError::Io(io::Error::from_raw_os_error(libc::EBADF)))
}

pub fn sys_read(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0();
    let buf_addr = sctx.arg1();
    let count = sctx.arg2() as usize;

    if count == 0 {
        return Ok(0);
    }

    let mut buffer = vec![0u8; count];

    let bytes_read: usize = if fd == 0 {
        match io::stdin().read(&mut buffer) {
            Ok(n) => n,
            Err(_) => return Ok(last_errno()),
        }
    } else {
        let mut table = fd_table().lock().unwrap();
        match table.files.get_mut(&fd) {
            Some(vkf) => match vkf.file.read(&mut buffer) {
                Ok(n) => n,
                Err(_) => return Ok(last_errno()),
            },
            None => {
                drop(table);
                let n = unsafe {
                    libc::read(fd as i32, buffer.as_mut_ptr().cast::<libc::c_void>(), count)
                };
                if n < 0 {
                    return Ok(last_errno());
                }
                n as usize
            }
        }
    };

    let preview_len = (bytes_read as usize).min(10).min(buffer.len());
    let preview = String::from_utf8_lossy(&buffer[..preview_len]);

    Logger::debug(
        format!("sys_read(fd={fd}, count={count}) => {bytes_read} ({preview:?})"),
        vk.cfg.verbose,
    );

    if bytes_read > 0 {
        vk.mem.write(&mut vk.uc, buf_addr, &buffer[..bytes_read])?;
    }

    Ok(bytes_read as u64)
}

pub fn sys_pread64(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0();
    let buf_addr = sctx.arg1();
    let count = sctx.arg2() as usize;
    let offset = match vk.cfg.arch {
        crate::vtype::Arch::X86 => sctx.arg3() | (sctx.arg4() << 32),
        crate::vtype::Arch::X86_64 => sctx.arg3(),
    };

    if count == 0 {
        return Ok(0);
    }

    let mut buffer = vec![0u8; count];

    let bytes_read = {
        let mut table = fd_table().lock().unwrap();
        match table.files.get_mut(&fd) {
            Some(vkf) => {
                let mut file = match vkf.file.try_clone() {
                    Ok(file) => file,
                    Err(_) => return Ok(neg_errno(libc::EIO)),
                };
                if file.seek(std::io::SeekFrom::Start(offset)).is_err() {
                    return Ok(neg_errno(libc::EIO));
                }
                match file.read(&mut buffer) {
                    Ok(n) => n,
                    Err(_) => return Ok(last_errno()),
                }
            }
            None => {
                drop(table);
                #[cfg(target_os = "linux")]
                {
                    let n = unsafe {
                        libc::pread64(
                            fd as i32,
                            buffer.as_mut_ptr().cast::<libc::c_void>(),
                            count,
                            offset as libc::off64_t,
                        )
                    };
                    if n < 0 {
                        return Ok(last_errno());
                    }
                    n as usize
                }
                #[cfg(not(target_os = "linux"))]
                {
                    return Ok(neg_errno(libc::ENOSYS));
                }
            }
        }
    };

    let preview_len = bytes_read.min(10).min(buffer.len());
    let preview = String::from_utf8_lossy(&buffer[..preview_len]);

    Logger::debug(
        format!(
            "sys_pread64(fd={fd}, count={count}, offset={offset:#x}) => {bytes_read} ({preview:?})"
        ),
        vk.cfg.verbose,
    );

    if bytes_read > 0 {
        vk.mem.write(&mut vk.uc, buf_addr, &buffer[..bytes_read])?;
    }

    Ok(bytes_read as u64)
}

pub fn sys_lseek(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0();
    let offset = sctx.arg1() as i64;
    let whence = sctx.arg2() as i32;

    Logger::debug(
        format!("sys_lseek(fd={fd}, offset={offset}, whence={whence})"),
        vk.cfg.verbose,
    );

    let result = if fd <= 2 {
        unsafe { libc::lseek(fd as c_int, offset as libc::off_t, whence) }
    } else {
        let mut table = fd_table().lock().unwrap();
        match table.files.get_mut(&fd) {
            Some(vkf) => {
                let pos = match whence {
                    libc::SEEK_SET => vkf.file.seek(std::io::SeekFrom::Start(offset as u64)),
                    libc::SEEK_CUR => vkf.file.seek(std::io::SeekFrom::Current(offset)),
                    libc::SEEK_END => vkf.file.seek(std::io::SeekFrom::End(offset)),
                    _ => return Ok(neg_errno(libc::EINVAL)),
                };
                match pos {
                    Ok(pos) => pos as i64,
                    Err(_) => return Ok(last_errno()),
                }
            }
            None => {
                drop(table);
                unsafe { libc::lseek(fd as c_int, offset as libc::off_t, whence) }
            }
        }
    };

    if result < 0 {
        return Ok(last_errno());
    }

    Ok(result as u64)
}

pub fn sys_open(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    // open(const char *pathname, int flags, mode_t mode)
    let path_ptr = sctx.arg0();
    let flags = sctx.arg1() as i32;
    let mode = sctx.arg2() as u32;

    let path = read_guest_cstring(vk, path_ptr)?;
    let host_path = match guest_path_at(vk, AT_FDCWD, &path) {
        Ok(path) => path,
        Err(_) => return Ok(neg_errno(libc::EBADF)),
    };

    Logger::debug(
        format!("sys_open(path={}, flags={})", host_path.display(), flags),
        vk.cfg.verbose,
    );

    let c_path = match CString::new(host_path.to_string_lossy().as_bytes()) {
        Ok(s) => s,
        Err(_) => return Ok((-(libc::EINVAL as i64)) as u64),
    };

    let fd: c_int = unsafe { libc::open(c_path.as_ptr() as *const c_char, flags as c_int, mode) };

    if fd == -1 {
        let err = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        Logger::warning(format!(
            "sys_open: failed to open {host_path:?} (guest path: {path:?}): errno={err}"
        ));
        return Ok((-(err as i64)) as u64);
    }

    let mut _file: Option<File> = None;
    #[cfg(target_os = "linux")]
    {
        _file = Some(unsafe { FromRawFd::from_raw_fd(fd) });
    }

    if _file.is_none() {
        unsafe { libc::close(fd) };
        return Ok((-(libc::EINVAL as i64)) as u64);
    }

    {
        let mut table = fd_table().lock().unwrap();

        table.files.insert(
            fd as u64,
            VkFile {
                file: _file.unwrap(),
                path: host_path,
                flags: flags as u64,
                mode: mode as u64,
            },
        );
    }

    Ok(fd as u64)
}

pub fn sys_access(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let path_ptr = sctx.arg0();
    let mode = sctx.arg1() as i32;

    let path = read_guest_cstring(vk, path_ptr)?;
    let host_path = match guest_path_at(vk, AT_FDCWD, &path) {
        Ok(path) => path,
        Err(_) => return Ok(neg_errno(libc::EBADF)),
    };

    Logger::debug(
        format!("sys_access(path={}, mode={mode:#x})", host_path.display()),
        vk.cfg.verbose,
    );

    let c_path = match CString::new(host_path.to_string_lossy().as_bytes()) {
        Ok(s) => s,
        Err(_) => return Ok(neg_errno(libc::EINVAL)),
    };

    let ret = unsafe { libc::access(c_path.as_ptr() as *const c_char, mode) };
    if ret == -1 {
        return Ok(last_errno());
    }

    Ok(0)
}

pub fn sys_fstat(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0();
    let statbuf_ptr = sctx.arg1();

    #[cfg(not(target_os = "linux"))]
    {
        Logger::warning("fstat not supported on this platform. syscall will return -1;");
        return Ok(last_errno());
    }

    #[cfg(target_os = "linux")]
    {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::fstat(fd as c_int, &mut st as *mut libc::stat) };
        if ret == -1 {
            return Ok(last_errno());
        }

        let st_len = mem::size_of::<libc::stat>();
        let st_bytes =
            unsafe { std::slice::from_raw_parts((&st as *const libc::stat).cast::<u8>(), st_len) };
        vk.mem.write(&mut vk.uc, statbuf_ptr, st_bytes)?;
        Ok(0)
    }
}

pub fn sys_openat(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let dirfd = sctx.arg0() as i64 as i32;
    let path_ptr = sctx.arg1();
    let flags = sctx.arg2() as i32;
    let mode = sctx.arg3() as u32;

    let path = read_guest_cstring(vk, path_ptr)?;
    let host_path = match guest_path_at(vk, dirfd, &path) {
        Ok(path) => path,
        Err(_) => return Ok(neg_errno(libc::EBADF)),
    };

    Logger::debug(
        format!("sys_openat(dirfd={}, path={})", dirfd, host_path.display()),
        vk.cfg.verbose,
    );

    let c_path = match CString::new(host_path.to_string_lossy().as_bytes()) {
        Ok(s) => s,
        Err(_) => return Ok(neg_errno(libc::EINVAL)),
    };

    let fd: c_int = unsafe { open_at(dirfd, c_path.as_ptr() as *const c_char, flags, mode) };
    if fd == -1 {
        return Ok(last_errno());
    }

    let mut _file: Option<File> = None;

    #[cfg(target_os = "linux")]
    {
        _file = Some(unsafe { std::fs::File::from_raw_fd(fd) });
    }

    if _file.is_none() {
        unsafe { libc::close(fd) };
        return Ok(neg_errno(libc::EINVAL));
    }

    let mut table = fd_table().lock().unwrap();
    table.files.insert(
        fd as u64,
        VkFile {
            file: _file.unwrap(),
            path: host_path,
            flags: flags as u64,
            mode: mode as u64,
        },
    );

    Ok(fd as u64)
}

pub fn sys_write(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0();
    let buf_addr = sctx.arg1();
    let count = sctx.arg2() as usize;

    if count == 0 {
        return Ok(0);
    }

    let buffer = vk.mem.read(&mut vk.uc, buf_addr, count)?;

    let bytes_written: usize = match fd {
        1 => match io::stdout().write(&buffer) {
            Ok(n) => n,
            Err(_) => return Ok(last_errno()),
        },
        2 => match io::stderr().write(&buffer) {
            Ok(n) => n,
            Err(_) => return Ok(last_errno()),
        },
        _ => {
            let mut table = fd_table().lock().unwrap();
            match table.files.get_mut(&fd) {
                Some(vkf) => match vkf.file.write(&buffer) {
                    Ok(n) => n,
                    Err(_) => return Ok(last_errno()),
                },
                None => {
                    drop(table);
                    let n = unsafe {
                        libc::write(fd as i32, buffer.as_ptr().cast::<libc::c_void>(), count)
                    };
                    if n < 0 {
                        return Ok(last_errno());
                    }
                    n as usize
                }
            }
        }
    };

    let preview_len = (bytes_written as usize).min(10).min(buffer.len());
    let preview = String::from_utf8_lossy(&buffer[..preview_len]);

    Logger::debug(
        format!("sys_write(fd={fd}, count={count}) => {bytes_written} ({preview:?})"),
        vk.cfg.verbose,
    );

    Ok(bytes_written as u64)
}

pub fn sys_writev(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0();
    let iov_addr = sctx.arg1();
    let iovcnt = sctx.arg2() as usize;

    if iovcnt == 0 {
        return Ok(0);
    }

    let ptr_size = (vk.cfg.archsize / 8) as usize;
    let iov_size = ptr_size * 2;

    let mut total = 0u64;
    let mut table_guard = if fd > 2 {
        Some(fd_table().lock().unwrap())
    } else {
        None
    };

    for index in 0..iovcnt {
        let base_addr = iov_addr + (index * iov_size) as u64;
        let iov_base = read_word(vk, base_addr, ptr_size)?;
        let iov_len = read_word(vk, base_addr + ptr_size as u64, ptr_size)? as usize;

        if iov_len == 0 {
            continue;
        }

        let buffer = vk.mem.read(&mut vk.uc, iov_base, iov_len)?;
        let write_result = match fd {
            1 => io::stdout().write(&buffer),
            2 => io::stderr().write(&buffer),
            _ => match table_guard.as_mut() {
                Some(table) => match table.files.get_mut(&fd) {
                    Some(vkf) => vkf.file.write(&buffer),
                    None => {
                        let count = unsafe {
                            libc::write(
                                fd as i32,
                                buffer.as_ptr().cast::<libc::c_void>(),
                                buffer.len(),
                            )
                        };
                        if count < 0 {
                            Err(io::Error::last_os_error())
                        } else {
                            Ok(count as usize)
                        }
                    }
                },
                None => return Ok(neg_errno(libc::EBADF)),
            },
        };

        match write_result {
            Ok(count) => {
                total += count as u64;
                if count < iov_len {
                    break;
                }
            }
            Err(_) => {
                if total > 0 {
                    return Ok(total);
                }
                return Ok(last_errno());
            }
        }
    }

    Ok(total)
}

pub fn sys_close(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0();

    if fd <= 2 {
        return Ok(0);
    }

    Logger::debug(format!("sys_close(fd={fd})"), vk.cfg.verbose);

    let mut table = fd_table().lock().unwrap();
    if table.files.remove(&fd).is_some() {
        Ok(0)
    } else {
        drop(table);

        let ret = unsafe { libc::close(fd as i32) };
        if ret == -1 { Ok(last_errno()) } else { Ok(0) }
    }
}

pub fn sys_dup(_vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let oldfd = sctx.arg0() as i32;

    if oldfd < 0 {
        return Ok(neg_errno(libc::EBADF));
    }

    let newfd = if oldfd <= 2 {
        let fd = unsafe { libc::dup(oldfd) };
        if fd == -1 {
            return Ok(last_errno());
        }
        fd
    } else {
        let cloned = {
            let table = fd_table().lock().unwrap();
            let Some(vkf) = table.files.get(&(oldfd as u64)) else {
                return Ok(neg_errno(libc::EBADF));
            };

            match vkf.file.try_clone() {
                Ok(file) => (file, vkf.path.clone(), vkf.flags, vkf.mode),
                Err(_) => return Ok(last_errno()),
            }
        };

        let (file, path, flags, mode) = cloned;
        let fd = file.as_raw_fd() as u64;

        let mut table = fd_table().lock().unwrap();
        table.files.insert(
            fd,
            VkFile {
                file,
                path,
                flags,
                mode,
            },
        );

        fd as i32
    };

    Ok(newfd as u64)
}

pub fn sys_fcntl(_vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0() as i32;
    let cmd = sctx.arg1() as i32;
    let arg = sctx.arg2() as i32;

    if fd < 0 {
        return Ok(neg_errno(libc::EBADF));
    }

    let ret = unsafe { libc::fcntl(fd, cmd, arg) };
    if ret == -1 {
        return Ok(last_errno());
    }

    if cmd == libc::F_SETFL && fd > 2 {
        let mut table = fd_table().lock().unwrap();
        if let Some(vkf) = table.files.get_mut(&(fd as u64)) {
            vkf.flags = arg as u64;
        }
    }

    Ok(ret as u64)
}

pub fn sys_ioctl(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0() as i32;
    let request = sctx.arg1() as libc::c_ulong;
    let arg = sctx.arg2();

    if fd < 0 {
        return Ok(neg_errno(libc::EBADF));
    }

    #[cfg(not(target_os = "linux"))]
    {
        Logger::warning("ioctl not supported on this platform. syscall will return -1;");
        return Ok(neg_errno(libc::ENOSYS));
    }

    #[cfg(target_os = "linux")]
    {
        let Some(host_fd) = host_fd_for_guest(fd as u64) else {
            return Ok(neg_errno(libc::EBADF));
        };

        Logger::debug(
            format!("sys_ioctl(fd={fd}, request={request:#x}, arg={arg:#x})"),
            vk.cfg.verbose,
        );

        let int_requests = [
            libc::FIONBIO as libc::c_ulong,
            libc::FIONREAD as libc::c_ulong,
            libc::TIOCINQ as libc::c_ulong,
            libc::TIOCOUTQ as libc::c_ulong,
        ];
        if int_requests.contains(&request) {
            if arg == 0 {
                return Ok(neg_errno(libc::EFAULT));
            }

            let mut value = if request == libc::FIONBIO as libc::c_ulong {
                let bytes = vk.mem.read(&mut vk.uc, arg, mem::size_of::<c_int>())?;
                c_int::from_le_bytes(bytes.try_into().expect("c_int is 4 bytes"))
            } else {
                0
            };

            let ret = unsafe { libc::ioctl(host_fd, request, &mut value) };
            if ret == -1 {
                return Ok(last_errno());
            }

            vk.mem.write(&mut vk.uc, arg, &value.to_le_bytes())?;
            return Ok(ret as u64);
        }

        if request == libc::TIOCGWINSZ as libc::c_ulong {
            if arg == 0 {
                return Ok(neg_errno(libc::EFAULT));
            }

            let mut winsize: libc::winsize = unsafe { mem::zeroed() };
            let ret = unsafe { libc::ioctl(host_fd, request, &mut winsize) };
            if ret == -1 {
                return Ok(last_errno());
            }

            let winsize_bytes = unsafe {
                std::slice::from_raw_parts(
                    (&winsize as *const libc::winsize).cast::<u8>(),
                    mem::size_of::<libc::winsize>(),
                )
            };
            vk.mem.write(&mut vk.uc, arg, winsize_bytes)?;
            return Ok(ret as u64);
        }

        let size = ioctl_request_size(request);
        if size == 0 {
            let ret = unsafe { libc::ioctl(host_fd, request, arg as libc::c_ulong) };
            if ret == -1 {
                return Ok(last_errno());
            }
            return Ok(ret as u64);
        }

        if arg == 0 {
            return Ok(neg_errno(libc::EFAULT));
        }

        let direction = ioctl_request_dir(request);
        let mut buffer = vec![0u8; size];
        if (direction & IOC_WRITE) != 0 {
            buffer = vk.mem.read(&mut vk.uc, arg, size)?;
        }

        let ret =
            unsafe { libc::ioctl(host_fd, request, buffer.as_mut_ptr().cast::<libc::c_void>()) };
        if ret == -1 {
            return Ok(last_errno());
        }

        if (direction & IOC_READ) != 0 {
            vk.mem.write(&mut vk.uc, arg, &buffer)?;
        }

        Ok(ret as u64)
    }
}

fn sys_path_getxattr(vk: &mut Valkyrie, sctx: &mut SubCtx, follow_symlinks: bool) -> Result<u64> {
    let path_ptr = sctx.arg0();
    let name_ptr = sctx.arg1();
    let value_ptr = sctx.arg2();
    let size = sctx.arg3() as usize;

    let path = read_guest_cstring(vk, path_ptr)?;
    let name = read_guest_cstring(vk, name_ptr)?;
    let host_path = match guest_path_at(vk, AT_FDCWD, &path) {
        Ok(path) => path,
        Err(_) => return Ok(neg_errno(libc::EBADF)),
    };

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (host_path, name, value_ptr, size, follow_symlinks);
        Logger::warning("getxattr not supported on this platform. syscall will return -1;");
        return Ok(neg_errno(libc::ENOSYS));
    }

    #[cfg(target_os = "linux")]
    {
        let c_path = match CString::new(host_path.to_string_lossy().as_bytes()) {
            Ok(path) => path,
            Err(_) => return Ok(neg_errno(libc::EINVAL)),
        };
        let c_name = match CString::new(name.as_bytes()) {
            Ok(name) => name,
            Err(_) => return Ok(neg_errno(libc::EINVAL)),
        };

        let syscall_name = if follow_symlinks {
            "sys_getxattr"
        } else {
            "sys_lgetxattr"
        };
        Logger::debug(
            format!("{syscall_name}(path={}, name={name})", host_path.display()),
            vk.cfg.verbose,
        );

        let mut buffer = vec![0u8; size];
        let ret = unsafe {
            if follow_symlinks {
                libc::getxattr(
                    c_path.as_ptr(),
                    c_name.as_ptr(),
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    size,
                )
            } else {
                libc::lgetxattr(
                    c_path.as_ptr(),
                    c_name.as_ptr(),
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    size,
                )
            }
        };

        if ret < 0 {
            return Ok(last_errno());
        }

        let ret = ret as usize;
        if value_ptr != 0 && ret > 0 {
            vk.mem.write(&mut vk.uc, value_ptr, &buffer[..ret])?;
        }

        Ok(ret as u64)
    }
}

pub fn sys_getxattr(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    sys_path_getxattr(vk, sctx, true)
}

pub fn sys_lgetxattr(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    sys_path_getxattr(vk, sctx, false)
}

pub fn sys_fgetxattr(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0() as c_int;
    let name_ptr = sctx.arg1();
    let value_ptr = sctx.arg2();
    let size = sctx.arg3() as usize;

    let name = read_guest_cstring(vk, name_ptr)?;

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, name, value_ptr, size);
        Logger::warning("fgetxattr not supported on this platform. syscall will return -1;");
        return Ok(neg_errno(libc::ENOSYS));
    }

    #[cfg(target_os = "linux")]
    {
        let c_name = match CString::new(name.as_bytes()) {
            Ok(name) => name,
            Err(_) => return Ok(neg_errno(libc::EINVAL)),
        };

        Logger::debug(
            format!("sys_fgetxattr(fd={fd}, name={name})"),
            vk.cfg.verbose,
        );

        let mut buffer = vec![0u8; size];
        let ret = unsafe {
            libc::fgetxattr(
                fd,
                c_name.as_ptr(),
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                size,
            )
        };
        if ret < 0 {
            return Ok(last_errno());
        }

        let ret = ret as usize;
        if value_ptr != 0 && ret > 0 {
            vk.mem.write(&mut vk.uc, value_ptr, &buffer[..ret])?;
        }

        Ok(ret as u64)
    }
}

pub fn sys_socket(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let domain = sctx.arg0() as c_int;
    let socket_type = sctx.arg1() as c_int;
    let protocol = sctx.arg2() as c_int;

    Logger::debug(
        format!("sys_socket(domain={domain}, type={socket_type:#x}, protocol={protocol})"),
        vk.cfg.verbose,
    );

    let fd = unsafe { libc::socket(domain, socket_type, protocol) };
    if fd < 0 {
        return Ok(last_errno());
    }

    Ok(fd as u64)
}

pub fn sys_connect(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0() as c_int;
    let addr_ptr = sctx.arg1();
    let addr_len = sctx.arg2() as libc::socklen_t;

    if addr_ptr == 0 {
        return Ok(neg_errno(libc::EFAULT));
    }

    let addr = vk.mem.read(&mut vk.uc, addr_ptr, addr_len as usize)?;

    Logger::debug(
        format!("sys_connect(fd={fd}, addr_ptr={addr_ptr:#x}, addr_len={addr_len})"),
        vk.cfg.verbose,
    );

    let ret = unsafe { libc::connect(fd, addr.as_ptr().cast::<libc::sockaddr>(), addr_len) };
    if ret < 0 {
        return Ok(last_errno());
    }

    Ok(ret as u64)
}

pub fn sys_sendto(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0() as c_int;
    let buf_addr = sctx.arg1();
    let len = sctx.arg2() as usize;
    let flags = sctx.arg3() as c_int;
    let dest_addr = sctx.arg4();
    let addr_len = sctx.arg5() as libc::socklen_t;

    let buffer = vk.mem.read(&mut vk.uc, buf_addr, len)?;
    let dest = if dest_addr == 0 || addr_len == 0 {
        None
    } else {
        Some(vk.mem.read(&mut vk.uc, dest_addr, addr_len as usize)?)
    };

    Logger::debug(
        format!("sys_sendto(fd={fd}, len={len}, flags={flags:#x})"),
        vk.cfg.verbose,
    );

    let (addr_ptr, addr_len) = match dest.as_ref() {
        Some(addr) => (addr.as_ptr().cast::<libc::sockaddr>(), addr_len),
        None => (std::ptr::null(), 0),
    };

    let ret = unsafe {
        libc::sendto(
            fd,
            buffer.as_ptr().cast::<libc::c_void>(),
            len,
            flags,
            addr_ptr,
            addr_len,
        )
    };
    if ret < 0 {
        return Ok(last_errno());
    }

    Ok(ret as u64)
}

pub fn sys_renameat(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let flags = 0;
    let mut subctx = SubCtx::new([sctx.arg0(), sctx.arg1(), sctx.arg2(), sctx.arg3(), flags, 0]);
    sys_renameat2(vk, &mut subctx)
}

pub fn sys_renameat2(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let old_dfd = sctx.arg0() as i64 as i32;
    let old_name_addr = sctx.arg1();
    let new_dfd = sctx.arg2() as i64 as i32;
    let new_name_addr = sctx.arg3();
    let flags = sctx.arg4() as u32;

    let old_name = read_guest_cstring(vk, old_name_addr)?;
    let new_name = read_guest_cstring(vk, new_name_addr)?;

    let old_abs = match get_path_at(vk, old_dfd, &old_name) {
        Some(p) => p,
        None => return Ok(neg_errno(libc::EBADF)),
    };
    let new_abs = match get_path_at(vk, new_dfd, &new_name) {
        Some(p) => p,
        None => return Ok(neg_errno(libc::EBADF)),
    };

    let old_c = match CString::new(old_abs.to_string_lossy().as_bytes()) {
        Ok(s) => s,
        Err(_) => return Ok(neg_errno(libc::EINVAL)),
    };
    let new_c = match CString::new(new_abs.to_string_lossy().as_bytes()) {
        Ok(s) => s,
        Err(_) => return Ok(neg_errno(libc::EINVAL)),
    };

    Logger::debug(
        format!(
            "sys_renameat2({}, {})",
            old_abs.display(),
            new_abs.display(),
        ),
        vk.cfg.verbose,
    );

    let mut _ret = -1_i64;
    // int renameat2(int olddirfd, const char *oldpath,
    //              int newdirfd, const char *newpath, unsigned int flags);

    #[cfg(target_os = "linux")]
    {
        _ret = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                old_c.as_ptr() as *const c_char,
                libc::AT_FDCWD,
                new_c.as_ptr() as *const c_char,
                flags as libc::c_uint,
            )
            .into()
        };
    }

    #[cfg(not(target_os = "linux"))]
    {
        if flags == 0 {
            Logger::warning("renameat2 not available on this platform. Using rename() as flags==0");
            _ret = unsafe {
                libc::rename(
                    old_c.as_ptr() as *const c_char,
                    new_c.as_ptr() as *const c_char,
                )
                .into()
            };
        } else {
            Logger::error("renameat2 with flags not supported on this platform");
        }
    }

    if _ret == -1 {
        Ok(last_errno())
    } else {
        Ok(_ret as u64)
    }
}

pub fn sys_statx(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let dfd = sctx.arg0() as i64 as i32;
    let file_name_addr = sctx.arg1();
    let flags = sctx.arg2() as u32;
    let mask = sctx.arg3() as u32;
    let statx_buf_addr = sctx.arg4();

    let file_name = read_guest_cstring(vk, file_name_addr)?;
    let mut st: Statx = Statx::default();

    // int statx(int dirfd, const char *pathname, int flags,
    //           unsigned int mask, struct statx *statxbuf);
    let mut _ret = -1_i64;

    #[cfg(target_os = "linux")]
    {
        if file_name.is_empty() && (flags as i32 & libc::AT_EMPTY_PATH) != 0 {
            let empty_path = b"\0";
            Logger::debug(
                format!("sys_statx(dirfd={dfd}, path=\"\", flags={flags:#x})"),
                vk.cfg.verbose,
            );
            _ret = unsafe {
                libc::syscall(
                    libc::SYS_statx as libc::c_long,
                    dfd,
                    empty_path.as_ptr() as *const c_char,
                    flags as c_int,
                    mask as libc::c_uint,
                    &mut st as *mut Statx,
                )
            };
        } else {
            let abs_path: PathBuf = match get_path_at(vk, dfd, &file_name) {
                Some(p) => p,
                None => return Ok(neg_errno(libc::EBADF)),
            };

            let c_path = match CString::new(abs_path.to_string_lossy().as_bytes()) {
                Ok(s) => s,
                Err(_) => return Ok(neg_errno(libc::EINVAL)),
            };

            Logger::debug(format!("sys_statx({})", abs_path.display()), vk.cfg.verbose);
            _ret = unsafe {
                libc::syscall(
                    libc::SYS_statx as libc::c_long,
                    libc::AT_FDCWD,
                    c_path.as_ptr() as *const c_char,
                    flags as c_int,
                    mask as libc::c_uint,
                    &mut st as *mut Statx,
                )
            };
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Logger::warning("statx not supported on this platform. syscall will return -1;");
    }

    if _ret == -1 {
        return Ok(last_errno());
    }

    let bytes = pack_statx_le(&st);
    vk.mem.write(&mut vk.uc, statx_buf_addr, &bytes)?;

    Ok(0)
}

pub fn sys_readlink(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let path_ptr = sctx.arg0();
    let buf_addr = sctx.arg1();
    let buf_size = sctx.arg2() as usize;

    if buf_size == 0 {
        return Ok(0);
    }

    let path = read_guest_cstring(vk, path_ptr)?;

    if path == "/proc/self/exe" {
        let target = vk
            .cfg
            .elf_file
            .as_deref()
            .unwrap_or("/proc/self/exe")
            .as_bytes()
            .to_vec();
        let count = target.len().min(buf_size);
        Logger::debug("sys_readlink(/proc/self/exe)", vk.cfg.verbose);
        vk.mem.write(&mut vk.uc, buf_addr, &target[..count])?;
        return Ok(count as u64);
    }

    let host_path = match guest_path_at(vk, AT_FDCWD, &path) {
        Ok(path) => path,
        Err(_) => return Ok(neg_errno(libc::EBADF)),
    };

    Logger::debug(
        format!("sys_readlink({})", host_path.display()),
        vk.cfg.verbose,
    );

    let target = match std::fs::read_link(&host_path) {
        Ok(p) => p,
        Err(_) => return Ok(last_errno()),
    };

    let target_bytes = target.to_string_lossy();
    let bytes = target_bytes.as_bytes();
    let count = bytes.len().min(buf_size);
    vk.mem.write(&mut vk.uc, buf_addr, &bytes[..count])?;
    Ok(count as u64)
}

pub fn sys_statfs(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let path_ptr = sctx.arg0();
    let statfs_buf_ptr = sctx.arg1();

    let path = read_guest_cstring(vk, path_ptr)?;

    #[cfg(not(target_os = "linux"))]
    {
        Logger::warning("statfs not supported on this platform. syscall will return -1;");
        return Ok(neg_errno(libc::ENOSYS));
    }

    #[cfg(target_os = "linux")]
    {
        let st = match statfs_for_path(vk, &path) {
            Ok(st) => st,
            Err(_) => return Ok(last_errno()),
        };

        let bytes = match vk.cfg.arch {
            crate::vtype::Arch::X86_64 => unsafe {
                std::slice::from_raw_parts(
                    (&st as *const libc::statfs64).cast::<u8>(),
                    mem::size_of::<libc::statfs64>(),
                )
                .to_vec()
            },
            crate::vtype::Arch::X86 => pack_linux_x86_statfs_le(&st),
        };

        vk.mem.write(&mut vk.uc, statfs_buf_ptr, &bytes)?;
        Ok(0)
    }
}

pub fn sys_statfs64(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let path_ptr = sctx.arg0();
    let buf_size = sctx.arg1() as usize;
    let statfs_buf_ptr = sctx.arg2();

    let path = read_guest_cstring(vk, path_ptr)?;

    #[cfg(not(target_os = "linux"))]
    {
        Logger::warning("statfs64 not supported on this platform. syscall will return -1;");
        return Ok(neg_errno(libc::ENOSYS));
    }

    #[cfg(target_os = "linux")]
    {
        let st = match statfs_for_path(vk, &path) {
            Ok(st) => st,
            Err(_) => return Ok(last_errno()),
        };

        let bytes = match vk.cfg.arch {
            crate::vtype::Arch::X86_64 => unsafe {
                std::slice::from_raw_parts(
                    (&st as *const libc::statfs64).cast::<u8>(),
                    mem::size_of::<libc::statfs64>(),
                )
                .to_vec()
            },
            crate::vtype::Arch::X86 => pack_linux_x86_statfs64_le(&st),
        };

        if buf_size < bytes.len() {
            return Ok(neg_errno(libc::EINVAL));
        }

        vk.mem.write(&mut vk.uc, statfs_buf_ptr, &bytes)?;
        Ok(0)
    }
}

pub fn sys_getdents64(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0() as i32;
    let dirp = sctx.arg1();
    let count = sctx.arg2() as usize;

    if count == 0 {
        return Ok(0);
    }

    #[cfg(not(target_os = "linux"))]
    {
        Logger::warning("getdents64 not supported on this platform. syscall will return -1;");
        return Ok(neg_errno(libc::ENOSYS));
    }

    #[cfg(target_os = "linux")]
    {
        if fd < 0 {
            return Ok(neg_errno(libc::EBADF));
        }

        let Some(host_fd) = host_fd_for_guest(fd as u64) else {
            return Ok(neg_errno(libc::EBADF));
        };

        Logger::debug(
            format!("sys_getdents64(fd={fd}, count={count})"),
            vk.cfg.verbose,
        );

        let mut buffer = vec![0u8; count];
        let ret = unsafe {
            libc::syscall(
                libc::SYS_getdents64 as libc::c_long,
                host_fd,
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                count,
            )
        };
        if ret < 0 {
            return Ok(last_errno());
        }

        let bytes_read = ret as usize;
        if bytes_read == 0 {
            return Ok(0);
        }

        vk.mem.write(&mut vk.uc, dirp, &buffer[..bytes_read])?;
        Ok(bytes_read as u64)
    }
}

// TODO : implement virtual proc mapper /sys with rootfs

#[cfg(target_os = "linux")]
fn stat_at(vk: &Valkyrie, dirfd: c_int, file_name: &str, flags: u32) -> Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ret = if file_name.is_empty() && (flags as i32 & libc::AT_EMPTY_PATH) != 0 {
        let empty_path = b"\0";
        Logger::debug(
            format!("sys_newfstatat(dirfd={dirfd}, path=\"\", flags={flags:#x})"),
            vk.cfg.verbose,
        );

        unsafe {
            libc::fstatat(
                dirfd,
                empty_path.as_ptr().cast::<c_char>(),
                &mut st as *mut libc::stat,
                flags as c_int,
            )
        }
    } else {
        let abs_path: PathBuf = match get_path_at(vk, dirfd, file_name) {
            Some(p) => p,
            None => {
                return Err(crate::error::ValkyrieError::Io(
                    io::Error::from_raw_os_error(libc::EBADF),
                ));
            }
        };

        let c_path = match CString::new(abs_path.to_string_lossy().as_bytes()) {
            Ok(s) => s,
            Err(_) => {
                return Err(crate::error::ValkyrieError::Io(
                    io::Error::from_raw_os_error(libc::EINVAL),
                ));
            }
        };

        Logger::debug(
            format!("sys_newfstatat({}, flags={flags:#x})", abs_path.display()),
            vk.cfg.verbose,
        );

        unsafe {
            libc::fstatat(
                libc::AT_FDCWD,
                c_path.as_ptr() as *const c_char,
                &mut st as *mut libc::stat,
                flags as c_int,
            )
        }
    };

    if ret == -1 {
        return Err(crate::error::ValkyrieError::Io(
            std::io::Error::last_os_error(),
        ));
    }

    Ok(st)
}

#[cfg(target_os = "linux")]
fn pack_linux_x86_stat64_le(st: &libc::stat) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(&st.st_dev.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&(st.st_ino as u32).to_le_bytes());
    bytes.extend_from_slice(&st.st_mode.to_le_bytes());
    bytes.extend_from_slice(&(st.st_nlink as u32).to_le_bytes());
    bytes.extend_from_slice(&st.st_uid.to_le_bytes());
    bytes.extend_from_slice(&st.st_gid.to_le_bytes());
    bytes.extend_from_slice(&st.st_rdev.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&st.st_size.to_le_bytes());
    bytes.extend_from_slice(&(st.st_blksize as u32).to_le_bytes());
    bytes.extend_from_slice(&(st.st_blocks as u64).to_le_bytes());
    bytes.extend_from_slice(&(st.st_atime as u32).to_le_bytes());
    bytes.extend_from_slice(&(st.st_atime_nsec as u32).to_le_bytes());
    bytes.extend_from_slice(&(st.st_mtime as u32).to_le_bytes());
    bytes.extend_from_slice(&(st.st_mtime_nsec as u32).to_le_bytes());
    bytes.extend_from_slice(&(st.st_ctime as u32).to_le_bytes());
    bytes.extend_from_slice(&(st.st_ctime_nsec as u32).to_le_bytes());
    bytes.extend_from_slice(&st.st_ino.to_le_bytes());
    bytes
}

pub fn sys_newfstatat(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let dirfd = sctx.arg0() as i64 as i32;
    let pathname_ptr = sctx.arg1();
    let statbuf_ptr = sctx.arg2();
    let flags = sctx.arg3() as u32;

    let file_name = read_guest_cstring(vk, pathname_ptr)?;

    #[cfg(not(target_os = "linux"))]
    {
        Logger::warning("newfstatat not supported on this platform. syscall will return -1;");
        return Ok(last_errno());
    }

    #[cfg(target_os = "linux")]
    {
        let st = match stat_at(vk, dirfd, &file_name, flags) {
            Ok(st) => st,
            Err(_) => return Ok(last_errno()),
        };

        let st_len = mem::size_of::<libc::stat>();
        let st_bytes =
            unsafe { std::slice::from_raw_parts((&st as *const libc::stat).cast::<u8>(), st_len) };
        vk.mem.write(&mut vk.uc, statbuf_ptr, st_bytes)?;

        Ok(0)
    }
}

pub fn sys_fstatat64(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let dirfd = sctx.arg0() as i64 as i32;
    let pathname_ptr = sctx.arg1();
    let statbuf_ptr = sctx.arg2();
    let flags = sctx.arg3() as u32;

    let file_name = read_guest_cstring(vk, pathname_ptr)?;

    #[cfg(not(target_os = "linux"))]
    {
        Logger::warning("fstatat64 not supported on this platform. syscall will return -1;");
        return Ok(last_errno());
    }

    #[cfg(target_os = "linux")]
    {
        let st = match stat_at(vk, dirfd, &file_name, flags) {
            Ok(st) => st,
            Err(_) => return Ok(last_errno()),
        };

        let st_bytes = pack_linux_x86_stat64_le(&st);
        vk.mem.write(&mut vk.uc, statbuf_ptr, &st_bytes)?;
        Ok(0)
    }
}
