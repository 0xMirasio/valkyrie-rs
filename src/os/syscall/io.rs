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

pub fn sys_open(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    // open(const char *pathname, int flags, mode_t mode)
    let path_ptr = sctx.arg0();
    let flags = sctx.arg1() as i32;
    let mode = sctx.arg2() as u32;

    let path = read_guest_cstring(vk, path_ptr)?;
    let host_path = resolve_guest_path(vk, &path);

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
    let host_path = resolve_guest_path(vk, &path);

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
    let host_path = resolve_guest_path(vk, &path);

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

    let host_path = resolve_guest_path(vk, &path);

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
