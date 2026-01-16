use crate::Valkyrie;
use crate::common::{last_errno, neg_errno};
use crate::error::Result;
use crate::fs::*;
use crate::logger::Logger;
use crate::os::register_syscall::SubCtx;

use libc::{c_char, c_int};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::io::FromRawFd;
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
            None => return Ok(neg_errno(libc::EBADF)),
        }
    };

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

    #[allow(unused_assignments)]
    let mut file: Option<File> = None;
    #[cfg(target_os = "linux")]
    {
        file = Some(unsafe { FromRawFd::from_raw_fd(fd) });
    }

    if file.is_none() {
        unsafe { libc::close(fd) };
        return Ok((-(libc::EINVAL as i64)) as u64);
    }

    {
        let mut table = fd_table().lock().unwrap();

        table.files.insert(
            fd as u64,
            VkFile {
                file: file.unwrap(),
                path: host_path,
                flags: flags as u64,
                mode: mode as u64,
            },
        );
    }

    Ok(fd as u64)
}

pub fn sys_openat(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let dirfd = sctx.arg0() as i64 as i32;
    let path_ptr = sctx.arg1();
    let flags = sctx.arg2() as i32;
    let mode = sctx.arg3() as u32;

    let path = read_guest_cstring(vk, path_ptr)?;
    let host_path = resolve_guest_path(vk, &path);

    let c_path = match CString::new(host_path.to_string_lossy().as_bytes()) {
        Ok(s) => s,
        Err(_) => return Ok(neg_errno(libc::EINVAL)),
    };

    let fd: c_int = unsafe { open_at(dirfd, c_path.as_ptr() as *const c_char, flags, mode) };
    if fd == -1 {
        return Ok(last_errno());
    }

    #[allow(unused_assignments)]
    let mut file: Option<File> = None;

    #[cfg(target_os = "linux")]
    {
        file = Some(unsafe { std::fs::File::from_raw_fd(fd) });
    }

    if file.is_none() {
        unsafe { libc::close(fd) };
        return Ok(neg_errno(libc::EINVAL));
    }

    let mut table = fd_table().lock().unwrap();
    table.files.insert(
        fd as u64,
        VkFile {
            file: file.unwrap(),
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
                None => return Ok(neg_errno(libc::EBADF)),
            }
        }
    };

    Ok(bytes_written as u64)
}

pub fn sys_close(_vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0();

    if fd <= 2 {
        return Ok(0);
    }

    let mut table = fd_table().lock().unwrap();
    if table.files.remove(&fd).is_some() {
        Ok(0)
    } else {
        Ok(neg_errno(libc::EBADF))
    }
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

    #[allow(unused_assignments)]
    let mut ret = -1_i64;
    // int renameat2(int olddirfd, const char *oldpath,
    //              int newdirfd, const char *newpath, unsigned int flags);

    #[cfg(target_os = "linux")]
    {
        ret = unsafe {
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
            ret = unsafe {
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

    if ret == -1 {
        Ok(last_errno())
    } else {
        Ok(ret as u64)
    }
}

pub fn sys_statx(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let dfd = sctx.arg0() as i64 as i32;
    let file_name_addr = sctx.arg1();
    let flags = sctx.arg2() as u32;
    let mask = sctx.arg3() as u32;
    let statx_buf_addr = sctx.arg4();

    let file_name = read_guest_cstring(vk, file_name_addr)?;
    let abs_path: PathBuf = match get_path_at(vk, dfd, &file_name) {
        Some(p) => p,
        None => return Ok(neg_errno(libc::EBADF)),
    };

    let c_path = match CString::new(abs_path.to_string_lossy().as_bytes()) {
        Ok(s) => s,
        Err(_) => return Ok(neg_errno(libc::EINVAL)),
    };

    let mut st: Statx = Statx::default();

    // int statx(int dirfd, const char *pathname, int flags,
    //           unsigned int mask, struct statx *statxbuf);
    #[allow(unused_assignments)]
    let mut ret = -1_i64;

    #[cfg(target_os = "linux")]
    {
        ret = unsafe {
            libc::syscall(
                libc::SYS_statx as libc::c_long,
                0 as c_int,
                c_path.as_ptr() as *const c_char,
                flags as c_int,
                mask as libc::c_uint,
                &mut st as *mut Statx,
            )
        };
    }
    #[cfg(not(target_os = "linux"))]
    {
        Logger::warning("statx not supported on this platform. syscall will return -1;");
    }

    if ret == -1 {
        return Ok(last_errno());
    }

    let bytes = pack_statx_le(&st);
    vk.mem.write(&mut vk.uc, statx_buf_addr, &bytes)?;

    Ok(0)
}
