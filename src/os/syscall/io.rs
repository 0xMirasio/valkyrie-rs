use crate::Valkyrie;
use crate::error::Result;
use crate::logger::Logger;
use crate::os::register_syscall::SubCtx;
use crate::vtype::*;

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::sync::{Mutex, OnceLock};

use crate::util::{read_guest_cstring, resolve_guest_path};

#[derive(Debug)]
struct FdTable {
    next_fd: u64,
    files: HashMap<u64, std::fs::File>,
}

impl Default for FdTable {
    fn default() -> Self {
        Self {
            next_fd: 3,
            files: HashMap::new(),
        }
    }
}

static FD_TABLE: OnceLock<Mutex<FdTable>> = OnceLock::new();

fn fd_table() -> &'static Mutex<FdTable> {
    FD_TABLE.get_or_init(|| Mutex::new(FdTable::default()))
}

pub fn sys_read(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0();
    let buf_addr = sctx.arg1();
    let count = sctx.arg2() as usize;

    if count == 0 {
        return Ok(0);
    }

    let mut buffer = vec![0u8; count];
    let bytes_read = if fd == 0 {
        io::stdin().read(&mut buffer).unwrap_or(0)
    } else {
        let mut table = fd_table().lock().unwrap();
        match table.files.get_mut(&fd) {
            Some(file) => file.read(&mut buffer).unwrap_or(0),
            None => {
                Logger::warning(format!("sys_read: invalid fd={fd}"));
                return Ok(u64::MAX);
            }
        }
    };

    if bytes_read > 0 {
        vk.mem.write(&mut vk.uc, buf_addr, &buffer[..bytes_read])?;
    }

    Ok(bytes_read as u64)
}

pub fn sys_open(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let path_ptr = sctx.arg0();
    let flags = sctx.arg1();

    let path = read_guest_cstring(vk, path_ptr)?;
    let host_path = resolve_guest_path(vk, &path);

    let mut options = OpenOptions::new();
    let read = flags & O_RDWR != 0 || flags & O_WRONLY == 0;
    let write = flags & (O_WRONLY | O_RDWR) != 0;

    options.read(read).write(write);

    if flags & O_CREAT != 0 {
        options.create(true);
    }
    if flags & O_TRUNC != 0 {
        options.truncate(true);
    }
    if flags & O_APPEND != 0 {
        options.append(true);
    }

    match options.open(&host_path) {
        Ok(file) => {
            let mut table = fd_table().lock().unwrap();
            let fd = table.next_fd;
            table.next_fd += 1;
            table.files.insert(fd, file);
            Ok(fd)
        }
        Err(err) => {
            Logger::warning(format!(
                "sys_open: failed to open {host_path:?} (guest path: {path:?}): {err}",
            ));
            Ok(u64::MAX)
        }
    }
}

//Todo : write good impl
pub fn sys_openat(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    // openat(int dirfd, const char *pathname, int flags, mode_t mode)
    let _dirfd = sctx.arg0() as i64 as i32;
    let path_ptr = sctx.arg1();
    let flags = sctx.arg2();
    let _mode = sctx.arg3();

    // Read pathname from emulated memory
    let path = read_guest_cstring(vk, path_ptr)?;
    let host_path = resolve_guest_path(vk, &path);

    let mut options = OpenOptions::new();
    let read = flags & O_RDWR != 0 || flags & O_WRONLY == 0;
    let write = flags & (O_WRONLY | O_RDWR) != 0;

    options.read(read).write(write);

    if flags & O_CREAT != 0 {
        options.create(true);
    }
    if flags & O_TRUNC != 0 {
        options.truncate(true);
    }
    if flags & O_APPEND != 0 {
        options.append(true);
    }

    match options.open(&host_path) {
        Ok(file) => {
            let mut table = fd_table().lock().unwrap();
            let fd = table.next_fd;
            table.next_fd += 1;
            table.files.insert(fd, file);
            return Ok(fd);
        }
        Err(err) => {
            Logger::warning(format!(
                "sys_openat: failed to open {host_path:?} (guest path: {path:?}): {err}",
            ));
            return Ok(u64::MAX);
        }
    }
}

pub fn sys_write(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let fd = sctx.arg0();
    let buf_addr = sctx.arg1();
    let count = sctx.arg2() as usize;

    if count == 0 {
        return Ok(0);
    }

    let buffer = vk.mem.read(&mut vk.uc, buf_addr, count)?;
    let bytes_written = match fd {
        1 => io::stdout().write_all(&buffer).map(|_| count).unwrap_or(0),
        2 => io::stderr().write_all(&buffer).map(|_| count).unwrap_or(0),
        _ => {
            let mut table = fd_table().lock().unwrap();
            match table.files.get_mut(&fd) {
                Some(file) => file.write(&buffer).unwrap_or(0),
                None => {
                    Logger::warning(format!("sys_write: invalid fd={fd}"));
                    return Ok(u64::MAX);
                }
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
        Logger::warning(format!("sys_close: invalid fd={fd}"));
        Ok(u64::MAX)
    }
}
