use crate::Valkyrie;
use crate::error::{Result, ValkyrieError};
use crate::vtype::MAX_PATH_LEN;

use crate::error::FsError;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub const AT_FDCWD: i32 = -100;

#[derive(Debug)]
pub struct VkFile {
    pub file: File,
    pub path: PathBuf,
    pub flags: u64,
    pub mode: u64,
}

#[derive(Debug)]
pub struct FdTable {
    pub next_fd: u64,
    pub files: HashMap<u64, VkFile>,
}

impl Default for FdTable {
    fn default() -> Self {
        Self {
            next_fd: 3,
            files: HashMap::new(),
        }
    }
}

pub static FD_TABLE: OnceLock<Mutex<FdTable>> = OnceLock::new();

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct StatxTimestamp {
    tv_sec: i64,
    tv_nsec: u32,
    __reserved: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Statx {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    __spare0: u16,
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: StatxTimestamp,
    stx_btime: StatxTimestamp,
    stx_ctime: StatxTimestamp,
    stx_mtime: StatxTimestamp,
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_mnt_id: u64,
    __spare2: [u64; 13],
}

pub fn push_u16_le(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
pub fn push_u32_le(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
pub fn push_u64_le(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
pub fn push_i64_le(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_le_bytes());
}
pub fn push_i32_le(out: &mut Vec<u8>, v: i32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn pack_statx_le(st: &Statx) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);

    push_u32_le(&mut out, st.stx_mask);
    push_u32_le(&mut out, st.stx_blksize);
    push_u64_le(&mut out, st.stx_attributes);
    push_u32_le(&mut out, st.stx_nlink);
    push_u32_le(&mut out, st.stx_uid);
    push_u32_le(&mut out, st.stx_gid);
    push_u16_le(&mut out, st.stx_mode);
    push_u16_le(&mut out, st.__spare0);
    push_u64_le(&mut out, st.stx_ino);
    push_u64_le(&mut out, st.stx_size);
    push_u64_le(&mut out, st.stx_blocks);
    push_u64_le(&mut out, st.stx_attributes_mask);

    for ts in [st.stx_atime, st.stx_btime, st.stx_ctime, st.stx_mtime] {
        push_i64_le(&mut out, ts.tv_sec);
        push_u32_le(&mut out, ts.tv_nsec);
        push_i32_le(&mut out, ts.__reserved);
    }

    push_u32_le(&mut out, st.stx_rdev_major);
    push_u32_le(&mut out, st.stx_rdev_minor);
    push_u32_le(&mut out, st.stx_dev_major);
    push_u32_le(&mut out, st.stx_dev_minor);
    push_u64_le(&mut out, st.stx_mnt_id);

    for x in st.__spare2 {
        push_u64_le(&mut out, x);
    }

    // sécurité: taille exacte attendue par l'UAPI
    debug_assert_eq!(out.len(), 256);
    out
}

pub fn fd_table() -> &'static Mutex<FdTable> {
    FD_TABLE.get_or_init(|| Mutex::new(FdTable::default()))
}

pub fn get_cwd_path(vk: &Valkyrie) -> Result<PathBuf> {
    let root = Path::new(&vk.cfg.rootfs);
    let cwd =
        std::env::current_dir().map_err(|_| ValkyrieError::FsError(FsError::CurrentDirError))?;
    if cwd.to_string_lossy().is_empty() || cwd == Path::new("/") {
        Ok(root.to_path_buf())
    } else {
        Ok(root.join(cwd.to_string_lossy().trim_start_matches('/')))
    }
}

pub fn get_path_at(vk: &Valkyrie, dirfd: i32, file_name: &str) -> Option<PathBuf> {
    let stripped = file_name.trim();

    if stripped.starts_with('/') {
        let mut abs = PathBuf::from(&vk.cfg.rootfs);
        abs.push(stripped.trim_start_matches('/'));
        return Some(abs);
    }

    let mut dir_path: PathBuf = if dirfd != AT_FDCWD {
        let table = fd_table().lock().ok()?;
        let df = table.files.get(&(dirfd as u64))?;
        df.path.clone()
    } else {
        get_cwd_path(vk).expect("Failed to get current working directory")
    };

    let rel = stripped.trim_start_matches('/');
    dir_path.push(rel);
    Some(dir_path)
}

pub fn read_guest_cstring(vk: &mut Valkyrie, addr: u64) -> Result<String> {
    let bytes = vk.mem.read(&mut vk.uc, addr, MAX_PATH_LEN)?;
    let nul_pos = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..nul_pos]).to_string())
}

pub fn resolve_guest_path(vk: &Valkyrie, path: &str) -> PathBuf {
    let root = Path::new(&vk.cfg.rootfs);
    if path.starts_with('/') {
        root.join(path.trim_start_matches('/'))
    } else {
        root.join(path)
    }
}

// TODO : check socket table
pub fn add_file_entry(target_fd: u64, file: VkFile, safe: bool) -> Result<()> {
    if safe && target_fd <= 2 {
        return Err(ValkyrieError::FsError(FsError::FileAlreadyHasFd(target_fd)));
    }

    let mut table = fd_table()
        .lock()
        .map_err(|_| ValkyrieError::FsError(FsError::PoisonedFdTable))?;

    if safe && table.files.contains_key(&target_fd) {
        return Err(ValkyrieError::FsError(FsError::FileAlreadyHasFd(target_fd)));
    }

    table.files.insert(target_fd, file);
    Ok(())
}

pub fn has_file_entry(target_fd: u64) -> bool {
    if target_fd <= 2 {
        return false;
    }
    fd_table()
        .lock()
        .map(|t| t.files.contains_key(&target_fd))
        .unwrap_or(false)
}

pub fn rm_file_entry(target_fd: u64) -> Result<()> {
    if target_fd <= 2 {
        return Err(ValkyrieError::FsError(FsError::NoFileAtFd(target_fd)));
    }

    let mut table = fd_table()
        .lock()
        .map_err(|_| ValkyrieError::FsError(FsError::PoisonedFdTable))?;

    if table.files.remove(&target_fd).is_none() {
        return Err(ValkyrieError::FsError(FsError::NoFileAtFd(target_fd)));
    }

    Ok(())
}
