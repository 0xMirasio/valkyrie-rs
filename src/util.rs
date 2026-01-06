use crate::Valkyrie;
use crate::error::Result;
use crate::vtype::MAX_PATH_LEN;

use std::path::{Path, PathBuf};

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
