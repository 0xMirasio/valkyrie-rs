use crate::Valkyrie;
use crate::vtype::*;
use crate::{Result, ValkyrieError};

use unicorn_engine::Unicorn;

pub fn align_down(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    value & !(align - 1)
}

pub fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

pub fn zero_fill<D>(uc: &mut Unicorn<'_, D>, mut addr: u64, mut size: u64) -> Result<()> {
    if size == 0 {
        return Ok(());
    }

    let chunk = [0u8; PAGE_SIZE as usize];
    while size > 0 {
        let write_size = size.min(chunk.len() as u64) as usize;
        uc.mem_write(addr, &chunk[..write_size])
            .map_err(|_| ValkyrieError::UnicornGeneralError("mem_write failed"))?;
        addr = addr.saturating_add(write_size as u64);
        size = size.saturating_sub(write_size as u64);
    }
    Ok(())
}

pub fn write_word(vk: &mut Valkyrie, addr: u64, value: u64, width: usize) -> Result<()> {
    let bytes = value.to_le_bytes();
    vk.mem.write(&mut vk.uc, addr, &bytes[..width])
}

pub fn read_word(vk: &mut Valkyrie, addr: u64, width: usize) -> Result<u64> {
    let bytes = vk.mem.read(&mut vk.uc, addr, width)?;
    let mut buf = [0u8; 8];
    buf[..width].copy_from_slice(&bytes);
    Ok(u64::from_le_bytes(buf))
}

pub fn neg_errno(e: i32) -> u64 {
    (-(e as i64)) as u64
}

pub fn last_errno() -> u64 {
    let e = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO);
    neg_errno(e)
}
