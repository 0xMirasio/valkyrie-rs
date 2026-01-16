use crate::vtype::PAGE_SIZE;
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
