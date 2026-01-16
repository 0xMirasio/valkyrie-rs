use crate::Valkyrie;
use crate::arch::regs::VRegister;
use crate::arch::x86_64::RegX86_64;
use crate::common::{align_up, neg_errno};
use crate::error::Result;
use crate::fs::fd_table;
use crate::os::register_syscall::SubCtx;
use crate::vtype::*;

use libc::EINVAL;
use std::io::{Read, Seek, SeekFrom};
use unicorn_engine::unicorn_const::Prot;

pub fn sys_brk(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let request = sctx.arg0();
    let current = vk.mem.heap_addr_exit;

    if request == 0 {
        return Ok(current);
    }

    let mapped_heap_end = vk
        .mem
        .regions
        .iter()
        .filter(|region| region.info == "[heap]")
        .map(|region| region.start + region.size)
        .max()
        .unwrap_or(vk.mem.heap_addr_exit);

    let heap_limit = vk
        .mem
        .regions
        .iter()
        .filter(|region| region.start > vk.mem.heap_addr_start)
        .map(|region| region.start)
        .min()
        .unwrap_or(u64::MAX);

    let new_break = align_up(request, PAGE_SIZE as u64);

    if new_break < vk.mem.heap_addr_start || new_break > heap_limit {
        return Ok(current);
    }

    if new_break > mapped_heap_end {
        let map_start = align_up(mapped_heap_end, PAGE_SIZE as u64);
        let map_size = new_break.saturating_sub(map_start);
        if map_size > 0 {
            vk.mem
                .map(&mut vk.uc, map_start, map_size, Prot::ALL, "[heap]")?;
        }
    }

    vk.mem.heap_addr_exit = new_break;
    Ok(new_break)
}

pub fn sys_arch_prctl(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let code = sctx.arg0();
    let addr = sctx.arg1();

    if vk.arch.arch != Arch::X86_64 {
        return Ok(neg_errno(EINVAL));
    }

    match code {
        ARCH_SET_FS => {
            vk.arch
                .regs
                .set_reg(&mut vk.uc, VRegister::X86_64(RegX86_64::FsBase), addr)?;
            Ok(0)
        }
        ARCH_SET_GS => {
            vk.arch
                .regs
                .set_reg(&mut vk.uc, VRegister::X86_64(RegX86_64::GsBase), addr)?;
            Ok(0)
        }
        ARCH_GET_FS => {
            let value = vk
                .arch
                .regs
                .get_reg(&mut vk.uc, VRegister::X86_64(RegX86_64::FsBase))?;
            vk.mem.write(&mut vk.uc, addr, &value.to_le_bytes())?;
            Ok(0)
        }
        ARCH_GET_GS => {
            let value = vk
                .arch
                .regs
                .get_reg(&mut vk.uc, VRegister::X86_64(RegX86_64::GsBase))?;
            vk.mem.write(&mut vk.uc, addr, &value.to_le_bytes())?;
            Ok(0)
        }
        _ => Ok(neg_errno(EINVAL)),
    }
}

fn prot_from_flags(prot: i32) -> Prot {
    let mut mapped = Prot::NONE;
    if (prot & libc::PROT_READ) != 0 {
        mapped |= Prot::READ;
    }
    if (prot & libc::PROT_WRITE) != 0 {
        mapped |= Prot::WRITE;
    }
    if (prot & libc::PROT_EXEC) != 0 {
        mapped |= Prot::EXEC;
    }
    mapped
}

fn next_mmap_addr(vk: &Valkyrie, len: u64) -> u64 {
    let max_end = vk
        .mem
        .regions
        .iter()
        .map(|region| region.start + region.size)
        .max()
        .unwrap_or(vk.mem.heap_addr_exit);
    let addr = align_up(max_end + PAGE_SIZE as u64, PAGE_SIZE as u64);
    align_up(addr + len, PAGE_SIZE as u64) - len
}

fn map_file_bytes(vk: &mut Valkyrie, addr: u64, size: u64, fd: u64, offset: u64) -> Result<u64> {
    if size == 0 {
        return Ok(0);
    }
    let mut table = fd_table().lock().unwrap();
    let vkf = match table.files.get_mut(&fd) {
        Some(file) => file,
        None => return Ok(neg_errno(libc::EBADF)),
    };

    let mut file = match vkf.file.try_clone() {
        Ok(file) => file,
        Err(_) => return Ok(neg_errno(libc::EIO)),
    };
    if file.seek(SeekFrom::Start(offset)).is_err() {
        return Ok(neg_errno(libc::EIO));
    }

    let mut buffer = vec![0u8; size as usize];
    if file.read(&mut buffer).is_err() {
        return Ok(neg_errno(libc::EIO));
    }
    vk.mem.write(&mut vk.uc, addr, &buffer)?;
    Ok(0)
}

pub fn sys_mmap(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let addr = sctx.arg0();
    let len = sctx.arg1();
    let prot = sctx.arg2() as i32;
    let flags = sctx.arg3() as i32;
    let fd = sctx.arg4() as i64;
    let offset = sctx.arg5();

    if len == 0 {
        return Ok(neg_errno(libc::EINVAL));
    }

    let page_size = PAGE_SIZE as u64;
    let map_len = align_up(len, page_size);

    if addr != 0 && addr % page_size != 0 {
        return Ok(neg_errno(libc::EINVAL));
    }

    let use_fixed = (flags & libc::MAP_FIXED) != 0;
    let map_addr = if addr == 0 || !use_fixed {
        next_mmap_addr(vk, map_len)
    } else {
        addr
    };

    let uc_prot = prot_from_flags(prot);
    if vk
        .mem
        .map(&mut vk.uc, map_addr, map_len, uc_prot, "[mmap]")
        .is_err()
    {
        return Ok(neg_errno(libc::ENOMEM));
    }

    let is_anon = (flags & libc::MAP_ANONYMOUS) != 0;
    if !is_anon && fd >= 0 {
        let fd = fd as u64;
        let result = map_file_bytes(vk, map_addr, map_len, fd, offset)?;
        if result != 0 {
            return Ok(result);
        }
    }

    Ok(map_addr)
}
