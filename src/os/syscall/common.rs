use crate::Valkyrie;
use crate::arch::regs::VRegister;
use crate::arch::x86_64::RegX86_64;
use crate::common::align_up;
use crate::error::Result;
use crate::logger::Logger;
use crate::os::register_syscall::SubCtx;
use crate::vtype::*;

use libc::EINVAL;
use unicorn_engine::unicorn_const::Prot;
use users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};

#[derive(Debug, Clone, Copy)]
pub struct LinuxCreds {
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
}

impl LinuxCreds {
    pub fn from_host() -> Self {
        Self {
            uid: get_current_uid() as u32,
            euid: get_effective_uid() as u32,
            gid: get_current_gid() as u32,
            egid: get_effective_gid() as u32,
        }
    }
}

pub fn sys_exit(vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
    Logger::info("sys_exit() called. Terminating emulation");
    let _ = vk.uc.emu_stop();
    Ok(0_u64)
}

pub fn sys_geteuid(vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
    Ok(vk.linux_creds.euid as u64)
}

pub fn sys_getuid(vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
    Ok(vk.linux_creds.uid as u64)
}

pub fn sys_getegid(vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
    Ok(vk.linux_creds.egid as u64)
}

pub fn sys_getgid(vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
    Ok(vk.linux_creds.gid as u64)
}

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
        return Ok((-(EINVAL as i64)) as u64);
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
        _ => Ok((-(EINVAL as i64)) as u64),
    }
}
