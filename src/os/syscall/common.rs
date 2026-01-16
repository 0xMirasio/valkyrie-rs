use crate::Valkyrie;
use crate::common::align_up;
use crate::error::Result;
use crate::logger::Logger;
use crate::os::register_syscall::SubCtx;

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

pub fn brk(_vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
    // TODO : implement brk properly
    Ok(0)
}

pub fn arch_prctl(_vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
    // TODO : implement arch_prctl properly
    Ok(0)
}
