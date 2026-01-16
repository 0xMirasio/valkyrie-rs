use crate::Valkyrie;
use crate::common::neg_errno;
use crate::error::Result;
use crate::logger::Logger;
use crate::os::register_syscall::SubCtx;
use crate::vtype::*;

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

#[cfg(target_os = "linux")]
fn host_uname() -> (String, String, String, String, String, String) {
    unsafe {
        let mut u: libc::utsname = core::mem::zeroed();
        if libc::uname(&mut u) == 0 {
            let c2s =
                |p: *const libc::c_char| std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned();
            (
                c2s(u.sysname.as_ptr()),
                c2s(u.nodename.as_ptr()),
                c2s(u.release.as_ptr()),
                c2s(u.version.as_ptr()),
                c2s(u.machine.as_ptr()),
                c2s(u.domainname.as_ptr()),
            )
        } else {
            fallback_uname()
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn host_uname() -> (String, String, String, String, String, String) {
    fallback_uname()
}

fn fallback_uname() -> (String, String, String, String, String, String) {
    Logger::error(
        "syscall::uname() unsupported on this os. Using generic uname struct. This maybe cause crash/unstability",
    );
    (
        "Linux".into(),
        "valkyrie".into(),
        "5.15.0".into(),
        "#1".into(),
        "x86_64".into(),
        "localdomain".into(),
    )
}

pub fn sys_uname(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    pub fn pack_field(s: &str) -> [u8; UTSNAME_LEN] {
        let mut out = [0u8; UTSNAME_LEN];
        let b = s.as_bytes();
        let n = b.len().min(UTSNAME_LEN - 1);
        out[..n].copy_from_slice(&b[..n]);
        out
    }

    let buf_addr = sctx.arg0();
    if buf_addr == 0 {
        return Ok(neg_errno(libc::EFAULT));
    }

    let (sysname, nodename, release, version, _machine_host, domainname) = host_uname();

    let machine = match vk.cfg.arch {
        Arch::X86 => "i686",
        Arch::X86_64 => "x86_64",
    };

    let fields = [
        pack_field(&sysname),
        pack_field(&nodename),
        pack_field(&release),
        pack_field(&version),
        pack_field(machine),
        pack_field(&domainname),
    ];

    for (i, f) in fields.iter().enumerate() {
        let addr = buf_addr + (i as u64) * (UTSNAME_LEN as u64);
        if vk.mem.write(&mut vk.uc, addr, f).is_err() {
            return Ok(neg_errno(libc::EFAULT));
        }
    }

    Ok(0)
}
