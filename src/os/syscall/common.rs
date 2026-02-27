use crate::Valkyrie;
use crate::common::{last_errno, neg_errno, write_word};
use crate::error::Result;
use crate::logger::Logger;
use crate::os::register_syscall::SubCtx;
use crate::vtype::*;

use users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};

const RLIM_INFINITY: u64 = libc::RLIM_INFINITY;

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
    vk.vstate = VState::Ended;
    let _ = vk.uc.emu_stop();
    Ok(0_u64)
}

// todo : implement sys_exit_group when threading is supported
pub fn sys_exit_group(_vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
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

pub fn sys_clock_gettime(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let _clock_id = sctx.arg0() as libc::clockid_t;
    let tp = sctx.arg1();
    if tp == 0 {
        return Ok(neg_errno(libc::EFAULT));
    }

    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(_clock_id, &mut ts as *mut libc::timespec) };
    if rc != 0 {
        return Ok(last_errno());
    }

    let width = (vk.cfg.archsize / 8) as usize;
    write_word(vk, tp, ts.tv_sec as u64, width)?;
    write_word(vk, tp + width as u64, ts.tv_nsec as u64, width)?;

    Ok(0)
}

pub fn sys_getrandom(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let buf_addr = sctx.arg0();
    let count = sctx.arg1() as usize;
    let _flags = sctx.arg2() as u32;

    if count == 0 {
        return Ok(0);
    }

    let mut buffer = vec![0u8; count];
    #[cfg(target_os = "linux")]
    {
        let rc = unsafe { libc::getrandom(buffer.as_mut_ptr() as *mut _, count, _flags) };
        if rc < 0 {
            return Ok(last_errno());
        }
        vk.mem.write(&mut vk.uc, buf_addr, &buffer[..rc as usize])?;
        Ok(rc as u64)
    }

    #[cfg(not(target_os = "linux"))]
    {
        vk.mem.write(&mut vk.uc, buf_addr, &buffer)?;
        Ok(count as u64)
    }
}

// TODO : implement resource limits properly
pub fn sys_prlimit64(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let _pid = sctx.arg0();
    let _resource = sctx.arg1();
    let new_limit = sctx.arg2();
    let old_limit = sctx.arg3();

    let width = (vk.cfg.archsize / 8) as usize;
    if old_limit != 0 {
        write_word(vk, old_limit, RLIM_INFINITY, width)?;
        write_word(vk, old_limit + width as u64, RLIM_INFINITY, width)?;
    }

    if new_limit != 0 {
        return Ok(0);
    }

    Ok(0)
}

pub fn sys_getpid(_vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
    #[cfg(target_os = "linux")]
    {
        Ok(unsafe { libc::getpid() as u64 })
    }

    #[cfg(not(target_os = "linux"))]
    {
        Logger::warning("sys_getpid() unsupported on this os. Returning dummy pid=3000");
        Ok(3000) // return dummy pid
    }
}

pub fn sys_tgkill(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let tgid = sctx.arg0() as i64;
    let tid = sctx.arg1() as i64;
    let sig = sctx.arg2() as i32;

    #[cfg(target_os = "linux")]
    {
        let host_pid = unsafe { libc::getpid() as i64 };
        let host_tid = unsafe { libc::syscall(libc::SYS_gettid) as i64 };

        if tgid != host_pid || tid != host_tid {
            return Ok(neg_errno(libc::ESRCH));
        }

        // todo : handle sigsegv properly : save for fuzzing mode.
        if sig == libc::SIGSEGV {
            Logger::info(format!(
                "sys_tgkill() received signal SIGSEGV. Terminating emulation"
            ));
            vk.vstate = VState::Ended;
            let _ = vk.uc.emu_stop();
        }

        if sig == libc::SIGKILL || sig == libc::SIGSTOP {
            Logger::info(format!(
                "sys_tgkill() received signal SIGKILL/SIGSTOP. Terminating emulation"
            ));
            vk.vstate = VState::Ended;
            let _ = vk.uc.emu_stop();
        }

        return Ok(0);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (tgid, tid, sig);
        Logger::warning(
            "sys_tgkill() unsupported on this os. Ignoring signal and returning failure",
        );
        Ok(neg_errno(libc::ENOSYS))
    }
}
