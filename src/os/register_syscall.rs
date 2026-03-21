use crate::Valkyrie;
use crate::arch::x86::handle_x86_syscall;
use crate::arch::x86_64::handle_x86_64_syscall;
use crate::error::{Result, ValkyrieError};
use crate::logger::Logger;
use crate::os::syscall::{common::*, io::*, memory::*, thread::*};
use crate::vtype::*;

type SyscallHandler = fn(&mut Valkyrie, u64, u32) -> Result<()>;
pub struct SubCtx {
    args: [u64; 6],
}

impl SubCtx {
    pub fn new(args: [u64; 6]) -> Self {
        Self { args }
    }

    #[inline]
    pub fn arg0(&self) -> u64 {
        self.args[0]
    }
    #[inline]
    pub fn arg1(&self) -> u64 {
        self.args[1]
    }
    #[inline]
    pub fn arg2(&self) -> u64 {
        self.args[2]
    }
    #[inline]
    pub fn arg3(&self) -> u64 {
        self.args[3]
    }
    #[inline]
    pub fn arg4(&self) -> u64 {
        self.args[4]
    }
    #[inline]
    pub fn arg5(&self) -> u64 {
        self.args[5]
    }
}

pub type SysFn = fn(&mut Valkyrie, &mut SubCtx) -> Result<u64>;

const SYSCALL_HANDLERS: &[(Arch, SyscallHandler)] = &[
    (Arch::X86_64, handle_x86_64_syscall),
    (Arch::X86, handle_x86_syscall),
];

pub const SYSCALL_TABLE_MAPPER: &[(&str, SysFn)] = &[
    ("read", sys_read),
    ("pread64", sys_pread64),
    ("lseek", sys_lseek),
    ("open", sys_open),
    ("write", sys_write),
    ("close", sys_close),
    ("access", sys_access),
    ("fstat", sys_fstat),
    ("exit", sys_exit),
    ("openat", sys_openat),
    ("renameat2", sys_renameat2),
    ("renameat", sys_renameat),
    ("statx", sys_statx),
    ("geteuid", sys_geteuid),
    ("geteuid32", sys_geteuid),
    ("getuid", sys_getuid),
    ("getuid32", sys_getuid),
    ("getegid", sys_getegid),
    ("getegid32", sys_getegid),
    ("getgid", sys_getgid),
    ("getgid32", sys_getgid),
    ("brk", sys_brk),
    ("prctl", sys_prctl),
    ("arch_prctl", sys_arch_prctl),
    ("uname", sys_uname),
    ("ugetrlimit", sys_ugetrlimit),
    ("mmap", sys_mmap),
    ("mmap2", sys_mmap2),
    ("munmap", sys_munmap),
    ("gettid", sys_gettid),
    ("set_tid_address", sys_set_tid_address),
    ("set_robust_list", sys_set_robust_list),
    ("get_robust_list", sys_get_robust_list),
    ("rseq", sys_rseq),
    ("writev", sys_writev),
    ("exit_group", sys_exit_group),
    ("mprotect", sys_mprotect),
    ("prlimit64", sys_prlimit64),
    ("clock_gettime", sys_clock_gettime),
    ("clock_gettime64", sys_clock_gettime64),
    ("getrandom", sys_getrandom),
    ("readlink", sys_readlink),
    ("lookup_dcookie", sys_lookup_dcookie),
    ("rt_sigaction", sys_rt_sigaction),
    ("newfstatat", sys_newfstatat),
    ("fstatat64", sys_fstatat64),
    ("getpid", sys_getpid),
    ("tgkill", sys_tgkill),
    ("dup", sys_dup),
    ("fcntl", sys_fcntl),
    ("fcntl64", sys_fcntl),
    ("set_thread_area", sys_set_thread_area),
    ("fstat", sys_fstat),
    ("ioctl", sys_ioctl),
    ("getxattr", sys_getxattr),
    ("lgetxattr", sys_lgetxattr),
    ("fgetxattr", sys_fgetxattr),
    ("socket", sys_socket),
    ("connect", sys_connect),
    ("sendto", sys_sendto),
    ("getdents64", sys_getdents64),
    ("statfs", sys_statfs),
    ("statfs64", sys_statfs64),
];

pub fn dispatch_syscall_by_name(name: &str, vk: &mut Valkyrie, subctx: &mut SubCtx) -> Result<u64> {
    let f = syscall_fn_from_name(name)
        .ok_or_else(|| ValkyrieError::UnknownSyscallName(name.to_string()))?;
    f(vk, subctx)
}

fn syscall_handler_for(arch: Arch) -> Result<SyscallHandler> {
    SYSCALL_HANDLERS
        .iter()
        .find(|(a, _)| *a == arch)
        .map(|(_, h)| *h)
        .ok_or(ValkyrieError::UnsupportedArch(arch))
}

pub fn syscall_name_from_no(syscall_no: u64, arch: Arch) -> Result<&'static str> {
    let table: &[(u64, &'static str)] = match arch {
        Arch::X86_64 => crate::arch::x86_64::SYSCALL_TABLE_X86_64,
        Arch::X86 => crate::arch::x86::SYSCALL_TABLE_X86,
    };

    table
        .binary_search_by_key(&syscall_no, |(n, _)| *n)
        .ok()
        .map(|idx| table[idx].1)
        .ok_or(ValkyrieError::UnknownSyscall(syscall_no))
}

pub fn syscall_fn_from_name(name: &str) -> Option<SysFn> {
    SYSCALL_TABLE_MAPPER
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, f)| *f)
}

pub fn install_syscall_hook(vk: &mut Valkyrie) -> Result<()> {
    if vk.cfg.os == OsType::BareMetal {
        Logger::warning("OsType == BareMetal. Syscall handling won't be enabled.");
        return Ok(());
    }

    let handler = syscall_handler_for(vk.cfg.arch)?;
    vk.refresh_ctx_ptr();

    let hooks_ptr: *mut crate::VCoreHooks<Valkyrie>;
    {
        let env = vk.uc.get_data_mut();
        hooks_ptr = &mut env.hooks as *mut _;
    }

    unsafe {
        (*hooks_ptr).hook_code(
            &mut vk.uc,
            move |vk: &mut Valkyrie, addr: u64, size: u32, _ud: Option<&mut ()>| {
                if let Err(err) = (handler)(vk, addr, size) {
                    Logger::warning(format!("syscall handling failed: {err}"));
                }
                None
            },
            None::<()>,
            1,
            0,
        )?;
    }

    Ok(())
}
