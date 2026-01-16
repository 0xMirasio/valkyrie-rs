use crate::Valkyrie;
use crate::arch::x86::handle_x86_syscall;
use crate::arch::x86_64::handle_x86_64_syscall;
use crate::error::{Result, ValkyrieError};
use crate::logger::Logger;
use crate::os::syscall::{common::*, io::*};
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
    ("open", sys_open),
    ("write", sys_write),
    ("close", sys_close),
    ("exit", sys_exit),
    ("openat", sys_openat),
    ("renameat2", sys_renameat2),
    ("renameat", sys_renameat),
    ("statx", sys_statx),
    ("geteuid", sys_geteuid),
    ("getuid", sys_getuid),
    ("getegid", sys_getegid),
    ("getgid", sys_getgid),
    ("brk", sys_brk),
    ("arch_prctl", sys_arch_prctl),
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
