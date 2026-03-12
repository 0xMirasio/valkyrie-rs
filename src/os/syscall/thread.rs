use crate::Valkyrie;
use crate::common::neg_errno;
use crate::error::Result;
use crate::os::register_syscall::SubCtx;

fn current_tid() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) as i64 };
        if tid < 0 {
            return 0;
        }
        tid as u64
    }

    #[cfg(not(target_os = "linux"))]
    {
        unsafe { libc::getpid() as u64 }
    }
}

pub fn sys_gettid(_vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
    Ok(current_tid())
}

pub fn sys_set_tid_address(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let tid_ptr = sctx.arg0();
    let tid = current_tid() as u32;

    if tid_ptr != 0 {
        vk.mem.write(&mut vk.uc, tid_ptr, &tid.to_le_bytes())?;
    }

    Ok(tid as u64)
}

// todo: implement robust list handling
pub fn sys_set_robust_list(_vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
    Ok(0)
}

pub fn sys_get_robust_list(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let head_ptr = sctx.arg1();
    let len_ptr = sctx.arg2();
    let ptr_size = (vk.cfg.archsize / 8) as usize;
    let zero = vec![0u8; ptr_size];

    if head_ptr != 0 {
        vk.mem.write(&mut vk.uc, head_ptr, &zero)?;
    }

    if len_ptr != 0 {
        vk.mem.write(&mut vk.uc, len_ptr, &zero)?;
    }

    Ok(0)
}

// todo : implement rseq handling
pub fn sys_rseq(_vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
    Ok(neg_errno(libc::ENOSYS))
}

// todo: track tls descriptor per-thread when threading support lands
pub fn sys_set_thread_area(_vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
    Ok(neg_errno(libc::ENOSYS)) // make most of x86 libc_start_main elf halt. Need to fix this
}
