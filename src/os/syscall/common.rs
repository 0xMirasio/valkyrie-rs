use crate::Valkyrie;
use crate::error::Result;
use crate::logger::Logger;
use crate::os::register_syscall::SubCtx;

pub fn sys_exit(vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
    Logger::info("sys_exit() called. Terminating emulation");
    let _ = vk.uc.emu_stop();
    Ok(0_u64)
}
