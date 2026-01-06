use crate::Valkyrie;
use crate::error::Result;
use crate::os::register_syscall::SubCtx;

pub fn sys_read(_vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    println!(
        "sys_read called with args: {:x}, {:x}, {:x}",
        sctx.arg0(),
        sctx.arg1(),
        sctx.arg2()
    );
    Ok(0)
}
