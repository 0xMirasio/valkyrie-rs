use std::panic::{AssertUnwindSafe, catch_unwind};

use libafl::executors::ExitKind;
use libafl::inputs::HasTargetBytes;
use libafl_bolts::AsSlice;

use crate::error::{Result, ValkyrieError};
use crate::Valkyrie;

pub const DEFAULT_COVERAGE_MAP_SIZE: usize = 64 * 1024;

#[derive(Debug)]
struct CoverageMapRef {
    ptr: *mut u8,
    len: usize,
    prev_loc: usize,
}

pub fn install_block_coverage(vk: &mut Valkyrie, coverage: &mut [u8]) -> Result<()> {
    if coverage.is_empty() {
        return Err(ValkyrieError::BadConfig("coverage map must be non-empty"));
    }

    clear_coverage(coverage);
    let coverage_ref = CoverageMapRef {
        ptr: coverage.as_mut_ptr(),
        len: coverage.len(),
        prev_loc: 0,
    };

    let self_ptr: *mut Valkyrie = vk;
    let hooks_ptr: *mut crate::hook::VCoreHooks<Valkyrie> = {
        let env = vk.uc.get_data_mut();
        env.set_ctx_ptr(self_ptr);
        &mut env.hooks as *mut _
    };

    unsafe {
        (*hooks_ptr).hook_block(
            &mut vk.uc,
            |_vk, addr, _size, state: Option<&mut CoverageMapRef>| {
                let state = state?;

                let cur_loc = ((addr >> 4) as usize) % state.len;
                let idx = (cur_loc ^ state.prev_loc) % state.len;

                let slot = state.ptr.add(idx);
                *slot = (*slot).saturating_add(1);

                state.prev_loc = cur_loc >> 1;
                None
            },
            Some(coverage_ref),
            1,
            0,
        )?;
    }

    Ok(())
}

pub fn clear_coverage(coverage: &mut [u8]) {
    coverage.fill(0);
}

pub fn run_valkyrie(vk: &mut Valkyrie) -> Result<ExitKind> {
    match catch_unwind(AssertUnwindSafe(|| vk.run())) {
        Ok(Ok(())) => {
            if vk.crashed {
                Ok(ExitKind::Crash)
            } else {
                Ok(ExitKind::Ok)
            }
        }
        Ok(Err(err)) => Err(err),
        Err(_) => Ok(ExitKind::Crash),
    }
}

pub fn emulate_input_with_coverage<I, F>(
    input: &I,
    coverage: &mut [u8],
    mut build: F,
) -> Result<ExitKind>
where
    I: HasTargetBytes,
    F: FnMut(&[u8]) -> Result<Valkyrie>,
{
    let bytes = input.target_bytes();
    let mut vk = build(bytes.as_slice())?;
    install_block_coverage(&mut vk, coverage)?;
    run_valkyrie(&mut vk)
}
