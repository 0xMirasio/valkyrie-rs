use std::panic::{AssertUnwindSafe, catch_unwind};

use libafl::executors::ExitKind;
use libafl::inputs::HasTargetBytes;
use libafl_bolts::AsSlice;
use unicorn_engine::Context;
use unicorn_engine::unicorn_const::Prot;

use crate::Valkyrie;
use crate::error::{Result, ValkyrieError};
use crate::memory::VMemRegion;

pub const DEFAULT_COVERAGE_MAP_SIZE: usize = 64 * 1024;

#[derive(Debug)]
struct CoverageMapRef {
    ptr: *mut u8,
    len: usize,
    prev_loc: usize,
}

#[derive(Debug)]
struct SharedCoverageHandle {
    state: *mut CoverageMapRef,
}

#[derive(Debug)]
struct WritableRegionSnapshot {
    start: u64,
    data: Vec<u8>,
}

#[derive(Debug)]
struct EmulatorSnapshot {
    context: Context,
    regions: Vec<VMemRegion>,
    writable_regions: Vec<WritableRegionSnapshot>,
    linux_creds: crate::LinuxCreds,
    guest_rt_sigactions: std::collections::HashMap<i32, Vec<u8>>,
    guest_rt_sigmask: Vec<u8>,
    guest_prctl_name: [u8; 16],
    guest_pdeathsig: i32,
    guest_dumpable: i32,
}

pub struct ReusableEmulator {
    vk: Valkyrie,
    snapshot: EmulatorSnapshot,
    coverage_state: Box<CoverageMapRef>,
}

impl ReusableEmulator {
    pub fn new(mut vk: Valkyrie, coverage: &mut [u8]) -> Result<Self> {
        vk.set_soft_unicorn_errors(true);
        vk.prepare_initial_run()?;
        let os_runner = vk.os.clone();
        let (start, end) = os_runner.prepare_execution(&mut vk)?;
        vk.set_prepared_execution_range(start, end);

        let snapshot = capture_snapshot(&mut vk)?;
        let mut coverage_state = Box::new(CoverageMapRef {
            ptr: coverage.as_mut_ptr(),
            len: coverage.len(),
            prev_loc: 0,
        });
        install_shared_block_coverage(&mut vk, &mut coverage_state)?;

        Ok(Self {
            vk,
            snapshot,
            coverage_state,
        })
    }

    pub fn run_input<I>(&mut self, input: &I) -> Result<ExitKind>
    where
        I: HasTargetBytes,
    {
        restore_snapshot(&mut self.vk, &self.snapshot)?;

        let bytes = input.target_bytes();
        self.vk.set_stdin_bytes(bytes.as_slice());
        self.vk.reset_execution_state();
        clear_coverage_map(&mut self.coverage_state);

        run_valkyrie_prepared(&mut self.vk)
    }
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

fn run_valkyrie_prepared(vk: &mut Valkyrie) -> Result<ExitKind> {
    match catch_unwind(AssertUnwindSafe(|| vk.run_prepared())) {
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

fn install_shared_block_coverage(
    vk: &mut Valkyrie,
    coverage_state: &mut Box<CoverageMapRef>,
) -> Result<()> {
    if coverage_state.len == 0 {
        return Err(ValkyrieError::BadConfig("coverage map must be non-empty"));
    }

    clear_coverage_map(coverage_state);
    let handle = SharedCoverageHandle {
        state: coverage_state.as_mut() as *mut CoverageMapRef,
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
            |_vk, addr, _size, state: Option<&mut SharedCoverageHandle>| {
                let state = &mut *state?.state;

                let cur_loc = ((addr >> 4) as usize) % state.len;
                let idx = (cur_loc ^ state.prev_loc) % state.len;

                let slot = state.ptr.add(idx);
                *slot = (*slot).saturating_add(1);

                state.prev_loc = cur_loc >> 1;
                None
            },
            Some(handle),
            1,
            0,
        )?;
    }

    Ok(())
}

fn clear_coverage_map(state: &mut CoverageMapRef) {
    if state.len == 0 {
        return;
    }

    let coverage = unsafe { std::slice::from_raw_parts_mut(state.ptr, state.len) };
    coverage.fill(0);
    state.prev_loc = 0;
}

fn capture_snapshot(vk: &mut Valkyrie) -> Result<EmulatorSnapshot> {
    let mut context = vk
        .uc
        .context_alloc()
        .map_err(|_| ValkyrieError::UnicornGeneralError("context_alloc failed"))?;
    vk.uc
        .context_save(&mut context)
        .map_err(|_| ValkyrieError::UnicornGeneralError("context_save failed"))?;

    let writable_region_metas = vk
        .mem
        .regions
        .iter()
        .filter(|region| (region.prot & Prot::WRITE) == Prot::WRITE)
        .map(|region| (region.start, region.size, region.prot))
        .collect::<Vec<_>>();
    let writable_regions = writable_region_metas
        .into_iter()
        .map(|(start, size, prot)| -> Result<WritableRegionSnapshot> {
            Ok(WritableRegionSnapshot {
                start,
                data: read_region_snapshot(vk, start, size, prot)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(EmulatorSnapshot {
        context,
        regions: vk.mem.regions.clone(),
        writable_regions,
        linux_creds: vk.linux_creds,
        guest_rt_sigactions: vk.guest_rt_sigactions.clone(),
        guest_rt_sigmask: vk.guest_rt_sigmask.clone(),
        guest_prctl_name: vk.guest_prctl_name,
        guest_pdeathsig: vk.guest_pdeathsig,
        guest_dumpable: vk.guest_dumpable,
    })
}

fn restore_snapshot(vk: &mut Valkyrie, snapshot: &EmulatorSnapshot) -> Result<()> {
    restore_memory_layout(vk, &snapshot.regions)?;

    for region in &snapshot.writable_regions {
        vk.mem.write(&mut vk.uc, region.start, &region.data)?;
    }

    vk.uc
        .context_restore(&snapshot.context)
        .map_err(|_| ValkyrieError::UnicornGeneralError("context_restore failed"))?;

    vk.linux_creds = snapshot.linux_creds;
    vk.guest_rt_sigactions = snapshot.guest_rt_sigactions.clone();
    vk.guest_rt_sigmask = snapshot.guest_rt_sigmask.clone();
    vk.guest_prctl_name = snapshot.guest_prctl_name;
    vk.guest_pdeathsig = snapshot.guest_pdeathsig;
    vk.guest_dumpable = snapshot.guest_dumpable;

    Ok(())
}

fn read_region_snapshot(vk: &mut Valkyrie, start: u64, size: u64, prot: Prot) -> Result<Vec<u8>> {
    let size = size as usize;
    if (prot & Prot::READ) == Prot::READ {
        return vk.mem.read(&mut vk.uc, start, size);
    }

    let readable_prot = prot | Prot::READ;
    vk.uc
        .mem_protect(start, size as u64, readable_prot)
        .map_err(|_| ValkyrieError::UnicornGeneralError("mem_protect failed"))?;
    let data = vk.mem.read(&mut vk.uc, start, size);
    vk.uc
        .mem_protect(start, size as u64, prot)
        .map_err(|_| ValkyrieError::UnicornGeneralError("mem_protect failed"))?;
    data
}

fn restore_memory_layout(vk: &mut Valkyrie, snapshot_regions: &[VMemRegion]) -> Result<()> {
    let current_regions = vk.mem.regions.clone();

    for region in &current_regions {
        for (start, size) in subtract_snapshot_coverage(region.start, region.size, snapshot_regions)
        {
            vk.uc
                .mem_unmap(start, size)
                .map_err(|_| ValkyrieError::UnicornGeneralError("mem_unmap failed"))?;
            vk.mem.remove_range(start, size);
        }
    }

    for region in snapshot_regions {
        if !is_range_mapped(&vk.mem.regions, region.start, region.size) {
            vk.uc
                .mem_map(region.start, region.size, region.prot)
                .map_err(|_| ValkyrieError::UnicornGeneralError("mem_map failed"))?;
        } else {
            vk.uc
                .mem_protect(region.start, region.size, region.prot)
                .map_err(|_| ValkyrieError::UnicornGeneralError("mem_protect failed"))?;
        }
    }

    vk.mem.regions = snapshot_regions.to_vec();
    Ok(())
}

fn subtract_snapshot_coverage(
    start: u64,
    size: u64,
    snapshot_regions: &[VMemRegion],
) -> Vec<(u64, u64)> {
    let mut pending = vec![(start, start.saturating_add(size))];

    for region in snapshot_regions {
        let cover_start = region.start;
        let cover_end = region.start.saturating_add(region.size);
        let mut next = Vec::new();

        for (segment_start, segment_end) in pending {
            if cover_end <= segment_start || cover_start >= segment_end {
                next.push((segment_start, segment_end));
                continue;
            }

            if segment_start < cover_start {
                next.push((segment_start, cover_start));
            }
            if cover_end < segment_end {
                next.push((cover_end, segment_end));
            }
        }

        pending = next;
        if pending.is_empty() {
            break;
        }
    }

    pending
        .into_iter()
        .filter_map(|(segment_start, segment_end)| {
            let size = segment_end.saturating_sub(segment_start);
            if size == 0 {
                None
            } else {
                Some((segment_start, size))
            }
        })
        .collect()
}

fn is_range_mapped(regions: &[VMemRegion], start: u64, size: u64) -> bool {
    let end = start.saturating_add(size);
    let mut cursor = start;
    let mut sorted = regions.iter().collect::<Vec<_>>();
    sorted.sort_by_key(|region| region.start);

    for region in sorted {
        let region_start = region.start;
        let region_end = region.start.saturating_add(region.size);
        if region_end <= cursor {
            continue;
        }
        if region_start > cursor {
            return false;
        }
        cursor = region_end.min(end);
        if cursor >= end {
            return true;
        }
    }

    cursor >= end
}
