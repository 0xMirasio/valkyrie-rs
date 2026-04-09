use std::collections::HashMap;

use libafl::executors::ExitKind;
use libafl::inputs::HasTargetBytes;
use libafl_bolts::AsSlice;
use unicorn_engine::Context;
use unicorn_engine::unicorn_const::{HookType, Prot};

use crate::Valkyrie;
use crate::arch::regs::VRegister;
use crate::error::{Result, ValkyrieError};
use crate::memory::VMemRegion;
use crate::vtype::PAGE_SIZE;

use super::core::{
    CoverageMapRef, clear_coverage_map, install_shared_block_coverage, run_valkyrie_prepared,
};

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
    guest_rt_sigactions: HashMap<i32, Vec<u8>>,
    guest_rt_sigmask: Vec<u8>,
    guest_prctl_name: [u8; 16],
    guest_pdeathsig: i32,
    guest_dumpable: i32,
}

pub struct ReusableEmulator {
    vk: Valkyrie,
    snapshot: EmulatorSnapshot,
    coverage_state: Box<CoverageMapRef>,
    restore_mode: SnapshotRestoreMode,
    dirty_tracker: Option<Box<DirtyPageTracker>>,
    _dirty_hook: Option<crate::hook::HookRet>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SnapshotRestoreMode {
    Raw,
    #[default]
    FullMemory,
    EditedMemory,
}

#[derive(Debug, Clone, Copy)]
pub enum SnapshotInputLocation {
    Register(VRegister),
    Memory(u64),
}

#[derive(Debug, Clone, Copy)]
pub enum SnapshotInputSize {
    Register(VRegister),
    Memory { addr: u64, size: usize },
}

#[derive(Debug, Clone, Copy)]
pub struct FunctionSnapshotConfig {
    pub entry_addr: u64,
    pub input_buffer: SnapshotInputLocation,
    pub input_capacity: usize,
    pub input_size: SnapshotInputSize,
    pub restore_mode: SnapshotRestoreMode,
}

pub struct FunctionSnapshotEmulator {
    vk: Valkyrie,
    snapshot: EmulatorSnapshot,
    coverage_state: Box<CoverageMapRef>,
    restore_mode: SnapshotRestoreMode,
    dirty_tracker: Option<Box<DirtyPageTracker>>,
    _dirty_hook: Option<crate::hook::HookRet>,
    input_buf_addr: u64,
    input_capacity: usize,
    input_size: SnapshotInputSize,
}

#[derive(Debug)]
struct DirtyPageRange {
    page_start: u64,
    page_end: u64,
    page_base: usize,
}

#[derive(Debug)]
struct DirtyPageTracker {
    page_size: u64,
    ranges: Vec<DirtyPageRange>,
    page_starts: Vec<u64>,
    dirty_words: Vec<u64>,
    touched_words: Vec<usize>,
    touched_generation: Vec<u32>,
    generation: u32,
}

#[derive(Debug, Clone, Copy)]
struct DirtyTrackerPtr(*mut DirtyPageTracker);

impl ReusableEmulator {
    pub fn new(vk: Valkyrie, coverage: &mut [u8]) -> Result<Self> {
        Self::new_with_restore_mode(vk, coverage, SnapshotRestoreMode::FullMemory)
    }

    pub fn new_at_entry(vk: Valkyrie, coverage: &mut [u8], entry_addr: u64) -> Result<Self> {
        Self::new_at_entry_with_restore_mode(
            vk,
            coverage,
            entry_addr,
            SnapshotRestoreMode::FullMemory,
        )
    }

    pub fn new_with_restore_mode(
        mut vk: Valkyrie,
        coverage: &mut [u8],
        restore_mode: SnapshotRestoreMode,
    ) -> Result<Self> {
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
        let (dirty_tracker, dirty_hook) =
            install_dirty_tracking_if_needed(&mut vk, &snapshot, restore_mode)?;

        Ok(Self {
            vk,
            snapshot,
            coverage_state,
            restore_mode,
            dirty_tracker,
            _dirty_hook: dirty_hook,
        })
    }

    pub fn new_at_entry_with_restore_mode(
        mut vk: Valkyrie,
        coverage: &mut [u8],
        entry_addr: u64,
        restore_mode: SnapshotRestoreMode,
    ) -> Result<Self> {
        vk.set_soft_unicorn_errors(true);
        vk.prepare_initial_run()?;
        let os_runner = vk.os.clone();
        let (start, end) = os_runner.prepare_execution(&mut vk)?;
        vk.set_prepared_execution_range(start, end);

        let bootstrap_hook = install_stop_hook(&mut vk, entry_addr)?;
        let bootstrap_exit = run_valkyrie_prepared(&mut vk)?;
        if bootstrap_exit == ExitKind::Crash {
            return Err(ValkyrieError::BadConfig(
                "snapshot bootstrap crashed before the requested entry",
            ));
        }
        delete_hook(&mut vk, bootstrap_hook)?;
        vk.set_prepared_execution_range(entry_addr, end);

        let snapshot = capture_snapshot(&mut vk)?;
        let mut coverage_state = Box::new(CoverageMapRef {
            ptr: coverage.as_mut_ptr(),
            len: coverage.len(),
            prev_loc: 0,
        });
        install_shared_block_coverage(&mut vk, &mut coverage_state)?;
        let (dirty_tracker, dirty_hook) =
            install_dirty_tracking_if_needed(&mut vk, &snapshot, restore_mode)?;

        Ok(Self {
            vk,
            snapshot,
            coverage_state,
            restore_mode,
            dirty_tracker,
            _dirty_hook: dirty_hook,
        })
    }

    pub fn run_input<I>(&mut self, input: &I) -> Result<ExitKind>
    where
        I: HasTargetBytes,
    {
        restore_snapshot(
            &mut self.vk,
            &self.snapshot,
            self.restore_mode,
            self.dirty_tracker.as_deref_mut(),
        )?;

        let bytes = input.target_bytes();
        self.vk.set_stdin_bytes(bytes.as_slice());
        self.vk.reset_execution_state();
        clear_coverage_map(&mut self.coverage_state);

        run_valkyrie_prepared(&mut self.vk)
    }
}

impl FunctionSnapshotEmulator {
    pub fn new(
        mut vk: Valkyrie,
        coverage: &mut [u8],
        config: FunctionSnapshotConfig,
    ) -> Result<Self> {
        if config.input_capacity == 0 {
            return Err(ValkyrieError::BadConfig(
                "snapshot input capacity must be non-zero",
            ));
        }
        if let SnapshotInputSize::Memory { size, .. } = config.input_size
            && (size == 0 || size > 8)
        {
            return Err(ValkyrieError::BadConfig(
                "snapshot input length field must be 1..=8 bytes",
            ));
        }

        vk.set_soft_unicorn_errors(true);
        vk.prepare_initial_run()?;
        let os_runner = vk.os.clone();
        let (start, end) = os_runner.prepare_execution(&mut vk)?;
        vk.set_prepared_execution_range(start, end);

        let bootstrap_hook = install_stop_hook(&mut vk, config.entry_addr)?;
        let bootstrap_exit = run_valkyrie_prepared(&mut vk)?;
        if bootstrap_exit == ExitKind::Crash {
            return Err(ValkyrieError::BadConfig(
                "snapshot bootstrap crashed before the function entry",
            ));
        }
        delete_hook(&mut vk, bootstrap_hook)?;
        vk.set_prepared_execution_range(config.entry_addr, end);

        let input_buf_addr = match config.input_buffer {
            SnapshotInputLocation::Register(reg) => vk.arch.regs.get_reg(&mut vk.uc, reg)?,
            SnapshotInputLocation::Memory(addr) => addr,
        };
        let snapshot = capture_snapshot(&mut vk)?;
        let mut coverage_state = Box::new(CoverageMapRef {
            ptr: coverage.as_mut_ptr(),
            len: coverage.len(),
            prev_loc: 0,
        });
        install_shared_block_coverage(&mut vk, &mut coverage_state)?;
        let (dirty_tracker, dirty_hook) =
            install_dirty_tracking_if_needed(&mut vk, &snapshot, config.restore_mode)?;

        Ok(Self {
            vk,
            snapshot,
            coverage_state,
            restore_mode: config.restore_mode,
            dirty_tracker,
            _dirty_hook: dirty_hook,
            input_buf_addr,
            input_capacity: config.input_capacity,
            input_size: config.input_size,
        })
    }

    pub fn run_input<I>(&mut self, input: &I) -> Result<ExitKind>
    where
        I: HasTargetBytes,
    {
        restore_snapshot(
            &mut self.vk,
            &self.snapshot,
            self.restore_mode,
            self.dirty_tracker.as_deref_mut(),
        )?;

        let bytes = input.target_bytes();
        let input_bytes = bytes.as_slice();
        if input_bytes.len() > self.input_capacity {
            return Err(ValkyrieError::BadConfig(
                "snapshot input exceeds configured guest buffer capacity",
            ));
        }

        self.vk
            .mem
            .write(&mut self.vk.uc, self.input_buf_addr, input_bytes)?;
        if input_bytes.len() < self.input_capacity {
            self.vk.mem.write(
                &mut self.vk.uc,
                self.input_buf_addr + input_bytes.len() as u64,
                &[0],
            )?;
        }

        match self.input_size {
            SnapshotInputSize::Register(reg) => {
                self.vk
                    .arch
                    .regs
                    .set_reg(&mut self.vk.uc, reg, input_bytes.len() as u64)?;
            }
            SnapshotInputSize::Memory { addr, size } => {
                let input_len = (input_bytes.len() as u64).to_le_bytes();
                self.vk
                    .mem
                    .write(&mut self.vk.uc, addr, &input_len[..size])?;
            }
        }

        self.vk.reset_execution_state();
        clear_coverage_map(&mut self.coverage_state);
        run_valkyrie_prepared(&mut self.vk)
    }
}

fn install_stop_hook(vk: &mut Valkyrie, addr: u64) -> Result<crate::hook::HookRet> {
    let self_ptr: *mut Valkyrie = vk;
    let hooks_ptr: *mut crate::hook::VCoreHooks<Valkyrie> = {
        let env = vk.uc.get_data_mut();
        env.set_ctx_ptr(self_ptr);
        &mut env.hooks as *mut _
    };

    unsafe {
        (*hooks_ptr).hook_address(
            &mut vk.uc,
            addr,
            |vk, _state: Option<&mut ()>| {
                let _ = vk.uc.emu_stop();
                None
            },
            None::<()>,
        )
    }
}

fn delete_hook(vk: &mut Valkyrie, hook: crate::hook::HookRet) -> Result<()> {
    let hooks_ptr: *mut crate::hook::VCoreHooks<Valkyrie> = {
        let env = vk.uc.get_data_mut();
        &mut env.hooks as *mut _
    };

    unsafe { (*hooks_ptr).hook_del(&mut vk.uc, hook) }
}

fn install_dirty_tracking_if_needed(
    vk: &mut Valkyrie,
    snapshot: &EmulatorSnapshot,
    restore_mode: SnapshotRestoreMode,
) -> Result<(Option<Box<DirtyPageTracker>>, Option<crate::hook::HookRet>)> {
    if restore_mode != SnapshotRestoreMode::EditedMemory {
        return Ok((None, None));
    }

    let mut dirty_tracker = Box::new(DirtyPageTracker::from_snapshot(snapshot));
    let hook = install_dirty_page_hook(vk, dirty_tracker.as_mut() as *mut DirtyPageTracker)?;
    Ok((Some(dirty_tracker), Some(hook)))
}

fn install_dirty_page_hook(
    vk: &mut Valkyrie,
    dirty_tracker: *mut DirtyPageTracker,
) -> Result<crate::hook::HookRet> {
    let self_ptr: *mut Valkyrie = vk;
    let hooks_ptr: *mut crate::hook::VCoreHooks<Valkyrie> = {
        let env = vk.uc.get_data_mut();
        env.set_ctx_ptr(self_ptr);
        &mut env.hooks as *mut _
    };

    unsafe {
        (*hooks_ptr).hook_mem(
            &mut vk.uc,
            HookType::MEM_WRITE,
            |_vk, _access, addr, size, _value, state: Option<&mut DirtyTrackerPtr>| {
                let state = state?;
                if size == 0 {
                    return None;
                }

                let tracker = &mut *state.0;
                tracker.mark_write(addr, size);
                None
            },
            Some(DirtyTrackerPtr(dirty_tracker)),
            1,
            0,
        )
    }
}

impl DirtyPageTracker {
    fn from_snapshot(snapshot: &EmulatorSnapshot) -> Self {
        let page_size = u64::from(PAGE_SIZE);
        let mut ranges = Vec::new();
        let mut page_starts = Vec::new();

        for region in &snapshot.writable_regions {
            let region_start = align_down(region.start, page_size);
            let region_end = align_up(
                region.start.saturating_add(region.data.len() as u64),
                page_size,
            );
            let page_base = page_starts.len();
            let mut page = region_start;
            while page < region_end {
                page_starts.push(page);
                page = page.saturating_add(page_size);
            }
            ranges.push(DirtyPageRange {
                page_start: region_start,
                page_end: region_end,
                page_base,
            });
        }

        let word_count = page_starts.len().div_ceil(64);
        Self {
            page_size,
            ranges,
            page_starts,
            dirty_words: vec![0; word_count],
            touched_words: Vec::new(),
            touched_generation: vec![0; word_count],
            generation: 1,
        }
    }

    fn mark_write(&mut self, addr: u64, size: usize) {
        if size == 0 {
            return;
        }

        let first_page = align_down(addr, self.page_size);
        let last_addr = addr.saturating_add(size.saturating_sub(1) as u64);
        let last_page = align_down(last_addr, self.page_size);
        let mut page = first_page;
        loop {
            if let Some(page_index) = self.lookup_page_index(page) {
                self.mark_page(page_index);
            }
            if page >= last_page {
                break;
            }
            page = page.saturating_add(self.page_size);
        }
    }

    fn take_dirty_pages(&mut self) -> Vec<u64> {
        let mut dirty_pages = Vec::new();

        for word_index in self.touched_words.drain(..) {
            let mut word = self.dirty_words[word_index];
            self.dirty_words[word_index] = 0;
            self.touched_generation[word_index] = 0;

            while word != 0 {
                let bit_index = word.trailing_zeros() as usize;
                let page_index = word_index * 64 + bit_index;
                if let Some(page_start) = self.page_starts.get(page_index) {
                    dirty_pages.push(*page_start);
                }
                word &= word - 1;
            }
        }

        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.generation = 1;
            self.touched_generation.fill(0);
        }

        dirty_pages
    }

    fn clear(&mut self) {
        self.dirty_words.fill(0);
        self.touched_words.clear();
        self.touched_generation.fill(0);
        self.generation = 1;
    }

    fn lookup_page_index(&self, page_start: u64) -> Option<usize> {
        self.ranges.iter().find_map(|range| {
            if page_start < range.page_start || page_start >= range.page_end {
                return None;
            }

            let offset = ((page_start - range.page_start) / self.page_size) as usize;
            Some(range.page_base + offset)
        })
    }

    fn mark_page(&mut self, page_index: usize) {
        let word_index = page_index / 64;
        let bit_index = page_index % 64;
        let bit_mask = 1_u64 << bit_index;

        if self.touched_generation[word_index] != self.generation {
            self.touched_generation[word_index] = self.generation;
            self.touched_words.push(word_index);
        }

        self.dirty_words[word_index] |= bit_mask;
    }
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

fn restore_snapshot(
    vk: &mut Valkyrie,
    snapshot: &EmulatorSnapshot,
    restore_mode: SnapshotRestoreMode,
    dirty_tracker: Option<&mut DirtyPageTracker>,
) -> Result<()> {
    match restore_mode {
        SnapshotRestoreMode::Raw => {}
        SnapshotRestoreMode::FullMemory => {
            restore_memory_layout(vk, &snapshot.regions)?;
            restore_all_writable_regions(vk, snapshot)?;
            clear_dirty_tracker(dirty_tracker);
        }
        SnapshotRestoreMode::EditedMemory => {
            let layout_changed = !same_memory_layout(&vk.mem.regions, &snapshot.regions);
            if layout_changed {
                restore_memory_layout(vk, &snapshot.regions)?;
                restore_all_writable_regions(vk, snapshot)?;
                clear_dirty_tracker(dirty_tracker);
            } else {
                restore_dirty_pages(vk, snapshot, dirty_tracker)?;
            }
        }
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

fn restore_all_writable_regions(vk: &mut Valkyrie, snapshot: &EmulatorSnapshot) -> Result<()> {
    for region in &snapshot.writable_regions {
        vk.mem.write(&mut vk.uc, region.start, &region.data)?;
    }

    Ok(())
}

fn restore_dirty_pages(
    vk: &mut Valkyrie,
    snapshot: &EmulatorSnapshot,
    dirty_tracker: Option<&mut DirtyPageTracker>,
) -> Result<()> {
    let Some(dirty_tracker) = dirty_tracker else {
        return restore_all_writable_regions(vk, snapshot);
    };

    let page_size = u64::from(PAGE_SIZE);
    let pages = dirty_tracker.take_dirty_pages();
    if pages.is_empty() {
        return Ok(());
    }

    for page_start in pages {
        let Some(region) = find_snapshot_writable_region(snapshot, page_start) else {
            continue;
        };

        let restore_start = page_start.max(region.start);
        let restore_end = page_start
            .saturating_add(page_size)
            .min(region.start.saturating_add(region.data.len() as u64));
        if restore_end <= restore_start {
            continue;
        }

        let offset = (restore_start - region.start) as usize;
        let size = (restore_end - restore_start) as usize;
        vk.mem.write(
            &mut vk.uc,
            restore_start,
            &region.data[offset..offset + size],
        )?;
    }

    Ok(())
}

fn find_snapshot_writable_region(
    snapshot: &EmulatorSnapshot,
    addr: u64,
) -> Option<&WritableRegionSnapshot> {
    snapshot.writable_regions.iter().find(|region| {
        let end = region.start.saturating_add(region.data.len() as u64);
        addr >= region.start && addr < end
    })
}

fn clear_dirty_tracker(dirty_tracker: Option<&mut DirtyPageTracker>) {
    if let Some(dirty_tracker) = dirty_tracker {
        dirty_tracker.clear();
    }
}

fn same_memory_layout(current_regions: &[VMemRegion], snapshot_regions: &[VMemRegion]) -> bool {
    if current_regions.len() != snapshot_regions.len() {
        return false;
    }

    let mut current = current_regions.iter().collect::<Vec<_>>();
    let mut snapshot = snapshot_regions.iter().collect::<Vec<_>>();
    current.sort_by_key(|region| region.start);
    snapshot.sort_by_key(|region| region.start);

    current.iter().zip(snapshot.iter()).all(|(left, right)| {
        left.start == right.start
            && left.size == right.size
            && left.prot == right.prot
            && left.info == right.info
    })
}

fn align_down(value: u64, align: u64) -> u64 {
    value & !(align.saturating_sub(1))
}

fn align_up(value: u64, align: u64) -> u64 {
    if value == 0 {
        return 0;
    }

    let mask = align.saturating_sub(1);
    value.saturating_add(mask) & !mask
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
