use std::fmt::Write as FmtWrite;
use std::io::Write as IoWrite;
use std::panic::{AssertUnwindSafe, catch_unwind};

use libafl::executors::ExitKind;
use libafl::inputs::HasTargetBytes;
use libafl::monitors::{Monitor, stats::ClientStatsManager};
use libafl_bolts::AsSlice;
use libafl_bolts::{ClientId, Error as LibAflError, format_duration};
use unicorn_engine::Context;
use unicorn_engine::unicorn_const::Prot;

use crate::Valkyrie;
use crate::arch::regs::VRegister;
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
}

pub struct FunctionSnapshotEmulator {
    vk: Valkyrie,
    snapshot: EmulatorSnapshot,
    coverage_state: Box<CoverageMapRef>,
    input_buf_addr: u64,
    input_capacity: usize,
    input_size: SnapshotInputSize,
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

        Ok(Self {
            vk,
            snapshot,
            coverage_state,
            input_buf_addr,
            input_capacity: config.input_capacity,
            input_size: config.input_size,
        })
    }

    pub fn run_input<I>(&mut self, input: &I) -> Result<ExitKind>
    where
        I: HasTargetBytes,
    {
        restore_snapshot(&mut self.vk, &self.snapshot)?;

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

#[derive(Debug, Clone, PartialEq)]
pub struct ValkyrieSnapshot {
    pub title: String,
    pub queue_dir: Option<String>,
    pub crashes_dir: Option<String>,
    pub event: String,
    pub sender_id: u32,
    pub run_time: String,
    pub clients: usize,
    pub corpus: u64,
    pub crashes: u64,
    pub executions: u64,
    pub execs_per_sec: String,
    pub last_new_path: String,
    pub last_crash: String,
    pub coverage: Option<(u64, u64)>,
    pub pending: u64,
    pub favored: u64,
    pub own_finds: u64,
    pub imported: u64,
    pub stability: Option<f64>,
    pub user_stats: Vec<(String, String)>,
}

pub fn format_valkyrie_snapshot(snapshot: &ValkyrieSnapshot) -> String {
    let mut rendered = String::new();
    let coverage = match snapshot.coverage {
        Some((hit, total)) if total != 0 => {
            let pct = (hit as f64 * 100.0) / total as f64;
            format!("{hit}/{total} ({pct:.2}%)")
        }
        Some((hit, total)) => format!("{hit}/{total}"),
        None => String::from("n/a"),
    };
    let stability = snapshot
        .stability
        .map(|value| format!("{:.2}%", value * 100.0))
        .unwrap_or_else(|| String::from("n/a"));

    let _ = writeln!(
        rendered,
        "\x1b[2J\x1b[H============================================"
    );
    let _ = writeln!(rendered, " Valkyrie monitor :: {}", snapshot.title);
    let _ = writeln!(rendered, "============================================");
    let _ = writeln!(
        rendered,
        " event           : {} (client #{})",
        snapshot.event, snapshot.sender_id
    );
    let _ = writeln!(rendered, " run time        : {}", snapshot.run_time);
    let _ = writeln!(rendered, " clients         : {}", snapshot.clients);
    let _ = writeln!(
        rendered,
        " corpus/crashes  : {}/{}",
        snapshot.corpus, snapshot.crashes
    );
    if let Some(queue_dir) = &snapshot.queue_dir {
        let _ = writeln!(rendered, " queue dir       : {queue_dir}");
    }
    if let Some(crashes_dir) = &snapshot.crashes_dir {
        let _ = writeln!(rendered, " crashes dir     : {crashes_dir}");
    }
    let _ = writeln!(rendered, " exec speed      : {}/s", snapshot.execs_per_sec);
    let _ = writeln!(rendered, " total execs     : {}", snapshot.executions);
    let _ = writeln!(rendered, " last new path   : {}", snapshot.last_new_path);
    let _ = writeln!(rendered, " last crash      : {}", snapshot.last_crash);
    let _ = writeln!(rendered, " coverage        : {}", coverage);
    let _ = writeln!(
        rendered,
        " pending/favored : {}/{}",
        snapshot.pending, snapshot.favored
    );
    let _ = writeln!(
        rendered,
        " own/imported    : {}/{}",
        snapshot.own_finds, snapshot.imported
    );
    let _ = writeln!(rendered, " stability       : {}", stability);

    if snapshot.user_stats.is_empty() {
        let _ = writeln!(rendered, " user stats      : n/a");
    } else {
        let stats = snapshot
            .user_stats
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(rendered, " user stats      : {stats}");
    }

    rendered
}

#[derive(Debug, Clone)]
pub struct ValkyrieMonitor {
    title: String,
    queue_dir: Option<String>,
    crashes_dir: Option<String>,
}

impl ValkyrieMonitor {
    #[must_use]
    pub fn new<T>(title: T) -> Self
    where
        T: Into<String>,
    {
        Self {
            title: title.into(),
            queue_dir: None,
            crashes_dir: None,
        }
    }

    #[must_use]
    pub fn with_output_dirs<Q, C>(mut self, queue_dir: Q, crashes_dir: C) -> Self
    where
        Q: Into<String>,
        C: Into<String>,
    {
        self.queue_dir = Some(queue_dir.into());
        self.crashes_dir = Some(crashes_dir.into());
        self
    }
}

impl Monitor for ValkyrieMonitor {
    fn display(
        &mut self,
        client_stats_manager: &mut ClientStatsManager,
        event_msg: &str,
        sender_id: ClientId,
    ) -> std::result::Result<(), LibAflError> {
        client_stats_manager.client_stats_insert(sender_id)?;

        let (run_time_pretty, client_stats_count, corpus_size, objective_size, total_execs, execs) = {
            let global = client_stats_manager.global_stats();
            (
                global.run_time_pretty.clone(),
                global.client_stats_count,
                global.corpus_size,
                global.objective_size,
                global.total_execs,
                global.execs_per_sec_pretty.clone(),
            )
        };
        let process_timing = client_stats_manager.process_timing(execs.clone(), total_execs);
        let coverage = client_stats_manager
            .edges_coverage()
            .map(|coverage| (coverage.edges_hit, coverage.edges_total));
        let geometry = client_stats_manager.item_geometry();
        let client = client_stats_manager.client_stats_for(sender_id)?;
        let mut user_stats = client
            .user_stats()
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<Vec<_>>();
        user_stats.sort_by(|left, right| left.0.cmp(&right.0));

        let snapshot = ValkyrieSnapshot {
            title: self.title.clone(),
            queue_dir: self.queue_dir.clone(),
            crashes_dir: self.crashes_dir.clone(),
            event: event_msg.to_string(),
            sender_id: sender_id.0,
            run_time: run_time_pretty,
            clients: client_stats_count,
            corpus: corpus_size,
            crashes: objective_size,
            executions: total_execs,
            execs_per_sec: execs,
            last_new_path: format_duration(&process_timing.last_new_entry),
            last_crash: format_duration(&process_timing.last_saved_solution),
            coverage,
            pending: geometry.pending,
            favored: geometry.pend_fav,
            own_finds: geometry.own_finds,
            imported: geometry.imported,
            stability: geometry.stability,
            user_stats,
        };

        let rendered = format_valkyrie_snapshot(&snapshot);
        print!("{rendered}");
        std::io::stdout()
            .flush()
            .map_err(|err| LibAflError::illegal_state(format!("monitor flush failed: {err}")))?;
        Ok(())
    }
}
