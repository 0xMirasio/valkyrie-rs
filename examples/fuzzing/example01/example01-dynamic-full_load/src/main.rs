use std::path::PathBuf;
use std::process;
use std::time::{Duration, Instant};

use libafl::corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase};
use libafl::events::{ProgressReporter, SimpleEventManager};
use libafl::executors::{ExitKind, inprocess::InProcessExecutor};
use libafl::feedbacks::{CrashFeedback, MaxMapFeedback};
use libafl::fuzzer::{Fuzzer, StdFuzzer};
use libafl::inputs::BytesInput;
use libafl::mutators::{
    BitFlipMutator, ByteDecMutator, ByteIncMutator, HavocScheduledMutator,
    SingleChoiceScheduledMutator, havoc_mutations,
};
use libafl::observers::StdMapObserver;
use libafl::schedulers::QueueScheduler;
use libafl::stages::StdMutationalStage;
use libafl::state::{HasCorpus, HasExecutions, HasSolutions, StdState};
use libafl_bolts::rands::StdRand;
use valkyrie_rs::fuzzing::core::DEFAULT_COVERAGE_MAP_SIZE;
use valkyrie_rs::fuzzing::monitor::{AflOutLayout, ValkyrieMonitor};
use valkyrie_rs::fuzzing::snapshot::{ReusableEmulator, SnapshotRestoreMode};
use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{Valkyrie, ValkyrieConfig};

const DEFAULT_ITERATIONS: usize = 25_000;
const FUZZ_SEED: u64 = 0xA11CE002;
const MONITOR_TITLE: &str = "example01-dynamic-full_load";

fn parse_iterations() -> usize {
    match std::env::args().nth(1) {
        Some(value) => value.parse::<usize>().unwrap_or_else(|err| {
            eprintln!("invalid iteration count {value:?}: {err}");
            process::exit(2);
        }),
        None => DEFAULT_ITERATIONS,
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../")
        .canonicalize()
        .unwrap_or_else(|err| {
            eprintln!("failed to resolve repo root: {err}");
            process::exit(2);
        })
}

fn example_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn ensure_output_layout() -> Result<AflOutLayout, String> {
    let root = example_root();
    AflOutLayout::create(root.join("afl_out"))
        .map_err(|err| format!("failed to create afl_out layout: {err}"))
}

fn main() {
    let iterations = parse_iterations();
    let repo_root = repo_root();
    let rootfs_path = repo_root.join("rootfs").join("x8664_linux_glibc2.39");
    let target_path = example_root().join("target.bin");
    let afl_out = ensure_output_layout().unwrap_or_else(|err| {
        eprintln!("failed to prepare LibAFL output layout: {err}");
        process::exit(2);
    });

    if !target_path.is_file() {
        eprintln!(
            "missing {}. run `make -C {}` first",
            target_path.display(),
            env!("CARGO_MANIFEST_DIR"),
        );
        process::exit(2);
    }

    let mut coverage = vec![0_u8; DEFAULT_COVERAGE_MAP_SIZE].into_boxed_slice();
    let edges_observer =
        unsafe { StdMapObserver::from_mut_ptr("edges", coverage.as_mut_ptr(), coverage.len()) };
    let mut feedback = MaxMapFeedback::new(&edges_observer);
    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        StdRand::with_seed(FUZZ_SEED),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::<BytesInput>::new(afl_out.crash_dir()).unwrap_or_else(|err| {
            eprintln!(
                "failed to create crash dir {}: {err}",
                afl_out.crash_dir().display()
            );
            process::exit(1);
        }),
        &mut feedback,
        &mut objective,
    )
    .unwrap_or_else(|err| {
        eprintln!("failed to create LibAFL state: {err}");
        process::exit(1);
    });

    for seed in [b"ABD".as_slice()] {
        state
            .corpus_mut()
            .add(Testcase::new(BytesInput::new(seed.to_vec())))
            .unwrap_or_else(|err| {
                eprintln!("failed to seed corpus: {err}");
                process::exit(1);
            });
    }

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let monitor = ValkyrieMonitor::new(MONITOR_TITLE).with_afl_out(afl_out.clone());
    let mut event_manager = SimpleEventManager::new(monitor);

    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap_or_else(|err| {
        eprintln!("failed to build Valkyrie config: {err}");
        process::exit(1);
    })
    .verbose(0)
    .feed_elf(&target_path)
    .unwrap_or_else(|err| {
        eprintln!(
            "failed to configure fuzz target {}: {err}",
            target_path.display()
        );
        process::exit(1);
    });
    let vk = Valkyrie::new(cfg).unwrap_or_else(|err| {
        eprintln!("failed to create Valkyrie instance: {err}");
        process::exit(1);
    });

    let mut runner = ReusableEmulator::new_with_restore_mode(
        vk,
        &mut coverage,
        SnapshotRestoreMode::FullMemory,
    )
    .unwrap_or_else(|err| {
        eprintln!("failed to create reusable emulator: {err}");
        process::exit(1);
    });

    let mut harness = |input: &BytesInput| -> ExitKind {
        runner.run_input(input).unwrap_or_else(|err| {
            eprintln!("emulation failed: {err}");
            process::exit(1);
        })
    };

    let mut executor = InProcessExecutor::new(
        &mut harness,
        libafl_bolts::tuples::tuple_list!(edges_observer),
        &mut fuzzer,
        &mut state,
        &mut event_manager,
    )
    .unwrap_or_else(|err| {
        eprintln!("failed to create LibAFL executor: {err}");
        process::exit(1);
    });
    let deterministic_mutator = SingleChoiceScheduledMutator::new(
        libafl_bolts::tuples::tuple_list!(
            BitFlipMutator::new(),
            ByteIncMutator::new(),
            ByteDecMutator::new(),
        ),
    );
    let havoc_mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = libafl_bolts::tuples::tuple_list!(
        StdMutationalStage::new(deterministic_mutator),
        StdMutationalStage::new(havoc_mutator),
    );
    let started = Instant::now();
    let monitor_timeout = Duration::from_millis(250);
    let mut first_crash_iter = None;

    for iter in 0..iterations {
        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut event_manager)
            .unwrap_or_else(|err| {
                eprintln!("fuzzing failed at iter={iter}: {err}");
                process::exit(1);
            });
        event_manager
            .maybe_report_progress(&mut state, monitor_timeout)
            .unwrap_or_else(|err| {
                eprintln!("monitor update failed at iter={iter}: {err}");
                process::exit(1);
            });

        if state.solutions().count() > 0 && first_crash_iter.is_none() {
            first_crash_iter = Some(iter + 1);
            println!("first crash discovered at iter={}", iter + 1);
        }
    }

    event_manager
        .report_progress(&mut state)
        .unwrap_or_else(|err| {
            eprintln!("final monitor update failed: {err}");
            process::exit(1);
        });

    let elapsed = started.elapsed().as_secs_f64();
    let executions = *state.executions();
    let exec_per_sec = if elapsed > 0.0 {
        executions as f64 / elapsed
    } else {
        0.0
    };

    println!(
        "done iterations={} executions={} corpus={} crashes={} elapsed_sec={elapsed:.6} exec_per_sec={exec_per_sec:.2}",
        iterations,
        executions,
        state.corpus().count(),
        state.solutions().count(),
    );
    if let Some(iter) = first_crash_iter {
        println!("first_crash_iter={iter}");
    }
}
