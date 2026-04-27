use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::time::Duration;
use std::time::Instant;

use libafl::corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus, Testcase};
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
use valkyrie_rs::arch::regs::VRegister;
use valkyrie_rs::arch::x86_64::RegX86_64;
use valkyrie_rs::fuzzing::core::DEFAULT_COVERAGE_MAP_SIZE;
use valkyrie_rs::fuzzing::monitor::{AflOutLayout, ValkyrieMonitor};
use valkyrie_rs::fuzzing::snapshot::{
    FunctionSnapshotConfig, FunctionSnapshotEmulator, SnapshotInputLocation, SnapshotInputSize,
    SnapshotRestoreMode,
};
use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{Valkyrie, ValkyrieConfig};

const DEFAULT_ITERATIONS: usize = 25_000;
const MAX_GUEST_INPUT_SIZE: usize = 4096;
const RAM_WORKSPACE_NAME: &str = "valkyrie-fuzzing_ex01";
const GUEST_BINARY_ARG0: &str = "/bin/target_png_parser";
const GUEST_INPUT_PATH: &str = "/tmp/valkyrie_fuzzing_ex01/input.png";
const BOOTSTRAP_SAMPLE_NAME: &str = "basic_valid.png";
const RESTORE_MODE: SnapshotRestoreMode = SnapshotRestoreMode::EditedMemory;

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
        .join("../../..")
        .canonicalize()
        .unwrap_or_else(|err| {
            eprintln!("failed to resolve repo root: {err}");
            process::exit(2);
        })
}

fn example_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn samples_root() -> PathBuf {
    example_root().join("fuzzer_samples")
}

fn ram_workspace_root() -> PathBuf {
    std::env::var_os("VALKYRIE_AFL_RAM_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/dev/shm").join(RAM_WORKSPACE_NAME))
}

fn ensure_output_layout() -> Result<AflOutLayout, String> {
    let layout = AflOutLayout::create(ram_workspace_root().join("afl_out"))
        .map_err(|err| format!("failed to create afl_out layout: {err}"))?;
    ensure_local_output_link("afl_out", layout.root_dir())?;
    Ok(layout)
}

fn guest_input_host_path(rootfs_path: &Path) -> PathBuf {
    rootfs_path.join(GUEST_INPUT_PATH.trim_start_matches('/'))
}

fn prepare_guest_input_path(rootfs_path: &Path) -> Result<PathBuf, String> {
    let host_path = guest_input_host_path(rootfs_path);
    let parent = host_path
        .parent()
        .ok_or_else(|| format!("guest input path has no parent: {}", host_path.display()))?;

    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    Ok(host_path)
}

fn guest_argv() -> Vec<Vec<u8>> {
    vec![
        GUEST_BINARY_ARG0.as_bytes().to_vec(),
        GUEST_INPUT_PATH.as_bytes().to_vec(),
    ]
}

fn ensure_local_output_link(name: &str, target: &Path) -> Result<(), String> {
    let local = example_root().join(name);

    if let Ok(meta) = fs::symlink_metadata(&local) {
        if !meta.file_type().is_symlink() {
            return Err(format!(
                "{} already exists and is not a symlink. Remove it or run setup_fuzzer.sh first",
                local.display()
            ));
        }

        let current = fs::read_link(&local)
            .map_err(|err| format!("failed to read symlink {}: {err}", local.display()))?;
        if current == target {
            return Ok(());
        }

        fs::remove_file(&local)
            .map_err(|err| format!("failed to replace {}: {err}", local.display()))?;
    }

    create_symlink(target, &local)
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(target, link).map_err(|err| {
        format!(
            "failed to create symlink {} -> {}: {err}",
            link.display(),
            target.display()
        )
    })
}

fn load_seed_corpus() -> Result<Vec<(PathBuf, Vec<u8>)>, String> {
    let mut entries = fs::read_dir(samples_root())
        .map_err(|err| format!("failed to read sample dir: {err}"))?
        .filter_map(|entry| entry.ok().map(|value| value.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("png"))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| !name.starts_with("crash_"))
        })
        .collect::<Vec<_>>();
    entries.sort();

    let mut corpus = Vec::with_capacity(entries.len());
    for path in entries {
        let bytes =
            fs::read(&path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        corpus.push((path, bytes));
    }

    if corpus.is_empty() {
        return Err(String::from(
            "no non-crashing PNG seeds found in fuzzer_samples/",
        ));
    }

    Ok(corpus)
}

fn bootstrap_sample_path(samples: &[(PathBuf, Vec<u8>)]) -> PathBuf {
    samples
        .iter()
        .find(|(path, _bytes)| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == BOOTSTRAP_SAMPLE_NAME)
        })
        .map(|(path, _bytes)| path.clone())
        .unwrap_or_else(|| samples[0].0.clone())
}

fn main() {
    let iterations = parse_iterations();
    let repo_root = repo_root();
    let rootfs_path = repo_root.join("rootfs").join("x8664_linux");
    let target_path = example_root().join("target.bin");
    let guest_input_host_path = prepare_guest_input_path(&rootfs_path).unwrap_or_else(|err| {
        eprintln!("failed to prepare guest input path: {err}");
        process::exit(2);
    });
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

    let samples = load_seed_corpus().unwrap_or_else(|err| {
        eprintln!("failed to load seed corpus: {err}");
        process::exit(2);
    });
    let bootstrap_sample = bootstrap_sample_path(&samples);
    fs::copy(&bootstrap_sample, &guest_input_host_path).unwrap_or_else(|err| {
        eprintln!(
            "failed to copy bootstrap sample {} to {}: {err}",
            bootstrap_sample.display(),
            guest_input_host_path.display(),
        );
        process::exit(2);
    });

    let parse_entry_addr = 0x00000000004018BF;

    let mut coverage = vec![0_u8; DEFAULT_COVERAGE_MAP_SIZE].into_boxed_slice();
    let edges_observer =
        unsafe { StdMapObserver::from_mut_ptr("edges", coverage.as_mut_ptr(), coverage.len()) };
    let mut feedback = MaxMapFeedback::new(&edges_observer);
    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        StdRand::with_seed(0x504E4758),
        InMemoryOnDiskCorpus::<BytesInput>::new(afl_out.queue_dir()).unwrap_or_else(|err| {
            eprintln!(
                "failed to create queue dir {}: {err}",
                afl_out.queue_dir().display()
            );
            process::exit(1);
        }),
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

    for (_path, seed) in samples {
        state
            .corpus_mut()
            .add(Testcase::new(BytesInput::new(seed)))
            .unwrap_or_else(|err| {
                eprintln!("failed to seed corpus: {err}");
                process::exit(1);
            });
    }

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let monitor =
        ValkyrieMonitor::new("fuzzing_ex01 :: in-memory PNG parser").with_afl_out(afl_out.clone());
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
    .argv(guest_argv())
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
    let snapshot_cfg = FunctionSnapshotConfig {
        entry_addr: parse_entry_addr,
        input_buffer: SnapshotInputLocation::Register(VRegister::X86_64(RegX86_64::RDI)),
        input_capacity: MAX_GUEST_INPUT_SIZE,
        input_size: SnapshotInputSize::Register(VRegister::X86_64(RegX86_64::RSI)),
        restore_mode: RESTORE_MODE,
    };
    let mut runner =
        FunctionSnapshotEmulator::new(vk, &mut coverage, snapshot_cfg).unwrap_or_else(|err| {
            eprintln!("failed to create in-memory snapshot emulator: {err}");
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

    let deterministic_mutator =
        SingleChoiceScheduledMutator::new(libafl_bolts::tuples::tuple_list!(
            BitFlipMutator::new(),
            ByteIncMutator::new(),
            ByteDecMutator::new(),
        ));
    let havoc_mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = libafl_bolts::tuples::tuple_list!(
        StdMutationalStage::new(deterministic_mutator),
        StdMutationalStage::new(havoc_mutator),
    );

    let started = Instant::now();
    let monitor_timeout = Duration::from_millis(5000);
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
