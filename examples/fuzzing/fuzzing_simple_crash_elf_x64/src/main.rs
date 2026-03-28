use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::time::Duration;
use std::time::Instant;

use libafl::corpus::{Corpus, InMemoryOnDiskCorpus, Testcase};
use libafl::events::{ProgressReporter, SimpleEventManager};
use libafl::executors::{ExitKind, inprocess::InProcessExecutor};
use libafl::feedbacks::{CrashFeedback, MaxMapFeedback};
use libafl::fuzzer::{Fuzzer, StdFuzzer};
use libafl::inputs::BytesInput;
use libafl::monitors::SimpleMonitor;
use libafl::mutators::{HavocScheduledMutator, havoc_mutations};
use libafl::observers::StdMapObserver;
use libafl::schedulers::QueueScheduler;
use libafl::stages::StdMutationalStage;
use libafl::state::{HasCorpus, HasExecutions, HasSolutions, StdState};
use libafl_bolts::rands::StdRand;
use valkyrie_rs::fuzzing::{DEFAULT_COVERAGE_MAP_SIZE, ReusableEmulator};
use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{Valkyrie, ValkyrieConfig};

const MIN_ITERATIONS: usize = 1_000;
const RAM_WORKSPACE_NAME: &str = "valkyrie-fuzzing_simple_crash_elf_x64";

fn parse_iterations() -> usize {
    match std::env::args().nth(1) {
        Some(value) => value.parse::<usize>().unwrap_or_else(|err| {
            eprintln!("invalid iteration count {value:?}: {err}");
            process::exit(2);
        }),
        None => MIN_ITERATIONS,
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

fn ram_workspace_root() -> PathBuf {
    std::env::var_os("VALKYRIE_AFL_RAM_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/dev/shm").join(RAM_WORKSPACE_NAME))
}

fn ensure_output_layout() -> Result<(PathBuf, PathBuf), String> {
    let ram_root = ram_workspace_root();
    let afl_out = ram_root.join("afl_out");
    let afl_crashs = ram_root.join("afl_crashs");

    fs::create_dir_all(&afl_out)
        .map_err(|err| format!("failed to create {}: {err}", afl_out.display()))?;
    fs::create_dir_all(&afl_crashs)
        .map_err(|err| format!("failed to create {}: {err}", afl_crashs.display()))?;

    ensure_local_output_link("afl_out", &afl_out)?;
    ensure_local_output_link("afl_crashs", &afl_crashs)?;

    Ok((afl_out, afl_crashs))
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

#[cfg(not(unix))]
fn create_symlink(target: &Path, link: &Path) -> Result<(), String> {
    let _ = target;
    let _ = link;
    Err(String::from(
        "this example expects a unix host for /dev/shm-backed output links",
    ))
}

fn main() {
    let requested_iterations = parse_iterations();
    let iterations = requested_iterations.max(MIN_ITERATIONS);
    let repo_root = repo_root();
    let rootfs_path = repo_root.join("rootfs").join("x8664_linux");
    let target_path = example_root().join("target.bin");
    let (afl_out_dir, afl_crashs_dir) = ensure_output_layout().unwrap_or_else(|err| {
        eprintln!("failed to prepare LibAFL output layout: {err}");
        process::exit(2);
    });

    if requested_iterations < MIN_ITERATIONS {
        eprintln!(
            "iteration count {requested_iterations} is too low for this example, using {MIN_ITERATIONS}"
        );
    }

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
        StdRand::with_seed(0xC0DEC0DE),
        InMemoryOnDiskCorpus::<BytesInput>::new(&afl_out_dir).unwrap_or_else(|err| {
            eprintln!(
                "failed to create corpus dir {}: {err}",
                afl_out_dir.display()
            );
            process::exit(1);
        }),
        InMemoryOnDiskCorpus::<BytesInput>::new(&afl_crashs_dir).unwrap_or_else(|err| {
            eprintln!(
                "failed to create crashes dir {}: {err}",
                afl_crashs_dir.display()
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

    for seed in [b"NOPE".as_slice(), b"A".as_slice(), b"AB".as_slice(), b"ABB".as_slice()] {
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
    let monitor = SimpleMonitor::new(|status| {
        println!("[monitor] {status}");
    });
    let mut event_manager = SimpleEventManager::new(monitor);

    println!("afl_out={}", afl_out_dir.display());
    println!("afl_crashs={}", afl_crashs_dir.display());

    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap_or_else(|err| {
        eprintln!("failed to build Valkyrie config: {err}");
        process::exit(1);
    })
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
    let mut runner = ReusableEmulator::new(vk, &mut coverage).unwrap_or_else(|err| {
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

    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = libafl_bolts::tuples::tuple_list!(StdMutationalStage::new(mutator));
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
            println!("crash discovered at iter={}", iter + 1);
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
