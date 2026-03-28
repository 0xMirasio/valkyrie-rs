use std::path::PathBuf;
use std::process;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::time::Instant;

use libafl::corpus::{Corpus, InMemoryCorpus, Testcase};
use libafl::events::NopEventManager;
use libafl::executors::{ExitKind, inprocess::InProcessExecutor};
use libafl::feedbacks::{CrashFeedback, MaxMapFeedback};
use libafl::fuzzer::{Fuzzer, StdFuzzer};
use libafl::inputs::BytesInput;
use libafl::mutators::{HavocScheduledMutator, mutations::BitFlipMutator};
use libafl::observers::StdMapObserver;
use libafl::schedulers::QueueScheduler;
use libafl::stages::StdMutationalStage;
use libafl::state::{HasCorpus, HasExecutions, HasSolutions, StdState};
use libafl_bolts::rands::StdRand;
use libafl_bolts::tuples::tuple_list;
use valkyrie_rs::fuzzing::{DEFAULT_COVERAGE_MAP_SIZE, emulate_input_with_coverage};
use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{Valkyrie, ValkyrieConfig};

fn parse_iterations() -> usize {
    match std::env::args().nth(1) {
        Some(value) => value.parse::<usize>().unwrap_or_else(|err| {
            eprintln!("invalid iteration count {value:?}: {err}");
            process::exit(2);
        }),
        None => 2_000,
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

struct StdioSilencer {
    stdout_fd: i32,
    stderr_fd: i32,
}

impl StdioSilencer {
    fn new() -> Result<Self, String> {
        let devnull = OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .map_err(|err| format!("failed to open /dev/null: {err}"))?;

        let stdout_fd = unsafe { libc::dup(libc::STDOUT_FILENO) };
        if stdout_fd < 0 {
            return Err(String::from("failed to duplicate stdout"));
        }

        let stderr_fd = unsafe { libc::dup(libc::STDERR_FILENO) };
        if stderr_fd < 0 {
            unsafe {
                libc::close(stdout_fd);
            }
            return Err(String::from("failed to duplicate stderr"));
        }

        let devnull_fd = devnull.as_raw_fd();
        if unsafe { libc::dup2(devnull_fd, libc::STDOUT_FILENO) } < 0 {
            unsafe {
                libc::close(stdout_fd);
                libc::close(stderr_fd);
            }
            return Err(String::from("failed to redirect stdout"));
        }
        if unsafe { libc::dup2(devnull_fd, libc::STDERR_FILENO) } < 0 {
            unsafe {
                libc::dup2(stdout_fd, libc::STDOUT_FILENO);
                libc::close(stdout_fd);
                libc::close(stderr_fd);
            }
            return Err(String::from("failed to redirect stderr"));
        }

        Ok(Self {
            stdout_fd,
            stderr_fd,
        })
    }
}

impl Drop for StdioSilencer {
    fn drop(&mut self) {
        unsafe {
            libc::dup2(self.stdout_fd, libc::STDOUT_FILENO);
            libc::dup2(self.stderr_fd, libc::STDERR_FILENO);
            libc::close(self.stdout_fd);
            libc::close(self.stderr_fd);
        }
    }
}

fn main() {
    let iterations = parse_iterations();
    let repo_root = repo_root();
    let rootfs_path = repo_root.join("rootfs").join("x8664_linux");
    let target_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target.bin");

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
        InMemoryCorpus::<BytesInput>::new(),
        InMemoryCorpus::<BytesInput>::new(),
        &mut feedback,
        &mut objective,
    )
    .unwrap_or_else(|err| {
        eprintln!("failed to create LibAFL state: {err}");
        process::exit(1);
    });

    for seed in [b"NOPE".as_slice(), b"ABB".as_slice()] {
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
    let mut event_manager = NopEventManager::new();

    let mut harness = |input: &BytesInput| -> ExitKind {
        let _silencer = StdioSilencer::new().unwrap_or_else(|err| {
            eprintln!("stdio redirect error: {err}");
            process::exit(1);
        });
        emulate_input_with_coverage(input, &mut coverage, |stdin| {
            let cfg = ValkyrieConfig::new(
                Arch::X86_64,
                OsType::Linux,
                rootfs_path.to_string_lossy().to_string(),
            )?
            .stdin_bytes(stdin)
            .feed_elf(&target_path)?;
            Valkyrie::new(cfg)
        })
        .unwrap_or_else(|err| {
            eprintln!("emulation failed: {err}");
            process::exit(1);
        })
    };

    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(edges_observer),
        &mut fuzzer,
        &mut state,
        &mut event_manager,
    )
    .unwrap_or_else(|err| {
        eprintln!("failed to create LibAFL executor: {err}");
        process::exit(1);
    });

    let mutator = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    let started = Instant::now();

    for iter in 0..iterations {
        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut event_manager)
            .unwrap_or_else(|err| {
                eprintln!("fuzzing failed at iter={iter}: {err}");
                process::exit(1);
            });

        if iter == 0 || (iter + 1) % 100 == 0 || iter + 1 == iterations {
            let executions = *state.executions();
            let elapsed = started.elapsed().as_secs_f64();
            let exec_per_sec = if elapsed > 0.0 {
                executions as f64 / elapsed
            } else {
                0.0
            };
            println!(
                "iter={} executions={} corpus={} crashes={} exec_per_sec={:.2}",
                iter + 1,
                executions,
                state.corpus().count(),
                state.solutions().count(),
                exec_per_sec,
            );
        }
    }

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
}
