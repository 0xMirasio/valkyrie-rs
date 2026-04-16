use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};

use libafl::monitors::{Monitor, stats::ClientStatsManager};
use libafl_bolts::{ClientId, Error as LibAflError, format_duration};

pub const DEFAULT_AFL_STATE_SAVE_INTERVAL: u64 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AflOutLayout {
    root_dir: PathBuf,
    queue_dir: PathBuf,
    crash_dir: PathBuf,
    config_dir: PathBuf,
    state_dir: PathBuf,
    state_save_interval: u64,
}

impl AflOutLayout {
    pub fn create<P: AsRef<Path>>(root_dir: P) -> std::io::Result<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();
        let queue_dir = root_dir.join("queue");
        let crash_dir = root_dir.join("crash");
        let config_dir = root_dir.join("config");
        let state_dir = root_dir.join("state");

        fs::create_dir_all(&queue_dir)?;
        fs::create_dir_all(&crash_dir)?;
        fs::create_dir_all(&config_dir)?;
        fs::create_dir_all(&state_dir)?;

        let layout = Self {
            root_dir,
            queue_dir,
            crash_dir,
            config_dir,
            state_dir,
            state_save_interval: DEFAULT_AFL_STATE_SAVE_INTERVAL,
        };
        layout.write_internal_config()?;
        Ok(layout)
    }

    #[must_use]
    pub fn with_state_save_interval(mut self, state_save_interval: u64) -> Self {
        self.state_save_interval = state_save_interval.max(1);
        self
    }

    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    #[must_use]
    pub fn queue_dir(&self) -> &Path {
        &self.queue_dir
    }

    #[must_use]
    pub fn crash_dir(&self) -> &Path {
        &self.crash_dir
    }

    #[must_use]
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    #[must_use]
    pub fn state_save_interval(&self) -> u64 {
        self.state_save_interval
    }

    fn write_internal_config(&self) -> std::io::Result<()> {
        let mut rendered = String::new();
        let _ = writeln!(rendered, "afl_out={}", self.root_dir.display());
        let _ = writeln!(rendered, "state_interval={}", self.state_save_interval);

        fs::write(self.config_dir.join("fuzzer.conf"), rendered)
    }

    pub fn write_config<K, V, I>(&self, entries: I) -> std::io::Result<()>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut rendered = String::new();
        let _ = writeln!(rendered, "afl_out={}", self.root_dir.display());
        let _ = writeln!(rendered, "state_interval={}", self.state_save_interval);
        for (key, value) in entries {
            let _ = writeln!(rendered, "{}={}", key.as_ref(), value.as_ref());
        }

        fs::write(self.config_dir.join("fuzzer.conf"), rendered)
    }

    pub fn write_state_snapshot(
        &self,
        snapshot: &ValkyrieSnapshot,
        archive_snapshot: bool,
    ) -> std::io::Result<()> {
        let rendered = format_valkyrie_snapshot(snapshot);
        fs::write(self.state_dir.join("latest.txt"), rendered.as_bytes())?;

        if archive_snapshot {
            fs::write(
                self.state_dir
                    .join(format!("exec_{:020}.txt", snapshot.executions)),
                rendered.as_bytes(),
            )?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValkyrieSnapshot {
    pub title: String,
    pub afl_out_dir: Option<String>,
    pub queue_dir: Option<String>,
    pub crash_dir: Option<String>,
    pub config_dir: Option<String>,
    pub state_dir: Option<String>,
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
    if let Some(afl_out_dir) = &snapshot.afl_out_dir {
        let _ = writeln!(rendered, " afl_out         : {afl_out_dir}");
    }
    if let Some(queue_dir) = &snapshot.queue_dir {
        let _ = writeln!(rendered, " queue dir       : {queue_dir}");
    }
    if let Some(crash_dir) = &snapshot.crash_dir {
        let _ = writeln!(rendered, " crash dir       : {crash_dir}");
    }
    if let Some(config_dir) = &snapshot.config_dir {
        let _ = writeln!(rendered, " config dir      : {config_dir}");
    }
    if let Some(state_dir) = &snapshot.state_dir {
        let _ = writeln!(rendered, " state dir       : {state_dir}");
    }
    let _ = writeln!(rendered, " exec speed      : {}/s", snapshot.execs_per_sec);
    let _ = writeln!(rendered, " total execs     : {}", snapshot.executions);
    let _ = writeln!(rendered, " last new path   : {}", snapshot.last_new_path);
    let _ = writeln!(rendered, " last crash      : {}", snapshot.last_crash);
    let _ = writeln!(rendered, " coverage        : {coverage}");
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
    let _ = writeln!(rendered, " stability       : {stability}");

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
struct AflOutMonitorState {
    layout: AflOutLayout,
    next_archive_at: u64,
}

impl AflOutMonitorState {
    fn new(layout: AflOutLayout) -> Self {
        let next_archive_at = layout.state_save_interval();
        Self {
            layout,
            next_archive_at,
        }
    }

    fn should_archive(&mut self, executions: u64) -> bool {
        if executions == 0 || executions < self.next_archive_at {
            return false;
        }

        let interval = self.layout.state_save_interval();
        let next_bucket = executions / interval + 1;
        self.next_archive_at = next_bucket.saturating_mul(interval);
        true
    }
}

#[derive(Debug, Clone)]
pub struct ValkyrieMonitor {
    title: String,
    afl_out: Option<AflOutMonitorState>,
}

impl ValkyrieMonitor {
    #[must_use]
    pub fn new<T>(title: T) -> Self
    where
        T: Into<String>,
    {
        Self {
            title: title.into(),
            afl_out: None,
        }
    }

    #[must_use]
    pub fn with_afl_out(mut self, layout: AflOutLayout) -> Self {
        self.afl_out = Some(AflOutMonitorState::new(layout));
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

        let (afl_out_dir, queue_dir, crash_dir, config_dir, state_dir, archive_snapshot) =
            if let Some(afl_out) = &mut self.afl_out {
                (
                    Some(afl_out.layout.root_dir().display().to_string()),
                    Some(afl_out.layout.queue_dir().display().to_string()),
                    Some(afl_out.layout.crash_dir().display().to_string()),
                    Some(afl_out.layout.config_dir().display().to_string()),
                    Some(afl_out.layout.state_dir().display().to_string()),
                    afl_out.should_archive(total_execs),
                )
            } else {
                (None, None, None, None, None, false)
            };

        let snapshot = ValkyrieSnapshot {
            title: self.title.clone(),
            afl_out_dir,
            queue_dir,
            crash_dir,
            config_dir,
            state_dir,
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

        if let Some(afl_out) = &self.afl_out {
            afl_out
                .layout
                .write_state_snapshot(&snapshot, archive_snapshot)
                .map_err(|err| {
                    LibAflError::illegal_state(format!("failed to persist afl_out state: {err}"))
                })?;
        }

        let rendered = format_valkyrie_snapshot(&snapshot);
        print!("{rendered}");
        std::io::stdout()
            .flush()
            .map_err(|err| LibAflError::illegal_state(format!("monitor flush failed: {err}")))?;
        Ok(())
    }
}
