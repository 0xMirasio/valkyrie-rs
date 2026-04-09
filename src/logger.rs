use std::cell::RefCell;
use std::fmt;
use std::io::{self, Write as IoWrite};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verbosity {
    Quiet = 0,
    #[default]
    Basic = 1,
    Debug2 = 2,
    Debug = 3,
}

impl Verbosity {
    #[inline(always)]
    pub const fn allows(self, level: LogLevel) -> bool {
        match level {
            LogLevel::Info | LogLevel::Success | LogLevel::Warning | LogLevel::Error => {
                !matches!(self, Self::Quiet)
            }
            LogLevel::Debug2 => matches!(self, Self::Debug2 | Self::Debug),
            LogLevel::Debug => matches!(self, Self::Debug),
        }
    }

    #[inline(always)]
    pub const fn forwards_guest_stdio(self) -> bool {
        !matches!(self, Self::Quiet)
    }
}

impl From<u8> for Verbosity {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Quiet,
            1 => Self::Basic,
            2 => Self::Debug2,
            _ => Self::Debug,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
    Debug,
    Debug2,
}

#[derive(Debug, Clone, Default)]
struct LoggerSettings {
    verbosity: Verbosity,
}

thread_local! {
    static LOGGER_SETTINGS: RefCell<LoggerSettings> = RefCell::new(LoggerSettings::default());
}

#[derive(Debug, Clone)]
pub struct Logger;

impl Logger {
    pub fn configure(verbosity: Verbosity) {
        LOGGER_SETTINGS.with(|settings| {
            *settings.borrow_mut() = LoggerSettings { verbosity };
        });
    }

    #[inline(always)]
    fn settings() -> LoggerSettings {
        LOGGER_SETTINGS.with(|settings| settings.borrow().clone())
    }

    #[inline(always)]
    fn color(level: LogLevel) -> &'static str {
        match level {
            LogLevel::Info => "\x1b[97m",     // white
            LogLevel::Success => "\x1b[32m",  // green
            LogLevel::Warning => "\x1b[33m",  // yellow
            LogLevel::Error => "\x1b[31m",    // red
            LogLevel::Debug => "\x1b[1;40m",  // bold grey
            LogLevel::Debug2 => "\x1b[37;2m", // light grey
        }
    }

    #[inline(always)]
    fn label(level: LogLevel) -> &'static str {
        match level {
            LogLevel::Info => "INFO",
            LogLevel::Success => "SUCCESS",
            LogLevel::Warning => "WARNING",
            LogLevel::Error => "ERROR",
            LogLevel::Debug => "DEBUG",
            LogLevel::Debug2 => "DEBUG2",
        }
    }

    #[inline(always)]
    fn reset() -> &'static str {
        "\x1b[0m"
    }

    fn log(level: LogLevel, msg: impl fmt::Display) {
        let settings = Self::settings();
        let should_log_terminal = settings.verbosity.allows(level);
        let colored_line = format!(
            "{}[{}] {}{}",
            Self::color(level),
            Self::label(level),
            msg,
            Self::reset()
        );

        if should_log_terminal && let Err(err) = Self::write_to_terminal(level, &colored_line) {
            eprintln!("[LOGGER] failed to write terminal log: {err}");
        }

        if let LogLevel::Error = level {
            panic!("fatal error: {msg}");
        }
    }

    fn write_to_terminal(level: LogLevel, line: &str) -> io::Result<()> {
        match level {
            LogLevel::Warning | LogLevel::Error => {
                let mut stderr = io::stderr().lock();
                writeln!(stderr, "{line}")
            }
            LogLevel::Info | LogLevel::Success | LogLevel::Debug | LogLevel::Debug2 => {
                let mut stdout = io::stdout().lock();
                writeln!(stdout, "{line}")
            }
        }
    }

    pub fn info(msg: impl fmt::Display) {
        Self::log(LogLevel::Info, msg);
    }

    pub fn success(msg: impl fmt::Display) {
        Self::log(LogLevel::Success, msg);
    }

    pub fn warning(msg: impl fmt::Display) {
        Self::log(LogLevel::Warning, msg);
    }

    pub fn error(msg: impl fmt::Display) {
        Self::log(LogLevel::Error, msg);
    }

    pub fn debug(msg: impl fmt::Display, _verbosity: Verbosity) {
        Self::log(LogLevel::Debug, msg);
    }

    pub fn debug_cgrey(msg: impl fmt::Display, _verbosity: Verbosity) {
        Self::log(LogLevel::Debug2, msg);
    }
}
