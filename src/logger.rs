use std::fmt;

/// Niveaux de log
#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
    Debug1,
    Debug2,
}

/// Logger minimaliste (ZST)
#[derive(Debug, Clone)]
pub struct Logger;

impl Logger {
    #[inline(always)]
    fn color(level: LogLevel) -> &'static str {
        match level {
            LogLevel::Info => "\x1b[97m",     // white
            LogLevel::Success => "\x1b[32m",  // green
            LogLevel::Warning => "\x1b[33m",  // yellow
            LogLevel::Error => "\x1b[31m",    // red
            LogLevel::Debug1 => "\x1b[1;40m", // bold grey
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
            LogLevel::Debug1 => "DEBUG1",
            LogLevel::Debug2 => "DEBUG2",
        }
    }

    #[inline(always)]
    fn reset() -> &'static str {
        "\x1b[0m"
    }

    fn log(level: LogLevel, msg: impl fmt::Display) {
        eprintln!(
            "{}[{}] {}{}",
            Self::color(level),
            Self::label(level),
            msg,
            Self::reset()
        );

        if let LogLevel::Error = level {
            panic!("fatal error: {msg}");
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

    pub fn debug(msg: impl fmt::Display, verbose: bool) {
        if verbose {
            Self::log(LogLevel::Debug1, msg);
        }
    }

    pub fn debug_cgrey(msg: impl fmt::Display, verbose: bool) {
        if verbose {
            Self::log(LogLevel::Debug2, msg);
        }
    }
}
