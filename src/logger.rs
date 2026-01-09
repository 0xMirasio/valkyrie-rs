use std::fmt;

/// Niveaux de log
#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
    Debug,
}

/// Logger minimaliste (ZST)
#[derive(Debug, Clone)]
pub struct Logger;

impl Logger {
    #[inline(always)]
    fn color(level: LogLevel) -> &'static str {
        match level {
            LogLevel::Info => "\x1b[37m",    // white
            LogLevel::Success => "\x1b[32m", // green
            LogLevel::Warning => "\x1b[33m", // yellow
            LogLevel::Error => "\x1b[31m",   // red
            LogLevel::Debug => "\x1b[36m",   // cyan
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
        }
    }

    #[inline(always)]
    fn reset() -> &'static str {
        "\x1b[0m"
    }

    fn log(level: LogLevel, msg: impl fmt::Display) {
        eprintln!(
            "{}[{}]{} {}",
            Self::color(level),
            Self::label(level),
            Self::reset(),
            msg
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
            Self::log(LogLevel::Debug, msg);
        }
    }
}
