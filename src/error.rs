use std::fmt;
use thiserror::Error;
use unicorn_engine;

pub type Result<T> = std::result::Result<T, ValkyrieError>;

#[derive(Debug, Error)]
pub enum ValkyrieError {
    #[error("bad config: {0}")]
    BadConfig(&'static str),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    #[error("struct conversion error: {0}")]
    StructConversion(&'static str),

    #[error("unsupported arch: {0:?}")]
    UnsupportedArch(crate::vtype::Arch),

    #[error("UnicornGeneralError: {0:?}")]
    UnicornGeneralError(&'static str),

    #[error("unicorn: {0:?}")]
    Unicorn(#[from] unicorn_engine::unicorn_const::uc_error),

    #[error("hook error: {0}")]
    Hook(&'static str),

    #[error("hook not handled: {0}")]
    HookNotHandled(&'static str),

    #[error("loader error: {0}")]
    Loader(&'static str),

    #[error("disassembler error: {0}")]
    Disassembler(&'static str),

    #[error("unknown syscall number: {0}")]
    UnknownSyscall(u64),

    #[error("unknown syscall name: {0}")]
    UnknownSyscallName(String),

    #[error("file system error: {0}")]
    FsError(FsError),
}

/// struct errors d'unpack
#[derive(Debug, Clone)]
pub enum StructError {
    UnsupportedBitness,
    BufferTooSmall { expected: usize, got: usize },
}

#[derive(Debug)]
pub enum FsError {
    FileAlreadyHasFd(u64),
    SocketAlreadyHasFd(u64),
    NoFileAtFd(u64),
    PoisonedFdTable,
    CurrentDirError,
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsError::FileAlreadyHasFd(fd) => write!(f, "file already exists at fd {fd}"),
            FsError::SocketAlreadyHasFd(fd) => {
                write!(f, "socket already exists at fd {fd}")
            }
            FsError::NoFileAtFd(fd) => write!(f, "no file at fd {fd}"),
            FsError::PoisonedFdTable => write!(f, "fd table mutex is poisoned"),
            FsError::CurrentDirError => write!(f, "failed to get current directory"),
        }
    }
}
