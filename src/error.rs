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
}

/// struct errors d'unpack
#[derive(Debug, Clone)]
pub enum StructError {
    UnsupportedBitness,
    BufferTooSmall { expected: usize, got: usize },
}
