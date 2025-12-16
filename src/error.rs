use thiserror::Error;

pub type Result<T> = std::result::Result<T, ValkyrieError>;

#[derive(Debug, Error)]
pub enum ValkyrieError {
    #[error("bad config: {0}")]
    BadConfig(&'static str),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}
