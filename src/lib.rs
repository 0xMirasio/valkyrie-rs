pub mod arch;
pub mod config;
pub mod error;
pub mod vtype;

pub use arch::x86::{X86Mode, X86RunOptions};
pub use config::ValkyrieConfig;
pub use error::{Result, ValkyrieError};

pub struct Valkyrie {
    cfg: ValkyrieConfig,
}

#[derive(Debug, Clone)]
pub struct State {
    pub entry: u64,
    pub pc: u64,
}

impl Valkyrie {
    //Valkyrie Instance
    pub fn new(cfg: ValkyrieConfig) -> Result<Self> {
        Ok(Self { cfg })
    }

    pub fn config(&self) -> &ValkyrieConfig {
        &self.cfg
    }
}
