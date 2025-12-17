pub mod arch;
pub mod config;
pub mod error;
pub mod hook;
pub mod util;
pub mod vstruct;
pub mod vtype;

pub use config::ValkyrieConfig;
pub use error::Result;

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
    pub fn run(cfg: ValkyrieConfig) -> Result<Self> {
        Ok(Self { cfg })
    }

    pub fn config(&self) -> &ValkyrieConfig {
        &self.cfg
    }
}
