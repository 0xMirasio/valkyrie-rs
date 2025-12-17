pub mod arch;
pub mod config;
pub mod error;
pub mod hook;
//pub mod loader;
pub mod util;
pub mod vstruct;
pub mod vtype;

pub use config::ValkyrieConfig;
pub use error::Result;
pub use hook::VCoreHooks;
pub use vstruct::VCoreStructs;
pub use vtype::VState;

use unicorn_engine::Unicorn;

pub struct Valkyrie {
    cfg: ValkyrieConfig,
    pub vstruct: VCoreStructs,           // VCoreStructs instance
    pub vcorehook: VCoreHooks<Valkyrie>, // VCoreHooks instance
    pub vstate: VState,                  // emulation state
    pub uc: Unicorn<'static, ()>,        // Unicorn engine
}

#[derive(Debug, Clone)]
pub struct State {
    pub entry: u64,
    pub pc: u64,
}

impl Valkyrie {
    //Valkyrie Instance
    pub fn run(cfg: ValkyrieConfig) -> Result<Self> {
        let vcorehook = VCoreHooks::new();
        let vstruct = VCoreStructs::new(cfg.endianess, cfg.archsize).unwrap();
        let vstate = VState::NotSet;

        let (uc_arch, uc_mode) = arch::unicorn_arch(cfg.arch);

        let uc = Unicorn::new(uc_arch, uc_mode).map_err(|_| {
            crate::error::ValkyrieError::UnicornGeneralError("failed to create unicorn")
        })?;

        Ok(Self {
            cfg,
            vstruct,
            vcorehook,
            vstate,
            uc,
        })
    }

    pub fn config(&self) -> &ValkyrieConfig {
        &self.cfg
    }
}
