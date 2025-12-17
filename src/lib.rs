pub mod arch;
pub mod config;
pub mod error;
pub mod hook;
pub mod loader;
pub mod memory;
pub mod util;
pub mod vstruct;
pub mod vtype;

pub use arch::VArch;
pub use config::ValkyrieConfig;
pub use error::Result;
pub use hook::VCoreHooks;
pub use memory::VMemory;
pub use vstruct::VCoreStructs;
pub use vtype::VState;

use unicorn_engine::Unicorn;

pub struct Valkyrie {
    cfg: ValkyrieConfig,
    pub vstruct: VCoreStructs,           // VCoreStructs instance
    pub vcorehook: VCoreHooks<Valkyrie>, // VCoreHooks instance
    pub vstate: VState,                  // emulation state
    pub uc: Unicorn<'static, ()>,        // Unicorn engine
    pub arch: arch::VArch,               // arch subgroup
    pub mem: memory::VMemory,            // mem subgroup
}

#[derive(Debug, Clone)]
pub struct State {
    pub entry: u64,
    pub pc: u64,
}

impl Valkyrie {
    //Valkyrie Instance
    pub fn new(cfg: ValkyrieConfig) -> Result<Self> {
        let vcorehook = VCoreHooks::new();
        let vstruct = VCoreStructs::new(cfg.endianess, cfg.archsize).unwrap();
        let vstate = VState::NotSet;

        let (uc_arch, uc_mode) = arch::get_unicorn_arch(cfg.arch);
        let arch_subgroup = arch::VArch::new(cfg.arch);

        let uc = Unicorn::new(uc_arch, uc_mode).map_err(|_| {
            crate::error::ValkyrieError::UnicornGeneralError("failed to create unicorn")
        })?;

        let mem_subgroup = memory::VMemory::new();

        let mut vk = Self {
            cfg,
            vstruct,
            vcorehook,
            vstate,
            uc,
            arch: arch_subgroup,
            mem: mem_subgroup,
        };

        let mut ldr = loader::select_loader(vk.cfg.os)?;
        ldr.run(&mut vk)?;

        Ok(vk)
    }
}
