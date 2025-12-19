pub mod arch;
pub mod config;
pub mod error;
pub mod hook;
pub mod loader;
pub mod memory;
pub mod os;
pub mod util;
pub mod vstruct;
pub mod vtype;

pub use arch::VArch;
pub use config::ValkyrieConfig;
pub use error::Result;
pub use hook::VCoreHooks;
pub use memory::VMemory;
pub use os::VCoreOs;
pub use vstruct::VCoreStructs;
pub use vtype::VState;

use unicorn_engine::Unicorn;
use vtype::Arch;

pub struct Valkyrie {
    cfg: ValkyrieConfig,
    pub vstruct: VCoreStructs,           // VCoreStructs instance
    pub vcorehook: VCoreHooks<Valkyrie>, // VCoreHooks instance
    pub vstate: VState,                  // emulation state
    pub uc: Unicorn<'static, ()>,        // Unicorn engine
    pub arch: arch::VArch,               // arch subgroup
    pub mem: memory::VMemory,            // mem subgroup
    pub os: os::VCoreOs,                 // os subgroup
    pub exit_trap_addr: Option<u64>,
    pub exit_trap_hook: Option<unicorn_engine::UcHookId>,
    pub initial_sp: u64,
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

        let mem_handle = memory::VMemory::new(&cfg).unwrap();
        let os_handle = os::select_os(cfg.os)?;

        let mut vk = Self {
            cfg,
            vstruct,
            vcorehook,
            vstate,
            uc,
            arch: arch_subgroup,
            mem: mem_handle,
            os: os_handle,
            exit_trap_addr: None,
            exit_trap_hook: None,
            initial_sp: 0,
        };

        let mut ldr = loader::select_loader(vk.cfg.os)?;
        ldr.run(&mut vk)?;

        vk.os.set_loader_info(
            ldr.load_address(),
            vk.cfg.baremetal_code.len() as u64,
            ldr.skip_exit_check(),
        );

        Ok(vk)
    }

    pub fn run(&mut self) -> Result<()> {
        self.setup_trap()?;
        self.write_exit_trap()?;

        let os_runner = self.os.clone();
        os_runner.run(self)
    }

    fn setup_trap(&mut self) -> Result<()> {
        if self.exit_trap_addr.is_some() {
            return Ok(());
        }

        let trap_addr: u64 = 0x0900_0000; // TODO : calculate dynamically this adress
        self.mem.map(
            &mut self.uc,
            trap_addr,
            crate::vtype::PAGE_SIZE as u64,
            unicorn_engine::unicorn_const::Prot::ALL,
            "[Stop guard page]",
        )?;

        let hook_id = self
            .uc
            .add_code_hook(trap_addr, trap_addr, move |uc, _, _| {
                let _ = uc.emu_stop();
            })
            .map_err(|_| {
                crate::error::ValkyrieError::UnicornGeneralError("failed to install exit trap hook")
            })?;

        self.exit_trap_addr = Some(trap_addr);
        self.exit_trap_hook = Some(hook_id);

        Ok(())
    }

    fn write_exit_trap(&mut self) -> Result<()> {
        if self.os.skip_exit_trap() {
            return Ok(());
        }

        let trap_addr =
            self.exit_trap_addr
                .ok_or(crate::error::ValkyrieError::UnicornGeneralError(
                    "exit trap address not initialized",
                ))?;

        let stack_reg = match self.cfg.arch {
            Arch::X86 => arch::regs::VRegister::X86(arch::x86::RegX86::ESP),
            Arch::X86_64 => arch::regs::VRegister::X86_64(arch::x86_64::RegX86_64::RSP),
        };

        self.initial_sp = self.arch.regs.get_reg(&mut self.uc, stack_reg)?;

        let ptr_size = (self.cfg.archsize / 8) as usize;
        let new_sp = self.initial_sp.saturating_sub(ptr_size as u64);

        let trap_bytes = trap_addr.to_le_bytes();

        self.mem
            .write(&mut self.uc, new_sp, &trap_bytes[..ptr_size])
            .map_err(|_| {
                crate::error::ValkyrieError::UnicornGeneralError("failed to write exit trap")
            })?;

        self.arch.regs.set_reg(&mut self.uc, stack_reg, new_sp)?;

        Ok(())
    }
}
