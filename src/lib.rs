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
pub use hook::{HookEnv, VCoreHooks};
pub use memory::VMemory;
pub use os::VCoreOs;
pub use vstruct::VCoreStructs;
pub use vtype::VState;

use error::ValkyrieError;
use unicorn_engine::Unicorn;
use util::Logger;
use vtype::Arch;

use std::fmt::Write;

pub struct Valkyrie {
    cfg: ValkyrieConfig,
    pub vstruct: VCoreStructs,                   // VCoreStructs instance
    pub vcorehook: VCoreHooks<Valkyrie>,         // VCoreHooks instance
    pub vstate: VState,                          // emulation state
    pub uc: Unicorn<'static, HookEnv<Valkyrie>>, // Unicorn engine
    pub arch: arch::VArch,                       // arch subgroup
    pub mem: memory::VMemory,                    // mem subgroup
    pub os: os::VCoreOs,                         // os subgroup
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
        let vcorehook: VCoreHooks<Valkyrie> = VCoreHooks::new();
        let vstruct = VCoreStructs::new(cfg.endianess, cfg.archsize).unwrap();
        let vstate = VState::NotSet;

        let (uc_arch, uc_mode) = arch::get_unicorn_arch(cfg.arch);
        let arch_subgroup = arch::VArch::new(cfg.arch);

        let uc: Unicorn<'static, HookEnv<Valkyrie>> =
            Unicorn::new_with_data(uc_arch, uc_mode, HookEnv::new())
                .map_err(|_| ValkyrieError::UnicornGeneralError("failed to create unicorn"))?;

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

        if vk.cfg.disassemble {
            vk.enable_instruction_trace()?;
        }

        if vk.cfg.debug {
            Logger::info("Debug mode enabled, launching udbserver");
            panic!("udbserver not supported yet");
            //udbserver::udbserver(&mut vk.uc, vk.cfg.debug_port, ldr.load_address())
            //    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        }

        Ok(vk)
    }

    fn refresh_ctx_ptr(&mut self) {
        let self_ptr: *mut Valkyrie = self;
        self.uc.get_data_mut().set_ctx_ptr(self_ptr);
    }

    pub fn enable_instruction_trace(&mut self) -> Result<()> {
        Logger::debug("Enabling instruction trace hook", self.cfg.verbose);
        self.refresh_ctx_ptr();

        let hooks_ptr: *mut VCoreHooks<Valkyrie>;
        {
            let env = self.uc.get_data_mut();
            env.disasm_enabled = true;

            hooks_ptr = &mut env.hooks as *mut _;
        }

        unsafe {
            (*hooks_ptr)
                .hook_code(
                    &mut self.uc,
                    |vk: &mut Valkyrie, addr: u64, size: u32, _ud: Option<&mut ()>| {
                        if size != 0
                            && let Err(e) =
                                vk.mem.show_instructions(&mut vk.uc, addr, size as usize)
                        {
                            Logger::warning(format!("disassembly failed at {addr:#x}: {e}"));
                        }
                        None
                    },
                    None::<()>,
                    1,
                    0,
                )
                .unwrap();
        }

        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        self.refresh_ctx_ptr();
        self.setup_trap()?;
        self.write_exit_trap()?;

        let os_runner = self.os.clone();
        self.vstate = VState::Running;
        os_runner.run(self)
    }

    pub fn panic_with_unicorn_context(
        &mut self,
        err: unicorn_engine::unicorn_const::uc_error,
    ) -> ! {
        let pc_reg: arch::regs::VRegister;
        let sp_reg: arch::regs::VRegister;
        let color_red = "\u{1b}[1;31m";
        let color_cyan = "\u{1b}[1;36m";
        let color_reset = "\u{1b}[0m";

        match self.cfg.arch {
            Arch::X86 => {
                pc_reg = arch::regs::VRegister::X86(arch::x86::RegX86::EIP);
                sp_reg = arch::regs::VRegister::X86(arch::x86::RegX86::ESP);
            }
            Arch::X86_64 => {
                pc_reg = arch::regs::VRegister::X86_64(arch::x86_64::RegX86_64::RIP);
                sp_reg = arch::regs::VRegister::X86_64(arch::x86_64::RegX86_64::RSP);
            }
        }

        let pc = self.arch.regs.get_reg(&mut self.uc, pc_reg).unwrap_or(0);
        let sp = self.arch.regs.get_reg(&mut self.uc, sp_reg).unwrap_or(0);
        let mut report = String::new();

        let _ = writeln!(
            report,
            "{color_red}Valkyrie panic:{color_reset} unicorn error {err:?} at pc={pc:#x} sp={sp:#x}"
        );
        let _ = writeln!(report, "{color_cyan}== Registers =={color_reset}");
        match self.cfg.arch {
            Arch::X86 => {
                let regs = vec![
                    ("EAX", arch::x86::RegX86::EAX),
                    ("EBX", arch::x86::RegX86::EBX),
                    ("ECX", arch::x86::RegX86::ECX),
                    ("EDX", arch::x86::RegX86::EDX),
                    ("ESI", arch::x86::RegX86::ESI),
                    ("EDI", arch::x86::RegX86::EDI),
                    ("EBP", arch::x86::RegX86::EBP),
                    ("ESP", arch::x86::RegX86::ESP),
                    ("EIP", arch::x86::RegX86::EIP),
                    ("EFLAGS", arch::x86::RegX86::EFLAGS),
                ];
                for (name, reg) in regs {
                    let value = self
                        .arch
                        .regs
                        .get_reg(&mut self.uc, arch::regs::VRegister::X86(reg));
                    match value {
                        Ok(val) => {
                            let _ = writeln!(report, "{name:>6} = {val:#010x}");
                        }
                        Err(err) => {
                            let _ = writeln!(report, "{name:>6} = <err {err}>");
                        }
                    }
                }
            }
            Arch::X86_64 => {
                let regs = vec![
                    ("RAX", arch::x86_64::RegX86_64::RAX),
                    ("RBX", arch::x86_64::RegX86_64::RBX),
                    ("RCX", arch::x86_64::RegX86_64::RCX),
                    ("RDX", arch::x86_64::RegX86_64::RDX),
                    ("RSI", arch::x86_64::RegX86_64::RSI),
                    ("RDI", arch::x86_64::RegX86_64::RDI),
                    ("RBP", arch::x86_64::RegX86_64::RBP),
                    ("RSP", arch::x86_64::RegX86_64::RSP),
                    ("R8", arch::x86_64::RegX86_64::R8),
                    ("R9", arch::x86_64::RegX86_64::R9),
                    ("R10", arch::x86_64::RegX86_64::R10),
                    ("R11", arch::x86_64::RegX86_64::R11),
                    ("R12", arch::x86_64::RegX86_64::R12),
                    ("R13", arch::x86_64::RegX86_64::R13),
                    ("R14", arch::x86_64::RegX86_64::R14),
                    ("R15", arch::x86_64::RegX86_64::R15),
                    ("RIP", arch::x86_64::RegX86_64::RIP),
                    ("EFLAGS", arch::x86_64::RegX86_64::EFLAGS),
                ];
                for (name, reg) in regs {
                    let value = self
                        .arch
                        .regs
                        .get_reg(&mut self.uc, arch::regs::VRegister::X86_64(reg));
                    match value {
                        Ok(val) => {
                            let _ = writeln!(report, "{name:>6} = {val:#018x}");
                        }
                        Err(err) => {
                            let _ = writeln!(report, "{name:>6} = <err {err}>");
                        }
                    }
                }
            }
        }

        let _ = writeln!(
            report,
            "{color_cyan}== Instructions around PC =={color_reset}"
        );
        let insn_size = 0x20;
        let (insn_base, insn_size) = if let Some(region) = self.mem.region_for(pc) {
            let base = pc.saturating_sub(0x10).max(region.start);
            let region_end = region.start + region.size;
            let max_size = region_end.saturating_sub(base) as usize;
            (base, insn_size.min(max_size))
        } else {
            (pc.saturating_sub(0x10), insn_size)
        };
        match self.mem.disassemble(&mut self.uc, insn_base, insn_size) {
            Ok(insns) => {
                for insn in insns {
                    let _ = writeln!(report, "\t{insn}");
                }
            }
            Err(err) => {
                let _ = writeln!(report, "disassembly failed: {err}");
            }
        }

        let _ = writeln!(report, "{color_cyan}== Stack dump =={color_reset}");
        let stack_dump_size = 0x40;
        let stack_dump_size = if let Some(region) = self.mem.region_for(sp) {
            let region_end = region.start + region.size;
            let max_size = region_end.saturating_sub(sp) as usize;
            stack_dump_size.min(max_size)
        } else {
            stack_dump_size
        };
        if stack_dump_size == 0 {
            let _ = writeln!(report, "stack dump skipped: empty range");
        } else {
            match self.mem.read(&mut self.uc, sp, stack_dump_size) {
                Ok(bytes) => {
                    let ptr_size = (self.cfg.archsize / 8) as usize;
                    for (i, chunk) in bytes.chunks(ptr_size).enumerate() {
                        let addr = sp + (i * ptr_size) as u64;
                        let mut value = 0u64;
                        for (shift, b) in chunk.iter().enumerate() {
                            value |= (*b as u64) << (shift * 8);
                        }
                        let _ = writeln!(report, "\t{addr:#x}: {value:#x}");
                    }
                }
                Err(err) => {
                    let _ = writeln!(report, "stack read failed: {err}");
                }
            }
        }
        panic!("{report}");
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
        let trap_bytes = trap_addr.to_le_bytes();

        self.mem
            .write(&mut self.uc, self.initial_sp, &trap_bytes[..ptr_size])
            .map_err(|_| {
                crate::error::ValkyrieError::UnicornGeneralError("failed to write exit trap")
            })?;

        Ok(())
    }
}
