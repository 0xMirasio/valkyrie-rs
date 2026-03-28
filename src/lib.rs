pub mod arch;
pub mod common;
pub mod config;
pub mod error;
pub mod fs;
#[cfg(feature = "libafl")]
pub mod fuzzing;
pub mod hook;
pub mod loader;
pub mod logger;
pub mod memory;
pub mod os;
pub mod vstruct;
pub mod vtype;

pub use arch::VArch;
pub use config::ValkyrieConfig;
pub use error::Result;
pub use hook::{HookEnv, VCoreHooks};
pub use memory::VMemory;
pub use os::VCoreOs;
pub use os::syscall::common::LinuxCreds;
pub use vstruct::VCoreStructs;
pub use vtype::VState;

use error::ValkyrieError;
use logger::Logger;
use std::collections::HashMap;
use std::path::Path;
use unicorn_engine::Unicorn;
use vtype::Arch;

use std::fmt::Write;

use crate::vtype::PAGE_SIZE;

pub struct Valkyrie {
    cfg: ValkyrieConfig,
    pub vstruct: VCoreStructs,                   // VCoreStructs instance
    pub vcorehook: VCoreHooks<Valkyrie>,         // VCoreHooks instance
    pub vstate: VState,                          // emulation state
    pub uc: Unicorn<'static, HookEnv<Valkyrie>>, // Unicorn engine
    pub arch: arch::VArch,                       // arch subgroup
    pub mem: memory::VMemory,                    // mem subgroup
    pub os: os::VCoreOs,                         // os subgroup
    pub exit_trap_addr: Option<u64>,             // exit trap address (for baremetal)
    pub exit_trap_hook: Option<unicorn_engine::UcHookId>, // exit trap hook id (for baremetal)
    pub initial_sp: u64,                         // initial stack pointer
    pub exit_status: Option<u64>,                // guest exit status
    pub crashed: bool,                           // guest crash status
    pub elf_auxv: Option<loader::elf::ElfAuxvInfo>, // ELF loader metadata for Linux startup
    pub linux_creds: LinuxCreds,                 // Linux credentials manager
    pub guest_rt_sigactions: HashMap<i32, Vec<u8>>,
    pub guest_rt_sigmask: Vec<u8>,
    pub guest_prctl_name: [u8; 16],
    pub guest_pdeathsig: i32,
    pub guest_dumpable: i32,
    pub stdin_offset: usize,
    pub soft_unicorn_errors: bool,
    pub prepared_start: Option<u64>,
    pub prepared_end: Option<u64>,
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
        let guest_prctl_name = guest_prctl_name_from_cfg(&cfg);

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
            exit_status: None,
            crashed: false,
            elf_auxv: None,
            linux_creds: LinuxCreds::from_host(),
            guest_rt_sigactions: HashMap::new(),
            guest_rt_sigmask: Vec::new(),
            guest_prctl_name,
            guest_pdeathsig: 0,
            guest_dumpable: 1,
            stdin_offset: 0,
            soft_unicorn_errors: false,
            prepared_start: None,
            prepared_end: None,
        };

        let mut ldr = loader::select_loader(vk.cfg.loader)?;
        ldr.run(&mut vk)?;

        let require_exit_trap = ldr.skip_exit_check(&mut vk);

        vk.os.set_loader_info(
            ldr.load_address(),
            vk.cfg.baremetal_code.len() as u64,
            require_exit_trap,
        );

        if vk.cfg.disassemble {
            vk.enable_instruction_trace()?;
        }

        if vk.cfg.debug {
            Logger::info("Debug mode enabled, launching udbserver");
            udbserver::udbserver(&mut vk.uc, vk.cfg.debug_port, ldr.load_address())
                .map_err(|e| std::io::Error::other(e.to_string()))?;
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
                            && let Err(e) = VMemory::show_instructions(vk, addr, size as usize)
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
        self.prepare_initial_run()?;
        self.run_prepared()
    }

    pub(crate) fn prepare_initial_run(&mut self) -> Result<()> {
        self.reset_execution_state();
        self.refresh_ctx_ptr();
        os::register_syscall::install_syscall_hook(self)?;
        self.setup_trap()?;
        self.write_exit_trap()?;
        Ok(())
    }

    pub(crate) fn run_prepared(&mut self) -> Result<()> {
        self.refresh_ctx_ptr();
        if let (Some(start), Some(end)) = (self.prepared_start, self.prepared_end) {
            self.vstate = VState::Running;
            if let Err(err) = self.uc.emu_start(start, end, self.cfg.timeout, self.cfg.count) {
                self.handle_unicorn_error(err)?;
            }
            self.vstate = VState::Ended;
            return Ok(());
        }

        let os_runner = self.os.clone();
        self.vstate = VState::Running;
        os_runner.run(self)
    }

    pub(crate) fn reset_execution_state(&mut self) {
        self.vstate = VState::NotSet;
        self.exit_status = None;
        self.crashed = false;
        self.stdin_offset = 0;
    }

    pub(crate) fn set_stdin_bytes(&mut self, value: &[u8]) {
        self.cfg.stdin_data.clear();
        self.cfg.stdin_data.extend_from_slice(value);
        self.stdin_offset = 0;
    }

    pub(crate) fn set_soft_unicorn_errors(&mut self, value: bool) {
        self.soft_unicorn_errors = value;
    }

    pub(crate) fn set_prepared_execution_range(&mut self, start: u64, end: u64) {
        self.prepared_start = Some(start);
        self.prepared_end = Some(end);
    }

    pub(crate) fn handle_unicorn_error(
        &mut self,
        err: unicorn_engine::unicorn_const::uc_error,
    ) -> Result<()> {
        if self.soft_unicorn_errors {
            self.crashed = true;
            self.vstate = VState::Ended;
            Logger::debug(
                format!("Soft unicorn crash captured during fuzzing: {err:?}"),
                self.cfg.verbose,
            );
            return Ok(());
        }

        self.panic_with_unicorn_context(err);
    }

    fn append_register_dump(&mut self, report: &mut String) {
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
                    ("GsBase", arch::x86::RegX86::GsBase),
                    ("GS", arch::x86::RegX86::GS),
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
                    ("FSBASE", arch::x86_64::RegX86_64::FsBase),
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
    }

    fn append_instruction_dump(&mut self, report: &mut String, pc: u64) {
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
    }

    fn append_stack_dump(&mut self, report: &mut String, sp: u64) {
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
            return;
        }

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

    pub fn format_runtime_debug_table(&mut self, title: impl std::fmt::Display) -> String {
        let pc_reg = self.arch.regs.pc;
        let sp_reg = self.arch.regs.sp;
        let color_cyan = "\u{1b}[1;36m";
        let color_reset = "\u{1b}[0m";

        let pc = self.arch.regs.get_reg(&mut self.uc, pc_reg).unwrap_or(0);
        let sp = self.arch.regs.get_reg(&mut self.uc, sp_reg).unwrap_or(0);
        let mut report = String::new();

        let _ = writeln!(report, "{title} at pc={pc:#x} sp={sp:#x}");
        let _ = writeln!(report, "{color_cyan}== Registers =={color_reset}");
        self.append_register_dump(&mut report);

        let _ = writeln!(
            report,
            "{color_cyan}== Instructions around PC =={color_reset}"
        );
        self.append_instruction_dump(&mut report, pc);

        let _ = writeln!(report, "{color_cyan}== Stack dump =={color_reset}");
        self.append_stack_dump(&mut report, sp);

        report
    }

    pub fn log_runtime_debug_table(&mut self, title: impl std::fmt::Display) {
        let report = self.format_runtime_debug_table(title);
        for line in report.lines() {
            Logger::info(line);
        }
    }

    pub fn panic_with_unicorn_context(
        &mut self,
        err: unicorn_engine::unicorn_const::uc_error,
    ) -> ! {
        self.crashed = true;
        let color_red = "\u{1b}[1;31m";
        let color_reset = "\u{1b}[0m";
        let report = self.format_runtime_debug_table(format!(
            "{color_red}Valkyrie panic:{color_reset} unicorn error {err:?}"
        ));
        panic!("{report}");
    }

    fn setup_trap(&mut self) -> Result<()> {
        if self.exit_trap_addr.is_some() {
            return Ok(());
        }

        if self.os.skip_exit_trap() {
            return Ok(());
        }

        let trap_addr = self
            .mem
            .regions
            .iter()
            .map(|region| region.start.saturating_add(region.size))
            .max()
            .map(|end| {
                crate::common::align_up(end.saturating_add(PAGE_SIZE as u64), PAGE_SIZE as u64)
            })
            .unwrap_or(PAGE_SIZE as u64);
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
        self.mem.show_mappings();

        self.mem
            .write(&mut self.uc, self.initial_sp, &trap_bytes[..ptr_size])?;

        Ok(())
    }
}

fn guest_prctl_name_from_cfg(cfg: &ValkyrieConfig) -> [u8; 16] {
    let mut name = [0u8; 16];
    let source = cfg
        .elf_file
        .as_deref()
        .and_then(|path| Path::new(path).file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| String::from("valkyrie"));

    let bytes = source.as_bytes();
    let len = bytes.len().min(name.len().saturating_sub(1));
    name[..len].copy_from_slice(&bytes[..len]);
    name
}
