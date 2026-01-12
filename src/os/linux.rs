use crate::Valkyrie;
use crate::arch::regs::VRegister;
use crate::arch::x86::RegX86;
use crate::arch::x86_64::RegX86_64;
use crate::error::Result;
use crate::logger::Logger;
use crate::os::Os;
use crate::vtype::{Arch, PAGE_SIZE, VState};

use unicorn_engine::unicorn_const::Prot;

const AT_NULL: u64 = 0;
const AT_PAGESZ: u64 = 6;
const AT_RANDOM: u64 = 25;

#[derive(Debug, Clone)]
pub struct OsLinux {
    load_address: Option<u64>,
    code_size: Option<u64>,
    skip_exit_check: bool,
}

impl OsLinux {
    pub fn new() -> Self {
        Self {
            load_address: None,
            code_size: None,
            skip_exit_check: false,
        }
    }
}

impl OsLinux {
    fn setup_tls_minimal(&self, vk: &mut Valkyrie) -> Result<()> {
        vk.mem.map(
            &mut vk.uc,
            vk.mem.tls_addr_start,
            PAGE_SIZE as u64,
            Prot::READ | Prot::WRITE,
            "[tls]",
        )?;

        let canary: u64 = 0xdead_beef_c0fe_babe;
        vk.uc
            .mem_write(vk.mem.tls_addr_start + 0x28, &canary.to_le_bytes())?;

        vk.arch.regs.set_reg(
            &mut vk.uc,
            match vk.cfg.arch {
                Arch::X86 => VRegister::X86(RegX86::FsBase),
                Arch::X86_64 => VRegister::X86_64(RegX86_64::FsBase),
            },
            vk.mem.tls_addr_start,
        )?;
        Ok(())
    }

    fn setup_stack_x86_64(&self, vk: &mut Valkyrie) -> Result<()> {
        let mut sp = vk.arch.regs.get_reg(&mut vk.uc, vk.arch.regs.sp)?;

        let random_bytes: [u8; 16] = [0x42; 16];
        sp -= 16;
        let at_random_ptr = sp;
        vk.uc.mem_write(sp, &random_bytes)?;

        let argv0 = b"valkyrie-rs\0";
        sp -= argv0.len() as u64;
        let argv0_ptr = sp;
        vk.uc.mem_write(sp, argv0)?;

        sp &= !0xFu64;

        let frame: &[u64] = &[
            1,
            argv0_ptr,
            0,
            0,
            AT_PAGESZ,
            PAGE_SIZE as u64,
            AT_RANDOM,
            at_random_ptr,
            AT_NULL,
            0,
        ];

        sp -= (frame.len() as u64) * 8;
        let mut p = sp;
        for &w in frame {
            vk.uc.mem_write(p, &w.to_le_bytes())?;
            p += 8;
        }

        vk.arch
            .regs
            .set_reg(&mut vk.uc, VRegister::X86_64(RegX86_64::RSP), sp)?;
        Ok(())
    }

    fn setup_stack_x86(&self, vk: &mut Valkyrie) -> Result<()> {
        let mut sp = vk.arch.regs.get_reg(&mut vk.uc, vk.arch.regs.sp)?;

        let random_bytes: [u8; 16] = [0x42; 16];
        sp -= 16;
        let at_random_ptr = sp;
        vk.uc.mem_write(sp, &random_bytes)?;

        let argv0 = b"valkyrie-rs\0";
        sp -= argv0.len() as u64;
        let argv0_ptr = sp;
        vk.uc.mem_write(sp, argv0)?;

        sp &= !0xFu64;

        let frame: &[u32] = &[
            1,
            argv0_ptr as u32,
            0,
            0,
            AT_PAGESZ as u32,
            PAGE_SIZE as u32,
            AT_RANDOM as u32,
            at_random_ptr as u32,
            AT_NULL as u32,
            0,
        ];

        sp -= (frame.len() as u64) * 4;
        let mut p = sp;
        for &w in frame {
            vk.uc.mem_write(p, &w.to_le_bytes())?;
            p += 4;
        }

        vk.arch
            .regs
            .set_reg(&mut vk.uc, VRegister::X86(RegX86::ESP), sp)?;
        Ok(())
    }

    fn setup_stack(&self, vk: &mut Valkyrie) -> Result<()> {
        match vk.cfg.arch {
            Arch::X86 => self.setup_stack_x86(vk),
            Arch::X86_64 => self.setup_stack_x86_64(vk),
        }
    }
}

impl Os for OsLinux {
    fn set_loader_info(&mut self, load_address: u64, code_size: u64, skip_exit_check: bool) {
        self.load_address = Some(load_address);
        self.code_size = Some(code_size);
        self.skip_exit_check = skip_exit_check;
    }

    fn skip_exit_trap(&self) -> bool {
        self.skip_exit_check
    }

    fn run(&self, vk: &mut Valkyrie) -> Result<()> {
        vk.vstate = VState::Running;

        let end = if vk.cfg.exit_point != 0 {
            vk.cfg.exit_point
        } else {
            0
        };

        Logger::info(format!(
            "OsLinux: Starting emulation at entry point {:#x} / end={:#x}",
            vk.cfg.entry_point, end
        ));

        self.setup_tls_minimal(vk)?;
        self.setup_stack(vk)?;

        vk.mem.show_mappings();

        if let Err(err) = vk
            .uc
            .emu_start(vk.cfg.entry_point, end, vk.cfg.timeout, vk.cfg.count)
        {
            vk.panic_with_unicorn_context(err);
        }

        vk.vstate = VState::Ended;
        Ok(())
    }
}

impl Default for OsLinux {
    fn default() -> Self {
        Self::new()
    }
}
