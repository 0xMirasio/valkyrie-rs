use crate::Valkyrie;
use crate::arch::regs::VRegister;
use crate::arch::x86::RegX86;
use crate::arch::x86_64::RegX86_64;
use crate::error::Result;
use crate::logger::Logger;
use crate::os::Os;
use crate::vtype::{Arch, PAGE_SIZE, VState};

use core::ffi::c_void;
use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::{RegisterX86, uc_error, uc_reg_write, uc_x86_mmr};

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
    #[allow(dead_code)]
    fn setup_tls_i386(&self, vk: &mut crate::Valkyrie, tls_base: u64) -> crate::error::Result<()> {
        let gdt_addr = vk.mem.tls_addr_start;
        let gdt_limit: u32 = 0x0fff;

        let desc_tls = gdt_desc(tls_base as u32, 0xFFFFF, 0xF2, 0xC);
        let desc_data = gdt_desc(0, 0xFFFFF, 0xF2, 0xC);
        let desc_code = gdt_desc(0, 0xFFFFF, 0xFA, 0xC);

        vk.mem.write(&mut vk.uc, gdt_addr + 8, &desc_tls)?;
        vk.mem.write(&mut vk.uc, gdt_addr + 16, &desc_data)?;
        vk.mem.write(&mut vk.uc, gdt_addr + 24, &desc_code)?;

        let gdtr = uc_x86_mmr {
            selector: 0,
            base: gdt_addr,
            limit: gdt_limit,
            flags: 0,
        };

        let err = unsafe {
            uc_reg_write(
                vk.uc.get_handle(),
                RegisterX86::GDTR as i32,
                (&gdtr as *const uc_x86_mmr).cast::<c_void>(),
            )
        };

        if err != uc_error::OK {
            return Err(crate::error::ValkyrieError::UnicornGeneralError(
                "failed to set GDTR",
            ));
        }

        let gs_sel = selector(1, 3) as u64;
        let ds_sel = selector(2, 3) as u64;
        let cs_sel = selector(3, 3) as u64;

        vk.arch
            .regs
            .set_reg(&mut vk.uc, VRegister::X86(RegX86::GS), gs_sel)?;

        vk.arch
            .regs
            .set_reg(&mut vk.uc, VRegister::X86(RegX86::DS), ds_sel)?;

        vk.arch
            .regs
            .set_reg(&mut vk.uc, VRegister::X86(RegX86::ES), ds_sel)?;

        vk.arch
            .regs
            .set_reg(&mut vk.uc, VRegister::X86(RegX86::SS), ds_sel)?;
        vk.arch
            .regs
            .set_reg(&mut vk.uc, VRegister::X86(RegX86::CS), cs_sel)?;

        Ok(())
    }

    fn setup_tls_minimal(&self, vk: &mut Valkyrie) -> Result<()> {
        let tls_size = vk.mem.tls_addr_exit - vk.mem.tls_addr_start;

        vk.mem.map(
            &mut vk.uc,
            vk.mem.tls_addr_start,
            tls_size,
            Prot::READ | Prot::WRITE,
            "[tls]",
        )?;

        let tls_base = vk.mem.tls_addr_start + 2 * PAGE_SIZE as u64;

        match vk.cfg.arch {
            Arch::X86 => {
                Logger::warning(
                    "TLS setup not implemented for x86. Program will likely crash if segments GS/FS are used.",
                );
                // todo : fix this
                //self.setup_tls_i386(vk, tls_base)?;
                return Ok(());
            }
            Arch::X86_64 => {
                vk.arch
                    .regs
                    .set_reg(&mut vk.uc, VRegister::X86_64(RegX86_64::FsBase), tls_base)?;
            }
        }

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
            PAGE_SIZE,
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
            u64::MAX
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

fn gdt_desc(base: u32, limit: u32, access: u8, flags: u8) -> [u8; 8] {
    let mut d = [0u8; 8];

    d[0] = (limit & 0xff) as u8;
    d[1] = ((limit >> 8) & 0xff) as u8;

    d[2] = (base & 0xff) as u8;
    d[3] = ((base >> 8) & 0xff) as u8;
    d[4] = ((base >> 16) & 0xff) as u8;

    d[5] = access;

    d[6] = (((limit >> 16) & 0x0f) as u8) | ((flags & 0x0f) << 4);
    d[7] = ((base >> 24) & 0xff) as u8;

    d
}

fn selector(idx: u16, rpl: u16) -> u16 {
    (idx << 3) | (rpl & 0x3)
}
