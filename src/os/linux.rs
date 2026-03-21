use crate::Valkyrie;
use crate::arch::regs::VRegister;
use crate::arch::x86::RegX86;
use crate::arch::x86_64::RegX86_64;
use crate::common::zero_fill;
use crate::error::Result;
use crate::logger::Logger;
use crate::os::Os;
use crate::vtype::{Arch, PAGE_SIZE, VState};

use core::ffi::c_void;
use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::{RegisterX86, uc_error, uc_reg_write, uc_x86_mmr};

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;

pub(crate) const X86_GDT_ENTRY_TLS_MIN: u32 = 6;
pub(crate) const X86_GDT_ENTRY_TLS_ENTRIES: u32 = 3;
pub(crate) const X86_GDT_ENTRY_TLS_MAX: u32 = X86_GDT_ENTRY_TLS_MIN + X86_GDT_ENTRY_TLS_ENTRIES - 1;
const X86_GDT_LIMIT: u32 = 0x0fff;
const X86_TLS_STUB_OFFSET: u64 = 0x100;

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

    fn guest_argv(vk: &Valkyrie) -> Vec<Vec<u8>> {
        if !vk.cfg.argv.is_empty() {
            return vk.cfg.argv.clone();
        }

        vec![
            vk.elf_auxv
                .as_ref()
                .map(|info| info.execfn.as_bytes().to_vec())
                .unwrap_or_else(|| b"valkyrie-rs".to_vec()),
        ]
    }
}

impl OsLinux {
    #[allow(dead_code)]
    fn setup_tls_i386(&self, vk: &mut crate::Valkyrie) -> crate::error::Result<()> {
        let gdt_addr = x86_gdt_addr(vk);
        zero_fill(&mut vk.uc, gdt_addr, X86_GDT_LIMIT as u64 + 1)?;

        install_x86_gdtr(vk)?;

        // Unicorn starts these i386 guests effectively at CPL0, so bootstrap with
        // flat kernel selectors while keeping user descriptors available for TLS loads.
        x86_write_gdt_entry(vk, 1, gdt_desc(0, 0xFFFFF, 0x9A, 0xC))?;
        x86_write_gdt_entry(vk, 2, gdt_desc(0, 0xFFFFF, 0x92, 0xC))?;
        x86_write_gdt_entry(vk, 3, gdt_desc(0, 0xFFFFF, 0xFA, 0xC))?;
        x86_write_gdt_entry(vk, 4, gdt_desc(0, 0xFFFFF, 0xF2, 0xC))?;

        Ok(())
    }

    fn setup_tls_minimal(&self, vk: &mut Valkyrie) -> Result<()> {
        let tls_size = vk.mem.tls_addr_exit - vk.mem.tls_addr_start;
        let tls_prot = match vk.cfg.arch {
            Arch::X86 => Prot::ALL,
            Arch::X86_64 => Prot::READ | Prot::WRITE,
        };

        vk.mem.map(
            &mut vk.uc,
            vk.mem.tls_addr_start,
            tls_size,
            tls_prot,
            "[tls]",
        )?;

        match vk.cfg.arch {
            Arch::X86 => {
                self.setup_tls_i386(vk)?;
            }
            Arch::X86_64 => {
                let tls_base = vk.mem.tls_addr_start + 2 * PAGE_SIZE as u64;
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

        let guest_argv = Self::guest_argv(vk);
        let mut argv_ptrs = Vec::with_capacity(guest_argv.len());
        for arg in guest_argv.iter().rev() {
            sp -= arg.len() as u64 + 1;
            vk.uc.mem_write(sp, arg)?;
            vk.uc.mem_write(sp + arg.len() as u64, &[0])?;
            argv_ptrs.push(sp);
        }
        argv_ptrs.reverse();
        let execfn_ptr = *argv_ptrs
            .first()
            .ok_or(crate::error::ValkyrieError::BadConfig(
                "guest argv must contain at least one entry",
            ))?;

        sp &= !0xFu64;

        let mut frame: Vec<u64> = Vec::with_capacity(argv_ptrs.len() + 4);
        frame.push(argv_ptrs.len() as u64);
        frame.extend(argv_ptrs.iter().copied());
        frame.push(0);
        frame.push(0);
        append_auxv64(vk, &mut frame, execfn_ptr, at_random_ptr);

        sp -= (frame.len() as u64) * 8;
        let mut p = sp;
        for &w in &frame {
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

        let guest_argv = Self::guest_argv(vk);
        let mut argv_ptrs = Vec::with_capacity(guest_argv.len());
        for arg in guest_argv.iter().rev() {
            sp -= arg.len() as u64 + 1;
            vk.uc.mem_write(sp, arg)?;
            vk.uc.mem_write(sp + arg.len() as u64, &[0])?;
            argv_ptrs.push(sp as u32);
        }
        argv_ptrs.reverse();
        let execfn_ptr = *argv_ptrs
            .first()
            .ok_or(crate::error::ValkyrieError::BadConfig(
                "guest argv must contain at least one entry",
            ))?;

        sp &= !0xFu64;

        let mut frame: Vec<u32> = Vec::with_capacity(argv_ptrs.len() + 4);
        frame.push(argv_ptrs.len() as u32);
        frame.extend(argv_ptrs.iter().copied());
        frame.push(0);
        frame.push(0);
        append_auxv32(vk, &mut frame, execfn_ptr, at_random_ptr as u32);

        sp -= (frame.len() as u64) * 4;
        let mut p = sp;
        for &w in &frame {
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

    fn setup_x86_entry_stub(&self, vk: &mut Valkyrie) -> Result<u64> {
        let stub_addr = vk.mem.tls_addr_start + X86_TLS_STUB_OFFSET;
        let target = vk.cfg.entry_point;
        let data_selector = selector(2, 0);
        let mut stub = Vec::with_capacity(15);

        stub.extend_from_slice(&[0x66, 0xB8]);
        stub.extend_from_slice(&data_selector.to_le_bytes());
        stub.extend_from_slice(&[0x8E, 0xD8]);
        stub.extend_from_slice(&[0x8E, 0xC0]);
        stub.extend_from_slice(&[0x8E, 0xD0]);
        stub.push(0xE9);

        let jump_src = stub_addr + stub.len() as u64 + 4;
        let rel = i64::try_from(target)
            .and_then(|target| i64::try_from(jump_src).map(|jump_src| target - jump_src))
            .map_err(|_| {
                crate::error::ValkyrieError::UnicornGeneralError("x86 entry target overflow")
            })?;
        let rel = i32::try_from(rel).map_err(|_| {
            crate::error::ValkyrieError::UnicornGeneralError("x86 entry jump out of range")
        })?;
        stub.extend_from_slice(&rel.to_le_bytes());

        vk.mem.write(&mut vk.uc, stub_addr, &stub)?;
        Ok(stub_addr)
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

        self.setup_tls_minimal(vk)?;
        self.setup_stack(vk)?;

        let start = match vk.cfg.arch {
            Arch::X86 => self.setup_x86_entry_stub(vk)?,
            Arch::X86_64 => vk.cfg.entry_point,
        };
        let end = if vk.cfg.exit_point != 0 {
            vk.cfg.exit_point
        } else {
            u64::MAX
        };

        Logger::info(format!(
            "OsLinux: Starting emulation at entry point {start:#x} / end={end:#x}"
        ));

        vk.mem.show_mappings();

        if let Err(err) = vk.uc.emu_start(start, end, vk.cfg.timeout, vk.cfg.count) {
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

fn append_auxv64(vk: &Valkyrie, frame: &mut Vec<u64>, execfn_ptr: u64, at_random_ptr: u64) {
    if let Some(info) = &vk.elf_auxv {
        frame.extend_from_slice(&[
            AT_PHDR,
            info.phdr,
            AT_PHENT,
            info.phent,
            AT_PHNUM,
            info.phnum,
            AT_BASE,
            info.base,
            AT_ENTRY,
            info.entry,
            AT_UID,
            vk.linux_creds.uid as u64,
            AT_EUID,
            vk.linux_creds.euid as u64,
            AT_GID,
            vk.linux_creds.gid as u64,
            AT_EGID,
            vk.linux_creds.egid as u64,
            AT_CLKTCK,
            100,
            AT_SECURE,
            0,
            AT_EXECFN,
            execfn_ptr,
        ]);
    }

    frame.extend_from_slice(&[
        AT_PAGESZ,
        PAGE_SIZE as u64,
        AT_RANDOM,
        at_random_ptr,
        AT_NULL,
        0,
    ]);
}

fn append_auxv32(vk: &Valkyrie, frame: &mut Vec<u32>, execfn_ptr: u32, at_random_ptr: u32) {
    if let Some(info) = &vk.elf_auxv {
        frame.extend_from_slice(&[
            AT_PHDR as u32,
            info.phdr as u32,
            AT_PHENT as u32,
            info.phent as u32,
            AT_PHNUM as u32,
            info.phnum as u32,
            AT_BASE as u32,
            info.base as u32,
            AT_ENTRY as u32,
            info.entry as u32,
            AT_UID as u32,
            vk.linux_creds.uid,
            AT_EUID as u32,
            vk.linux_creds.euid,
            AT_GID as u32,
            vk.linux_creds.gid,
            AT_EGID as u32,
            vk.linux_creds.egid,
            AT_CLKTCK as u32,
            100,
            AT_SECURE as u32,
            0,
            AT_EXECFN as u32,
            execfn_ptr,
        ]);
    }

    frame.extend_from_slice(&[
        AT_PAGESZ as u32,
        PAGE_SIZE,
        AT_RANDOM as u32,
        at_random_ptr,
        AT_NULL as u32,
        0,
    ]);
}

pub(crate) fn x86_gdt_addr(vk: &Valkyrie) -> u64 {
    vk.mem.tls_addr_start
}

pub(crate) fn x86_gdt_entry_addr(vk: &Valkyrie, entry_number: u32) -> u64 {
    x86_gdt_addr(vk) + (entry_number as u64 * 8)
}

pub(crate) fn x86_write_gdt_entry(
    vk: &mut Valkyrie,
    entry_number: u32,
    descriptor: [u8; 8],
) -> Result<()> {
    let entry_addr = x86_gdt_entry_addr(vk, entry_number);
    vk.mem.write(&mut vk.uc, entry_addr, &descriptor)
}

fn install_x86_gdtr(vk: &mut Valkyrie) -> Result<()> {
    let gdtr = uc_x86_mmr {
        selector: 0,
        base: x86_gdt_addr(vk),
        limit: X86_GDT_LIMIT,
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

    Ok(())
}
