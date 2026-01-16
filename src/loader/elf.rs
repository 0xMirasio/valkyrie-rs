use crate::Valkyrie;
use crate::arch::regs::VRegister;
use crate::arch::x86::RegX86;
use crate::arch::x86_64::RegX86_64;
use crate::common::{align_down, align_up, zero_fill};
use crate::error::{Result, ValkyrieError};
use crate::loader::Loader;
use crate::logger::Logger;
use crate::vtype::{Arch, PAGE_SIZE};

use lief::elf::Binary;
use lief::elf::segment;
use unicorn_engine::unicorn_const::Prot;

pub struct LoaderElf {
    pub load_address: u64,
}

impl LoaderElf {
    pub fn new() -> Self {
        Self { load_address: 0 }
    }
}

impl Loader for LoaderElf {
    fn run(&mut self, vk: &mut Valkyrie) -> Result<()> {
        let elf_path = vk
            .cfg
            .elf_file
            .as_ref()
            .ok_or(ValkyrieError::BadConfig("elf file path is missing"))?;

        let elf =
            Binary::parse(elf_path).ok_or(ValkyrieError::Loader("failed to parse ELF file"))?;

        let entry = elf.header().entrypoint();
        if vk.cfg.entry_point == 0 {
            vk.cfg.entry_point = entry;
        }

        let mut min_addr = u64::MAX;
        let mut max_addr = 0u64;

        for seg in elf.segments() {
            if seg.p_type() != segment::Type::LOAD {
                continue;
            }

            let vaddr = seg.virtual_address();
            let vsize = seg.virtual_size();
            if vsize == 0 {
                continue;
            }

            let page_size = PAGE_SIZE as u64;
            let aligned_start = align_down(vaddr, page_size);
            let aligned_end = align_up(vaddr.saturating_add(vsize), page_size);
            let map_size = aligned_end.saturating_sub(aligned_start);

            let prot = prot_from_flags(seg.flags());
            vk.mem
                .map(&mut vk.uc, aligned_start, map_size, prot, "[elf]")?; // TODO : set segment name here

            let content = seg.content();
            if !content.is_empty() {
                vk.mem.write(&mut vk.uc, vaddr, content)?;
            }

            let bss_size = vsize.saturating_sub(content.len() as u64);
            if bss_size > 0 {
                zero_fill(&mut vk.uc, vaddr + content.len() as u64, bss_size)?;
            }

            min_addr = min_addr.min(aligned_start);
            max_addr = max_addr.max(aligned_end);
        }

        if min_addr == u64::MAX {
            return Err(ValkyrieError::Loader("no loadable ELF segments"));
        }

        self.load_address = min_addr;
        vk.mem.code_addr_start = min_addr;
        vk.mem.code_addr_exit = max_addr;

        let stack_size = vk.cfg.stack_size;
        if stack_size == 0 {
            return Err(ValkyrieError::BadConfig("stack_size must be > 0"));
        }

        let heap_size = vk.cfg.heap_size;
        if heap_size == 0 {
            return Err(ValkyrieError::BadConfig("heap_size must be > 0"));
        }

        vk.mem.tls_addr_start = align_up(max_addr + PAGE_SIZE as u64, PAGE_SIZE as u64);
        vk.mem.tls_addr_exit = vk.mem.tls_addr_start + PAGE_SIZE as u64;

        let stack_addr = align_up(vk.mem.tls_addr_exit + PAGE_SIZE as u64, PAGE_SIZE as u64);
        vk.mem.stack_addr_start = stack_addr;
        vk.mem.stack_addr_exit = stack_addr + stack_size;
        vk.mem.map(
            &mut vk.uc,
            vk.mem.stack_addr_start,
            stack_size,
            Prot::ALL,
            "[stack]",
        )?;

        let heap_addr = align_up(vk.mem.stack_addr_exit + PAGE_SIZE as u64, PAGE_SIZE as u64);
        vk.mem.heap_addr_start = heap_addr;
        vk.mem.heap_addr_exit = heap_addr + heap_size;

        vk.mem.map(
            &mut vk.uc,
            vk.mem.heap_addr_start,
            heap_size,
            Prot::ALL,
            "[heap]",
        )?;

        if vk.cfg.verbose {
            Logger::debug(
                format!(
                    "LoaderElf: entry={entry:#x} load_address={min_addr:#x} max_addr={max_addr:#x}",
                ),
                vk.cfg.verbose,
            );
        }

        let sp = vk.mem.stack_addr_exit.saturating_sub(0x10);
        vk.arch.regs.set_reg(
            &mut vk.uc,
            match vk.cfg.arch {
                Arch::X86 => VRegister::X86(RegX86::ESP),
                Arch::X86_64 => VRegister::X86_64(RegX86_64::RSP),
            },
            sp,
        )?;

        Ok(())
    }

    fn load_address(&self) -> u64 {
        self.load_address
    }
}

impl Default for LoaderElf {
    fn default() -> Self {
        Self::new()
    }
}

fn prot_from_flags(flags: u32) -> Prot {
    let flags = segment::Flags::from_value(flags);
    let mut prot = Prot::NONE;
    if flags.contains(segment::Flags::R) {
        prot |= Prot::READ;
    }
    if flags.contains(segment::Flags::W) {
        prot |= Prot::WRITE;
    }
    if flags.contains(segment::Flags::X) {
        prot |= Prot::EXEC;
    }
    prot
}
