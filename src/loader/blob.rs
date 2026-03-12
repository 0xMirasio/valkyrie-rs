use crate::Valkyrie;
use crate::arch::regs::VRegister;
use crate::arch::x86::RegX86;
use crate::arch::x86_64::RegX86_64;
use crate::common::align_up;
use crate::error::{Result, ValkyrieError};
use crate::loader::Loader;
use crate::logger::Logger;
use crate::vtype::{Arch, PAGE_SIZE};

use unicorn_engine::unicorn_const::Prot;

pub struct LoaderBlob {
    pub load_address: u64,
}

impl LoaderBlob {
    pub fn new() -> Self {
        Self { load_address: 0 }
    }
}

impl Loader for LoaderBlob {
    fn run(&mut self, vk: &mut Valkyrie) -> Result<()> {
        let entry = vk.cfg.code_base_address;
        let code_size = vk.cfg.code_ram_size;

        if code_size == 0 {
            return Err(ValkyrieError::BadConfig("code_size must be > 0"));
        }

        if vk.cfg.baremetal_code.is_empty() {
            return Err(ValkyrieError::BadConfig("baremetal code must be non-empty"));
        }

        self.load_address = entry;

        // map/write code
        vk.mem
            .map(&mut vk.uc, entry, code_size, Prot::ALL, "[code]")?;
        vk.mem.write(&mut vk.uc, entry, &vk.cfg.baremetal_code)?;

        vk.mem.code_addr_start = vk.cfg.code_base_address;
        vk.mem.code_addr_exit = vk.cfg.code_base_address + code_size;

        // map TLS

        vk.mem.tls_addr_start =
            align_up(vk.mem.code_addr_exit + PAGE_SIZE as u64, PAGE_SIZE as u64);
        vk.mem.tls_addr_exit = vk.mem.tls_addr_start + PAGE_SIZE as u64;

        // map stack

        let stack_addr = align_up(vk.mem.tls_addr_exit + PAGE_SIZE as u64, PAGE_SIZE as u64);
        let stack_size = vk.cfg.stack_size;

        vk.mem.stack_addr_start = stack_addr;
        vk.mem.stack_addr_exit = stack_addr + stack_size;

        if stack_size == 0 {
            return Err(ValkyrieError::BadConfig("stack_size must be > 0"));
        }

        vk.mem.map(
            &mut vk.uc,
            vk.mem.stack_addr_start,
            stack_size,
            Prot::ALL,
            "[stack]",
        )?;

        // Map Heap
        let heap_addr = align_up(vk.mem.stack_addr_exit + PAGE_SIZE as u64, PAGE_SIZE as u64);
        let heap_size = vk.cfg.heap_size;

        vk.mem.heap_addr_start = heap_addr;
        vk.mem.heap_addr_exit = heap_addr + heap_size;

        if heap_size == 0 {
            return Err(ValkyrieError::BadConfig("heap_size must be > 0"));
        }

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
                    "LoaderBlob: code_base_addr={entry:#x} code_ram_size={code_size:#x} heap_size={heap_size:#x} stack_size={stack_size:#x}",
                ),
                vk.cfg.verbose,
            );
        }

        // Stack pointer
        let sp = stack_addr + stack_size - 0x10;
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

impl Default for LoaderBlob {
    fn default() -> Self {
        Self::new()
    }
}
