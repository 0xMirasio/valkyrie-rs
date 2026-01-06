use crate::Valkyrie;
use crate::arch::regs::VRegister;
use crate::arch::x86::RegX86;
use crate::arch::x86_64::RegX86_64;
use crate::error::{Result, ValkyrieError};
use crate::loader::Loader;
use crate::logger::Logger;
use crate::vtype::Arch;

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
        let entry = vk.cfg.entry_point;
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

        // Map Heap
        let heap_addr = entry + code_size;
        let heap_size = vk.cfg.heap_size;

        if vk.cfg.verbose {
            Logger::debug(
                format!(
                    "LoaderBlob: entry={entry:#x} code_ram_size={code_size:#x} heap_size={heap_size:#x}"
                ),
                vk.cfg.verbose,
            );
        }

        if heap_size == 0 {
            return Err(ValkyrieError::BadConfig("heap_size must be > 0"));
        }

        vk.mem
            .map(&mut vk.uc, heap_addr, heap_size, Prot::ALL, "[heap]")?;

        // Stack pointer
        let sp = heap_addr.saturating_sub(0x1000);
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
