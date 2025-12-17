use crate::Valkyrie;
use crate::error::{Result, ValkyrieError};
use crate::loader::Loader;

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

        self.load_address = entry; // "for consistency" comme Qiling

        // Map code memory
        vk.uc
            .mem_map(entry, code_size, unicorn_engine::unicorn_const::Prot::ALL)
            .map_err(ValkyrieError::Unicorn)?;

        // Write code
        vk.uc
            .mem_write(entry, &vk.cfg.baremetal_code)
            .map_err(ValkyrieError::Unicorn)?;

        // Map Heap
        let heap_addr = entry + code_size;
        let heap_size = vk.cfg.heap_size;

        if heap_size == 0 {
            return Err(ValkyrieError::BadConfig("heap_size must be > 0"));
        }

        vk.uc
            .mem_map(
                heap_addr,
                heap_size,
                unicorn_engine::unicorn_const::Prot::ALL,
            )
            .map_err(ValkyrieError::Unicorn)?;

        // Stack pointer
        let sp = heap_addr.saturating_sub(0x1000);
        vk.arch.set_sp(&mut vk.uc, sp)?; // tu dois avoir un helper arch

        Ok(())
    }
}
