use crate::error::{Result, ValkyrieError};
use crate::util::Logger;

use unicorn_engine::Unicorn;
use unicorn_engine::unicorn_const::Prot;

#[derive(Debug, Clone)]
pub struct VMemRegion {
    pub start: u64,
    pub size: u64,
    pub prot: Prot,
    pub info: &'static str,
}

#[derive(Debug, Default, Clone)]
pub struct VMemory {
    regions: Vec<VMemRegion>,
}

impl VMemory {
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    pub fn map<D>(
        &mut self,
        uc: &mut Unicorn<'_, D>,
        addr: u64,
        size: u64,
        prot: Prot,
        info: &'static str,
    ) -> Result<()> {
        if size == 0 {
            return Err(ValkyrieError::BadConfig("mem.map size must be > 0"));
        }

        uc.mem_map(addr, size, prot)
            .map_err(|_| ValkyrieError::UnicornGeneralError("mem_map failed"))?;

        self.regions.push(VMemRegion {
            start: addr,
            size,
            prot,
            info,
        });

        Ok(())
    }

    pub fn write<D>(&self, uc: &mut Unicorn<'_, D>, addr: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Err(ValkyrieError::BadConfig(
                "mem.write buffer must be non-empty",
            ));
        }

        uc.mem_write(addr, data)
            .map_err(|_| ValkyrieError::UnicornGeneralError("mem_write failed"))?;

        Ok(())
    }

    pub fn read<D>(&self, uc: &mut Unicorn<'_, D>, addr: u64, size: usize) -> Result<Vec<u8>> {
        if size == 0 {
            return Err(ValkyrieError::BadConfig("mem.read size must be > 0"));
        }

        let mut buf = vec![0u8; size];
        uc.mem_read(addr, &mut buf)
            .map_err(|_| ValkyrieError::UnicornGeneralError("mem_read failed"))?;
        Ok(buf)
    }

    pub fn show_mappings(&self) {
        if self.regions.is_empty() {
            Logger::warning("show_mappings() Memory regions mappings is empty");
            return;
        }

        Logger::info("== Memory regions mappings  ==");
        for (i, r) in self.regions.iter().enumerate() {
            Logger::info(&format!(
                "#{i}: {:#x} - {:#x} (size={:#x}) prot={:?} info={}",
                r.start,
                r.start + r.size,
                r.size,
                r.prot,
                r.info
            ));
        }
    }
}
