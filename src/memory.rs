use crate::config::ValkyrieConfig;
use crate::error::{Result, ValkyrieError};
use crate::util::Logger;
use crate::vtype::Arch;

use capstone::arch::x86::{ArchMode, ArchSyntax};
use capstone::prelude::*;
use unicorn_engine::Unicorn;
use unicorn_engine::unicorn_const::Prot;

#[derive(Debug, Clone)]
pub struct VMemRegion {
    pub start: u64,
    pub size: u64,
    pub prot: Prot,
    pub info: &'static str,
}

#[derive(Debug)]
pub struct VMemory {
    regions: Vec<VMemRegion>,
    disassembler: Option<Capstone>,
}

impl VMemory {
    pub fn new(cfg: &ValkyrieConfig) -> Result<Self> {
        let disassembler = if cfg.disassemble {
            Some(Self::build_disassembler(cfg.arch, cfg.archsize)?)
        } else {
            None
        };

        Ok(Self {
            regions: Vec::new(),
            disassembler,
        })
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
            Logger::info(format!(
                "#{i}: {:#x} - {:#x} (size={:#x}) prot={:?} info={}",
                r.start,
                r.start + r.size,
                r.size,
                r.prot,
                r.info
            ));
        }
    }

    pub fn disassemble<D>(
        &self,
        uc: &mut Unicorn<'_, D>,
        addr: u64,
        size: usize,
    ) -> Result<Vec<String>> {
        let cs = self
            .disassembler
            .as_ref()
            .ok_or(ValkyrieError::Disassembler("disassembler disabled"))?;

        let mut buf = vec![0u8; size];
        uc.mem_read(addr, &mut buf)
            .map_err(|_| ValkyrieError::UnicornGeneralError("mem_read failed"))?;

        let insns = cs
            .disasm_all(&buf, addr)
            .map_err(|_| ValkyrieError::Disassembler("failed to disassemble"))?;

        Ok(insns
            .iter()
            .map(|i| format!("{:#x}: {}", i.address(), i))
            .collect())
    }

    fn build_disassembler(arch: Arch, archsize: u16) -> Result<Capstone> {
        match (arch, archsize) {
            (Arch::X86, 32) => Capstone::new()
                .x86()
                .mode(ArchMode::Mode32)
                .syntax(ArchSyntax::Intel)
                .build()
                .map_err(|_| ValkyrieError::Disassembler("failed to init x86 disassembler")),
            (Arch::X86_64, 64) => Capstone::new()
                .x86()
                .mode(ArchMode::Mode64)
                .syntax(ArchSyntax::Intel)
                .build()
                .map_err(|_| ValkyrieError::Disassembler("failed to init x86_64 disassembler")),
            _ => Err(ValkyrieError::UnsupportedArch(arch)),
        }
    }
}
