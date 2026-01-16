use crate::Valkyrie;
use crate::config::ValkyrieConfig;
use crate::error::{Result, ValkyrieError};
use crate::logger::Logger;
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
    pub regions: Vec<VMemRegion>,
    disassembler: Option<Capstone>,
    pub heap_addr_start: u64,
    pub heap_addr_exit: u64,
    pub stack_addr_start: u64,
    pub stack_addr_exit: u64,
    pub code_addr_start: u64,
    pub code_addr_exit: u64,
    pub tls_addr_start: u64,
    pub tls_addr_exit: u64,
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
            heap_addr_start: 0,
            heap_addr_exit: 0,
            stack_addr_start: 0,
            stack_addr_exit: 0,
            code_addr_start: 0,
            code_addr_exit: 0,
            tls_addr_start: 0,
            tls_addr_exit: 0,
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

    pub fn dump_stacks(vk: &mut Valkyrie) {
        Logger::info("== Stack memory dump ==");

        let sp = match vk.arch.regs.get_sp(&mut vk.uc) {
            Ok(v) => v,
            Err(e) => {
                Logger::warning(format!("dump_stacks(): failed to read SP: {e}"));
                return;
            }
        };

        if sp == 0 {
            Logger::warning("dump_stacks(): SP is 0");
            return;
        }

        let start = sp.saturating_sub(16);
        let end = sp.saturating_add(16);
        let len = (end - start) as usize;

        let buf = match vk.mem.read(&mut vk.uc, start, len) {
            Ok(b) => b,
            Err(e) => {
                Logger::warning(format!("dump_stacks(): mem.read failed at {start:#x}: {e}"));
                return;
            }
        };

        println!("SP: {sp:#x} | dumping [{start:#x}..{end:#x}]");

        for (i, chunk) in buf.chunks(16).enumerate() {
            let addr = start + (i * 16) as u64;

            let hex = chunk
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");

            let ascii = chunk
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect::<String>();

            println!("{addr:#018x}: {hex:<47} |{ascii}|");
        }
    }

    pub fn region_for(&self, addr: u64) -> Option<&VMemRegion> {
        self.regions
            .iter()
            .find(|region| addr >= region.start && addr < region.start + region.size)
    }

    pub fn show_instructions(vk: &mut Valkyrie, addr: u64, size: usize) -> Result<()> {
        if size == 0 {
            return Ok(());
        }

        let insns = vk.mem.disassemble(&mut vk.uc, addr, size)?;
        if insns.is_empty() {
            Logger::warning(format!(
                "disassembler produced no instructions at {addr:#x}"
            ));
            return Ok(());
        }

        let pending_updates = vk.arch.regs.take_reg_updates();
        for (i, insn) in insns.into_iter().enumerate() {
            // On affiche les updates sur la prochaine instruction (la 1ère qu'on imprime ici)
            if i == 0 && !pending_updates.is_empty() {
                let regs = pending_updates
                    .iter()
                    .map(|u| format!("{:?}={:#x}", u.reg, u.value))
                    .collect::<Vec<_>>()
                    .join(", ");

                Logger::info(format!("{insn} ; {regs}"));
            } else {
                Logger::info(insn);
            }
        }

        Ok(())
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

        Ok(insns.iter().map(|i| format!("{i}")).collect())
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
