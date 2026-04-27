use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use unicorn_engine::unicorn_const::Prot;

use crate::error::Result;
use crate::memory::VMemRegion;
use crate::vtype::TraceFormat;

#[derive(Debug, Clone)]
pub struct TraceOptions {
    pub format: TraceFormat,
    pub output: PathBuf,
}

impl TraceOptions {
    pub fn new(format: TraceFormat) -> Self {
        Self {
            format,
            output: default_trace_output_path(format),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ModuleKey {
    base: u64,
    end: u64,
    path: String,
}

#[derive(Debug, Clone)]
struct DrcovModule {
    base: u64,
    end: u64,
    path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DrcovBbEntry {
    start: u32,
    size: u16,
    module_id: u16,
}

#[derive(Debug)]
pub struct TraceRecorder {
    options: TraceOptions,
    modules: Vec<DrcovModule>,
    module_ids: HashMap<ModuleKey, u16>,
    bb_entries: Vec<DrcovBbEntry>,
    bb_set: HashSet<DrcovBbEntry>,
}

impl TraceRecorder {
    pub fn new(options: TraceOptions) -> Self {
        Self {
            options,
            modules: Vec::new(),
            module_ids: HashMap::new(),
            bb_entries: Vec::new(),
            bb_set: HashSet::new(),
        }
    }

    pub fn output_path(&self) -> &Path {
        &self.options.output
    }

    pub fn record_block(
        &mut self,
        addr: u64,
        size: u32,
        regions: &[VMemRegion],
        main_elf_path: Option<&str>,
    ) {
        if size == 0 {
            return;
        }

        let Some(region) = region_for_exec_addr(regions, addr) else {
            return;
        };
        let module_end = region.start.saturating_add(region.size);
        if addr >= module_end {
            return;
        }

        let module_id = self.ensure_module(region, main_elf_path);
        let offset = addr.saturating_sub(region.start);
        if offset > u32::MAX as u64 {
            return;
        }

        let max_size = module_end.saturating_sub(addr);
        if max_size == 0 {
            return;
        }

        let mut bb_size = (size as u64).min(max_size);
        if bb_size > u16::MAX as u64 {
            bb_size = u16::MAX as u64;
        }
        if bb_size == 0 {
            return;
        }

        let entry = DrcovBbEntry {
            start: offset as u32,
            size: bb_size as u16,
            module_id,
        };
        if self.bb_set.insert(entry) {
            self.bb_entries.push(entry);
        }
    }

    pub fn flush(&self) -> Result<()> {
        match self.options.format {
            TraceFormat::Drcov => self.write_drcov(),
        }
    }

    fn ensure_module(&mut self, region: &VMemRegion, main_elf_path: Option<&str>) -> u16 {
        let path = module_path_for_region(region, main_elf_path);
        let key = ModuleKey {
            base: region.start,
            end: region.start.saturating_add(region.size),
            path: path.clone(),
        };

        if let Some(&id) = self.module_ids.get(&key) {
            return id;
        }

        let id = if self.modules.len() > u16::MAX as usize {
            u16::MAX
        } else {
            self.modules.len() as u16
        };
        self.modules.push(DrcovModule {
            base: key.base,
            end: key.end,
            path: key.path.clone(),
        });
        self.module_ids.insert(key, id);
        id
    }

    fn write_drcov(&self) -> Result<()> {
        if let Some(parent) = self.options.output.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let mut writer = BufWriter::new(File::create(&self.options.output)?);
        writeln!(writer, "DRCOV VERSION: 2")?;
        writeln!(writer, "DRCOV FLAVOR: drcov")?;
        writeln!(
            writer,
            "Module Table: version 2, count {}",
            self.modules.len()
        )?;
        writeln!(
            writer,
            "Columns: id, base, end, entry, checksum, timestamp, path"
        )?;

        for (id, module) in self.modules.iter().enumerate() {
            writeln!(
                writer,
                "{id}, {:#x}, {:#x}, 0x0, 0x0, 0x0, {}",
                module.base, module.end, module.path
            )?;
        }

        let mut entries = self.bb_entries.clone();
        entries.sort_by_key(|entry| (entry.module_id, entry.start, entry.size));
        writeln!(writer, "BB Table: {} bbs", entries.len())?;
        for entry in entries {
            writer.write_all(&entry.start.to_le_bytes())?;
            writer.write_all(&entry.size.to_le_bytes())?;
            writer.write_all(&entry.module_id.to_le_bytes())?;
        }
        writer.flush()?;
        Ok(())
    }
}

fn default_trace_output_path(format: TraceFormat) -> PathBuf {
    match format {
        TraceFormat::Drcov => PathBuf::from("valkyrie_trace.drcov"),
    }
}

fn region_for_exec_addr(regions: &[VMemRegion], addr: u64) -> Option<&VMemRegion> {
    regions.iter().find(|region| {
        (region.prot & Prot::EXEC) == Prot::EXEC
            && addr >= region.start
            && addr < region.start.saturating_add(region.size)
    })
}

fn module_path_for_region(region: &VMemRegion, main_elf_path: Option<&str>) -> String {
    if let Some(main_elf_path) = main_elf_path
        && (region.info.starts_with("[.") || region.info == "[segment]")
    {
        return main_elf_path.to_string();
    }

    if region.info.starts_with('[') && region.info.ends_with(']') && region.info.len() >= 2 {
        return region.info[1..region.info.len() - 1].to_string();
    }

    region.info.clone()
}
