use crate::Valkyrie;
use crate::arch::regs::VRegister;
use crate::arch::x86::RegX86;
use crate::arch::x86_64::RegX86_64;
use crate::common::{align_down, align_up, zero_fill};
use crate::error::{Result, ValkyrieError};
use crate::fs::resolve_guest_path;
use crate::loader::Loader;
use crate::logger::Logger;
use crate::vtype::{Arch, PAGE_SIZE};

use lief::elf::{Binary, header::FileType, section::Flags, segment};
use lief::generic::Section;
use unicorn_engine::unicorn_const::Prot;

pub struct LoaderElf {
    pub load_address: u64,
}

#[derive(Debug, Clone)]
pub struct ElfAuxvInfo {
    pub phdr: u64,
    pub phent: u64,
    pub phnum: u64,
    pub base: u64,
    pub entry: u64,
    pub execfn: String,
}

#[derive(Clone)]
struct SectionSpan {
    start: u64,
    end: u64,
    name: String,
}

#[derive(Debug, Clone)]
struct MappedElf {
    min_addr: u64,
    max_addr: u64,
    entry: u64,
    phdr: u64,
    phent: u64,
    phnum: u64,
    base: u64,
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
            .ok_or(ValkyrieError::BadConfig("elf file path is missing"))?
            .clone();

        let elf =
            Binary::parse(&elf_path).ok_or(ValkyrieError::Loader("failed to parse ELF file"))?;

        let main = map_elf_binary(vk, &elf, 0, None)?;

        let runtime_entry = if has_interp(&elf) {
            let interp_guest_path = elf.interpreter();
            let interp_host_path = resolve_guest_path(vk, &interp_guest_path);
            let interp = Binary::parse(&interp_host_path)
                .ok_or(ValkyrieError::Loader("failed to parse ELF interpreter"))?;
            let interp = map_elf_binary(vk, &interp, choose_shared_object_base(vk), Some("ld.so"))?;

            vk.elf_auxv = Some(ElfAuxvInfo {
                phdr: main.phdr,
                phent: main.phent,
                phnum: main.phnum,
                base: interp.base,
                entry: main.entry,
                execfn: elf_path.clone(),
            });

            self.load_address = main.min_addr.min(interp.min_addr);
            vk.mem.code_addr_start = self.load_address;
            vk.mem.code_addr_exit = main.max_addr.max(interp.max_addr);
            interp.entry
        } else {
            vk.elf_auxv = Some(ElfAuxvInfo {
                phdr: main.phdr,
                phent: main.phent,
                phnum: main.phnum,
                base: 0,
                entry: main.entry,
                execfn: elf_path.clone(),
            });

            self.load_address = main.min_addr;
            vk.mem.code_addr_start = main.min_addr;
            vk.mem.code_addr_exit = main.max_addr;
            main.entry
        };

        if vk.cfg.entry_point == 0 {
            vk.cfg.entry_point = runtime_entry;
        }

        let max_addr = vk.mem.code_addr_exit;

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
                    "LoaderElf: entry={runtime_entry:#x} load_address={:#x} max_addr={max_addr:#x}",
                    self.load_address,
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

fn has_interp(elf: &Binary) -> bool {
    elf.segments()
        .any(|seg| seg.p_type() == segment::Type::INTERP)
}

fn choose_shared_object_base(vk: &Valkyrie) -> u64 {
    let guard_gap = 0x0100_0000_u64;
    let highest = vk
        .mem
        .regions
        .iter()
        .map(|region| region.start.saturating_add(region.size))
        .max()
        .unwrap_or(0);
    align_up(highest.saturating_add(guard_gap), PAGE_SIZE as u64)
}

fn map_elf_binary(
    vk: &mut Valkyrie,
    elf: &Binary,
    base_hint: u64,
    name_prefix: Option<&str>,
) -> Result<MappedElf> {
    let load_bias = match elf.header().file_type() {
        FileType::DYN => base_hint,
        _ => 0,
    };
    let alloc_sections = collect_alloc_sections(elf);
    let mut min_addr = u64::MAX;
    let mut max_addr = 0u64;

    for seg in elf.segments() {
        if seg.p_type() != segment::Type::LOAD {
            continue;
        }

        let vaddr = load_bias.saturating_add(seg.virtual_address());
        let vsize = seg.virtual_size();
        if vsize == 0 {
            continue;
        }

        let page_size = PAGE_SIZE as u64;
        let aligned_start = align_down(vaddr, page_size);
        let aligned_end = align_up(vaddr.saturating_add(vsize), page_size);
        let prot = prot_from_flags(seg.flags());

        map_segment_by_section(
            vk,
            aligned_start,
            aligned_end,
            prot,
            &alloc_sections,
            page_size,
            name_prefix,
        )?;

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

    Ok(MappedElf {
        min_addr,
        max_addr,
        entry: load_bias.saturating_add(elf.header().entrypoint()),
        phdr: program_headers_addr(elf, load_bias)?,
        phent: elf.header().program_header_size() as u64,
        phnum: elf.header().numberof_segments() as u64,
        base: load_bias,
    })
}

fn program_headers_addr(elf: &Binary, load_bias: u64) -> Result<u64> {
    let phoff = elf.header().program_headers_offset();
    let phsize = elf.header().program_header_size() as u64;
    let phnum = elf.header().numberof_segments() as u64;
    let phend = phoff.saturating_add(phsize.saturating_mul(phnum));

    for seg in elf.segments() {
        if seg.p_type() != segment::Type::LOAD {
            continue;
        }

        let file_start = seg.file_offset();
        let file_end = file_start.saturating_add(seg.physical_size());
        if phoff >= file_start && phend <= file_end {
            return Ok(load_bias
                .saturating_add(seg.virtual_address())
                .saturating_add(phoff.saturating_sub(file_start)));
        }
    }

    Err(ValkyrieError::Loader(
        "failed to locate mapped ELF program headers",
    ))
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

fn collect_alloc_sections(elf: &Binary) -> Vec<SectionSpan> {
    let mut sections = elf
        .sections()
        .filter_map(|section| {
            if !section.flags().contains(Flags::ALLOC) {
                return None;
            }

            let size = section.size();
            if size == 0 {
                return None;
            }

            let start = section.virtual_address();
            let end = start.saturating_add(size);
            if start >= end {
                return None;
            }

            let name = section.name();
            if name.is_empty() {
                return None;
            }

            Some(SectionSpan {
                start,
                end,
                name: name.to_string(),
            })
        })
        .collect::<Vec<_>>();

    sections.sort_by_key(|section| section.start);
    sections
}

fn section_name_for_page(page_start: u64, page_end: u64, sections: &[SectionSpan]) -> String {
    let mut best_name = "segment";
    let mut best_overlap = 0u64;

    for section in sections {
        if section.end <= page_start || section.start >= page_end {
            continue;
        }

        let overlap_start = page_start.max(section.start);
        let overlap_end = page_end.min(section.end);
        let overlap = overlap_end.saturating_sub(overlap_start);
        if overlap > best_overlap {
            best_overlap = overlap;
            best_name = &section.name;
        }
    }

    format!("[{best_name}]")
}

fn map_segment_by_section(
    vk: &mut Valkyrie,
    aligned_start: u64,
    aligned_end: u64,
    prot: Prot,
    sections: &[SectionSpan],
    page_size: u64,
    name_prefix: Option<&str>,
) -> Result<()> {
    let mut chunk_start = aligned_start;
    let mut current = aligned_start;
    let mut chunk_label = prefixed_section_name(
        section_name_for_page(current, current + page_size, sections),
        name_prefix,
    );

    while current < aligned_end {
        let next = current + page_size;
        let next_label = if next < aligned_end {
            prefixed_section_name(
                section_name_for_page(next, next + page_size, sections),
                name_prefix,
            )
        } else {
            chunk_label.clone()
        };

        if next >= aligned_end || next_label != chunk_label {
            vk.mem.map(
                &mut vk.uc,
                chunk_start,
                next.saturating_sub(chunk_start),
                prot,
                chunk_label.clone(),
            )?;

            chunk_start = next;
            chunk_label = next_label;
        }

        current = next;
    }

    Ok(())
}

fn prefixed_section_name(section_name: String, name_prefix: Option<&str>) -> String {
    if let Some(prefix) = name_prefix {
        return format!("[{prefix}:{}]", section_name.trim_matches(['[', ']']));
    }

    section_name
}
