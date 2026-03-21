pub use crate::arch;
pub use crate::error::ValkyrieError;
pub use crate::hook::VCoreHooks;
pub use crate::logger::Logger;
pub use crate::vstruct::VCoreStructs;
pub use crate::vtype::{Arch, Endianess, LoaderType, OsType, PAGE_SIZE, VState};

use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ValkyrieConfig {
    pub arch: Arch,               // arch
    pub os: OsType,               // os
    pub loader: LoaderType,       // loader
    pub rootfs: String,           // rootfspath
    pub argv: Vec<Vec<u8>>,       // guest argv
    pub verbose: bool,            // verbosity
    pub endianess: Endianess,     // endianess
    pub archsize: u16,            // archsize
    pub baremetal_code: Vec<u8>,  // user baremetal code
    pub elf_file: Option<String>, // elf file path
    pub entry_point: u64,         // program entrypoint
    pub exit_point: u64,          // program exit_point
    pub code_ram_size: u64,       // program ram size
    pub heap_size: u64,           // program heap size
    pub stack_size: u64,          // program stack size
    pub code_base_address: u64,
    pub count: usize,      // program instruction max count
    pub timeout: u64,      // program execution max timeout
    pub disassemble: bool, // disassemble execution
    pub debug: bool,       // debug mode
    pub debug_port: u16,   // debug server port
}

// implement a new ValkyrieConfig.
impl ValkyrieConfig {
    pub fn new(arch: Arch, os: OsType, rootfs: String) -> Result<Self, ValkyrieError> {
        Logger::info("New Valkyrie instance");

        let path = Path::new(&rootfs);

        if !path.exists() {
            return Err(ValkyrieError::BadConfig("rootfs path does not exist"));
        }

        let (endianess, archsize) = arch::defaults_for_arch(arch);

        Logger::info(format!(
            "guessed arch defaults: arch={arch:?}, archsize={archsize}bit, endianess={endianess:?}"
        ));

        // todo : add profile management
        let code_ram_size: u64 = (PAGE_SIZE as u64) * 10000; // 40000Kb default ram space
        let heap_size: u64 = (PAGE_SIZE as u64) * 100; // 400kb default heap size
        let stack_size: u64 = (PAGE_SIZE as u64) * 100; // 400kb default stack size

        Ok(Self {
            arch,
            os,
            loader: LoaderType::Raw,
            rootfs,
            argv: Vec::new(),
            verbose: false,
            endianess,
            archsize,
            baremetal_code: Vec::new(),
            elf_file: Option::None,
            entry_point: 0,
            exit_point: 0,
            code_ram_size,
            heap_size,
            stack_size,
            code_base_address: 0x400000, // TODO : this address must be set according to arch/size
            count: usize::MAX,           // no instructions limit
            timeout: u64::MAX,           // no timeout limit
            disassemble: false,
            debug: false,
            debug_port: 1234,
        })
    }

    /// Save baremetal blob in config.
    pub fn feed_baremetal(mut self, code: &[u8]) -> Result<Self, ValkyrieError> {
        if code.is_empty() {
            return Err(ValkyrieError::BadConfig("baremetal code must be non-empty"));
        }

        if code.len() as u64 > self.code_ram_size {
            return Err(ValkyrieError::BadConfig(
                "baremetal code exceeds cfg.code_ram_size, increase code_ram_size with .code_ram_size before calling feed_baremetal()",
            ));
        }
        self.loader = LoaderType::Raw;
        self.baremetal_code.clear();
        self.baremetal_code.extend_from_slice(code);

        Ok(self)
    }

    // save code as file
    pub fn feed_file<P: AsRef<Path>>(mut self, path: P) -> Result<Self, ValkyrieError> {
        let path_ref: &Path = path.as_ref();

        let meta = fs::metadata(path_ref).map_err(|e| {
            ValkyrieError::BadConfig(Box::leak(
                format!("file not accessible {}: {}", path_ref.display(), e).into_boxed_str(),
            ))
        })?;
        if !meta.is_file() {
            return Err(ValkyrieError::BadConfig("path is not a regular file"));
        }

        let code = fs::read(path_ref).map_err(|e| {
            ValkyrieError::BadConfig(Box::leak(
                format!("failed to read {}: {}", path_ref.display(), e).into_boxed_str(),
            ))
        })?;

        if code.is_empty() {
            return Err(ValkyrieError::BadConfig("baremetal code must be non-empty"));
        }

        if code.len() as u64 > self.code_ram_size {
            return Err(ValkyrieError::BadConfig(
                "code exceeds cfg.code_ram_size, increase code_ram_size with .code_ram_size before calling feed_file()",
            ));
        }

        self.loader = LoaderType::Raw;
        self.baremetal_code.clear();
        self.baremetal_code.extend_from_slice(&code);
        Ok(self)
    }

    /// ELF feed
    pub fn feed_elf<P: AsRef<Path>>(mut self, path: P) -> Result<Self, ValkyrieError> {
        let path_ref: &Path = path.as_ref();

        let meta = fs::metadata(path_ref).map_err(|e| {
            ValkyrieError::BadConfig(Box::leak(
                format!("file not accessible {}: {}", path_ref.display(), e).into_boxed_str(),
            ))
        })?;
        if !meta.is_file() {
            return Err(ValkyrieError::BadConfig("path is not a regular file"));
        }

        self.loader = LoaderType::Elf;
        self.elf_file = Some(path_ref.to_string_lossy().to_string());
        Ok(self)
    }

    // setter ValkyrieConfig::verbose
    pub fn verbose(mut self, value: bool) -> Self {
        self.verbose = value;
        self
    }

    // setter ValkyrieConfig::argv
    pub fn argv<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<Vec<u8>>,
    {
        self.argv = values.into_iter().map(Into::into).collect();
        self
    }

    //setter ValkyrieConfig::disassemble
    pub fn disassemble(mut self, value: bool) -> Self {
        self.disassemble = value;
        self
    }

    // setter ValkyrieConfig::debug
    pub fn debug(mut self, value: bool) -> Self {
        self.debug = value;
        self
    }

    // setter ValkyrieConfig::debug_port
    pub fn debug_port(mut self, value: u16) -> Self {
        self.debug_port = value;
        self
    }

    // setter ValkyrieConfig::endianess
    pub fn endianess(mut self, value: Endianess) -> Self {
        self.endianess = value;
        self
    }

    // setter ValkyrieConfig::archsize
    pub fn archsize(mut self, value: u16) -> Self {
        self.archsize = value;
        self
    }

    // setter ValkyrieConfig::entry_point
    pub fn entry_point(mut self, value: u64) -> Self {
        self.entry_point = value;
        self
    }

    // setter ValkyrieConfig::code_base_addr
    pub fn code_base_addr(mut self, value: u64) -> Self {
        self.code_base_address = value;
        self
    }

    // setter ValkyrieConfig::exit_point
    pub fn exit_point(mut self, value: u64) -> Self {
        self.exit_point = value;
        self
    }

    // setter ValkyrieConfig::code_ram_size
    pub fn code_ram_size(mut self, value: u64) -> Self {
        self.code_ram_size = value;
        self
    }

    // setter ValkyrieConfig::heap_size
    pub fn heap_size(mut self, value: u64) -> Self {
        self.heap_size = value;
        self
    }

    // setter ValkyrieConfig::stack_size
    pub fn stack_size(mut self, value: u64) -> Self {
        self.stack_size = value;
        self
    }
}
