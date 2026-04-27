#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86,
    X86_64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianess {
    LittleEndian,
    BigEndian,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsType {
    BareMetal, // shellcode
    Linux,     // linux
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderType {
    Raw, // shellcode
    Elf, // linux
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VState {
    NotSet,  // emulation not starting
    Running, // emulation running
    Stopped, // emulation is paused
    Ended,   // emulation has finished
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceFormat {
    Drcov,
}

pub const PAGE_SIZE: u32 = 0x1000; //4Kb page
pub const MAX_PATH_LEN: usize = 4096; // max path length

pub const ARCH_SET_GS: u64 = 0x1001;
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;
pub const ARCH_GET_GS: u64 = 0x1004;

pub const UTSNAME_LEN: usize = 65;
