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

pub const PAGE_SIZE: u32 = 0x1000; //4Kb page
pub const MAX_PATH_LEN: usize = 4096; // max path length

pub const O_RDONLY: u64 = 0;
pub const O_WRONLY: u64 = 1;
pub const O_RDWR: u64 = 2;
pub const O_CREAT: u64 = 0x40;
pub const O_TRUNC: u64 = 0x200;
pub const O_APPEND: u64 = 0x400;
