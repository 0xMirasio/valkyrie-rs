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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VState {
    NotSet,  // emulation not starting
    Running, // emulation running
    Stopped, // emulation is paused
    Ended,   // emulation has finished
}

pub const PAGE_SIZE: u32 = 0x1000; //4Kb page
