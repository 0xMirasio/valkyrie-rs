use unicorn_engine::{
    Unicorn,
    unicorn_const::{Arch, Mode, Prot, RegisterX86},
};

pub const SAMPLE_X86_64: [u8; 16] = [
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0xBF, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
    0xC7, 0x00, 0x04, 0x00, 0x00, 0x00, // mov dword ptr [rax], 4 (maked crash here)
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    use unicorn_engine::{
        Unicorn,
        unicorn_const::{Arch, Mode, Prot, RegisterX86},
    };

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64)?;

    // map code
    let base = 0x1000;
    uc.mem_map(base, 0x2000, Prot::ALL)?;
    uc.mem_write(base, &SAMPLE_X86_64)?;

    // map stack
    let stack = 0x8000_0000;
    uc.mem_map(stack - 0x2000, 0x2000, Prot::ALL)?;
    uc.reg_write(RegisterX86::RSP, stack)?;

    // set entry point
    uc.reg_write(RegisterX86::RIP, base)?;

    // start gdb server
    udbserver::udbserver(&mut uc, 1234, base)?;

    // run
    uc.emu_start(base, base + SAMPLE_X86_64.len() as u64, 0, 0)?;
    Ok(())
}
