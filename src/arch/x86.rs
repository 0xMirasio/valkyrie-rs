use unicorn_engine::Unicorn;
use unicorn_engine::unicorn_const::RegisterX86;

use crate::Valkyrie;
use crate::arch::regs::VRegister;
use crate::error::Result;
use crate::logger::Logger;
use crate::os::register_syscall::{SubCtx, dispatch_syscall_by_name, syscall_name_from_no};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegX86 {
    // GPR 32
    EAX,
    EBX,
    ECX,
    EDX,
    ESI,
    EDI,
    EBP,
    ESP,
    EIP,

    // Flags
    EFLAGS,

    // Segments
    CS,
    SS,
    DS,
    ES,
    FS,
    GS,

    // Segment bases
    FsBase,
    GsBase,

    // Control regs
    CR0,
    CR1,
    CR2,
    CR3,
    CR4,

    // Debug regs
    DR0,
    DR1,
    DR2,
    DR3,
    DR4,
    DR5,
    DR6,
    DR7,

    // x87
    ST0,
    ST1,
    ST2,
    ST3,
    ST4,
    ST5,
    ST6,
    ST7,

    // SSE/AVX registers
    XMM0,
    XMM1,
    XMM2,
    XMM3,
    XMM4,
    XMM5,
    XMM6,
    XMM7,
    XMM8,
    XMM9,
    XMM10,
    XMM11,
    XMM12,
    XMM13,
    XMM14,
    XMM15,
    XMM16,
    XMM17,
    XMM18,
    XMM19,
    XMM20,
    XMM21,
    XMM22,
    XMM23,
    XMM24,
    XMM25,
    XMM26,
    XMM27,
    XMM28,
    XMM29,
    XMM30,
    XMM31,

    YMM0,
    YMM1,
    YMM2,
    YMM3,
    YMM4,
    YMM5,
    YMM6,
    YMM7,
    YMM8,
    YMM9,
    YMM10,
    YMM11,
    YMM12,
    YMM13,
    YMM14,
    YMM15,
    YMM16,
    YMM17,
    YMM18,
    YMM19,
    YMM20,
    YMM21,
    YMM22,
    YMM23,
    YMM24,
    YMM25,
    YMM26,
    YMM27,
    YMM28,
    YMM29,
    YMM30,
    YMM31,

    ZMM0,
    ZMM1,
    ZMM2,
    ZMM3,
    ZMM4,
    ZMM5,
    ZMM6,
    ZMM7,
    ZMM8,
    ZMM9,
    ZMM10,
    ZMM11,
    ZMM12,
    ZMM13,
    ZMM14,
    ZMM15,
    ZMM16,
    ZMM17,
    ZMM18,
    ZMM19,
    ZMM20,
    ZMM21,
    ZMM22,
    ZMM23,
    ZMM24,
    ZMM25,
    ZMM26,
    ZMM27,
    ZMM28,
    ZMM29,
    ZMM30,
    ZMM31,
}

fn to_uc(reg: RegX86) -> RegisterX86 {
    match reg {
        RegX86::EAX => RegisterX86::EAX,
        RegX86::EBX => RegisterX86::EBX,
        RegX86::ECX => RegisterX86::ECX,
        RegX86::EDX => RegisterX86::EDX,
        RegX86::ESI => RegisterX86::ESI,
        RegX86::EDI => RegisterX86::EDI,
        RegX86::EBP => RegisterX86::EBP,
        RegX86::ESP => RegisterX86::ESP,
        RegX86::EIP => RegisterX86::EIP,

        RegX86::EFLAGS => RegisterX86::EFLAGS,

        RegX86::CS => RegisterX86::CS,
        RegX86::SS => RegisterX86::SS,
        RegX86::DS => RegisterX86::DS,
        RegX86::ES => RegisterX86::ES,
        RegX86::FS => RegisterX86::FS,
        RegX86::GS => RegisterX86::GS,

        RegX86::FsBase => RegisterX86::FS_BASE,
        RegX86::GsBase => RegisterX86::GS_BASE,

        RegX86::CR0 => RegisterX86::CR0,
        RegX86::CR1 => RegisterX86::CR1,
        RegX86::CR2 => RegisterX86::CR2,
        RegX86::CR3 => RegisterX86::CR3,
        RegX86::CR4 => RegisterX86::CR4,

        RegX86::DR0 => RegisterX86::DR0,
        RegX86::DR1 => RegisterX86::DR1,
        RegX86::DR2 => RegisterX86::DR2,
        RegX86::DR3 => RegisterX86::DR3,
        RegX86::DR4 => RegisterX86::DR4,
        RegX86::DR5 => RegisterX86::DR5,
        RegX86::DR6 => RegisterX86::DR6,
        RegX86::DR7 => RegisterX86::DR7,

        RegX86::ST0 => RegisterX86::ST0,
        RegX86::ST1 => RegisterX86::ST1,
        RegX86::ST2 => RegisterX86::ST2,
        RegX86::ST3 => RegisterX86::ST3,
        RegX86::ST4 => RegisterX86::ST4,
        RegX86::ST5 => RegisterX86::ST5,
        RegX86::ST6 => RegisterX86::ST6,
        RegX86::ST7 => RegisterX86::ST7,

        RegX86::XMM0 => RegisterX86::XMM0,
        RegX86::XMM1 => RegisterX86::XMM1,
        RegX86::XMM2 => RegisterX86::XMM2,
        RegX86::XMM3 => RegisterX86::XMM3,
        RegX86::XMM4 => RegisterX86::XMM4,
        RegX86::XMM5 => RegisterX86::XMM5,
        RegX86::XMM6 => RegisterX86::XMM6,
        RegX86::XMM7 => RegisterX86::XMM7,
        RegX86::XMM8 => RegisterX86::XMM8,
        RegX86::XMM9 => RegisterX86::XMM9,
        RegX86::XMM10 => RegisterX86::XMM10,
        RegX86::XMM11 => RegisterX86::XMM11,
        RegX86::XMM12 => RegisterX86::XMM12,
        RegX86::XMM13 => RegisterX86::XMM13,
        RegX86::XMM14 => RegisterX86::XMM14,
        RegX86::XMM15 => RegisterX86::XMM15,
        RegX86::XMM16 => RegisterX86::XMM16,
        RegX86::XMM17 => RegisterX86::XMM17,
        RegX86::XMM18 => RegisterX86::XMM18,
        RegX86::XMM19 => RegisterX86::XMM19,
        RegX86::XMM20 => RegisterX86::XMM20,
        RegX86::XMM21 => RegisterX86::XMM21,
        RegX86::XMM22 => RegisterX86::XMM22,
        RegX86::XMM23 => RegisterX86::XMM23,
        RegX86::XMM24 => RegisterX86::XMM24,
        RegX86::XMM25 => RegisterX86::XMM25,
        RegX86::XMM26 => RegisterX86::XMM26,
        RegX86::XMM27 => RegisterX86::XMM27,
        RegX86::XMM28 => RegisterX86::XMM28,
        RegX86::XMM29 => RegisterX86::XMM29,
        RegX86::XMM30 => RegisterX86::XMM30,
        RegX86::XMM31 => RegisterX86::XMM31,

        RegX86::YMM0 => RegisterX86::YMM0,
        RegX86::YMM1 => RegisterX86::YMM1,
        RegX86::YMM2 => RegisterX86::YMM2,
        RegX86::YMM3 => RegisterX86::YMM3,
        RegX86::YMM4 => RegisterX86::YMM4,
        RegX86::YMM5 => RegisterX86::YMM5,
        RegX86::YMM6 => RegisterX86::YMM6,
        RegX86::YMM7 => RegisterX86::YMM7,
        RegX86::YMM8 => RegisterX86::YMM8,
        RegX86::YMM9 => RegisterX86::YMM9,
        RegX86::YMM10 => RegisterX86::YMM10,
        RegX86::YMM11 => RegisterX86::YMM11,
        RegX86::YMM12 => RegisterX86::YMM12,
        RegX86::YMM13 => RegisterX86::YMM13,
        RegX86::YMM14 => RegisterX86::YMM14,
        RegX86::YMM15 => RegisterX86::YMM15,
        RegX86::YMM16 => RegisterX86::YMM16,
        RegX86::YMM17 => RegisterX86::YMM17,
        RegX86::YMM18 => RegisterX86::YMM18,
        RegX86::YMM19 => RegisterX86::YMM19,
        RegX86::YMM20 => RegisterX86::YMM20,
        RegX86::YMM21 => RegisterX86::YMM21,
        RegX86::YMM22 => RegisterX86::YMM22,
        RegX86::YMM23 => RegisterX86::YMM23,
        RegX86::YMM24 => RegisterX86::YMM24,
        RegX86::YMM25 => RegisterX86::YMM25,
        RegX86::YMM26 => RegisterX86::YMM26,
        RegX86::YMM27 => RegisterX86::YMM27,
        RegX86::YMM28 => RegisterX86::YMM28,
        RegX86::YMM29 => RegisterX86::YMM29,
        RegX86::YMM30 => RegisterX86::YMM30,
        RegX86::YMM31 => RegisterX86::YMM31,

        RegX86::ZMM0 => RegisterX86::ZMM0,
        RegX86::ZMM1 => RegisterX86::ZMM1,
        RegX86::ZMM2 => RegisterX86::ZMM2,
        RegX86::ZMM3 => RegisterX86::ZMM3,
        RegX86::ZMM4 => RegisterX86::ZMM4,
        RegX86::ZMM5 => RegisterX86::ZMM5,
        RegX86::ZMM6 => RegisterX86::ZMM6,
        RegX86::ZMM7 => RegisterX86::ZMM7,
        RegX86::ZMM8 => RegisterX86::ZMM8,
        RegX86::ZMM9 => RegisterX86::ZMM9,
        RegX86::ZMM10 => RegisterX86::ZMM10,
        RegX86::ZMM11 => RegisterX86::ZMM11,
        RegX86::ZMM12 => RegisterX86::ZMM12,
        RegX86::ZMM13 => RegisterX86::ZMM13,
        RegX86::ZMM14 => RegisterX86::ZMM14,
        RegX86::ZMM15 => RegisterX86::ZMM15,
        RegX86::ZMM16 => RegisterX86::ZMM16,
        RegX86::ZMM17 => RegisterX86::ZMM17,
        RegX86::ZMM18 => RegisterX86::ZMM18,
        RegX86::ZMM19 => RegisterX86::ZMM19,
        RegX86::ZMM20 => RegisterX86::ZMM20,
        RegX86::ZMM21 => RegisterX86::ZMM21,
        RegX86::ZMM22 => RegisterX86::ZMM22,
        RegX86::ZMM23 => RegisterX86::ZMM23,
        RegX86::ZMM24 => RegisterX86::ZMM24,
        RegX86::ZMM25 => RegisterX86::ZMM25,
        RegX86::ZMM26 => RegisterX86::ZMM26,
        RegX86::ZMM27 => RegisterX86::ZMM27,
        RegX86::ZMM28 => RegisterX86::ZMM28,
        RegX86::ZMM29 => RegisterX86::ZMM29,
        RegX86::ZMM30 => RegisterX86::ZMM30,
        RegX86::ZMM31 => RegisterX86::ZMM31,
    }
}

pub fn set_reg<D>(uc: &mut Unicorn<'_, D>, reg: RegX86, value: u64) -> Result<()> {
    // 32-bit regs: on tronque
    uc.reg_write(to_uc(reg), value as u32 as u64)?;
    Ok(())
}

pub fn get_reg<D>(uc: &mut Unicorn<'_, D>, reg: RegX86) -> Result<u64> {
    Ok(uc.reg_read(to_uc(reg))? as u32 as u64)
}

pub fn handle_x86_syscall(vk: &mut Valkyrie, addr: u64, size: u32) -> Result<()> {
    // int 0x80 = 0xCD 0x80
    let insn = vk.mem.read(&mut vk.uc, addr, 2)?;
    if insn != [0xCD, 0x80] {
        return Ok(());
    }

    // Linux i386 int 0x80 ABI:
    // eax = no, ebx/ecx/edx/esi/edi/ebp = args
    let syscall_no = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86(RegX86::EAX))?;
    let arg0 = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86(RegX86::EBX))?;
    let arg1 = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86(RegX86::ECX))?;
    let arg2 = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86(RegX86::EDX))?;
    let arg3 = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86(RegX86::ESI))?;
    let arg4 = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86(RegX86::EDI))?;
    let arg5 = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86(RegX86::EBP))?;

    let name = match syscall_name_from_no(syscall_no, vk.cfg.arch) {
        Ok(n) => n,
        Err(_) => {
            Logger::warning(format!("x86 syscall: unknown syscall no={syscall_no}"));
            vk.arch
                .regs
                .set_reg(&mut vk.uc, VRegister::X86(RegX86::EAX), 0)?;
            let step = if size == 0 { 2 } else { size as u64 };
            vk.arch.regs.set_reg(
                &mut vk.uc,
                VRegister::X86(RegX86::EIP),
                addr.saturating_add(step),
            )?;
            return Ok(());
        }
    };

    Logger::debug(
        format!(
            "x86 syscall: no={syscall_no} ({name}) [ebx={arg0:#x}, ecx={arg1:#x}, edx={arg2:#x}]"
        ),
        vk.cfg.verbose,
    );

    let mut subctx = SubCtx::new([arg0, arg1, arg2, arg3, arg4, arg5]);

    let result = match dispatch_syscall_by_name(name, vk, &mut subctx) {
        Ok(v) => v,
        Err(e) => {
            Logger::warning(format!(
                "x86 syscall: failed to handle syscall no={syscall_no} ({name}) | err={e:?}"
            ));
            0
        }
    };

    vk.arch
        .regs
        .set_reg(&mut vk.uc, VRegister::X86(RegX86::EAX), result)?;

    let step = if size == 0 { 2 } else { size as u64 };
    vk.arch.regs.set_reg(
        &mut vk.uc,
        VRegister::X86(RegX86::EIP),
        addr.saturating_add(step),
    )?;

    Ok(())
}
