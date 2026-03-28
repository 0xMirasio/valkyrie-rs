use crate::Valkyrie;
use crate::common::neg_errno;
use crate::error::Result;
use crate::os::linux::{
    X86_GDT_ENTRY_TLS_MAX, X86_GDT_ENTRY_TLS_MIN, x86_gdt_entry_addr, x86_write_gdt_entry,
};
use crate::os::register_syscall::SubCtx;
use crate::vtype::Arch;

fn current_tid() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) as i64 };
        if tid < 0 {
            return 0;
        }
        tid as u64
    }

    #[cfg(not(target_os = "linux"))]
    {
        unsafe { libc::getpid() as u64 }
    }
}

pub fn sys_gettid(_vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
    Ok(current_tid())
}

pub fn sys_set_tid_address(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let tid_ptr = sctx.arg0();
    let tid = current_tid() as u32;

    if tid_ptr != 0 {
        vk.mem.write(&mut vk.uc, tid_ptr, &tid.to_le_bytes())?;
    }

    Ok(tid as u64)
}

// todo: implement robust list handling
pub fn sys_set_robust_list(_vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
    Ok(0)
}

pub fn sys_get_robust_list(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    let head_ptr = sctx.arg1();
    let len_ptr = sctx.arg2();
    let ptr_size = (vk.cfg.archsize / 8) as usize;
    let zero = vec![0u8; ptr_size];

    if head_ptr != 0 {
        vk.mem.write(&mut vk.uc, head_ptr, &zero)?;
    }

    if len_ptr != 0 {
        vk.mem.write(&mut vk.uc, len_ptr, &zero)?;
    }

    Ok(0)
}

// todo : implement rseq handling
pub fn sys_rseq(_vk: &mut Valkyrie, _sctx: &mut SubCtx) -> Result<u64> {
    Ok(neg_errno(libc::ENOSYS))
}

#[derive(Debug, Clone, Copy)]
struct UserDesc {
    entry_number: u32,
    base_addr: u32,
    limit: u32,
    flags: u32,
}

impl UserDesc {
    fn from_guest(vk: &mut Valkyrie, addr: u64) -> Result<Self> {
        let bytes = vk.mem.read(&mut vk.uc, addr, 16)?;

        Ok(Self {
            entry_number: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            base_addr: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            limit: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            flags: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        })
    }

    fn write_back_entry_number(self, vk: &mut Valkyrie, addr: u64) -> Result<()> {
        vk.mem
            .write(&mut vk.uc, addr, &self.entry_number.to_le_bytes())?;
        Ok(())
    }

    fn seg_32bit(self) -> bool {
        (self.flags & 0x1) != 0
    }

    fn contents(self) -> u32 {
        (self.flags >> 1) & 0x3
    }

    fn read_exec_only(self) -> bool {
        ((self.flags >> 3) & 0x1) != 0
    }

    fn limit_in_pages(self) -> bool {
        ((self.flags >> 4) & 0x1) != 0
    }

    fn seg_not_present(self) -> bool {
        ((self.flags >> 5) & 0x1) != 0
    }

    fn useable(self) -> bool {
        ((self.flags >> 6) & 0x1) != 0
    }

    fn is_empty(self) -> bool {
        self.base_addr == 0
            && self.limit == 0
            && !self.seg_32bit()
            && self.contents() == 0
            && self.read_exec_only()
            && !self.limit_in_pages()
            && self.seg_not_present()
            && !self.useable()
    }
}

fn find_free_tls_entry(vk: &mut Valkyrie) -> Result<Option<u32>> {
    for entry_number in X86_GDT_ENTRY_TLS_MIN..=X86_GDT_ENTRY_TLS_MAX {
        let entry_addr = x86_gdt_entry_addr(vk, entry_number);
        let descriptor = vk.mem.read(&mut vk.uc, entry_addr, 8)?;
        if descriptor.iter().all(|byte| *byte == 0) {
            return Ok(Some(entry_number));
        }
    }

    Ok(None)
}

fn user_desc_access_byte(desc: UserDesc) -> Option<u8> {
    let typ = match desc.contents() {
        0 => {
            if desc.read_exec_only() {
                0x0
            } else {
                0x2
            }
        }
        1 => {
            if desc.read_exec_only() {
                0x4
            } else {
                0x6
            }
        }
        2 => {
            if desc.read_exec_only() {
                0x8
            } else {
                0xA
            }
        }
        _ => return None,
    };

    let present = if desc.seg_not_present() { 0 } else { 0x80 };
    Some(present | 0x60 | 0x10 | typ)
}

fn user_desc_flags(desc: UserDesc) -> u8 {
    let mut flags = 0u8;

    if desc.useable() {
        flags |= 0x1;
    }
    if desc.seg_32bit() {
        flags |= 0x4;
    }
    if desc.limit_in_pages() {
        flags |= 0x8;
    }

    flags
}

fn gdt_desc(base: u32, limit: u32, access: u8, flags: u8) -> [u8; 8] {
    let mut d = [0u8; 8];

    d[0] = (limit & 0xff) as u8;
    d[1] = ((limit >> 8) & 0xff) as u8;
    d[2] = (base & 0xff) as u8;
    d[3] = ((base >> 8) & 0xff) as u8;
    d[4] = ((base >> 16) & 0xff) as u8;
    d[5] = access;
    d[6] = (((limit >> 16) & 0x0f) as u8) | ((flags & 0x0f) << 4);
    d[7] = ((base >> 24) & 0xff) as u8;

    d
}

pub fn sys_set_thread_area(vk: &mut Valkyrie, sctx: &mut SubCtx) -> Result<u64> {
    if vk.cfg.arch != Arch::X86 {
        return Ok(neg_errno(libc::ENOSYS));
    }

    let user_desc_addr = sctx.arg0();
    if user_desc_addr == 0 {
        return Ok(neg_errno(libc::EFAULT));
    }

    let mut desc = UserDesc::from_guest(vk, user_desc_addr)?;
    if desc.limit > 0x000f_ffff {
        return Ok(neg_errno(libc::EINVAL));
    }

    let entry_number = if desc.entry_number == u32::MAX {
        match find_free_tls_entry(vk)? {
            Some(entry_number) => entry_number,
            None => return Ok(neg_errno(libc::ESRCH)),
        }
    } else {
        desc.entry_number
    };

    if !(X86_GDT_ENTRY_TLS_MIN..=X86_GDT_ENTRY_TLS_MAX).contains(&entry_number) {
        return Ok(neg_errno(libc::EINVAL));
    }

    if desc.contents() == 3 {
        return Ok(neg_errno(libc::EINVAL));
    }

    desc.entry_number = entry_number;
    desc.write_back_entry_number(vk, user_desc_addr)?;

    if desc.is_empty() {
        x86_write_gdt_entry(vk, entry_number, [0u8; 8])?;
        return Ok(0);
    }

    let Some(access) = user_desc_access_byte(desc) else {
        return Ok(neg_errno(libc::EINVAL));
    };
    let flags = user_desc_flags(desc);

    x86_write_gdt_entry(
        vk,
        entry_number,
        gdt_desc(desc.base_addr, desc.limit, access, flags),
    )?;

    Ok(0)
}
