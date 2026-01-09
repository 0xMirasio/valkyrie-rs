use std::fs;
use std::path::Path;

use valkyrie_rs::arch::regs::VRegister;
use valkyrie_rs::arch::x86_64::RegX86_64;
use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{Valkyrie, ValkyrieConfig};

// write(1, "hello, world!\n", 14)
pub const HELLO_WRITE_X86_64: [u8; 53] = [
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1        ; SYS_write
    0xBF, 0x01, 0x00, 0x00, 0x00, // mov edi, 1        ; fd=stdout
    0x48, 0x83, 0xEC, 0x10, // sub rsp, 0x10
    0x48, 0xBB, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x77, // mov rbx, 0x77202c6f6c6c6568
    0x48, 0x89, 0x1C, 0x24, // mov [rsp], rbx
    0x48, 0xBB, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x0a, 0x00,
    0x00, // mov rbx, 0x0000000a21646c726f
    0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+8], rbx
    0x48, 0x89, 0xE6, // mov rsi, rsp
    0xBA, 0x0E, 0x00, 0x00, 0x00, // mov edx, 14
    0x0F, 0x05, // syscall
];

// open("/tmp/.f"), write("test"), close(), open("/tmp/.f"), read(fd), write(stdout), close(fd)
pub const IO_WRITE_READ_X86_64: [u8; 176] = [
    0x48, 0xBB, 0x2F, 0x74, 0x6D, 0x70, 0x2F, 0x2E, 0x66,
    0x00, // movabs rbx, 0x00662e2f706d742f  ; "/tmp/.f\0"
    0x53, // push rbx
    0x49, 0x89, 0xE5, // mov r13, rsp               ; r13 = path ptr
    0x68, 0x74, 0x65, 0x73, 0x74, // push 0x74736574            ; "test"
    0x49, 0x89, 0xE6, // mov r14, rsp               ; r14 = data ptr
    0xB8, 0x01, 0x01, 0x00, 0x00, // mov eax, 0x101             ; SYS_openat
    0xBF, 0x9C, 0xFF, 0xFF, 0xFF, // mov edi, 0xffffff9c        ; AT_FDCWD
    0x4C, 0x89, 0xEE, // mov rsi, r13               ; pathname
    0xBA, 0x42, 0x00, 0x00, 0x00, // mov edx, 0x42              ; flags
    0x41, 0xBA, 0xA4, 0x01, 0x00, 0x00, // mov r10d, 0x1a4            ; mode
    0x0F, 0x05, // syscall
    0x49, 0x89, 0xC4, // mov r12, rax               ; fd
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1                 ; SYS_write
    0x4C, 0x89, 0xE7, // mov rdi, r12               ; fd
    0x4C, 0x89, 0xF6, // mov rsi, r14               ; buf
    0xBA, 0x04, 0x00, 0x00, 0x00, // mov edx, 4                 ; len
    0x0F, 0x05, // syscall
    0xB8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3                 ; SYS_close
    0x4C, 0x89, 0xE7, // mov rdi, r12               ; fd
    0x0F, 0x05, // syscall
    0xB8, 0x01, 0x01, 0x00, 0x00, // mov eax, 0x101             ; SYS_openat
    0xBF, 0x9C, 0xFF, 0xFF, 0xFF, // mov edi, 0xffffff9c        ; AT_FDCWD
    0x4C, 0x89, 0xEE, // mov rsi, r13               ; pathname
    0xBA, 0x42, 0x00, 0x00, 0x00, // mov edx, 0x42              ; flags
    0x41, 0xBA, 0xA4, 0x01, 0x00, 0x00, // mov r10d, 0x1a4            ; mode
    0x0F, 0x05, // syscall
    0x49, 0x89, 0xC4, // mov r12, rax               ; fd
    0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00, // sub rsp, 0x100
    0x49, 0x89, 0xE7, // mov r15, rsp               ; r15 = buf
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0                 ; SYS_read
    0x4C, 0x89, 0xE7, // mov rdi, r12               ; fd
    0x4C, 0x89, 0xFE, // mov rsi, r15               ; buf
    0xBA, 0x00, 0x01, 0x00, 0x00, // mov edx, 0x100             ; count
    0x0F, 0x05, // syscall
    0x48, 0x89, 0xC3, // mov rbx, rax               ; bytes read
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1                 ; SYS_write
    0xBF, 0x01, 0x00, 0x00, 0x00, // mov edi, 1                 ; stdout
    0x4C, 0x89, 0xFE, // mov rsi, r15               ; buf
    0x48, 0x89, 0xDA, // mov rdx, rbx               ; len
    0x0F, 0x05, // syscall
    0xB8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3                 ; SYS_close
    0x4C, 0x89, 0xE7, // mov rdi, r12               ; fd
    0x0F, 0x05, // syscall
    0xB8, 0x3C, 0x00, 0x00, 0x00, // mov eax, 60                ; SYS_exit
    0x31, 0xFF, // xor edi, edi               ; status = 0
    0x0F, 0x05, // syscall
];

#[test]
fn integration_syscall_write_x86_64_linux() {
    let rootfs_path = Path::new("/");
    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .entry_point(0x400000)
    .feed_baremetal(&HELLO_WRITE_X86_64)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();

    let rsp = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86_64(RegX86_64::RSP))
        .unwrap();

    vk.run().unwrap();

    let rax = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86_64(RegX86_64::RAX))
        .unwrap();

    assert_eq!(rax, 14, "write() should return 14, got {rax}");

    let trap_addr = vk.exit_trap_addr.expect("exit trap not set");
    let stack_bytes = vk.mem.read(&mut vk.uc, rsp, 8).unwrap();
    let trapped = u64::from_le_bytes(stack_bytes.try_into().unwrap());
    assert_eq!(trapped, trap_addr);
}

#[test]
fn integration_syscall_multiple_io_x86_64_linux() {
    let rootfs_path = Path::new("/");

    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .entry_point(0x400000)
    .feed_baremetal(&IO_WRITE_READ_X86_64)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();

    let rsp = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86_64(RegX86_64::RSP))
        .unwrap();

    let _ = fs::remove_file("/tmp/.f");
    vk.run().unwrap();

    let trap_addr = vk.exit_trap_addr.expect("exit trap not set");
    let stack_bytes = vk.mem.read(&mut vk.uc, rsp, 8).unwrap();
    let trapped = u64::from_le_bytes(stack_bytes.try_into().unwrap());
    assert_eq!(trapped, trap_addr);

    let p = Path::new("/tmp/.f");
    assert!(p.exists(), "expected {p:?} to exist after vk.run()");

    let content = fs::read(p).expect("failed to read /tmp/.f");
    assert_eq!(
        content, b"test",
        "unexpected content in /tmp/.f: {content:?}"
    );
}
