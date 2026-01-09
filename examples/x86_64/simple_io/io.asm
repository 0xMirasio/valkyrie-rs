; x86-64 Linux, NASM
; Behavior:
; 1) openat(AT_FDCWD, "/tmp/.f", O_RDWR|O_CREAT, 0644)
; 2) write(fd, "test", 4)
; 3) close(fd)
; 4) openat("/tmp/.f") 
; 5) read(fd, buf, 256)
; 6) write(1, buf, nread)
; 7) close(fd)
; 8) exit(0)

BITS 64
GLOBAL _start

%define SYS_read    0
%define SYS_write   1
%define SYS_close   3
%define SYS_openat  257
%define SYS_exit    60

%define AT_FDCWD    -100

%define O_RDWR      2
%define O_CREAT     64
%define FLAGS       (O_RDWR | O_CREAT)

_start:
    ; --- push "/tmp/.f\0" on stack ---
    mov     rbx, 0x00662e2f706d742f     ; "/tmp/.f\0" little-endian
    push    rbx
    mov     r13, rsp                    ; r13 = path pointer

    ; --- Build "test" on stack ---
    push    dword 0x74736574            ; "test" (plus 4 zero bytes)
    mov     r14, rsp                    ; r14 = "test" pointer

    ; --- fd = openat(AT_FDCWD, path, FLAGS, 0644) ---
    mov     eax, SYS_openat
    mov     edi, AT_FDCWD
    mov     rsi, r13
    mov     edx, FLAGS
    mov     r10d, 0644o
    syscall
    mov     r12, rax                    ; r12 = fd

    ; --- write(fd, "test", 4) ---
    mov     eax, SYS_write
    mov     rdi, r12
    mov     rsi, r14
    mov     edx, 4
    syscall

    ; --- close(fd) ---
    mov     eax, SYS_close
    mov     rdi, r12
    syscall

    ; --- fd = openat("/tmp/.f") 
    mov     eax, SYS_openat
    mov     edi, AT_FDCWD
    mov     rsi, r13
    mov     edx, FLAGS
    mov     r10d, 0644o
    syscall
    mov     r12, rax

    ; --- Allocate read buffer on stack (256 bytes) ---
    sub     rsp, 256
    mov     r15, rsp                    ; r15 = buf

    ; --- n = read(fd, buf, 256) ---
    mov     eax, SYS_read
    mov     rdi, r12
    mov     rsi, r15
    mov     edx, 256
    syscall
    ; rax = nread
    mov     rbx, rax                    ; save nread

    ; --- write(1, buf, nread) ---
    mov     eax, SYS_write
    mov     edi, 1                      ; stdout
    mov     rsi, r15
    mov     rdx, rbx
    syscall

    ; --- close(fd) ---
    mov     eax, SYS_close
    mov     rdi, r12
    syscall

    ; --- exit(0) ---
    mov     eax, SYS_exit
    xor     edi, edi
    syscall
