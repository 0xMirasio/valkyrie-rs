.global _start

.text
_start:
    sub $0x100, %rsp

    xor %eax, %eax
    xor %edi, %edi
    mov %rsp, %rsi
    mov $0x100, %edx
    syscall

    cmpb $'A', (%rsp)
    jne exit_ok
    cmpb $'B', 1(%rsp)
    jne exit_ok
    cmpb $'C', 2(%rsp)
    jne exit_ok

    movb $0x41, 0

exit_ok:
    mov $60, %eax
    xor %edi, %edi
    syscall
