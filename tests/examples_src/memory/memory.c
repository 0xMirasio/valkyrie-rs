#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#include <asm/prctl.h>
#endif

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

int main(void) {
    void *start_brk = sbrk(0);
    if (start_brk == (void *)-1) {
        die("sbrk(start)");
    }

    if (sbrk(0x2000) == (void *)-1) {
        die("sbrk(grow)");
    }

    void *after_brk = sbrk(0);
    if (after_brk == (void *)-1) {
        die("sbrk(after)");
    }
    assert(after_brk > start_brk);

    size_t page = 0x1000;
    char *mem = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        die("mmap");
    }

    strcpy(mem, "mem-ok");
    if (mprotect(mem, page, PROT_READ) != 0) {
        die("mprotect");
    }

    if (munmap(mem, page) != 0) {
        die("munmap");
    }

    puts("test/memory-ok\n");
    return 0;
}