#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

int main(void) {
    const char *src = "/tmp/f";
    const char *dst = "/tmp/d";
    const char *text = "test\n";

    // 1) open /tmp/f, write "test\n", close
    int fd = open(src, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) die("open(/tmp/f)");

    ssize_t n = write(fd, text, strlen(text));
    if (n < 0) die("write(/tmp/f)");
    if ((size_t)n != strlen(text)) {
        fprintf(stderr, "short write\n");
        close(fd);
        return 1;
    }

    if (close(fd) < 0) die("close(/tmp/f)");

    long rc = syscall(SYS_renameat2, AT_FDCWD, src, AT_FDCWD, dst, 0);
    if (rc < 0) die("renameat2(/tmp/f -> /tmp/d)");

    fd = open(dst, O_RDONLY);
    if (fd < 0) die("open(/tmp/d)");

    char buf[4096];
    for (;;) {
        ssize_t r = read(fd, buf, sizeof(buf));
        if (r < 0) die("read(/tmp/d)");
        if (r == 0) break;

        ssize_t off = 0;
        while (off < r) {
            ssize_t w = write(STDOUT_FILENO, buf + off, (size_t)(r - off));
            if (w < 0) die("write(stdout)");
            off += w;
        }
    }

    if (close(fd) < 0) die("close(/tmp/d)");

    struct statx stx;
    memset(&stx, 0, sizeof(stx));

    if (statx(AT_FDCWD, "/tmp/d", AT_STATX_SYNC_AS_STAT, STATX_BASIC_STATS, &stx) < 0) {
        perror("statx");
        return 1;
    }

    assert((long long)stx.stx_size == 5);


    return 0;
}
