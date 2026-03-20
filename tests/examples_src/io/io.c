#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#if !defined(SYS_newfstatat) && defined(SYS_fstatat64)
#define SYS_newfstatat SYS_fstatat64
#endif

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

struct linux_dirent64 {
    ino64_t d_ino;
    off64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

static int dir_contains_name(int fd, const char *needle) {
    char buf[1024];

    for (;;) {
        long nread = syscall(SYS_getdents64, fd, buf, sizeof(buf));
        if (nread < 0) {
            return -1;
        }
        if (nread == 0) {
            return 0;
        }

        size_t offset = 0;
        while (offset < (size_t)nread) {
            struct linux_dirent64 *dent = (struct linux_dirent64 *)(buf + offset);
            if (dent->d_reclen == 0) {
                return 0;
            }
            if (strcmp(dent->d_name, needle) == 0) {
                return 1;
            }
            offset += dent->d_reclen;
        }
    }
}

int main(void) {
    const char *src = "/tmp/f";
    const char *mid = "/tmp/m";
    const char *dst = "/tmp/d";

    int fd = open(src, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        die("open(/tmp/f)");
    }

    const char *head = "te";
    const char *tail = "st\n";
    struct iovec iov[2] = {
        {.iov_base = (void *)head, .iov_len = 2},
        {.iov_base = (void *)tail, .iov_len = 3},
    };

    ssize_t n = writev(fd, iov, 2);
    if (n != 5) {
        die("writev(/tmp/f)");
    }

    if (close(fd) < 0) {
        die("close(/tmp/f)");
    }

    if (renameat(AT_FDCWD, src, AT_FDCWD, mid) != 0) {
        die("renameat(/tmp/f -> /tmp/m)");
    }

    long rc = syscall(SYS_renameat2, AT_FDCWD, mid, AT_FDCWD, dst, 0);
    if (rc < 0) {
        die("renameat2(/tmp/m -> /tmp/d)");
    }

    fd = openat(AT_FDCWD, dst, O_RDONLY, 0);
    if (fd < 0) {
        die("openat(/tmp/d)");
    }

    int unread = -1;
    if (ioctl(fd, FIONREAD, &unread) != 0) {
        die("ioctl(FIONREAD)");
    }
    assert(unread == 5);

    char buf[16] = {0};
    ssize_t r = read(fd, buf, sizeof(buf));
    if (r < 0) {
        die("read(/tmp/d)");
    }

    if (r != 5 || buf[0] != 't' || buf[1] != 'e' || buf[2] != 's' || buf[3] != 't' || buf[4] != '\n') {
        fprintf(stderr, "unexpected read buffer\n");
        return 1;
    }

    if (write(STDOUT_FILENO, buf, (size_t)r) != r) {
        die("write(stdout)");
    }

    if (close(fd) < 0) {
        die("close(/tmp/d)");
    }

    struct statx stx;
    memset(&stx, 0, sizeof(stx));
    if (statx(AT_FDCWD, dst, AT_STATX_SYNC_AS_STAT, STATX_BASIC_STATS, &stx) < 0) {
        die("statx");
    }
    assert((long long)stx.stx_size == 5);

    struct stat st;
    if (syscall(SYS_newfstatat, AT_FDCWD, dst, &st, 0) != 0) {
        die("newfstatat");
    }
    assert((long long)st.st_size == 5);

    struct statfs sfs;
    memset(&sfs, 0, sizeof(sfs));
    if (syscall(SYS_statfs, dst, &sfs) != 0) {
        die("statfs");
    }
    assert((long long)sfs.f_bsize > 0);

    int dirfd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        die("open(/tmp)");
    }

    int found_dst = dir_contains_name(dirfd, "d");
    if (found_dst < 0) {
        die("getdents64(/tmp)");
    }
    assert(found_dst == 1);

    if (close(dirfd) < 0) {
        die("close(/tmp)");
    }

    char exe_path[512] = {0};
    ssize_t link_n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (link_n <= 0) {
        die("readlink(/proc/self/exe)");
    }

    puts("test/io-ok\n");
    return 0;
}
