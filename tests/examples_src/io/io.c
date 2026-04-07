#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#if !defined(SYS_newfstatat) && defined(SYS_fstatat64)
#define SYS_newfstatat SYS_fstatat64
#endif

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static void expect_errno_in(const char *what, int actual, const int *expected, size_t expected_len) {
    for (size_t i = 0; i < expected_len; ++i) {
        if (actual == expected[i]) {
            return;
        }
    }

    fprintf(stderr, "%s: unexpected errno=%d\n", what, actual);
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

static void exercise_lseek_calls(int fd) {
    if (lseek(fd, 2, SEEK_SET) != 2) {
        die("lseek(libc)");
    }

    char single = '\0';
    if (read(fd, &single, 1) != 1) {
        die("read(after libc lseek)");
    }
    assert(single == 's');

    long pos = syscall(SYS_lseek, fd, 0, SEEK_SET);
    if (pos != 0) {
        die("lseek(syscall)");
    }
}

static void exercise_xattr_calls(const char *path, int fd) {
    char value[32];
    const int missing_xattr_errnos[] = {ENODATA, ENOTSUP, EOPNOTSUPP};

    errno = 0;
    ssize_t rc = getxattr(path, "user.valkyrie.missing", value, sizeof(value));
    if (rc != -1) {
        fprintf(stderr, "getxattr(libc) unexpectedly succeeded\n");
        exit(1);
    }
    expect_errno_in("getxattr(libc)", errno, missing_xattr_errnos, sizeof(missing_xattr_errnos) / sizeof(missing_xattr_errnos[0]));

    errno = 0;
    rc = syscall(SYS_lgetxattr, path, "user.valkyrie.missing", value, sizeof(value));
    if (rc != -1) {
        fprintf(stderr, "lgetxattr(syscall) unexpectedly succeeded\n");
        exit(1);
    }
    expect_errno_in("lgetxattr(syscall)", errno, missing_xattr_errnos, sizeof(missing_xattr_errnos) / sizeof(missing_xattr_errnos[0]));

    errno = 0;
    rc = fgetxattr(fd, "user.valkyrie.missing", value, sizeof(value));
    if (rc != -1) {
        fprintf(stderr, "fgetxattr(libc) unexpectedly succeeded\n");
        exit(1);
    }
    expect_errno_in("fgetxattr(libc)", errno, missing_xattr_errnos, sizeof(missing_xattr_errnos) / sizeof(missing_xattr_errnos[0]));
}

static void exercise_rt_sigprocmask_calls(void) {
    sigset_t set;
    if (sigemptyset(&set) != 0) {
        die("sigemptyset");
    }
    if (sigaddset(&set, SIGUSR1) != 0) {
        die("sigaddset");
    }
    if (sigprocmask(SIG_BLOCK, &set, NULL) != 0) {
        die("sigprocmask(libc)");
    }

    unsigned long clear_mask = 0;
    unsigned long old_mask = 0;
    long rc = syscall(SYS_rt_sigprocmask, SIG_SETMASK, &clear_mask, &old_mask, sizeof(clear_mask));
    if (rc != 0) {
        die("rt_sigprocmask(syscall)");
    }
    assert((old_mask & (1UL << (SIGUSR1 - 1))) != 0);
}

static void exercise_time_calls(void) {
    time_t libc_now = time(NULL);
    if (libc_now == (time_t)-1) {
        die("time(libc)");
    }

    time_t raw_now = 0;
    long rc = syscall(SYS_time, &raw_now);
    if (rc < 0) {
        die("time(syscall)");
    }

    long long delta = (long long)libc_now - (long long)raw_now;
    if (delta < 0) {
        delta = -delta;
    }
    assert(delta <= 1);
}

static void exercise_readlinkat_calls(void) {
    char exe_path[512] = {0};
    ssize_t link_n = readlinkat(AT_FDCWD, "/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (link_n <= 0) {
        die("readlinkat(/proc/self/exe)");
    }
}

static void exercise_futex_calls(void) {
    uint32_t futex_word = 1;

    errno = 0;
    long rc = syscall(
        SYS_futex,
        &futex_word,
        FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
        0,
        NULL,
        NULL,
        0
    );
    if (rc != -1) {
        fprintf(stderr, "futex WAIT unexpectedly succeeded\n");
        exit(1);
    }
    assert(errno == EAGAIN);

    rc = syscall(
        SYS_futex,
        &futex_word,
        FUTEX_WAKE | FUTEX_PRIVATE_FLAG,
        1,
        NULL,
        NULL,
        0
    );
    if (rc != 0) {
        die("futex WAKE");
    }
}

static void exercise_epoll_timerfd_calls(void) {
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        die("epoll_create1");
    }

    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (tfd < 0) {
        die("timerfd_create");
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.u64 = 0x1234;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev) != 0) {
        die("epoll_ctl");
    }

    struct itimerspec spec;
    memset(&spec, 0, sizeof(spec));
    spec.it_value.tv_nsec = 1000000;
    if (timerfd_settime(tfd, 0, &spec, NULL) != 0) {
        die("timerfd_settime");
    }

    struct epoll_event out;
    memset(&out, 0, sizeof(out));
    int n = epoll_wait(epfd, &out, 1, 200);
    if (n != 1) {
        fprintf(stderr, "epoll_wait returned %d\n", n);
        exit(1);
    }
    assert((out.events & EPOLLIN) != 0);

    uint64_t expirations = 0;
    if (read(tfd, &expirations, sizeof(expirations)) != (ssize_t)sizeof(expirations)) {
        die("read(timerfd)");
    }
    assert(expirations >= 1);

    if (close(tfd) < 0) {
        die("close(timerfd)");
    }
    if (close(epfd) < 0) {
        die("close(epoll)");
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

    exercise_lseek_calls(fd);
    exercise_xattr_calls(dst, fd);

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
   
    if (syscall(SYS_chmod, dst, 0600) != 0) {
        die("chmod(syscall)");
    }

    memset(&st, 0, sizeof(st));
    if (stat(dst, &st) != 0) {
        die("stat(after chmod)");
    }
    assert((st.st_mode & 0777) == 0600);

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

    exercise_rt_sigprocmask_calls();
    exercise_time_calls();
    exercise_readlinkat_calls();
    exercise_futex_calls();
    exercise_epoll_timerfd_calls();

    puts("test/io-ok\n");
    return 0;
}
