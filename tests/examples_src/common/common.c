#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

int main(void) {
    struct utsname uts;
    if (uname(&uts) != 0) {
        die("uname");
    }
    if (strlen(uts.sysname) == 0) {
        fprintf(stderr, "unexpected empty uname.sysname\n");
        return 1;
    }

    uid_t uid = getuid();
    uid_t euid = geteuid();
    gid_t gid = getgid();
    gid_t egid = getegid();
    pid_t pid = getpid();

    if (pid <= 0) {
        fprintf(stderr, "invalid pid=%d\n", pid);
        return 1;
    }

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        die("clock_gettime");
    }

    unsigned char random_buf[16];
    ssize_t got = getrandom(random_buf, sizeof(random_buf), 0);
    if (got < 0) {
        die("getrandom");
    }
    if (got != (ssize_t)sizeof(random_buf)) {
        fprintf(stderr, "short getrandom=%zd\n", got);
        return 1;
    }

    struct rlimit lim;
    if (syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, NULL, &lim) != 0) {
        die("prlimit64");
    }

    assert(uid == euid);
    assert(gid == egid);
    assert(lim.rlim_cur > 0);

    printf("test/common-ok\n");
    return 0;
}