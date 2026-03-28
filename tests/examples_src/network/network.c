#define _GNU_SOURCE
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

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

static void fill_missing_unix_addr(struct sockaddr_un *addr, const char *path) {
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr->sun_path)) {
        fprintf(stderr, "unix socket path too long\n");
        exit(1);
    }
    strcpy(addr->sun_path, path);
}

static void exercise_socket_calls(void) {
    const char *missing_sock = "/tmp/valkyrie_missing.sock";
    const int socket_errnos[] = {ENOENT, ECONNREFUSED};
    struct sockaddr_un addr;
    fill_missing_unix_addr(&addr, missing_sock);

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        die("socket(libc)");
    }

    errno = 0;
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc != -1) {
        fprintf(stderr, "connect(libc) unexpectedly succeeded\n");
        exit(1);
    }
    expect_errno_in("connect(libc)", errno, socket_errnos, sizeof(socket_errnos) / sizeof(socket_errnos[0]));

    if (close(fd) < 0) {
        die("close(socket libc)");
    }

    fd = (int)syscall(SYS_socket, AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        die("socket(syscall)");
    }

    errno = 0;
    ssize_t sent = syscall(
        SYS_sendto,
        fd,
        "vk",
        2,
        0,
        &addr,
        (socklen_t)sizeof(addr)
    );
    if (sent != -1) {
        fprintf(stderr, "sendto(syscall) unexpectedly succeeded\n");
        exit(1);
    }
    expect_errno_in("sendto(syscall)", errno, socket_errnos, sizeof(socket_errnos) / sizeof(socket_errnos[0]));

    if (close(fd) < 0) {
        die("close(socket syscall)");
    }
}

static void exercise_getsockopt_calls(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        die("socket(getsockopt)");
    }

    int socket_type = 0;
    socklen_t optlen = sizeof(socket_type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &optlen) != 0) {
        die("getsockopt(libc)");
    }
    assert(optlen == sizeof(socket_type));
    assert(socket_type == SOCK_STREAM);

    int socket_error = -1;
    optlen = sizeof(socket_error);
    long rc = syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_ERROR, &socket_error, &optlen);
    if (rc != 0) {
        die("getsockopt(syscall)");
    }
    assert(optlen == sizeof(socket_error));
    assert(socket_error == 0);

    if (close(fd) < 0) {
        die("close(socket getsockopt)");
    }
}

static void exercise_recvfrom_calls(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
        die("socketpair");
    }

    const char *payload = "rx";
    if (write(sv[0], payload, 2) != 2) {
        die("write(socketpair)");
    }

    char buf[8] = {0};
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    ssize_t rc = recvfrom(sv[1], buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peer_len);
    if (rc != 2) {
        die("recvfrom");
    }
    assert(buf[0] == 'r' && buf[1] == 'x');

    if (close(sv[0]) < 0) {
        die("close(socketpair[0])");
    }
    if (close(sv[1]) < 0) {
        die("close(socketpair[1])");
    }
}

struct pselect6_sigmask_arg {
    const void *ss;
    size_t ss_len;
};

static void exercise_pselect6_calls(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        die("socketpair(pselect6)");
    }

    const char payload = 'p';
    if (write(sv[0], &payload, 1) != 1) {
        die("write(socketpair for pselect)");
    }

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sv[1], &readfds);
    struct timespec timeout = {
        .tv_sec = 0,
        .tv_nsec = 1000000,
    };

    int rc = pselect(sv[1] + 1, &readfds, NULL, NULL, &timeout, NULL);
    if (rc != 1) {
        die("pselect(libc)");
    }
    assert(FD_ISSET(sv[1], &readfds));

    char buf[2] = {0};
    if (read(sv[1], buf, 1) != 1) {
        die("read(after pselect libc)");
    }
    assert(buf[0] == payload);

    if (write(sv[0], &payload, 1) != 1) {
        die("write(socketpair for pselect6)");
    }

    FD_ZERO(&readfds);
    FD_SET(sv[1], &readfds);
    timeout.tv_sec = 0;
    timeout.tv_nsec = 1000000;

    struct pselect6_sigmask_arg sigmask = {
        .ss = NULL,
        .ss_len = 0,
    };

    long raw_rc = syscall(SYS_pselect6, sv[1] + 1, &readfds, NULL, NULL, &timeout, &sigmask);
    if (raw_rc != 1) {
        die("pselect6(syscall)");
    }
    assert(FD_ISSET(sv[1], &readfds));

    memset(buf, 0, sizeof(buf));
    if (read(sv[1], buf, 1) != 1) {
        die("read(after pselect6 syscall)");
    }
    assert(buf[0] == payload);

    if (close(sv[0]) < 0) {
        die("close(socketpair pselect[0])");
    }
    if (close(sv[1]) < 0) {
        die("close(socketpair pselect[1])");
    }
}

static void exercise_poll_shutdown_calls(const char *host, const char *port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)atoi(port));
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        die("inet_pton");
    }

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (fd < 0) {
        die("socket(tcp poll)");
    }

    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        die("fcntl(F_GETFL)");
    }
    if (fcntl(fd, F_SETFL, flags) != 0) {
        die("fcntl(F_SETFL)");
    }

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc != 0 && errno != EINPROGRESS) {
        die("connect(tcp poll)");
    }

    struct pollfd pfd = {
        .fd = fd,
        .events = POLLOUT,
        .revents = 0,
    };
    rc = poll(&pfd, 1, 1000);
    if (rc != 1) {
        die("poll(libc)");
    }
    assert((pfd.revents & POLLOUT) != 0);

    int socket_error = -1;
    socklen_t optlen = sizeof(socket_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &optlen) != 0) {
        die("getsockopt(poll connect)");
    }
    assert(optlen == sizeof(socket_error));
    assert(socket_error == 0);

    const char *payload = "hello-from-guest\n";
    if (write(fd, payload, strlen(payload)) != (ssize_t)strlen(payload)) {
        die("write(tcp poll)");
    }

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN;
    long raw_rc = syscall(SYS_poll, &pfd, 1, 1000);
    if (raw_rc != 1) {
        die("poll(syscall)");
    }
    assert((pfd.revents & POLLIN) != 0);

    char buf[16] = {0};
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n <= 0) {
        die("read(tcp poll)");
    }
    assert(memmem(buf, (size_t)n, "ack", 3) != NULL);

    raw_rc = syscall(SYS_shutdown, fd, SHUT_RD);
    if (raw_rc != 0) {
        die("shutdown(syscall)");
    }

    if (close(fd) < 0) {
        die("close(tcp poll)");
    }
}

int main(void) {
    exercise_socket_calls();
    exercise_getsockopt_calls();
    exercise_recvfrom_calls();
    exercise_pselect6_calls();
    if (access("/tmp/valkyrie_network_tcp", F_OK) == 0) {
        exercise_poll_shutdown_calls("127.0.0.1", "4444");
    }

    puts("test/network-ok\n");
    return 0;
}
