#include <signal.h>
#include <unistd.h>

int main(void) {
    char buf[8] = {0};
    ssize_t n = read(0, buf, sizeof(buf));

    if (n >= 3 && buf[0] == 'A' && buf[1] == 'B' && buf[2] == 'C') {
        raise(SIGSEGV);
    }

    return 0;
}
