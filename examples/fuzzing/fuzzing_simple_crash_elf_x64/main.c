#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

int main() {
    char buf[100];
    fgets(buf, sizeof(buf), stdin);

    if (buf[0] == 'A' && buf[1] == 'B' && buf[2] == 'C') {
        raise(SIGSEGV);
    }

    return 0;
}