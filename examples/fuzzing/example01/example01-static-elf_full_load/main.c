#include <stdio.h>

int main(void) {
    char buf[100] = {0};

    if (fgets(buf, sizeof(buf), stdin) == NULL) {
        return 0;
    }

    if (buf[0] != 'A') {
        return 0;
    }

    if (buf[1] != 'B') {
        return 0;
    }

    if (buf[2] != 'C') {
        return 0;
    }

    *(volatile unsigned char *)0 = 0x41;
    return 0;
}
