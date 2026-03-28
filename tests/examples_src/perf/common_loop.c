#define main common_single_run
#include "../common/common.c"
#undef main

#include <errno.h>
#include <limits.h>

static long parse_iterations(int argc, char **argv) {
    if (argc < 2) {
        return 20000;
    }

    char *end = NULL;
    errno = 0;
    long value = strtol(argv[1], &end, 10);
    if (errno != 0 || end == argv[1] || *end != '\0' || value < 1 || value > INT_MAX) {
        fprintf(stderr, "invalid iteration count: %s\n", argv[1]);
        return -1;
    }

    return value;
}

int main(int argc, char **argv) {
    long iterations = parse_iterations(argc, argv);
    if (iterations < 1) {
        return 1;
    }

    for (long i = 0; i < iterations; ++i) {
        if (common_single_run() != 0) {
            fprintf(stderr, "common workload failed at iter=%ld\n", i);
            return 1;
        }
    }

    return 0;
}
