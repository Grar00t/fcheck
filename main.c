#include "fcheck.h"
#include <stdio.h>
#include <string.h>

static void usage(const char *p) {
    fprintf(stderr,
        "usage:\n"
        "  %s build  <dir> <index.fcheck>\n"
        "  %s verify <index.fcheck>\n"
        "  %s dump   <index.fcheck>\n",
        p, p, p);
}

int main(int argc, char **argv) {
    if (argc < 3) { usage(argv[0]); return 2; }

    if (strcmp(argv[1], "build") == 0 && argc == 4) {
        fc_status s = fc_index_build(argv[2], argv[3]);
        if (s != FC_OK) { fprintf(stderr, "error: %s\n", fc_status_str(s)); return 2; }
        return 0;
    }
    if (strcmp(argv[1], "verify") == 0 && argc == 3) {
        fc_status s = fc_index_verify(argv[2]);

        if (s == FC_OK)
            return 0;

        if (s == FC_ERR_MISMATCH)
            return 1;

        fprintf(stderr, "error: %s\n", fc_status_str(s));
        return 2;
    }
    if (strcmp(argv[1], "dump") == 0 && argc == 3) {
        fc_status s = fc_index_dump(argv[2]);
        if (s != FC_OK) { fprintf(stderr, "error: %s\n", fc_status_str(s)); return 2; }
        return 0;
    }
    usage(argv[0]);
    return 2;
}