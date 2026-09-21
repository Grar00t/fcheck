#include "fcheck.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int run = 0, failed = 0;
#define CHECK(c, m) do { run++; if (!(c)) { failed++; fprintf(stderr, "FAIL: %s\n", m); } } while (0)

static void wf(const char *p, const char *s) {
    FILE *f = fopen(p, "wb");
    if (!f) abort();
    size_t n = strlen(s);
    if (fwrite(s, 1, n, f) != n) abort();
    fclose(f);
}

static void run_quiet(const char *cmd) {
    int rc = system(cmd);
    (void)rc;
}

static fc_status verify_silent(const char *path) {
    fflush(stdout);
    int saved = dup(1);
    if (saved < 0) return fc_index_verify(path);
    FILE *n = freopen("/dev/null", "w", stdout);
    (void)n;
    fc_status s = fc_index_verify(path);
    fflush(stdout);
    dup2(saved, 1);
    close(saved);
    return s;
}

static void test_sha256_known(void) {
    wf("t_fc_abc", "abc");
    uint8_t d[32];
    CHECK(fc_sha256_file("t_fc_abc", d) == FC_OK, "sha file");
    static const uint8_t exp[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    CHECK(memcmp(d, exp, 32) == 0, "sha256(abc) correct");
    remove("t_fc_abc");
}

static void test_sha256_empty(void) {
    wf("t_fc_empty", "");
    uint8_t d[32];
    fc_sha256_file("t_fc_empty", d);
    static const uint8_t exp[32] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
        0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
        0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
    };
    CHECK(memcmp(d, exp, 32) == 0, "sha256(empty) correct");
    remove("t_fc_empty");
}

static void test_index_and_verify(void) {
    run_quiet("rm -rf t_fc_dir t_fc.idx");
    run_quiet("mkdir -p t_fc_dir/sub");
    wf("t_fc_dir/a.txt", "hello");
    wf("t_fc_dir/b.txt", "world");
    wf("t_fc_dir/sub/c.txt", "nested");

    CHECK(fc_index_build("t_fc_dir", "t_fc.idx") == FC_OK, "build index");

    fc_status s = verify_silent("t_fc.idx");
    CHECK(s == FC_OK, "verify clean");

    wf("t_fc_dir/a.txt", "HELLO");
    s = verify_silent("t_fc.idx");
    CHECK(s != FC_OK, "verify detects modification");

    wf("t_fc_dir/a.txt", "hello");
    remove("t_fc_dir/sub/c.txt");
    s = verify_silent("t_fc.idx");
    CHECK(s != FC_OK, "verify detects missing");

    run_quiet("rm -rf t_fc_dir t_fc.idx");
}


static void test_truncated_index_rejected(void) {
    run_quiet("rm -rf t_fc_dir t_fc.idx t_fc.idx.trunc");
    run_quiet("mkdir -p t_fc_dir");

    wf("t_fc_dir/a.txt", "alpha");
    wf("t_fc_dir/b.txt", "beta");

    CHECK(fc_index_build("t_fc_dir", "t_fc.idx") == FC_OK,
          "build truncation regression index");

    struct stat st;

    if (stat("t_fc.idx", &st) != 0 || st.st_size < 2) {
        CHECK(0, "stat truncation regression index");
        run_quiet("rm -rf t_fc_dir t_fc.idx t_fc.idx.trunc");
        return;
    }

    FILE *src = fopen("t_fc.idx", "rb");
    FILE *dst = fopen("t_fc.idx.trunc", "wb");

    if (!src || !dst) {
        if (src) fclose(src);
        if (dst) fclose(dst);

        CHECK(0, "open truncation regression files");
        run_quiet("rm -rf t_fc_dir t_fc.idx t_fc.idx.trunc");
        return;
    }

    long remaining = (long)st.st_size - 1;
    unsigned char buf[4096];

    while (remaining > 0) {
        size_t want =
            remaining < (long)sizeof(buf)
            ? (size_t)remaining
            : sizeof(buf);

        size_t got = fread(buf, 1, want, src);

        if (got == 0)
            break;

        if (fwrite(buf, 1, got, dst) != got)
            break;

        remaining -= (long)got;
    }

    fclose(src);
    fclose(dst);

    CHECK(remaining == 0,
          "create one-byte-truncated index");

    CHECK(fc_index_verify("t_fc.idx.trunc") == FC_ERR_FORMAT,
          "reject partial final index record");

    CHECK(fc_index_verify("t_fc.idx") == FC_OK,
          "accept original complete index");

    run_quiet("rm -rf t_fc_dir t_fc.idx t_fc.idx.trunc");
}


static void test_long_path_supported(void) {
    static const char *dir =
        "t_fc_dir/"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    char file_path[256];
    char command[320];

    run_quiet("rm -rf t_fc_dir t_fc.idx");

    int n = snprintf(command, sizeof(command),
                     "mkdir -p %s", dir);

    CHECK(n > 0 && (size_t)n < sizeof(command),
          "construct long-path mkdir command");

    if (n <= 0 || (size_t)n >= sizeof(command))
        return;

    run_quiet(command);

    n = snprintf(file_path, sizeof(file_path),
                 "%s/file.txt", dir);

    CHECK(n > 75 && (size_t)n < sizeof(file_path),
          "regression path exceeds old 75-char limit");

    if (n <= 75 || (size_t)n >= sizeof(file_path))
        return;

    wf(file_path, "long-path-regression");

    CHECK(fc_index_build("t_fc_dir", "t_fc.idx") == FC_OK,
          "build index containing long path");

    CHECK(verify_silent("t_fc.idx") == FC_OK,
          "verify index containing long path");

    run_quiet("rm -rf t_fc_dir t_fc.idx");
}


static void test_verify_status_contract(void) {
    run_quiet("rm -rf t_fc_dir t_fc.idx");
    run_quiet("mkdir -p t_fc_dir");

    wf("t_fc_dir/a.txt", "alpha");

    CHECK(fc_index_build("t_fc_dir", "t_fc.idx") == FC_OK,
          "build index for verify-status contract");

    CHECK(verify_silent("t_fc.idx") == FC_OK,
          "verify-status clean is FC_OK");

    /* Same size, different bytes: force digest mismatch rather
     * than FC_SIZE_CHANGED. */
    wf("t_fc_dir/a.txt", "omega");

    CHECK(verify_silent("t_fc.idx") == FC_ERR_MISMATCH,
          "verify-status modified file is FC_ERR_MISMATCH");

    run_quiet("rm -rf t_fc_dir t_fc.idx");
}


static int write_repeated_a(const char *path, size_t count) {
    FILE *f = fopen(path, "wb");
    if (!f)
        return 0;

    for (size_t i = 0; i < count; i++) {
        if (fputc('a', f) == EOF) {
            fclose(f);
            return 0;
        }
    }

    return fclose(f) == 0;
}

static void test_sha256_boundary_vectors(void) {
    struct sha_case {
        size_t length;
        uint8_t expected[32];
    };

    static const struct sha_case cases[] = {
        {
            55,
            {
                0x9f,0x43,0x90,0xf8,0xd3,0x0c,0x2d,0xd9,
                0x2e,0xc9,0xf0,0x95,0xb6,0x5e,0x2b,0x9a,
                0xe9,0xb0,0xa9,0x25,0xa5,0x25,0x8e,0x24,
                0x1c,0x9f,0x1e,0x91,0x0f,0x73,0x43,0x18
            }
        },
        {
            56,
            {
                0xb3,0x54,0x39,0xa4,0xac,0x6f,0x09,0x48,
                0xb6,0xd6,0xf9,0xe3,0xc6,0xaf,0x0f,0x5f,
                0x59,0x0c,0xe2,0x0f,0x1b,0xde,0x70,0x90,
                0xef,0x79,0x70,0x68,0x6e,0xc6,0x73,0x8a
            }
        },
        {
            64,
            {
                0xff,0xe0,0x54,0xfe,0x7a,0xe0,0xcb,0x6d,
                0xc6,0x5c,0x3a,0xf9,0xb6,0x1d,0x52,0x09,
                0xf4,0x39,0x85,0x1d,0xb4,0x3d,0x0b,0xa5,
                0x99,0x73,0x37,0xdf,0x15,0x46,0x68,0xeb
            }
        },
        {
            65,
            {
                0x63,0x53,0x61,0xc4,0x8b,0xb9,0xea,0xb1,
                0x41,0x98,0xe7,0x6e,0xa8,0xab,0x7f,0x1a,
                0x41,0x68,0x5d,0x6a,0xd6,0x2a,0xa9,0x14,
                0x6d,0x30,0x1d,0x4f,0x17,0xeb,0x0a,0xe0
            }
        },
        {
            1000,
            {
                0x41,0xed,0xec,0xe4,0x2d,0x63,0xe8,0xd9,
                0xbf,0x51,0x5a,0x9b,0xa6,0x93,0x2e,0x1c,
                0x20,0xcb,0xc9,0xf5,0xa5,0xd1,0x34,0x64,
                0x5a,0xdb,0x5d,0xb1,0xb9,0x73,0x7e,0xa3
            }
        }
    };

    const char *path = "t_fc_sha_boundary";
    uint8_t digest[FC_DIGEST];

    for (size_t i = 0;
         i < sizeof(cases) / sizeof(cases[0]);
         i++) {

        CHECK(write_repeated_a(path, cases[i].length),
              "write SHA-256 boundary vector");

        CHECK(fc_sha256_file(path, digest) == FC_OK,
              "hash SHA-256 boundary vector");

        CHECK(memcmp(digest, cases[i].expected, FC_DIGEST) == 0,
              "SHA-256 boundary KAT matches");
    }

    remove(path);
}


static void test_wrong_entry_size_header_rejected(void) {
    run_quiet("rm -rf t_fc_dir t_fc.idx");
    run_quiet("mkdir -p t_fc_dir");

    wf("t_fc_dir/a.txt", "alpha");

    CHECK(fc_index_build("t_fc_dir", "t_fc.idx") == FC_OK,
          "build index for entry-size header test");

    CHECK(verify_silent("t_fc.idx") == FC_OK,
          "entry-size header baseline is valid");

    FILE *f = fopen("t_fc.idx", "r+b");

    CHECK(f != NULL,
          "open index for entry-size header mutation");

    if (f) {
        uint32_t bad = FC_ENTRY + 1u;
        uint8_t b[4];

        b[0] = (uint8_t)(bad);
        b[1] = (uint8_t)(bad >> 8);
        b[2] = (uint8_t)(bad >> 16);
        b[3] = (uint8_t)(bad >> 24);

        int seek_ok = fseek(f, 12L, SEEK_SET) == 0;
        size_t written = 0;

        if (seek_ok)
            written = fwrite(b, 1, sizeof(b), f);

        CHECK(seek_ok && written == sizeof(b),
              "mutate serialized entry-size header");

        fclose(f);

        CHECK(fc_index_verify("t_fc.idx") == FC_ERR_FORMAT,
              "verify rejects wrong serialized entry size");

        CHECK(fc_index_dump("t_fc.idx") == FC_ERR_FORMAT,
              "dump rejects wrong serialized entry size");
    }

    run_quiet("rm -rf t_fc_dir t_fc.idx");
}


static void test_empty_path_records_rejected(void) {
    run_quiet("rm -rf t_fc_dir t_fc.idx t_fc_zero.idx");
    run_quiet("mkdir -p t_fc_dir");

    wf("t_fc_dir/a.txt", "alpha");

    CHECK(fc_index_build("t_fc_dir", "t_fc.idx") == FC_OK,
          "build index for empty-path format tests");

    CHECK(verify_silent("t_fc.idx") == FC_OK,
          "empty-path test baseline is valid");

    /* Mutate first serialized entry's path length to zero. */
    FILE *f = fopen("t_fc.idx", "r+b");

    CHECK(f != NULL,
          "open index for empty-path mutation");

    if (f) {
        uint8_t zero_len[4] = {0, 0, 0, 0};

        int seek_ok =
            fseek(f, (long)FC_HEADER + 48L, SEEK_SET) == 0;

        size_t written = 0;

        if (seek_ok)
            written = fwrite(
                zero_len,
                1,
                sizeof(zero_len),
                f
            );

        CHECK(seek_ok && written == sizeof(zero_len),
              "write zero serialized path length");

        fclose(f);

        CHECK(fc_index_verify("t_fc.idx") == FC_ERR_FORMAT,
              "verify rejects empty serialized path");

        CHECK(fc_index_dump("t_fc.idx") == FC_ERR_FORMAT,
              "dump rejects empty serialized path");
    }

    /*
     * Build another valid index, then append one complete
     * zero-filled record. Its serialized path length is zero.
     */
    CHECK(fc_index_build("t_fc_dir", "t_fc_zero.idx") == FC_OK,
          "build index for zero-record test");

    f = fopen("t_fc_zero.idx", "ab");

    CHECK(f != NULL,
          "open index for zero-record append");

    if (f) {
        uint8_t zero_record[FC_ENTRY] = {0};

        size_t written = fwrite(
            zero_record,
            1,
            sizeof(zero_record),
            f
        );

        CHECK(written == sizeof(zero_record),
              "append complete zero-filled record");

        fclose(f);

        CHECK(fc_index_verify("t_fc_zero.idx") == FC_ERR_FORMAT,
              "verify rejects zero-filled complete record");

        CHECK(fc_index_dump("t_fc_zero.idx") == FC_ERR_FORMAT,
              "dump rejects zero-filled complete record");
    }

    run_quiet("rm -rf t_fc_dir t_fc.idx t_fc_zero.idx");
}


static int mutate_serialized_path(const char *path, int mode) {
    FILE *f = fopen(path, "r+b");
    if (!f)
        return 0;

    uint8_t lenbuf[4];

    if (fseek(f, (long)FC_HEADER + 48L, SEEK_SET) != 0 ||
        fread(lenbuf, 1, sizeof(lenbuf), f) != sizeof(lenbuf)) {
        fclose(f);
        return 0;
    }

    uint32_t plen =
        (uint32_t)lenbuf[0] |
        ((uint32_t)lenbuf[1] << 8) |
        ((uint32_t)lenbuf[2] << 16) |
        ((uint32_t)lenbuf[3] << 24);

    if (plen < 2 || plen + 1 >= FC_ENTRY - 52) {
        fclose(f);
        return 0;
    }

    if (mode == 0) {
        uint32_t bad = plen + 1;

        lenbuf[0] = (uint8_t)bad;
        lenbuf[1] = (uint8_t)(bad >> 8);
        lenbuf[2] = (uint8_t)(bad >> 16);
        lenbuf[3] = (uint8_t)(bad >> 24);

        if (fseek(f, (long)FC_HEADER + 48L, SEEK_SET) != 0 ||
            fwrite(lenbuf, 1, sizeof(lenbuf), f) != sizeof(lenbuf)) {
            fclose(f);
            return 0;
        }
    } else {
        long offset = (long)FC_HEADER + 52L;

        if (mode == 2)
            offset += (long)plen - 1L;

        if (fseek(f, offset, SEEK_SET) != 0 ||
            fputc(0, f) == EOF) {
            fclose(f);
            return 0;
        }
    }

    return fclose(f) == 0;
}


static void test_embedded_nul_paths_rejected(void) {
    static const char *indexes[] = {
        "t_fc_p5_plus.idx",
        "t_fc_p5_first.idx",
        "t_fc_p5_last.idx"
    };

    run_quiet(
        "rm -rf t_fc_dir "
        "t_fc_p5_good.idx "
        "t_fc_p5_plus.idx "
        "t_fc_p5_first.idx "
        "t_fc_p5_last.idx"
    );

    run_quiet("mkdir -p t_fc_dir");
    wf("t_fc_dir/a.txt", "alpha");

    CHECK(fc_index_build("t_fc_dir", "t_fc_p5_good.idx") == FC_OK,
          "build P5 canonical index");

    CHECK(verify_silent("t_fc_p5_good.idx") == FC_OK,
          "P5 canonical index verifies");

    for (int mode = 0; mode < 3; mode++) {
        CHECK(fc_index_build("t_fc_dir", indexes[mode]) == FC_OK,
              "build P5 malformed-path source index");

        CHECK(mutate_serialized_path(indexes[mode], mode),
              "mutate P5 serialized path");

        CHECK(fc_index_verify(indexes[mode]) == FC_ERR_FORMAT,
              "verify rejects NUL within declared path");

        CHECK(fc_index_dump(indexes[mode]) == FC_ERR_FORMAT,
              "dump rejects NUL within declared path");
    }

    run_quiet(
        "rm -rf t_fc_dir "
        "t_fc_p5_good.idx "
        "t_fc_p5_plus.idx "
        "t_fc_p5_first.idx "
        "t_fc_p5_last.idx"
    );
}

int main(void) {
    test_sha256_known();
    test_sha256_empty();
    test_sha256_boundary_vectors();
    test_index_and_verify();
    test_truncated_index_rejected();
    test_long_path_supported();
    test_verify_status_contract();
    test_wrong_entry_size_header_rejected();
    test_empty_path_records_rejected();
    test_embedded_nul_paths_rejected();
    printf("tests: %d, failed: %d\n", run, failed);
    return failed ? 1 : 0;
}