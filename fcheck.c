#include "fcheck.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

/* ---------- SHA-256 (streaming) ---------- */
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BS0(x) (ROR(x,2) ^ ROR(x,13) ^ ROR(x,22))
#define BS1(x) (ROR(x,6) ^ ROR(x,11) ^ ROR(x,25))
#define SS0(x) (ROR(x,7) ^ ROR(x,18) ^ ((x) >> 3))
#define SS1(x) (ROR(x,17) ^ ROR(x,19) ^ ((x) >> 10))

static void sha256_compress(uint32_t s[8], const uint8_t b[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)b[i*4]<<24)|((uint32_t)b[i*4+1]<<16)|
               ((uint32_t)b[i*4+2]<<8)|(uint32_t)b[i*4+3];
    for (int i = 16; i < 64; i++)
        w[i] = SS1(w[i-2]) + w[i-7] + SS0(w[i-15]) + w[i-16];
    uint32_t a=s[0],b_=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + BS1(e) + CH(e,f,g) + K256[i] + w[i];
        uint32_t t2 = BS0(a) + MAJ(a,b_,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b_; b_=a; a=t1+t2;
    }
    s[0]+=a; s[1]+=b_; s[2]+=c; s[3]+=d;
    s[4]+=e; s[5]+=f; s[6]+=g; s[7]+=h;
}

typedef struct {
    uint32_t s[8];
    uint64_t total;
    uint8_t  buf[64];
    size_t   buf_len;
} sha256_ctx;

static void sha256_init(sha256_ctx *c) {
    static const uint32_t iv[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    memcpy(c->s, iv, sizeof(iv));
    c->total = 0;
    c->buf_len = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len) {
    c->total += len;
    if (c->buf_len) {
        size_t need = 64 - c->buf_len;
        size_t take = len < need ? len : need;
        memcpy(c->buf + c->buf_len, data, take);
        c->buf_len += take;
        data += take;
        len  -= take;
        if (c->buf_len == 64) {
            sha256_compress(c->s, c->buf);
            c->buf_len = 0;
        }
    }
    while (len >= 64) {
        sha256_compress(c->s, data);
        data += 64;
        len  -= 64;
    }
    if (len) {
        memcpy(c->buf, data, len);
        c->buf_len = len;
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t total_bits = c->total * 8u;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buf_len != 56) sha256_update(c, &zero, 1);
    uint8_t lenbuf[8];
    for (int i = 0; i < 8; i++) lenbuf[i] = (uint8_t)(total_bits >> (8*(7-i)));
    memcpy(c->buf + 56, lenbuf, 8);
    sha256_compress(c->s, c->buf);
    c->buf_len = 0;
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->s[i] >> 24);
        out[i*4+1] = (uint8_t)(c->s[i] >> 16);
        out[i*4+2] = (uint8_t)(c->s[i] >> 8);
        out[i*4+3] = (uint8_t)(c->s[i]);
    }
}

fc_status fc_sha256_file(const char *path, uint8_t out[FC_DIGEST]) {
    FILE *f = fopen(path, "rb");
    if (!f) return FC_ERR_IO;
    sha256_ctx c;
    sha256_init(&c);
    uint8_t buf[65536];
    for (;;) {
        size_t n = fread(buf, 1, sizeof(buf), f);
        if (n > 0) sha256_update(&c, buf, n);
        if (n < sizeof(buf)) {
            if (ferror(f)) { fclose(f); return FC_ERR_IO; }
            break;
        }
    }
    fclose(f);
    sha256_final(&c, out);
    return FC_OK;
}

/* ---------- status strings ---------- */
const char *fc_status_str(fc_status s) {
    switch (s) {
        case FC_OK: return "OK";
        case FC_ERR_IO: return "IO error";
        case FC_ERR_FORMAT: return "format error";
        case FC_ERR_ARG: return "invalid argument";
        case FC_ERR_NOMEM: return "out of memory";
        case FC_ERR_NOTFOUND: return "not found";
        case FC_ERR_MISMATCH: return "integrity mismatch";
    }
    return "unknown";
}

const char *fc_result_str(fc_result r) {
    switch (r) {
        case FC_MATCH: return "MATCH";
        case FC_MODIFIED: return "MODIFIED";
        case FC_MISSING: return "MISSING";
        case FC_NEW: return "NEW";
        case FC_SIZE_CHANGED: return "SIZE_CHANGED";
        case FC_INDEX_CORRUPT: return "INDEX_CORRUPT";
    }
    return "?";
}

/* ---------- little-endian helpers ---------- */
static void put_u32le(uint8_t *p, uint32_t v) {
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8);
    p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}
static uint32_t get_u32le(const uint8_t *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static void put_u64le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i]=(uint8_t)(v>>(8*i));
}
static uint64_t get_u64le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i]<<(8*i);
    return v;
}

/* ---------- path join with overflow detection ---------- */
static fc_status join_path(char *out, size_t outsz, const char *a, const char *b) {
    size_t al = strlen(a), bl = strlen(b);
    if (al + 1 + bl + 1 > outsz) return FC_ERR_ARG;
    memcpy(out, a, al);
    out[al] = '/';
    memcpy(out + al + 1, b, bl);
    out[al + 1 + bl] = 0;
    return FC_OK;
}

/* ---------- index entry ---------- */
typedef struct {
    uint64_t size;
    int64_t  mtime;
    uint8_t  digest[32];
    char     path[FC_MAX_PATH];
} fc_entry;

static fc_status write_header(FILE *fp) {
    uint8_t h[FC_HEADER];
    memset(h, 0, sizeof(h));
    memcpy(h, FC_MAGIC, 8);
    put_u32le(h+8, FC_VERSION);
    put_u32le(h+12, FC_ENTRY);
    if (fwrite(h, 1, sizeof(h), fp) != sizeof(h)) return FC_ERR_IO;
    return FC_OK;
}

static fc_status read_header(FILE *fp) {
    uint8_t h[FC_HEADER];
    if (fread(h, 1, sizeof(h), fp) != sizeof(h)) return FC_ERR_FORMAT;
    if (memcmp(h, FC_MAGIC, 8) != 0) return FC_ERR_FORMAT;
    if (get_u32le(h+8) != FC_VERSION) return FC_ERR_FORMAT;
    return FC_OK;
}

static fc_status write_entry(FILE *fp, const fc_entry *e) {
    uint8_t buf[FC_ENTRY];
    memset(buf, 0, sizeof(buf));
    put_u64le(buf, e->size);
    put_u64le(buf+8, (uint64_t)e->mtime);
    memcpy(buf+16, e->digest, 32);
    size_t plen = strlen(e->path);
    if (plen >= FC_ENTRY - 52) return FC_ERR_ARG;
    put_u32le(buf+48, (uint32_t)plen);
    memcpy(buf+52, e->path, plen);
    if (fwrite(buf, 1, sizeof(buf), fp) != sizeof(buf)) return FC_ERR_IO;
    return FC_OK;
}

/* Reads one serialized entry.
 * FC_OK + eof=0 : one complete entry parsed
 * FC_OK + eof=1 : clean EOF at record boundary
 * FC_ERR_IO      : underlying read error
 * FC_ERR_FORMAT  : partial final record or malformed entry
 */
static fc_status read_entry(FILE *fp, fc_entry *e, int *eof) {
    uint8_t buf[FC_ENTRY];
    size_t got;

    *eof = 0;
    got = fread(buf, 1, sizeof(buf), fp);

    if (got == 0) {
        if (feof(fp)) {
            *eof = 1;
            return FC_OK;
        }
        return FC_ERR_IO;
    }

    if (got != sizeof(buf))
        return FC_ERR_FORMAT;

    e->size = get_u64le(buf);
    e->mtime = (int64_t)get_u64le(buf + 8);
    memcpy(e->digest, buf + 16, 32);

    uint32_t plen = get_u32le(buf + 48);
    if (plen >= FC_ENTRY - 52)
        return FC_ERR_FORMAT;

    memcpy(e->path, buf + 52, plen);
    e->path[plen] = 0;

    return FC_OK;
}

/* ---------- recursive scan ---------- */
typedef struct {
    fc_entry *ents;
    size_t    count;
    size_t    cap;
} entry_vec;

static fc_status vec_push(entry_vec *v, const fc_entry *e) {
    if (v->count == v->cap) {
        size_t nc = v->cap ? v->cap * 2 : 64;
        fc_entry *p = realloc(v->ents, nc * sizeof(fc_entry));
        if (!p) return FC_ERR_NOMEM;
        v->ents = p; v->cap = nc;
    }
    v->ents[v->count++] = *e;
    return FC_OK;
}

static int entry_cmp(const void *a, const void *b) {
    const fc_entry *x = a, *y = b;
    return strcmp(x->path, y->path);
}

static fc_status scan_dir(const char *root, const char *rel,
                          const char *index_path, entry_vec *v) {
    char full[FC_MAX_PATH];
    fc_status ps;
    if (rel[0]) {
        ps = join_path(full, sizeof(full), root, rel);
    } else {
        if (strlen(root) >= sizeof(full)) return FC_ERR_ARG;
        strcpy(full, root);
        ps = FC_OK;
    }
    if (ps != FC_OK) return ps;

    DIR *d = opendir(full);
    if (!d) return FC_ERR_IO;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;

        char child_rel[FC_MAX_PATH];
        if (rel[0]) {
            ps = join_path(child_rel, sizeof(child_rel), rel, de->d_name);
        } else {
            if (strlen(de->d_name) >= sizeof(child_rel)) { ps = FC_ERR_ARG; }
            else { strcpy(child_rel, de->d_name); ps = FC_OK; }
        }
        if (ps != FC_OK) { closedir(d); return ps; }

        char child_full[FC_MAX_PATH];
        ps = join_path(child_full, sizeof(child_full), root, child_rel);
        if (ps != FC_OK) { closedir(d); return ps; }

        struct stat st;
        if (stat(child_full, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            fc_status s = scan_dir(root, child_rel, index_path, v);
            if (s != FC_OK) { closedir(d); return s; }
        } else if (S_ISREG(st.st_mode)) {
            /* skip the index file itself */
            struct stat ist;
            if (stat(index_path, &ist) == 0 &&
                ist.st_ino == st.st_ino && ist.st_dev == st.st_dev)
                continue;

            fc_entry e;
            memset(&e, 0, sizeof(e));
            e.size = (uint64_t)st.st_size;
            e.mtime = (int64_t)st.st_mtime;
            size_t fl = strlen(child_full);
            if (fl >= sizeof(e.path)) { closedir(d); return FC_ERR_ARG; }
            memcpy(e.path, child_full, fl + 1);
            fc_status s = fc_sha256_file(child_full, e.digest);
            if (s != FC_OK) { closedir(d); return s; }
            s = vec_push(v, &e);
            if (s != FC_OK) { closedir(d); return s; }
        }
    }
    closedir(d);
    return FC_OK;
}

/* ---------- public ---------- */
fc_status fc_index_build(const char *root, const char *index_path) {
    if (!root || !index_path) return FC_ERR_ARG;

    entry_vec v = {0};
    fc_status s = scan_dir(root, "", index_path, &v);
    if (s != FC_OK) { free(v.ents); return s; }

    qsort(v.ents, v.count, sizeof(fc_entry), entry_cmp);

    FILE *fp = fopen(index_path, "wb");
    if (!fp) { free(v.ents); return FC_ERR_IO; }

    s = write_header(fp);
    if (s == FC_OK) {
        for (size_t i = 0; i < v.count && s == FC_OK; i++)
            s = write_entry(fp, &v.ents[i]);
    }
    if (fclose(fp) != 0 && s == FC_OK) s = FC_ERR_IO;
    fprintf(stderr, "fcheck: indexed %zu files\n", v.count);
    free(v.ents);
    return s;
}

fc_status fc_index_verify(const char *index_path) {
    if (!index_path) return FC_ERR_ARG;
    FILE *fp = fopen(index_path, "rb");
    if (!fp) return FC_ERR_IO;

    fc_status s = read_header(fp);
    if (s != FC_OK) { fclose(fp); return s; }

    size_t matched = 0, modified = 0, missing = 0, size_changed = 0, errors = 0;
    fc_entry e;
    for (;;) {
        int eof = 0;
        s = read_entry(fp, &e, &eof);
        if (s != FC_OK) {
            if (s == FC_ERR_FORMAT)
                fprintf(stderr,
                        "fcheck: index truncated or malformed\n");
            fclose(fp);
            return s;
        }
        if (eof)
            break;

        struct stat st;
        if (stat(e.path, &st) != 0) {
            printf("%-12s %s\n", fc_result_str(FC_MISSING), e.path);
            missing++;
            continue;
        }
        if ((uint64_t)st.st_size != e.size) {
            printf("%-12s %s (size %llu -> %llu)\n",
                   fc_result_str(FC_SIZE_CHANGED), e.path,
                   (unsigned long long)e.size, (unsigned long long)st.st_size);
            size_changed++;
            continue;
        }
        uint8_t d[32];
        fc_status hs = fc_sha256_file(e.path, d);
        if (hs != FC_OK) {
            printf("%-12s %s (read error)\n", "ERROR", e.path);
            errors++;
            continue;
        }
        if (memcmp(d, e.digest, 32) != 0) {
            printf("%-12s %s\n", fc_result_str(FC_MODIFIED), e.path);
            modified++;
        } else {
            matched++;
        }
    }
    fclose(fp);

    printf("\n--- summary ---\n");
    printf("matched:      %zu\n", matched);
    printf("modified:     %zu\n", modified);
    printf("size changed: %zu\n", size_changed);
    printf("missing:      %zu\n", missing);
    printf("errors:       %zu\n", errors);
    if (errors)
        return FC_ERR_IO;

    return (modified || missing || size_changed)
        ? FC_ERR_MISMATCH
        : FC_OK;
}

fc_status fc_index_dump(const char *index_path) {
    if (!index_path) return FC_ERR_ARG;
    FILE *fp = fopen(index_path, "rb");
    if (!fp) return FC_ERR_IO;
    fc_status s = read_header(fp);
    if (s != FC_OK) { fclose(fp); return s; }
    fc_entry e;
    for (;;) {
        int eof = 0;
        s = read_entry(fp, &e, &eof);
        if (s != FC_OK) {
            if (s == FC_ERR_FORMAT)
                fprintf(stderr,
                        "fcheck: index truncated or malformed\n");
            fclose(fp);
            return s;
        }
        if (eof)
            break;
        printf("%10llu  %s\n", (unsigned long long)e.size, e.path);
    }
    fclose(fp);
    return FC_OK;
}