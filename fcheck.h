#ifndef FCHECK_H
#define FCHECK_H

#include <stddef.h>
#include <stdint.h>

#define FC_MAGIC     "FCHECK1"
#define FC_VERSION   1u
#define FC_HEADER    64u
#define FC_MAX_PATH  4096u
#define FC_ENTRY     (52u + FC_MAX_PATH)
#define FC_DIGEST    32u

typedef enum {
    FC_OK = 0,
    FC_ERR_IO,
    FC_ERR_FORMAT,
    FC_ERR_ARG,
    FC_ERR_NOMEM,
    FC_ERR_NOTFOUND,
    FC_ERR_MISMATCH
} fc_status;

typedef enum {
    FC_MATCH = 0,
    FC_MODIFIED,
    FC_MISSING,
    FC_NEW,
    FC_SIZE_CHANGED,
    FC_INDEX_CORRUPT
} fc_result;

const char *fc_status_str(fc_status s);
const char *fc_result_str(fc_result r);

fc_status fc_index_build(const char *root, const char *index_path);
fc_status fc_index_verify(const char *index_path);
fc_status fc_index_dump(const char *index_path);
/* NULL path/output and a final symlink return FC_ERR_ARG; failures leave output unchanged. */
fc_status fc_sha256_file(const char *path, uint8_t out[FC_DIGEST]);

#endif