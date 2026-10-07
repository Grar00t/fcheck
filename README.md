# fcheck

`fcheck` is a small C11 SHA-256 file-integrity baseline checker.

It records a baseline for files beneath a directory and later verifies
those files against the stored index.

## Current scope

`fcheck` can detect:

- content modification;
- file-size changes;
- missing indexed files;
- file-type changes such as replacing an indexed regular file with a symbolic link;
- malformed or truncated index files.

Typical uses include verifying project trees after copying, backup,
restore, or archival.

It is **not**:

- a backup system;
- a malware scanner;
- a digital-signature system;
- an authenticated evidence ledger;
- a tamper-proof index.

The index is not protected by an HMAC or digital signature. An actor
able to modify both the files and their index is outside the current
trust model.

## Build

```sh
make clean
make CFLAGS="-std=c11 -O2 -Wall -Wextra -Wpedantic -Werror"
```

## Tests

```sh
./test_fcheck
```

The current test suite covers:

- SHA-256 of empty input;
- SHA-256 of `abc`;
- SHA-256 boundary inputs of 55, 56, 64, 65, and 1000 bytes;
- truncated-index rejection;
- long-path handling;
- integrity-mismatch status behavior;
- clean, mismatch, and operational CLI exit codes;
- symbolic-link replacement after baseline creation.

Sanitizer validation:

```sh
make clean
make CFLAGS="-std=c11 -O1 -g -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined -fno-omit-frame-pointer"
ASAN_OPTIONS=detect_leaks=1 ./test_fcheck
```

## Usage

Create a baseline:

```sh
./fcheck build /path/to/directory baseline.idx
```

Verify it later:

```sh
./fcheck verify baseline.idx
```

Dump indexed entries:

```sh
./fcheck dump baseline.idx
```

## `verify` exit codes

| Code | Meaning |
| ---: | --- |
| `0` | All indexed files matched |
| `1` | Integrity mismatch |
| `2` | Operational, I/O, or index-format error |

Integrity mismatch currently includes modified, missing, or
size-changed indexed files.

## Path representation

The current format uses:

```text
FC_MAX_PATH = 4096
```

The serialized representation can store path strings up to
`FC_MAX_PATH - 1` bytes, subject to filesystem and platform limits.

## Symbolic links

`fcheck build` does not follow symbolic links.

Symlink entries are skipped, whether they point to files or
directories. This prevents symlink traversal outside the requested
tree and avoids directory-symlink cycles. The target of a symlink is
not indexed through that symlink path.

The root path must not contain symbolic-link components. This
includes a symbolic-link root written with aliases such as a trailing
slash or `.` / `..` path components. Such roots are rejected rather
than followed.

## Index format

The first public format is version 1.

It stores absolute paths captured when the baseline is built.

Pre-publication prototype indexes using 128-byte records are not
compatible with the current format and must be rebuilt.

## SHA-256

File hashing is streaming; files are not loaded entirely into memory.

The local SHA-256 implementation is covered by known-answer and
padding-boundary tests. This does not make the index authenticated.

## Platform evidence

The current verified build and CI target is GNU/Linux. WSL/Linux has
also been used during development.

Native Windows support is not claimed by the current evidence.

## License

MIT.
