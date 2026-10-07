# Security Policy

## Scope

`fcheck` is a local file-integrity baseline checker. It detects drift between a stored index and later filesystem state.

It does **not** authenticate the baseline itself. An actor that can modify both indexed files and the baseline index is outside the current trust model.

## Security-relevant behavior

- SHA-256 is computed by the bundled streaming implementation.
- Symbolic links are not followed while building a baseline.
- Root paths containing symbolic-link components are rejected.
- Baseline output refuses a final path that is a symbolic link.
- Malformed or truncated indexes fail closed as operational errors.
- Baseline creation fails closed if directory enumeration or file metadata lookup fails.
- Integrity mismatch is separated from operational failure by exit status.

## Reporting

Please open a GitHub issue for reproducible security defects that do not require private disclosure. Do not attach secrets, private datasets, credentials, or production evidence.

For a report, include the exact command, platform, compiler, observed exit code, and the smallest reproducible filesystem fixture.
