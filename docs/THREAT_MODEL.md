# Threat Model

## Protected property

The checker is intended to detect unexpected changes to files after a baseline has been recorded.

## In scope

- content modification after baseline creation
- file truncation or extension
- missing indexed files
- malformed or truncated index data
- accidental symlink traversal and pre-existing symlink components during baseline creation

## Out of scope

- an attacker who can rewrite both the files and the baseline index
- authenticity of the person who created the baseline
- confidentiality of indexed paths or hashes
- malware detection or behavioral analysis
- remote attestation
- cryptographic signing of the index
- protection against concurrent filesystem namespace mutation or symlink-swap races during a build

## Trust boundary

The baseline index must be protected separately if tamper resistance is required. A practical deployment can place the index on read-only media, a separately protected volume, or wrap it in an authenticated signature workflow.

## Verification contract

A clean result means only that the current files match the stored baseline according to the implemented format and SHA-256 comparison. It is not proof that either state is trustworthy or authorized.
