# Changelog

## Unreleased

- `verify` and `compare` reports have a `coverage` block, a one-line summary on stderr and in the HTML report. Without a root hash, passing events are undecided (`unanchored`); with one, every event is decided.
- `--min-coverage PCT`: exit 3 when fewer than PCT percent of items were decided and nothing else failed.

## 0.1.0

First release.

- `record`: redact secrets in agent events and chain them with SHA-256 hashes.
- `verify`: detect edited, reordered, inserted or removed events, optionally against a root hash you kept elsewhere.
- `compare`: show which events differ between two traces.
