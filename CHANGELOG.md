# Changelog

## 0.1.0

First release.

- `record`: redact secrets in agent events and chain them with SHA-256 hashes.
- `verify`: detect edited, reordered, inserted or removed events, optionally against a root hash you kept elsewhere.
- `compare`: show which events differ between two traces.
