# Changelog

## v1.0.0 — 2026-03-19

### Changed
- Permission drift parsing rewritten to use `@effectorhq/core` TOML parser — eliminates the old regex-based `permissions = [...]` approach
- Normalize object-based `effector.toml` permissions into capability tags for drift reports (e.g. `network:external`, `read:filesystem`)
- `permissionCreep` rule: if no `effector.toml` manifest is found, any detected sensitive operation is flagged as undeclared (safe default)
- Scanner scope remains static-only — aligns with published README

---

## v0.1.0 — 2026-03-05

### Added
- Static scanner: prompt injection, data exfiltration, obfuscation detection
- Permission drift check: declared vs detected capability behavior
- CLI: `npx @effectorhq/audit <dir>` and `npx @effectorhq/audit permissions <dir>`
- JSON output format (`--format json`)
- Zero dependencies — Node.js built-ins only
