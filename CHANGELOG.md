# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · [Semantic Versioning](https://semver.org/)

---

## [1.0.0] — 2026-03-19

Promoted to stable. Package published as `@effectorhq/audit`.

### Added
- **Permission-interface mismatch rule** — detects when a tool's declared `[effector.interface]` types imply permissions not declared in `[effector.permissions]` (e.g. `output = "APIResponse"` with `network = false`)
- `prepublishOnly` script — runs 24 tests before publish
- `files` field — `src/`, `bin/`, `README.md`, `LICENSE`
- `CHANGELOG.md`

### Changed
- Permission drift parsing rewritten to use `@effectorhq/core` TOML parser — eliminates the old regex-based `permissions = [...]` approach
- Object-based `effector.toml` permissions normalized into capability tags for drift reports (e.g. `network:external`, `read:filesystem`)
- `permissionCreep` rule: if no `effector.toml` manifest is found, any detected sensitive operation is flagged as undeclared (safe default)
- Dependency on `@effectorhq/core` changed from `file:../effector-core` to `^1.0.0` (npm)
- Scanner scope remains static-only — consistent with published README
- 24 tests (all passing)

---

## [0.1.0] — 2026-03-05

Initial release.

### Added
- **Static scanner** — 4 check categories:
  - Prompt injection: detects role-override patterns, jailbreak keywords, instruction-override attempts
  - Data exfiltration: detects credential access, environment variable exfiltration, file reading patterns
  - Obfuscation: detects base64 encoding, eval-like patterns, encoded strings
  - Permission drift: declared vs detected capability behavior
- **Permission drift check** — compares `effector.toml` declared permissions against statically detected sensitive operations
- **CLI** — `npx @effectorhq/audit <dir>` and `npx @effectorhq/audit permissions <dir>`
- `--format json` output flag
- `--severity` filter flag
- Zero dependencies — Node.js built-ins only
- 24 tests
