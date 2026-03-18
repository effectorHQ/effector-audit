# Changelog

## v1.0.0
- Unify permission parsing with `@effectorhq/core` TOML parsing (no more regex-based drift).
- Normalize the object-based `effector.toml` permissions model into capability tags for drift reports.
- Harden `permission-creep`: if no `effector.toml` manifest is found, treat detected sensitive operations as undeclared (safe default).
- Keep the scanner scope static-only and align behavior with the published README.

