# effector-audit

[![npm version](https://img.shields.io/badge/npm-effector--audit-E03E3E.svg)](https://www.npmjs.com/package/effector-audit)
[![CI](https://github.com/effectorHQ/effector-audit/actions/workflows/test.yml/badge.svg)](https://github.com/effectorHQ/effector-audit/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#)

**Security scanner for Effector packages (static-only).**

---

## The Trust Crisis

On February 18, 2026, Snyk published the [ToxicSkills Report](https://snyk.io/blog/toxicskills/). The findings were severe: **36% of ClawHub skills contained prompt injection or malicious payloads.** The ClawHavoc campaign had planted 1,184+ malicious skills targeting developers. Trend Micro confirmed distribution of the Atomic macOS Stealer through community-published skills. Microsoft, Cisco, and 1Password all published independent analyses confirming the systemic nature of the threat.

The root cause wasn't a bug. It was an architectural absence: **no code signing, no security review, no formal permission model for AI agent capabilities.** Anyone could publish a skill to ClawHub. Everyone had to trust it blindly.

This is npm circa 2018 — before `npm audit`, before lockfiles, before Sigstore. Except the stakes are higher, because AI agent capabilities don't just run code. They control what an AI does in the world: reading your files, calling APIs, sending messages, modifying databases.

`effector-audit` closes this gap.

## Install

```bash
npm install @effectorhq/audit
```

You can also use the CLI directly without installing globally:

```bash
npx @effectorhq/audit ./my-skill
npx @effectorhq/audit ./my-skill --format json
```

See the published package on npm: **https://www.npmjs.com/package/@effectorhq/audit**

## What It Does

### 1. Static Analysis (implemented)

Scans Effector packages for known vulnerability patterns (no execution sandbox):

```bash
npx effector-audit ./my-skill/

  ✗ CRITICAL  prompt-injection    Line 23: System prompt override detected
  ✗ HIGH      data-exfiltration   Line 47: Unscoped network access to external domain
  ⚠ MEDIUM    permission-creep    Network/filesystem/subprocess usage without declared permissions

  2 critical, 1 warning — audit failed
```

**Detection patterns include:**
- Prompt injection and jailbreak attempts in SKILL.md content
- Data exfiltration vectors (unscoped network, filesystem access)
- Obfuscated instructions (base64, unicode tricks, invisible text)

### 2. Permission Drift Check (implemented)

Cross-references declared permissions against actual capability behavior:

```bash
npx effector-audit permissions ./my-skill/

  Declared permissions:
    ✓ network:external

  Detected behavior:
    ✗ network:evil.com       (fetch/curl — NOT DECLARED)
    ✗ write:filesystem       (fs.writeFileSync — NOT DECLARED)

  Permission drift detected: 2 undeclared capabilities
```

## What Is Not Implemented Yet

The README previously described signing/supply-chain verification. Those are **roadmap** items and are not in the current codebase:

- Cryptographic signing / verification
- Supply-chain verification / SBOM generation
- GitHub Action `effector-audit-action`

## Integration

### CI/CD Pipeline

```bash
# In your publish pipeline
effector-audit . && effector-audit permissions . && npm publish
```

### Registry Gate

`effector-audit` is designed to be a registry gate — ClawHub, MCP Registry, or any future capability registry can require signed, audited Effectors before listing them.

## Architecture

```
effector-audit
├── scanner/          # Static analysis engine
│   ├── rules/        # Detection rules (prompt injection, exfiltration, etc.)
│   ├── analyzer.js   # AST + content analysis for SKILL.md and code
│   └── reporter.js   # Output formatting (terminal, JSON)
├── permissions/       # Permission analysis
│   └── diff.js       # Permission drift detection
```

## Roadmap

- [x] **v0.1** — Core scanner (prompt injection + exfiltration + basic permission creep signals)
- [x] **v0.1** — Permission drift check (`effector.toml` vs detected behavior)
- [ ] **v0.2** — Signing + verification
- [ ] **v0.3** — Supply chain verification / SBOM
- [ ] **v0.4** — GitHub Action
- [ ] **v0.5** — Type contract verification (types catalog)
- [ ] **v1.0** — Production-ready, registry-gate capable

## Contributing

Security tooling needs adversarial thinking. We especially need:

- **New detection rules** — Found a new attack pattern? Submit a rule
- **False positive reports** — If the scanner flags legitimate patterns, we need to know
- **Registry integration** — Help us build gates for ClawHub, MCP Registry, and others
- **Signing UX** — Make signing as frictionless as possible for capability authors

## License

[MIT](./LICENSE)

---

<sub>Part of the <a href="https://github.com/effectorHQ">effectorHQ</a> studio. We build hands for AI.</sub>
