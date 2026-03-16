# effector-audit

[![npm version](https://img.shields.io/badge/npm-effector--audit-E03E3E.svg)](https://www.npmjs.com/package/effector-audit)
[![CI](https://github.com/effectorHQ/effector-audit/actions/workflows/test.yml/badge.svg)](https://github.com/effectorHQ/effector-audit/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#)

**Security audit and cryptographic signing for AI agent capabilities.**

---

## The Trust Crisis

On February 18, 2026, Snyk published the [ToxicSkills Report](https://snyk.io/blog/toxicskills/). The findings were severe: **36% of ClawHub skills contained prompt injection or malicious payloads.** The ClawHavoc campaign had planted 1,184+ malicious skills targeting developers. Trend Micro confirmed distribution of the Atomic macOS Stealer through community-published skills. Microsoft, Cisco, and 1Password all published independent analyses confirming the systemic nature of the threat.

The root cause wasn't a bug. It was an architectural absence: **no code signing, no security review, no formal permission model for AI agent capabilities.** Anyone could publish a skill to ClawHub. Everyone had to trust it blindly.

This is npm circa 2018 — before `npm audit`, before lockfiles, before Sigstore. Except the stakes are higher, because AI agent capabilities don't just run code. They control what an AI does in the world: reading your files, calling APIs, sending messages, modifying databases.

`effector-audit` closes this gap.

## Install

```bash
npm install effector-audit
```

You can also use the CLI directly without installing globally:

```bash
npx effector-audit ./my-skill
npx effector-audit ./my-skill --format json
```

See the published package on npm: **https://www.npmjs.com/package/effector-audit**

## What It Does

### 1. Static Analysis

Scans Effector packages for known vulnerability patterns:

```bash
npx effector-audit scan ./my-skill/

  ✗ CRITICAL  prompt-injection    Line 23: System prompt override detected
  ✗ HIGH      data-exfiltration   Line 47: Unscoped network access to external domain
  ⚠ MEDIUM    permission-creep    Requests filesystem write but description says "read-only"
  ✓ PASS      dependency-check    All dependencies are signed and verified
  ✓ PASS      type-safety         Interface types match declared contract

  2 critical, 1 warning — audit failed
```

**Detection patterns include:**
- Prompt injection and jailbreak attempts in SKILL.md content
- Permission declarations that exceed described functionality
- Data exfiltration vectors (unscoped network, filesystem access)
- Dependency vulnerabilities (transitive risk analysis)
- Type contract violations (declared interface vs. actual behavior)
- Obfuscated instructions (base64, unicode tricks, invisible text)

### 2. Cryptographic Signing

Sign Effector packages with [Sigstore](https://www.sigstore.dev/) — the same infrastructure securing npm, PyPI, and Homebrew:

```bash
# Sign with your identity (keyless, tied to OIDC identity)
npx effector-audit sign ./my-skill/

  ✓ Signed by: developer@example.com
  ✓ Transparency log: rekor.sigstore.dev/e/12345
  ✓ Signature: effector.sig (detached, verifiable)

# Verify before installing
npx effector-audit verify ./downloaded-skill/

  ✓ Signed by: developer@example.com (verified via Fulcio)
  ✓ Signature valid, not tampered
  ✓ Timestamp: 2026-03-10T14:32:00Z (Rekor logged)
```

No PGP keys to manage. No key servers. Identity-based signing through existing GitHub/Google/Microsoft accounts, backed by certificate transparency logs.

### 3. Permission Verification

Cross-references declared permissions against actual capability behavior:

```bash
npx effector-audit permissions ./my-skill/

  Declared permissions:
    ✓ read:repository
    ✓ network:api.github.com

  Detected behavior:
    ✓ read:repository        (Line 12: uses gh api repos/...)
    ✗ network:slack.com      (Line 34: curl to Slack webhook — NOT DECLARED)
    ✗ write:filesystem       (Line 45: writes to /tmp — NOT DECLARED)

  Permission drift detected: 2 undeclared capabilities
```

### 4. Supply Chain Verification

Verify the entire dependency tree:

```bash
npx effector-audit supply-chain ./my-workflow/

  Dependencies:
    ├── code-review@1.2.0      ✓ signed (effectorHQ)
    ├── security-scan@2.0.0    ✓ signed (snyk-community)
    ├── slack-notify@0.5.0     ⚠ unsigned (community)
    └── custom-formatter@0.1.0 ✗ unverified (no provenance)

  Trust chain: 2/4 verified, 1 unsigned, 1 unverified
  Recommendation: Pin custom-formatter to exact version, request signing
```

## Why This Matters Now

The attack surface for AI agent capabilities is unique and growing:

| Attack vector | Traditional software | AI agent capabilities |
|---------------|---------------------|----------------------|
| Code injection | Runs in sandbox | **Controls AI behavior — acts with user's permissions** |
| Dependency confusion | Installs wrong package | **Teaches AI wrong skills — behavioral corruption** |
| Permission escalation | OS-level containment | **No standard permission model — skills do whatever they want** |
| Supply chain | Lock files, SBOMs | **No signing, no provenance, no verification** |

The February 2026 ClawHub crisis was the "left-pad moment" for AI capabilities — except instead of broken builds, the consequence was compromised agents exfiltrating data and installing malware.

Research supports this urgency:
- Vercel's analysis found that **reducing to the right tools matters more than adding more tools** — bad tools create infinite loops and cascading failures ([Vercel Security Boundaries, 2026](https://vercel.com/blog/security-boundaries-in-agentic-architectures))
- The ACNBP framework ([arXiv:2506.13590](https://arxiv.org/abs/2506.13590)) proposed capability attestation for multi-agent systems — `effector-audit` provides the concrete implementation
- Defense-in-depth architectures now require **app-level sandboxing + secret injection** as standard practice ([NVIDIA Sandboxing Guidance, 2026](https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/))

## Integration

### GitHub Action

```yaml
- uses: effectorHQ/effector-audit-action@v1
  with:
    path: ./skills/
    fail-on: critical
    verify-signatures: true
```

### CI/CD Pipeline

```bash
# In your publish pipeline
effector-audit scan . && effector-audit sign . && npm publish
```

### Registry Gate

`effector-audit` is designed to be a registry gate — ClawHub, MCP Registry, or any future capability registry can require signed, audited Effectors before listing them.

## Architecture

```
effector-audit
├── scanner/          # Static analysis engine
│   ├── rules/        # Detection rules (prompt injection, exfiltration, etc.)
│   ├── analyzer.js   # AST + content analysis for SKILL.md and code
│   └── reporter.js   # Output formatting (terminal, JSON, SARIF)
├── signer/           # Sigstore integration
│   ├── sign.js       # Keyless signing via Fulcio
│   ├── verify.js     # Signature verification via Rekor
│   └── bundle.js     # Signature bundling in effector.toml
├── permissions/       # Permission analysis
│   ├── declared.js   # Parse permission declarations from manifest
│   ├── detected.js   # Detect actual behavior from content analysis
│   └── diff.js       # Permission drift detection
└── supply-chain/     # Dependency tree verification
    ├── resolve.js    # Dependency resolution
    ├── verify.js     # Transitive trust verification
    └── sbom.js       # Software Bill of Materials generation
```

## Roadmap

- [ ] **v0.1** — Core scanner with prompt injection + exfiltration detection, CLI output
- [ ] **v0.2** — Sigstore signing + verification, GitHub Action
- [ ] **v0.3** — Permission analysis, drift detection
- [ ] **v0.4** — Supply chain verification, SBOM generation
- [ ] **v0.5** — Integration with `effector-types` (type contract verification)
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
