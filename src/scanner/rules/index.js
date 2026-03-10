/**
 * Detection rules for effector-audit scanner.
 * Each rule is a function that checks file content and returns findings.
 */

/** Detect prompt injection patterns in SKILL.md and prompt files. */
const promptInjection = {
  id: 'prompt-injection',
  check(content, lines, file) {
    const findings = [];
    const patterns = [
      { regex: /ignore\s+(all\s+)?previous\s+instructions/i, msg: 'System prompt override attempt detected' },
      { regex: /you\s+are\s+now\s+(a|an)\s+/i, msg: 'Role reassignment attempt detected' },
      { regex: /disregard\s+(your|all|the)\s+(instructions|rules|guidelines)/i, msg: 'Instruction override attempt detected' },
      { regex: /\bDAN\b.*\bjailbreak/i, msg: 'Known jailbreak pattern detected' },
      { regex: /system:\s*you\s+must/i, msg: 'Injected system directive detected' },
      { regex: /\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>/i, msg: 'Chat template injection markers detected' },
    ];

    for (let i = 0; i < lines.length; i++) {
      for (const { regex, msg } of patterns) {
        if (regex.test(lines[i])) {
          findings.push({
            severity: 'critical',
            rule: 'prompt-injection',
            message: msg,
            file,
            line: i + 1,
          });
        }
      }
    }
    return findings;
  },
};

/** Detect potential data exfiltration vectors. */
const dataExfiltration = {
  id: 'data-exfiltration',
  check(content, lines, file) {
    const findings = [];
    const patterns = [
      { regex: /curl\s+.*-d\s+.*\$/, msg: 'Curl POST with variable data — potential exfiltration' },
      { regex: /fetch\s*\(\s*['"][^'"]*['"].*body/, msg: 'Fetch POST request — verify data destination' },
      { regex: /webhook\.site|requestbin|pipedream|ngrok/i, msg: 'Known data collection service URL detected' },
      { regex: /btoa\s*\(|base64.*encode|\.toString\s*\(\s*['"]base64/i, msg: 'Base64 encoding of data — potential obfuscated exfiltration' },
    ];

    for (let i = 0; i < lines.length; i++) {
      for (const { regex, msg } of patterns) {
        if (regex.test(lines[i])) {
          findings.push({
            severity: 'high',
            rule: 'data-exfiltration',
            message: msg,
            file,
            line: i + 1,
          });
        }
      }
    }
    return findings;
  },
};

/** Detect permission creep — declared vs actual behavior mismatch signals. */
const permissionCreep = {
  id: 'permission-creep',
  check(content, lines, file) {
    const findings = [];

    // Check for filesystem writes in skills that don't declare write permissions
    const hasWriteDeclaration = /permissions.*write:filesystem|access.*write/i.test(content);
    const hasWriteOps = /writeFileSync|fs\.write|> \/|>> \/|tee\s+\//i.test(content);

    if (hasWriteOps && !hasWriteDeclaration) {
      findings.push({
        severity: 'medium',
        rule: 'permission-creep',
        message: 'Filesystem write operations detected but no write permission declared',
        file,
      });
    }

    // Check for network access in skills that don't declare it
    const hasNetworkDeclaration = /permissions.*network|requires.*api|domains/i.test(content);
    const hasNetworkOps = /curl\s+|wget\s+|fetch\(|http\.get|axios\.|request\(/i.test(content);

    if (hasNetworkOps && !hasNetworkDeclaration) {
      findings.push({
        severity: 'medium',
        rule: 'permission-creep',
        message: 'Network access detected but no network permission declared',
        file,
      });
    }

    return findings;
  },
};

/** Detect obfuscated content that may hide malicious instructions. */
const obfuscation = {
  id: 'obfuscation',
  check(content, lines, file) {
    const findings = [];

    // Base64 encoded blocks longer than 100 chars (potential hidden payload)
    const base64Regex = /[A-Za-z0-9+/=]{100,}/;
    for (let i = 0; i < lines.length; i++) {
      if (base64Regex.test(lines[i]) && !file.endsWith('.json')) {
        findings.push({
          severity: 'medium',
          rule: 'obfuscation',
          message: 'Large base64-encoded block detected — verify contents',
          file,
          line: i + 1,
        });
      }
    }

    // Unicode tricks (zero-width characters, RTL override)
    const unicodeTricks = /[\u200B\u200C\u200D\u2060\u202A\u202B\u202C\u202D\u202E\uFEFF]/;
    for (let i = 0; i < lines.length; i++) {
      if (unicodeTricks.test(lines[i])) {
        findings.push({
          severity: 'high',
          rule: 'obfuscation',
          message: 'Hidden unicode characters detected (zero-width or RTL override)',
          file,
          line: i + 1,
        });
      }
    }

    return findings;
  },
};

export const rules = [promptInjection, dataExfiltration, permissionCreep, obfuscation];
