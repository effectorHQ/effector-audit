/**
 * Detection rules for effector-audit scanner.
 * Each rule is a function that checks file content and returns findings.
 */

import { parseEffectorToml } from '@effectorhq/core/toml';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

// Context types that imply network access
const NETWORK_CONTEXT_TYPES = new Set([
  'GitHubCredentials', 'APICredentials', 'SlackCredentials',
  'AWSCredentials', 'GenericAPIKey',
]);

// Context types that imply filesystem access
const FILESYSTEM_CONTEXT_TYPES = new Set([
  'Repository',
]);

/** Check permission-interface consistency in effector.toml files. */
const permissionInterfaceConsistency = {
  id: 'permission-interface-mismatch',
  check(content, lines, file) {
    if (!file.endsWith('effector.toml')) return [];

    const findings = [];
    const toml = parseEffectorToml(content);
    const context = toml.interface?.context || [];
    const perms = toml.permissions;

    for (const ctxType of context) {
      if (NETWORK_CONTEXT_TYPES.has(ctxType) && !perms.network) {
        findings.push({
          severity: 'medium',
          rule: 'permission-interface-mismatch',
          message: `Context type "${ctxType}" implies network access, but network = false in permissions`,
          file,
        });
      }
      if (FILESYSTEM_CONTEXT_TYPES.has(ctxType) && !perms.filesystem?.length) {
        findings.push({
          severity: 'low',
          rule: 'permission-interface-mismatch',
          message: `Context type "${ctxType}" implies filesystem access, but no filesystem paths declared in permissions`,
          file,
        });
      }
    }

    return findings;
  },
};

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

    if (file.endsWith('effector.toml')) return [];

    // Unit tests (and some repos) may pass TOML content directly without a real file tree.
    // If this looks like an effector manifest section, treat this file as the declaration source.
    let declared;
    if (file.endsWith('.toml') && /\[effector\.permissions\]/.test(content)) {
      try {
        declared = normalizeDeclaredPermissions(parseEffectorToml(content)?.permissions);
      } catch {
        declared = new Set();
      }
    } else {
      declared = getDeclaredCapabilitiesForFile(file);
    }
    const hasManifest = declared.size > 0;

    const hasReadOps = /readFileSync|fs\.read|cat\s+\//i.test(content);
    const hasWriteOps = /writeFileSync|fs\.write|>\s+\/|>>\s+\/|tee\s+\//i.test(content);
    const hasNetworkOps = /curl\s+|wget\s+|fetch\(|axios|http\.get|http\.post|request\(/i.test(content);
    const hasSubprocessOps = /exec\(|execSync|spawn|child_process/i.test(content);
    const hasEnvReadOps = /process\.env|getenv|\$\{?\w+\}?/i.test(content);

    if (hasReadOps && (!hasManifest || !declared.has('read:filesystem'))) {
      findings.push({
        severity: 'medium',
        rule: 'permission-creep',
        message: hasManifest
          ? 'Filesystem read operations detected but filesystem permission not declared in effector.toml'
          : 'Filesystem read operations detected but no effector.toml found to declare permissions',
        file,
      });
    }

    if (hasWriteOps && (!hasManifest || !declared.has('write:filesystem'))) {
      findings.push({
        severity: 'medium',
        rule: 'permission-creep',
        message: hasManifest
          ? 'Filesystem write operations detected but filesystem permission not declared in effector.toml'
          : 'Filesystem write operations detected but no effector.toml found to declare permissions',
        file,
      });
    }

    if (hasNetworkOps && (!hasManifest || !declared.has('network:external'))) {
      findings.push({
        severity: 'medium',
        rule: 'permission-creep',
        message: hasManifest
          ? 'Network access detected but network permission not declared in effector.toml'
          : 'Network access detected but no effector.toml found to declare permissions',
        file,
      });
    }

    if (hasSubprocessOps && (!hasManifest || !declared.has('subprocess:exec'))) {
      findings.push({
        severity: 'medium',
        rule: 'permission-creep',
        message: hasManifest
          ? 'Subprocess usage detected but subprocess permission not declared in effector.toml'
          : 'Subprocess usage detected but no effector.toml found to declare permissions',
        file,
      });
    }

    if (hasEnvReadOps && (!hasManifest || !declared.has('env:read'))) {
      findings.push({
        severity: 'low',
        rule: 'permission-creep',
        message: hasManifest
          ? 'Environment variable access detected but env-read not declared in effector.toml'
          : 'Environment variable access detected but no effector.toml found to declare permissions',
        file,
      });
    }

    return findings;
  },
};

const manifestCache = new Map();

function getDeclaredCapabilitiesForFile(filePath) {
  const root = findNearestPackageRoot(filePath);
  if (!root) return new Set();

  const cached = manifestCache.get(root);
  if (cached) return cached;

  const manifestPath = join(root, 'effector.toml');
  try {
    const def = parseEffectorToml(readFileSync(manifestPath, 'utf-8'));
    const declared = normalizeDeclaredPermissions(def?.permissions);
    manifestCache.set(root, declared);
    return declared;
  } catch {
    const empty = new Set();
    manifestCache.set(root, empty);
    return empty;
  }
}

function findNearestPackageRoot(filePath) {
  let dir = dirname(filePath);

  for (let i = 0; i < 50; i++) {
    const manifestPath = join(dir, 'effector.toml');
    if (existsSync(manifestPath)) return dir;

    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }

  return null;
}

function normalizeDeclaredPermissions(permissions) {
  const declared = new Set();
  if (!permissions) return declared;

  if (permissions.network) declared.add('network:external');
  if (permissions.subprocess) declared.add('subprocess:exec');

  if (Array.isArray(permissions.envRead) && permissions.envRead.length > 0) declared.add('env:read');
  if (Array.isArray(permissions.envWrite) && permissions.envWrite.length > 0) declared.add('env:write');

  // @effectorhq/core/toml currently doesn't encode read vs write separately; treat as both.
  if (Array.isArray(permissions.filesystem) && permissions.filesystem.length > 0) {
    declared.add('read:filesystem');
    declared.add('write:filesystem');
  }

  return declared;
}

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

export const rules = [promptInjection, dataExfiltration, permissionCreep, obfuscation, permissionInterfaceConsistency];
