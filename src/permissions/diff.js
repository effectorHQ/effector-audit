/**
 * Permission drift detection.
 * Compares declared permissions in effector.toml against detected behavior in content.
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { parseEffectorToml } from '@effectorhq/core/toml';

/**
 * Analyze permission drift between declared and detected capabilities.
 * @param {string} targetPath
 * @returns {Promise<{ declared: string[], detected: string[], undeclared: string[], unused: string[] }>}
 */
export async function checkPermissions(targetPath) {
  const declared = parseDeclaredPermissions(targetPath);
  const detected = detectActualBehavior(targetPath);

  const undeclared = detected.filter((p) => !declared.includes(p));
  const unused = declared.filter((p) => !detected.includes(p));

  // Output
  console.log('\n  Declared permissions:');
  for (const p of declared) {
    const used = detected.includes(p);
    console.log(`    ${used ? '✓' : '○'} ${p}`);
  }

  if (detected.length > 0) {
    console.log('\n  Detected behavior:');
    for (const p of detected) {
      const isDeclared = declared.includes(p);
      console.log(`    ${isDeclared ? '✓' : '✗'} ${p}${isDeclared ? '' : '  — NOT DECLARED'}`);
    }
  }

  return { declared, detected, undeclared, unused };
}

function parseDeclaredPermissions(targetPath) {
  const manifestPath = join(targetPath, 'effector.toml');
  if (!existsSync(manifestPath)) return [];

  const content = readFileSync(manifestPath, 'utf-8');
  const def = parseEffectorToml(content);
  return normalizeDeclaredPermissions(def?.permissions);
}

function normalizeDeclaredPermissions(permissions) {
  if (!permissions) return [];

  const declared = new Set();

  // effector-spec defines an object model; @effectorhq/core/toml currently parses:
  // { network:boolean, subprocess:boolean, envRead:string[], envWrite:string[], filesystem:string[] }
  // filesystem is an array but does not encode read vs write; we treat it as allowing both.
  if (permissions.network) declared.add('network:external');
  if (permissions.subprocess) declared.add('subprocess:exec');

  if (Array.isArray(permissions.envRead) && permissions.envRead.length > 0) declared.add('env:read');
  if (Array.isArray(permissions.envWrite) && permissions.envWrite.length > 0) declared.add('env:write');

  if (Array.isArray(permissions.filesystem) && permissions.filesystem.length > 0) {
    declared.add('read:filesystem');
    declared.add('write:filesystem');
  }

  return [...declared];
}

function detectActualBehavior(targetPath) {
  const detected = new Set();

  // Scan all text files for behavior patterns
  const files = collectTextFiles(targetPath);

  for (const file of files) {
    const content = readFileSync(file, 'utf-8');

    // Filesystem
    if (/readFileSync|fs\.read|cat\s+\//i.test(content)) detected.add('read:filesystem');
    if (/writeFileSync|fs\.write|>\s+\/|tee\s+/i.test(content)) detected.add('write:filesystem');

    // Network
    if (/curl|wget|fetch\(|axios|http\.get|http\.post/i.test(content)) {
      detected.add('network:external');
      // Try to extract specific domains
      const urlMatch = content.match(/https?:\/\/([^\/\s'"]+)/g);
      if (urlMatch) {
        for (const url of urlMatch) {
          try {
            const domain = new URL(url).hostname;
            detected.add(`network:${domain}`);
          } catch { /* ignore malformed URLs */ }
        }
      }
    }

    // Subprocess
    if (/exec\(|execSync|spawn|child_process/i.test(content)) detected.add('subprocess:exec');

    // Environment variables
    if (/process\.env|getenv|\$\{?\w+\}?/i.test(content)) detected.add('env:read');
  }

  return [...detected];
}

function collectTextFiles(dir) {
  const results = [];

  try {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
        results.push(...collectTextFiles(fullPath));
      } else if (entry.isFile()) {
        const ext = entry.name.split('.').pop();
        if (['md', 'js', 'ts', 'py', 'toml', 'yml', 'yaml'].includes(ext)) {
          results.push(fullPath);
        }
      }
    }
  } catch { /* directory not readable */ }

  return results;
}
