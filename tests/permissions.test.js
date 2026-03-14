/**
 * Tests for permissions/diff.js
 */

import { test } from 'node:test';
import assert from 'node:assert';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { checkPermissions } from '../src/permissions/diff.js';

async function createTempDir(files) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'audit-perm-'));
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(dir, name);
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, content, 'utf-8');
  }
  return dir;
}

async function cleanup(dir) {
  await fs.rm(dir, { recursive: true, force: true });
}

test('checkPermissions: detects network access', async () => {
  const dir = await createTempDir({
    'SKILL.md': `---
name: net-skill
---
## Commands
curl https://api.example.com/data
`,
  });

  try {
    const originalLog = console.log;
    console.log = () => {};
    const result = await checkPermissions(dir);
    console.log = originalLog;

    assert.ok(result.detected.some(p => p.startsWith('network:')));
  } finally {
    await cleanup(dir);
  }
});

test('checkPermissions: detects filesystem reads', async () => {
  const dir = await createTempDir({
    'handler.js': 'const data = readFileSync("/etc/config", "utf-8");',
  });

  try {
    const originalLog = console.log;
    console.log = () => {};
    const result = await checkPermissions(dir);
    console.log = originalLog;

    assert.ok(result.detected.includes('read:filesystem'));
  } finally {
    await cleanup(dir);
  }
});

test('checkPermissions: detects subprocess execution', async () => {
  const dir = await createTempDir({
    'run.js': 'const { execSync } = require("child_process");\nexecSync("ls -la");',
  });

  try {
    const originalLog = console.log;
    console.log = () => {};
    const result = await checkPermissions(dir);
    console.log = originalLog;

    assert.ok(result.detected.includes('subprocess:exec'));
  } finally {
    await cleanup(dir);
  }
});

test('checkPermissions: no drift when no toml and no behavior', async () => {
  const dir = await createTempDir({
    'SKILL.md': `---
name: inert-skill
---
## Purpose
Just returns a static string.
`,
  });

  try {
    const originalLog = console.log;
    console.log = () => {};
    const result = await checkPermissions(dir);
    console.log = originalLog;

    assert.strictEqual(result.undeclared.length, 0);
  } finally {
    await cleanup(dir);
  }
});

test('checkPermissions: extracts specific domains', async () => {
  const dir = await createTempDir({
    'SKILL.md': `---
name: linear-skill
---
## Commands
curl https://api.linear.app/graphql
curl https://api.github.com/repos
`,
  });

  try {
    const originalLog = console.log;
    console.log = () => {};
    const result = await checkPermissions(dir);
    console.log = originalLog;

    assert.ok(result.detected.includes('network:api.linear.app'));
    assert.ok(result.detected.includes('network:api.github.com'));
  } finally {
    await cleanup(dir);
  }
});

test('checkPermissions: returns undeclared capabilities', async () => {
  const dir = await createTempDir({
    'effector.toml': `[effector]
name = "test"
`,
    'SKILL.md': `---
name: test
---
## Commands
curl https://api.example.com/secret
`,
  });

  try {
    const originalLog = console.log;
    console.log = () => {};
    const result = await checkPermissions(dir);
    console.log = originalLog;

    // No permissions declared but network detected → undeclared
    assert.ok(result.undeclared.length > 0);
  } finally {
    await cleanup(dir);
  }
});
