/**
 * Static analysis engine for Effector packages.
 * Scans SKILL.md files, code, and manifests for security vulnerabilities.
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, extname } from 'node:path';
import { rules } from './rules/index.js';

/**
 * @param {string} targetPath - Path to the Effector package directory
 * @param {{ format?: string }} options
 * @returns {Promise<{ findings: Array<{ severity: string, rule: string, message: string, file?: string, line?: number }>, summary: { critical: number, high: number, medium: number, low: number, info: number } }>}
 */
export async function scan(targetPath, options = {}) {
  const findings = [];

  // Collect all scannable files
  const files = collectFiles(targetPath);

  for (const file of files) {
    const content = readFileSync(file, 'utf-8');
    const lines = content.split('\n');

    for (const rule of rules) {
      const ruleFindings = rule.check(content, lines, file);
      findings.push(...ruleFindings);
    }
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));

  const summary = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    info: findings.filter((f) => f.severity === 'info').length,
  };

  // Output
  if (options.format === 'json') {
    console.log(JSON.stringify({ findings, summary }, null, 2));
  } else {
    printTerminal(findings, summary);
  }

  return { findings, summary };
}

function collectFiles(dir) {
  const results = [];
  const scannableExts = new Set(['.md', '.js', '.ts', '.py', '.toml', '.yml', '.yaml', '.json']);

  if (!existsSync(dir)) return results;

  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
      results.push(...collectFiles(fullPath));
    } else if (entry.isFile() && scannableExts.has(extname(entry.name))) {
      results.push(fullPath);
    }
  }
  return results;
}

function printTerminal(findings, summary) {
  const icons = { critical: '✗', high: '✗', medium: '⚠', low: '⚠', info: '✓' };
  const colors = { critical: '\x1b[31m', high: '\x1b[31m', medium: '\x1b[33m', low: '\x1b[33m', info: '\x1b[32m' };
  const reset = '\x1b[0m';

  console.log('');
  for (const f of findings) {
    const icon = icons[f.severity] || '?';
    const color = colors[f.severity] || '';
    const loc = f.line ? ` Line ${f.line}:` : '';
    console.log(`  ${color}${icon} ${f.severity.toUpperCase().padEnd(9)}${reset} ${f.rule.padEnd(22)}${loc} ${f.message}`);
  }

  const total = findings.length;
  if (total === 0) {
    console.log('  \x1b[32m✓ No issues found\x1b[0m');
  } else {
    console.log('');
    const parts = [];
    if (summary.critical) parts.push(`${summary.critical} critical`);
    if (summary.high) parts.push(`${summary.high} high`);
    if (summary.medium) parts.push(`${summary.medium} medium`);
    if (summary.low) parts.push(`${summary.low} low`);
    console.log(`  ${parts.join(', ')} — audit ${summary.critical + summary.high > 0 ? 'failed' : 'passed with warnings'}`);
  }
  console.log('');
}
