#!/usr/bin/env node

/**
 * effector-audit — Security audit and cryptographic signing for AI agent capabilities.
 *
 * Usage:
 *   effector-audit scan <path>          Static analysis for vulnerabilities
 *   effector-audit sign <path>          Sign an Effector package (Sigstore)
 *   effector-audit verify <path>        Verify signature and provenance
 *   effector-audit permissions <path>   Analyze permission drift
 *   effector-audit supply-chain <path>  Verify dependency trust chain
 *   effector-audit --help               Show this help
 *   effector-audit --version            Show version
 */

import { parseArgs } from 'node:util';
import { scan } from '../src/scanner/analyzer.js';
import { checkPermissions } from '../src/permissions/diff.js';

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    help: { type: 'boolean', short: 'h' },
    version: { type: 'boolean', short: 'v' },
    format: { type: 'string', short: 'f', default: 'terminal' },
    'fail-on': { type: 'string', default: 'critical' },
  },
});

if (values.version) {
  console.log('effector-audit 0.1.0');
  process.exit(0);
}

if (values.help || positionals.length === 0) {
  console.log(`
effector-audit — Security audit and signing for AI agent capabilities

Commands:
  scan <path>           Static analysis for vulnerabilities
  sign <path>           Sign an Effector package (Sigstore keyless)
  verify <path>         Verify signature and provenance
  permissions <path>    Detect permission drift
  supply-chain <path>   Verify dependency trust chain

Options:
  -f, --format <fmt>    Output format: terminal, json, sarif (default: terminal)
  --fail-on <level>     Fail threshold: critical, high, medium, low (default: critical)
  -h, --help            Show this help
  -v, --version         Show version
`);
  process.exit(0);
}

const [command, targetPath] = positionals;

if (!targetPath) {
  console.error('Error: path is required. Usage: effector-audit <command> <path>');
  process.exit(1);
}

async function main() {
  switch (command) {
    case 'scan': {
      const results = await scan(targetPath, { format: values.format });
      const failLevel = values['fail-on'] || 'critical';
      const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
      const threshold = severityOrder.indexOf(failLevel);
      const hasFailing = results.findings.some(
        (f) => severityOrder.indexOf(f.severity) <= threshold
      );
      process.exit(hasFailing ? 1 : 0);
    }

    case 'sign':
      console.log('Signing is not yet implemented. Coming in v0.2.');
      console.log('Will use Sigstore keyless signing via Fulcio + Rekor.');
      process.exit(0);

    case 'verify':
      console.log('Verification is not yet implemented. Coming in v0.2.');
      process.exit(0);

    case 'permissions': {
      const drift = await checkPermissions(targetPath);
      if (drift.undeclared.length > 0) {
        console.log(`\n  Permission drift detected: ${drift.undeclared.length} undeclared capabilities`);
        process.exit(1);
      }
      console.log('\n  No permission drift detected.');
      process.exit(0);
    }

    case 'supply-chain':
      console.log('Supply chain verification is not yet implemented. Coming in v0.4.');
      process.exit(0);

    default:
      console.error(`Unknown command: ${command}`);
      console.error('Run effector-audit --help for usage.');
      process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal:', err.message);
  process.exit(1);
});
