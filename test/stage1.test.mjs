/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Comprehensive Stage 1 Native `node:test` Suite (28 Deterministic Vectors)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';

import { jcsCanonicalize, jcsStringify } from '../src/core/jcs.mjs';
import {
  DOMAIN_PREFIX,
  allocSecure,
  b64u,
  domainSha256,
  ensureDeviceEd25519Keypair,
  signDomainPayload,
  unb64u,
  verifyDomainPayload,
  zeroizeBuffer,
} from '../src/core/crypto-primitives.mjs';
import {
  backupConfigBeforeEdit,
  parseJsoncSafe,
  withPidLock,
  writeFileAtomic600,
} from '../src/core/workspace-io.mjs';
import { SipPipelineBus } from '../src/core/pipeline-bus.mjs';
import { discoverMcpConfigs } from '../src/stage1/config-discovery.mjs';
import {
  formatAuditSarif,
  formatAuditTerminalReport,
  maskSecretPreview,
  runStaticMcpAudit,
} from '../src/stage1/audit-scanner.mjs';
import { createOrUpdateSchemaLock, verifySchemaLock } from '../src/stage1/schema-lock.mjs';
import { runCli } from '../src/cli.mjs';

/**
 * Helper to run a test inside an isolated temporary workspace and clean up afterwards.
 * @param {(dir: string) => Promise<void> | void} fn
 */
async function withTempSandbox(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sip-v3-stage1-'));
  try {
    await fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ============================================================================
// 1. RFC 8785 JCS Determinism
// ============================================================================

test('01. RFC 8785 JCS sorts object keys strictly by raw UTF-16 code units', () => {
  // RFC 8785 Section 3.2.3 key sorting vector:
  // "\r" (0x000D) < "1" (0x0031) < "a" (0x0061) < "\u0080" (0x0080) < "\uD83D\uDE00" (0xD83D...) < "\uFB33" (0xFB33)
  const input = {
    '\ufb33': 'hebrew',
    a: 'latin',
    '\ud83d\ude00': 'surrogate-pair',
    '1': 'digit',
    '\u0080': 'c1',
    '\r': 'cr',
  };
  const canonical = jcsStringify(input);
  assert.equal(
    canonical,
    '{"\\r":"cr","1":"digit","a":"latin","\u0080":"c1","\ud83d\ude00":"surrogate-pair","\ufb33":"hebrew"}'
  );
  assert.ok(Buffer.isBuffer(jcsCanonicalize(input)));
});

test('02. RFC 8785 JCS normalizes -0 to "0", omits undefined object keys, maps array undefined to null', () => {
  const obj = {
    zeroNeg: -0,
    zeroPos: 0,
    omitted: undefined,
    nested: { b: 2, a: 1, skip: undefined },
    arr: [1, undefined, -0, true, null],
  };
  assert.equal(
    jcsStringify(obj),
    '{"arr":[1,null,0,true,null],"nested":{"a":1,"b":2},"zeroNeg":0,"zeroPos":0}'
  );
});

test('03. RFC 8785 JCS throws TypeError on NaN, Infinity, -Infinity, and BigInt', () => {
  assert.throws(() => jcsStringify({ bad: Number.NaN }), TypeError);
  assert.throws(() => jcsStringify({ bad: Number.POSITIVE_INFINITY }), TypeError);
  assert.throws(() => jcsStringify({ bad: Number.NEGATIVE_INFINITY }), TypeError);
  assert.throws(() => jcsStringify(10n), TypeError);
});

// ============================================================================
// 2. Domain-Separated Crypto & Secure Memory
// ============================================================================

test('04. Crypto primitives enforce b64u lengths (43B SHA-256, 86B Ed25519) and domain separation', async () => {
  await withTempSandbox((dir) => {
    const sipDir = path.join(dir, '.sip');
    const sec = allocSecure(32);
    assert.equal(sec.length, 32);
    assert.ok(sec.every((b) => b === 0));
    sec[0] = 0xaa;
    zeroizeBuffer(sec);
    assert.ok(sec.every((b) => b === 0));

    const h0 = domainSha256(DOMAIN_PREFIX.EVENT_SKELETON, 'payload');
    const h6 = domainSha256(DOMAIN_PREFIX.SCHEMA_LOCK, 'payload');
    assert.notDeepEqual(h0, h6, 'Different domain prefix bytes must produce distinct digests');
    assert.equal(b64u(h6).length, 43);
    assert.deepEqual(unb64u(b64u(h6)), h6);
    assert.throws(() => unb64u('abc='), /Invalid base64url/);

    const kp = ensureDeviceEd25519Keypair(sipDir);
    assert.equal(kp.publicKeyB64u.length, 43);
    const sig = signDomainPayload('SIP-TEST', h6, kp.privateKey);
    assert.equal(sig.length, 86);
    assert.equal(verifyDomainPayload('SIP-TEST', h6, sig, kp.publicKeyB64u), true);
    assert.equal(verifyDomainPayload('SIP-WRONG-DOMAIN', h6, sig, kp.publicKeyB64u), false);
  });
});

// ============================================================================
// 3. Bulletproof JSONC Parser, Atomic IO & PID Lock
// ============================================================================

test('05. parseJsoncSafe strips BOM, // and /* */ comments, trailing commas while preserving https:// URLs in strings', () => {
  const rawVscodeJsonc = `\uFEFF{
    // VS Code MCP configuration with comments and URLs
    "servers": {
      "atlassian": {
        "type": "http",
        "url": "https://mcp.atlassian.com/v2/mcp", // inline comment after URL!
        "headers": {
          "X-Note": "keep // slashes and /* stars */ and [1,2,] inside string!",
        },
      }, /* multi-line
            block comment */
    },
  }`;

  const parsed = parseJsoncSafe(rawVscodeJsonc);
  assert.equal(parsed.servers.atlassian.url, 'https://mcp.atlassian.com/v2/mcp');
  assert.equal(
    parsed.servers.atlassian.headers['X-Note'],
    'keep // slashes and /* stars */ and [1,2,] inside string!'
  );
});

test('06. parseJsoncSafe reports exact line and column on malformed JSONC', () => {
  const broken = `{\n  // comment on line 2\n  "mcpServers": {\n    "bad": truX\n  }\n}`;
  assert.throws(
    () => parseJsoncSafe(broken),
    (err) => {
      assert.ok(err instanceof SyntaxError);
      assert.equal(err.line, 4);
      assert.ok(err.column >= 1);
      return true;
    }
  );
});

test('07. withPidLock reclaims dead-PID stale locks and writeFileAtomic600 enforces 0o600 permissions', async () => {
  await withTempSandbox(async (dir) => {
    const sipDir = path.join(dir, '.sip');
    fs.mkdirSync(sipDir, { recursive: true, mode: 0o700 });
    // Plant a dead PID lock
    fs.writeFileSync(
      path.join(sipDir, 'op.lock'),
      JSON.stringify({ pid: 999_999_999, ts: Date.now() }),
      'utf8'
    );

    let executed = false;
    await withPidLock(sipDir, () => {
      executed = true;
    });
    assert.equal(executed, true);
    assert.equal(fs.existsSync(path.join(sipDir, 'op.lock')), false);

    const target = path.join(sipDir, 'secret.json');
    writeFileAtomic600(target, '{"ok":true}');
    const mode = fs.statSync(target).mode & 0o777;
    assert.equal(mode, 0o600);
  });
});

test('08. SipPipelineBus executes registered Stage 1-4 slots deterministically with latency telemetry', async () => {
  const bus = new SipPipelineBus();
  assert.equal(bus.listSlots().length, 7);
  const order = [];
  bus.register('onConfigAudit', 'step-1', (ctx) => {
    order.push('first');
    return { count: ctx.count + 1 };
  });
  bus.register('onConfigAudit', 'step-2', (ctx) => {
    order.push('second');
    return { count: ctx.count * 10 };
  });

  const res = await bus.executeSlot('onConfigAudit', { count: 2 });
  assert.deepEqual(order, ['first', 'second']);
  assert.equal(res.context.count, 30);
  assert.equal(bus.getTelemetry().length, 2);
});

// ============================================================================
// 4. Cross-Platform 5-Client MCP Discovery
// ============================================================================

test('09. discoverMcpConfigs discovers Claude Desktop, Claude Code, Cursor, Windsurf, and VS Code ("servers" & "mcpServers")', async () => {
  await withTempSandbox((dir) => {
    const ws = path.join(dir, 'workspace');
    const home = path.join(dir, 'home');
    fs.mkdirSync(path.join(ws, '.cursor'), { recursive: true });
    fs.mkdirSync(path.join(ws, '.vscode'), { recursive: true });
    fs.mkdirSync(path.join(home, '.codeium', 'windsurf'), { recursive: true });
    fs.mkdirSync(path.join(home, 'Library', 'Application Support', 'Claude'), { recursive: true });

    fs.writeFileSync(
      path.join(ws, '.mcp.json'),
      JSON.stringify({ mcpServers: { claudeCodeSrv: { command: 'node', args: ['a.js'] } } })
    );
    fs.writeFileSync(
      path.join(ws, '.cursor', 'mcp.json'),
      JSON.stringify({ mcpServers: { cursorSrv: { command: 'node', args: ['b.js'] } } })
    );
    fs.writeFileSync(
      path.join(ws, '.vscode', 'mcp.json'),
      `{\n  // VS Code uses "servers" root object\n  "servers": {\n    "vscodeSrv": { "type": "http", "url": "https://mcp.example.com/sse", },\n  }\n}`
    );
    fs.writeFileSync(
      path.join(home, '.codeium', 'windsurf', 'mcp_config.json'),
      JSON.stringify({ mcpServers: { windsurfSrv: { command: 'node', args: ['w.js'] } } })
    );
    fs.writeFileSync(
      path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      JSON.stringify({ mcpServers: { desktopSrv: { command: 'node', args: ['d.js'] } } })
    );

    const configs = discoverMcpConfigs({
      workspaceDir: ws,
      homeDir: home,
      platform: 'darwin',
      includeGlobal: true,
    });

    const serverNames = configs.flatMap((c) => c.servers.map((s) => `${s.client}:${s.serverName}`));
    assert.ok(serverNames.includes('claude-code:claudeCodeSrv'));
    assert.ok(serverNames.includes('cursor:cursorSrv'));
    assert.ok(serverNames.includes('vscode:vscodeSrv'));
    assert.ok(serverNames.includes('windsurf:windsurfSrv'));
    assert.ok(serverNames.includes('claude-desktop:desktopSrv'));
  });
});

test('10. discoverMcpConfigs never throws on missing directories or malformed JSONC files', async () => {
  await withTempSandbox((dir) => {
    fs.writeFileSync(path.join(dir, '.mcp.json'), '{ malformed jsonc !!! ');
    const configs = discoverMcpConfigs({ workspaceDir: dir, includeGlobal: false });
    assert.equal(configs.length, 1);
    assert.ok(configs[0].parseError);
    assert.equal(configs[0].servers.length, 0);
  });
});

// ============================================================================
// 5. SIP-R01 Plaintext Secrets & Screenshot-Safe Zero-Leak Invariant
// ============================================================================

test('11. maskSecretPreview enforces <first4>****...****<last2> for >=8 chars and ****[REDACTED] for <8 chars', () => {
  assert.equal(maskSecretPreview('sk-p' + 'roj-123456789x'), 'sk-p****...****9x');
  assert.equal(maskSecretPreview('short77'), '****[REDACTED]');
  assert.equal(maskSecretPreview(''), '****[REDACTED]');
});

test('12. SIP-R01 detects OpenAI, AWS, GitHub, Slack, and Postgres DSN plaintext credentials', async () => {
  await withTempSandbox((dir) => {
    fs.writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          multiLeak: {
            command: 'npx',
            args: [
              '-y',
              '@vendor/mcp@1.0.0',
              'postgres://dbadmin:SuperSecretDbPass99@db.example.com:5432/prod',
            ],
            env: {
              OPENAI_API_KEY: 'sk-p' + 'roj-99887766554433221100abcdef',
              AWS_ACCESS_KEY_ID: 'AK' + 'IAIOSFODNN7EXAMPLE',
              GITHUB_TOKEN: 'gh' + 'p_1234567890abcdefghijklmnopqrstuvwxyz',
              SLACK_BOT_TOKEN: 'xo' + 'xb-123456789012-123456789012-abcdefABCDEF123456',
            },
          },
        },
      })
    );

    const configs = discoverMcpConfigs({ workspaceDir: dir, includeGlobal: false });
    const audit = runStaticMcpAudit({ configs, workspaceDir: dir });
    const r01 = audit.findings.filter((f) => f.ruleId === 'SIP-R01');
    assert.equal(r01.length, 5);
  });
});

test('13. SCREENSHOT-SAFE ZERO-LEAK INVARIANT: planted key sk-p' + 'roj-SUPERSECRET998877665544xyz NEVER appears in terminal, JSON, SARIF, or sip2.lock.json', async () => {
  const PLANTED_SECRET = 'sk-p' + 'roj-SUPERSECRET998877665544xyz';

  await withTempSandbox(async (dir) => {
    fs.writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          leakyServer: {
            command: 'npx',
            args: ['-y', '@vendor/server@1.2.3', `--api-key=${PLANTED_SECRET}`],
            url: `https://mcp.example.com/sse?api_key=${PLANTED_SECRET}`,
            headers: {
              Authorization: `Bearer ${PLANTED_SECRET}`,
            },
            env: {
              OPENAI_API_KEY: PLANTED_SECRET,
            },
          },
        },
      })
    );

    const termRes = await runCli(['audit', '--dir', dir, '--no-global']);
    const jsonRes = await runCli(['audit', '--dir', dir, '--no-global', '--json']);
    const sarifRes = await runCli(['audit', '--dir', dir, '--no-global', '--format', 'sarif']);
    await runCli(['lock', '--dir', dir, '--no-global']);

    const lockRaw = fs.readFileSync(path.join(dir, '.sip', 'sip2.lock.json'), 'utf8');

    assert.equal(
      termRes.stdout.includes(PLANTED_SECRET),
      false,
      'Terminal report must NEVER contain raw secret'
    );
    assert.equal(
      jsonRes.stdout.includes(PLANTED_SECRET),
      false,
      'JSON audit output must NEVER contain raw secret'
    );
    assert.equal(
      sarifRes.stdout.includes(PLANTED_SECRET),
      false,
      'SARIF 2.1.0 output must NEVER contain raw secret'
    );
    assert.equal(
      lockRaw.includes(PLANTED_SECRET),
      false,
      'sip2.lock.json must NEVER contain raw secret'
    );
    assert.equal(
      lockRaw.includes('SUPERSECRET'),
      false,
      'sip2.lock.json must NEVER contain secret body substring'
    );
    assert.ok(termRes.stdout.includes('sk-p****...****yz'));
  });
});

// ============================================================================
// 6. Zero False Positives (0.00% FP) & Grade A+
// ============================================================================

test('14. ZERO FALSE POSITIVES (0.00% FP): RFC 4122 UUIDs, 64-char SHA-256 digests, clean URLs, paths, and ${env:API_KEY} produce 0 alerts and Grade A+ when pinned & sealed', async () => {
  await withTempSandbox(async (dir) => {
    fs.writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          enterpriseClean: {
            command: 'npx',
            args: [
              '-y',
              '@modelcontextprotocol/server-filesystem@0.6.2',
              './workspace-data',
              '550e8400-e29b-41d4-a716-446655440000',
              'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            ],
            env: {
              API_KEY: '${env:API_KEY}',
              SECONDARY_TOKEN: '$CORPORATE_VAULT_TOKEN',
              TENANT_UUID: '550e8400-e29b-41d4-a716-446655440000',
              ARTIFACT_SHA256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
              GIT_COMMIT_SHA1: '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
            },
          },
          remoteClean: {
            type: 'http',
            url: 'https://mcp.atlassian.com/v2/mcp/550e8400-e29b-41d4-a716-446655440000',
            headers: {
              Authorization: '${env:ATLASSIAN_BEARER}',
            },
          },
        },
      })
    );

    const configs = discoverMcpConfigs({ workspaceDir: dir, includeGlobal: false });
    await createOrUpdateSchemaLock({ workspaceDir: dir, configs });

    const audit = runStaticMcpAudit({ configs, workspaceDir: dir });
    const secretAlerts = audit.findings.filter((f) => f.ruleId === 'SIP-R01');
    assert.equal(secretAlerts.length, 0, 'Expected 0.00% false positive secret alerts');
    assert.equal(audit.findings.length, 0, 'Expected zero total findings on pinned & sealed config');
    assert.equal(audit.score, 100);
    assert.equal(audit.grade, 'A+');
  });
});

// ============================================================================
// 7. SIP-R02 Supply-Chain Pinning Checks
// ============================================================================

test('15. SIP-R02 flags unpinned npx / @latest / uvx / docker run:latest and passes exact @1.4.2 pins', async () => {
  await withTempSandbox((dir) => {
    fs.writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          unpinnedNpx: { command: 'npx', args: ['-y', '@vendor/pkg'] },
          latestNpx: { command: 'npx', args: ['-y', '@vendor/pkg@latest'] },
          unpinnedUvx: { command: 'uvx', args: ['mcp-server-git'] },
          unpinnedDocker: { command: 'docker', args: ['run', '-i', '--rm', 'mcp/postgres:latest'] },
          pinnedNpx: { command: 'npx', args: ['-y', '@vendor/pkg@1.4.2'] },
          pinnedUvx: { command: 'uvx', args: ['mcp-server-git==0.6.2'] },
          pinnedDocker: {
            command: 'docker',
            args: [
              'run',
              '-i',
              'mcp/postgres@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            ],
          },
        },
      })
    );

    const configs = discoverMcpConfigs({ workspaceDir: dir, includeGlobal: false });
    const audit = runStaticMcpAudit({ configs, workspaceDir: dir, skipLockCheck: true });
    const r02Servers = audit.findings
      .filter((f) => f.ruleId === 'SIP-R02')
      .map((f) => f.serverName)
      .sort();

    assert.deepEqual(r02Servers, ['latestNpx', 'unpinnedDocker', 'unpinnedNpx', 'unpinnedUvx']);
  });
});

// ============================================================================
// 8. SIP-R03 Unicode Plane-14 Tag Smuggling & Bidi Injection
// ============================================================================

test('16. SIP-R03 detects Plane-14 Unicode tags (U+E0001..U+E007F) hidden in args or descriptions', async () => {
  await withTempSandbox((dir) => {
    const smuggled = 'Safe tool description\u{E0001}\u{E0041}\u{E0042}';
    fs.writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          trojanPlane14: {
            command: 'npx',
            args: ['-y', '@vendor/pkg@1.4.2'],
            description: smuggled,
          },
        },
      })
    );

    const configs = discoverMcpConfigs({ workspaceDir: dir, includeGlobal: false });
    const audit = runStaticMcpAudit({ configs, workspaceDir: dir, skipLockCheck: true });
    const r03 = audit.findings.filter((f) => f.ruleId === 'SIP-R03');
    assert.ok(r03.length >= 1, 'Expected SIP-R03 Plane-14 finding');
    assert.ok(r03.some((f) => f.message.includes('U+E0001')));
  });
});

test('17. SIP-R03 detects Trojan-Source Bidi overrides (U+202E) and zero-width joiners (U+200D)', async () => {
  await withTempSandbox((dir) => {
    fs.writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          bidiServer: {
            command: 'node',
            args: ['server-\u202Etxt.js', '--tag=clean\u200Dhidden'],
          },
        },
      })
    );

    const configs = discoverMcpConfigs({ workspaceDir: dir, includeGlobal: false });
    const audit = runStaticMcpAudit({ configs, workspaceDir: dir, skipLockCheck: true });
    const r03 = audit.findings.filter((f) => f.ruleId === 'SIP-R03');
    assert.ok(r03.length >= 1);
  });
});

// ============================================================================
// 9. SIP-R04 Blast Radius & Plaintext HTTP Transport
// ============================================================================

test('18. SIP-R04 flags root /, ~/.ssh, .env mounts, permission bypass flags, and remote http:// while allowing loopback http://127.0.0.1', async () => {
  await withTempSandbox((dir) => {
    fs.writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          rootFs: {
            command: 'npx',
            args: ['-y', '@modelcontextprotocol/server-filesystem@0.6.2', '/', '~/.ssh', '--dangerously-skip-permissions'],
          },
          remoteHttp: {
            type: 'http',
            url: 'http://mcp.internal.corp:8080/sse',
          },
          localLoopbackHttp: {
            type: 'http',
            url: 'http://127.0.0.1:3001/sse',
          },
        },
      })
    );

    const configs = discoverMcpConfigs({ workspaceDir: dir, includeGlobal: false });
    const audit = runStaticMcpAudit({ configs, workspaceDir: dir, skipLockCheck: true });
    const r04 = audit.findings.filter((f) => f.ruleId === 'SIP-R04');
    assert.equal(r04.filter((f) => f.serverName === 'rootFs').length, 3);
    assert.equal(r04.filter((f) => f.serverName === 'remoteHttp').length, 1);
    assert.equal(r04.filter((f) => f.serverName === 'localLoopbackHttp').length, 0);
  });
});

// ============================================================================
// 10. RFC 8785 + Ed25519 Schema Lock, 1-Byte Rug-Pull & Lock Forgery Detection
// ============================================================================

test('19. createOrUpdateSchemaLock seals workspace and verifySchemaLock passes with Ed25519 verification', async () => {
  await withTempSandbox(async (dir) => {
    fs.writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          git: { command: 'uvx', args: ['mcp-server-git==0.6.2', '--repository', './repo'] },
        },
      })
    );

    const configs = discoverMcpConfigs({ workspaceDir: dir, includeGlobal: false });
    const outcome = await createOrUpdateSchemaLock({ workspaceDir: dir, configs });
    assert.equal(outcome.written, true);
    assert.equal(outcome.lockManifest.signatureB64u.length, 86);

    const check = verifySchemaLock({ workspaceDir: dir, configs });
    assert.equal(check.valid, true);
    assert.equal(check.signatureValid, true);
    assert.equal(check.status, 'VERIFIED');
  });
});

test('20. verifySchemaLock immediately catches a 1-byte Rug-Pull mutation in server args', async () => {
  await withTempSandbox(async (dir) => {
    const mcpPath = path.join(dir, '.mcp.json');
    fs.writeFileSync(
      mcpPath,
      JSON.stringify({
        mcpServers: {
          fsServer: {
            command: 'npx',
            args: ['-y', '@modelcontextprotocol/server-filesystem@0.6.2', './safe-dir'],
          },
        },
      })
    );

    let configs = discoverMcpConfigs({ workspaceDir: dir, includeGlobal: false });
    await createOrUpdateSchemaLock({ workspaceDir: dir, configs });

    // Mutate a single byte in args: '0.6.2' -> '0.6.3'
    fs.writeFileSync(
      mcpPath,
      JSON.stringify({
        mcpServers: {
          fsServer: {
            command: 'npx',
            args: ['-y', '@modelcontextprotocol/server-filesystem@0.6.3', './safe-dir'],
          },
        },
      })
    );

    configs = discoverMcpConfigs({ workspaceDir: dir, includeGlobal: false });
    const check = verifySchemaLock({ workspaceDir: dir, configs });
    assert.equal(check.valid, false);
    assert.equal(check.status, 'DRIFT_DETECTED');
    assert.equal(check.driftDetails[0].reason, 'SERVER_DIGEST_DRIFT');

    const cliVerify = await runCli(['verify-lock', '--dir', dir, '--no-global']);
    assert.equal(cliVerify.exitCode, 2);
  });
});

test('21. verifySchemaLock catches manual forgery/modification inside .sip/sip2.lock.json', async () => {
  await withTempSandbox(async (dir) => {
    fs.writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          fsServer: { command: 'npx', args: ['-y', '@vendor/pkg@1.0.0'] },
        },
      })
    );

    const configs = discoverMcpConfigs({ workspaceDir: dir, includeGlobal: false });
    await createOrUpdateSchemaLock({ workspaceDir: dir, configs });

    const lockPath = path.join(dir, '.sip', 'sip2.lock.json');
    const lockJson = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    // Forge server digest in lockfile without device private key
    lockJson.servers[0].jcsSha256 = 'A'.repeat(43);
    fs.writeFileSync(lockPath, JSON.stringify(lockJson, null, 2));

    const check = verifySchemaLock({ workspaceDir: dir, configs });
    assert.equal(check.valid, false);
    assert.equal(check.status, 'SIGNATURE_FORGERY_DETECTED');
  });
});

test('22. --install-hooks creates .sip-backup, installs pre-tool-guard.mjs, and blocks Plane-14 / lock tampering with exit code 2', async () => {
  await withTempSandbox(async (dir) => {
    fs.mkdirSync(path.join(dir, '.claude'), { recursive: true });
    fs.mkdirSync(path.join(dir, '.git', 'hooks'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, '.claude', 'settings.local.json'),
      JSON.stringify({ permissions: { allow: [] } })
    );
    fs.writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          clean: { command: 'npx', args: ['-y', '@vendor/pkg@1.2.0'] },
        },
      })
    );

    const lockRes = await runCli(['lock', '--dir', dir, '--no-global', '--install-hooks']);
    assert.equal(lockRes.exitCode, 0);

    // Verify backup of .claude/settings.local.json was created
    const claudeFiles = fs.readdirSync(path.join(dir, '.claude'));
    assert.ok(
      claudeFiles.some((f) => f.startsWith('settings.local.json.sip-backup-')),
      'Expected .sip-backup file in .claude/'
    );

    const guardPath = path.join(dir, '.sip', 'hooks', 'pre-tool-guard.mjs');
    assert.equal(fs.existsSync(guardPath), true);
    assert.equal(fs.existsSync(path.join(dir, '.git', 'hooks', 'pre-commit')), true);

    // 1) Clean invocation passes with exit code 0
    const cleanRun = spawnSync(process.execPath, [guardPath], {
      cwd: dir,
      input: JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls -la' } }),
      encoding: 'utf8',
    });
    assert.equal(cleanRun.status, 0);

    // 2) Plane-14 smuggling payload in tool stdin is blocked with exit code 2
    const smuggleRun = spawnSync(process.execPath, [guardPath], {
      cwd: dir,
      input: JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'echo hi\u{E0001}' } }),
      encoding: 'utf8',
    });
    assert.equal(smuggleRun.status, 2);

    // 3) Tampered .mcp.json is blocked with exit code 2
    fs.writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          clean: { command: 'npx', args: ['-y', '@vendor/evil-pkg@9.9.9'] },
        },
      })
    );
    const tamperRun = spawnSync(process.execPath, [guardPath], {
      cwd: dir,
      input: '{}',
      encoding: 'utf8',
    });
    assert.equal(tamperRun.status, 2);
  });
});

// ============================================================================
// 11. Dry-Run, Backups, CI Exit Codes, SARIF 2.1.0 & < 150ms Performance SLA
// ============================================================================

test('23. lock --dry-run writes ZERO files or directories to disk', async () => {
  await withTempSandbox(async (dir) => {
    fs.writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: { s1: { command: 'npx', args: ['-y', '@vendor/pkg@1.0.0'] } },
      })
    );

    const beforeEntries = fs.readdirSync(dir).sort();
    const res = await runCli(['lock', '--dir', dir, '--no-global', '--dry-run']);
    assert.equal(res.exitCode, 0);
    const afterEntries = fs.readdirSync(dir).sort();

    assert.deepEqual(afterEntries, beforeEntries, '--dry-run must not create .sip or any files');
    assert.equal(fs.existsSync(path.join(dir, '.sip')), false);
  });
});

test('24. backupConfigBeforeEdit creates mode 0o600 timestamped .sip-backup copy', async () => {
  await withTempSandbox((dir) => {
    const cfgPath = path.join(dir, 'mcp.json');
    fs.writeFileSync(cfgPath, '{"mcpServers":{}}', 'utf8');
    const bkp = backupConfigBeforeEdit(cfgPath);
    assert.ok(bkp && bkp.includes('.sip-backup-'));
    assert.equal(fs.readFileSync(bkp, 'utf8'), '{"mcpServers":{}}');
    assert.equal(fs.statSync(bkp).mode & 0o777, 0o600);
  });
});

test('25. CLI --ci --fail-on B enforces non-zero exit code on failing grades and 0 on Grade A/A+', async () => {
  await withTempSandbox(async (dir) => {
    // Vulnerable config (unpinned + unsealed => score 65, Grade C)
    fs.writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: { s1: { command: 'npx', args: ['-y', '@vendor/unpinned'] } },
      })
    );

    const failRes = await runCli(['audit', '--dir', dir, '--no-global', '--ci', '--fail-on', 'B']);
    assert.equal(failRes.exitCode, 1);

    // Fix pin -> score 85 (Grade A) -> passes --fail-on B!
    fs.writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: { s1: { command: 'npx', args: ['-y', '@vendor/pinned@2.1.0'] } },
      })
    );
    const passRes = await runCli(['audit', '--dir', dir, '--no-global', '--ci', '--fail-on', 'B']);
    assert.equal(passRes.exitCode, 0);
  });
});

test('26. formatAuditSarif emits valid OASIS SARIF 2.1.0 schema with runs[0].tool.driver and results', async () => {
  await withTempSandbox((dir) => {
    fs.writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          srv: { command: 'npx', args: ['-y', 'unpinned-mcp'] },
        },
      })
    );
    const configs = discoverMcpConfigs({ workspaceDir: dir, includeGlobal: false });
    const audit = runStaticMcpAudit({ configs, workspaceDir: dir });
    const sarif = formatAuditSarif(audit);

    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.$schema, 'https://json.schemastore.org/sarif-2.1.0.json');
    assert.equal(sarif.runs[0].tool.driver.name, '@shuliak-corp/sip1-mcp');
    assert.equal(sarif.runs[0].tool.driver.rules.length, 5);
    assert.ok(sarif.runs[0].results.length >= 1);
    assert.ok(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri);
  });
});

test('27. formatAuditTerminalReport includes Screenshot-Safe header, 1-command fix, and compliance attestation footer', async () => {
  await withTempSandbox((dir) => {
    fs.writeFileSync(
      path.join(dir, '.mcp.json'),
      JSON.stringify({ mcpServers: { s: { command: 'npx', args: ['-y', 'pkg@1.0.0'] } } })
    );
    const configs = discoverMcpConfigs({ workspaceDir: dir, includeGlobal: false });
    const audit = runStaticMcpAudit({ configs, workspaceDir: dir });
    const report = formatAuditTerminalReport(audit);

    assert.ok(report.includes('[SHULIAK SIP v3.0 · ZERO-EGRESS MCP SECURITY AUDIT]'));
    assert.ok(report.includes('[SCREENSHOT-SAFE · ZERO RAW SECRETS DISPLAYED]'));
    assert.ok(report.includes('npx -y @shuliak-corp/sip1-mcp lock'));
    assert.ok(report.includes('https://shuliak.dev/#pricing'));
  });
});

test('28. Full multi-file discovery + 5-class static audit completes well under < 150 ms SLA', async () => {
  await withTempSandbox((dir) => {
    fs.mkdirSync(path.join(dir, '.cursor'), { recursive: true });
    fs.mkdirSync(path.join(dir, '.vscode'), { recursive: true });

    const servers = {};
    for (let i = 0; i < 20; i++) {
      servers[`srv_${i}`] = {
        command: 'npx',
        args: ['-y', `@scope/mcp-tool-${i}@1.2.${i}`, './workspace'],
        env: { API_TOKEN: '${env:SAFE_TOKEN}' },
      };
    }

    fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: servers }));
    fs.writeFileSync(path.join(dir, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: servers }));
    fs.writeFileSync(path.join(dir, '.vscode', 'mcp.json'), JSON.stringify({ servers }));

    const t0 = performance.now();
    const configs = discoverMcpConfigs({ workspaceDir: dir, includeGlobal: false });
    const audit = runStaticMcpAudit({ configs, workspaceDir: dir });
    const elapsedMs = performance.now() - t0;

    assert.equal(audit.totalServers, 60);
    assert.ok(elapsedMs < 150, `Expected scan latency < 150ms, got ${elapsedMs.toFixed(2)}ms`);
  });
});
