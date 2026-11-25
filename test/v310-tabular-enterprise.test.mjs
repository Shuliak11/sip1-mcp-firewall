import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const fb = await import(
  '../src/stage5/protected-file-bridge.mjs'
);

test('TAB-01: CSV client_name + negative balance + DDE', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tb01-'));
  try {
    const f = path.join(tmp, 'ledger.csv');
    fs.writeFileSync(
      f,
      'client_name,ssn,balance,formula\n' +
      'Alice Smith,123-45-6789,-14500.50,=cmd|\'/C calc\'!A0\n'
    );
    const k = crypto.randomBytes(32);
    const v = fb.createBridgeSessionVault('2026-11-20');
    const r = fb.readProtectedDocument({
      filePath: f, key32: k, sessionVault: v,
    });
    assert.equal(r.safeText.includes('Alice Smith'), false);
    assert.equal(r.safeText.includes('123-45-6789'), false);
    assert.equal(r.safeText.includes('-14500.50'), true);

    const s = fb.saveRestoredDocument({
      aiDraftText: r.safeText, sessionVault: v, sourcePath: f,
    });
    const out = fs.readFileSync(s.savedPath, 'utf8');
    assert.equal(out.includes('Alice Smith'), true);
    assert.equal(out.includes('123-45-6789'), true);
    assert.equal(out.includes("'=cmd|"), true);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('TAB-02: RFC 4180 comma-in-name zero column shift', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tb02-'));
  try {
    const f = path.join(tmp, 'partners.csv');
    const row = '"Doe, Jr., John","Acme ""HQ"", LLC",500.00\n';
    fs.writeFileSync(f, 'full_name,vendor,amount\n' + row);
    const k = crypto.randomBytes(32);
    const v = fb.createBridgeSessionVault('2026-11-20');
    const r = fb.readProtectedDocument({
      filePath: f, key32: k, sessionVault: v,
    });
    assert.equal(r.safeText.includes('Doe, Jr.'), false);
    assert.equal(r.safeText.includes('Acme'), false);
    const colsSafe = r.safeText.trim().split('\n')[1].split(',');
    assert.equal(colsSafe.length, 3);

    const s = fb.saveRestoredDocument({
      aiDraftText: r.safeText, sessionVault: v, sourcePath: f,
    });
    const out = fs.readFileSync(s.savedPath, 'utf8');
    assert.equal(out.includes('"Doe, Jr., John"'), true);
    assert.equal(out.includes('"Acme ""HQ"", LLC"'), true);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('TAB-03: European semicolon CSV & Cyrillic headers', () => {
  const k = crypto.randomBytes(32);
  const v = fb.createBridgeSessionVault('2026-11-20');
  const semi =
    '\u0424\u0418\u041e;\u0413\u043e\u0440\u043e\u0434;' +
    'amount\nIvan Petrov;Batumi;1250.00\n';
  const r = fb.sanitizeTabularDocument(semi, k, v, '.csv');
  assert.equal(r.text.includes('Ivan Petrov'), false);
  assert.equal(r.text.includes('Batumi'), false);
  assert.equal(r.text.includes('1250.00'), true);
});

test('TAB-04: Markdown pipe table clinical MRN & Name', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tb04-'));
  try {
    const f = path.join(tmp, 'intake.md');
    const md =
      '# Clinical Chart\n\n' +
      '| Patient Name | MRN | Copay |\n' +
      '| --- | --- | --- |\n' +
      '| Sarah Connor | MRN-99481 | 45.00 |\n';
    fs.writeFileSync(f, md);
    const k = crypto.randomBytes(32);
    const v = fb.createBridgeSessionVault('2026-11-20');
    const r = fb.readProtectedDocument({
      filePath: f, key32: k, sessionVault: v,
    });
    assert.equal(r.safeText.includes('Sarah Connor'), false);
    assert.equal(r.safeText.includes('MRN-99481'), false);
    assert.equal(r.safeText.includes('45.00'), true);

    const s = fb.saveRestoredDocument({
      aiDraftText: r.safeText, sessionVault: v, sourcePath: f,
    });
    const out = fs.readFileSync(s.savedPath, 'utf8');
    assert.equal(out.includes('Sarah Connor'), true);
    assert.equal(out.includes('MRN-99481'), true);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('TAB-05: Streaming .jsonl audit log PII protection', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tb05-'));
  try {
    const f = path.join(tmp, 'events.jsonl');
    fs.writeFileSync(
      f,
      '{"ev":"signup","client_name":"Bob Lee","amt":99}\n' +
      '{"ev":"ok","server_name":"prod-eu-1","amt":10}\n'
    );
    const k = crypto.randomBytes(32);
    const v = fb.createBridgeSessionVault('2026-11-20');
    const r = fb.readProtectedDocument({
      filePath: f, key32: k, sessionVault: v,
    });
    assert.equal(r.safeText.includes('Bob Lee'), false);
    assert.equal(r.safeText.includes('prod-eu-1'), true);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('TAB-06: Safe technical columns 0% false positives', () => {
  const k = crypto.randomBytes(32);
  const v = fb.createBridgeSessionVault('2026-11-20');
  const techCsv =
    'file_name,server_name,table_name,product_name,status\n' +
    'invoice.pdf,db-primary,users_v2,SIP-Enterprise,ACTIVE\n';
  const r = fb.sanitizeTabularDocument(techCsv, k, v, '.csv');
  assert.equal(r.count, 0);
  assert.equal(r.text, techCsv);
});
