import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ibanMod97 } from '../src/stage3/nist-ff1-twins.mjs';
import {
  isValidStrictPan,
  transformStrictPan,
  isValidAbaRouting,
  transformAbaRouting,
  isValidIsoLei,
  transformIsoLei,
  transformSepaIban,
  isValidUsSsn,
  transformUsSsn,
  isValidUsItin,
  transformUsItin,
  isValidUsEin,
  transformUsEin,
  isValidIsin,
  transformIsin,
  isValidEsNif,
  transformEsNif,
  isValidUsNpi,
  transformUsNpi,
  isValidMedicareMbi,
  transformMedicareMbi,
  isValidDeaNumber,
  transformDeaNumber,
  isValidIsoVin,
  transformIsoVin,
  maskHipaaSafeZip,
  shiftIsoDateString,
  pseudonymizeSectorText,
} from '../src/stage4/sector-packs.mjs';
import {
  createBridgeSessionVault,
  readProtectedDocument,
  saveRestoredDocument,
  sanitizeStructuredJson,
} from '../src/stage5/protected-file-bridge.mjs';

const K32 = crypto.createHash('sha256')
  .update('sip1-v310-test-key').digest();
const TWK = Buffer.from('epoch-2026-11-20', 'utf8');

test('V310-01: PAN 13..19, ISO LEI & Date.now', () => {
  for (const p of [
    '4012888888881',
    '3782 822463 10005',
    '4532-0151-1283-0366',
    '4532-0151-1283-0366-914',
  ]) {
    const syn = transformStrictPan(K32, TWK, p, false);
    assert.notEqual(syn, p);
    assert.equal(isValidStrictPan(syn), true);
    assert.notEqual(syn.slice(-4), p.slice(-4));
    assert.equal(transformStrictPan(K32, TWK, syn, true), p);
  }
  assert.equal(isValidStrictPan('1763640123458'), false);

  const lei = '5493006MHB84DD0ZWV18';
  const synLei = transformIsoLei(K32, TWK, lei, false);
  assert.equal(isValidIsoLei(synLei), true);
  assert.equal(transformIsoLei(K32, TWK, synLei, true), lei);
});

test('V310-02: SEPA IBAN FR/ES/IT/BE/NO roundtrips', () => {
  for (const ib of [
    'FR76 3000 6000 0112 3456 7890 189',
    'ES91 2100 0418 4502 0005 1332',
    'IT60 X054 2811 1010 0000 0123 456',
    'BE68 5390 0754 7034',
    'NO93 8601 1117 947',
  ]) {
    const syn = transformSepaIban(K32, TWK, ib, false);
    assert.notEqual(syn, ib);
    assert.equal(ibanMod97(syn.replace(/\s+/g, '')), 1);
    assert.equal(transformSepaIban(K32, TWK, syn, true), ib);
  }
});

test('V310-03: ABA, SSN, ITIN, EIN, ISIN, ES NIF', () => {
  const aba = '021000021';
  const sA = transformAbaRouting(K32, TWK, aba, false);
  assert.equal(isValidAbaRouting(sA), true);
  assert.equal(transformAbaRouting(K32, TWK, sA, true), aba);

  const ssn = '123-45-6789';
  const sS = transformUsSsn(K32, TWK, ssn, false);
  assert.equal(isValidUsSsn(sS), true);
  assert.equal(transformUsSsn(K32, TWK, sS, true), ssn);

  const itin = '912-70-1234';
  const sI = transformUsItin(K32, TWK, itin, false);
  assert.equal(isValidUsItin(sI), true);
  assert.equal(transformUsItin(K32, TWK, sI, true), itin);

  const ein = '12-3456789';
  const sE = transformUsEin(K32, TWK, ein, false);
  assert.equal(isValidUsEin(sE), true);
  assert.equal(transformUsEin(K32, TWK, sE, true), ein);

  const isin = 'US0378331005';
  const sN = transformIsin(K32, TWK, isin, false);
  assert.equal(isValidIsin(sN), true);
  assert.equal(transformIsin(K32, TWK, sN, true), isin);

  const nif = 'X1234567L';
  const sF = transformEsNif(K32, TWK, nif, false);
  assert.equal(isValidEsNif(sF), true);
  assert.equal(transformEsNif(K32, TWK, sF, true), nif);
});

test('V310-04: HIPAA NPI, MBI, DEA, VIN, ZIP', () => {
  const npi = '1234567893';
  const sP = transformUsNpi(K32, TWK, npi, false);
  assert.equal(isValidUsNpi(sP), true);
  assert.equal(transformUsNpi(K32, TWK, sP, true), npi);

  const mbi = '1EG4-TE5-MK72';
  const sM = transformMedicareMbi(K32, TWK, mbi, false);
  assert.equal(isValidMedicareMbi(sM), true);
  assert.equal(transformMedicareMbi(K32, TWK, sM, true), mbi);

  const dea = 'AB1234563';
  const sD = transformDeaNumber(K32, TWK, dea, false);
  assert.equal(isValidDeaNumber(sD), true);
  assert.equal(transformDeaNumber(K32, TWK, sD, true), dea);

  const vin = '1HGCM82633A004352';
  const sV = transformIsoVin(K32, TWK, vin, false);
  assert.equal(isValidIsoVin(sV), true);
  assert.equal(transformIsoVin(K32, TWK, sV, true), vin);

  assert.equal(maskHipaaSafeZip('94107-1234'), '94100-0000');
  assert.equal(maskHipaaSafeZip('82190'), '00000');

  const hRes = pseudonymizeSectorText(
    'Patient Age: 94, ZIP: 82190, Project Chimera',
    K32, TWK, ['hipaa_clinical'],
    { watchlist: ['Project Chimera'] }
  );
  assert.equal(hRes.text.includes('94'), false);
  assert.equal(hRes.text.includes('82190'), false);
  assert.equal(hRes.text.includes('Chimera'), false);
});

test('V310-05: Bridge symlink, BOM, CSV & KV', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 's310-'));
  try {
    const dotDir = path.join(tmp, '.ssh');
    fs.mkdirSync(dotDir);
    const secKey = path.join(dotDir, 'id_rsa');
    fs.writeFileSync(secKey, 'SECRET');
    const sym = path.join(tmp, 'innocent.txt');
    fs.symlinkSync(secKey, sym);

    const vault = createBridgeSessionVault('2026-11-20');
    assert.throws(
      () => readProtectedDocument({
        filePath: sym, key32: K32, sessionVault: vault,
      }),
      /ERR_BLOCKED_SENSITIVE_DOTPATH/
    );

    const rawJson = JSON.parse(
      '{"patient_name":"Jane Roe","mrn":"MRN-9981",' +
      '"__proto__":{"polluted":true}}'
    );
    const cleanObj = sanitizeStructuredJson(
      rawJson, K32, vault
    );
    assert.notEqual(cleanObj.patient_name, 'Jane Roe');
    assert.equal(({}).polluted, undefined);

    const csvIn = path.join(tmp, 'ledger.csv');
    const body = 'ssn,iban,email,amount,memo\n' +
      '123-45-6789,FR7630006000011234567890189,' +
      'cfo@acme.com,-1450.25,' +
      '"=HYPERLINK(""http://evil"",A1)"\n';
    const utf16 = Buffer.concat([
      Buffer.from([0xff, 0xfe]),
      Buffer.from(body, 'utf16le'),
    ]);
    fs.writeFileSync(csvIn, utf16);

    const rd = readProtectedDocument({
      filePath: csvIn, key32: K32, sessionVault: vault,
    });
    assert.equal(rd.safeText.includes('123-45-6789'), false);
    const sv = saveRestoredDocument({
      aiDraftText: rd.safeText,
      sessionVault: vault,
      sourcePath: csvIn,
    });
    assert.equal(sv.neutralizedCsvFormulas, 1);
    const finalTxt = fs.readFileSync(sv.savedPath, 'utf8');
    assert.equal(finalTxt.includes('123-45-6789'), true);
    assert.equal(finalTxt.includes('-1450.25'), true);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
