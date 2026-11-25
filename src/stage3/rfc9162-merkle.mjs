/**
 * @license Apache-2.0
 * SHULIAK SIP v3.1 - RFC 9162 Section 2.1 Merkle Tree
 * Implements 0x00 leaf, 0x01 node, MTH, PATH(m, D_n),
 * PROOF(m, D_n), and Ed25519-signed ledger proofs.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import { Buffer } from 'node:buffer';
import { jcsCanonicalize } from '../core/jcs.mjs';
import {
  b64u,
  domainSha256,
  ensureDeviceEd25519Keypair,
  signDomainPayload,
  verifyDomainPayload,
} from '../core/crypto-primitives.mjs';
import { resolveIsepPaths } from './isep-engine.mjs';

export const DOMAIN_PREFIX_MERKLE_PROOF = 0x0b;
export const MERKLE_PROOF_SIGN_LABEL =
  'SIP-v3-MERKLE-PROOF\0';

function toBuf(x) {
  if (Buffer.isBuffer(x)) return x;
  if (x instanceof Uint8Array) return Buffer.from(x);
  return Buffer.from(String(x), 'utf8');
}

export function hashMerkleLeaf(leafBytes) {
  return crypto.createHash('sha256')
    .update(Buffer.from([0x00]))
    .update(toBuf(leafBytes))
    .digest();
}

export function hashMerkleNode(left32, right32) {
  return crypto.createHash('sha256')
    .update(Buffer.from([0x01]))
    .update(toBuf(left32))
    .update(toBuf(right32))
    .digest();
}

export function largestPow2LessThan(n) {
  if (!Number.isInteger(n) || n <= 1) return 0;
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function isPowerOfTwo(n) {
  return Number.isInteger(n) && n > 0 && (n & (n - 1)) === 0;
}

export function computeMerkleTreeHead(leaves) {
  const n = leaves.length;
  if (n === 0) {
    return crypto.createHash('sha256').digest();
  }
  if (n === 1) {
    return hashMerkleLeaf(leaves[0]);
  }
  const k = largestPow2LessThan(n);
  const left = computeMerkleTreeHead(leaves.slice(0, k));
  const right = computeMerkleTreeHead(leaves.slice(k));
  return hashMerkleNode(left, right);
}

export function generateInclusionPath(leafIndex, leaves) {
  const n = leaves.length;
  if (!Number.isInteger(leafIndex) ||
      leafIndex < 0 || leafIndex >= n) {
    throw new RangeError(
      `Invalid leaf index ${leafIndex} for size ${n}`
    );
  }
  if (n === 1) return [];
  const k = largestPow2LessThan(n);
  if (leafIndex < k) {
    return [
      ...generateInclusionPath(
        leafIndex, leaves.slice(0, k)
      ),
      computeMerkleTreeHead(leaves.slice(k)),
    ];
  }
  return [
    ...generateInclusionPath(
      leafIndex - k, leaves.slice(k)
    ),
    computeMerkleTreeHead(leaves.slice(0, k)),
  ];
}

export function verifyInclusionProof({
  leafBytes,
  leafIndex,
  treeSize,
  auditPath,
  expectedRoot,
}) {
  if (!Number.isInteger(treeSize) || treeSize <= 0) {
    return false;
  }
  if (!Number.isInteger(leafIndex) ||
      leafIndex < 0 || leafIndex >= treeSize) {
    return false;
  }
  if (!Array.isArray(auditPath)) return false;

  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = hashMerkleLeaf(leafBytes);
  const expBuf = typeof expectedRoot === 'string'
    ? Buffer.from(expectedRoot, 'hex')
    : toBuf(expectedRoot);

  for (const node of auditPath) {
    if (sn === 0) return false;
    const p = typeof node === 'string'
      ? Buffer.from(node, 'hex') : toBuf(node);
    if ((fn & 1) === 1 || fn === sn) {
      r = hashMerkleNode(p, r);
      while ((fn & 1) === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      r = hashMerkleNode(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && r.length === expBuf.length &&
    crypto.timingSafeEqual(r, expBuf);
}

function subproof(m, leaves, isCompleteSubtree) {
  const n = leaves.length;
  if (m === n) {
    return isCompleteSubtree
      ? [] : [computeMerkleTreeHead(leaves)];
  }
  const k = largestPow2LessThan(n);
  if (m <= k) {
    return [
      ...subproof(m, leaves.slice(0, k), isCompleteSubtree),
      computeMerkleTreeHead(leaves.slice(k)),
    ];
  }
  return [
    ...subproof(m - k, leaves.slice(k), false),
    computeMerkleTreeHead(leaves.slice(0, k)),
  ];
}

export function generateConsistencyProof(firstSize, leaves) {
  const n = leaves.length;
  if (!Number.isInteger(firstSize) ||
      firstSize <= 0 || firstSize > n) {
    throw new RangeError(
      `Invalid consistency sizes (${firstSize}, ${n})`
    );
  }
  if (firstSize === n) return [];
  return subproof(firstSize, leaves, true);
}

export function verifyConsistencyProof({
  firstSize,
  secondSize,
  firstRoot,
  secondRoot,
  proof,
}) {
  if (!Number.isInteger(firstSize) ||
      !Number.isInteger(secondSize) ||
      firstSize <= 0 || firstSize > secondSize) {
    return false;
  }
  const fBuf = typeof firstRoot === 'string'
    ? Buffer.from(firstRoot, 'hex') : toBuf(firstRoot);
  const sBuf = typeof secondRoot === 'string'
    ? Buffer.from(secondRoot, 'hex') : toBuf(secondRoot);
  if (!Array.isArray(proof)) return false;

  if (firstSize === secondSize) {
    return proof.length === 0 &&
      fBuf.length === sBuf.length &&
      crypto.timingSafeEqual(fBuf, sBuf);
  }

  const nodes = proof.map((x) =>
    typeof x === 'string' ? Buffer.from(x, 'hex') : toBuf(x)
  );
  const path = isPowerOfTwo(firstSize)
    ? [fBuf, ...nodes] : nodes;
  if (path.length === 0) return false;

  let fn = firstSize - 1;
  let sn = secondSize - 1;
  while ((fn & 1) === 1) {
    fn >>= 1;
    sn >>= 1;
  }

  let fr = path[0];
  let sr = path[0];
  for (let i = 1; i < path.length; i++) {
    if (sn === 0) return false;
    const c = path[i];
    if ((fn & 1) === 1 || fn === sn) {
      fr = hashMerkleNode(c, fr);
      sr = hashMerkleNode(c, sr);
      while ((fn & 1) === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      sr = hashMerkleNode(sr, c);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 &&
    fr.length === fBuf.length &&
    sr.length === sBuf.length &&
    crypto.timingSafeEqual(fr, fBuf) &&
    crypto.timingSafeEqual(sr, sBuf);
}

export function generateSignedIsepMerkleProof({
  workspaceDir = process.cwd(),
  seq,
  compareSize = null,
}) {
  const targetSeq = Number(seq);
  if (!Number.isInteger(targetSeq) || targetSeq < 1) {
    throw new Error('Valid positive --seq <N> is required');
  }
  const paths = resolveIsepPaths({ workspaceDir });
  if (!fs.existsSync(paths.logPath)) {
    throw new Error(
      `ISEP ledger not found at ${paths.logPath}`
    );
  }
  const lines = fs.readFileSync(paths.logPath, 'utf8')
    .split('\n').map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) {
    throw new Error('ISEP ledger has zero records');
  }

  const leaves = lines.map((l) => Buffer.from(l, 'utf8'));
  let leafIndex = -1;
  let matchedRec = null;
  for (let i = 0; i < lines.length; i++) {
    const rec = JSON.parse(lines[i]);
    if (rec.record_type === 'AGENT_EVENT' &&
        rec.seq === targetSeq) {
      leafIndex = i;
      matchedRec = rec;
      break;
    }
  }
  if (leafIndex < 0) {
    throw new Error(`AGENT_EVENT seq=${targetSeq} not found`);
  }

  const rootHex = computeMerkleTreeHead(leaves)
    .toString('hex');
  const inclusionPathHex = generateInclusionPath(
    leafIndex, leaves
  ).map((b) => b.toString('hex'));
  const leafHashHex = hashMerkleLeaf(leaves[leafIndex])
    .toString('hex');

  let consistency = null;
  if (Number.isInteger(compareSize) &&
      compareSize > 0 && compareSize <= leaves.length) {
    const prevRootHex = computeMerkleTreeHead(
      leaves.slice(0, compareSize)
    ).toString('hex');
    const proofHex = generateConsistencyProof(
      compareSize, leaves
    ).map((b) => b.toString('hex'));
    consistency = {
      first_size: compareSize,
      first_root_hex: prevRootHex,
      second_size: leaves.length,
      second_root_hex: rootHex,
      proof_hex: proofHex,
    };
  }

  const kp = ensureDeviceEd25519Keypair(paths.sipDir, {
    ephemeralOnly: false,
  });
  const unsignedProof = {
    chain_hash: matchedRec.chain_hash,
    consistency,
    custodian_key_id: kp.keyId,
    custodian_pub_b64u: kp.publicKeyB64u,
    generated_at: new Date().toISOString(),
    inclusion_path_hex: inclusionPathHex,
    leaf_hash_hex: leafHashHex,
    leaf_index: leafIndex,
    leaf_record_raw: lines[leafIndex],
    merkle_root_hex: rootHex,
    seq: targetSeq,
    spec: 'RFC-9162-Section-2.1',
    tree_size: leaves.length,
    v: 'sip-merkle-proof/3.1',
  };
  const digestBuf = domainSha256(
    DOMAIN_PREFIX_MERKLE_PROOF,
    jcsCanonicalize(unsignedProof)
  );
  const sigB64u = signDomainPayload(
    MERKLE_PROOF_SIGN_LABEL, digestBuf, kp.privateKey
  );
  return {
    ...unsignedProof,
    proof_digest_0x0b: b64u(digestBuf),
    signature_b64u: sigB64u,
  };
}

export function verifySignedIsepMerkleProof(proofObj) {
  if (!proofObj || typeof proofObj !== 'object' ||
      proofObj.v !== 'sip-merkle-proof/3.1') {
    return { valid: false, reason: 'Invalid proof schema' };
  }
  const {
    proof_digest_0x0b: dig,
    signature_b64u: sig,
    ...unsigned
  } = proofObj;
  const expectedDig = domainSha256(
    DOMAIN_PREFIX_MERKLE_PROOF,
    jcsCanonicalize(unsigned)
  );
  if (b64u(expectedDig) !== dig) {
    return { valid: false, reason: '0x0B digest mismatch' };
  }
  const sigOk = verifyDomainPayload(
    MERKLE_PROOF_SIGN_LABEL,
    expectedDig, sig, unsigned.custodian_pub_b64u
  );
  if (!sigOk) {
    return { valid: false, reason: 'Invalid Ed25519 sig' };
  }
  const incOk = verifyInclusionProof({
    leafBytes: Buffer.from(unsigned.leaf_record_raw, 'utf8'),
    leafIndex: unsigned.leaf_index,
    treeSize: unsigned.tree_size,
    auditPath: unsigned.inclusion_path_hex,
    expectedRoot: unsigned.merkle_root_hex,
  });
  if (!incOk) {
    return { valid: false, reason: 'RFC 9162 PATH invalid' };
  }
  if (unsigned.consistency) {
    const c = unsigned.consistency;
    const cOk = verifyConsistencyProof({
      firstSize: c.first_size,
      secondSize: c.second_size,
      firstRoot: c.first_root_hex,
      secondRoot: c.second_root_hex,
      proof: c.proof_hex,
    });
    if (!cOk) {
      return {
        valid: false,
        reason: 'RFC 9162 PROOF consistency invalid',
      };
    }
  }
  return {
    valid: true,
    seq: unsigned.seq,
    treeSize: unsigned.tree_size,
    merkleRootHex: unsigned.merkle_root_hex,
  };
}
