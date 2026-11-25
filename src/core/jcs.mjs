/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Strict IETF RFC 8785 JSON Canonicalization Scheme (JCS)
 * Zero external dependencies. Pure ES6/IEEE-754 & UTF-16 code unit ordering.
 */

import { Buffer } from 'node:buffer';

/**
 * Compare two strings strictly by raw UTF-16 code units per RFC 8785 Section 3.2.3.
 * Never uses localeCompare.
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function compareUtf16CodeUnits(a, b) {
  const minLen = a.length < b.length ? a.length : b.length;
  for (let i = 0; i < minLen; i++) {
    const ca = a.charCodeAt(i);
    const cb = b.charCodeAt(i);
    if (ca !== cb) {
      return ca - cb;
    }
  }
  return a.length - b.length;
}

/**
 * Serialize a JS string according to RFC 8785 Section 3.2.2.2.
 * @param {string} str
 * @returns {string}
 */
function serializeJcsString(str) {
  if (typeof str.isWellFormed === 'function' &&
      !str.isWellFormed()) {
    throw new TypeError(
      'RFC 8785 JCS forbids unpaired surrogates'
    );
  }
  let out = '"';
  const len = str.length;
  for (let i = 0; i < len; i++) {
    const code = str.charCodeAt(i);
    if (code === 0x22) {
      out += '\\"';
    } else if (code === 0x5c) {
      out += '\\\\';
    } else if (code === 0x08) {
      out += '\\b';
    } else if (code === 0x09) {
      out += '\\t';
    } else if (code === 0x0a) {
      out += '\\n';
    } else if (code === 0x0c) {
      out += '\\f';
    } else if (code === 0x0d) {
      out += '\\r';
    } else if (code < 0x20) {
      out += '\\u' + code.toString(16).padStart(4, '0');
    } else if (code >= 0xd800 && code <= 0xdbff) {
      // High surrogate: verify valid low surrogate follows
      if (i + 1 < len) {
        const next = str.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          out += str[i] + str[i + 1];
          i++;
          continue;
        }
      }
      throw new TypeError(
        'RFC 8785 JCS forbids unpaired surrogate'
      );
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError(
        'RFC 8785 JCS forbids unpaired surrogate'
      );
    } else {
      out += str[i];
    }
  }
  out += '"';
  return out;
}

/**
 * Internal recursive RFC 8785 serializer.
 * @param {unknown} value
 * @param {WeakSet<object>} seen
 * @returns {string}
 */
function serializeValue(value, seen) {
  if (value === null) {
    return 'null';
  }

  const type = typeof value;

  if (type === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (type === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError(`RFC 8785 JCS forbids non-finite number: ${String(value)}`);
    }
    if (value === 0) {
      // Handles both +0 and -0 -> "0"
      return '0';
    }
    // ES6 Number.prototype.toString(10) matches IEEE-754 / RFC 8785 Section 3.2.2.3
    return String(value);
  }

  if (type === 'string') {
    return serializeJcsString(value);
  }

  if (type === 'bigint') {
    throw new TypeError('RFC 8785 JCS forbids BigInt values');
  }

  if (type === 'undefined' || type === 'function' || type === 'symbol') {
    throw new TypeError(`RFC 8785 JCS cannot serialize root ${type}`);
  }

  if (type === 'object') {
    const obj = /** @type {Record<string, unknown>} */ (value);
    if (seen.has(obj)) {
      throw new TypeError('RFC 8785 JCS cannot serialize circular structure');
    }
    seen.add(obj);

    try {
      if (Array.isArray(obj)) {
        const parts = [];
        for (let i = 0; i < obj.length; i++) {
          const item = obj[i];
          const itemType = typeof item;
          if (item === undefined || itemType === 'function' || itemType === 'symbol') {
            parts.push('null');
          } else {
            parts.push(serializeValue(item, seen));
          }
        }
        return '[' + parts.join(',') + ']';
      }

      const keys = Object.keys(obj).sort(compareUtf16CodeUnits);
      const props = [];
      for (let i = 0; i < keys.length; i++) {
        const k = keys[i];
        const v = obj[k];
        const vType = typeof v;
        if (v === undefined || vType === 'function' || vType === 'symbol') {
          continue;
        }
        props.push(serializeJcsString(k) + ':' + serializeValue(v, seen));
      }
      return '{' + props.join(',') + '}';
    } finally {
      seen.delete(obj);
    }
  }

  throw new TypeError(`Unsupported value type in JCS: ${type}`);
}

/**
 * Canonicalize a JavaScript value into an RFC 8785 JCS string.
 * @param {unknown} value
 * @returns {string}
 */
export function jcsStringify(value) {
  return serializeValue(value, new WeakSet());
}

/**
 * Canonicalize a JavaScript value into an RFC 8785 UTF-8 Buffer.
 * @param {unknown} value
 * @returns {Buffer}
 */
export function jcsCanonicalize(value) {
  return Buffer.from(jcsStringify(value), 'utf8');
}
