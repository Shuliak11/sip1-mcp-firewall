/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 1 Cross-Platform 9-Client MCP Configuration Discovery
 * Supports Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, OpenAI Codex CLI (TOML),
 * Devin Desktop, Cline, and GitHub Copilot CLI / Agent.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseJsoncSafe } from '../core/workspace-io.mjs';

/**
 * Infer MCP client identifier from a file path.
 * @param {string} filePath
 * @returns {string}
 */
function inferClientFromPath(filePath) {
  const norm = filePath.replace(/\\/g, '/').toLowerCase();
  if (norm.includes('claude_desktop_config.json')) return 'claude-desktop';
  if (norm.includes('.codex/') || norm.endsWith('config.toml')) return 'codex';
  if (norm.includes('devin/') || norm.includes('.devin/')) return 'devin';
  if (norm.includes('cline') || norm.includes('saoudrizwan.claude-dev')) return 'cline';
  if (norm.includes('copilot')) return 'copilot';
  if (norm.includes('.vscode/')) return 'vscode';
  if (norm.includes('.cursor/')) return 'cursor';
  if (norm.includes('windsurf/')) return 'windsurf';
  if (norm.includes('.roo/')) return 'roo';
  if (norm.includes('.gemini/')) return 'gemini';
  if (norm.includes('.zed/') ||
      norm.includes('/zed/')) return 'zed';
  if (norm.includes('.claude') || norm.endsWith('/.mcp.json') || norm === '.mcp.json') {
    return 'claude-code';
  }
  return 'mcp-config';
}

/**
 * Zero-dependency state-machine TOML parser tailored for OpenAI Codex CLI `config.toml`
 * (`[mcp_servers.<name>]`, `[mcp_servers.<name>.env]`, `[mcp_servers.<name>.headers]`,
 * `[mcpServers.<name>]`, dotted keys, inline tables `{ K = "V" }`, arrays, `#` comments,
 * basic `"..."` escapes, and `'...'` literal strings).
 *
 * @param {string} rawText
 * @returns {Record<string, any>}
 */
export function parseTomlMcpConfigSafe(rawText) {
  const text = String(rawText ?? '').replace(/^\uFEFF/, '');
  /** @type {Record<string, any>} */
  const root = {};

  /**
   * Create structured syntax error with 1-based line and column.
   * @param {string} msg
   * @param {number} line
   * @param {number} col
   */
  function makeTomlError(msg, line, col) {
    const err = /** @type {Error & { line?: number, column?: number }} */ (new Error(msg));
    err.line = line;
    err.column = col;
    return err;
  }

  /**
   * Strip `#` comment outside single/double quotes on a logical line.
   * @param {string} lineStr
   */
  function stripTomlComment(lineStr) {
    let inBasic = false;
    let inLiteral = false;
    for (let i = 0; i < lineStr.length; i++) {
      const ch = lineStr[i];
      if (inBasic) {
        if (ch === '\\') {
          i++;
          continue;
        }
        if (ch === '"') inBasic = false;
      } else if (inLiteral) {
        if (ch === "'") inLiteral = false;
      } else {
        if (ch === '"') inBasic = true;
        else if (ch === "'") inLiteral = true;
        else if (ch === '#') return lineStr.slice(0, i);
      }
    }
    if (inBasic || inLiteral) {
      return null; // Unterminated string on this single line
    }
    return lineStr;
  }

  /**
   * Split a dotted TOML key path (`mcp_servers."my-db".env` or `env.API_KEY`) into segments.
   * @param {string} rawKeyPath
   * @param {number} lineNo
   * @returns {string[]}
   */
  function parseKeySegments(rawKeyPath, lineNo) {
    const segments = [];
    let i = 0;
    const s = rawKeyPath.trim();
    if (!s) throw makeTomlError('Empty TOML key', lineNo, 1);

    while (i < s.length) {
      while (i < s.length && /\s/.test(s[i])) i++;
      if (i >= s.length) break;

      if (s[i] === '"' || s[i] === "'") {
        const quote = s[i++];
        let seg = '';
        let closed = false;
        while (i < s.length) {
          const ch = s[i++];
          if (quote === '"' && ch === '\\' && i < s.length) {
            const esc = s[i++];
            seg += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
            continue;
          }
          if (ch === quote) {
            closed = true;
            break;
          }
          seg += ch;
        }
        if (!closed) throw makeTomlError('Unterminated quoted TOML key', lineNo, i + 1);
        segments.push(seg);
      } else {
        let seg = '';
        while (i < s.length && /[A-Za-z0-9_-]/.test(s[i])) {
          seg += s[i++];
        }
        if (!seg) {
          throw makeTomlError(`Invalid character "${s[i]}" in TOML key`, lineNo, i + 1);
        }
        segments.push(seg);
      }

      while (i < s.length && /\s/.test(s[i])) i++;
      if (i < s.length) {
        if (s[i] === '.') {
          i++;
          if (i >= s.length) throw makeTomlError('Trailing dot in TOML key', lineNo, i + 1);
        } else {
          throw makeTomlError(`Unexpected token "${s[i]}" in TOML key`, lineNo, i + 1);
        }
      }
    }
    return segments;
  }

  /**
   * Split comma-separated items at depth 0 (outside quotes, `[...]`, and `{...}`).
   * @param {string} inner
   * @param {number} lineNo
   * @returns {string[]}
   */
  function splitTopLevelComma(inner, lineNo) {
    const parts = [];
    let buf = '';
    let inBasic = false;
    let inLiteral = false;
    let bracketDepth = 0;
    let braceDepth = 0;

    for (let i = 0; i < inner.length; i++) {
      const ch = inner[i];
      if (inBasic) {
        buf += ch;
        if (ch === '\\' && i + 1 < inner.length) {
          buf += inner[++i];
          continue;
        }
        if (ch === '"') inBasic = false;
      } else if (inLiteral) {
        buf += ch;
        if (ch === "'") inLiteral = false;
      } else {
        if (ch === '"') {
          inBasic = true;
          buf += ch;
        } else if (ch === "'") {
          inLiteral = true;
          buf += ch;
        } else if (ch === '[') {
          bracketDepth++;
          buf += ch;
        } else if (ch === ']') {
          bracketDepth--;
          buf += ch;
        } else if (ch === '{') {
          braceDepth++;
          buf += ch;
        } else if (ch === '}') {
          braceDepth--;
          buf += ch;
        } else if (ch === ',' && bracketDepth === 0 && braceDepth === 0) {
          if (buf.trim()) parts.push(buf.trim());
          buf = '';
        } else {
          buf += ch;
        }
      }
    }
    if (inBasic || inLiteral || bracketDepth !== 0 || braceDepth !== 0) {
      throw makeTomlError('Unbalanced delimiters in TOML composite value', lineNo, 1);
    }
    if (buf.trim()) parts.push(buf.trim());
    return parts;
  }

  /**
   * Parse a TOML scalar, array, or inline table value.
   * @param {string} rawVal
   * @param {number} lineNo
   * @returns {any}
   */
  function parseTomlValue(rawVal, lineNo) {
    const v = rawVal.trim();
    if (!v) throw makeTomlError('Missing TOML value after "="', lineNo, 1);

    if (v.startsWith('"""') && v.endsWith('"""') && v.length >= 6) {
      return v.slice(3, -3);
    }
    if (v.startsWith("'''") && v.endsWith("'''") && v.length >= 6) {
      return v.slice(3, -3);
    }
    if (v.startsWith('"')) {
      if (!v.endsWith('"') || v.length < 2) {
        throw makeTomlError('Unterminated TOML basic string', lineNo, 1);
      }
      let out = '';
      for (let i = 1; i < v.length - 1; i++) {
        const ch = v[i];
        if (ch === '\\') {
          if (i + 1 >= v.length - 1) {
            throw makeTomlError('Invalid trailing escape in TOML string', lineNo, i + 1);
          }
          const esc = v[++i];
          if (esc === 'n') out += '\n';
          else if (esc === 'r') out += '\r';
          else if (esc === 't') out += '\t';
          else if (esc === '"' || esc === '\\' || esc === '/') out += esc;
          else if (esc === 'u' && /^[0-9A-Fa-f]{4}/.test(v.slice(i + 1, i + 5))) {
            out += String.fromCharCode(parseInt(v.slice(i + 1, i + 5), 16));
            i += 4;
          } else {
            out += esc;
          }
        } else {
          out += ch;
        }
      }
      return out;
    }
    if (v.startsWith("'")) {
      if (!v.endsWith("'") || v.length < 2) {
        throw makeTomlError('Unterminated TOML literal string', lineNo, 1);
      }
      return v.slice(1, -1);
    }
    if (v.startsWith('[')) {
      if (!v.endsWith(']')) throw makeTomlError('Unterminated TOML array', lineNo, 1);
      const inner = v.slice(1, -1).trim();
      if (!inner) return [];
      return splitTopLevelComma(inner, lineNo).map((item) => parseTomlValue(item, lineNo));
    }
    if (v.startsWith('{')) {
      if (!v.endsWith('}')) throw makeTomlError('Unterminated TOML inline table', lineNo, 1);
      const inner = v.slice(1, -1).trim();
      /** @type {Record<string, any>} */
      const tbl = {};
      if (!inner) return tbl;
      for (const entry of splitTopLevelComma(inner, lineNo)) {
        const eqIdx = findTopLevelEquals(entry);
        if (eqIdx <= 0) throw makeTomlError('Invalid entry in TOML inline table', lineNo, 1);
        const kSegs = parseKeySegments(entry.slice(0, eqIdx), lineNo);
        const entryVal = parseTomlValue(entry.slice(eqIdx + 1), lineNo);
        assignNestedPath(tbl, kSegs, entryVal, lineNo);
      }
      return tbl;
    }
    if (v === 'true') return true;
    if (v === 'false') return false;
    if (/^[+-]?\d[\d_]*(?:\.[\d_]+)?$/.test(v)) {
      return Number(v.replace(/_/g, ''));
    }
    throw makeTomlError(`Unsupported or unquoted TOML value "${v}"`, lineNo, 1);
  }

  /**
   * Find first `=` outside quotes.
   * @param {string} str
   */
  function findTopLevelEquals(str) {
    let inBasic = false;
    let inLiteral = false;
    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      if (inBasic) {
        if (ch === '\\') i++;
        else if (ch === '"') inBasic = false;
      } else if (inLiteral) {
        if (ch === "'") inLiteral = false;
      } else {
        if (ch === '"') inBasic = true;
        else if (ch === "'") inLiteral = true;
        else if (ch === '=') return i;
      }
    }
    return -1;
  }

  /**
   * Assign a nested object path safely (preventing prototype pollution).
   * @param {Record<string, any>} base
   * @param {string[]} segments
   * @param {any} val
   * @param {number} lineNo
   */
  function assignNestedPath(base, segments, val, lineNo) {
    let cursor = base;
    for (let i = 0; i < segments.length - 1; i++) {
      const seg = segments[i];
      if (seg === '__proto__' || seg === 'constructor' || seg === 'prototype') {
        throw makeTomlError('Forbidden prototype key in TOML config', lineNo, 1);
      }
      if (cursor[seg] === undefined) {
        cursor[seg] = {};
      } else if (!cursor[seg] || typeof cursor[seg] !== 'object' || Array.isArray(cursor[seg])) {
        throw makeTomlError(`TOML key conflict on "${seg}"`, lineNo, 1);
      }
      cursor = cursor[seg];
    }
    const leaf = segments[segments.length - 1];
    if (leaf === '__proto__' || leaf === 'constructor' || leaf === 'prototype') {
      throw makeTomlError('Forbidden prototype key in TOML config', lineNo, 1);
    }
    cursor[leaf] = val;
  }

  /**
   * Count bracket/brace balance outside quotes to join multi-line arrays/inline tables.
   * @param {string} s
   */
  function delimiterBalance(s) {
    let inBasic = false;
    let inLiteral = false;
    let depth = 0;
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      if (inBasic) {
        if (ch === '\\') i++;
        else if (ch === '"') inBasic = false;
      } else if (inLiteral) {
        if (ch === "'") inLiteral = false;
      } else {
        if (ch === '"') inBasic = true;
        else if (ch === "'") inLiteral = true;
        else if (ch === '[' || ch === '{') depth++;
        else if (ch === ']' || ch === '}') depth--;
      }
    }
    return { inQuote: inBasic || inLiteral, depth };
  }

  const rawLines = text.split(/\r?\n/);
  /** @type {Record<string, any>} */
  let currentTable = root;

  for (let idx = 0; idx < rawLines.length; idx++) {
    const startLineNo = idx + 1;
    const strippedFirst = stripTomlComment(rawLines[idx]);
    if (strippedFirst === null) {
      throw makeTomlError('Unterminated string literal in TOML config', startLineNo, 1);
    }
    let acc = strippedFirst.trim();
    if (!acc) continue;

    // Join multi-line `[...]` or `{...}` RHS expressions
    if (!acc.startsWith('[')) {
      let bal = delimiterBalance(acc);
      while (bal.depth > 0 && idx + 1 < rawLines.length) {
        idx++;
        const nextStripped = stripTomlComment(rawLines[idx]);
        if (nextStripped === null) {
          throw makeTomlError('Unterminated string literal in multi-line TOML value', idx + 1, 1);
        }
        acc += ' ' + nextStripped.trim();
        bal = delimiterBalance(acc);
      }
      if (bal.depth !== 0) {
        throw makeTomlError('Unclosed array or inline table in TOML config', startLineNo, 1);
      }
    }

    // Table header `[section.sub]` or array-of-tables `[[section]]`
    if (acc.startsWith('[[') && acc.endsWith(']]')) {
      const headerSegs = parseKeySegments(acc.slice(2, -2), startLineNo);
      let cursor = root;
      for (let i = 0; i < headerSegs.length - 1; i++) {
        const seg = headerSegs[i];
        if (!cursor[seg] || typeof cursor[seg] !== 'object') cursor[seg] = {};
        cursor = cursor[seg];
      }
      const leaf = headerSegs[headerSegs.length - 1];
      if (!Array.isArray(cursor[leaf])) cursor[leaf] = [];
      const item = {};
      cursor[leaf].push(item);
      currentTable = item;
      continue;
    }

    if (acc.startsWith('[')) {
      if (!acc.endsWith(']')) {
        throw makeTomlError('Unterminated TOML table header', startLineNo, 1);
      }
      const headerSegs = parseKeySegments(acc.slice(1, -1), startLineNo);
      let cursor = root;
      for (const seg of headerSegs) {
        if (seg === '__proto__' || seg === 'constructor' || seg === 'prototype') {
          throw makeTomlError('Forbidden prototype key in TOML header', startLineNo, 1);
        }
        if (cursor[seg] === undefined) {
          cursor[seg] = {};
        } else if (!cursor[seg] || typeof cursor[seg] !== 'object' || Array.isArray(cursor[seg])) {
          throw makeTomlError(`TOML table conflict on "${seg}"`, startLineNo, 1);
        }
        cursor = cursor[seg];
      }
      currentTable = cursor;
      continue;
    }

    const eqIdx = findTopLevelEquals(acc);
    if (eqIdx <= 0) {
      throw makeTomlError(`Expected key = value assignment in TOML config`, startLineNo, 1);
    }
    const keySegs = parseKeySegments(acc.slice(0, eqIdx), startLineNo);
    const parsedVal = parseTomlValue(acc.slice(eqIdx + 1), startLineNo);
    assignNestedPath(currentTable, keySegs, parsedVal, startLineNo);
  }

  // Normalize Codex `mcp_servers` -> `mcpServers` if present so downstream extractors are uniform
  if (root.mcp_servers && typeof root.mcp_servers === 'object' && !Array.isArray(root.mcp_servers)) {
    root.mcpServers = {
      ...(root.mcpServers && typeof root.mcpServers === 'object' ? root.mcpServers : {}),
      ...root.mcp_servers,
    };
  }

  return root;
}

/**
 * Normalize a raw MCP server entry into a canonical Stage 1 inspection structure.
 * Supports stdio (`command`, `args`, `env`) and HTTP/SSE (`url`, `headers`, `type`/`transport`).
 *
 * @param {string} serverName
 * @param {Record<string, any>} rawServer
 * @param {{ client: string, scope: 'workspace' | 'global' | 'explicit', filePath: string, rootKey: 'mcpServers' | 'servers' }} meta
 */
export function normalizeServerDefinition(serverName, rawServer, meta) {
  const obj = rawServer && typeof rawServer === 'object' ? rawServer : {};
  const cmdObj = obj.command && typeof obj.command ===
    'object' ? obj.command : null;
  const command = typeof obj.command === 'string'
    ? obj.command
    : typeof cmdObj?.path === 'string'
      ? cmdObj.path : null;
  const rawArgs = Array.isArray(obj.args)
    ? obj.args
    : Array.isArray(cmdObj?.args) ? cmdObj.args : [];
  const args = rawArgs.map((a) => String(a));
  const url =
    typeof obj.url === 'string'
      ? obj.url
      : typeof obj.serverUrl === 'string'
        ? obj.serverUrl
        : typeof obj.http_url === 'string'
          ? obj.http_url
          : null;

  const rawTransport =
    typeof obj.transport === 'string'
      ? obj.transport
      : typeof obj.type === 'string'
        ? obj.type
        : null;
  const transport = rawTransport || (url ? 'http' : 'stdio');

  /** @type {Record<string, string>} */
  const env = {};
  const envSrc = (obj.env && typeof obj.env === 'object'
    && !Array.isArray(obj.env)) ? obj.env
    : (cmdObj?.env && typeof cmdObj.env === 'object'
      && !Array.isArray(cmdObj.env)) ? cmdObj.env : null;
  if (envSrc) {
    for (const [k, v] of Object.entries(envSrc)) {
      if (v !== undefined && v !== null) {
        env[String(k)] = String(v);
      }
    }
  }

  /** @type {Record<string, string>} */
  const headers = {};
  const rawHeaders =
    obj.headers && typeof obj.headers === 'object' && !Array.isArray(obj.headers)
      ? obj.headers
      : obj.http_headers && typeof obj.http_headers === 'object' && !Array.isArray(obj.http_headers)
        ? obj.http_headers
        : null;
  if (rawHeaders) {
    for (const [k, v] of Object.entries(rawHeaders)) {
      if (v !== undefined && v !== null) {
        headers[String(k)] = String(v);
      }
    }
  }

  const description = typeof obj.description === 'string' ? obj.description : '';

  return {
    serverName: String(serverName),
    client: meta.client,
    scope: meta.scope,
    filePath: meta.filePath,
    rootKey: meta.rootKey,
    command,
    args,
    env,
    headers,
    url,
    transport,
    description,
  };
}

/**
 * Extract normalized servers and Claude/Cursor hook metadata from a parsed JSONC/TOML root value.
 * Normalizes `"mcpServers"`, Codex `"mcp_servers"`, and VS Code `"servers"`.
 *
 * @param {any} parsed
 * @param {{ client: string, scope: 'workspace' | 'global' | 'explicit', filePath: string, workspaceDir?: string }} meta
 */
export function extractServersFromParsedConfig(parsed, meta) {
  const servers = [];
  let hasPreToolUseHook = false;

  if (!parsed || typeof parsed !== 'object' ||
      Array.isArray(parsed)) {
    return { servers, hasPreToolUseHook };
  }

  if (parsed.hooks && typeof parsed.hooks === 'object') {
    const preTool = parsed.hooks.PreToolUse;
    const beforeMcp = parsed.hooks.beforeMCPExecution;
    if (Array.isArray(preTool) && preTool.length > 0) {
      hasPreToolUseHook = true;
    } else if (preTool && typeof preTool === 'object' && Object.keys(preTool).length > 0) {
      hasPreToolUseHook = true;
    } else if (Array.isArray(beforeMcp) && beforeMcp.length > 0) {
      hasPreToolUseHook = true;
    }
  }

  // 1. Standard `"mcpServers"` root object (Claude, Cursor, Windsurf, Cline, Devin, Copilot, Codex)
  const mcpServersObj =
    parsed.mcpServers && typeof parsed.mcpServers === 'object' && !Array.isArray(parsed.mcpServers)
      ? parsed.mcpServers
      : parsed.mcp_servers && typeof parsed.mcp_servers === 'object' && !Array.isArray(parsed.mcp_servers)
        ? parsed.mcp_servers
        : null;

  if (mcpServersObj) {
    for (const [name, srv] of Object.entries(mcpServersObj)) {
      if (srv && typeof srv === 'object' && !Array.isArray(srv)) {
        servers.push(
          normalizeServerDefinition(name, srv, {
            client: meta.client,
            scope: meta.scope,
            filePath: meta.filePath,
            rootKey: 'mcpServers',
          })
        );
      }
    }
  }

  // 2. VS Code / Copilot `"servers"` root object (`.vscode/mcp.json`, `.github/copilot-mcp.json`) or nested `mcp.servers`
  if (parsed.servers && typeof parsed.servers === 'object' && !Array.isArray(parsed.servers)) {
    for (const [name, srv] of Object.entries(parsed.servers)) {
      if (srv && typeof srv === 'object' && !Array.isArray(srv)) {
        servers.push(
          normalizeServerDefinition(name, srv, {
            client: meta.client,
            scope: meta.scope,
            filePath: meta.filePath,
            rootKey: 'servers',
          })
        );
      }
    }
  } else if (
    parsed.mcp &&
    typeof parsed.mcp === 'object' &&
    parsed.mcp.servers &&
    typeof parsed.mcp.servers === 'object' &&
    !Array.isArray(parsed.mcp.servers)
  ) {
    for (const [name, srv] of Object.entries(parsed.mcp.servers)) {
      if (srv && typeof srv === 'object' && !Array.isArray(srv)) {
        servers.push(
          normalizeServerDefinition(name, srv, {
            client: meta.client,
            scope: meta.scope,
            filePath: meta.filePath,
            rootKey: 'servers',
          })
        );
      }
    }
  }

  // 3. Claude Code `~/.claude.json` workspace-scoped `projects[workspaceDir].mcpServers`
  if (
    meta.workspaceDir &&
    parsed.projects &&
    typeof parsed.projects === 'object' &&
    !Array.isArray(parsed.projects)
  ) {
    const wsProject = parsed.projects[meta.workspaceDir];
    if (wsProject && typeof wsProject === 'object' && wsProject.mcpServers) {
      for (const [name, srv] of Object.entries(wsProject.mcpServers)) {
        if (srv && typeof srv === 'object' && !Array.isArray(srv)) {
          servers.push(
            normalizeServerDefinition(name, srv, {
              client: meta.client,
              scope: meta.scope,
              filePath: meta.filePath,
              rootKey: 'mcpServers',
            })
          );
        }
      }
    }
  }

  if (parsed.context_servers &&
      typeof parsed.context_servers === 'object' &&
      !Array.isArray(parsed.context_servers)) {
    for (const [name, srv] of
         Object.entries(parsed.context_servers)) {
      if (srv && typeof srv === 'object' &&
          !Array.isArray(srv)) {
        servers.push(normalizeServerDefinition(
          name, srv, {
            client: meta.client,
            scope: meta.scope,
            filePath: meta.filePath,
            rootKey: 'context_servers',
          }
        ));
      }
    }
  }

  return { servers, hasPreToolUseHook };
}

/**
 * Resolve OS-specific Claude Desktop config path.
 * @param {string} homeDir
 * @param {string} platform
 * @param {Record<string, string | undefined>} env
 * @returns {string}
 */
function resolveClaudeDesktopPath(homeDir, platform, env) {
  if (platform === 'darwin') {
    return path.join(homeDir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
  }
  if (platform === 'win32') {
    const appData = env.APPDATA || path.join(homeDir, 'AppData', 'Roaming');
    return path.join(appData, 'Claude', 'claude_desktop_config.json');
  }
  const xdgConfig = env.XDG_CONFIG_HOME || path.join(homeDir, '.config');
  return path.join(xdgConfig, 'Claude', 'claude_desktop_config.json');
}

/**
 * Resolve OS-specific Cline VS Code globalStorage `cline_mcp_settings.json` path.
 * @param {string} homeDir
 * @param {string} platform
 * @param {Record<string, string | undefined>} env
 * @returns {string}
 */
function resolveClineGlobalPath(homeDir, platform, env) {
  const relSuffix = path.join(
    'Code',
    'User',
    'globalStorage',
    'saoudrizwan.claude-dev',
    'settings',
    'cline_mcp_settings.json'
  );
  if (platform === 'darwin') {
    return path.join(homeDir, 'Library', 'Application Support', relSuffix);
  }
  if (platform === 'win32') {
    const appData = env.APPDATA || path.join(homeDir, 'AppData', 'Roaming');
    return path.join(appData, relSuffix);
  }
  const xdgConfig = env.XDG_CONFIG_HOME || path.join(homeDir, '.config');
  return path.join(xdgConfig, relSuffix);
}

/**
 * Resolve OS-specific Devin Desktop global MCP config paths.
 * @param {string} homeDir
 * @param {string} platform
 * @param {Record<string, string | undefined>} env
 * @returns {string[]}
 */
function resolveDevinGlobalPaths(homeDir, platform, env) {
  const xdgConfig = env.XDG_CONFIG_HOME || path.join(homeDir, '.config');
  const paths = [path.join(xdgConfig, 'devin', 'mcp_config.json')];
  if (platform === 'darwin') {
    paths.push(path.join(homeDir, 'Library', 'Application Support', 'Devin', 'mcp_config.json'));
  } else if (platform === 'win32') {
    const appData = env.APPDATA || path.join(homeDir, 'AppData', 'Roaming');
    paths.push(path.join(appData, 'Devin', 'mcp_config.json'));
  }
  return paths;
}

/**
 * Supported 9-client catalog identifier list.
 */
export const SUPPORTED_MCP_CLIENTS = Object.freeze([
  'claude-desktop',
  'claude-code',
  'cursor',
  'windsurf',
  'vscode',
  'codex',
  'devin',
  'cline',
  'copilot',
]);

/**
 * Discover MCP configuration files across 9 major AI clients (project-level & OS-level).
 * Never throws if directories or files do not exist; records unreadable or malformed JSONC/TOML
 * files cleanly as structured diagnostic entries.
 *
 * @param {{
 *   workspaceDir?: string,
 *   homeDir?: string,
 *   platform?: string,
 *   env?: Record<string, string | undefined>,
 *   includeGlobal?: boolean,
 *   explicitFiles?: string[],
 * }} [options]
 */
export function discoverMcpConfigs(options = {}) {
  const workspaceDir = path.resolve(options.workspaceDir || process.cwd());
  const homeDir = options.homeDir ? path.resolve(options.homeDir) : os.homedir();
  const platform = options.platform || process.platform;
  const env = options.env || process.env;
  const includeGlobal = options.includeGlobal !== false;
  const explicitFiles = Array.isArray(options.explicitFiles) ? options.explicitFiles : [];

  /** @type {Array<{ filePath: string, client: string, scope: 'workspace' | 'global' | 'explicit', isClaudeSettings?: boolean, format?: 'jsonc' | 'toml' }>} */
  const candidates = [
    // Workspace-scoped configs across all 9 clients
    { filePath: path.join(workspaceDir, '.mcp.json'), client: 'claude-code', scope: 'workspace' },
    {
      filePath: path.join(workspaceDir, '.claude', 'settings.json'),
      client: 'claude-code',
      scope: 'workspace',
      isClaudeSettings: true,
    },
    {
      filePath: path.join(workspaceDir, '.claude', 'settings.local.json'),
      client: 'claude-code',
      scope: 'workspace',
      isClaudeSettings: true,
    },
    { filePath: path.join(workspaceDir, '.cursor', 'mcp.json'), client: 'cursor', scope: 'workspace' },
    { filePath: path.join(workspaceDir, '.vscode', 'mcp.json'), client: 'vscode', scope: 'workspace' },
    {
      filePath: path.join(workspaceDir, '.codex', 'config.toml'),
      client: 'codex',
      scope: 'workspace',
      format: 'toml',
    },
    {
      filePath: path.join(workspaceDir, '.devin', 'mcp_config.json'),
      client: 'devin',
      scope: 'workspace',
    },
    {
      filePath: path.join(workspaceDir, '.cline', 'mcp_settings.json'),
      client: 'cline',
      scope: 'workspace',
    },
    {
      filePath: path.join(workspaceDir, 'cline_mcp_settings.json'),
      client: 'cline',
      scope: 'workspace',
    },
    {
      filePath: path.join(workspaceDir, '.github', 'copilot-mcp.json'),
      client: 'copilot',
      scope: 'workspace',
    },
    {
      filePath: path.join(
        workspaceDir, '.roo', 'mcp.json'
      ),
      client: 'roo',
      scope: 'workspace',
    },
    {
      filePath: path.join(
        workspaceDir, '.gemini', 'settings.json'
      ),
      client: 'gemini',
      scope: 'workspace',
    },
    {
      filePath: path.join(
        workspaceDir, '.zed', 'settings.json'
      ),
      client: 'zed',
      scope: 'workspace',
    },
  ];

  if (includeGlobal) {
    const codexHome = env.CODEX_HOME ? path.resolve(env.CODEX_HOME) : path.join(homeDir, '.codex');
    candidates.push(
      {
        filePath: resolveClaudeDesktopPath(homeDir, platform, env),
        client: 'claude-desktop',
        scope: 'global',
      },
      { filePath: path.join(homeDir, '.claude.json'), client: 'claude-code', scope: 'global' },
      { filePath: path.join(homeDir, '.cursor', 'mcp.json'), client: 'cursor', scope: 'global' },
      {
        filePath: path.join(homeDir, '.codeium', 'windsurf', 'mcp_config.json'),
        client: 'windsurf',
        scope: 'global',
      },
      {
        filePath: path.join(codexHome, 'config.toml'),
        client: 'codex',
        scope: 'global',
        format: 'toml',
      },
      ...resolveDevinGlobalPaths(homeDir, platform, env).map((fp) => ({
        filePath: fp,
        client: 'devin',
        scope: /** @type {'global'} */ ('global'),
      })),
      {
        filePath: resolveClineGlobalPath(homeDir, platform, env),
        client: 'cline',
        scope: 'global',
      },
      {
        filePath: path.join(homeDir, '.copilot', 'mcp-config.json'),
        client: 'copilot',
        scope: 'global',
      },
      {
        filePath: path.join(
          homeDir, '.cline', 'data', 'settings',
          'cline_mcp_settings.json'
        ),
        client: 'cline',
        scope: 'global',
      },
      {
        filePath: path.join(
          homeDir, '.gemini', 'settings.json'
        ),
        client: 'gemini',
        scope: 'global',
      },
      {
        filePath: path.join(
          env.XDG_CONFIG_HOME ||
            path.join(homeDir, '.config'),
          'zed', 'settings.json'
        ),
        client: 'zed',
        scope: 'global',
      }
    );
  }

  for (const explicit of explicitFiles) {
    if (typeof explicit === 'string' && explicit.trim()) {
      const resolved = path.isAbsolute(explicit) ? explicit : path.resolve(workspaceDir, explicit);
      candidates.push({
        filePath: resolved,
        client: inferClientFromPath(resolved),
        scope: 'explicit',
        format: resolved.toLowerCase().endsWith('.toml') ? 'toml' : 'jsonc',
        isClaudeSettings:
          resolved.endsWith('settings.json') || resolved.endsWith('settings.local.json'),
      });
    }
  }

  const seenPaths = new Set();
  const discovered = [];

  for (const candidate of candidates) {
    const normalizedPath = path.resolve(candidate.filePath);
    if (seenPaths.has(normalizedPath)) {
      continue;
    }
    seenPaths.add(normalizedPath);

    let stat;
    try {
      stat = fs.statSync(normalizedPath);
    } catch {
      // File or parent directory does not exist -> skip silently
      continue;
    }

    if (!stat.isFile()) {
      continue;
    }

    let rawText = '';
    try {
      rawText = fs.readFileSync(normalizedPath, 'utf8');
    } catch (readErr) {
      const msg = readErr instanceof Error ? readErr.message : String(readErr);
      discovered.push({
        filePath: normalizedPath,
        client: candidate.client,
        scope: candidate.scope,
        isClaudeSettings: Boolean(candidate.isClaudeSettings),
        hasPreToolUseHook: false,
        servers: [],
        parseError: {
          message: `Unreadable MCP config file: ${msg}`,
          line: 1,
          column: 1,
        },
      });
      continue;
    }

    const isToml = candidate.format === 'toml' || normalizedPath.toLowerCase().endsWith('.toml');

    try {
      const parsed = isToml ? parseTomlMcpConfigSafe(rawText) : parseJsoncSafe(rawText);
      const { servers, hasPreToolUseHook } = extractServersFromParsedConfig(parsed, {
        client: candidate.client,
        scope: candidate.scope,
        filePath: normalizedPath,
        workspaceDir,
      });

      const record = {
        filePath: normalizedPath,
        client: candidate.client,
        scope: candidate.scope,
        isClaudeSettings: Boolean(candidate.isClaudeSettings),
        hasPreToolUseHook,
        servers,
        parseError: null,
      };
      // Attach rawText as non-enumerable so Plane-14/Bidi scanner can inspect source comments/keys
      // without ever serializing raw config text into JSON outputs.
      Object.defineProperty(record, '_rawSource', {
        value: rawText,
        enumerable: false,
        writable: false,
      });
      discovered.push(record);
    } catch (parseErr) {
      const e = /** @type {Error & { line?: number, column?: number }} */ (parseErr);
      const record = {
        filePath: normalizedPath,
        client: candidate.client,
        scope: candidate.scope,
        isClaudeSettings: Boolean(candidate.isClaudeSettings),
        hasPreToolUseHook: false,
        servers: [],
        parseError: {
          message: e.message || (isToml ? 'Malformed TOML configuration' : 'Malformed JSONC configuration'),
          line: e.line || 1,
          column: e.column || 1,
        },
      };
      Object.defineProperty(record, '_rawSource', {
        value: rawText,
        enumerable: false,
        writable: false,
      });
      discovered.push(record);
    }
  }

  return discovered;
}
