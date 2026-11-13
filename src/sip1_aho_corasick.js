// MODULE 2: AHO-CORASICK AUTOMATON
"use strict";
class AhoCorasickAutomaton {
  constructor(patterns) {
    this.trie = [{ next: Object.create(null), fail: 0, out: [] }];
    if (Array.isArray(patterns)) {
      for (const p of patterns) this.addPattern(p.prefix || p, p.label || p);
      this.buildFailureLinks();
    }
  }
  addPattern(pat, label) {
    const s = String(pat || "");
    if (!s) return;
    let node = 0;
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      if (this.trie[node].next[ch] === undefined) {
        this.trie[node].next[ch] = this.trie.length;
        this.trie.push({ next: Object.create(null), fail: 0, out: [] });
      }
      node = this.trie[node].next[ch];
    }
    this.trie[node].out.push({ prefix: s, label: label || s });
  }
  buildFailureLinks() {
    const q = [];
    for (const ch of Object.keys(this.trie[0].next)) q.push(this.trie[0].next[ch]);
    while (q.length > 0) {
      const curr = q.shift();
      for (const ch of Object.keys(this.trie[curr].next)) {
        const nxt = this.trie[curr].next[ch];
        q.push(nxt);
        let f = this.trie[curr].fail;
        while (f > 0 && this.trie[f].next[ch] === undefined) f = this.trie[f].fail;
        if (this.trie[f].next[ch] !== undefined) f = this.trie[f].next[ch];
        this.trie[nxt].fail = f;
        if (this.trie[f].out.length > 0) this.trie[nxt].out = this.trie[nxt].out.concat(this.trie[f].out);
      }
    }
  }
  search(text) {
    const hits = [];
    let node = 0;
    const s = String(text || "");
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      while (node > 0 && this.trie[node].next[ch] === undefined) node = this.trie[node].fail;
      if (this.trie[node].next[ch] !== undefined) node = this.trie[node].next[ch];
      for (const item of this.trie[node].out) {
        hits.push({ index: i - item.prefix.length + 1, prefix: item.prefix, label: item.label });
      }
    }
    return hits;
  }
}
const DEFAULT_PREFIXES = [
  { prefix: "AKIA", label: "AWS" }, { prefix: "ASIA", label: "AWS" },
  { prefix: "ghp_", label: "GH" }, { prefix: "gho_", label: "GH" },
  { prefix: "github_pat_", label: "GH" }, { prefix: "xoxb-", label: "SLACK" },
  { prefix: "sk-proj-", label: "OPENAI" }, { prefix: "sk-ant-", label: "CLAUDE" },
  { prefix: "xai-", label: "GROK" }, { prefix: "AIzaSy", label: "GCP" },
  { prefix: "-----BEGIN ", label: "PEM" }, { prefix: "eyJhbGciOi", label: "JWT" }
];
module.exports = { AhoCorasickAutomaton, AhoCorasick: AhoCorasickAutomaton, DEFAULT_PREFIXES };
