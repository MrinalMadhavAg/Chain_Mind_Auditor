import type { PendingTx } from "../types.js";

// Everything in this file treats its input as attacker-controlled. Contract
// source is written by the deployer, and pending transactions are crafted by
// anyone. Nothing here throws on bad input; invalid data becomes null.

// ---------------------------------------------------------------------------
// Shape validation (heuristics path)
// ---------------------------------------------------------------------------

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const HEX_RE = /^0x[0-9a-fA-F]*$/;

// Upper bound on calldata we will scan. Real mainnet txs are capped around
// 128 KB by node policy; anything larger is not worth regex time.
const MAX_INPUT_CHARS = 262_144;

export function isAddress(value: unknown): value is string {
  return typeof value === "string" && ADDRESS_RE.test(value);
}

export function isHex(value: unknown): value is string {
  return typeof value === "string" && HEX_RE.test(value);
}

// Accepts the three encodings a quantity arrives in: bigint (ethers objects),
// hex string (raw JSON-RPC), or a safe integer number (hand-built fixtures).
// Returns null rather than throwing on anything else.
function toBigInt(value: unknown): bigint | null {
  try {
    if (typeof value === "bigint") return value >= 0n ? value : null;
    if (typeof value === "number") return Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : null;
    if (typeof value === "string" && isHex(value) && value.length > 2 && value.length <= 66) return BigInt(value);
  } catch {
    // fall through
  }
  return null;
}

// The object comes from JSON-RPC, so it is typed as unknown and every field
// is checked. Returns null for anything missing identity fields; malformed
// but identifiable txs are kept, since malformation is itself a signal.
export function sanitizeTx(raw: unknown): PendingTx | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;

  if (typeof r.hash !== "string" || !HASH_RE.test(r.hash)) return null;
  if (!isAddress(r.from)) return null;

  let to: string | null = null;
  if (r.to !== null && r.to !== undefined && r.to !== "") {
    if (!isAddress(r.to)) return null;
    to = r.to.toLowerCase();
  }

  // Odd length hex is still accepted: it is exactly what the
  // malformed-calldata rule wants to see. Non-hex is not.
  const rawInput = r.input ?? r.data ?? "0x";
  if (!isHex(rawInput) || rawInput.length > MAX_INPUT_CHARS) return null;

  return {
    hash: r.hash.toLowerCase(),
    from: r.from.toLowerCase(),
    to,
    value: toBigInt(r.value) ?? 0n,
    gasPrice: toBigInt(r.gasPrice) ?? toBigInt(r.maxFeePerGas),
    input: rawInput.toLowerCase(),
  };
}

// ---------------------------------------------------------------------------
// Source cleaning (LLM path)
// ---------------------------------------------------------------------------

// Zero-width characters and bidirectional overrides (the "Trojan Source"
// class) make code render differently from how it compiles, and can hide
// text from a human reviewer while the model still reads it. Other C0
// controls are dropped too; tab, newline and carriage return are kept.
const INVISIBLE_RE = /[​-‏‪-‮⁠-⁤⁦-⁩﻿؜­]/g;
const C0_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

export function stripControlChars(text: string): string {
  return text.replace(INVISIBLE_RE, "").replace(C0_RE, "");
}

// Comments are the densest injection channel and carry no execution
// semantics, so removing them costs the analysis nothing.
// A character scanner rather than a regex, because a regex cannot tell
// "// in a string literal" (e.g. a URL) from a real comment.
export function stripComments(source: string): string {
  let out = "";
  let i = 0;
  const n = source.length;

  while (i < n) {
    const c = source[i];
    const next = source[i + 1];

    if (c === '"' || c === "'") {
      // Copy the string literal verbatim, honoring backslash escapes.
      const quote = c;
      out += c;
      i++;
      while (i < n && source[i] !== quote && source[i] !== "\n") {
        if (source[i] === "\\" && i + 1 < n) {
          out += source[i]! + source[i + 1]!;
          i += 2;
        } else {
          out += source[i];
          i++;
        }
      }
      if (i < n) {
        out += source[i];
        i++;
      }
    } else if (c === "/" && next === "/") {
      while (i < n && source[i] !== "\n") i++;
    } else if (c === "/" && next === "*") {
      i += 2;
      while (i < n && !(source[i] === "*" && source[i + 1] === "/")) i++;
      i += 2;
      // Keep a space so tokens on either side of the comment stay separate.
      out += " ";
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

// Imports tell the model nothing it can verify (the imported file is either
// already in the concatenated source or absent) and cost tokens.
// [^;]* spans newlines, so multi-line import lists are removed whole.
export function stripImports(source: string): string {
  return source.replace(/^\s*import\s[^;]*;/gm, "");
}

// Source must not be able to close the data block early and write text that
// appears to sit outside it. Any variant of the tag (spacing, case) is
// replaced with an inert marker.
export function escapeDelimiters(text: string): string {
  return text.replace(/<\s*\/?\s*contract_source\s*>/gi, "[delimiter removed]");
}

// An explicit marker so the model knows it is looking at a partial contract
// and does not reason as if absent functions do not exist.
export function capLength(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max)}\n\n[TRUNCATED: showing ${max} of ${text.length} characters. Functions below this point were not provided.]`;
}

export const MAX_SOURCE_CHARS = 24_000;

// Order matters: invisible characters go first so they cannot hide a comment
// marker from the scanner, and the delimiter escape and cap run last on the
// final text.
export function sanitizeSource(raw: string, max = MAX_SOURCE_CHARS): string {
  let s = stripControlChars(raw);
  s = stripComments(s);
  s = stripImports(s);
  s = s.replace(/[ \t]+$/gm, "").replace(/\n{3,}/g, "\n\n").trim();
  s = escapeDelimiters(s);
  return capLength(s, max);
}
