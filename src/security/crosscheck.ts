import { FILE_HEADER_RE, isLibraryPath } from "../ingest/etherscan.js";
import type { ContractAnalysis, CrossCheckResult, RiskLevel } from "../types.js";
import { stripComments, stripControlChars } from "./sanitize.js";

// The deterministic engine checks the probabilistic one. A regex cannot be
// talked out of seeing `selfdestruct(`. If the model fails to report a hard
// signal the regex found, either it missed it or something in the source
// persuaded it not to, and both cases deserve a loud warning.

interface HardSignal {
  id: string;
  label: string;
  // What must appear in the code.
  code: RegExp;
  // How the LLM would plausibly phrase it in red_flags. Loose on purpose:
  // the question is "did it mention this at all", not exact wording.
  llm: RegExp;
}

const HARD_SIGNALS: HardSignal[] = [
  {
    id: "selfdestruct",
    label: "selfdestruct",
    code: /\b(selfdestruct|suicide)\s*\(/,
    llm: /self.?destruct|suicide/i,
  },
  {
    id: "delegatecall",
    label: "delegatecall",
    code: /\bdelegatecall\s*\(/,
    llm: /delegate.?call/i,
  },
  {
    id: "owner-mint",
    label: "owner-only mint (onlyOwner + _mint)",
    // A function carrying onlyOwner whose body calls _mint. [^}]* stops at the
    // first closing brace, which is enough for the typical short mint body.
    code: /function\s+\w+\s*\([^)]*\)[^{;]*\bonlyOwner\b[^{;]*\{[^}]*\b_mint\s*\(/,
    llm: /mint/i,
  },
  {
    id: "blacklist",
    label: "blacklist",
    code: /black.?list|block.?list/i,
    llm: /black.?list|block.?list|deny.?list/i,
  },
  {
    id: "pause",
    label: "pause",
    code: /\bfunction\s+(pause|_pause)\s*\(|\bwhenNotPaused\b/,
    llm: /paus/i,
  },
];

// Phrases that only make sense as instructions to a model. Matched against
// the raw source, comments included, since that is where payloads live.
const INJECTION_MARKERS: { label: string; re: RegExp }[] = [
  { label: "ignore previous instructions", re: /ignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|prompts?|rules|context)/i },
  { label: "disregard previous", re: /disregard\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)/i },
  { label: "role reassignment (you are now)", re: /you\s+are\s+now\b/i },
  { label: "fake system turn (system:)", re: /(^|[\s/*#])system\s*:/im },
  { label: "new instructions", re: /new\s+instructions\s*:/i },
  { label: "verdict dictation", re: /(report|mark|classify|rate)\s+(this|the)\s+(contract\s+)?as\s+(safe|low[\s-]risk|secure|audited)/i },
  { label: "prompt delimiter in source", re: /<\s*\/?\s*contract_source\s*>/i },
  { label: "chat template token", re: /<\|im_start\|>|<\|im_end\|>|\[\/?INST\]/i },
];

// Library files are skipped for hard signals: vendored OpenZeppelin code
// contains delegatecall (Address.sol) and pause (Pausable.sol) whether or
// not the contract actually uses them, which would make every contract
// "disagree". Only multi-file sources carry file headers to split on.
function projectCode(raw: string): string {
  const parts = raw.split(FILE_HEADER_RE);
  // split with a capture group yields [preamble, path1, body1, path2, body2, ...]
  if (parts.length === 1) return raw;
  let out = parts[0] ?? "";
  for (let i = 1; i + 1 < parts.length; i += 2) {
    if (!isLibraryPath(parts[i]!)) out += `\n${parts[i + 1]}`;
  }
  return out;
}

function snippet(text: string, index: number, matchLen: number): string {
  const start = Math.max(0, index - 30);
  const end = Math.min(text.length, index + matchLen + 30);
  return text.slice(start, end).replace(/\s+/g, " ").trim();
}

// rawSource: the full source before sanitization. Hard signals are scanned
// on the full length with comments removed, so a comment that merely
// mentions "selfdestruct" does not count, but code past the LLM's length cap
// still does. sanitized: what the LLM actually saw, used to say whether a
// missed signal was even visible to it.
export function crossCheck(rawSource: string, sanitized: string, analysis: ContractAnalysis | null): CrossCheckResult {
  const visible = stripControlChars(rawSource);
  const code = stripComments(projectCode(visible));

  const regexSignals: string[] = [];
  const disagreements: string[] = [];

  for (const sig of HARD_SIGNALS) {
    if (!sig.code.test(code)) continue;
    regexSignals.push(sig.label);
    if (!analysis) continue;
    const reported = analysis.red_flags.some((f) => sig.llm.test(f));
    if (reported) continue;
    const seen = sig.code.test(sanitized);
    disagreements.push(
      seen
        ? `Regex found ${sig.label} in the source the LLM was given, but the LLM did not report it.`
        : `Regex found ${sig.label} in a part of the source cut by the length cap, so the LLM never saw it.`,
    );
  }

  const injectionMarkers: string[] = [];
  for (const m of INJECTION_MARKERS) {
    const hit = m.re.exec(visible);
    if (hit) injectionMarkers.push(`${m.label}: "${snippet(visible, hit.index, hit[0].length)}"`);
  }

  // Escalate on either: a missed hard signal means the summary cannot be
  // trusted, and a contract that tries to steer its auditor is hostile
  // regardless of what else it does.
  // Without an LLM verdict the tool cannot vouch for the contract, so the
  // floor is medium, and any hard signal alone makes it high.
  const base: RiskLevel = analysis?.overall_risk ?? (regexSignals.length > 0 ? "high" : "medium");
  const finalRisk: RiskLevel = disagreements.length > 0 || injectionMarkers.length > 0 ? "high" : base;

  return { regexSignals, disagreements, injectionMarkers, finalRisk };
}
