import type { LLMProvider } from "../llm/provider.js";
import { crossCheck } from "../security/crosscheck.js";
import { sanitizeSource, stripControlChars } from "../security/sanitize.js";
import type { ContractAnalysis, CrossCheckResult, FunctionSummary, RiskLevel } from "../types.js";
import { logger } from "../util/logger.js";

export type LLMResult =
  | { ok: true; analysis: ContractAnalysis; sanitized: string }
  | { ok: false; error: string; sanitized: string };

// Models add ```json fences even when told not to. Rather than trusting the
// format, take the outermost {...} span, which also drops any prose before
// or after the object.
export function extractJson(text: string): string {
  const unfenced = text.replace(/```(?:json)?/gi, "");
  const start = unfenced.indexOf("{");
  const end = unfenced.lastIndexOf("}");
  return start >= 0 && end > start ? unfenced.slice(start, end + 1) : unfenced.trim();
}

function toRisk(value: unknown): RiskLevel | null {
  if (typeof value !== "string") return null;
  const v = value.trim().toLowerCase();
  return v === "low" || v === "medium" || v === "high" ? v : null;
}

// Model output is untrusted too: an injected contract can make the model echo
// arbitrary text. Strings are control-char stripped and length capped, and
// arrays are bounded, before anything reaches the terminal.
function cleanText(value: unknown, max: number): string | null {
  if (typeof value !== "string") return null;
  const s = stripControlChars(value).trim();
  return s ? s.slice(0, max) : null;
}

// Returns a problem description, or the validated object. Hand-written
// instead of a schema library: the schema is four fields.
export function validateAnalysis(parsed: unknown): ContractAnalysis | string {
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return "top level is not an object";
  const p = parsed as Record<string, unknown>;

  const purpose = cleanText(p.purpose, 400);
  if (!purpose) return "missing purpose";

  const overall = toRisk(p.overall_risk);
  if (!overall) return `overall_risk is not low|medium|high (got ${JSON.stringify(p.overall_risk)})`;

  if (!Array.isArray(p.functions)) return "functions is not an array";
  const functions: FunctionSummary[] = [];
  for (const f of p.functions.slice(0, 20)) {
    if (typeof f !== "object" || f === null) continue;
    const fr = f as Record<string, unknown>;
    const name = cleanText(fr.name, 80);
    const does = cleanText(fr.does, 300);
    // A missing per-function risk is tolerated as medium rather than failing
    // the whole analysis over one field.
    if (name && does) functions.push({ name, does, risk: toRisk(fr.risk) ?? "medium" });
  }

  if (!Array.isArray(p.red_flags)) return "red_flags is not an array";
  const red_flags = p.red_flags
    .slice(0, 20)
    .map((r) => cleanText(r, 300))
    .filter((r): r is string => r !== null);

  return { purpose, functions, red_flags, overall_risk: overall };
}

function tryParse(text: string): ContractAnalysis | string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(extractJson(text));
  } catch (err) {
    return `invalid JSON (${err instanceof Error ? err.message : String(err)})`;
  }
  return validateAnalysis(parsed);
}

// sanitize -> prompt -> call -> parse -> validate, with one strict retry.
// Never throws: provider failures come back as { ok: false } so the caller
// can still run the regex cross-check and show partial results.
export async function analyzeContract(rawSource: string, provider: LLMProvider): Promise<LLMResult> {
  const sanitized = sanitizeSource(rawSource);
  logger.info(`sanitized source: ${rawSource.length} -> ${sanitized.length} chars, sending to ${provider.name}`);

  try {
    const first = tryParse(await provider.analyze(sanitized));
    if (typeof first !== "string") return { ok: true, analysis: first, sanitized };

    // One retry only: a model that fails twice on format will likely keep
    // failing, and each attempt costs rate-limited tokens.
    logger.warn(`LLM reply rejected (${first}), retrying once with stricter instruction`);
    const second = tryParse(await provider.analyze(sanitized, { strict: true }));
    if (typeof second !== "string") return { ok: true, analysis: second, sanitized };
    return { ok: false, error: `LLM reply unusable after retry: ${second}`, sanitized };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err), sanitized };
  }
}

export interface ContractAudit {
  analysis: ContractAnalysis | null;
  llmError?: string;
  check: CrossCheckResult;
}

// The full contract pipeline, shared by the CLI and the demo so both run
// exactly the same path. The cross-check runs even when the LLM fails, so
// the deterministic half of the result is never lost.
export async function auditContract(rawSource: string, provider: LLMProvider): Promise<ContractAudit> {
  const result = await analyzeContract(rawSource, provider);
  const analysis = result.ok ? result.analysis : null;
  const check = crossCheck(rawSource, result.sanitized, analysis);
  return result.ok ? { analysis, check } : { analysis, llmError: result.error, check };
}
