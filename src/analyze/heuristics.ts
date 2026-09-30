import type { PendingTx, RiskLevel, TxReport } from "../types.js";
import { logger } from "../util/logger.js";
import { TxHistory, createRules, type Rule } from "./rules.js";

// Weighted scoring instead of booleans: several weak signals together can
// outrank one strong one, and the per-rule weights in the output show
// exactly why a score came out the way it did.
export function riskFromScore(score: number): RiskLevel {
  if (score > 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

export class HeuristicEngine {
  private readonly history: TxHistory;
  private readonly rules: Rule[];

  // now() is injectable so the demo can replay a burst deterministically.
  constructor(now: () => number = Date.now) {
    this.history = new TxHistory(now);
    this.rules = createRules(this.history);
  }

  analyze(tx: PendingTx): TxReport {
    const findings = [];
    for (const rule of this.rules) {
      // One buggy rule must not take down the stream or hide other findings.
      try {
        const f = rule.check(tx);
        if (f) findings.push(f);
      } catch (err) {
        logger.warn(`rule ${rule.id} threw on ${tx.hash}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    this.history.record(tx);
    const score = findings.reduce((sum, f) => sum + f.weight, 0);
    return { tx, findings, score, risk: riskFromScore(score) };
  }
}
