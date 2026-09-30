export type RiskLevel = "low" | "medium" | "high";

// A pending transaction after sanitization. Every field has been
// shape-checked, so analyzers can trust types without re-validating.
// `to` is null for contract creation.
export interface PendingTx {
  hash: string;
  from: string;
  to: string | null;
  value: bigint; // wei
  gasPrice: bigint | null; // wei; maxFeePerGas for EIP-1559 txs
  input: string; // lowercase 0x-prefixed hex
}

export interface Finding {
  ruleId: string;
  ruleName: string;
  weight: number;
  explanation: string;
}

export interface TxReport {
  tx: PendingTx;
  findings: Finding[];
  score: number;
  risk: RiskLevel;
}

export interface ContractSource {
  address: string;
  name: string;
  compilerVersion: string;
  sourceCode: string; // all files concatenated for multi-file contracts
  abi: string;
}

export interface FunctionSummary {
  name: string;
  does: string;
  risk: RiskLevel;
}

// Mirrors the JSON schema the LLM is instructed to return.
export interface ContractAnalysis {
  purpose: string;
  functions: FunctionSummary[];
  red_flags: string[];
  overall_risk: RiskLevel;
}

export interface CrossCheckResult {
  regexSignals: string[]; // hard signals found by regex in raw source
  disagreements: string[]; // signals the LLM failed to report
  injectionMarkers: string[]; // prompt injection phrases found in raw source
  finalRisk: RiskLevel; // LLM risk, escalated to high on disagreement or injection
}
