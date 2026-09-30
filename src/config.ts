import dotenv from "dotenv";
import { LOG_LEVELS, setLogLevel, type LogLevel } from "./util/logger.js";

// quiet: dotenv 17+ prints an "injecting env" line on load by default,
// which would pollute CLI output.
dotenv.config({ quiet: true });

// Thrown instead of calling process.exit here, so index.ts owns the single
// exit path and can print every missing variable at once.
export class ConfigError extends Error {
  constructor(public readonly problems: string[]) {
    super(`Configuration invalid:\n  - ${problems.join("\n  - ")}`);
    this.name = "ConfigError";
  }
}

function read(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value ? value : undefined;
}

// Called once at startup regardless of command. LOG_LEVEL is optional, but a
// typo in it is still an error rather than being silently ignored.
export function initBaseConfig(): void {
  const raw = read("LOG_LEVEL") ?? "info";
  if (!LOG_LEVELS.includes(raw as LogLevel)) {
    throw new ConfigError([`LOG_LEVEL must be one of ${LOG_LEVELS.join(", ")} (got "${raw}")`]);
  }
  setLogLevel(raw as LogLevel);
}

// Requirements are split into groups so each command asks only for what it
// uses. The contract command never needs Alchemy credentials, and tx --watch
// never needs Etherscan or an LLM.

export interface EtherscanConfig {
  etherscanApiKey: string;
}

export function requireEtherscan(): EtherscanConfig {
  const key = read("ETHERSCAN_API_KEY");
  if (!key) throw new ConfigError(["ETHERSCAN_API_KEY is required for the contract command"]);
  return { etherscanApiKey: key };
}

export interface MempoolConfig {
  wssUrl: string;
}

export function requireMempool(): MempoolConfig {
  const explicit = read("ALCHEMY_WSS_URL");
  const key = read("ALCHEMY_API_KEY");

  // Accept either the full URL or just the key. The URL wins if both are
  // set, since it may point at a non-default network or endpoint.
  const wssUrl = explicit ?? (key ? `wss://eth-mainnet.g.alchemy.com/v2/${key}` : undefined);
  if (!wssUrl) {
    throw new ConfigError(["ALCHEMY_WSS_URL or ALCHEMY_API_KEY is required for the tx command"]);
  }
  if (!/^wss?:\/\//.test(wssUrl)) {
    throw new ConfigError([`ALCHEMY_WSS_URL must start with wss:// (got "${wssUrl.slice(0, 12)}...")`]);
  }
  return { wssUrl };
}

// Only Groq is implemented. LLM_PROVIDER is still read and validated so the
// selection mechanism exists; a new provider adds a name here and a case in
// llm/provider.ts.
export type ProviderName = "groq";

export interface LLMConfig {
  provider: ProviderName;
  groqApiKey: string;
  groqModel: string;
}

export function requireLLM(): LLMConfig {
  const problems: string[] = [];
  const provider = (read("LLM_PROVIDER") ?? "groq").toLowerCase();
  if (provider !== "groq") {
    problems.push(`LLM_PROVIDER must be "groq" (got "${provider}")`);
  }
  const groqApiKey = read("GROQ_API_KEY");
  if (!groqApiKey) problems.push("GROQ_API_KEY is required for contract analysis");
  if (problems.length > 0 || !groqApiKey) throw new ConfigError(problems);

  return {
    provider: "groq",
    groqApiKey,
    // gpt-oss-120b rather than a Llama 3 variant: Llama 3 chat models are not
    // available on every Groq account, and this one is. Any accessible
    // chat model can be set via GROQ_MODEL.
    groqModel: read("GROQ_MODEL") ?? "openai/gpt-oss-120b",
  };
}
