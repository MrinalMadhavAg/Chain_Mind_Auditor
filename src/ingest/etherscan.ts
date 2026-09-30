import { isAddress } from "../security/sanitize.js";
import type { ContractSource } from "../types.js";
import { RetryableError, isRetryableStatus, withBackoff } from "../util/backoff.js";
import { TTLCache } from "../util/cache.js";
import { logger } from "../util/logger.js";
import { TokenBucket } from "../util/ratelimit.js";

// Etherscan V2 unified endpoint: one base URL for every chain, selected by
// the chainid query param (1 = Ethereum mainnet). V1 per-chain domains are
// deprecated.
const BASE_URL = "https://api.etherscan.io/v2/api";
const CHAIN_ID = "1";
const REQUEST_TIMEOUT_MS = 15_000;

export class EtherscanError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EtherscanError";
  }
}

// Module-level singletons: the limits apply to the API key, so they must be
// shared by every call in the process, not created per request.
// Free tier: 5 calls/sec.
const bucket = new TokenBucket(5, 5);
// null is cached too, so an unverified address is also only asked about once.
const cache = new TTLCache<ContractSource | null>(60 * 60 * 1000);

interface EtherscanResponse {
  status?: string;
  message?: string;
  result?: unknown;
}

interface SourceFile {
  content?: unknown;
}

// Vendored libraries go last so that when the source is truncated for the
// LLM, what gets cut is audited dependency code rather than the contract
// under review.
export function isLibraryPath(path: string): boolean {
  return /(^|\/)(@openzeppelin|@uniswap|@chainlink|@solmate|solmate|node_modules|lib\/)/i.test(path);
}

// File boundaries are kept as comment headers. The sanitizer strips them
// with other comments, but the cross-check uses them to tell project files
// from vendored ones.
export const FILE_HEADER_RE = /^\/\/ File: (.+)$/m;

function concatSources(sources: Record<string, SourceFile>): string {
  const entries = Object.entries(sources).filter(([, f]) => typeof f?.content === "string");
  entries.sort(([a], [b]) => Number(isLibraryPath(a)) - Number(isLibraryPath(b)));
  return entries.map(([path, f]) => `// File: ${path}\n${f.content as string}`).join("\n\n");
}

// SourceCode arrives in one of four shapes:
//   ""                 unverified contract
//   "pragma ..."       flat single-file Solidity
//   "{...}"            JSON: either standard JSON input { sources } or a bare
//                      { path: { content } } map (older multi-file format)
//   "{{...}}"          standard JSON input wrapped in an extra brace pair,
//                      which naive JSON.parse rejects
export function parseSourceCode(raw: string): string {
  const s = raw.trim();
  if (!s.startsWith("{")) return s;

  const jsonText = s.startsWith("{{") && s.endsWith("}}") ? s.slice(1, -1) : s;
  try {
    const parsed = JSON.parse(jsonText) as Record<string, unknown>;
    const sources = (parsed.sources ?? parsed) as Record<string, SourceFile>;
    const joined = concatSources(sources);
    // If no entry had string content, this was not a sources map after all.
    return joined || s;
  } catch {
    // Unparseable JSON-looking text: return as-is rather than losing it.
    return s;
  }
}

async function request(address: string, apiKey: string): Promise<EtherscanResponse> {
  const url = new URL(BASE_URL);
  url.search = new URLSearchParams({
    chainid: CHAIN_ID,
    module: "contract",
    action: "getsourcecode",
    address,
    apikey: apiKey,
  }).toString();

  await bucket.acquire();

  let res: Response;
  try {
    res = await fetch(url, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  } catch (err) {
    // Network failures and timeouts are transient from our point of view.
    const cause = err instanceof Error ? ((err.cause as { code?: string } | undefined)?.code ?? err.message) : String(err);
    throw new RetryableError(`network error (${cause})`);
  }

  if (!res.ok) {
    if (isRetryableStatus(res.status)) throw new RetryableError(`HTTP ${res.status}`);
    throw new EtherscanError(`HTTP ${res.status}`);
  }

  let body: EtherscanResponse;
  try {
    body = (await res.json()) as EtherscanResponse;
  } catch {
    throw new RetryableError("response was not valid JSON");
  }

  // Etherscan reports rate limiting with HTTP 200 and status "0", so the
  // body has to be inspected, not just the status code.
  if (body.status === "0" && typeof body.result === "string") {
    if (/rate limit/i.test(body.result)) throw new RetryableError(`rate limited: ${body.result}`);
    throw new EtherscanError(body.result);
  }
  return body;
}

export async function fetchContractSource(address: string, apiKey: string): Promise<ContractSource | null> {
  // Validate before spending a request: a malformed address would only come
  // back as an error, and it would still cost a token.
  if (!isAddress(address)) {
    throw new EtherscanError(`"${address}" is not a valid address (expected 0x followed by 40 hex characters)`);
  }
  const key = address.toLowerCase();
  if (cache.has(key)) {
    logger.debug(`etherscan cache hit for ${key}`);
    return cache.get(key) ?? null;
  }

  const body = await withBackoff("etherscan getsourcecode", () => request(key, apiKey));

  const first = Array.isArray(body.result) ? (body.result[0] as Record<string, unknown> | undefined) : undefined;
  if (!first) throw new EtherscanError("unexpected response shape (no result entry)");

  const rawSource = typeof first.SourceCode === "string" ? first.SourceCode : "";
  if (rawSource.trim() === "") {
    cache.set(key, null);
    return null;
  }

  const source: ContractSource = {
    address: key,
    name: typeof first.ContractName === "string" && first.ContractName ? first.ContractName : "(unnamed)",
    compilerVersion: typeof first.CompilerVersion === "string" ? first.CompilerVersion : "unknown",
    sourceCode: parseSourceCode(rawSource),
    abi: typeof first.ABI === "string" ? first.ABI : "",
  };
  cache.set(key, source);
  return source;
}
