import type { LLMConfig } from "../config.js";
import { GroqProvider } from "./groq.js";

export interface AnalyzeOptions {
  // Set on the retry after an unparseable reply: adds a stricter
  // "JSON only" instruction.
  strict?: boolean;
}

// The one seam between the tool and any model. A provider is only a
// transport: it builds the request from prompt.ts and returns the model's
// raw text. Fence stripping, parsing and validation live in analyze/llm.ts,
// so they are written once and every provider is held to the same checks.
export interface LLMProvider {
  name: string;
  analyze(sanitizedSource: string, opts?: AnalyzeOptions): Promise<string>;
}

export class LLMError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LLMError";
  }
}

// The only place a concrete provider is named. Adding a provider means one
// new file in llm/ and one case here; nothing outside llm/ changes.
// Ollama was cut for time. Its OpenAI-compatible /v1/chat/completions route
// would make it a near copy of groq.ts with a different base URL and no key.
export function createProvider(config: LLMConfig): LLMProvider {
  switch (config.provider) {
    case "groq":
      return new GroqProvider(config.groqApiKey, config.groqModel);
  }
}
