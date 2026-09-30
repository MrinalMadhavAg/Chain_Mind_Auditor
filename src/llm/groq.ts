import { RetryableError, isRetryableStatus, withBackoff } from "../util/backoff.js";
import { SYSTEM_PROMPT, STRICT_SUFFIX, buildUserPrompt } from "./prompt.js";
import { LLMError, type AnalyzeOptions, type LLMProvider } from "./provider.js";

// Groq exposes an OpenAI-compatible chat completions API, so this is plain
// fetch with no SDK. Any OpenAI-compatible server can be targeted by
// changing BASE_URL and the key.
const BASE_URL = "https://api.groq.com/openai/v1/chat/completions";
const REQUEST_TIMEOUT_MS = 60_000;

interface ChatResponse {
  choices?: { message?: { content?: unknown } }[];
  error?: { message?: string };
}

export class GroqProvider implements LLMProvider {
  readonly name: string;

  constructor(
    private readonly apiKey: string,
    private readonly model: string,
  ) {
    this.name = `groq (${model})`;
  }

  async analyze(sanitizedSource: string, opts: AnalyzeOptions = {}): Promise<string> {
    const user = buildUserPrompt(sanitizedSource) + (opts.strict ? STRICT_SUFFIX : "");
    return withBackoff("groq chat completion", () => this.request(user));
  }

  private async request(user: string): Promise<string> {
    let res: Response;
    try {
      res = await fetch(BASE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.apiKey}` },
        body: JSON.stringify({
          model: this.model,
          // Low temperature: this is analysis, and repeat runs on the same
          // contract should agree with each other.
          temperature: 0.1,
          // Generous because reasoning models (gpt-oss) spend completion
          // tokens thinking before they emit the JSON.
          max_tokens: 6000,
          messages: [
            { role: "system", content: SYSTEM_PROMPT },
            { role: "user", content: user },
          ],
        }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (err) {
      const cause = err instanceof Error ? ((err.cause as { code?: string } | undefined)?.code ?? err.message) : String(err);
      throw new RetryableError(`network error (${cause})`);
    }

    if (!res.ok) {
      if (isRetryableStatus(res.status)) throw new RetryableError(`HTTP ${res.status}`);
      if (res.status === 401) throw new LLMError("Groq rejected the API key (HTTP 401). Check GROQ_API_KEY.");
      const detail = await res.text().catch(() => "");
      throw new LLMError(`Groq HTTP ${res.status}: ${detail.slice(0, 200)}`);
    }

    let body: ChatResponse;
    try {
      body = (await res.json()) as ChatResponse;
    } catch {
      throw new RetryableError("response was not valid JSON");
    }
    const content = body.choices?.[0]?.message?.content;
    if (typeof content !== "string" || content.trim() === "") {
      throw new LLMError("Groq returned an empty completion");
    }
    return content;
  }
}
