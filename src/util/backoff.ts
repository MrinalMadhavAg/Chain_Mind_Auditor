import { logger } from "./logger.js";

// Thrown by an operation to signal the failure is transient and worth
// retrying. Anything else (bad input, 4xx other than 429) fails immediately,
// since retrying a request that is wrong just burns quota.
export class RetryableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RetryableError";
  }
}

export class RetriesExhaustedError extends Error {
  constructor(
    message: string,
    public readonly attempts: number,
  ) {
    super(message);
    this.name = "RetriesExhaustedError";
  }
}

// HTTP 429 and 5xx are the transient classes: rate limited, or the server is
// having a bad moment. Both usually resolve on their own.
export function isRetryableStatus(status: number): boolean {
  return status === 429 || status >= 500;
}

const DELAYS_MS = [1000, 2000, 4000, 8000];
const MAX_ATTEMPTS = 4;

// Exponential delays give a rate limiter time to reset without hammering it.
// Four attempts caps the worst case wait at about 7 seconds of sleeping.
export async function withBackoff<T>(label: string, fn: () => Promise<T>): Promise<T> {
  let lastError = "";
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (!(err instanceof RetryableError)) throw err;
      lastError = err.message;
      if (attempt === MAX_ATTEMPTS) break;
      const delay = DELAYS_MS[attempt - 1] ?? 8000;
      logger.warn(`${label}: ${err.message}, retrying in ${delay / 1000}s (attempt ${attempt}/${MAX_ATTEMPTS})`);
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
  throw new RetriesExhaustedError(`${label} failed after ${MAX_ATTEMPTS} attempts: ${lastError}`, MAX_ATTEMPTS);
}
