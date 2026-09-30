// Token bucket. Etherscan's free tier allows 5 calls/sec; a bucket smooths
// bursts to that rate on our side instead of discovering the limit via
// rejected requests.
export class TokenBucket {
  private tokens: number;
  private lastRefill: number;

  constructor(
    private readonly capacity: number,
    private readonly refillPerSec: number,
  ) {
    this.tokens = capacity;
    this.lastRefill = Date.now();
  }

  // Tokens are refilled lazily from elapsed time rather than by a timer, so
  // an idle bucket costs nothing and never keeps the process alive.
  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.capacity, this.tokens + elapsed * this.refillPerSec);
    this.lastRefill = now;
  }

  async acquire(): Promise<void> {
    for (;;) {
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      // Sleep exactly until the next whole token is available.
      const waitMs = Math.ceil(((1 - this.tokens) / this.refillPerSec) * 1000);
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }
  }
}
