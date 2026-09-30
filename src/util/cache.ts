// In-memory TTL cache. Verified source is immutable for a given address, so
// a hit is always correct; the TTL only bounds memory in long sessions.
// No persistence by design: no database, and a run is short.
export class TTLCache<V> {
  private store = new Map<string, { value: V; expires: number }>();

  constructor(private readonly ttlMs: number) {}

  get(key: string): V | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expires) {
      this.store.delete(key);
      return undefined;
    }
    return entry.value;
  }

  // Using has() rather than get() !== undefined lets callers cache null,
  // which is how "this contract is unverified" is remembered.
  has(key: string): boolean {
    this.get(key); // evicts the entry if expired
    return this.store.has(key);
  }

  set(key: string, value: V): void {
    this.store.set(key, { value, expires: Date.now() + this.ttlMs });
  }
}
