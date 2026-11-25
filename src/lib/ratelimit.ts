/**
 * Per-provider token bucket. Requests queue (FIFO per key) instead of failing.
 *
 * capacity = perMinute, refill = perMinute / 60 s. A provider 429 calls
 * `penalize()` which empties the bucket and blocks it until Retry-After.
 */

export interface Clock {
  now(): number;
  sleep(ms: number, signal?: AbortSignal): Promise<void>;
}

export function abortReason(signal: AbortSignal): Error {
  const r: unknown = signal.reason;
  if (r instanceof Error) return r;
  const e = new Error('Aborted');
  e.name = 'AbortError';
  return e;
}

export const realClock: Clock = {
  now: () => Date.now(),
  sleep: (ms, signal) =>
    new Promise<void>((resolve, reject) => {
      if (signal?.aborted) {
        reject(abortReason(signal));
        return;
      }
      const onAbort = () => {
        clearTimeout(t);
        reject(abortReason(signal!));
      };
      const t = setTimeout(() => {
        signal?.removeEventListener('abort', onAbort);
        resolve();
      }, Math.max(0, ms));
      signal?.addEventListener('abort', onAbort, { once: true });
    }),
};

interface Bucket {
  capacity: number;
  /** tokens per ms */
  rate: number;
  tokens: number;
  last: number;
  blockedUntil: number;
  /** Tail of the FIFO queue for this key. */
  tail: Promise<void>;
  waiting: number;
}

export class RateLimiter {
  private buckets = new Map<string, Bucket>();

  constructor(private clock: Clock = realClock) {}

  private bucket(key: string, perMinute: number, burst?: number): Bucket {
    let b = this.buckets.get(key);
    // NaN/Infinity would make take() spin (sleep(NaN) fires at once and tokens never reach 1).
    const pm = Number.isFinite(perMinute) ? Math.max(1, perMinute) : 1;
    const rate = pm / 60_000;
    const capacity = Math.max(1, Math.floor(burst !== undefined && Number.isFinite(burst) ? burst : pm));
    if (!b) {
      b = {
        capacity,
        rate,
        tokens: capacity,
        last: this.clock.now(),
        blockedUntil: 0,
        tail: Promise.resolve(),
        waiting: 0,
      };
      this.buckets.set(key, b);
    } else if (b.capacity !== capacity || b.rate !== rate) {
      // Limit changed (e.g. a key was added): adopt it without granting a burst.
      this.refill(b);
      b.capacity = capacity;
      b.rate = rate;
      b.tokens = Math.min(b.tokens, capacity);
    }
    return b;
  }

  private refill(b: Bucket): void {
    const now = this.clock.now();
    // No refill while penalized: after a 429 the bucket restarts empty at blockedUntil
    // instead of releasing a burst the moment Retry-After expires.
    const from = Math.max(b.last, b.blockedUntil);
    if (now > from) b.tokens = Math.min(b.capacity, b.tokens + (now - from) * b.rate);
    b.last = now;
  }

  /**
   * Resolves when a token has been consumed. Rejects only if `signal` aborts,
   * and then at once, even while queued behind other waiters (whose turn is
   * not delayed; the abandoned turn consumes no token).
   */
  acquire(key: string, perMinute: number, signal?: AbortSignal, burst?: number): Promise<void> {
    if (signal?.aborted) return Promise.reject(abortReason(signal));
    const b = this.bucket(key, perMinute, burst);
    b.waiting++;
    let left = false;
    const leave = () => {
      if (!left) {
        left = true;
        b.waiting--;
      }
    };
    let abandoned = false;
    const turn = b.tail.then(() => (abandoned ? undefined : this.take(b, signal)));
    // Keep the chain alive even if this waiter aborts.
    b.tail = turn.then(leave, leave);
    if (!signal) return turn;
    let onAbort!: () => void;
    const aborted = new Promise<never>((_, reject) => {
      onAbort = () => {
        abandoned = true;
        leave();
        reject(abortReason(signal));
      };
      signal.addEventListener('abort', onAbort, { once: true });
    });
    return Promise.race([turn, aborted]).finally(() => signal.removeEventListener('abort', onAbort));
  }

  private async take(b: Bucket, signal?: AbortSignal): Promise<void> {
    for (;;) {
      if (signal?.aborted) throw abortReason(signal);
      this.refill(b);
      const now = this.clock.now();
      if (now < b.blockedUntil) {
        await this.clock.sleep(b.blockedUntil - now, signal);
        continue;
      }
      if (b.tokens >= 1) {
        b.tokens -= 1;
        return;
      }
      await this.clock.sleep(Math.ceil((1 - b.tokens) / b.rate), signal);
    }
  }

  /** Provider said "slow down": drain the bucket and pause it for `ms`. */
  penalize(key: string, ms: number): void {
    const b = this.buckets.get(key);
    if (!b) return;
    this.refill(b);
    b.tokens = 0;
    // A NaN here would poison refill() (no token would ever accrue again).
    const wait = Number.isFinite(ms) ? Math.max(0, ms) : 0;
    b.blockedUntil = Math.max(b.blockedUntil, this.clock.now() + wait);
  }

  /** Number of requests currently queued or running acquire() for `key` (for UI hints). */
  pending(key: string): number {
    return this.buckets.get(key)?.waiting ?? 0;
  }
}
