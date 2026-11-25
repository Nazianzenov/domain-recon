import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RateLimiter } from '@/lib/ratelimit';

describe('RateLimiter (token bucket)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('allows a burst of perMinute requests, then spaces the rest at 60/perMinute s', async () => {
    const rl = new RateLimiter();
    const done: number[] = [];
    const all = Array.from({ length: 6 }, (_, i) => rl.acquire('vt', 4).then(() => done.push(i)));
    await vi.advanceTimersByTimeAsync(0);
    expect(done).toEqual([0, 1, 2, 3]);
    await vi.advanceTimersByTimeAsync(14_999);
    expect(done).toEqual([0, 1, 2, 3]);
    await vi.advanceTimersByTimeAsync(1);
    expect(done).toEqual([0, 1, 2, 3, 4]);
    await vi.advanceTimersByTimeAsync(15_000);
    expect(done).toEqual([0, 1, 2, 3, 4, 5]);
    await Promise.all(all);
  });

  it('queues FIFO instead of failing', async () => {
    const rl = new RateLimiter();
    const order: string[] = [];
    await rl.acquire('p', 1);
    const a = rl.acquire('p', 1).then(() => order.push('a'));
    const b = rl.acquire('p', 1).then(() => order.push('b'));
    const c = rl.acquire('p', 1).then(() => order.push('c'));
    await vi.advanceTimersByTimeAsync(180_000);
    await Promise.all([a, b, c]);
    expect(order).toEqual(['a', 'b', 'c']);
  });

  it('keeps providers independent', async () => {
    const rl = new RateLimiter();
    await rl.acquire('a', 1);
    let bDone = false;
    void rl.acquire('b', 1).then(() => (bDone = true));
    await vi.advanceTimersByTimeAsync(0);
    expect(bDone).toBe(true);
  });

  it('rejects an aborted waiter without blocking the ones behind it', async () => {
    const rl = new RateLimiter();
    await rl.acquire('p', 1);
    const ac = new AbortController();
    const aborted = rl.acquire('p', 1, ac.signal);
    let nextDone = false;
    const next = rl.acquire('p', 1).then(() => (nextDone = true));
    ac.abort();
    await expect(aborted).rejects.toThrow();
    // The aborted waiter did not consume the token: the next one gets it at 60 s.
    await vi.advanceTimersByTimeAsync(60_000);
    await next;
    expect(nextDone).toBe(true);
  });

  it('penalize() drains the bucket and blocks until Retry-After', async () => {
    const rl = new RateLimiter();
    await rl.acquire('p', 10);
    rl.penalize('p', 30_000);
    let done = false;
    void rl.acquire('p', 10).then(() => (done = true));
    await vi.advanceTimersByTimeAsync(29_999);
    expect(done).toBe(false);
    await vi.advanceTimersByTimeAsync(6_001); // blocked 30 s, then one token needs 6 s at 10/min
    expect(done).toBe(true);
  });

  it('refills over time up to capacity (no unbounded burst)', async () => {
    const rl = new RateLimiter();
    await rl.acquire('p', 2);
    await rl.acquire('p', 2);
    await vi.advanceTimersByTimeAsync(10 * 60_000); // long idle: refill caps at 2
    const done: number[] = [];
    for (let i = 0; i < 3; i++) void rl.acquire('p', 2).then(() => done.push(i));
    await vi.advanceTimersByTimeAsync(0);
    expect(done).toEqual([0, 1]);
  });
});

describe('RateLimiter: cancellation, penalties and limit changes', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('an aborted waiter deep in the queue rejects at once, not when its turn comes', async () => {
    const rl = new RateLimiter();
    await rl.acquire('p', 1);
    const head = rl.acquire('p', 1); // waits 60 s for the next token
    const ac = new AbortController();
    let rejectedAt: number | null = null;
    const behind = rl.acquire('p', 1, ac.signal).catch(() => (rejectedAt = Date.now()));
    expect(rl.pending('p')).toBe(2);
    await vi.advanceTimersByTimeAsync(1_000);
    ac.abort();
    await behind;
    expect(rejectedAt).toBe(1_000);
    expect(rl.pending('p')).toBe(1);
    // The head is not delayed, and the abandoned turn consumes no token.
    await vi.advanceTimersByTimeAsync(59_000);
    await head;
    let nextAt: number | null = null;
    const next = rl.acquire('p', 1).then(() => (nextAt = Date.now()));
    await vi.advanceTimersByTimeAsync(60_000);
    await next;
    expect(nextAt).toBe(120_000);
  });

  it('rejects synchronously-aborted signals without queueing', async () => {
    const rl = new RateLimiter();
    const ac = new AbortController();
    ac.abort();
    await expect(rl.acquire('p', 1, ac.signal)).rejects.toThrow();
    expect(rl.pending('p')).toBe(0);
  });

  it('no tokens accrue while penalized: no burst the moment Retry-After expires', async () => {
    const rl = new RateLimiter();
    await rl.acquire('p', 10); // 9 left
    rl.penalize('p', 30_000);
    const done: number[] = [];
    for (let i = 0; i < 3; i++) void rl.acquire('p', 10).then(() => done.push(Date.now()));
    await vi.advanceTimersByTimeAsync(30_001);
    expect(done).toEqual([]); // previously 5 tokens had accrued during the block
    await vi.advanceTimersByTimeAsync(30_000);
    expect(done).toEqual([36_000, 42_000, 48_000]);
  });

  it('adopts a lower limit without granting a burst', async () => {
    const rl = new RateLimiter();
    await rl.acquire('p', 10); // 9 tokens left at capacity 10
    const done: number[] = [];
    for (let i = 0; i < 3; i++) void rl.acquire('p', 2).then(() => done.push(Date.now()));
    await vi.advanceTimersByTimeAsync(0);
    expect(done).toEqual([0, 0]); // clamped to the new capacity (2)
    await vi.advanceTimersByTimeAsync(30_000);
    expect(done).toEqual([0, 0, 30_000]);
  });

  it('a non-finite penalty does not stop the bucket from refilling', async () => {
    const rl = new RateLimiter();
    await rl.acquire('p', 60);
    rl.penalize('p', Number.NaN);
    let done = false;
    void rl.acquire('p', 60).then(() => (done = true));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(done).toBe(true);
  });

  it('a non-finite limit falls back to 1/min instead of spinning', async () => {
    const rl = new RateLimiter();
    await rl.acquire('nan', Number.NaN);
    let done = false;
    void rl.acquire('nan', Number.NaN, undefined, Number.NaN).then(() => (done = true));
    await vi.advanceTimersByTimeAsync(59_999);
    expect(done).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(done).toBe(true);
  });
});

describe('RateLimiter burst capacity', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('burst 1 spaces requests evenly (per-second APIs) instead of a 60-request burst', async () => {
    const rl = new RateLimiter();
    const done: number[] = [];
    for (let i = 0; i < 3; i++) void rl.acquire('shodan-host', 60, undefined, 1).then(() => done.push(i));
    await vi.advanceTimersByTimeAsync(0);
    expect(done).toEqual([0]);
    await vi.advanceTimersByTimeAsync(1000);
    expect(done).toEqual([0, 1]);
    await vi.advanceTimersByTimeAsync(1000);
    expect(done).toEqual([0, 1, 2]);
  });
});
