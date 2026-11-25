import { describe, expect, it } from 'vitest';
import { ERROR_TTL_MAX, ResultCache, cacheKey, errorTtl, isFresh, memoryKV } from '@/lib/cache';
import { DAY, HOUR, MINUTE } from '@/lib/types';

const mod = { id: 'rdap', version: 3, ttl: DAY };
const ent = { kind: 'domain' as const, value: 'example.com' };

function setup(start = 1_000_000) {
  let t = start;
  const kv = memoryKV();
  const cache = new ResultCache(kv, () => t);
  return { kv, cache, advance: (ms: number) => (t += ms), now: () => t };
}

describe('cache keys and TTL math', () => {
  it('builds `${id}@${version}:${kind}:${value}` keys', () => {
    expect(cacheKey(mod, ent)).toBe('rdap@3:domain:example.com');
  });

  it('bumping the module version changes the key (invalidates)', () => {
    expect(cacheKey({ ...mod, version: 4 }, ent)).not.toBe(cacheKey(mod, ent));
  });

  it('isFresh is true strictly before ttl elapses', () => {
    expect(isFresh({ fetchedAt: 0, ttl: 100 }, 99)).toBe(true);
    expect(isFresh({ fetchedAt: 0, ttl: 100 }, 100)).toBe(false);
  });

  it('treats entries from the future (clock moved back) as stale', () => {
    expect(isFresh({ fetchedAt: 1000, ttl: DAY }, 500)).toBe(false);
  });

  it('caps error TTL at 2 minutes', () => {
    expect(errorTtl(DAY)).toBe(2 * MINUTE);
    expect(errorTtl(30_000)).toBe(30_000);
    expect(ERROR_TTL_MAX).toBe(120_000);
  });
});

describe('ResultCache stale-while-revalidate', () => {
  it('returns fresh data, then stale data after TTL (not undefined)', async () => {
    const { cache, advance } = setup();
    await cache.storeResult(mod, ent, { data: { a: 1 }, summary: 's', pivots: [{ kind: 'ip', value: '1.2.3.4' }] });
    const hit = await cache.lookup(mod, ent);
    expect(hit?.fresh).toBe(true);
    expect(hit?.entry.data).toEqual({ a: 1 });
    expect(hit?.entry.pivots).toEqual([{ kind: 'ip', value: '1.2.3.4' }]);
    advance(DAY + 1);
    const stale = await cache.lookup(mod, ent);
    expect(stale?.fresh).toBe(false);
    expect(stale?.entry.data).toEqual({ a: 1 });
  });

  it('returns undefined on a miss and on malformed entries', async () => {
    const { cache, kv } = setup();
    expect(await cache.lookup(mod, ent)).toBeUndefined();
    await kv.set(cacheKey(mod, ent), { nope: true });
    expect(await cache.lookup(mod, ent)).toBeUndefined();
  });

  it('serves errors only while fresh and never longer than 2 minutes', async () => {
    const { cache, advance, kv } = setup();
    await cache.storeError(mod, ent, { kind: 'http', message: 'HTTP 500', status: 500 });
    expect((await cache.lookup(mod, ent))?.entry.error?.status).toBe(500);
    advance(2 * MINUTE - 1);
    expect(await cache.lookup(mod, ent)).toBeDefined();
    advance(1);
    expect(await cache.lookup(mod, ent)).toBeUndefined();
    expect(kv.map.size).toBe(0); // expired error is deleted, never served stale
  });

  it('ignores a tampered error entry with a long TTL', async () => {
    const { cache, kv } = setup();
    await kv.set(cacheKey(mod, ent), { error: { kind: 'http', message: 'x' }, fetchedAt: 1_000_000, ttl: HOUR });
    expect(await cache.lookup(mod, ent)).toBeUndefined();
  });

  it('never caches cancellations', async () => {
    const { cache, kv } = setup();
    await cache.storeError(mod, ent, { kind: 'aborted', message: 'Cancelled' });
    expect(kv.map.size).toBe(0);
  });

  it('a successful result overwrites a cached error', async () => {
    const { cache } = setup();
    await cache.storeError(mod, ent, { kind: 'timeout', message: 't' });
    await cache.storeResult(mod, ent, { data: 1 });
    const hit = await cache.lookup(mod, ent);
    expect(hit?.entry.error).toBeUndefined();
    expect(hit?.entry.data).toBe(1);
  });

  it('getRaw/setRaw honour the max age', async () => {
    const { cache, advance } = setup();
    await cache.setRaw('bootstrap', { v: 1 }, DAY);
    expect(await cache.getRaw('bootstrap', DAY)).toEqual({ v: 1 });
    expect(await cache.getRaw('bootstrap', HOUR)).toEqual({ v: 1 });
    advance(HOUR);
    expect(await cache.getRaw('bootstrap', HOUR)).toBeUndefined();
    expect(await cache.getRaw('bootstrap', DAY)).toEqual({ v: 1 });
  });

  it('clear() empties everything', async () => {
    const { cache, kv } = setup();
    await cache.storeResult(mod, ent, { data: 1 });
    await cache.clear();
    expect(kv.map.size).toBe(0);
  });

  it('survives a throwing KV', async () => {
    const cache = new ResultCache({
      get: () => Promise.reject(new Error('idb gone')),
      set: () => Promise.reject(new Error('idb gone')),
      del: () => Promise.reject(new Error('idb gone')),
      clear: () => Promise.reject(new Error('idb gone')),
    });
    expect(await cache.lookup(mod, ent)).toBeUndefined();
    await expect(cache.storeResult(mod, ent, { data: 1 })).resolves.toBeDefined();
  });
});

describe('per-result TTL and key provenance', () => {
  it('a result can shorten (never lengthen) its TTL', async () => {
    const { cache } = setup();
    expect((await cache.storeResult(mod, ent, { data: 1, ttl: 60_000 })).ttl).toBe(60_000);
    expect((await cache.storeResult(mod, ent, { data: 1, ttl: 10 * DAY })).ttl).toBe(DAY);
    expect((await cache.storeResult(mod, ent, { data: 1 })).ttl).toBe(DAY);
  });

  it('records whether a key was used', async () => {
    const { cache } = setup();
    await cache.storeResult(mod, ent, { data: 1 }, false);
    expect((await cache.lookup(mod, ent))?.entry.keyed).toBe(false);
  });

  it('records key provenance on error entries too (a keyless error must not outlive adding a key)', async () => {
    const { cache } = setup();
    await cache.storeError(mod, ent, { kind: 'http', message: 'HTTP 429', status: 429 }, false);
    expect((await cache.lookup(mod, ent))?.entry).toMatchObject({ keyed: false, error: { status: 429 } });
    await cache.storeError(mod, ent, { kind: 'http', message: 'HTTP 500', status: 500 });
    expect((await cache.lookup(mod, ent))?.entry).not.toHaveProperty('keyed');
  });
});
