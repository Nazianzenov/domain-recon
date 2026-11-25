import { describe, expect, it } from 'vitest';
import { cacheKey } from '@/lib/cache';
import { FetchError } from '@/lib/http';
import { Investigation, createShared, investigate, type OrchestratorDeps } from '@/lib/orchestrator';
import { RateLimiter } from '@/lib/ratelimit';
import { DEFAULT_SETTINGS } from '@/lib/settings';
import type { CardState, Entity, Module, RunEvent } from '@/lib/types';
import { DAY, SkipError } from '@/lib/types';
import { dummyModule } from '@/modules/dummy';
import { memoryCache } from './helpers';

function collector() {
  const events: RunEvent[] = [];
  const cards = new Map<string, CardState[]>();
  const emit = (e: RunEvent) => {
    events.push(e);
    if (e.type === 'card') cards.set(e.card.id, [...(cards.get(e.card.id) ?? []), e.card]);
  };
  const last = (id: string) => cards.get(id)?.at(-1);
  const entities = () => events.filter((e): e is Extract<RunEvent, { type: 'entity' }> => e.type === 'entity').map((e) => e.entity);
  return { events, cards, emit, last, entities };
}

function deps(modules: Module[], over: Partial<OrchestratorDeps> = {}): OrchestratorDeps {
  return {
    modules,
    isEnabled: () => true,
    allowActive: false,
    cache: memoryCache(),
    limiter: new RateLimiter(),
    settings: DEFAULT_SETTINGS,
    getKey: async () => undefined,
    fetch: (() => Promise.reject(new Error('no network in tests'))) as typeof fetch,
    ...over,
  };
}

const ipsModule = (n: number): Module => ({
  id: 'ips',
  label: 'IPs',
  version: 1,
  accepts: ['domain', 'ip'],
  ttl: DAY,
  async run(e) {
    if (e.kind === 'ip') return { data: {}, pivots: [{ kind: 'domain', value: 'other.example' }, { kind: 'ip', value: '9.9.9.9' }] };
    const pivots = Array.from({ length: n }, (_, i) => ({ kind: 'ip' as const, value: `8.8.${i}.1` }));
    return {
      data: { n },
      pivots: [...pivots, { kind: 'ip', value: '10.0.0.1' }, { kind: 'hash', value: '-123', note: 'mmh3' }],
    };
  },
});

const ipProbe: Module = {
  id: 'probe',
  label: 'Probe',
  version: 1,
  accepts: ['ip'],
  ttl: DAY,
  async run(e: Entity) {
    return { data: { ip: e.value }, summary: e.value };
  },
};

const ROOT = { kind: 'domain' as const, value: 'example.com' };
const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));
/** Resolves with value() after `ms`, or rejects like the fetch helpers when `signal` aborts. */
const abortable = <T>(signal: AbortSignal, ms: number, value: () => T) =>
  new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => resolve(value()), ms);
    signal.addEventListener('abort', () => {
      clearTimeout(t);
      reject(new FetchError('aborted', 'Cancelled', 'https://x'));
    });
  });

describe('orchestrator', () => {
  it('runs the dummy module end to end: queued -> running -> ok, then cached', async () => {
    const d = deps([dummyModule as Module]);
    const c1 = collector();
    await investigate({ kind: 'domain', value: 'xn--bcher-kva.example' }, c1.emit, d).done;
    const states = c1.cards.get('dummy|domain:xn--bcher-kva.example')!.map((c) => c.status);
    expect(states).toEqual(['queued', 'running', 'ok']);
    expect(c1.last('dummy|domain:xn--bcher-kva.example')!.summary).toContain('IDN');
    expect(c1.events.at(-1)).toEqual({ type: 'done', cancelled: false });

    const c2 = collector();
    await investigate({ kind: 'domain', value: 'xn--bcher-kva.example' }, c2.emit, d).done;
    const last = c2.last('dummy|domain:xn--bcher-kva.example')!;
    expect(last.status).toBe('cached');
    expect(last.stale).toBe(false);
    expect(last.revalidating).toBe(false);
  });

  it('pivots one hop only, caps at 10 IPs per domain, skips private IPs, lists hashes', async () => {
    const c = collector();
    await investigate({ kind: 'domain', value: 'example.com' }, c.emit, deps([ipsModule(12), ipProbe])).done;
    const ips = c.entities().filter((e) => e.kind === 'ip');
    expect(ips).toHaveLength(10);
    expect(ips.every((e) => e.depth === 1)).toBe(true);
    // depth-1 pivots (9.9.9.9 from an IP) are not expanded
    expect(ips.some((e) => e.value === '9.9.9.9')).toBe(false);
    expect(ips.some((e) => e.value === '10.0.0.1')).toBe(false);
    const capped = c.events.filter((e) => e.type === 'pivot-capped').at(-1) as Extract<RunEvent, { type: 'pivot-capped' }>;
    expect(capped.dropped).toEqual(['8.8.10.1', '8.8.11.1']);
    const pivots = c.events.filter((e): e is Extract<RunEvent, { type: 'pivot' }> => e.type === 'pivot');
    expect(pivots.some((p) => p.pivot.kind === 'hash' && p.pivot.note === 'mmh3')).toBe(true);
    expect(c.last('probe|ip:8.8.0.1')!.status).toBe('ok');
  });

  it('a failing module renders an error card and never breaks the run', async () => {
    const boom: Module = {
      id: 'boom',
      label: 'Boom',
      version: 1,
      accepts: ['domain'],
      ttl: DAY,
      run: () => Promise.reject(new FetchError('http', 'HTTP 500', 'https://x', 500)),
    };
    const c = collector();
    const d = deps([boom, dummyModule as Module]);
    await investigate({ kind: 'domain', value: 'example.com' }, c.emit, d).done;
    expect(c.last('boom|domain:example.com')).toMatchObject({ status: 'error', error: { kind: 'http', status: 500 } });
    expect(c.last('dummy|domain:example.com')!.status).toBe('ok');
    // The error is cached briefly (<= 2 min) and replayed without re-running.
    const hit = await d.cache.lookup(boom, { kind: 'domain', value: 'example.com' });
    expect(hit?.entry.ttl).toBeLessThanOrEqual(120_000);
  });

  it('skips keyed modules without a key, and runs them when a key exists', async () => {
    const keyed: Module = { ...ipProbe, id: 'vt', key: 'virustotal', accepts: ['domain'] };
    const c = collector();
    await investigate({ kind: 'domain', value: 'example.com' }, c.emit, deps([keyed])).done;
    expect(c.last('vt|domain:example.com')).toMatchObject({ status: 'skipped', skip: { reason: 'no-key' } });
    const c2 = collector();
    await investigate({ kind: 'domain', value: 'example.com' }, c2.emit, deps([keyed], { getKey: async () => 'k' })).done;
    expect(c2.last('vt|domain:example.com')!.status).toBe('ok');
  });

  it('SkipError from a module renders as skipped', async () => {
    const skipper: Module = { ...ipProbe, id: 'sk', accepts: ['domain'], run: () => Promise.reject(new SkipError('disabled by user')) };
    const c = collector();
    await investigate({ kind: 'domain', value: 'example.com' }, c.emit, deps([skipper])).done;
    expect(c.last('sk|domain:example.com')).toMatchObject({ status: 'skipped', skip: { reason: 'module', message: 'disabled by user' } });
  });

  it('gates active modules behind OPSEC and runs them after runActive()', async () => {
    let ran = 0;
    const active: Module = { ...ipProbe, id: 'fav', accepts: ['domain'], active: true, run: async () => ({ data: ++ran }) };
    const c = collector();
    const inv = new Investigation({ kind: 'domain', value: 'example.com' }, deps([active]), c.emit);
    await inv.start();
    expect(c.last('fav|domain:example.com')).toMatchObject({ status: 'skipped', skip: { reason: 'active' } });
    expect(ran).toBe(0);
    await inv.runActive();
    expect(c.last('fav|domain:example.com')!.status).toBe('ok');
    expect(ran).toBe(1);
  });

  it('stale-while-revalidate: renders stale cache immediately, then the fresh result', async () => {
    let t = 1_000_000;
    const cache = memoryCache(() => t);
    let v = 0;
    const m: Module = { ...ipProbe, id: 'swr', accepts: ['domain'], ttl: 1000, run: async () => ({ data: ++v, summary: `v${v}` }) };
    const d = deps([m], { cache, now: () => t });
    await investigate({ kind: 'domain', value: 'example.com' }, () => undefined, d).done;
    t += 5000; // expired
    const c = collector();
    await investigate({ kind: 'domain', value: 'example.com' }, c.emit, d).done;
    const seq = c.cards.get('swr|domain:example.com')!;
    expect(seq.map((x) => x.status)).toEqual(['queued', 'cached', 'ok']);
    expect(seq[1]).toMatchObject({ stale: true, revalidating: true, data: 1 });
    expect(seq[2]).toMatchObject({ data: 2, summary: 'v2' });
  });

  it('keeps stale data on screen when revalidation fails', async () => {
    let t = 1_000_000;
    const cache = memoryCache(() => t);
    let fail = false;
    const m: Module = {
      ...ipProbe,
      id: 'flaky',
      accepts: ['domain'],
      ttl: 1000,
      run: async () => {
        if (fail) throw new FetchError('timeout', 'Timed out', 'https://x');
        return { data: 'good' };
      },
    };
    const d = deps([m], { cache, now: () => t });
    await investigate({ kind: 'domain', value: 'example.com' }, () => undefined, d).done;
    t += 5000;
    fail = true;
    const c = collector();
    await investigate({ kind: 'domain', value: 'example.com' }, c.emit, d).done;
    expect(c.last('flaky|domain:example.com')).toMatchObject({ status: 'error', data: 'good', stale: true });
    // stale data is still in the cache (not replaced by the error)
    expect((await cache.lookup(m, { kind: 'domain', value: 'example.com' }))?.entry.data).toBe('good');
  });

  it('force refresh bypasses the cache; refresh() re-runs one card', async () => {
    let v = 0;
    const m: Module = { ...ipProbe, id: 'f', accepts: ['domain'], run: async () => ({ data: ++v }) };
    const d = deps([m]);
    await investigate({ kind: 'domain', value: 'example.com' }, () => undefined, d).done;
    const c = collector();
    await investigate({ kind: 'domain', value: 'example.com' }, c.emit, { ...d, force: true }).done;
    expect(c.last('f|domain:example.com')).toMatchObject({ status: 'ok', data: 2 });
    const c2 = collector();
    const inv = new Investigation({ kind: 'domain', value: 'example.com' }, d, c2.emit);
    await inv.start();
    expect(c2.last('f|domain:example.com')).toMatchObject({ status: 'cached', data: 2 });
    await inv.refresh('f', { kind: 'domain', value: 'example.com' });
    expect(c2.last('f|domain:example.com')).toMatchObject({ status: 'ok', data: 3 });
  });

  it('cancel() aborts in-flight modules without caching the cancellation', async () => {
    const slow: Module = {
      ...ipProbe,
      id: 'slow',
      accepts: ['domain'],
      run: (_e, ctx) =>
        new Promise((_, reject) => ctx.signal.addEventListener('abort', () => reject(new FetchError('aborted', 'Cancelled', 'x')))),
    };
    const d = deps([slow]);
    const c = collector();
    const { investigation, done } = investigate({ kind: 'domain', value: 'example.com' }, c.emit, d);
    await new Promise((r) => setTimeout(r, 5));
    investigation.cancel();
    await done;
    expect(c.last('slow|domain:example.com')).toMatchObject({ status: 'error', error: { kind: 'aborted' } });
    expect(c.events.at(-1)).toEqual({ type: 'done', cancelled: true });
    expect(await d.cache.lookup(slow, { kind: 'domain', value: 'example.com' })).toBeUndefined();
  });

  it('respects module enable toggles', async () => {
    const c = collector();
    await investigate({ kind: 'domain', value: 'example.com' }, c.emit, deps([dummyModule as Module], { isEnabled: () => false })).done;
    expect(c.cards.size).toBe(0);
  });

  it('shares a per-run memo between modules', async () => {
    let fetches = 0;
    const mk = (id: string): Module => ({
      ...ipProbe,
      id,
      accepts: ['domain'],
      run: async (_e, ctx) => ({ data: await ctx.shared.memo('homepage', async () => ++fetches) }),
    });
    await investigate({ kind: 'domain', value: 'example.com' }, () => undefined, deps([mk('a'), mk('b')])).done;
    expect(fetches).toBe(1);
  });

  it('uses the documented cache key format', () => {
    expect(cacheKey(dummyModule, { kind: 'domain', value: 'example.com' })).toBe('dummy@1:domain:example.com');
  });
});

describe('orchestrator: pivot priority, key provenance, hints', () => {
  it('DNS (primaryPivots) IPs win the 10-IP cap even when a slower-to-start module finishes first', async () => {
    const historical: Module = {
      id: 'vt',
      label: 'VT',
      version: 1,
      accepts: ['domain'],
      ttl: DAY,
      run: async () => ({ data: {}, pivots: Array.from({ length: 12 }, (_, i) => ({ kind: 'ip' as const, value: `9.9.${i}.9` })) }),
    };
    const dns: Module = {
      id: 'dns',
      label: 'DNS',
      version: 1,
      accepts: ['domain'],
      ttl: DAY,
      primaryPivots: true,
      run: () => new Promise((r) => setTimeout(() => r({ data: {}, pivots: [{ kind: 'ip', value: '1.1.1.1' }, { kind: 'ip', value: '1.0.0.1' }] }), 20)),
    };
    const c = collector();
    await investigate({ kind: 'domain', value: 'example.com' }, c.emit, deps([historical, dns])).done;
    const ips = c.entities().filter((e) => e.kind === 'ip').map((e) => e.value);
    expect(ips).toHaveLength(10);
    expect(ips.slice(0, 2)).toEqual(['1.1.1.1', '1.0.0.1']);
  });

  it('keyOptional: a keyless cached result is revalidated once a key exists', async () => {
    let runs = 0;
    const m: Module = { ...ipProbe, id: 'sh', accepts: ['domain'], key: 'shodan', keyOptional: true, run: async () => ({ data: ++runs }) };
    const cache = memoryCache();
    await investigate({ kind: 'domain', value: 'example.com' }, () => undefined, deps([m], { cache })).done;
    const c = collector();
    await investigate({ kind: 'domain', value: 'example.com' }, c.emit, deps([m], { cache, getKey: async () => 'k' })).done;
    const seq = c.cards.get('sh|domain:example.com')!;
    expect(seq.map((x) => x.status)).toEqual(['queued', 'cached', 'ok']);
    expect(seq[1]).toMatchObject({ stale: true, revalidating: true });
    expect(runs).toBe(2);
  });

  it('a short per-result TTL makes the next run revalidate', async () => {
    let t = 1_000_000;
    let v = 0;
    const m: Module = { ...ipProbe, id: 'p', accepts: ['domain'], run: async () => ({ data: ++v, ttl: 1000 }) };
    const d = deps([m], { cache: memoryCache(() => t), now: () => t });
    await investigate({ kind: 'domain', value: 'example.com' }, () => undefined, d).done;
    t += 2000;
    const c = collector();
    await investigate({ kind: 'domain', value: 'example.com' }, c.emit, d).done;
    expect(c.last('p|domain:example.com')).toMatchObject({ status: 'ok', data: 2 });
  });

  it('no-key hints use the provider display name', async () => {
    const keyed: Module = { ...ipProbe, id: 'uh', key: 'abusech', accepts: ['domain'] };
    const c = collector();
    await investigate({ kind: 'domain', value: 'example.com' }, c.emit, deps([keyed])).done;
    expect(c.last('uh|domain:example.com')!.skip!.message).toBe('Add your abuse.ch Auth-Key in settings to enable this check.');
  });

  it('keyOptional: a cached keyless error is not replayed once a key exists', async () => {
    let runs = 0;
    let fail = true;
    const m: Module = {
      ...ipProbe,
      id: 'sh',
      accepts: ['domain'],
      key: 'shodan',
      keyOptional: true,
      run: async () => {
        runs++;
        if (fail) throw new FetchError('http', 'HTTP 429', 'https://x', 429);
        return { data: runs };
      },
    };
    const cache = memoryCache();
    await investigate(ROOT, () => undefined, deps([m], { cache })).done;
    const c0 = collector();
    await investigate(ROOT, c0.emit, deps([m], { cache })).done;
    expect(runs).toBe(1); // still keyless: the error is replayed for <= 2 min
    expect(c0.last('sh|domain:example.com')).toMatchObject({ status: 'error', error: { status: 429 } });
    fail = false;
    const c = collector();
    await investigate(ROOT, c.emit, deps([m], { cache, getKey: async () => 'k' })).done;
    expect(runs).toBe(2);
    expect(c.last('sh|domain:example.com')).toMatchObject({ status: 'ok', data: 2 });
  });

  it('does not cache auth failures of keyed modules (the user may be fixing the key right now)', async () => {
    let status = 401;
    const m: Module = { ...ipProbe, id: 'vt', accepts: ['domain'], key: 'virustotal', run: () => Promise.reject(new FetchError('http', `HTTP ${status}`, 'https://x', status)) };
    const d = deps([m], { getKey: async () => 'bad' });
    await investigate(ROOT, () => undefined, d).done;
    expect(await d.cache.lookup(m, ROOT)).toBeUndefined();
    status = 500;
    await investigate(ROOT, () => undefined, d).done;
    expect((await d.cache.lookup(m, ROOT))?.entry.error?.status).toBe(500);
  });
});

describe('orchestrator: OPSEC toggle, cancellation and re-runs', () => {
  it('switching to passive stops an in-flight active module (skipped, not cached); passive modules carry on', async () => {
    let activeRuns = 0;
    const active: Module = {
      ...ipProbe,
      id: 'fav',
      accepts: ['domain'],
      active: true,
      run: (_e, ctx) => {
        activeRuns++;
        return abortable(ctx.signal, 40, () => ({ data: 'icon' }));
      },
    };
    const passive: Module = { ...ipProbe, id: 'pas', accepts: ['domain'], run: (_e, ctx) => abortable(ctx.signal, 20, () => ({ data: 'dns' })) };
    const d = deps([active, passive], { allowActive: true });
    const c = collector();
    const inv = new Investigation(ROOT, d, c.emit);
    const started = inv.start();
    await tick();
    inv.setAllowActive(false);
    await started;
    expect(c.last('fav|domain:example.com')).toMatchObject({ status: 'skipped', skip: { reason: 'active' } });
    expect(c.last('pas|domain:example.com')).toMatchObject({ status: 'ok', data: 'dns' });
    expect(await d.cache.lookup(active, ROOT)).toBeUndefined();
    expect(c.events.at(-1)).toEqual({ type: 'done', cancelled: false });
    // Re-enabling runs it again.
    await inv.runActive();
    expect(activeRuns).toBe(2);
    expect(c.last('fav|domain:example.com')).toMatchObject({ status: 'ok', data: 'icon' });
  });

  it('runActive() does not start a second run of an active module that is already live', async () => {
    let runs = 0;
    const active: Module = {
      ...ipProbe,
      id: 'fav',
      accepts: ['domain'],
      active: true,
      run: (_e, ctx) => {
        runs++;
        return abortable(ctx.signal, 20, () => ({ data: runs }));
      },
    };
    const inv = new Investigation(ROOT, deps([active], { allowActive: true }), () => undefined);
    const started = inv.start();
    await tick();
    await inv.runActive();
    await started;
    expect(runs).toBe(1);
  });

  it('after Cancel, a module error that wraps the abort is reported as cancelled and not cached', async () => {
    const wrapper: Module = {
      ...ipProbe,
      id: 'wrap',
      accepts: ['domain'],
      run: (_e, ctx) => new Promise((_, reject) => ctx.signal.addEventListener('abort', () => reject(new Error('lookup failed: Cancelled')))),
    };
    const d = deps([wrapper]);
    const c = collector();
    const { investigation, done } = investigate(ROOT, c.emit, d);
    await tick();
    investigation.cancel();
    await done;
    expect(c.last('wrap|domain:example.com')).toMatchObject({ status: 'error', error: { kind: 'aborted' } });
    expect(await d.cache.lookup(wrapper, ROOT)).toBeUndefined();
  });

  it('a result that only arrives after Cancel is shown but not cached (it may be partial)', async () => {
    const deaf: Module = { ...ipProbe, id: 'deaf', accepts: ['domain'], run: () => new Promise((r) => setTimeout(() => r({ data: 'partial' }), 20)) };
    const d = deps([deaf]);
    const c = collector();
    const { investigation, done } = investigate(ROOT, c.emit, d);
    await tick();
    investigation.cancel();
    await done;
    expect(c.last('deaf|domain:example.com')).toMatchObject({ status: 'ok', data: 'partial' });
    expect(await d.cache.lookup(deaf, ROOT)).toBeUndefined();
  });

  it('pivots that arrive after Cancel are listed but start no new entity', async () => {
    const dns: Module = {
      ...ipProbe,
      id: 'dns',
      accepts: ['domain'],
      primaryPivots: true,
      run: () => new Promise((r) => setTimeout(() => r({ data: {}, pivots: [{ kind: 'ip', value: '1.1.1.1' }] }), 20)),
    };
    const c = collector();
    const { investigation, done } = investigate(ROOT, c.emit, deps([dns, ipProbe]));
    await tick();
    investigation.cancel();
    await done;
    expect(c.entities().filter((e) => e.kind === 'ip')).toEqual([]);
    expect(c.events.some((e) => e.type === 'pivot' && e.pivot.value === '1.1.1.1')).toBe(true);
    expect(c.cards.has('probe|ip:1.1.1.1')).toBe(false);
  });

  it('a superseded run neither overwrites the newer card nor caches its error over the newer result', async () => {
    let call = 0;
    let failFirst!: (e: unknown) => void;
    const m: Module = {
      ...ipProbe,
      id: 'f',
      accepts: ['domain'],
      run: () => (++call === 1 ? new Promise((_, reject) => (failFirst = reject)) : Promise.resolve({ data: 'fresh' })),
    };
    const d = deps([m]);
    const c = collector();
    const inv = new Investigation(ROOT, d, c.emit);
    const started = inv.start();
    await tick();
    const refreshed = inv.refresh('f', ROOT);
    await tick();
    failFirst(new FetchError('http', 'HTTP 500', 'https://x', 500));
    await Promise.all([started, refreshed]);
    expect(c.last('f|domain:example.com')).toMatchObject({ status: 'ok', data: 'fresh' });
    expect((await d.cache.lookup(m, ROOT))?.entry).toMatchObject({ data: 'fresh' });
  });

  it('refresh() re-fetches memoised network results but keeps per-run state memos; refetch:false reuses them', async () => {
    let pages = 0;
    let states = 0;
    const m: Module = {
      ...ipProbe,
      id: 'fav',
      accepts: ['domain'],
      run: async (_e, ctx) => {
        const page = await ctx.shared.memo('homepage:example.com', async () => ++pages);
        const gate = await ctx.shared.memo('shodan:host-gate', async () => ({ n: ++states }));
        return { data: { page, gate: gate.n } };
      },
    };
    const c = collector();
    const inv = new Investigation(ROOT, deps([m]), c.emit);
    await inv.start();
    expect(c.last('fav|domain:example.com')!.data).toEqual({ page: 1, gate: 1 });
    await inv.refresh('fav', ROOT);
    expect(c.last('fav|domain:example.com')!.data).toEqual({ page: 2, gate: 1 });
    // The refreshed value replaces the run's memo for later modules.
    expect(await inv.shared.memo('homepage:example.com', async () => 99)).toBe(2);
    await inv.refresh('fav', ROOT, { refetch: false });
    expect(c.last('fav|domain:example.com')!.data).toEqual({ page: 2, gate: 1 });
    expect(pages).toBe(2);
  });

  it('refresh() of an unknown card still ends with a done event (the UI is waiting for it)', async () => {
    const c = collector();
    const inv = new Investigation(ROOT, deps([ipProbe]), c.emit);
    await inv.start();
    c.events.length = 0;
    await inv.refresh('nope', ROOT);
    expect(c.events).toEqual([{ type: 'done', cancelled: false }]);
  });

  it('refresh() after Cancel runs on a fresh signal', async () => {
    let v = 0;
    const m: Module = { ...ipProbe, id: 'f', accepts: ['domain'], run: (_e, ctx) => abortable(ctx.signal, 10, () => ({ data: ++v })) };
    const c = collector();
    const inv = new Investigation(ROOT, deps([m]), c.emit);
    const started = inv.start();
    inv.cancel();
    await started;
    expect(c.last('f|domain:example.com')).toMatchObject({ status: 'error', error: { kind: 'aborted' } });
    await inv.refresh('f', ROOT);
    expect(c.last('f|domain:example.com')).toMatchObject({ status: 'ok', data: 1 });
    expect(c.events.at(-1)).toEqual({ type: 'done', cancelled: false });
  });
});

describe('orchestrator: stale primary pivots', () => {
  function setup(fresh: { ips: string[] } | 'fail') {
    let t = 1_000_000;
    let mode: { ips: string[] } | 'fail' = { ips: ['1.1.1.1'] };
    const dns: Module = {
      ...ipProbe,
      id: 'dns',
      accepts: ['domain'],
      ttl: 1000,
      primaryPivots: true,
      run: async () => {
        if (mode === 'fail') throw new FetchError('timeout', 'Timed out', 'https://x');
        return { data: mode.ips, pivots: mode.ips.map((value) => ({ kind: 'ip' as const, value })) };
      },
    };
    const d = deps([dns, ipProbe], { cache: memoryCache(() => t), now: () => t });
    return {
      d,
      async run() {
        await investigate(ROOT, () => undefined, d).done; // caches 1.1.1.1
        t += 5000;
        mode = fresh;
        const c = collector();
        await investigate(ROOT, c.emit, d).done;
        return c;
      },
    };
  }

  it('waits for the revalidation and expands the current IPs, not the outdated cached ones', async () => {
    const c = await setup({ ips: ['2.2.2.2'] }).run();
    expect(c.entities().filter((e) => e.kind === 'ip').map((e) => e.value)).toEqual(['2.2.2.2']);
  });

  it('falls back to the stale pivots when the revalidation fails (and keeps them on the card)', async () => {
    const c = await setup('fail').run();
    expect(c.entities().filter((e) => e.kind === 'ip').map((e) => e.value)).toEqual(['1.1.1.1']);
    expect(c.last('dns|domain:example.com')).toMatchObject({ status: 'error', stale: true, pivots: [{ kind: 'ip', value: '1.1.1.1' }] });
  });
});

describe('createShared (per-run memo)', () => {
  it('a joiner whose own run is live retries when the originator was cancelled', async () => {
    const shared = createShared();
    const ac = new AbortController();
    const first = shared.memo('homepage:x', () => abortable(ac.signal, 1000, () => 'theirs'));
    const joiner = shared.memo('homepage:x', async () => 'mine');
    ac.abort();
    await expect(first).rejects.toMatchObject({ kind: 'aborted' });
    await expect(joiner).resolves.toBe('mine');
    // ...and the retry is memoised for later callers.
    await expect(shared.memo('homepage:x', async () => 'later')).resolves.toBe('mine');
  });

  it('shares other failures with concurrent joiners, but does not memoise them', async () => {
    const shared = createShared();
    let fail!: (e: unknown) => void;
    const a = shared.memo('k', () => new Promise((_, reject) => (fail = reject)));
    const b = shared.memo('k', async () => 'b');
    fail(new Error('boom'));
    await expect(a).rejects.toThrow('boom');
    await expect(b).rejects.toThrow('boom');
    await expect(shared.memo('k', async () => 'next')).resolves.toBe('next');
  });

  it('turns a synchronous throw into a rejection', async () => {
    const shared = createShared();
    await expect(
      shared.memo('k', () => {
        throw new Error('sync');
      }),
    ).rejects.toThrow('sync');
  });
});
