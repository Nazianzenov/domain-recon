import { vi } from 'vitest';
import { ResultCache, memoryKV } from '@/lib/cache';
import { createHttp } from '@/lib/http';
import { createShared } from '@/lib/orchestrator';
import { RateLimiter } from '@/lib/ratelimit';
import type { Ctx, Entity, ProviderKey, Settings } from '@/lib/types';
import { DEFAULT_SETTINGS } from '@/lib/settings';

export type Route = (url: URL, init: RequestInit) => Response | Promise<Response> | undefined;

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

export function text(body: string, status = 200, contentType = 'text/html; charset=utf-8'): Response {
  return new Response(body, { status, headers: { 'content-type': contentType } });
}

export function bytes(b: Uint8Array<ArrayBuffer>, status = 200, contentType = 'image/x-icon'): Response {
  return new Response(b, { status, headers: { 'content-type': contentType } });
}

/**
 * A fetch mock that dispatches to routes in order; unmatched requests fail
 * the test loudly (all network access in tests must be mocked).
 */
export function mockFetch(...routes: Route[]) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    calls.push({ url: url.href, init });
    for (const r of routes) {
      const res = await r(url, init);
      if (res) return res;
    }
    throw new Error(`Unmocked fetch: ${init.method ?? 'GET'} ${url.href}`);
  });
  return { fetch: fn as unknown as typeof fetch, calls };
}

export function makeCtx(opts: {
  fetch: typeof fetch;
  root?: string;
  keys?: Partial<Record<ProviderKey, string>>;
  settings?: Partial<Settings>;
  now?: () => number;
  signal?: AbortSignal;
  /** Share a raw cache across ctx instances (e.g. RDAP bootstrap caching tests). */
  cache?: ResultCache;
}): Ctx {
  const signal = opts.signal ?? new AbortController().signal;
  const now = opts.now ?? (() => Date.now());
  const settings: Settings = { ...DEFAULT_SETTINGS, ...opts.settings, keys: { ...opts.keys } };
  const http = createHttp({ fetch: opts.fetch, limiter: new RateLimiter(), signal, now });
  const root: Entity = { kind: 'domain', value: opts.root ?? 'example.com', depth: 0 };
  const cache = opts.cache ?? memoryCache(now);
  return {
    signal,
    root,
    ...http,
    getKey: async (p) => settings.keys[p],
    settings,
    shared: createShared(),
    rawCache: {
      get: (key, maxAgeMs) => cache.getRaw(key, maxAgeMs),
      set: (key, data, ttlMs) => cache.setRaw(key, data, ttlMs),
    },
    now,
  };
}

export function memoryCache(now?: () => number): ResultCache {
  return new ResultCache(memoryKV(), now);
}
