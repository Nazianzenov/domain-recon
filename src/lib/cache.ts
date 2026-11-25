import { clear, createStore, del, get, set } from 'idb-keyval';
import type { Entity, Module, ModuleOutput, Pivot, SerializedError, Severity } from './types';
import { MINUTE } from './types';

/** Minimal async KV interface (idb-keyval in the extension, a Map in tests). */
export interface KV {
  get(key: string): Promise<unknown>;
  set(key: string, value: unknown): Promise<void>;
  del(key: string): Promise<void>;
  clear(): Promise<void>;
}

/**
 * Stored value. The spec's `{ data, fetchedAt, ttl }` plus the rest of the
 * module output (pivots/summary/severity) so cached cards render and pivot
 * exactly like fresh ones, and `error` for short-lived error entries.
 */
export interface CacheEntry {
  data?: unknown;
  pivots?: Pivot[];
  summary?: string;
  severity?: Severity;
  error?: SerializedError;
  fetchedAt: number;
  ttl: number;
  /** For keyOptional modules: was an API key configured when this was fetched? */
  keyed?: boolean;
}

export const ERROR_TTL_MAX = 2 * MINUTE;

export function cacheKey(m: Pick<Module, 'id' | 'version'>, e: Pick<Entity, 'kind' | 'value'>): string {
  return `${m.id}@${m.version}:${e.kind}:${e.value}`;
}

export function errorTtl(moduleTtl: number): number {
  return Math.min(moduleTtl, ERROR_TTL_MAX);
}

/** Fresh = younger than its TTL. A fetchedAt in the future (clock moved back) counts as stale. */
export function isFresh(entry: Pick<CacheEntry, 'fetchedAt' | 'ttl'>, now: number): boolean {
  const age = now - entry.fetchedAt;
  return age >= 0 && age < entry.ttl;
}

function isEntry(v: unknown): v is CacheEntry {
  return (
    !!v &&
    typeof v === 'object' &&
    typeof (v as CacheEntry).fetchedAt === 'number' &&
    typeof (v as CacheEntry).ttl === 'number'
  );
}

export interface CacheHit {
  entry: CacheEntry;
  /** false = expired data: render it, then revalidate (stale-while-revalidate). */
  fresh: boolean;
}

export class ResultCache {
  constructor(
    private kv: KV,
    private now: () => number = () => Date.now(),
  ) {}

  /**
   * Returns data entries whether fresh or stale (SWR), but error entries only
   * while fresh: an expired error is never shown, it is simply retried.
   */
  async lookup(m: Pick<Module, 'id' | 'version'>, e: Pick<Entity, 'kind' | 'value'>): Promise<CacheHit | undefined> {
    const key = cacheKey(m, e);
    let v: unknown;
    try {
      v = await this.kv.get(key);
    } catch {
      return undefined; // cache trouble must never break a run
    }
    if (!isEntry(v)) return undefined;
    const fresh = isFresh(v, this.now());
    if (v.error) {
      if (fresh && v.ttl <= ERROR_TTL_MAX) return { entry: v, fresh: true };
      await this.kv.del(key).catch(() => undefined);
      return undefined;
    }
    return { entry: v, fresh };
  }

  async storeResult(
    m: Pick<Module, 'id' | 'version' | 'ttl'>,
    e: Pick<Entity, 'kind' | 'value'>,
    out: ModuleOutput,
    keyed?: boolean,
  ): Promise<CacheEntry> {
    const entry: CacheEntry = {
      data: out.data,
      ...(out.pivots ? { pivots: out.pivots } : {}),
      ...(out.summary !== undefined ? { summary: out.summary } : {}),
      ...(out.severity ? { severity: out.severity } : {}),
      fetchedAt: this.now(),
      // A result may ask for a shorter TTL (partial data), never a longer one.
      ttl: out.ttl !== undefined && out.ttl >= 0 ? Math.min(out.ttl, m.ttl) : m.ttl,
      ...(keyed !== undefined ? { keyed } : {}),
    };
    await this.kv.set(cacheKey(m, e), entry).catch(() => undefined);
    return entry;
  }

  /** Errors are cached for at most 2 minutes, and cancellations never. */
  async storeError(
    m: Pick<Module, 'id' | 'version' | 'ttl'>,
    e: Pick<Entity, 'kind' | 'value'>,
    error: SerializedError,
    keyed?: boolean,
  ): Promise<void> {
    if (error.kind === 'aborted') return;
    const entry: CacheEntry = { error, fetchedAt: this.now(), ttl: errorTtl(m.ttl), ...(keyed !== undefined ? { keyed } : {}) };
    await this.kv.set(cacheKey(m, e), entry).catch(() => undefined);
  }

  async remove(m: Pick<Module, 'id' | 'version'>, e: Pick<Entity, 'kind' | 'value'>): Promise<void> {
    await this.kv.del(cacheKey(m, e)).catch(() => undefined);
  }

  /** Raw access for non-module caches (e.g. the IANA RDAP bootstrap file). */
  async getRaw<T>(key: string, maxAgeMs: number): Promise<T | undefined> {
    try {
      const v = await this.kv.get(key);
      if (isEntry(v) && !v.error && isFresh({ fetchedAt: v.fetchedAt, ttl: Math.min(v.ttl, maxAgeMs) }, this.now())) {
        return v.data as T;
      }
    } catch {
      /* ignore */
    }
    return undefined;
  }

  async setRaw(key: string, data: unknown, ttl: number): Promise<void> {
    await this.kv.set(key, { data, fetchedAt: this.now(), ttl } satisfies CacheEntry).catch(() => undefined);
  }

  clear(): Promise<void> {
    return this.kv.clear();
  }
}

export function memoryKV(): KV & { map: Map<string, unknown> } {
  const map = new Map<string, unknown>();
  return {
    map,
    get: async (k) => structuredClone(map.get(k)),
    set: async (k, v) => {
      map.set(k, structuredClone(v));
    },
    del: async (k) => {
      map.delete(k);
    },
    clear: async () => {
      map.clear();
    },
  };
}

let idbStore: ReturnType<typeof createStore> | undefined;

/** IndexedDB-backed KV via idb-keyval (lazy so tests never touch IndexedDB). */
export function idbKV(): KV {
  idbStore ??= createStore('domain-recon', 'results');
  const store = idbStore;
  return {
    get: (k) => get(k, store),
    set: (k, v) => set(k, v, store),
    del: (k) => del(k, store),
    clear: () => clear(store),
  };
}

/** Process-wide cache instance used by the sidebar and options pages. */
let shared: ResultCache | undefined;
export function getCache(): ResultCache {
  shared ??= new ResultCache(idbKV());
  return shared;
}
