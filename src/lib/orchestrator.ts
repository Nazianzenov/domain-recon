import type { CacheHit, ResultCache } from './cache';
import { createHttp, isAbortError, serializeError } from './http';
import { isPublicIp, normalizeIp } from './ip';
import { PROVIDER_KEY_NAMES } from './providers';
import type { RateLimiter } from './ratelimit';
import type {
  CardState,
  Ctx,
  Entity,
  Module,
  ModuleOutput,
  Pivot,
  ProviderKey,
  RunEvent,
  RunShared,
  SerializedError,
  Settings,
} from './types';
import { SkipError } from './types';

export const MAX_IPS_PER_DOMAIN = 10;
/** Pivot one hop only: domain (depth 0) -> its IPs (depth 1). */
export const MAX_DEPTH = 1;

/**
 * Memo keys holding network results (DoH answers in doh.ts, homepage and
 * favicon bytes in homepage.ts). A per-card refresh recomputes these; other
 * memos are per-run state (Shodan pacing gate, AbuseIPDB quota hold, RDAP
 * bootstrap) and stay shared.
 */
export const REFETCH_ON_REFRESH = /^(?:doh|homepage|favicons):/;

export function entityKey(e: Pick<Entity, 'kind' | 'value'>): string {
  return `${e.kind}:${e.value}`;
}

export function cardId(moduleId: string, e: Pick<Entity, 'kind' | 'value'>): string {
  return `${moduleId}|${entityKey(e)}`;
}

export interface SharedScope extends RunShared {
  /**
   * A scope for one re-run: keys matching `fresh` are recomputed once in it
   * (and, on success, replace the parent's value); every other key is shared.
   */
  fork(fresh: (key: string) => boolean): RunShared;
}

function memoIn<T>(map: Map<string, Promise<unknown>>, key: string, fn: () => Promise<T>): Promise<T> {
  const existing = map.get(key) as Promise<T> | undefined;
  if (existing) {
    // If the run that started this entry was cancelled (or stopped by the OPSEC
    // toggle), a caller whose own run is still live retries with its own fn
    // instead of inheriting someone else's "Cancelled".
    return existing.catch((err: unknown) => {
      if (isAbortError(err)) return memoIn(map, key, fn);
      throw err;
    });
  }
  let p: Promise<T>;
  try {
    p = fn();
  } catch (err) {
    return Promise.reject(err instanceof Error ? err : new Error(String(err)));
  }
  map.set(key, p);
  // Failures are not memoised: the next caller retries. (Registered before any
  // joiner's handler, so the entry is gone by the time a joiner retries.)
  p.catch(() => {
    if (map.get(key) === p) map.delete(key);
  });
  return p;
}

export function createShared(): SharedScope {
  const map = new Map<string, Promise<unknown>>();
  return {
    memo: <T>(key: string, fn: () => Promise<T>) => memoIn(map, key, fn),
    fork(fresh) {
      const own = new Map<string, Promise<unknown>>();
      return {
        memo<T>(key: string, fn: () => Promise<T>): Promise<T> {
          if (!fresh(key)) return memoIn(map, key, fn);
          const first = !own.has(key);
          const p = memoIn(own, key, fn);
          if (first) {
            // Later runs of this investigation see the refreshed value.
            p.then(
              () => {
                if (own.get(key) === p) map.set(key, p);
              },
              () => undefined,
            );
          }
          return p;
        },
      };
    },
  };
}

export interface OrchestratorDeps {
  /** Full registry; filtered with isEnabled + accepts. */
  modules: readonly Module[];
  isEnabled(m: Module): boolean;
  /** OPSEC: may active modules contact the target? */
  allowActive: boolean;
  /** Bypass the cache (global force refresh). */
  force?: boolean;
  cache: ResultCache;
  limiter: RateLimiter;
  settings: Settings;
  getKey(p: ProviderKey): Promise<string | undefined>;
  fetch?: typeof fetch;
  now?: () => number;
  maxIpsPerDomain?: number;
}

type Emit = (e: RunEvent) => void;

const CANCELLED: SerializedError = { kind: 'aborted', message: 'Cancelled' };
const ACTIVE_SKIP = { reason: 'active', message: 'Active check: contacts the target directly. Use "Run active checks".' } as const;

/** Auth failures depend on the key the user may be fixing right now: never replay them from the cache. */
function isAuthFailure(m: Module, error: SerializedError): boolean {
  return !!m.key && error.kind === 'http' && (error.status === 401 || error.status === 403);
}

/**
 * One investigation: BFS from a root domain over de-duplicated entities.
 * All matching modules for an entity run concurrently; every result streams
 * to `emit` as soon as it settles. A failing module yields an error card and
 * never breaks the run.
 */
export class Investigation {
  readonly root: Entity;
  readonly shared: SharedScope = createShared();
  private controller = new AbortController();
  /** Aborted when the user switches back to passive: stops active modules mid-flight. */
  private activeController = new AbortController();
  private seen = new Set<string>();
  private entities = new Map<string, Entity>();
  private ipCount = new Map<string, number>();
  private dropped = new Map<string, string[]>();
  private tasks = new Set<Promise<void>>();
  /** Per entity: settles when its primaryPivots modules (DNS) have finished. */
  private primaryDone = new Map<string, Promise<unknown>>();
  /** Per card: generation of the latest run. An older run that is still in flight no longer emits. */
  private generation = new Map<string, number>();
  /** Per card: the latest run while it is in flight. */
  private live = new Map<string, { gen: number; signal: AbortSignal }>();
  private now: () => number;

  constructor(
    root: Pick<Entity, 'kind' | 'value'>,
    private deps: OrchestratorDeps,
    private emit: Emit,
  ) {
    this.root = { kind: root.kind, value: root.value, depth: 0 };
    this.now = deps.now ?? (() => Date.now());
  }

  get signal(): AbortSignal {
    return this.controller.signal;
  }

  setAllowActive(v: boolean): void {
    if (!v) {
      // OPSEC: "Passive only" must also stop active modules already contacting
      // the target (favicon fetches several URLs, the AI module calls out).
      this.activeController.abort();
      this.activeController = new AbortController();
    }
    this.deps = { ...this.deps, allowActive: v };
  }

  cancel(): void {
    this.controller.abort();
  }

  /** Run the whole investigation; resolves when every task (including pivots) settled. */
  async start(): Promise<void> {
    this.visit(this.root);
    await this.idle();
  }

  /** Wait until no task is in flight (tasks may spawn more tasks), then emit `done`. */
  async idle(): Promise<void> {
    while (this.tasks.size > 0) {
      await Promise.allSettled([...this.tasks]);
    }
    this.emit({ type: 'done', cancelled: this.controller.signal.aborted });
  }

  /**
   * Per-card refresh: bypass the cache for one module/entity. By default the
   * run's memoised network results (DoH answers, homepage, favicon) are
   * fetched again too; `refetch: false` reuses them (e.g. the AI check after
   * consent should analyse the homepage the favicon check already fetched).
   * Always ends with a `done` event, even when there is nothing to run.
   */
  async refresh(moduleId: string, entity: Pick<Entity, 'kind' | 'value'>, opts: { refetch?: boolean } = {}): Promise<void> {
    const m = this.deps.modules.find((x) => x.id === moduleId);
    const e = this.entities.get(entityKey(entity));
    if (m && e) {
      this.renew();
      const shared = opts.refetch === false ? this.shared : this.shared.fork((k) => REFETCH_ON_REFRESH.test(k));
      this.track(this.runModule(m, e, true, shared));
    }
    await this.idle();
  }

  /**
   * After the user enabled active checks: run active modules for every known
   * entity (cache still honoured unless `force`).
   */
  async runActive(): Promise<void> {
    this.renew();
    this.deps = { ...this.deps, allowActive: true };
    for (const e of this.entities.values()) {
      for (const m of this.modulesFor(e)) {
        if (!m.active) continue;
        // A live run reads allowActive when it gets to the gate: do not contact the target twice.
        const live = this.live.get(cardId(m.id, e));
        if (live && !live.signal.aborted) continue;
        this.track(this.runModule(m, e, !!this.deps.force));
      }
    }
    await this.idle();
  }

  private renew(): void {
    if (this.controller.signal.aborted) this.controller = new AbortController();
  }

  private modulesFor(e: Entity): Module[] {
    return this.deps.modules.filter((m) => m.accepts.includes(e.kind) && this.deps.isEnabled(m));
  }

  private track(p: Promise<void>): void {
    this.tasks.add(p);
    const done = () => {
      this.tasks.delete(p);
    };
    // then(done, done), not finally(): a rejected task must not become an unhandled rejection.
    p.then(done, done);
  }

  private visit(e: Entity, from?: { moduleId: string; entity: Entity }): void {
    const key = entityKey(e);
    if (this.seen.has(key)) return;
    this.seen.add(key);
    this.entities.set(key, e);
    this.emit({ type: 'entity', entity: e, ...(from ? { from } : {}) });
    const mods = this.modulesFor(e);
    for (const m of mods) {
      this.emit({ type: 'card', card: this.baseCard(m, e, 'queued') });
    }
    const primary: Array<Promise<void>> = [];
    for (const m of mods) {
      const p = this.runModule(m, e, !!this.deps.force);
      if (m.primaryPivots) primary.push(p);
      this.track(p);
    }
    this.primaryDone.set(key, Promise.allSettled(primary));
  }

  private baseCard(m: Module, e: Entity, status: CardState['status']): CardState {
    return { id: cardId(m.id, e), moduleId: m.id, label: m.label, entity: e, status };
  }

  /**
   * Pivots from non-primary modules wait until the entity's primary modules
   * (DNS) have settled, so current IPs claim the per-domain IP cap before
   * historical ones (VirusTotal resolutions). Tracked as a task.
   */
  private queuePivots(parent: Entity, m: Module, pivots: Pivot[] | undefined): void {
    if (!pivots?.length) return;
    const gate = m.primaryPivots ? undefined : this.primaryDone.get(entityKey(parent));
    if (!gate) {
      this.handlePivots(parent, m, pivots);
      return;
    }
    this.track(gate.then(() => this.handlePivots(parent, m, pivots)));
  }

  private handlePivots(parent: Entity, m: Module, pivots: Pivot[]): void {
    const from = { moduleId: m.id, entity: parent };
    for (const p of pivots) {
      if (p.kind === 'ip') {
        const ip = normalizeIp(p.value);
        if (!ip) continue;
        const pivot: Pivot = { ...p, value: ip };
        this.emit({ type: 'pivot', pivot, from });
        // One hop only, and only from the root domain to its IPs.
        if (parent.depth >= MAX_DEPTH || parent.kind !== 'domain') continue;
        if (this.seen.has(entityKey(pivot))) continue;
        if (!isPublicIp(ip)) continue; // private/reserved: listed, not investigated
        // Cancelled: results that still arrive are listed, but start no new entity
        // (it would only show a column of "Cancelled" cards). Not counted against the cap.
        if (this.controller.signal.aborted) continue;
        const max = this.deps.maxIpsPerDomain ?? MAX_IPS_PER_DOMAIN;
        const n = this.ipCount.get(parent.value) ?? 0;
        if (n >= max) {
          const list = this.dropped.get(parent.value) ?? [];
          if (!list.includes(ip)) {
            list.push(ip);
            this.dropped.set(parent.value, list);
            this.emit({ type: 'pivot-capped', domain: parent.value, dropped: [...list] });
          }
          continue;
        }
        this.ipCount.set(parent.value, n + 1);
        this.visit({ kind: 'ip', value: ip, depth: parent.depth + 1 }, from);
      } else {
        // Hashes (and any other kinds) are displayed as pivotable values only.
        this.emit({ type: 'pivot', pivot: p, from });
      }
    }
  }

  private makeCtx(m: Module, signal: AbortSignal, shared: RunShared): Ctx {
    const http = createHttp({
      fetch: this.deps.fetch ?? globalThis.fetch.bind(globalThis),
      limiter: this.deps.limiter,
      signal,
      ...(m.rateLimit
        ? {
            defaultLimit: {
              key: m.key ?? m.id,
              perMinute: m.rateLimit.perMinute,
              ...(m.rateLimit.burst !== undefined ? { burst: m.rateLimit.burst } : {}),
            },
          }
        : {}),
      now: this.now,
    });
    return {
      signal,
      root: this.root,
      ...http,
      getKey: (p) => this.deps.getKey(p),
      settings: this.deps.settings,
      shared,
      rawCache: {
        get: (key, maxAgeMs) => this.deps.cache.getRaw(key, maxAgeMs),
        set: (key, data, ttlMs) => this.deps.cache.setRaw(key, data, ttlMs),
      },
      now: this.now,
    };
  }

  private runModule(m: Module, e: Entity, force: boolean, shared: RunShared = this.shared): Promise<void> {
    const id = cardId(m.id, e);
    const gen = (this.generation.get(id) ?? 0) + 1;
    this.generation.set(id, gen);
    const main = this.controller.signal;
    const active = m.active ? this.activeController.signal : undefined;
    const signal = active ? AbortSignal.any([main, active]) : main;
    this.live.set(id, { gen, signal });
    const current = () => this.generation.get(id) === gen;
    return this.execute(m, e, force, shared, { signal, main, active }, current).finally(() => {
      if (this.live.get(id)?.gen === gen) this.live.delete(id);
    });
  }

  private async execute(
    m: Module,
    e: Entity,
    force: boolean,
    shared: RunShared,
    sig: { signal: AbortSignal; main: AbortSignal; active: AbortSignal | undefined },
    current: () => boolean,
  ): Promise<void> {
    const { signal } = sig;
    const base = this.baseCard(m, e, 'queued');
    // A newer run of the same card (refresh, runActive) owns the card: this one goes quiet.
    const emit = (patch: Partial<CardState>) => {
      if (current()) this.emit({ type: 'card', card: { ...base, ...patch } });
    };
    let stale: CacheHit | undefined;
    let keyed: boolean | undefined;
    /** A stale primary result's pivots wait for its revalidation (fresh IPs, not outdated ones, claim the cap). */
    const releaseStalePivots = () => {
      if (stale && m.primaryPivots) this.queuePivots(e, m, stale.entry.pivots);
    };

    try {
      const hasKey = m.key ? !!(await this.deps.getKey(m.key)) : undefined;
      if (m.key && !m.keyOptional && !hasKey) {
        emit({
          status: 'skipped',
          skip: { reason: 'no-key', message: `Add your ${PROVIDER_KEY_NAMES[m.key]} in settings to enable this check.` },
        });
        return;
      }
      // keyOptional modules: remember whether a key was used, so a keyless
      // result (or error) is refreshed as soon as the user adds a key.
      keyed = m.key && m.keyOptional ? hasKey : undefined;

      if (!force) {
        const hit = await this.deps.cache.lookup(m, e);
        const keyAdded = !!hit && keyed === true && hit.entry.keyed !== true;
        if (hit?.entry.error && !keyAdded) {
          emit({ status: 'error', error: hit.entry.error, fetchedAt: hit.entry.fetchedAt });
          return;
        }
        if (hit && !hit.entry.error) {
          const fresh = hit.fresh && !keyAdded;
          const canRefresh = !m.active || this.deps.allowActive;
          const revalidating = !fresh && canRefresh;
          emit({
            status: 'cached',
            data: hit.entry.data,
            ...(hit.entry.summary !== undefined ? { summary: hit.entry.summary } : {}),
            ...(hit.entry.severity ? { severity: hit.entry.severity } : {}),
            ...(hit.entry.pivots ? { pivots: hit.entry.pivots } : {}),
            fetchedAt: hit.entry.fetchedAt,
            stale: !fresh,
            revalidating,
          });
          if (!revalidating) {
            this.queuePivots(e, m, hit.entry.pivots);
            return;
          }
          stale = hit;
          if (!m.primaryPivots) this.queuePivots(e, m, hit.entry.pivots);
        }
      }

      if (m.active && !this.deps.allowActive) {
        emit({ status: 'skipped', skip: ACTIVE_SKIP });
        return;
      }

      if (signal.aborted) throw new DOMException('Aborted', 'AbortError');
      if (!stale) emit({ status: 'running' });

      let out: ModuleOutput;
      try {
        out = await m.run(e, this.makeCtx(m, signal, shared));
      } catch (err) {
        if (err instanceof SkipError) {
          emit({ status: 'skipped', skip: { reason: err.reason, message: err.message } });
          releaseStalePivots();
          return;
        }
        throw err;
      }
      // A result that arrives after cancellation may be partial (sub-requests
      // aborted and swallowed by the module): show it, but do not cache it.
      const fetchedAt = signal.aborted ? this.now() : (await this.deps.cache.storeResult(m, e, out, keyed)).fetchedAt;
      emit({
        status: 'ok',
        data: out.data,
        ...(out.summary !== undefined ? { summary: out.summary } : {}),
        ...(out.severity ? { severity: out.severity } : {}),
        ...(out.pivots ? { pivots: out.pivots } : {}),
        fetchedAt,
      });
      this.queuePivots(e, m, out.pivots);
    } catch (err) {
      releaseStalePivots();
      if (sig.active?.aborted && !sig.main.aborted) {
        // Stopped by the switch to "Passive only": not an error, never cached.
        if (stale) {
          const s = stale.entry;
          emit({
            status: 'cached',
            data: s.data,
            ...(s.summary !== undefined ? { summary: s.summary } : {}),
            ...(s.severity ? { severity: s.severity } : {}),
            ...(s.pivots ? { pivots: s.pivots } : {}),
            fetchedAt: s.fetchedAt,
            stale: true,
            revalidating: false,
          });
        } else {
          emit({ status: 'skipped', skip: ACTIVE_SKIP });
        }
        return;
      }
      // After Cancel, whatever a module throws (it may wrap the AbortError) is a cancellation.
      const cancelled = signal.aborted || isAbortError(err);
      const error = cancelled ? CANCELLED : serializeError(err);
      if (stale) {
        // Revalidation failed: keep showing the stale data (and keep it cached).
        const s = stale.entry;
        emit({
          status: 'error',
          error,
          data: s.data,
          ...(s.summary !== undefined ? { summary: s.summary } : {}),
          ...(s.severity ? { severity: s.severity } : {}),
          ...(s.pivots ? { pivots: s.pivots } : {}),
          fetchedAt: s.fetchedAt,
          stale: true,
        });
        return;
      }
      // A superseded run must not overwrite the newer run's cached result with its error.
      if (!cancelled && current() && !isAuthFailure(m, error)) await this.deps.cache.storeError(m, e, error, keyed);
      emit({ status: 'error', error });
    }
  }
}

/** Spec entry point: investigate(root, emit). */
export function investigate(
  root: Pick<Entity, 'kind' | 'value'>,
  emit: Emit,
  deps: OrchestratorDeps,
): { investigation: Investigation; done: Promise<void> } {
  const investigation = new Investigation(root, deps, emit);
  return { investigation, done: investigation.start() };
}
