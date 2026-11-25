/**
 * Core contracts. One abstraction: modules that take an entity and emit data
 * plus pivots (new entities). Everything else (orchestrator, cache, UI,
 * export) is generic over this interface.
 */

export type Kind = 'domain' | 'ip' | 'hash';

export interface Entity {
  kind: Kind;
  value: string;
  depth: number;
}

export type Pivot = Omit<Entity, 'depth'> & {
  /** Optional human label, e.g. "Shodan favicon mmh3" or "SendGrid account". */
  note?: string;
};

export type ProviderKey =
  | 'virustotal'
  | 'otx'
  | 'abuseipdb'
  | 'abusech'
  | 'shodan'
  | 'mnemonic'
  | 'anthropic';

/** Reputation-style severity a module can attach so the summary header can show the worst hit. */
export type Severity = 'none' | 'info' | 'low' | 'medium' | 'high';

export interface ModuleOutput<D = unknown> {
  data: D;
  pivots?: Pivot[];
  /** One-line summary shown on the collapsed card. */
  summary?: string;
  /** Extension of the spec's run() return type: lets the header compute "worst reputation hit". */
  severity?: Severity;
  /**
   * Shorter cache TTL for this particular result (e.g. a partial result after a
   * transient sub-request failure). Capped at the module's ttl.
   */
  ttl?: number;
}

/** A displayable fact derived from module data. Rendered as text only. */
export interface Fact {
  label: string;
  value: string | string[];
  /** https link only; the UI refuses anything else. */
  href?: string;
  tone?: 'good' | 'warn' | 'bad';
  /** Marks the value as a pivotable indicator (copy button, defanged in exports). */
  pivot?: boolean;
  /** Bare values for the copy button, parallel to `value` (when the display adds dates/labels). */
  copy?: string[];
}

export interface RequestOpts {
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string | URLSearchParams;
  /** Default 15 000 ms. */
  timeoutMs?: number;
  /**
   * HTTP statuses that should resolve (with the parsed body) rather than throw.
   * Example: 404 from InternetDB means "no data", not an error.
   */
  okStatuses?: number[];
  /**
   * Override the rate limit bucket for this request. Defaults to the module's
   * `rateLimit` keyed by `module.key ?? module.id`. `false` disables limiting.
   */
  rateLimit?: { key: string; perMinute: number; burst?: number } | false;
}

export interface JsonResponse<T> {
  status: number;
  data: T;
  url: string;
  headers: Headers;
}

export interface BytesResponse {
  status: number;
  bytes: Uint8Array;
  contentType: string | null;
  url: string;
}

export interface TextResponse {
  status: number;
  text: string;
  contentType: string | null;
  /** Final URL after redirects. */
  url: string;
}

/** Per-investigation memo shared by all modules (dedupes DoH lookups, homepage fetch, favicon bytes). */
export interface RunShared {
  memo<T>(key: string, fn: () => Promise<T>): Promise<T>;
}

export interface Ctx {
  /** Aborts on Cancel. Already combined into the fetch helpers. */
  signal: AbortSignal;
  /** The root domain entity of this investigation. */
  root: Entity;
  fetchJson<T = unknown>(url: string, opts?: RequestOpts & { maxBytes?: number }): Promise<JsonResponse<T>>;
  fetchBytes(url: string, opts?: RequestOpts & { maxBytes?: number }): Promise<BytesResponse>;
  fetchText(url: string, opts?: RequestOpts & { maxBytes?: number }): Promise<TextResponse>;
  getKey(provider: ProviderKey): Promise<string | undefined>;
  settings: Readonly<Settings>;
  shared: RunShared;
  /** Persistent raw cache for non-module data (e.g. the IANA RDAP bootstrap file, 24 h). */
  rawCache: {
    get<T>(key: string, maxAgeMs: number): Promise<T | undefined>;
    set(key: string, data: unknown, ttlMs: number): Promise<void>;
  };
  /** Injectable clock for tests. */
  now(): number;
}

export interface Module<D = unknown> {
  id: string;
  label: string;
  /** Bump to invalidate this module's cache. */
  version: number;
  accepts: Kind[];
  /** Needs a user API key. Module is skipped (with a hint) when missing, unless `keyOptional`. */
  key?: ProviderKey;
  /** The key improves results but is not required (Mnemonic, Shodan). */
  keyOptional?: boolean;
  /** Cache TTL in ms. */
  ttl: number;
  /** Contacts the target directly (OPSEC-gated). */
  active?: boolean;
  /** Disabled until the user enables it in settings. */
  defaultEnabled?: boolean;
  /** perMinute = refill rate; burst = bucket capacity (default perMinute). */
  rateLimit?: { perMinute: number; burst?: number };
  /**
   * This module's pivots for an entity are expanded before any other module's
   * (DNS: current IPs win the per-domain IP cap over historical resolutions).
   */
  primaryPivots?: boolean;
  /** Short note shown under the card (e.g. Mnemonic's unauthenticated caveat). */
  note?: string;
  run(e: Entity, ctx: Ctx): Promise<ModuleOutput<D>>;
  /** Render-friendly facts for the expanded card and Markdown export. */
  facts?(data: D, e: Entity): Fact[];
  /** Contribution to the summary header (root domain cards only). */
  headline?(data: D, e: Entity): Partial<Headline>;
}

/** Summary-header fields contributed by modules (merged in registry order; lists are unioned). */
export interface Headline {
  domainAgeDays: number;
  registeredOn: string;
  registrar: string;
  /** Name the registration data belongs to (a parent such as weebly.com when investigating a subdomain). */
  registrationFor: string;
  m365: { tenant: boolean; tenantId?: string; namespaceType?: string; region?: string };
  emailProviders: string[];
  brand: {
    brand: string | null;
    confidence: number;
    impersonation: 'low' | 'medium' | 'high';
    expectedDomain: string | null;
    evidence: string[];
  };
  /** Signals from the fetched homepage (active checks). */
  page: {
    finalHost: string | null;
    hasPasswordInput: boolean;
    /** Hosts that password-bearing forms submit to, other than the investigated name or the host of the page actually served (after redirects). */
    offsiteFormHosts: string[];
  };
}

/**
 * Thrown by a module to mark itself skipped (renders grey, never cached as
 * error). reason 'consent' = needs the user's optional data-collection consent.
 */
export class SkipError extends Error {
  constructor(
    message: string,
    public readonly reason: 'module' | 'consent' = 'module',
  ) {
    super(message);
    this.name = 'SkipError';
  }
}

export interface Settings {
  keys: Partial<Record<ProviderKey, string>>;
  /** Module enable overrides keyed by module id; missing = module.defaultEnabled ?? true. */
  modules: Record<string, boolean>;
  claudeModel: string;
}

export type CardStatus = 'queued' | 'running' | 'ok' | 'cached' | 'error' | 'skipped';

export interface SerializedError {
  kind: 'http' | 'timeout' | 'network' | 'parse' | 'aborted' | 'module';
  message: string;
  status?: number;
}

export interface CardState {
  /** `${moduleId}|${kind}:${value}` */
  id: string;
  moduleId: string;
  label: string;
  entity: Entity;
  status: CardStatus;
  data?: unknown;
  summary?: string;
  severity?: Severity;
  pivots?: Pivot[];
  error?: SerializedError;
  /** Why the module was skipped. */
  skip?: { reason: 'no-key' | 'active' | 'module' | 'consent'; message: string };
  /** When data came from cache: when it was fetched. */
  fetchedAt?: number;
  /** Cached data is shown while a background refresh runs. */
  revalidating?: boolean;
  /** Expired cache entry (stale-while-revalidate). */
  stale?: boolean;
}

export type RunEvent =
  | { type: 'entity'; entity: Entity; from?: { moduleId: string; entity: Entity } }
  | { type: 'card'; card: CardState }
  | { type: 'pivot'; pivot: Pivot; from: { moduleId: string; entity: Entity } }
  | { type: 'pivot-capped'; domain: string; dropped: string[] }
  | { type: 'done'; cancelled: boolean };

export const MINUTE = 60_000;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;
