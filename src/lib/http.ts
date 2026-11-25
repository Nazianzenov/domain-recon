import type { BytesResponse, JsonResponse, RequestOpts, SerializedError, TextResponse } from './types';
import { SECRET_HEADERS } from './providers';
import { abortReason, type RateLimiter } from './ratelimit';

export const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_BYTES = 5 * 1024 * 1024;
/** JSON APIs: generous (keyed Mnemonic pages are ~4 MB) but bounded. */
const DEFAULT_JSON_MAX_BYTES = 16 * 1024 * 1024;

export type FetchErrorKind = 'http' | 'timeout' | 'network' | 'parse' | 'aborted';

/** Typed error for every failure mode of the fetch helpers. */
export class FetchError extends Error {
  constructor(
    public readonly kind: FetchErrorKind,
    message: string,
    public readonly url: string,
    public readonly status?: number,
    /** First 2 KB of the response body (http errors only). */
    public readonly body?: string,
  ) {
    super(message);
    this.name = 'FetchError';
  }
}

export function isAbortError(err: unknown): boolean {
  return (
    (err instanceof FetchError && err.kind === 'aborted') ||
    (err instanceof Error && err.name === 'AbortError')
  );
}

export function serializeError(err: unknown): SerializedError {
  if (err instanceof FetchError) {
    return {
      kind: err.kind,
      message: err.message,
      ...(err.status !== undefined ? { status: err.status } : {}),
    };
  }
  if (isAbortError(err)) return { kind: 'aborted', message: 'Cancelled' };
  if (err instanceof Error) return { kind: 'module', message: err.message || err.name };
  return { kind: 'module', message: String(err) };
}

/** Pull a human message out of common API error bodies. */
export function extractErrorMessage(body: string): string | undefined {
  try {
    const j: unknown = JSON.parse(body);
    if (j && typeof j === 'object') {
      const o = j as Record<string, unknown>;
      const err = o['error'];
      if (err && typeof err === 'object') {
        const m = (err as Record<string, unknown>)['message'];
        if (typeof m === 'string') return m;
      }
      for (const k of ['message', 'detail', 'error_description', 'error', 'query_status']) {
        const v = o[k];
        if (typeof v === 'string' && v) return v;
      }
      const errors = o['errors'];
      if (Array.isArray(errors) && errors[0] && typeof errors[0] === 'object') {
        const d = (errors[0] as Record<string, unknown>)['detail'];
        if (typeof d === 'string') return d;
      }
      // Argus/Mnemonic envelope: { messages: [{ message }] }
      const messages = o['messages'];
      if (Array.isArray(messages) && messages[0] && typeof messages[0] === 'object') {
        const m = (messages[0] as Record<string, unknown>)['message'];
        if (typeof m === 'string' && m) return m;
      }
    }
  } catch {
    /* not JSON */
  }
  const text = body.trim().slice(0, 200);
  return text && !text.startsWith('<') ? text : undefined;
}

export function parseRetryAfter(h: string | null, now: number): number | undefined {
  if (!h) return undefined;
  const secs = Number(h);
  if (Number.isFinite(secs)) return Math.max(0, secs * 1000);
  const date = Date.parse(h);
  return Number.isFinite(date) ? Math.max(0, date - now) : undefined;
}

/** Query parameters that carry credentials (Shodan `?key=`). */
const SECRET_PARAM_RE = /^(?:key|api[-_]?key|apikey|token|access[-_]?token|auth|secret|password)$/i;

/** Credential values sent with a request: secret headers and secret query parameters. */
function secretsOf(url: string, headers: Record<string, string>): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(headers)) {
    if (!SECRET_HEADERS.has(k.toLowerCase())) continue;
    out.push(v);
    const scheme = /^\s*(?:bearer|basic|token)\s+(\S+)/i.exec(v);
    if (scheme) out.push(scheme[1]!);
  }
  try {
    for (const [k, v] of new URL(url).searchParams) if (SECRET_PARAM_RE.test(k)) out.push(v);
  } catch {
    /* relative/invalid URL: fetch will fail anyway */
  }
  const all = new Set<string>();
  for (const s of out) {
    const t = s.trim();
    if (t.length < 4) continue; // never blank out short common substrings
    all.add(t);
    try {
      all.add(encodeURIComponent(t));
    } catch {
      /* lone surrogate */
    }
  }
  return [...all].sort((a, b) => b.length - a.length);
}

/** APIs sometimes echo the key back ("Invalid key abc…"): never let it reach a message or stored body. */
function redact(text: string, secrets: readonly string[]): string {
  let out = text;
  // Same marker the modules' own redaction uses (shodan.ts, virustotal.ts).
  for (const s of secrets) if (out.includes(s)) out = out.split(s).join('[key]');
  return out;
}

async function readCapped(res: Response, maxBytes: number, url: string): Promise<Uint8Array> {
  const len = Number(res.headers.get('content-length'));
  if (Number.isFinite(len) && len > maxBytes) {
    throw new FetchError('parse', `Response too large (${len} bytes)`, url, res.status);
  }
  if (!res.body) return new Uint8Array(await res.arrayBuffer());
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new FetchError('parse', `Response exceeded ${maxBytes} bytes`, url, res.status);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

export function decodeText(bytes: Uint8Array, contentType: string | null): string {
  const charset = /charset\s*=\s*["']?([\w.:-]+)/i.exec(contentType ?? '')?.[1];
  try {
    return new TextDecoder(charset ?? 'utf-8').decode(bytes);
  } catch {
    return new TextDecoder('utf-8').decode(bytes);
  }
}

/**
 * HTML decoding per the WHATWG order (simplified): a BOM wins, then the
 * Content-Type charset, then a <meta charset> / http-equiv in the first
 * 1024 bytes, then UTF-8. Many non-English sites declare their legacy
 * encoding only in <meta>, which decodeText() alone turns into mojibake.
 */
export function decodeHtml(bytes: Uint8Array, contentType: string | null): string {
  const b = bytes;
  if (b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) return new TextDecoder('utf-8').decode(b);
  if (b[0] === 0xfe && b[1] === 0xff) return new TextDecoder('utf-16be').decode(b);
  if (b[0] === 0xff && b[1] === 0xfe) return new TextDecoder('utf-16le').decode(b);
  if (/charset\s*=/i.test(contentType ?? '')) return decodeText(b, contentType);
  let head = '';
  const n = Math.min(b.length, 1024);
  for (let i = 0; i < n; i++) head += String.fromCharCode(b[i]!);
  let label = /<meta\b[^>]*?\bcharset\s*=\s*["']?\s*([\w.:-]+)/i.exec(head)?.[1]?.toLowerCase();
  // A <meta> claiming UTF-16 cannot be right for bytes we just read as ASCII.
  if (label?.startsWith('utf-16')) label = 'utf-8';
  return decodeText(b, label ? `text/html; charset=${label}` : contentType);
}

export interface HttpDeps {
  fetch: typeof fetch;
  limiter: RateLimiter;
  signal: AbortSignal;
  /** Module-level rate limit, used unless a request overrides it. */
  defaultLimit?: { key: string; perMinute: number; burst?: number };
  now?: () => number;
}

/** Longest Retry-After we wait out automatically; longer (daily quotas) fails fast. */
export const MAX_AUTO_RETRY_WAIT_MS = 5 * 60_000;

function carriesSecret(headers: Record<string, string>): boolean {
  return Object.keys(headers).some((h) => SECRET_HEADERS.has(h.toLowerCase()));
}

export interface Http {
  fetchJson<T = unknown>(url: string, opts?: RequestOpts & { maxBytes?: number }): Promise<JsonResponse<T>>;
  fetchBytes(url: string, opts?: RequestOpts & { maxBytes?: number }): Promise<BytesResponse>;
  fetchText(url: string, opts?: RequestOpts & { maxBytes?: number }): Promise<TextResponse>;
}

/**
 * fetch() wrappers: 15 s timeout, credentials omitted, no referrer, rate
 * limited per provider, one automatic retry after a 429, typed errors.
 */
export function createHttp(deps: HttpDeps): Http {
  const now = deps.now ?? (() => Date.now());

  interface Raw {
    res: Response;
    /** This attempt's timeout (it also bounds reading the body). */
    timeout: AbortSignal;
    secrets: string[];
  }

  async function raw(url: string, opts: RequestOpts, accept?: string): Promise<Raw> {
    const limit = opts.rateLimit === false ? undefined : (opts.rateLimit ?? deps.defaultLimit);
    const custom = opts.headers ?? {};
    // Case-insensitive: { Accept } next to the default { accept } would be sent as both values joined.
    const hasAccept = Object.keys(custom).some((k) => k.toLowerCase() === 'accept');
    const headers: Record<string, string> = { ...(accept && !hasAccept ? { accept } : {}), ...custom };
    const secrets = secretsOf(url, headers);
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    for (let attempt = 0; ; attempt++) {
      if (deps.signal.aborted) throw new FetchError('aborted', 'Cancelled', url);
      if (limit) {
        try {
          await deps.limiter.acquire(limit.key, limit.perMinute, deps.signal, limit.burst);
        } catch {
          throw new FetchError('aborted', 'Cancelled', url);
        }
      }
      const timeout = AbortSignal.timeout(timeoutMs);
      const signal = AbortSignal.any([deps.signal, timeout]);
      let res: Response;
      try {
        res = await deps.fetch(url, {
          method: opts.method ?? 'GET',
          headers,
          ...(opts.body !== undefined ? { body: opts.body } : {}),
          credentials: 'omit',
          referrerPolicy: 'no-referrer',
          cache: 'no-store',
          // fetch only strips Authorization on cross-origin redirects; custom key
          // headers (x-apikey, Key, Auth-Key...) would be resent to the target.
          redirect: carriesSecret(headers) ? 'error' : 'follow',
          signal,
        });
      } catch (err) {
        if (deps.signal.aborted) throw new FetchError('aborted', 'Cancelled', url);
        if (timeout.aborted) throw timeoutError(url, timeoutMs);
        const msg = redact(err instanceof Error ? err.message : String(err), secrets);
        throw new FetchError('network', `Network error (offline, blocked, or CORS): ${msg}`, url);
      }
      if (res.status === 429 && limit && attempt === 0) {
        const wait = parseRetryAfter(res.headers.get('retry-after'), now()) ?? 60_000;
        // A daily-quota 429 (Retry-After of hours) is not worth waiting for: fail fast below.
        if (wait <= MAX_AUTO_RETRY_WAIT_MS) {
          deps.limiter.penalize(limit.key, wait);
          await res.body?.cancel().catch(() => undefined);
          continue; // re-queues behind the limiter
        }
      }
      if (!res.ok && !(opts.okStatuses ?? []).includes(res.status)) {
        let body = '';
        try {
          body = redact((await res.text()).slice(0, 2048), secrets);
        } catch {
          /* ignore */
        }
        const detail = extractErrorMessage(body);
        throw new FetchError(
          'http',
          `HTTP ${res.status}${res.statusText ? ` ${res.statusText}` : ''}${detail ? `: ${detail}` : ''}`,
          url,
          res.status,
          body,
        );
      }
      return { res, timeout, secrets };
    }
  }

  function timeoutError(url: string, ms: number): FetchError {
    return new FetchError('timeout', `Timed out after ${ms / 1000}s`, url);
  }

  async function guardBody<T>(url: string, r: Raw, timeoutMs: number, fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (err) {
      if (err instanceof FetchError) throw err;
      if (deps.signal.aborted) throw new FetchError('aborted', 'Cancelled', url);
      // The timeout also covers a slow body: report it as a timeout, not a network failure.
      if (r.timeout.aborted) throw timeoutError(url, timeoutMs);
      const msg = redact(err instanceof Error ? err.message : String(err), r.secrets);
      throw new FetchError('network', `Failed reading response: ${msg}`, url);
    }
  }

  return {
    async fetchJson<T>(url: string, opts: RequestOpts & { maxBytes?: number } = {}): Promise<JsonResponse<T>> {
      const r = await raw(url, opts, 'application/json');
      const { res } = r;
      // Size-capped like the other helpers: a hostile/broken API cannot stream an unbounded body.
      const text = await guardBody(url, r, opts.timeoutMs ?? DEFAULT_TIMEOUT_MS, async () =>
        decodeText(await readCapped(res, opts.maxBytes ?? DEFAULT_JSON_MAX_BYTES, url), res.headers.get('content-type')),
      );
      let data: T;
      if (text.trim() === '') {
        data = null as T;
      } else {
        try {
          data = JSON.parse(text) as T;
        } catch {
          throw new FetchError('parse', `Invalid JSON from ${new URL(url).host}`, url, res.status, redact(text.slice(0, 2048), r.secrets));
        }
      }
      return { status: res.status, data, url: res.url || url, headers: res.headers };
    },

    async fetchBytes(url, opts = {}): Promise<BytesResponse> {
      const r = await raw(url, opts);
      const { res } = r;
      const bytes = await guardBody(url, r, opts.timeoutMs ?? DEFAULT_TIMEOUT_MS, () =>
        readCapped(res, opts.maxBytes ?? DEFAULT_MAX_BYTES, url),
      );
      return { status: res.status, bytes, contentType: res.headers.get('content-type'), url: res.url || url };
    },

    async fetchText(url, opts = {}): Promise<TextResponse> {
      const r = await raw(url, opts, 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8');
      const { res } = r;
      const bytes = await guardBody(url, r, opts.timeoutMs ?? DEFAULT_TIMEOUT_MS, () =>
        readCapped(res, opts.maxBytes ?? DEFAULT_MAX_BYTES, url),
      );
      const contentType = res.headers.get('content-type');
      return { status: res.status, text: decodeHtml(bytes, contentType), contentType, url: res.url || url };
    },
  };
}

export { abortReason };
