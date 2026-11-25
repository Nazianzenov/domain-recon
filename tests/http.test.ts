import { describe, expect, it, vi } from 'vitest';
import { FetchError, createHttp, extractErrorMessage, parseRetryAfter, serializeError } from '@/lib/http';
import { RateLimiter } from '@/lib/ratelimit';
import { json, mockFetch, text } from './helpers';

function http(fetchImpl: typeof fetch, signal = new AbortController().signal) {
  return createHttp({ fetch: fetchImpl, limiter: new RateLimiter(), signal });
}

describe('fetch wrappers', () => {
  it('omits credentials, sends no referrer, sets accept', async () => {
    const m = mockFetch(() => json({ ok: true }));
    const res = await http(m.fetch).fetchJson<{ ok: boolean }>('https://api.example/x');
    expect(res.data.ok).toBe(true);
    const init = m.calls[0]!.init;
    expect(init.credentials).toBe('omit');
    expect(init.referrerPolicy).toBe('no-referrer');
    expect((init.headers as Record<string, string>)['accept']).toBe('application/json');
  });

  it('turns non-2xx into typed http errors with the API message', async () => {
    const m = mockFetch(() => json({ error: { code: 'NotFoundError', message: 'Domain not found' } }, 404));
    const err = await http(m.fetch).fetchJson('https://api.example/x').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).kind).toBe('http');
    expect((err as FetchError).status).toBe(404);
    expect((err as FetchError).message).toContain('Domain not found');
  });

  it('okStatuses resolve instead of throwing', async () => {
    const m = mockFetch(() => json({ detail: 'No information available' }, 404));
    const res = await http(m.fetch).fetchJson('https://x/y', { okStatuses: [404] });
    expect(res.status).toBe(404);
  });

  it('typed parse error on invalid JSON (e.g. an HTML error page)', async () => {
    const m = mockFetch(() => text('<html>oops</html>'));
    const err = await http(m.fetch).fetchJson('https://x/y').catch((e: unknown) => e);
    expect((err as FetchError).kind).toBe('parse');
  });

  it('typed network error when fetch rejects', async () => {
    const m = mockFetch(() => {
      throw new TypeError('NetworkError when attempting to fetch resource.');
    });
    const err = await http(m.fetch).fetchJson('https://x/y').catch((e: unknown) => e);
    expect((err as FetchError).kind).toBe('network');
  });

  it('times out after timeoutMs with a typed timeout error', async () => {
    const hanging = ((_: RequestInfo | URL, init?: RequestInit) =>
      new Promise((_, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      })) as typeof fetch;
    const err = await http(hanging).fetchJson('https://x/y', { timeoutMs: 20 }).catch((e: unknown) => e);
    expect((err as FetchError).kind).toBe('timeout');
  });

  it('cancellation yields kind "aborted"', async () => {
    const ac = new AbortController();
    const hanging = ((_: RequestInfo | URL, init?: RequestInit) =>
      new Promise((_, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      })) as typeof fetch;
    const p = http(hanging, ac.signal).fetchJson('https://x/y');
    ac.abort();
    const err = await p.catch((e: unknown) => e);
    expect((err as FetchError).kind).toBe('aborted');
    expect(serializeError(err).kind).toBe('aborted');
  });

  it('retries once after a 429 behind the limiter (Retry-After)', async () => {
    vi.useFakeTimers();
    try {
      let n = 0;
      const m = mockFetch(() => (n++ === 0 ? json({}, 429, { 'retry-after': '2' }) : json({ ok: 1 })));
      const h = createHttp({ fetch: m.fetch, limiter: new RateLimiter(), signal: new AbortController().signal, defaultLimit: { key: 'p', perMinute: 60 } });
      const p = h.fetchJson('https://x/y');
      await vi.advanceTimersByTimeAsync(3_100);
      const res = await p;
      expect(res.status).toBe(200);
      expect(m.calls).toHaveLength(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('fetchBytes enforces maxBytes', async () => {
    const m = mockFetch(() => new Response(new Uint8Array(100)));
    const err = await http(m.fetch).fetchBytes('https://x/y', { maxBytes: 10 }).catch((e: unknown) => e);
    expect((err as FetchError).kind).toBe('parse');
  });

  it('fetchText decodes the declared charset', async () => {
    const latin1 = new Uint8Array([0x63, 0x61, 0x66, 0xe9]); // "café" in ISO-8859-1
    const m = mockFetch(() => new Response(latin1, { headers: { 'content-type': 'text/html; charset=iso-8859-1' } }));
    const res = await http(m.fetch).fetchText('https://x/y');
    expect(res.text).toBe('café');
  });
});

describe('extractErrorMessage', () => {
  it.each([
    ['{"error":{"message":"bad key"}}', 'bad key'],
    ['{"detail":"Authentication required"}', 'Authentication required'],
    ['{"errors":[{"detail":"Invalid IP"}]}', 'Invalid IP'],
    ['{"query_status":"unknown_auth_key"}', 'unknown_auth_key'],
    ['plain text failure', 'plain text failure'],
    ['<html>nope</html>', undefined],
  ])('%s', (body, expected) => {
    expect(extractErrorMessage(body)).toBe(expected);
  });
});

describe('fetch wrapper hardening', () => {
  it('fails fast on a daily-quota 429 (Retry-After beyond the auto-retry cap)', async () => {
    const m = mockFetch(() => json({ errors: [{ detail: 'Daily rate limit of 1000 requests exceeded' }] }, 429, { 'retry-after': '36000' }));
    const h = createHttp({ fetch: m.fetch, limiter: new RateLimiter(), signal: new AbortController().signal, defaultLimit: { key: 'p', perMinute: 60 } });
    const err = await h.fetchJson('https://x/y').catch((e: unknown) => e);
    expect((err as FetchError).status).toBe(429);
    expect((err as FetchError).message).toContain('Daily rate limit');
    expect(m.calls).toHaveLength(1);
  });

  it('refuses redirects when a secret header is sent, follows them otherwise', async () => {
    const m = mockFetch(() => json({}));
    const h = http(m.fetch);
    await h.fetchJson('https://x/a', { headers: { 'x-apikey': 'secret' } });
    await h.fetchJson('https://x/b', { headers: { 'Auth-Key': 'secret' } });
    await h.fetchJson('https://x/c');
    expect(m.calls.map((c) => c.init.redirect)).toEqual(['error', 'error', 'follow']);
  });

  it('caps JSON bodies', async () => {
    const m = mockFetch(() => new Response(JSON.stringify({ big: 'x'.repeat(100) })));
    const err = await http(m.fetch).fetchJson('https://x/y', { maxBytes: 50 }).catch((e: unknown) => e);
    expect((err as FetchError).kind).toBe('parse');
  });

  it('extracts Argus-style messages[0].message', () => {
    expect(extractErrorMessage('{"responseCode":402,"messages":[{"message":"Resource limit exceeded"}]}')).toBe('Resource limit exceeded');
  });

  it('a timeout while reading the body is a timeout, not a network error', async () => {
    const slowBody = ((_: RequestInfo | URL, init?: RequestInit) =>
      Promise.resolve(
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(new TextEncoder().encode('{"partial":'));
              init?.signal?.addEventListener('abort', () => controller.error(init.signal!.reason));
            },
          }),
          { headers: { 'content-type': 'application/json' } },
        ),
      )) as typeof fetch;
    const err = await http(slowBody).fetchJson('https://x/y', { timeoutMs: 20 }).catch((e: unknown) => e);
    expect((err as FetchError).kind).toBe('timeout');
  });

  it('never echoes the API key from an error body (header and query-string keys)', async () => {
    const KEY = 'sk-secret-0123456789';
    const m = mockFetch((u) =>
      json({ error: { message: `Invalid key ${u.searchParams.get('key') ?? KEY} for this endpoint` } }, 401),
    );
    const h = http(m.fetch);
    const e1 = (await h.fetchJson('https://api.example/a', { headers: { 'x-apikey': KEY } }).catch((e: unknown) => e)) as FetchError;
    expect(e1.message).toContain('Invalid key [key]');
    expect(e1.message).not.toContain(KEY);
    expect(e1.body).not.toContain(KEY);
    const e2 = (await h.fetchJson(`https://api.example/b?key=${KEY}`).catch((e: unknown) => e)) as FetchError;
    expect(e2.message).not.toContain(KEY);
    expect(serializeError(e2).message).not.toContain(KEY);
    // Bearer tokens: the bare token is redacted too.
    const e3 = (await h.fetchJson('https://api.example/c', { headers: { Authorization: `Bearer ${KEY}` } }).catch((e: unknown) => e)) as FetchError;
    expect(e3.message).not.toContain(KEY);
  });

  it('does not redact short or non-secret values', async () => {
    const m = mockFetch(() => json({ message: 'limit 100 exceeded for page 2' }, 400));
    const err = (await http(m.fetch).fetchJson('https://api.example/a?page=2&limit=100').catch((e: unknown) => e)) as FetchError;
    expect(err.message).toContain('limit 100 exceeded for page 2');
  });

  it('a caller-supplied Accept (any case) replaces the default instead of joining it', async () => {
    const m = mockFetch(() => json({}));
    await http(m.fetch).fetchJson('https://x/a', { headers: { Accept: 'application/dns-json' } });
    const headers = new Headers(m.calls[0]!.init.headers);
    expect(headers.get('accept')).toBe('application/dns-json');
  });

  it('fetchText honours <meta charset> when the header has none, and a BOM over both', async () => {
    const cp1251 = new Uint8Array([
      ...new TextEncoder().encode('<html><head><meta charset="windows-1251"><title>'),
      0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2, // "Привет"
      ...new TextEncoder().encode('</title>'),
    ]);
    const m1 = mockFetch(() => new Response(cp1251, { headers: { 'content-type': 'text/html' } }));
    expect((await http(m1.fetch).fetchText('https://x/')).text).toContain('<title>Привет</title>');

    const httpEquiv = new Uint8Array([
      ...new TextEncoder().encode('<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">caf'),
      0xe9,
    ]);
    const m2 = mockFetch(() => new Response(httpEquiv, { headers: { 'content-type': 'text/html' } }));
    expect((await http(m2.fetch).fetchText('https://x/')).text).toMatch(/café$/);

    const bom = new Uint8Array([0xef, 0xbb, 0xbf, ...new TextEncoder().encode('<meta charset="windows-1251">é')]);
    const m3 = mockFetch(() => new Response(bom, { headers: { 'content-type': 'text/html; charset=iso-8859-1' } }));
    expect((await http(m3.fetch).fetchText('https://x/')).text).toMatch(/é$/);

    // The header still wins over <meta>.
    const m4 = mockFetch(() => new Response(httpEquiv, { headers: { 'content-type': 'text/html; charset=utf-8' } }));
    expect((await http(m4.fetch).fetchText('https://x/')).text).toMatch(/caf�$/);
  });

  it('parseRetryAfter: seconds, HTTP-date (past = now) and junk', () => {
    expect(parseRetryAfter('2', 0)).toBe(2000);
    expect(parseRetryAfter('Wed, 25 Nov 2026 12:01:00 GMT', Date.parse('Wed, 25 Nov 2026 12:00:00 GMT'))).toBe(60_000);
    expect(parseRetryAfter('Wed, 25 Nov 2026 11:00:00 GMT', Date.parse('Wed, 25 Nov 2026 12:00:00 GMT'))).toBe(0);
    expect(parseRetryAfter(null, 0)).toBeUndefined();
    expect(parseRetryAfter('soon', 0)).toBeUndefined();
  });
});
