import { describe, expect, it, vi } from 'vitest';
import { FetchError, createHttp, isAbortError } from '@/lib/http';
import { investigate, type OrchestratorDeps } from '@/lib/orchestrator';
import { RateLimiter, type Clock } from '@/lib/ratelimit';
import { DEFAULT_SETTINGS } from '@/lib/settings';
import type { CardState, Entity, Module, RunEvent } from '@/lib/types';
import { HOUR, SkipError } from '@/lib/types';
import {
  MAX_IOCS,
  MAX_URLS,
  THREATFOX_API,
  URLHAUS_API,
  abuseTime,
  abusechKeyTest,
  parseThreatfox,
  parseUrlhaus,
  threatfoxModule,
  threatfoxSummary,
  urlhausModule,
  urlhausSeverity,
  urlhausSummary,
  type ThreatfoxData,
  type UrlhausData,
} from '@/modules/abusech';
import { json, makeCtx, memoryCache, mockFetch, text, type Route } from './helpers';

const KEY = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718';
const NOW = Date.parse('2026-11-25T12:00:00Z');
const domain = (value = 'vektorex.com'): Entity => ({ kind: 'domain', value, depth: 0 });
const ip = (value: string): Entity => ({ kind: 'ip', value, depth: 1 });

const headerOf = (init: RequestInit, name: string) => (init.headers as Record<string, string> | undefined)?.[name];
const formHost = (init: RequestInit) => (init.body instanceof URLSearchParams ? init.body.get('host') : undefined);
const jsonBody = (init: RequestInit): unknown => JSON.parse(String(init.body));

/** Serves `res` for POSTs to `api`; each call may return a different response. */
function postRoute(api: string, ...responses: Array<() => Response>): Route {
  let i = 0;
  return (url, init) => {
    if (url.href !== api || init.method !== 'POST') return undefined;
    const r = responses[Math.min(i, responses.length - 1)];
    i++;
    return r?.();
  };
}

const urlhaus = (...responses: Array<() => Response>) => postRoute(URLHAUS_API, ...responses);
const threatfox = (...responses: Array<() => Response>) => postRoute(THREATFOX_API, ...responses);

/** No key: 401 with a JSON body served as application/octet-stream (research §11). */
const unauthorized = () =>
  new Response('{"error": "Unauthorized"}', { status: 401, headers: { 'content-type': 'application/octet-stream' } });
const badKey = () => json({ query_status: 'unknown_auth_key' }, 403);
const tooMany = () => json({ query_status: 'rate_limited' }, 429, { 'retry-after': '0' });

/** `key: null` = no abuse.ch key stored. */
async function runModule<D>(m: Module<D>, e: Entity, routes: Route[], key: string | null = KEY) {
  const f = mockFetch(...routes);
  const ctx = makeCtx({ fetch: f.fetch, keys: key === null ? {} : { abusech: key }, now: () => NOW });
  const out = await m.run(e, ctx);
  return { out, calls: f.calls, facts: m.facts!(out.data, e) };
}

async function runError<D>(m: Module<D>, e: Entity, routes: Route[], key: string | null = KEY) {
  const f = mockFetch(...routes);
  const ctx = makeCtx({ fetch: f.fetch, keys: key === null ? {} : { abusech: key }, now: () => NOW });
  const err = await m.run(e, ctx).then(
    () => undefined,
    (x: unknown) => x,
  );
  expect(err).toBeInstanceOf(Error);
  return { err: err as Error, calls: f.calls };
}

// ---------------------------------------------------------------------------
// Fixtures shaped like the live APIs (docs/research/threat-intel.md §11)

function urlEntry(id: number, url: string, status: string, added: string, tags: unknown = ['exe']): Record<string, unknown> {
  return {
    id: String(id),
    urlhaus_reference: `https://urlhaus.abuse.ch/url/${id}/`,
    url,
    url_status: status,
    date_added: added,
    threat: 'malware_download',
    reporter: 'abuse_ch',
    larted: 'false',
    takedown_time_seconds: null,
    tags,
  };
}

const URLHAUS_DOMAIN = {
  query_status: 'ok',
  urlhaus_reference: 'https://urlhaus.abuse.ch/host/vektorex.com/',
  host: 'vektorex.com',
  firstseen: '2019-01-15 07:09:01 UTC',
  url_count: '120',
  blacklists: { spamhaus_dbl: 'abused_legit_malware', surbl: 'not listed' },
  urls: [
    urlEntry(121319, 'http://vektorex.com/x.exe', 'offline', '2019-02-11 07:45:05 UTC', ['AZORult', 'exe']),
    urlEntry(3170001, 'http://vektorex.com/wp-content/plugins/a/Invoice.zip', 'online', '2026-11-20 14:02:11 UTC', ['zip', 'AsyncRAT']),
    urlEntry(3169000, 'http://vektorex.com/bin.sh', 'unknown', '2026-11-01 09:00:00 UTC', null),
    'garbage',
    { id: '5', url_status: 'online', date_added: '2026-11-24 00:00:00 UTC' },
  ],
};

const URLHAUS_IPV4_OLD = {
  query_status: 'ok',
  urlhaus_reference: 'https://urlhaus.abuse.ch/host/198.51.100.23/',
  host: '198.51.100.23',
  firstseen: '2023-04-02 10:11:12 UTC',
  url_count: '2',
  urls: [
    urlEntry(2500001, 'http://198.51.100.23/bins/x86', 'offline', '2023-04-02 10:11:12 UTC', ['elf', 'mirai']),
    urlEntry(2500002, 'http://198.51.100.23/bins/arm7', 'offline', '2023-04-03 01:00:00 UTC', ['elf', 'mirai']),
  ],
};

const TF_DOMAIN_IOC = {
  id: '1450123',
  ioc: 'vektorex.com',
  threat_type: 'payload_delivery',
  threat_type_desc: 'Indicator that identifies a malware distribution server (payload delivery)',
  ioc_type: 'domain',
  ioc_type_desc: 'Domain that is used for botnet Command&control (C&C)',
  malware: 'win.asyncrat',
  malware_printable: 'AsyncRAT',
  malware_alias: null,
  malware_malpedia: 'https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat',
  confidence_level: 50,
  first_seen: '2026-10-01 08:00:00 UTC',
  last_seen: '2026-11-20 08:00:00 UTC',
  reference: 'https://bazaar.abuse.ch/sample/0f3c/',
  reporter: 'abuse_ch',
  tags: 'AsyncRAT,RAT',
  malware_samples: [],
};

function csIoc(id: number, ioc: string, confidence: unknown, firstSeen = '2026-09-14 10:00:00 UTC'): Record<string, unknown> {
  return {
    id: String(id),
    ioc,
    threat_type: 'botnet_cc',
    threat_type_desc: 'Indicator that identifies a botnet command&control server (C&C)',
    ioc_type: 'ip:port',
    ioc_type_desc: 'ip:port combination that is used for botnet Command&control (C&C)',
    malware: 'win.cobalt_strike',
    malware_printable: 'Cobalt Strike',
    malware_alias: 'Agentemis,BEACON,CobaltStrike',
    malware_malpedia: 'https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike',
    confidence_level: confidence,
    first_seen: firstSeen,
    last_seen: null,
    reference: null,
    reporter: 'abuse_ch',
    tags: ['CobaltStrike'],
    malware_samples: [],
  };
}

const TF_TYPES = {
  query_status: 'ok',
  data: {
    '1': { ioc_type: 'url', fk_threat_type: 'payload_delivery', description: 'URL that delivers a malware payload' },
    '2': { ioc_type: 'domain', fk_threat_type: 'botnet_cc', description: 'Domain that is used for botnet Command&control (C&C)' },
    '3': { ioc_type: 'ip:port', fk_threat_type: 'botnet_cc', description: 'ip:port combination that is used for botnet Command&control (C&C)' },
  },
};

// ---------------------------------------------------------------------------

describe('abuse.ch module metadata', () => {
  it('declares two modules sharing the abusech key (one rate-limit bucket), 24 h TTL', () => {
    for (const m of [urlhausModule, threatfoxModule] as Module[]) {
      expect(m.version).toBe(1);
      expect(m.accepts).toEqual(['domain', 'ip']);
      expect(m.key).toBe('abusech');
      expect(m.keyOptional).toBeFalsy();
      expect(m.active).toBeFalsy();
      expect(m.ttl).toBe(24 * HOUR);
      expect(m.rateLimit).toEqual({ perMinute: 30 });
    }
    expect(urlhausModule.id).toBe('urlhaus');
    expect(urlhausModule.label).toBe('URLhaus (abuse.ch)');
    expect(threatfoxModule.id).toBe('threatfox');
    expect(threatfoxModule.label).toBe('ThreatFox (abuse.ch)');
    expect(threatfoxModule.note).toMatch(/6 months/);
  });

  it('parses abuse.ch timestamps to ISO and rejects junk', () => {
    expect(abuseTime('2019-01-15 07:09:01 UTC')).toBe('2019-01-15T07:09:01.000Z');
    expect(abuseTime('2026-11-20 14:02:11')).toBe('2026-11-20T14:02:11.000Z');
    expect(abuseTime('yesterday')).toBeNull();
    expect(abuseTime(1547536141)).toBeNull();
    expect(abuseTime(null)).toBeNull();
  });
});

describe('URLhaus', () => {
  it('POSTs host= as a form with the Auth-Key header and parses a listed domain', async () => {
    const { out, calls, facts } = await runModule(urlhausModule, domain('VekTorex.com.'), [urlhaus(() => json(URLHAUS_DOMAIN))]);

    expect(calls).toHaveLength(1);
    const { url, init } = calls[0]!;
    expect(url).toBe('https://urlhaus-api.abuse.ch/v1/host/');
    expect(init.method).toBe('POST');
    expect(init.body).toBeInstanceOf(URLSearchParams);
    expect(String(init.body)).toBe('host=vektorex.com');
    expect(headerOf(init, 'Auth-Key')).toBe(KEY);
    expect(init.credentials).toBe('omit');

    const d = out.data;
    expect(d.status).toBe('ok');
    expect(d.host).toBe('vektorex.com');
    expect(d.urlCount).toBe(120);
    expect(d.urlsReturned).toBe(5);
    expect(d.skipped).toBe(2);
    expect(d.onlineCount).toBe(1);
    expect(d.firstSeen).toBe('2019-01-15T07:09:01.000Z');
    expect(d.lastAdded).toBe('2026-11-20T14:02:11.000Z');
    expect(d.blacklists).toEqual({ spamhaus_dbl: 'abused_legit_malware', surbl: 'not listed' });
    expect(d.reference).toBe('https://urlhaus.abuse.ch/host/vektorex.com/');
    // Online first, then status unknown, then offline; URLs kept as plain strings.
    expect(d.urls.map((u) => [u.url_status, u.url])).toEqual([
      ['online', 'http://vektorex.com/wp-content/plugins/a/Invoice.zip'],
      ['unknown', 'http://vektorex.com/bin.sh'],
      ['offline', 'http://vektorex.com/x.exe'],
    ]);
    expect(d.urls[0]).toEqual({
      url: 'http://vektorex.com/wp-content/plugins/a/Invoice.zip',
      url_status: 'online',
      threat: 'malware_download',
      tags: ['zip', 'AsyncRAT'],
      date_added: '2026-11-20T14:02:11.000Z',
    });
    expect(d.urls[1]!.tags).toEqual([]);
    expect(d.topTags).toEqual(expect.arrayContaining(['AZORult', 'AsyncRAT', 'exe', 'zip']));

    expect(out.severity).toBe('high');
    expect(out.summary).toBe('120 malware URLs · 1 online · newest 2026-11-20 · Spamhaus DBL: compromised site used for malware');
    expect(out.pivots).toBeUndefined();

    // Facts: GUI link built by us, malware URLs as copyable (defanged-in-export) text, never links.
    expect(facts[0]).toEqual({
      label: 'URLhaus',
      value: 'Listed (view host on URLhaus)',
      href: 'https://urlhaus.abuse.ch/host/vektorex.com/',
      tone: 'bad',
    });
    expect(facts.find((f) => f.label === 'Malware URLs')!.value).toBe('120 (5 returned by the API)');
    expect(facts.find((f) => f.label === 'Spamhaus DBL')).toMatchObject({ value: 'abused_legit_malware (compromised site used for malware)', tone: 'warn' });
    expect(facts.find((f) => f.label === 'SURBL')).toMatchObject({ value: 'not listed', tone: 'good' });
    expect(facts.find((f) => f.label === 'Skipped')!.value).toBe('2 malformed URL entries');
    const urlFacts = facts.filter((f) => f.pivot);
    expect(urlFacts.map((f) => f.value)).toEqual(d.urls.map((u) => u.url));
    expect(urlFacts[0]).toMatchObject({ label: 'online · 2026-11-20 · malware_download · zip, AsyncRAT', tone: 'bad' });
    expect(urlFacts.every((f) => f.href === undefined)).toBe(true);

    // The key never leaks into what is cached, shown or exported.
    expect(JSON.stringify([out, facts])).not.toContain(KEY);
  });

  it('keeps at most MAX_URLS (online first) but counts online URLs across the whole response', async () => {
    const urls = Array.from({ length: 100 }, (_, i) =>
      urlEntry(4000000 + i, `http://vektorex.com/p/${i}.exe`, i % 40 === 7 ? 'online' : 'offline', `2026-0${1 + (i % 9)}-15 10:00:00 UTC`),
    );
    const { out, facts } = await runModule(urlhausModule, domain(), [urlhaus(() => json({ ...URLHAUS_DOMAIN, url_count: '250', urls }))]);
    expect(out.data.urls).toHaveLength(MAX_URLS);
    expect(out.data.urlCount).toBe(250);
    expect(out.data.urlsReturned).toBe(100);
    expect(out.data.onlineCount).toBe(3);
    expect(out.data.urls.slice(0, 3).every((u) => u.url_status === 'online')).toBe(true);
    expect(out.data.urls[3]!.url_status).toBe('offline');
    expect(out.data.topTags).toEqual(['exe']);
    expect(facts.find((f) => f.label === 'Online')!.value).toBe('3 of 100 returned');
    expect(facts.find((f) => f.label === 'Shown')!.value).toBe('20 of 100 URLs (online first, then newest)');
    expect(JSON.stringify(out.data).length).toBeLessThan(8000);
  });

  it('maps no_results to a clean "not listed" result', async () => {
    const { out, facts } = await runModule(urlhausModule, domain('example.com'), [urlhaus(() => json({ query_status: 'no_results' }))]);
    expect(out.data).toMatchObject({ status: 'no_results', host: 'example.com', urlCount: 0, onlineCount: 0, urls: [], blacklists: null });
    expect(out.severity).toBe('none');
    expect(out.summary).toBe('Not listed in URLhaus');
    expect(facts).toEqual([{ label: 'URLhaus', value: 'Not listed', tone: 'good' }]);
  });

  it('IPv4: no blacklists field; only old offline URLs is a low (old) signal', async () => {
    const { out, calls, facts } = await runModule(urlhausModule, ip('198.51.100.23'), [urlhaus(() => json(URLHAUS_IPV4_OLD))]);
    expect(formHost(calls[0]!.init)).toBe('198.51.100.23');
    expect(out.data.blacklists).toBeNull();
    expect(out.data.onlineCount).toBe(0);
    expect(out.severity).toBe('low');
    expect(out.summary).toBe('2 malware URLs · none online · newest 2023-04-03 (old signal)');
    expect(facts.some((f) => f.label === 'Spamhaus DBL')).toBe(false);
    expect(facts[0]!.href).toBe('https://urlhaus.abuse.ch/host/198.51.100.23/');
  });

  it('IPv6: sends the canonical address; no_results is clean, invalid_host is a skip', async () => {
    const ok = await runModule(urlhausModule, ip('2001:DB8:0:0::1'), [urlhaus(() => json({ query_status: 'no_results' }))]);
    expect(formHost(ok.calls[0]!.init)).toBe('2001:db8::1');
    expect(ok.out.severity).toBe('none');
    expect(ok.out.data.host).toBe('2001:db8::1');

    const { err } = await runError(urlhausModule, ip('2001:db8::1'), [urlhaus(() => json({ query_status: 'invalid_host' }))]);
    expect(err).toBeInstanceOf(SkipError);
    expect(err.message).toMatch(/IPv6/);
  });

  it('grades severity: online > any URLs > blacklisted only > none; old URLs are low unless blacklisted now', () => {
    const parse = (body: Record<string, unknown>, host = 'vektorex.com') => parseUrlhaus(host, { query_status: 'ok', ...body });
    const recentOffline = parse({ url_count: '1', urls: [urlEntry(1, 'http://vektorex.com/a', 'offline', '2026-06-01 00:00:00 UTC')] });
    expect(urlhausSeverity(recentOffline, NOW)).toBe('medium');

    const oldButListed = parse({
      url_count: '1',
      blacklists: { spamhaus_dbl: 'botnet_cc_domain', surbl: 'not listed' },
      urls: [urlEntry(1, 'http://vektorex.com/a', 'offline', '2020-06-01 00:00:00 UTC')],
    });
    expect(urlhausSeverity(oldButListed, NOW)).toBe('medium');

    const undated = parse({ url_count: '3', urls: [] });
    expect(urlhausSeverity(undated, NOW)).toBe('medium');

    const blacklistedOnly = parse({ url_count: '0', urls: [], blacklists: { spamhaus_dbl: 'phishing_domain', surbl: 'listed' } });
    expect(urlhausSeverity(blacklistedOnly, NOW)).toBe('low');

    const clean = parse({ url_count: '0', urls: [], blacklists: { spamhaus_dbl: 'not listed', surbl: 'not listed' } });
    expect(urlhausSeverity(clean, NOW)).toBe('none');
  });

  it('does not downgrade to "old signal" when URLhaus returned only part of the list (order undocumented)', () => {
    const old = (n: number) => urlEntry(n, `http://vektorex.com/${n}`, 'offline', '2020-06-01 00:00:00 UTC');
    const truncated = parseUrlhaus('vektorex.com', { query_status: 'ok', url_count: '150', urls: [old(1), old(2)] });
    expect(urlhausSeverity(truncated, NOW)).toBe('medium');
    expect(urlhausSummary(truncated, urlhausSeverity(truncated, NOW))).not.toMatch(/old signal/);

    const withSkipped = parseUrlhaus('vektorex.com', { query_status: 'ok', url_count: '2', urls: [old(1), { id: '2' }] });
    expect(withSkipped.skipped).toBe(1);
    expect(urlhausSeverity(withSkipped, NOW)).toBe('medium');

    const complete = parseUrlhaus('vektorex.com', { query_status: 'ok', url_count: '2', urls: [old(1), old(2)] });
    expect(urlhausSeverity(complete, NOW)).toBe('low');
  });

  it('summarises a blacklisted-only host', async () => {
    const body = { query_status: 'ok', url_count: '0', urls: [], blacklists: { spamhaus_dbl: 'phishing_domain', surbl: 'listed' } };
    const { out, facts } = await runModule(urlhausModule, domain(), [urlhaus(() => json(body))]);
    expect(out.severity).toBe('low');
    expect(out.summary).toBe('Known to URLhaus, no malware URLs · Spamhaus DBL: phishing domain · SURBL: listed');
    expect(facts[0]).toMatchObject({ value: 'Known host, no malware URLs (view on URLhaus)', tone: 'warn' });
    expect(facts.find((f) => f.label === 'SURBL')).toEqual({ label: 'SURBL', value: 'listed', tone: 'warn' });
  });

  it('only documented blacklist codes count as listed; other values stay neutral', async () => {
    const body = {
      query_status: 'ok',
      url_count: '0',
      urls: [],
      blacklists: { spamhaus_dbl: 'unknown_return_code', surbl: 'error' },
    };
    const { out, facts } = await runModule(urlhausModule, domain(), [urlhaus(() => json(body))]);
    expect(out.severity).toBe('none');
    expect(out.summary).toBe('Known to URLhaus, no malware URLs');
    expect(facts[0]).toEqual({
      label: 'URLhaus',
      value: 'Known host, no malware URLs (view on URLhaus)',
      href: 'https://urlhaus.abuse.ch/host/vektorex.com/',
    });
    expect(facts.find((f) => f.label === 'Spamhaus DBL')).toEqual({ label: 'Spamhaus DBL', value: 'unknown_return_code' });
    expect(facts.find((f) => f.label === 'SURBL')).toEqual({ label: 'SURBL', value: 'error' });
    // Prototype names from the provider are plain text, not Object.prototype lookups.
    const proto = parseUrlhaus('vektorex.com', { query_status: 'ok', url_count: '0', urls: [], blacklists: { spamhaus_dbl: 'constructor', surbl: '__proto__' } });
    expect(urlhausSeverity(proto, NOW)).toBe('none');
  });

  describe('errors', () => {
    it('401 (no/unsent key, octet-stream body) -> clear Auth-Key error', async () => {
      const { err } = await runError(urlhausModule, domain(), [urlhaus(unauthorized)]);
      expect(err).toBeInstanceOf(FetchError);
      expect((err as FetchError).status).toBe(401);
      expect(err.message).toMatch(/HTTP 401/);
      expect(err.message).toMatch(/Auth-Key/);
      expect(err.message).not.toContain(KEY);
    });

    it('403 unknown_auth_key -> invalid key error', async () => {
      const { err } = await runError(urlhausModule, domain(), [urlhaus(badKey)]);
      expect((err as FetchError).status).toBe(403);
      expect(err.message).toMatch(/rejected the Auth-Key \(unknown_auth_key\)/);
      expect(err.message).toMatch(/settings/);
      expect(err.message).not.toContain(KEY);
    });

    it('403 without a JSON body is still reported as a key problem', async () => {
      const { err } = await runError(urlhausModule, domain(), [urlhaus(() => text('Forbidden', 403, 'text/plain'))]);
      expect(err.message).toMatch(/HTTP 403/);
      expect(err.message).toMatch(/Auth-Key/);
    });

    it('429 -> quota error', async () => {
      const { err } = await runError(urlhausModule, domain(), [urlhaus(tooMany)]);
      expect((err as FetchError).status).toBe(429);
      expect(err.message).toMatch(/URLhaus rate limit or quota exceeded \(HTTP 429\)/);
    });

    it('5xx -> provider unavailable; network errors pass through', async () => {
      const { err } = await runError(urlhausModule, domain(), [urlhaus(() => text('<html>Bad gateway</html>', 502))]);
      expect(err.message).toBe('URLhaus is unavailable (HTTP 502). Try again later.');

      const net = await runError(urlhausModule, domain(), [
        () => {
          throw new TypeError('NetworkError when attempting to fetch resource.');
        },
      ]);
      expect((net.err as FetchError).kind).toBe('network');
    });

    it('200 unknown_auth_key and http_post_expected are errors, not "not listed"', async () => {
      const a = await runError(urlhausModule, domain(), [urlhaus(() => json({ query_status: 'unknown_auth_key' }))]);
      expect(a.err.message).toMatch(/unknown_auth_key/);
      const b = await runError(urlhausModule, domain(), [urlhaus(() => json({ query_status: 'http_post_expected' }))]);
      expect(b.err.message).toMatch(/http_post_expected/);
    });

    it('missing key -> skip without a request; key with invalid characters -> error without a request', async () => {
      const none = await runError(urlhausModule, domain(), [urlhaus(() => json(URLHAUS_DOMAIN))], null);
      expect(none.err).toBeInstanceOf(SkipError);
      expect(none.calls).toHaveLength(0);

      const bad = await runError(urlhausModule, domain(), [urlhaus(() => json(URLHAUS_DOMAIN))], 'abc def');
      expect(bad.err.message).toMatch(/invalid characters/);
      expect(bad.err.message).not.toContain('abc def');
      expect(bad.calls).toHaveLength(0);
    });

    it('trims the stored key before sending it', async () => {
      const { calls } = await runModule(urlhausModule, domain(), [urlhaus(() => json({ query_status: 'no_results' }))], `  ${KEY}\n`);
      expect(headerOf(calls[0]!.init, 'Auth-Key')).toBe(KEY);
    });

    it('rejects entity kinds it does not accept', async () => {
      const { err, calls } = await runError(urlhausModule, { kind: 'hash', value: '-123', depth: 1 }, []);
      expect(err).toBeInstanceOf(SkipError);
      expect(calls).toHaveLength(0);
    });
  });

  describe('malformed payloads', () => {
    it('non-JSON and non-object bodies -> parse errors', async () => {
      const a = await runError(urlhausModule, domain(), [urlhaus(() => text('<html>maintenance</html>'))]);
      expect((a.err as FetchError).kind).toBe('parse');
      const b = await runError(urlhausModule, domain(), [urlhaus(() => json([1, 2, 3]))]);
      expect((b.err as FetchError).kind).toBe('parse');
      expect(b.err.message).toMatch(/not a JSON object/);
    });

    it('unknown or missing query_status -> parse error (never a false "clean")', async () => {
      const a = await runError(urlhausModule, domain(), [urlhaus(() => json({ query_status: 'something_new' }))]);
      expect(a.err.message).toMatch(/query_status "something_new"/);
      const b = await runError(urlhausModule, domain(), [urlhaus(() => json({ host: 'vektorex.com' }))]);
      expect(b.err.message).toMatch(/no query_status/);
    });

    it('wrong field types degrade to empty values; unsafe reference and control characters are dropped', () => {
      const d: UrlhausData = parseUrlhaus('vektorex.com', {
        query_status: 'ok',
        url_count: 'many',
        urls: 'none',
        blacklists: 'listed',
        firstseen: 1547536141,
        urlhaus_reference: 'javascript:alert(1)',
      });
      expect(d).toMatchObject({ urlCount: 0, urls: [], blacklists: null, firstSeen: null, reference: null, skipped: 0 });
      expect(urlhausSeverity(d, NOW)).toBe('none');

      const e = parseUrlhaus('vektorex.com', {
        query_status: 'ok',
        url_count: 1,
        urlhaus_reference: 'https://evil.example/host/vektorex.com/',
        // RLO override, NUL, zero-width space, BOM, bell, line separator (escaped: no literal bidi chars in source).
        urls: [urlEntry(1, 'http://vektorex.com/\u202eexe.pdf\u0000', 'ONLINE', 'not a date', ['a\u0007b', 42, '', 'x\u200by\ufeff\u2028'])],
      });
      expect(e.reference).toBeNull();
      expect(e.urls[0]).toEqual({ url: 'http://vektorex.com/exe.pdf', url_status: 'online', threat: 'malware_download', tags: ['ab', 'xy'], date_added: null });
    });

    it('URL entries that all fail to parse -> parse error, not "N URLs, none online"', async () => {
      const body = { ...URLHAUS_DOMAIN, urls: [{ id: '1', link: 'http://vektorex.com/x', url_status: 'online' }, 'junk'] };
      const { err } = await runError(urlhausModule, domain(), [urlhaus(() => json(body))]);
      expect((err as FetchError).kind).toBe('parse');
      expect(err.message).toMatch(/2 URL entries but none could be parsed/);
    });
  });
});

describe('ThreatFox', () => {
  it('POSTs search_ioc with exact_match:true as JSON with the Auth-Key header (domain)', async () => {
    const { out, calls, facts } = await runModule(threatfoxModule, domain(), [threatfox(() => json({ query_status: 'ok', data: [TF_DOMAIN_IOC] }))]);
    expect(calls).toHaveLength(1);
    const { url, init } = calls[0]!;
    expect(url).toBe('https://threatfox-api.abuse.ch/api/v1/');
    expect(init.method).toBe('POST');
    expect(jsonBody(init)).toEqual({ query: 'search_ioc', search_term: 'vektorex.com', exact_match: true });
    expect(headerOf(init, 'Auth-Key')).toBe(KEY);
    expect(headerOf(init, 'Content-Type')).toBe('application/json');

    const d = out.data;
    expect(d).toMatchObject({ query: 'vektorex.com', status: 'ok', count: 1, skipped: 0, maxConfidence: 50, malware: ['AsyncRAT'], threatTypes: ['payload_delivery'] });
    expect(d.iocs[0]).toEqual({
      id: '1450123',
      ioc: 'vektorex.com',
      ioc_type: 'domain',
      threat_type: 'payload_delivery',
      malware_printable: 'AsyncRAT',
      confidence_level: 50,
      first_seen: '2026-10-01T08:00:00.000Z',
      last_seen: '2026-11-20T08:00:00.000Z',
      reference: 'https://bazaar.abuse.ch/sample/0f3c/',
      tags: ['AsyncRAT', 'RAT'],
    });
    // Compact: provider-only fields (descriptions, malpedia, samples) are not stored.
    expect(JSON.stringify(d)).not.toMatch(/malpedia|threat_type_desc|malware_samples/);

    expect(out.severity).toBe('medium');
    expect(out.summary).toBe('1 IOC · AsyncRAT · payload delivery · confidence up to 50% · last seen 2026-11-20');

    expect(facts[0]).toEqual({
      label: 'ThreatFox',
      value: 'Listed (search ThreatFox)',
      href: 'https://threatfox.abuse.ch/browse.php?search=ioc%3Avektorex.com',
      tone: 'warn',
    });
    const iocFact = facts.find((f) => f.pivot)!;
    expect(iocFact).toEqual({
      label: 'AsyncRAT · domain · payload delivery · 50% · 2026-10-01 → 2026-11-20',
      value: 'vektorex.com',
      pivot: true,
      href: 'https://threatfox.abuse.ch/ioc/1450123/',
      tone: 'warn',
    });
    // External references are text only.
    expect(facts.find((f) => f.label === 'References')).toEqual({ label: 'References', value: ['https://bazaar.abuse.ch/sample/0f3c/'] });
    expect(JSON.stringify([out, facts])).not.toContain(KEY);
  });

  it('IPv4: ip:port IOCs, confidence >= 75 -> high, sorted by confidence', async () => {
    const body = {
      query_status: 'ok',
      data: [csIoc(41, '139.180.203.104:443', 75, '2026-09-14 10:00:00 UTC'), csIoc(42, '139.180.203.104:8443', '100', '2026-10-02 10:00:00 UTC')],
    };
    const { out, calls, facts } = await runModule(threatfoxModule, ip('139.180.203.104'), [threatfox(() => json(body))]);
    expect(jsonBody(calls[0]!.init)).toEqual({ query: 'search_ioc', search_term: '139.180.203.104', exact_match: true });
    expect(out.data.iocs.map((i) => [i.ioc, i.confidence_level])).toEqual([
      ['139.180.203.104:8443', 100],
      ['139.180.203.104:443', 75],
    ]);
    expect(out.data.maxConfidence).toBe(100);
    expect(out.severity).toBe('high');
    expect(out.summary).toBe('2 IOCs · Cobalt Strike · botnet C&C · confidence up to 100% · last seen 2026-10-02');
    expect(facts[0]!.tone).toBe('bad');
    expect(facts.filter((f) => f.pivot).map((f) => f.value)).toEqual(['139.180.203.104:8443', '139.180.203.104:443']);
  });

  it('IPv6: sends the canonical address; no_result with a string data field is clean', async () => {
    const body = { query_status: 'no_result', data: 'Your search did not yield any results' };
    const { out, calls, facts } = await runModule(threatfoxModule, ip('2001:0DB8::0001'), [threatfox(() => json(body))]);
    expect(jsonBody(calls[0]!.init)).toEqual({ query: 'search_ioc', search_term: '2001:db8::1', exact_match: true });
    expect(out.data).toMatchObject({ status: 'no_results', count: 0, iocs: [], maxConfidence: null });
    expect(out.severity).toBe('none');
    expect(out.summary).toBe('Not listed in ThreatFox');
    expect(facts).toEqual([
      {
        label: 'ThreatFox',
        value: 'Not listed (ThreatFox keeps IOCs for 6 months)',
        tone: 'good',
        href: 'https://threatfox.abuse.ch/browse.php?search=ioc%3A2001%3Adb8%3A%3A1',
      },
    ]);
  });

  it.each([
    ['no_results', { query_status: 'no_results' }],
    ['ok with an empty list', { query_status: 'ok', data: [] }],
    ['ok with null data', { query_status: 'ok', data: null }],
  ])('treats %s as not listed', (_name, body) => {
    const d: ThreatfoxData = parseThreatfox('example.com', body);
    expect(d.status).toBe('no_results');
    expect(d.count).toBe(0);
  });

  it('illegal_search_term -> skip', async () => {
    const { err } = await runError(threatfoxModule, domain(), [threatfox(() => json({ query_status: 'illegal_search_term', data: 'Illegal search term' }))]);
    expect(err).toBeInstanceOf(SkipError);
  });

  it('caps stored IOCs at MAX_IOCS but grades on all of them', () => {
    const list = Array.from({ length: 30 }, (_, i) => csIoc(100 + i, `139.180.203.104:${1000 + i}`, i === 29 ? 90 : 40));
    // The newest IOC has the lowest confidence, so it falls outside the stored top 20.
    list.push(csIoc(999, '139.180.203.104:9999', 10, '2026-11-24 09:00:00 UTC'));
    const d = parseThreatfox('139.180.203.104', { query_status: 'ok', data: list });
    expect(d.count).toBe(31);
    expect(d.iocs).toHaveLength(MAX_IOCS);
    expect(d.iocs[0]!.confidence_level).toBe(90);
    expect(d.maxConfidence).toBe(90);
    expect(d.lastSeen).toBe('2026-11-24T09:00:00.000Z');
    expect(d.iocs.some((i) => i.id === '999')).toBe(false);
    const facts = threatfoxModule.facts!(d, ip('139.180.203.104'));
    expect(facts.find((f) => f.label === 'IOCs')!.value).toBe('31 (20 shown)');
  });

  describe('errors', () => {
    it('401 -> Auth-Key error', async () => {
      const { err } = await runError(threatfoxModule, domain(), [threatfox(unauthorized)]);
      expect((err as FetchError).status).toBe(401);
      expect(err.message).toMatch(/Auth-Key/);
    });

    it('403 unknown_auth_key -> invalid key error', async () => {
      const { err } = await runError(threatfoxModule, domain(), [threatfox(badKey)]);
      expect(err.message).toMatch(/unknown_auth_key/);
      expect(err.message).not.toContain(KEY);
    });

    it('429 -> quota error', async () => {
      const { err } = await runError(threatfoxModule, ip('139.180.203.104'), [threatfox(tooMany)]);
      expect(err.message).toMatch(/ThreatFox rate limit or quota exceeded \(HTTP 429\)/);
    });

    it('other 4xx keep the provider status text', async () => {
      const { err } = await runError(threatfoxModule, domain(), [threatfox(() => json({ query_status: 'unknown_query' }, 400))]);
      expect(err.message).toBe('ThreatFox error (HTTP 400: unknown_query).');
    });
  });

  describe('malformed payloads', () => {
    it('unknown status, non-list data and all-junk lists are errors (never a false "clean")', async () => {
      const a = await runError(threatfoxModule, domain(), [threatfox(() => json({ query_status: 'whatever' }))]);
      expect((a.err as FetchError).kind).toBe('parse');
      expect(() => parseThreatfox('x.com', { query_status: 'ok', data: { ioc: 'x.com' } })).toThrow(/not a list/);
      expect(() => parseThreatfox('x.com', { query_status: 'ok', data: [1, 'x', { id: 3 }] })).toThrow(/none could be parsed/);
      expect(() => parseThreatfox('x.com', 'ok')).toThrow(/not a JSON object/);
    });

    it('tolerates odd field types: clamps confidence, drops bad ids, timestamps and references', () => {
      const d = parseThreatfox('x.com', {
        query_status: 'ok',
        data: [
          { ioc: 'x.com', id: 'abc', confidence_level: 150, first_seen: 'soon', reference: 'javascript:alert(1)', tags: null },
          { ioc: 'x.com', id: 7, confidence_level: 'high', tags: ['t1', 't1', 't2'] },
          'junk',
        ],
      });
      expect(d.count).toBe(2);
      expect(d.skipped).toBe(1);
      expect(d.iocs[0]).toMatchObject({ id: null, confidence_level: 100, first_seen: null, reference: null, tags: [] });
      expect(d.iocs[1]).toMatchObject({ id: '7', confidence_level: null, tags: ['t1', 't2'] });
      const facts = threatfoxModule.facts!(d, domain('x.com'));
      const iocFacts = facts.filter((f) => f.pivot);
      expect(iocFacts[0]!.href).toBeUndefined();
      expect(iocFacts[1]!.href).toBe('https://threatfox.abuse.ch/ioc/7/');
      expect(facts.find((f) => f.label === 'Skipped')!.value).toBe('1 malformed IOC entry');
    });

    it('provider strings that look like prototype names are shown as text', () => {
      const d = parseThreatfox('x.com', {
        query_status: 'ok',
        data: [{ ioc: 'x.com', threat_type: 'constructor', confidence_level: 50 }, { ioc: 'x.com', threat_type: '__proto__', confidence_level: 50 }],
      });
      const summary = threatfoxSummary(d);
      expect(summary).toMatch(/^2 IOCs · constructor, +proto +· confidence up to 50%$/);
      const facts = threatfoxModule.facts!(d, domain('x.com'));
      expect(facts.find((f) => f.label === 'Threat types')!.value).toMatch(/^constructor, +proto *$/);
      expect(JSON.stringify([summary, facts])).not.toMatch(/function|native code|\[object Object\]/);
    });
  });
});

describe('abuse.ch cancellation', () => {
  it.each([
    ['URLhaus', urlhausModule as Module],
    ['ThreatFox', threatfoxModule as Module],
  ])('%s: Cancel mid-request surfaces as an abort, not as a provider error', async (_name, m) => {
    const ac = new AbortController();
    const f = mockFetch(() => {
      ac.abort();
      throw new DOMException('The operation was aborted.', 'AbortError');
    });
    const ctx = makeCtx({ fetch: f.fetch, keys: { abusech: KEY }, now: () => NOW, signal: ac.signal });
    const err = await m.run(domain(), ctx).then(
      () => undefined,
      (x: unknown) => x,
    );
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).kind).toBe('aborted');
    expect(isAbortError(err)).toBe(true);
    expect(f.calls).toHaveLength(1);
  });

  it('an already-cancelled run makes no request', async () => {
    const ac = new AbortController();
    ac.abort();
    const f = mockFetch(urlhaus(() => json(URLHAUS_DOMAIN)));
    const ctx = makeCtx({ fetch: f.fetch, keys: { abusech: KEY }, now: () => NOW, signal: ac.signal });
    const err = await urlhausModule.run(domain(), ctx).then(
      () => undefined,
      (x: unknown) => x,
    );
    expect(isAbortError(err)).toBe(true);
    expect(f.calls).toHaveLength(0);
  });
});

describe('abuse.ch key tester', () => {
  const http = (...routes: Route[]) => {
    const m = mockFetch(...routes);
    return { http: createHttp({ fetch: m.fetch, limiter: new RateLimiter(), signal: new AbortController().signal }), calls: m.calls };
  };

  it('uses the cheap ThreatFox "types" query with the Auth-Key header', async () => {
    const { http: h, calls } = http(threatfox(() => json(TF_TYPES)));
    const msg = await abusechKeyTest(` ${KEY} `, h);
    expect(msg).toBe('Auth-Key accepted by abuse.ch ThreatFox (3 IOC types). URLhaus uses the same key.');
    expect(msg).not.toContain(KEY);
    expect(calls).toHaveLength(1);
    expect(jsonBody(calls[0]!.init)).toEqual({ query: 'types' });
    expect(headerOf(calls[0]!.init, 'Auth-Key')).toBe(KEY);
  });

  it('401 -> missing key; 403 unknown_auth_key -> invalid key; 429 -> quota', async () => {
    await expect(abusechKeyTest(KEY, http(threatfox(unauthorized)).http)).rejects.toThrow(/HTTP 401.*Auth-Key/);
    await expect(abusechKeyTest(KEY, http(threatfox(badKey)).http)).rejects.toThrow(/rejected the Auth-Key \(unknown_auth_key\)/);
    await expect(abusechKeyTest(KEY, http(threatfox(tooMany)).http)).rejects.toThrow(/HTTP 429/);
  });

  it('empty or malformed keys fail without a request', async () => {
    const a = http(threatfox(() => json(TF_TYPES)));
    await expect(abusechKeyTest('   ', a.http)).rejects.toThrow(/Enter your abuse.ch Auth-Key/);
    await expect(abusechKeyTest('key with spaces', a.http)).rejects.toThrow(/invalid characters/);
    expect(a.calls).toHaveLength(0);
  });

  it('unexpected payloads are errors', async () => {
    await expect(abusechKeyTest(KEY, http(threatfox(() => json({ query_status: 'unknown_auth_key' }))).http)).rejects.toThrow(/unknown_auth_key/);
    await expect(abusechKeyTest(KEY, http(threatfox(() => json({ query_status: 'nope' }))).http)).rejects.toThrow(/query_status "nope"/);
    await expect(abusechKeyTest(KEY, http(threatfox(() => json([]))).http)).rejects.toThrow(/Unexpected response/);
  });
});

describe('abuse.ch through the orchestrator', () => {
  /** Virtual time: the limiter's waits (bucket refill, Retry-After) resolve instantly. */
  function instantLimiter(): RateLimiter {
    let t = 0;
    const clock: Clock = {
      now: () => t,
      sleep: async (ms) => {
        t += ms;
      },
    };
    return new RateLimiter(clock);
  }

  function deps(fetchImpl: typeof fetch, limiter: RateLimiter, key: string | null = KEY): OrchestratorDeps {
    return {
      modules: [urlhausModule as Module, threatfoxModule as Module],
      isEnabled: () => true,
      allowActive: false,
      cache: memoryCache(),
      limiter,
      settings: DEFAULT_SETTINGS,
      getKey: async (p) => (p === 'abusech' && key !== null ? key : undefined),
      fetch: fetchImpl,
    };
  }

  async function investigateRoot(d: OrchestratorDeps) {
    const events: RunEvent[] = [];
    await investigate({ kind: 'domain', value: 'vektorex.com' }, (e) => events.push(e), d).done;
    const cards = events.filter((e): e is Extract<RunEvent, { type: 'card' }> => e.type === 'card').map((e) => e.card);
    return (id: string): CardState | undefined => cards.filter((c) => c.id === id).at(-1);
  }

  it('shares one "abusech" rate-limit bucket and retries once after a 429', async () => {
    const m = mockFetch(urlhaus(tooMany, () => json(URLHAUS_DOMAIN)), threatfox(() => json({ query_status: 'ok', data: [TF_DOMAIN_IOC] })));
    const limiter = instantLimiter();
    const acquire = vi.spyOn(limiter, 'acquire');
    const last = await investigateRoot(deps(m.fetch, limiter));

    expect(last('urlhaus|domain:vektorex.com')).toMatchObject({ status: 'ok', severity: 'high' });
    expect(last('threatfox|domain:vektorex.com')).toMatchObject({ status: 'ok', severity: 'medium' });
    expect(m.calls.filter((c) => c.url === URLHAUS_API)).toHaveLength(2);
    expect(acquire.mock.calls.length).toBe(3);
    expect(acquire.mock.calls.every(([k, perMinute]) => k === 'abusech' && perMinute === 30)).toBe(true);
  });

  it('a 429 that persists after the retry becomes a quota error card', async () => {
    const m = mockFetch(urlhaus(tooMany), threatfox(() => json({ query_status: 'no_result', data: 'Your search did not yield any results' })));
    const last = await investigateRoot(deps(m.fetch, instantLimiter()));
    const card = last('urlhaus|domain:vektorex.com')!;
    expect(card.status).toBe('error');
    expect(card.error).toMatchObject({ kind: 'http', status: 429 });
    expect(card.error!.message).toMatch(/rate limit or quota exceeded/);
    expect(m.calls.filter((c) => c.url === URLHAUS_API)).toHaveLength(2);
    expect(last('threatfox|domain:vektorex.com')).toMatchObject({ status: 'ok', severity: 'none', summary: 'Not listed in ThreatFox' });
  });

  it('without a key both modules are skipped with the settings hint and make no requests', async () => {
    const m = mockFetch();
    const last = await investigateRoot(deps(m.fetch, instantLimiter(), null));
    for (const id of ['urlhaus|domain:vektorex.com', 'threatfox|domain:vektorex.com']) {
      expect(last(id)).toMatchObject({ status: 'skipped', skip: { reason: 'no-key' } });
    }
    expect(m.calls).toHaveLength(0);
  });
});
