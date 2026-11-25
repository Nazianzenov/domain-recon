import { describe, expect, it } from 'vitest';
import { FetchError, createHttp } from '@/lib/http';
import { cardId, investigate, type OrchestratorDeps } from '@/lib/orchestrator';
import { RateLimiter, type Clock } from '@/lib/ratelimit';
import { DEFAULT_SETTINGS } from '@/lib/settings';
import type { CardState, Ctx, Entity, Fact, Module, RunEvent } from '@/lib/types';
import { HOUR, SkipError } from '@/lib/types';
import {
  MAX_CATEGORIES,
  MAX_FLAGGED,
  MAX_TAGS,
  RESOLUTIONS_LIMIT,
  severityOf,
  virustotalKeyTest,
  virustotalModule,
  vtErrorMessage,
  type VtData,
} from '@/modules/virustotal';
import { json, makeCtx, memoryCache, mockFetch, text, type Route } from './helpers';

const KEY = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9';
const API = 'https://www.virustotal.com/api/v3';
const domain = (value = 'example.com'): Entity => ({ kind: 'domain', value, depth: 0 });
const ip = (value: string): Entity => ({ kind: 'ip', value, depth: 1 });

// ---------------------------------------------------------------------------
// Fixtures shaped like the live API (docs/research/threat-intel.md §8)

const engine = (name: string, category: string, result: string) => ({ method: 'blacklist', engine_name: name, category, result });

const DOMAIN_CLEAN = {
  data: {
    id: 'example.com',
    type: 'domain',
    links: { self: `${API}/domains/example.com` },
    attributes: {
      last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 66, undetected: 28, timeout: 0 },
      reputation: 0,
      categories: {
        'Forcepoint ThreatSeeker': 'information technology',
        Sophos: 'Information Technology',
        BitDefender: 'computersandsoftware',
        'alphaMountain.ai': 'Information Technology (alphaMountain.ai)',
      },
      registrar: 'RESERVED-Internet Assigned Numbers Authority',
      creation_date: 694224000,
      last_analysis_date: 1795000000,
      last_dns_records: [{ type: 'A', value: '93.184.215.14', ttl: 300 }],
      tags: [],
      total_votes: { harmless: 3, malicious: 0 },
      popularity_ranks: { Tranco: { rank: 120, timestamp: 1795000000 } },
      last_analysis_results: {
        Fortinet: engine('Fortinet', 'harmless', 'clean'),
        Kaspersky: engine('Kaspersky', 'undetected', 'unrated'),
      },
      whois: 'Domain Name: EXAMPLE.COM\nRegistry Domain ID: 2336799_DOMAIN_COM-VRSN\n'.repeat(50),
    },
  },
};

const DOMAIN_MALICIOUS = {
  data: {
    id: 'secure-login-verify.top',
    type: 'domain',
    attributes: {
      last_analysis_stats: { malicious: 7, suspicious: 2, harmless: 55, undetected: 30, timeout: 0 },
      reputation: -12,
      categories: { Webroot: 'Phishing and Other Frauds', 'Forcepoint ThreatSeeker': 'phishing', Sophos: 'phishing' },
      creation_date: 1790000000,
      last_analysis_date: 1795000000,
      tags: ['phishing', 'dga'],
      total_votes: { harmless: 0, malicious: 4 },
      last_analysis_results: {
        Sophos: engine('Sophos', 'malicious', 'phishing'),
        Fortinet: engine('Fortinet', 'malicious', 'phishing'),
        Kaspersky: engine('Kaspersky', 'suspicious', 'suspicious'),
        BitDefender: engine('BitDefender', 'malicious', 'malware'),
        'G-Data': engine('G-Data', 'malicious', 'phishing'),
        CRDF: engine('CRDF', 'malicious', 'malicious'),
        Webroot: engine('Webroot', 'malicious', 'malicious'),
        ESET: engine('ESET', 'malicious', 'phishing'),
        Quttera: engine('Quttera', 'suspicious', 'suspicious'),
        Google: engine('Google', 'harmless', 'clean'),
      },
    },
  },
};

const resolution = (ipAddress: string, date: number, host = 'example.com') => ({
  type: 'resolution',
  id: `${ipAddress}${host}`,
  links: { self: `${API}/resolutions/${ipAddress}${host}` },
  attributes: {
    ip_address: ipAddress,
    host_name: host,
    date,
    resolver: 'VirusTotal',
    ip_address_last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 60, undetected: 34, timeout: 0 },
    host_name_last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 66, undetected: 28, timeout: 0 },
  },
});

/** Deliberately unsorted, with a duplicate IP, an uppercase IPv6, a private IP and junk entries. */
const RESOLUTIONS = {
  meta: { count: 18, cursor: 'CuABChEKBGRhdGUSCQjS3' },
  data: [
    resolution('93.184.216.34', 1716000000),
    resolution('93.184.215.14', 1700000000),
    resolution('2606:2800:21F:CB07:6820:80DA:AF6B:8B2C', 1790000000),
    resolution('93.184.215.14', 1795000000),
    resolution('10.0.0.1', 1764000000),
    { type: 'resolution', id: 'junk', attributes: { ip_address: 'not-an-ip', date: 1795000000 } },
    { type: 'resolution', id: 'no-attributes' },
    'junk',
  ],
  links: {
    self: `${API}/domains/example.com/resolutions?limit=40`,
    next: `${API}/domains/example.com/resolutions?cursor=CuABChEKBGRhdGUSCQjS3&limit=40`,
  },
};

const IP_GOOGLE = {
  data: {
    id: '8.8.8.8',
    type: 'ip_address',
    attributes: {
      as_owner: 'GOOGLE',
      asn: 15169,
      country: 'US',
      continent: 'NA',
      network: '8.8.8.0/24',
      regional_internet_registry: 'ARIN',
      last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 62, undetected: 32, timeout: 0 },
      reputation: 571,
      tags: [],
      total_votes: { harmless: 120, malicious: 12 },
      last_analysis_date: 1795000000,
      whois: 'NetRange: 8.8.8.0 - 8.8.8.255\n'.repeat(40),
    },
  },
};

const IP6 = {
  data: {
    id: '2001:4860:4860::8888',
    type: 'ip_address',
    attributes: {
      as_owner: 'GOOGLE',
      asn: 15169,
      country: 'US',
      network: '2001:4860::/32',
      last_analysis_stats: { malicious: 1, suspicious: 0, harmless: 60, undetected: 33, timeout: 0 },
      reputation: 0,
      last_analysis_results: { CRDF: engine('CRDF', 'malicious', 'malicious') },
    },
  },
};

const vtErr = (code: string, message: string, status: number, headers: Record<string, string> = {}) =>
  json({ error: { code, message } }, status, headers);

const NOT_FOUND = (what: string) => vtErr('NotFoundError', `${what} not found`, 404);

const QUOTAS = {
  data: {
    api_requests_hourly: { user: { allowed: 240, used: 3 }, group: { allowed: 0, used: 0, inherited_from: null } },
    api_requests_daily: { user: { allowed: 500, used: 12 }, group: { allowed: 0, used: 0, inherited_from: null } },
    api_requests_monthly: { user: { allowed: 15500, used: 40 } },
  },
};

// ---------------------------------------------------------------------------
// Helpers

/** Route VT API paths (after /api/v3) to fixtures or responders. */
function vtRoute(map: Record<string, unknown | ((u: URL, init: RequestInit) => Response)>): Route {
  return (u, init) => {
    if (u.host !== 'www.virustotal.com' || !u.pathname.startsWith('/api/v3/')) return undefined;
    const path = u.pathname.slice('/api/v3'.length);
    const v = map[path];
    if (v === undefined) return undefined;
    return typeof v === 'function' ? (v as (u: URL, i: RequestInit) => Response)(u, init) : json(v);
  };
}

const headers = (init: RequestInit) => (init.headers as Record<string, string> | undefined) ?? {};
const fact = (facts: Fact[], prefix: string) => facts.find((f) => f.label.startsWith(prefix));
const values = (f: Fact | undefined) => (f ? (Array.isArray(f.value) ? f.value : [f.value]) : []);
/** Fails the test when a promise expected to reject resolves instead. */
const fail = (): never => {
  throw new Error('expected a rejection');
};

async function run(e: Entity, routes: Route[], keys: Record<string, string> = { virustotal: KEY }) {
  const m = mockFetch(...routes);
  const ctx = makeCtx({ fetch: m.fetch, keys });
  const out = await virustotalModule.run(e, ctx);
  return { out, calls: m.calls, facts: virustotalModule.facts!(out.data, e) };
}

async function runError(e: Entity, routes: Route[], keys: Record<string, string> = { virustotal: KEY }) {
  const m = mockFetch(...routes);
  const ctx = makeCtx({ fetch: m.fetch, keys });
  const err = await virustotalModule.run(e, ctx).then(
    () => {
      throw new Error('expected run() to reject');
    },
    (x: unknown) => x,
  );
  return { err: err as Error, calls: m.calls };
}

/** A clock that advances instantly, so rate-limit waits don't slow the tests. */
function fakeClock(): Clock & { t: number } {
  const c = {
    t: 1_000_000,
    now: () => c.t,
    sleep: async (ms: number) => {
      c.t += Math.max(1, ms);
    },
  };
  return c;
}

/** A ctx whose requests go through the module's real 4/min bucket (with the automatic 429 retry). */
function limitedCtx(fetchImpl: typeof fetch, clock = fakeClock()): Ctx {
  const signal = new AbortController().signal;
  const http = createHttp({
    fetch: fetchImpl,
    limiter: new RateLimiter(clock),
    signal,
    defaultLimit: { key: 'virustotal', perMinute: 4 },
    now: clock.now,
  });
  return { ...makeCtx({ fetch: fetchImpl, keys: { virustotal: KEY } }), ...http };
}

// ---------------------------------------------------------------------------

describe('virustotal module metadata', () => {
  it('declares the contract the orchestrator relies on', () => {
    expect(virustotalModule.id).toBe('virustotal');
    expect(virustotalModule.label).toBe('VirusTotal');
    expect(virustotalModule.version).toBe(1);
    expect(virustotalModule.key).toBe('virustotal');
    expect(virustotalModule.keyOptional).toBeFalsy();
    expect(virustotalModule.accepts).toEqual(['domain', 'ip']);
    expect(virustotalModule.rateLimit).toEqual({ perMinute: 4 });
    expect(virustotalModule.ttl).toBe(24 * HOUR);
    expect(virustotalModule.active).toBeFalsy();
    expect(virustotalModule.note).toMatch(/shared with VirusTotal/);
  });
});

describe('severityOf', () => {
  const s = (malicious: number, suspicious: number) => ({ malicious, suspicious, harmless: 50, undetected: 30, timeout: 0 });
  it('maps detections conservatively', () => {
    expect(severityOf(null)).toBe('none');
    expect(severityOf(s(0, 0))).toBe('none');
    expect(severityOf(s(0, 1))).toBe('low');
    expect(severityOf(s(0, 2))).toBe('low');
    expect(severityOf(s(0, 3))).toBe('medium');
    expect(severityOf(s(1, 0))).toBe('medium');
    expect(severityOf(s(4, 9))).toBe('medium');
    expect(severityOf(s(5, 0))).toBe('high');
    expect(severityOf(s(40, 0))).toBe('high');
  });
});

describe('virustotal domain lookup', () => {
  it('fetches the domain and one page of resolutions with the x-apikey header only', async () => {
    const { out, calls, facts } = await run(domain(), [
      vtRoute({ '/domains/example.com': DOMAIN_CLEAN, '/domains/example.com/resolutions': RESOLUTIONS }),
    ]);

    expect(calls.map((c) => c.url)).toEqual([
      `${API}/domains/example.com`,
      `${API}/domains/example.com/resolutions?limit=${RESOLUTIONS_LIMIT}`,
    ]);
    for (const c of calls) {
      expect(headers(c.init)['x-apikey']).toBe(KEY);
      expect(c.url).not.toContain(KEY);
      expect(c.init.credentials).toBe('omit');
      expect(c.init.method).toBe('GET');
    }

    const d = out.data;
    expect(d.kind).toBe('domain');
    expect(d.indicator).toBe('example.com');
    expect(d.found).toBe(true);
    expect(d.stats).toEqual({ malicious: 0, suspicious: 0, harmless: 66, undetected: 28, timeout: 0 });
    expect(d.engines).toBe(94);
    expect(d.reputation).toBe(0);
    expect(d.votes).toEqual({ harmless: 3, malicious: 0 });
    // Distinct values, case-insensitively.
    expect(d.categories).toEqual(['information technology', 'computersandsoftware', 'Information Technology (alphaMountain.ai)']);
    expect(d.tags).toEqual([]);
    expect(d.flaggedBy).toEqual([]);
    expect(d.registrar).toBe('RESERVED-Internet Assigned Numbers Authority');
    expect(d.creationDate).toBe('1992-01-01T00:00:00.000Z');
    expect(d.lastAnalysisDate).toBe('2026-11-18T11:06:40.000Z');
    expect(d.asOwner).toBeUndefined();
    expect(d.guiUrl).toBe('https://www.virustotal.com/gui/domain/example.com');

    // Deduped (latest date kept), normalised, most recent first, junk dropped.
    expect(d.resolutions).toEqual([
      { ip: '93.184.215.14', date: '2026-11-18T11:06:40.000Z' },
      { ip: '2606:2800:21f:cb07:6820:80da:af6b:8b2c', date: '2026-09-21T14:13:20.000Z' },
      { ip: '10.0.0.1', date: '2025-11-24T16:00:00.000Z' },
      { ip: '93.184.216.34', date: '2024-05-18T02:40:00.000Z' },
    ]);
    expect(d.resolutionsTotal).toBe(18);
    expect(d.resolutionsTruncated).toBe(true);
    expect(d.resolutionsError).toBeUndefined();

    expect(out.severity).toBe('none');
    expect(out.summary).toBe('0/94 malicious · reputation 0 · 18 resolutions');
    expect(out.pivots).toEqual([
      { kind: 'ip', value: '93.184.215.14', note: 'VirusTotal resolution, last seen 2026-11-18' },
      { kind: 'ip', value: '2606:2800:21f:cb07:6820:80da:af6b:8b2c', note: 'VirusTotal resolution, last seen 2026-09-21' },
      { kind: 'ip', value: '10.0.0.1', note: 'VirusTotal resolution, last seen 2025-11-24' },
      { kind: 'ip', value: '93.184.216.34', note: 'VirusTotal resolution, last seen 2024-05-18' },
    ]);

    // Compact and serialisable: no whois, no raw engine results, no key.
    const serialised = JSON.stringify(d);
    expect(JSON.parse(serialised)).toEqual(d);
    expect(serialised).not.toContain('whois');
    expect(serialised).not.toContain('Registry Domain ID');
    expect(serialised).not.toContain(KEY);
    expect(JSON.stringify(out)).not.toContain(KEY);

    expect(fact(facts, 'Detections')).toEqual({ label: 'Detections', value: '0/94 malicious', tone: 'good' });
    expect(fact(facts, 'Engine breakdown')?.value).toBe('66 harmless · 28 undetected · 0 timeout');
    expect(fact(facts, 'Reputation')?.value).toMatch(/^0 /);
    expect(fact(facts, 'Reputation')?.tone).toBeUndefined();
    expect(values(fact(facts, 'Categories'))).toEqual(d.categories);
    expect(fact(facts, 'Registrar')?.value).toBe('RESERVED-Internet Assigned Numbers Authority');
    expect(fact(facts, 'Created')?.value).toBe('1992-01-01');
    expect(fact(facts, 'Last analysis')?.value).toBe('2026-11-18');
    const res = fact(facts, 'Resolutions');
    expect(res?.label).toBe('Resolutions · 18 total, 4 most recent shown');
    expect(res?.pivot).toBe(true);
    expect(values(res)[0]).toBe('93.184.215.14 (last 2026-11-18)');
    expect(fact(facts, 'Flagged by')).toBeUndefined();
    expect(fact(facts, 'VirusTotal')).toEqual({
      label: 'VirusTotal',
      value: 'https://www.virustotal.com/gui/domain/example.com',
      href: 'https://www.virustotal.com/gui/domain/example.com',
    });
    for (const f of facts) {
      if (f.href) expect(f.href.startsWith('https://')).toBe(true);
      expect(JSON.stringify(f)).not.toContain(KEY);
    }
  });

  it('normalises the domain (case, trailing dot) and URL-encodes it', async () => {
    const { calls, out } = await run(domain('Example.COM.'), [
      vtRoute({ '/domains/example.com': DOMAIN_CLEAN, '/domains/example.com/resolutions': { data: [], meta: { count: 0 }, links: {} } }),
    ]);
    expect(calls[0]!.url).toBe(`${API}/domains/example.com`);
    expect(out.data.indicator).toBe('example.com');
    expect(out.data.resolutions).toEqual([]);
    expect(out.data.resolutionsTotal).toBe(0);
    expect(out.data.resolutionsTruncated).toBe(false);
    expect(out.pivots).toBeUndefined();
    expect(out.summary).toBe('0/94 malicious · reputation 0 · 0 resolutions');

    const m = mockFetch(() => json(DOMAIN_CLEAN));
    await virustotalModule.run(domain('a b/../c?.com'), makeCtx({ fetch: m.fetch, keys: { virustotal: KEY } }));
    expect(m.calls[0]!.url).toBe(`${API}/domains/a%20b%2F..%2Fc%3F.com`);
  });

  it('flags a malicious domain: high severity, engines listed, tone bad', async () => {
    const { out, facts } = await run(domain('secure-login-verify.top'), [
      vtRoute({
        '/domains/secure-login-verify.top': DOMAIN_MALICIOUS,
        '/domains/secure-login-verify.top/resolutions': {
          meta: { count: 1 },
          data: [resolution('203.0.113.7', 1795000000, 'secure-login-verify.top')],
          links: { self: '…' },
        },
      }),
    ]);
    const d = out.data;
    expect(out.severity).toBe('high');
    expect(out.summary).toBe('7/94 malicious · 2 suspicious · reputation -12 · 1 resolution');
    expect(d.categories).toEqual(['Phishing and Other Frauds', 'phishing']);
    expect(d.tags).toEqual(['phishing', 'dga']);
    expect(d.votes).toEqual({ harmless: 0, malicious: 4 });
    expect(d.registrar).toBeUndefined();
    expect(d.creationDate).toBe('2026-09-21T14:13:20.000Z');
    // Malicious first, then alphabetical; harmless engines left out.
    expect(d.flaggedBy.map((h) => `${h.engine}:${h.category}`)).toEqual([
      'BitDefender:malicious',
      'CRDF:malicious',
      'ESET:malicious',
      'Fortinet:malicious',
      'G-Data:malicious',
      'Sophos:malicious',
      'Webroot:malicious',
      'Kaspersky:suspicious',
      'Quttera:suspicious',
    ]);
    expect(d.resolutionsTruncated).toBe(false);
    expect(out.pivots).toEqual([{ kind: 'ip', value: '203.0.113.7', note: 'VirusTotal resolution, last seen 2026-11-18' }]);

    expect(fact(facts, 'Detections')).toEqual({ label: 'Detections', value: '7/94 malicious, 2 suspicious', tone: 'bad' });
    const flagged = fact(facts, 'Flagged by');
    expect(flagged?.tone).toBe('bad');
    expect(values(flagged)).toContain('BitDefender: malware (malicious)');
    expect(values(flagged)).toContain('CRDF: malicious');
    expect(values(flagged)).toContain('Kaspersky: suspicious');
    expect(fact(facts, 'Reputation')?.tone).toBe('warn');
    expect(fact(facts, 'Community votes')).toEqual({ label: 'Community votes', value: '4 malicious · 0 harmless', tone: 'warn' });
    expect(values(fact(facts, 'Tags'))).toEqual(['phishing', 'dga']);
    expect(fact(facts, 'Resolutions')?.label).toBe('Resolutions · 1 total');
  });

  it('medium and low severities from the stats', async () => {
    const withStats = (malicious: number, suspicious: number) => ({
      data: { attributes: { last_analysis_stats: { malicious, suspicious, harmless: 60, undetected: 30, timeout: 1 }, reputation: -1 } },
    });
    const empty = { data: [], meta: { count: 0 }, links: {} };
    const one = await run(domain('a.example'), [vtRoute({ '/domains/a.example': withStats(1, 0), '/domains/a.example/resolutions': empty })]);
    expect(one.out.severity).toBe('medium');
    expect(one.out.summary).toBe('1/92 malicious · reputation -1 · 0 resolutions');
    const sus = await run(domain('b.example'), [vtRoute({ '/domains/b.example': withStats(0, 3), '/domains/b.example/resolutions': empty })]);
    expect(sus.out.severity).toBe('medium');
    const low = await run(domain('c.example'), [vtRoute({ '/domains/c.example': withStats(0, 1), '/domains/c.example/resolutions': empty })]);
    expect(low.out.severity).toBe('low');
    expect(fact(low.facts, 'Detections')).toEqual({ label: 'Detections', value: '0/92 malicious, 1 suspicious', tone: 'warn' });
  });

  it('404 NotFoundError: found:false, severity none, no resolutions call', async () => {
    const { out, calls, facts } = await run(domain('nx-7f3a9.example'), [
      vtRoute({ '/domains/nx-7f3a9.example': () => NOT_FOUND('Domain "nx-7f3a9.example"') }),
    ]);
    expect(calls).toHaveLength(1);
    expect(out.data.found).toBe(false);
    expect(out.data.stats).toBeNull();
    expect(out.data.reputation).toBeNull();
    expect(out.data.resolutions).toEqual([]);
    // Not queried, so unknown rather than zero.
    expect(out.data.resolutionsTotal).toBeNull();
    expect(out.data.guiUrl).toBe('https://www.virustotal.com/gui/domain/nx-7f3a9.example');
    expect(out.severity).toBe('none');
    expect(out.summary).toBe('Not in VirusTotal');
    expect(out.pivots).toBeUndefined();
    expect(fact(facts, 'Status')?.value).toMatch(/^Not in VirusTotal/);
    expect(fact(facts, 'Detections')).toBeUndefined();
    expect(fact(facts, 'Resolutions')).toBeUndefined();
    expect(fact(facts, 'VirusTotal')?.href).toBe('https://www.virustotal.com/gui/domain/nx-7f3a9.example');
  });

  it('a 404 with a non-JSON body still means not found', async () => {
    const { out } = await run(domain('nx.example'), [vtRoute({ '/domains/nx.example': () => text('<html>Not Found</html>', 404) })]);
    expect(out.data.found).toBe(false);
    expect(out.severity).toBe('none');
  });

  it('resolutions 404 -> empty list', async () => {
    const { out } = await run(domain(), [
      vtRoute({ '/domains/example.com': DOMAIN_CLEAN, '/domains/example.com/resolutions': () => NOT_FOUND('Domain "example.com"') }),
    ]);
    expect(out.data.found).toBe(true);
    expect(out.data.resolutions).toEqual([]);
    expect(out.data.resolutionsTotal).toBe(0);
    expect(out.pivots).toBeUndefined();
  });

  it('resolutions failure keeps the verdict and records the error', async () => {
    const { out, facts } = await run(domain(), [
      vtRoute({
        '/domains/example.com': DOMAIN_CLEAN,
        '/domains/example.com/resolutions': () => vtErr('TransientError', 'Please try again later', 503),
      }),
    ]);
    expect(out.data.found).toBe(true);
    expect(out.severity).toBe('none');
    expect(out.data.resolutions).toEqual([]);
    expect(out.data.resolutionsTotal).toBeNull();
    expect(out.data.resolutionsError).toMatch(/temporarily unavailable/);
    expect(out.summary).toBe('0/94 malicious · reputation 0 · resolutions unavailable');
    expect(out.pivots).toBeUndefined();
    expect(fact(facts, 'Resolutions')?.tone).toBe('warn');
  });

  it('a cancel during the resolutions call propagates instead of becoming resolutionsError', async () => {
    const ac = new AbortController();
    const m = mockFetch(
      vtRoute({
        '/domains/example.com': DOMAIN_CLEAN,
        '/domains/example.com/resolutions': () => {
          ac.abort();
          throw new DOMException('The operation was aborted.', 'AbortError');
        },
      }),
    );
    const ctx = makeCtx({ fetch: m.fetch, keys: { virustotal: KEY }, signal: ac.signal });
    const err = await virustotalModule.run(domain(), ctx).then(fail, (x: unknown) => x);
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).kind).toBe('aborted');
    expect(m.calls).toHaveLength(2);
  });

  it('all-zero stats (object exists, no engine has scanned it) is "no analysis yet", not clean', async () => {
    const unscanned = {
      data: {
        attributes: {
          last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 },
          reputation: 0,
          last_analysis_results: {},
        },
      },
    };
    const { out, facts } = await run(domain('fresh.example'), [
      vtRoute({ '/domains/fresh.example': unscanned, '/domains/fresh.example/resolutions': { data: [], meta: { count: 0 } } }),
    ]);
    expect(out.data.found).toBe(true);
    expect(out.data.stats).toEqual({ malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 });
    expect(out.data.engines).toBe(0);
    expect(out.severity).toBe('none');
    expect(out.summary).toBe('no analysis yet · reputation 0 · 0 resolutions');
    expect(out.summary).not.toContain('0/0');
    expect(fact(facts, 'Detections')).toEqual({ label: 'Detections', value: 'No analysis yet' });
    expect(fact(facts, 'Engine breakdown')).toBeUndefined();
  });

  it('malformed resolutions payload -> resolutionsError, no pivots', async () => {
    const { out } = await run(domain(), [
      vtRoute({ '/domains/example.com': DOMAIN_CLEAN, '/domains/example.com/resolutions': { data: 'nope' } }),
    ]);
    expect(out.data.resolutionsError).toMatch(/no data array/);
    expect(out.pivots).toBeUndefined();
  });

  it('caps resolutions and reports "N+" when VirusTotal gives no count', async () => {
    const many = Array.from({ length: 60 }, (_, i) => resolution(`198.51.${Math.floor(i / 250)}.${(i % 250) + 1}`, 1795000000 - i * 3600));
    const { out, facts } = await run(domain(), [
      vtRoute({
        '/domains/example.com': DOMAIN_CLEAN,
        '/domains/example.com/resolutions': { data: many, links: { next: `${API}/domains/example.com/resolutions?cursor=x` } },
      }),
    ]);
    expect(out.data.resolutions).toHaveLength(RESOLUTIONS_LIMIT);
    expect(out.data.resolutions[0]!.ip).toBe('198.51.0.1');
    expect(out.data.resolutionsTotal).toBeNull();
    expect(out.data.resolutionsTruncated).toBe(true);
    expect(out.pivots).toHaveLength(RESOLUTIONS_LIMIT);
    expect(out.summary).toBe(`0/94 malicious · reputation 0 · ${RESOLUTIONS_LIMIT}+ resolutions`);
    expect(fact(facts, 'Resolutions')?.label).toBe(`Resolutions · ${RESOLUTIONS_LIMIT}+ total, ${RESOLUTIONS_LIMIT} most recent shown`);
  });

  it('parses junk attributes defensively and caps lists', async () => {
    const attrs = {
      last_analysis_stats: { malicious: 'lots', suspicious: null },
      reputation: 'bad',
      categories: Object.fromEntries([
        ...Array.from({ length: 30 }, (_, i) => [`Vendor${i}`, `category ${i}`]),
        ['Broken', 42],
      ]),
      tags: Array.from({ length: 50 }, (_, i) => (i === 3 ? { nope: 1 } : `tag-${i}`)),
      creation_date: -5,
      last_analysis_date: 'yesterday',
      registrar: 12,
      total_votes: 'many',
      last_analysis_results: Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`E${String(i).padStart(2, '0')}`, engine(`E${String(i).padStart(2, '0')}`, 'malicious', 'x')])),
    };
    const { out, facts } = await run(domain(), [
      vtRoute({ '/domains/example.com': { data: { attributes: attrs } }, '/domains/example.com/resolutions': { data: [] } }),
    ]);
    const d = out.data;
    expect(d.found).toBe(true);
    expect(d.stats).toBeNull();
    expect(d.engines).toBe(0);
    expect(d.reputation).toBeNull();
    expect(d.votes).toBeNull();
    expect(d.categories).toHaveLength(MAX_CATEGORIES);
    expect(d.tags).toHaveLength(MAX_TAGS);
    expect(d.tags).not.toContain('tag-3');
    expect(d.flaggedBy).toHaveLength(MAX_FLAGGED);
    expect(d.creationDate).toBeUndefined();
    expect(d.lastAnalysisDate).toBeUndefined();
    expect(d.registrar).toBeUndefined();
    expect(d.resolutionsTotal).toBeNull();
    expect(d.resolutionsTruncated).toBe(false);
    expect(out.severity).toBe('none');
    expect(out.summary).toBe('no analysis yet · 0 resolutions');
    expect(fact(facts, 'Detections')?.value).toBe('No analysis yet');
  });

  it('missing data.attributes is a parse error', async () => {
    const { err } = await runError(domain(), [vtRoute({ '/domains/example.com': {} })]);
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).kind).toBe('parse');
    expect(err.message).toMatch(/Unexpected response from VirusTotal/);
  });

  it('invalid JSON is a parse error', async () => {
    const { err } = await runError(domain(), [vtRoute({ '/domains/example.com': () => text('<html>oops</html>', 200) })]);
    expect((err as FetchError).kind).toBe('parse');
  });
});

describe('virustotal IP lookup', () => {
  it('IPv4: one call, AS/country/network fields, GUI link', async () => {
    const { out, calls, facts } = await run(ip('8.8.8.8'), [vtRoute({ '/ip_addresses/8.8.8.8': IP_GOOGLE })]);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(`${API}/ip_addresses/8.8.8.8`);
    expect(headers(calls[0]!.init)['x-apikey']).toBe(KEY);

    const d = out.data;
    expect(d.kind).toBe('ip');
    expect(d.found).toBe(true);
    expect(d.asOwner).toBe('GOOGLE');
    expect(d.asn).toBe(15169);
    expect(d.country).toBe('US');
    expect(d.network).toBe('8.8.8.0/24');
    expect(d.reputation).toBe(571);
    expect(d.registrar).toBeUndefined();
    expect(d.resolutions).toEqual([]);
    expect(d.resolutionsTotal).toBeNull();
    expect(d.guiUrl).toBe('https://www.virustotal.com/gui/ip-address/8.8.8.8');
    expect(JSON.stringify(d)).not.toContain('NetRange');
    expect(out.pivots).toBeUndefined();
    expect(out.severity).toBe('none');
    expect(out.summary).toBe('0/94 malicious · reputation 571 · AS15169 GOOGLE');

    expect(fact(facts, 'AS')?.value).toBe('AS15169 GOOGLE');
    expect(fact(facts, 'Network')?.value).toBe('8.8.8.0/24');
    expect(fact(facts, 'Country')?.value).toBe('US');
    expect(fact(facts, 'Resolutions')).toBeUndefined();
    expect(fact(facts, 'Community votes')?.tone).toBeUndefined();
    expect(fact(facts, 'VirusTotal')?.href).toBe('https://www.virustotal.com/gui/ip-address/8.8.8.8');
  });

  it('IPv6: canonical form with raw colons in the path', async () => {
    const { out, calls, facts } = await run(ip('2001:4860:4860:0:0:0:0:8888'), [
      vtRoute({ '/ip_addresses/2001:4860:4860::8888': IP6 }),
    ]);
    expect(calls[0]!.url).toBe(`${API}/ip_addresses/2001:4860:4860::8888`);
    expect(out.data.indicator).toBe('2001:4860:4860::8888');
    expect(out.data.network).toBe('2001:4860::/32');
    expect(out.data.flaggedBy).toEqual([{ engine: 'CRDF', category: 'malicious', result: 'malicious' }]);
    expect(out.severity).toBe('medium');
    expect(out.summary).toBe('1/94 malicious · reputation 0 · AS15169 GOOGLE');
    expect(fact(facts, 'VirusTotal')?.href).toBe('https://www.virustotal.com/gui/ip-address/2001:4860:4860::8888');
  });

  it('IP not in VirusTotal', async () => {
    const { out, facts } = await run(ip('198.51.100.77'), [
      vtRoute({ '/ip_addresses/198.51.100.77': () => NOT_FOUND('Resource "198.51.100.77"') }),
    ]);
    expect(out.data.found).toBe(false);
    expect(out.severity).toBe('none');
    expect(out.summary).toBe('Not in VirusTotal');
    expect(fact(facts, 'Status')?.value).toMatch(/IP address/);
  });

  it('an invalid IP entity is skipped without a request', async () => {
    const { err, calls } = await runError(ip('not-an-ip'), []);
    expect(err).toBeInstanceOf(SkipError);
    expect(calls).toHaveLength(0);
  });
});

describe('virustotal errors', () => {
  it('401 WrongCredentialsError -> invalid key message without the key', async () => {
    const { err } = await runError(domain(), [vtRoute({ '/domains/example.com': () => vtErr('WrongCredentialsError', 'Wrong API key', 401) })]);
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).status).toBe(401);
    expect(err.message).toBe('VirusTotal rejected the API key (WrongCredentialsError: Wrong API key). Check it in settings.');
    expect(err.message).not.toContain(KEY);
    expect((err as FetchError).body).toBeUndefined();
  });

  it('an error body echoing the key is redacted', async () => {
    const { err } = await runError(ip('8.8.8.8'), [
      vtRoute({ '/ip_addresses/8.8.8.8': () => vtErr('WrongCredentialsError', `Wrong API key ${KEY}`, 401) }),
    ]);
    expect(err.message).not.toContain(KEY);
    expect(err.message).toContain('[key]');
    // A key straddling the 160-char detail cut must not leak partially either.
    const long = await runError(ip('8.8.8.8'), [
      vtRoute({ '/ip_addresses/8.8.8.8': () => vtErr('ForbiddenError', `${'x'.repeat(130)} ${KEY}`, 403) }),
    ]);
    expect(long.err.message).not.toContain(KEY.slice(0, 20));
  });

  it('other 401 codes', () => {
    const body = (code: string, msg: string) => JSON.stringify({ error: { code, message: msg } });
    expect(vtErrorMessage(401, body('AuthenticationRequiredError', 'X-Apikey header is missing'))).toMatch(/did not receive an API key/);
    expect(vtErrorMessage(401, body('UserNotActiveError', 'User is not active'))).toMatch(/not active/);
    expect(vtErrorMessage(401, undefined)).toMatch(/rejected the API key \(HTTP 401\)/);
    expect(vtErrorMessage(400, body('InvalidArgumentError', 'Invalid domain'))).toBe('VirusTotal rejected the lookup (InvalidArgumentError: Invalid domain).');
    expect(vtErrorMessage(500, '<html>')).toBe('VirusTotal error (HTTP 500).');
  });

  it('403 ForbiddenError', async () => {
    const { err } = await runError(ip('8.8.8.8'), [
      vtRoute({ '/ip_addresses/8.8.8.8': () => vtErr('ForbiddenError', 'You are not allowed to perform the requested operation', 403) }),
    ]);
    expect((err as FetchError).status).toBe(403);
    expect(err.message).toMatch(/^VirusTotal refused access \(ForbiddenError/);
  });

  it('429 QuotaExceededError (no limiter) -> quota message', async () => {
    const { err } = await runError(domain(), [vtRoute({ '/domains/example.com': () => vtErr('QuotaExceededError', 'Quota exceeded', 429) })]);
    expect((err as FetchError).status).toBe(429);
    expect(err.message).toMatch(/quota exceeded \(QuotaExceededError\)/);
    expect(err.message).toMatch(/4 lookups\/min and 500\/day/);
    expect(err.message).toMatch(/00:00 UTC/);
  });

  it('429 after the automatic retry through the 4/min bucket -> quota message', async () => {
    const m = mockFetch(vtRoute({ '/domains/example.com': () => vtErr('QuotaExceededError', 'Quota exceeded', 429, { 'retry-after': '1' }) }));
    const err = await virustotalModule.run(domain(), limitedCtx(m.fetch)).then(fail, (x: unknown) => x as Error);
    expect(m.calls).toHaveLength(2); // original + one automatic retry
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).status).toBe(429);
    expect((err as Error).message).toMatch(/quota exceeded/);
  });

  it('a single 429 is retried transparently', async () => {
    let n = 0;
    const m = mockFetch(
      vtRoute({
        '/ip_addresses/8.8.8.8': () => (n++ === 0 ? vtErr('TooManyRequestsError', 'Too many requests', 429, { 'retry-after': '2' }) : json(IP_GOOGLE)),
      }),
    );
    const out = await virustotalModule.run(ip('8.8.8.8'), limitedCtx(m.fetch));
    expect(m.calls).toHaveLength(2);
    expect(out.data.found).toBe(true);
  });

  it('TooManyRequestsError message', () => {
    expect(vtErrorMessage(429, JSON.stringify({ error: { code: 'TooManyRequestsError', message: 'x' } }))).toMatch(/rate limiting/);
  });

  it('a missing key is a skip (defensive), a key with bad characters an error; no request either way', async () => {
    const none = await runError(domain(), [], {});
    expect(none.err).toBeInstanceOf(SkipError);
    expect(none.calls).toHaveLength(0);
    const bad = await runError(domain(), [], { virustotal: 'abc\ndef' });
    expect(bad.err.message).toMatch(/invalid characters/);
    expect(bad.err.message).not.toContain('abc');
    expect(bad.calls).toHaveLength(0);
  });
});

describe('virustotal in the orchestrator', () => {
  function collector() {
    const cards = new Map<string, CardState>();
    const events: RunEvent[] = [];
    const emit = (e: RunEvent) => {
      events.push(e);
      if (e.type === 'card') cards.set(e.card.id, e.card);
    };
    return { cards, events, emit };
  }

  function deps(fetchImpl: typeof fetch, key: string | undefined): OrchestratorDeps {
    return {
      modules: [virustotalModule as Module],
      isEnabled: () => true,
      allowActive: false,
      cache: memoryCache(),
      limiter: new RateLimiter(fakeClock()),
      settings: DEFAULT_SETTINGS,
      getKey: async (p) => (p === 'virustotal' ? key : undefined),
      fetch: fetchImpl,
    };
  }

  it('resolutions pivot to public IPs, which get their own VirusTotal cards', async () => {
    const m = mockFetch(
      vtRoute({
        '/domains/example.com': DOMAIN_CLEAN,
        '/domains/example.com/resolutions': {
          meta: { count: 3 },
          data: [resolution('8.8.8.8', 1795000000), resolution('10.0.0.1', 1790000000), resolution('2001:4860:4860::8888', 1716000000)],
          links: {},
        },
        '/ip_addresses/8.8.8.8': IP_GOOGLE,
        '/ip_addresses/2001:4860:4860::8888': IP6,
      }),
    );
    const c = collector();
    const { done } = investigate({ kind: 'domain', value: 'example.com' }, c.emit, deps(m.fetch, KEY));
    await done;

    const root = c.cards.get(cardId('virustotal', { kind: 'domain', value: 'example.com' }));
    expect(root?.status).toBe('ok');
    expect(root?.severity).toBe('none');
    expect(root?.summary).toBe('0/94 malicious · reputation 0 · 3 resolutions');
    expect(c.cards.get(cardId('virustotal', { kind: 'ip', value: '8.8.8.8' }))?.status).toBe('ok');
    const v6 = c.cards.get(cardId('virustotal', { kind: 'ip', value: '2001:4860:4860::8888' }));
    expect(v6?.status).toBe('ok');
    expect(v6?.severity).toBe('medium');
    // Private IPs are listed as pivots but not investigated.
    expect(c.cards.has(cardId('virustotal', { kind: 'ip', value: '10.0.0.1' }))).toBe(false);
    expect(m.calls).toHaveLength(4);
    for (const call of m.calls) expect(headers(call.init)['x-apikey']).toBe(KEY);
    expect((root?.data as VtData).resolutions).toHaveLength(3);
  });

  it('is skipped with a hint when no key is set', async () => {
    const m = mockFetch();
    const c = collector();
    await investigate({ kind: 'domain', value: 'example.com' }, c.emit, deps(m.fetch, undefined)).done;
    const card = c.cards.get(cardId('virustotal', { kind: 'domain', value: 'example.com' }));
    expect(card?.status).toBe('skipped');
    expect(card?.skip?.reason).toBe('no-key');
    expect(m.calls).toHaveLength(0);
  });
});

describe('virustotalKeyTest', () => {
  const http = (fetchImpl: typeof fetch) => createHttp({ fetch: fetchImpl, limiter: new RateLimiter(), signal: new AbortController().signal });
  const quotasRoute = (res: () => Response): Route => (u) =>
    u.host === 'www.virustotal.com' && u.pathname === `/api/v3/users/${KEY}/overall_quotas` ? res() : undefined;

  it('calls overall_quotas (no quota cost) with x-apikey and summarises the daily quota', async () => {
    const m = mockFetch(quotasRoute(() => json(QUOTAS)));
    const msg = await virustotalKeyTest(`  ${KEY}\n`, http(m.fetch));
    expect(m.calls).toHaveLength(1);
    expect(m.calls[0]!.url).toBe(`${API}/users/${KEY}/overall_quotas`);
    expect(headers(m.calls[0]!.init)['x-apikey']).toBe(KEY);
    expect(m.calls[0]!.init.method).toBe('GET');
    expect(msg).toBe('Key accepted by VirusTotal: 12 of 500 daily requests used (488 left; resets 00:00 UTC).');
    expect(msg).not.toContain(KEY);
  });

  it('falls back to the group quota, then to a plain success message', async () => {
    const group = { data: { api_requests_daily: { user: { used: 5 }, group: { allowed: 99000000, used: 45073, inherited_from: 'company' } } } };
    const m1 = mockFetch(quotasRoute(() => json(group)));
    expect(await virustotalKeyTest(KEY, http(m1.fetch))).toMatch(/45073 of 99000000 daily requests used/);
    const m2 = mockFetch(quotasRoute(() => json({ data: {} })));
    expect(await virustotalKeyTest(KEY, http(m2.fetch))).toBe('Key accepted by VirusTotal.');
    const m3 = mockFetch(quotasRoute(() => text('', 200, 'application/json')));
    expect(await virustotalKeyTest(KEY, http(m3.fetch))).toBe('Key accepted by VirusTotal.');
    // Group-inherited keys report user.allowed = 0: use the group allowance, never "0 of 0".
    const inherited = { data: { api_requests_daily: { user: { allowed: 0, used: 7 }, group: { allowed: 1000, used: 250, inherited_from: 'org' } } } };
    const m4 = mockFetch(quotasRoute(() => json(inherited)));
    expect(await virustotalKeyTest(KEY, http(m4.fetch))).toBe(
      'Key accepted by VirusTotal: 250 of 1000 daily requests used (750 left; resets 00:00 UTC).',
    );
    const zero = { data: { api_requests_daily: { user: { allowed: 0, used: 0 }, group: { allowed: 0, used: 0 } } } };
    const m5 = mockFetch(quotasRoute(() => json(zero)));
    expect(await virustotalKeyTest(KEY, http(m5.fetch))).toBe('Key accepted by VirusTotal.');
  });

  it('401 -> clear invalid-key message, as a plain Error without the key', async () => {
    const m = mockFetch(quotasRoute(() => vtErr('WrongCredentialsError', 'Wrong API key', 401)));
    const err = await virustotalKeyTest(KEY, http(m.fetch)).then(fail, (x: unknown) => x as Error);
    expect(err).toBeInstanceOf(Error);
    expect(err).not.toBeInstanceOf(FetchError); // FetchError carries the URL, which contains the key
    expect(err.message).toMatch(/rejected the API key/);
    expect(err.message).not.toContain(KEY);
  });

  it('404 echoing the key is redacted', async () => {
    const m = mockFetch(quotasRoute(() => vtErr('NotFoundError', `User "${KEY}" not found`, 404)));
    const err = await virustotalKeyTest(KEY, http(m.fetch)).then(fail, (x: unknown) => x as Error);
    expect(err.message).toBe('VirusTotal does not recognise this API key (user not found).');
    const m2 = mockFetch(quotasRoute(() => vtErr('ForbiddenError', `Key ${KEY} is not allowed`, 403)));
    const err2 = await virustotalKeyTest(KEY, http(m2.fetch)).then(fail, (x: unknown) => x as Error);
    expect(err2.message).toMatch(/refused access/);
    expect(err2.message).not.toContain(KEY);
    expect(err2.message).toContain('[key]');
  });

  it('quota and network errors are redacted too', async () => {
    const m = mockFetch(quotasRoute(() => vtErr('QuotaExceededError', 'Quota exceeded', 429)));
    expect((await virustotalKeyTest(KEY, http(m.fetch)).then(fail, (x: unknown) => x as Error)).message).toMatch(/quota exceeded/);
    const net = mockFetch(() => {
      throw new TypeError(`NetworkError when attempting to fetch ${API}/users/${KEY}/overall_quotas`);
    });
    const err = await virustotalKeyTest(KEY, http(net.fetch)).then(fail, (x: unknown) => x as Error);
    expect(err.message).toMatch(/^Network error/);
    expect(err.message).not.toContain(KEY);
  });

  it('redacts the URL-encoded form of the key as well (it is what the request URL carries)', async () => {
    const odd = 'abc/def+ghi=jkl';
    const encoded = encodeURIComponent(odd);
    expect(encoded).not.toBe(odd);
    const net = mockFetch((u) => {
      throw new TypeError(`NetworkError when attempting to fetch ${u.href}`);
    });
    const err = await virustotalKeyTest(odd, http(net.fetch)).then(fail, (x: unknown) => x as Error);
    expect(net.calls[0]!.url).toBe(`${API}/users/${encoded}/overall_quotas`);
    expect(err.message).not.toContain(encoded);
    expect(err.message).not.toContain(odd);
    expect(err.message).toContain('[key]');
  });

  it('rejects empty and non-ASCII keys without a request', async () => {
    const m = mockFetch();
    await expect(virustotalKeyTest('   ', http(m.fetch))).rejects.toThrow(/Enter a VirusTotal API key/);
    await expect(virustotalKeyTest('clé', http(m.fetch))).rejects.toThrow(/invalid characters/);
    expect(m.calls).toHaveLength(0);
  });
});
