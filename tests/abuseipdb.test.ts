import { describe, expect, it } from 'vitest';
import { FetchError, createHttp } from '@/lib/http';
import { investigate, type OrchestratorDeps } from '@/lib/orchestrator';
import { RateLimiter, type Clock } from '@/lib/ratelimit';
import { DEFAULT_SETTINGS } from '@/lib/settings';
import type { CardState, Ctx, Entity, Fact, Module, RunEvent } from '@/lib/types';
import { HOUR, MINUTE, SkipError } from '@/lib/types';
import {
  MAX_HOSTNAMES,
  abuseipdbFacts,
  abuseipdbKeyTest,
  abuseipdbModule,
  abuseipdbSeverity,
  parseCheck,
  type AbuseIpdbData,
} from '@/modules/abuseipdb';
import { json, makeCtx, mockFetch, text, memoryCache, type Route } from './helpers';

const KEY = 'c0ffee1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678';
const API = 'https://api.abuseipdb.com/api/v2/check';
const NOW = Date.parse('2026-11-25T17:00:00Z');
const ip = (value: string): Entity => ({ kind: 'ip', value, depth: 1 });
const header = (init: RequestInit, name: string) => new Headers(init.headers).get(name);

// ---------------------------------------------------------------------------
// Fixtures shaped like the live API (docs/research/threat-intel.md §10)

const TOR_EXIT = {
  data: {
    ipAddress: '185.220.101.45',
    isPublic: true,
    ipVersion: 4,
    isWhitelisted: false,
    abuseConfidenceScore: 87,
    countryCode: 'DE',
    usageType: 'Fixed Line ISP',
    isp: 'Stiftung Erneuerbare Freiheit',
    domain: 'for-privacy.net',
    hostnames: ['tor-exit-45.for-privacy.net'],
    isTor: true,
    totalReports: 412,
    numDistinctUsers: 96,
    lastReportedAt: '2026-11-20T14:03:11+00:00',
  },
};

/** The research notes' example response, verbatim. */
const RESEARCH_EXAMPLE = {
  data: {
    ipAddress: '118.25.6.39',
    isPublic: true,
    ipVersion: 4,
    isWhitelisted: false,
    abuseConfidenceScore: 100,
    countryCode: 'CN',
    usageType: 'Data Center/Web Hosting/Transit',
    isp: 'Tencent Cloud Computing (Beijing) Co. Ltd',
    domain: 'tencent.com',
    hostnames: [],
    isTor: false,
    totalReports: 1,
    numDistinctUsers: 1,
    lastReportedAt: '2018-12-20T20:55:14+00:00',
  },
};

const WHITELISTED = {
  data: {
    ipAddress: '1.1.1.1',
    isPublic: true,
    ipVersion: 4,
    isWhitelisted: true,
    abuseConfidenceScore: 0,
    countryCode: 'AU',
    usageType: 'Content Delivery Network',
    isp: 'APNIC and Cloudflare DNS Resolver project',
    domain: 'cloudflare.com',
    hostnames: ['one.one.one.one'],
    isTor: false,
    totalReports: 112,
    numDistinctUsers: 38,
    lastReportedAt: '2026-11-24T09:12:40+00:00',
  },
};

const UNREPORTED = {
  data: {
    ipAddress: '93.184.216.34',
    isPublic: true,
    ipVersion: 4,
    isWhitelisted: false,
    abuseConfidenceScore: 0,
    countryCode: 'US',
    usageType: 'Content Delivery Network',
    isp: 'Edgecast Inc.',
    domain: 'edgecast.com',
    hostnames: [],
    isTor: false,
    totalReports: 0,
    numDistinctUsers: 0,
    lastReportedAt: null,
  },
};

const IPV6 = '2a01:4f8:c17:b8f::2';
const IPV6_RESULT = {
  data: {
    ipAddress: IPV6,
    isPublic: true,
    ipVersion: 6,
    isWhitelisted: false,
    abuseConfidenceScore: 34,
    countryCode: 'DE',
    usageType: 'Data Center/Web Hosting/Transit',
    isp: 'Hetzner Online GmbH',
    domain: 'hetzner.com',
    hostnames: ['static.2.0.0.0.0.0.0.0.0.0.0.0.f.8.b.0.7.1.c.0.8.f.4.0.1.0.a.2.ip6.arpa'],
    isTor: false,
    totalReports: 9,
    numDistinctUsers: 5,
    lastReportedAt: '2026-11-02T03:44:19+00:00',
  },
};

const ERR_401 = {
  errors: [
    {
      detail: 'Authentication failed. Your API key is either missing, incorrect, or revoked. Note: The APIv2 key differs from the APIv1 key.',
      status: 401,
    },
  ],
};
const ERR_422 = {
  errors: [
    {
      detail: 'The ip address must be a valid IPv4 or IPv6 address (e.g. 8.8.8.8 or 2001:4860:4860::8888).',
      status: 422,
      source: { parameter: 'ipAddress' },
    },
  ],
};
const ERR_429 = {
  errors: [{ detail: 'Daily rate limit of 1000 requests exceeded for this endpoint. See headers for additional details.', status: 429 }],
};
/** Midnight UTC, 7 h after NOW. */
const RESET_EPOCH = String(Date.parse('2026-11-26T00:00:00Z') / 1000);
const quotaHeaders = (retryAfter = '25200') => ({
  'X-RateLimit-Limit': '1000',
  'X-RateLimit-Remaining': '0',
  'X-RateLimit-Reset': RESET_EPOCH,
  'Retry-After': retryAfter,
});

/** Answers check requests by ipAddress (each value builds a fresh Response). */
function abuseRoute(map: Record<string, () => Response>): Route {
  return (url) => {
    if (`${url.origin}${url.pathname}` !== API) return undefined;
    return map[url.searchParams.get('ipAddress') ?? '']?.();
  };
}

const ctxFor = (f: typeof fetch, keys: Partial<Record<'abuseipdb', string>> = { abuseipdb: KEY }) => makeCtx({ fetch: f, keys, now: () => NOW });

async function runErr(e: Entity, ctx: Ctx): Promise<unknown> {
  return abuseipdbModule.run(e, ctx).then(
    () => {
      throw new Error('expected run() to fail');
    },
    (err: unknown) => err,
  );
}

function factMap(facts: Fact[]): Record<string, Fact> {
  return Object.fromEntries(facts.map((f) => [f.label, f]));
}

// ---------------------------------------------------------------------------

describe('abuseipdb module metadata', () => {
  it('matches the spec', () => {
    expect(abuseipdbModule.id).toBe('abuseipdb');
    expect(abuseipdbModule.label).toBe('AbuseIPDB');
    expect(abuseipdbModule.version).toBe(1);
    expect(abuseipdbModule.key).toBe('abuseipdb');
    expect(abuseipdbModule.keyOptional).toBeUndefined();
    expect(abuseipdbModule.accepts).toEqual(['ip']);
    expect(abuseipdbModule.ttl).toBe(24 * HOUR);
    expect(abuseipdbModule.rateLimit).toEqual({ perMinute: 30 });
  });
});

describe('abuseipdb check (IPv4)', () => {
  it('sends the documented request: Key + Accept headers, 90-day window, no credentials', async () => {
    const m = mockFetch(abuseRoute({ '185.220.101.45': () => json(TOR_EXIT) }));
    await abuseipdbModule.run(ip('185.220.101.45'), ctxFor(m.fetch));
    expect(m.calls).toHaveLength(1);
    const call = m.calls[0]!;
    expect(call.url).toBe(`${API}?ipAddress=185.220.101.45&maxAgeInDays=90`);
    expect(header(call.init, 'Key')).toBe(KEY);
    // Exactly one Accept value (not "application/json, application/json").
    expect(header(call.init, 'Accept')).toBe('application/json');
    expect(call.init.credentials).toBe('omit');
    expect(call.init.method).toBe('GET');
    // The key travels only in the header.
    expect(call.url).not.toContain(KEY);
  });

  it('malicious Tor exit -> high, compact data, spec summary', async () => {
    const m = mockFetch(abuseRoute({ '185.220.101.45': () => json(TOR_EXIT) }));
    const out = await abuseipdbModule.run(ip('185.220.101.45'), ctxFor(m.fetch));
    expect(out.severity).toBe('high');
    expect(out.summary).toBe('Confidence 87% · 412 reports from 96 users · last 2026-11-20 · Tor exit');
    expect(out.pivots).toBeUndefined();
    expect(out.data).toEqual<AbuseIpdbData>({
      ipAddress: '185.220.101.45',
      abuseConfidenceScore: 87,
      totalReports: 412,
      numDistinctUsers: 96,
      lastReportedAt: '2026-11-20T14:03:11.000Z',
      countryCode: 'DE',
      isp: 'Stiftung Erneuerbare Freiheit',
      domain: 'for-privacy.net',
      usageType: 'Fixed Line ISP',
      isWhitelisted: false,
      isTor: true,
      isPublic: true,
      hostnames: ['tor-exit-45.for-privacy.net'],
      hostnamesTotal: 1,
      maxAgeInDays: 90,
      guiUrl: 'https://www.abuseipdb.com/check/185.220.101.45',
    });
    expect(JSON.parse(JSON.stringify(out.data))).toEqual(out.data);
  });

  it('research example (1 old report, score 100) -> high', async () => {
    const m = mockFetch(abuseRoute({ '118.25.6.39': () => json(RESEARCH_EXAMPLE) }));
    const out = await abuseipdbModule.run(ip('118.25.6.39'), ctxFor(m.fetch));
    expect(out.severity).toBe('high');
    expect(out.summary).toBe('Confidence 100% · 1 report from 1 user · last 2018-12-20');
    expect(out.data.hostnames).toEqual([]);
    expect(out.data.lastReportedAt).toBe('2018-12-20T20:55:14.000Z');
  });

  it('never reported ("not found") -> data with zero counts, severity none', async () => {
    const m = mockFetch(abuseRoute({ '93.184.216.34': () => json(UNREPORTED) }));
    const out = await abuseipdbModule.run(ip('93.184.216.34'), ctxFor(m.fetch));
    expect(out.severity).toBe('none');
    expect(out.summary).toBe('No reports in the last 90 days');
    expect(out.data.totalReports).toBe(0);
    expect(out.data.lastReportedAt).toBeNull();
    const f = factMap(abuseipdbFacts(out.data));
    expect(f['Abuse confidence']).toEqual({ label: 'Abuse confidence', value: '0%', tone: 'good' });
    expect(f['Reports (90 days)']!.value).toBe('None');
    expect(f['Last reported']).toBeUndefined();
  });

  it('allow-listed address -> none even with reports, and says so', async () => {
    const m = mockFetch(abuseRoute({ '1.1.1.1': () => json(WHITELISTED) }));
    const out = await abuseipdbModule.run(ip('1.1.1.1'), ctxFor(m.fetch));
    expect(out.severity).toBe('none');
    expect(out.summary).toBe('Allow-listed by AbuseIPDB · Confidence 0% · 112 reports from 38 users · last 2026-11-24');
    const f = factMap(abuseipdbFacts(out.data));
    expect(f['Allow-listed']!.tone).toBe('good');
    expect(f['Abuse confidence']!.tone).toBeUndefined();
  });

  it('a score without reports in the window does not claim "0 reports from 0 users"', async () => {
    const lingering = { data: { ...UNREPORTED.data, abuseConfidenceScore: 12 } };
    const m = mockFetch(abuseRoute({ '93.184.216.34': () => json(lingering) }));
    const out = await abuseipdbModule.run(ip('93.184.216.34'), ctxFor(m.fetch));
    expect(out.severity).toBe('low');
    expect(out.summary).toBe('Confidence 12% · no reports in the last 90 days');
  });

  it('formats large counts with separators', async () => {
    const big = { data: { ...TOR_EXIT.data, isTor: false, totalReports: 12345, numDistinctUsers: 1001 } };
    const m = mockFetch(abuseRoute({ '185.220.101.45': () => json(big) }));
    const out = await abuseipdbModule.run(ip('185.220.101.45'), ctxFor(m.fetch));
    expect(out.summary).toBe('Confidence 87% · 12,345 reports from 1,001 users · last 2026-11-20');
  });
});

describe('abuseipdb check (IPv6)', () => {
  it('normalises, URL-encodes the address and builds an encoded GUI link', async () => {
    const m = mockFetch(abuseRoute({ [IPV6]: () => json(IPV6_RESULT) }));
    const out = await abuseipdbModule.run(ip('2A01:04F8:0C17:0B8F:0000:0000:0000:0002'), ctxFor(m.fetch));
    expect(m.calls[0]!.url).toBe(`${API}?ipAddress=2a01%3A4f8%3Ac17%3Ab8f%3A%3A2&maxAgeInDays=90`);
    expect(header(m.calls[0]!.init, 'Key')).toBe(KEY);
    expect(out.severity).toBe('medium');
    expect(out.summary).toBe('Confidence 34% · 9 reports from 5 users · last 2026-11-02');
    expect(out.data.ipAddress).toBe(IPV6);
    expect(out.data.guiUrl).toBe('https://www.abuseipdb.com/check/2a01%3A4f8%3Ac17%3Ab8f%3A%3A2');
    const link = abuseipdbFacts(out.data).find((f) => f.href);
    expect(link).toEqual({ label: 'AbuseIPDB', value: `abuseipdb.com/check/${IPV6}`, href: out.data.guiUrl });
  });

  it('checks an IPv4-mapped address as the IPv4 address it carries', async () => {
    const m = mockFetch(abuseRoute({ '185.220.101.45': () => json(TOR_EXIT) }));
    const out = await abuseipdbModule.run(ip('::ffff:185.220.101.45'), ctxFor(m.fetch));
    expect(m.calls[0]!.url).toBe(`${API}?ipAddress=185.220.101.45&maxAgeInDays=90`);
    expect(out.data.ipAddress).toBe('185.220.101.45');
    expect(out.severity).toBe('high');
  });

  it('still skips an IPv4-mapped private address', async () => {
    const m = mockFetch();
    expect(await runErr(ip('::ffff:10.0.0.1'), ctxFor(m.fetch))).toBeInstanceOf(SkipError);
    expect(m.calls).toHaveLength(0);
  });
});

describe('abuseipdb severity', () => {
  const sev = (abuseConfidenceScore: number, totalReports = 0, isWhitelisted: boolean | null = false) =>
    abuseipdbSeverity({ abuseConfidenceScore, totalReports, isWhitelisted });

  it('follows the thresholds', () => {
    expect(sev(100, 50)).toBe('high');
    expect(sev(75, 3)).toBe('high');
    expect(sev(74, 3)).toBe('medium');
    expect(sev(25, 1)).toBe('medium');
    expect(sev(24, 1)).toBe('low');
    expect(sev(1, 0)).toBe('low');
    expect(sev(0, 2)).toBe('low');
    expect(sev(0, 0)).toBe('none');
    expect(sev(0, 0, null)).toBe('none');
  });

  it('allow-listed wins over any score', () => {
    expect(sev(100, 400, true)).toBe('none');
  });

  it('fact tone tracks severity', () => {
    const base = parseCheck(TOR_EXIT, '185.220.101.45', API);
    const tone = (score: number) => abuseipdbFacts({ ...base, abuseConfidenceScore: score })[0]!.tone;
    expect(tone(90)).toBe('bad');
    expect(tone(30)).toBe('warn');
    expect(tone(5)).toBe('warn');
  });
});

describe('abuseipdb facts', () => {
  it('lists the useful fields as plain text with one https link', async () => {
    const m = mockFetch(abuseRoute({ '185.220.101.45': () => json(TOR_EXIT) }));
    const out = await abuseipdbModule.run(ip('185.220.101.45'), ctxFor(m.fetch));
    const facts = abuseipdbFacts(out.data);
    expect(facts.map((f) => f.label)).toEqual([
      'Abuse confidence',
      'Reports (90 days)',
      'Last reported',
      'Tor exit node',
      'Usage type',
      'ISP',
      'ISP domain',
      'Country',
      'Hostnames',
      'AbuseIPDB',
    ]);
    const f = factMap(facts);
    expect(f['Abuse confidence']).toEqual({ label: 'Abuse confidence', value: '87%', tone: 'bad' });
    expect(f['Reports (90 days)']!.value).toBe('412 from 96 distinct users');
    expect(f['Last reported']!.value).toBe('2026-11-20 14:03 UTC');
    expect(f['Tor exit node']!.tone).toBe('warn');
    expect(f['Hostnames']).toEqual({ label: 'Hostnames', value: ['tor-exit-45.for-privacy.net'], pivot: true });
    for (const fact of facts) {
      if (fact.href) expect(fact.href.startsWith('https://')).toBe(true);
    }
    expect(facts.filter((x) => x.href)).toHaveLength(1);
  });

  it('caps hostnames and reports the total', () => {
    const hostnames = Array.from({ length: 25 }, (_, i) => `host-${i}.example.net`);
    const d = parseCheck({ data: { ...TOR_EXIT.data, hostnames } }, '185.220.101.45', API);
    expect(d.hostnames).toHaveLength(MAX_HOSTNAMES);
    expect(d.hostnamesTotal).toBe(25);
    const f = abuseipdbFacts(d).find((x) => x.label.startsWith('Hostnames'));
    expect(f!.label).toBe(`Hostnames (${MAX_HOSTNAMES} of 25)`);
  });

  it('flags a non-public address the API reports', () => {
    const d = parseCheck({ data: { ...UNREPORTED.data, isPublic: false } }, '93.184.216.34', API);
    expect(factMap(abuseipdbFacts(d))['Public address']!.tone).toBe('warn');
  });
});

describe('abuseipdb malformed payloads', () => {
  it('coerces junk field types without crashing', () => {
    const d = parseCheck(
      {
        data: {
          ipAddress: 12,
          abuseConfidenceScore: '42',
          totalReports: '7',
          numDistinctUsers: -3,
          lastReportedAt: 'yesterday',
          countryCode: 12,
          isp: '   ',
          domain: 'Example.NET',
          usageType: null,
          hostnames: ['ok.example.net', 5, 'bad host!', 'OK.example.net.', null],
          isTor: 'true',
          isWhitelisted: null,
        },
      },
      '198.51.100.7',
      API,
    );
    expect(d).toMatchObject({
      ipAddress: '198.51.100.7',
      abuseConfidenceScore: 42,
      totalReports: 7,
      numDistinctUsers: 0,
      lastReportedAt: null,
      countryCode: null,
      isp: null,
      domain: 'example.net',
      usageType: null,
      hostnames: ['ok.example.net'],
      hostnamesTotal: 1,
      isTor: false,
      isWhitelisted: null,
      isPublic: null,
    });
  });

  it('clamps an out-of-range score', () => {
    expect(parseCheck({ data: { abuseConfidenceScore: 150 } }, '8.8.8.8', API).abuseConfidenceScore).toBe(100);
    expect(parseCheck({ data: { abuseConfidenceScore: -5 } }, '8.8.8.8', API).abuseConfidenceScore).toBe(0);
  });

  it('caps long strings', () => {
    const d = parseCheck({ data: { abuseConfidenceScore: 0, isp: 'x'.repeat(5000) } }, '8.8.8.8', API);
    expect(d.isp!.length).toBeLessThanOrEqual(200);
  });

  it.each([
    ['an empty object', {}],
    ['data as an array', { data: [] }],
    ['data as a string', { data: 'nope' }],
    ['no abuseConfidenceScore', { data: { ipAddress: '8.8.8.8', totalReports: 3 } }],
    ['a non-numeric score', { data: { abuseConfidenceScore: 'n/a' } }],
    ['a JSON array', [1, 2, 3]],
  ])('rejects %s with a parse error', async (_name, body) => {
    const m = mockFetch(abuseRoute({ '8.8.8.8': () => json(body) }));
    const err = await runErr(ip('8.8.8.8'), ctxFor(m.fetch));
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).kind).toBe('parse');
    expect((err as FetchError).message).toMatch(/^Unexpected response from AbuseIPDB/);
  });

  it('an errors envelope on HTTP 200 surfaces its detail', async () => {
    const m = mockFetch(abuseRoute({ '8.8.8.8': () => json(ERR_422) }));
    const err = (await runErr(ip('8.8.8.8'), ctxFor(m.fetch))) as FetchError;
    expect(err.kind).toBe('parse');
    expect(err.message).toContain('must be a valid IPv4 or IPv6 address');
  });

  it('an empty 200 body is a parse error', async () => {
    const m = mockFetch(abuseRoute({ '8.8.8.8': () => new Response('', { status: 200 }) }));
    const err = (await runErr(ip('8.8.8.8'), ctxFor(m.fetch))) as FetchError;
    expect(err.kind).toBe('parse');
  });

  it('an HTML 200 body is reported as not JSON', async () => {
    const m = mockFetch(abuseRoute({ '8.8.8.8': () => text('<html>maintenance</html>') }));
    const err = (await runErr(ip('8.8.8.8'), ctxFor(m.fetch))) as FetchError;
    expect(err.kind).toBe('parse');
    expect(err.message).toBe('Unexpected response from AbuseIPDB (not JSON).');
  });
});

describe('abuseipdb errors', () => {
  it('401 -> invalid key message, never the key itself', async () => {
    const m = mockFetch(abuseRoute({ '8.8.8.8': () => json(ERR_401, 401) }));
    const err = (await runErr(ip('8.8.8.8'), ctxFor(m.fetch))) as FetchError;
    expect(err).toBeInstanceOf(FetchError);
    expect(err.kind).toBe('http');
    expect(err.status).toBe(401);
    expect(err.message).toMatch(/^AbuseIPDB rejected the API key \(HTTP 401\): Authentication failed/);
    expect(err.message).toContain('Check the key in settings');
    expect(err.message).not.toContain(KEY);
  });

  it('401 with a non-JSON body still reads as a bad key', async () => {
    const m = mockFetch(abuseRoute({ '8.8.8.8': () => text('<html>Unauthorized</html>', 401) }));
    const err = (await runErr(ip('8.8.8.8'), ctxFor(m.fetch))) as FetchError;
    expect(err.status).toBe(401);
    expect(err.message).toBe('AbuseIPDB rejected the API key (HTTP 401). Check the key in settings (an APIv2 key is required).');
  });

  it('redacts the key if the provider ever echoes it', async () => {
    const echo = { errors: [{ detail: `Key ${KEY} is revoked.`, status: 401 }] };
    const m = mockFetch(abuseRoute({ '8.8.8.8': () => json(echo, 401) }));
    const err = (await runErr(ip('8.8.8.8'), ctxFor(m.fetch))) as FetchError;
    expect(err.message).toContain('[redacted]');
    expect(err.message).not.toContain(KEY);
    expect(err.body ?? '').not.toContain(KEY);
  });

  it('403 -> refused, check key/account', async () => {
    const m = mockFetch(abuseRoute({ '8.8.8.8': () => json({ errors: [{ detail: 'Forbidden.', status: 403 }] }, 403) }));
    const err = (await runErr(ip('8.8.8.8'), ctxFor(m.fetch))) as FetchError;
    expect(err.status).toBe(403);
    expect(err.message).toBe('AbuseIPDB refused the request (HTTP 403): Forbidden. Check the API key and your AbuseIPDB account.');
  });

  it('422 -> validation detail', async () => {
    const m = mockFetch(abuseRoute({ '8.8.8.8': () => json(ERR_422, 422) }));
    const err = (await runErr(ip('8.8.8.8'), ctxFor(m.fetch))) as FetchError;
    expect(err.status).toBe(422);
    expect(err.message).toBe(
      'AbuseIPDB rejected the lookup (HTTP 422): The ip address must be a valid IPv4 or IPv6 address (e.g. 8.8.8.8 or 2001:4860:4860::8888).',
    );
  });

  it('422 with several errors joins their details', async () => {
    const body = { errors: [{ detail: 'First problem.' }, { detail: 'Second problem' }, { nope: 1 }] };
    const m = mockFetch(abuseRoute({ '8.8.8.8': () => json(body, 422) }));
    const err = (await runErr(ip('8.8.8.8'), ctxFor(m.fetch))) as FetchError;
    expect(err.message).toBe('AbuseIPDB rejected the lookup (HTTP 422): First problem; Second problem.');
  });

  it('429 -> quota message with the reset time from X-RateLimit-Reset', async () => {
    const m = mockFetch(abuseRoute({ '8.8.8.8': () => json(ERR_429, 429, quotaHeaders()) }));
    const err = (await runErr(ip('8.8.8.8'), ctxFor(m.fetch))) as FetchError;
    expect(err.status).toBe(429);
    expect(err.message).toBe(
      'AbuseIPDB quota exhausted (HTTP 429): Daily rate limit of 1000 requests exceeded for this endpoint. ' +
        'The free plan allows 1,000 checks per day; the quota resets in about 7 h.',
    );
  });

  it('429 without any headers or body still reads as a quota error', async () => {
    const m = mockFetch(abuseRoute({ '8.8.8.8': () => text('', 429) }));
    const err = (await runErr(ip('8.8.8.8'), ctxFor(m.fetch))) as FetchError;
    expect(err.status).toBe(429);
    expect(err.message).toBe('AbuseIPDB quota exhausted (HTTP 429). The free plan allows 1,000 checks per day.');
  });

  it('429 falls back to Retry-After when X-RateLimit-Reset is missing', async () => {
    const m = mockFetch(abuseRoute({ '8.8.8.8': () => json(ERR_429, 429, { 'Retry-After': '1800' }) }));
    const err = (await runErr(ip('8.8.8.8'), ctxFor(m.fetch))) as FetchError;
    expect(err.message).toContain('resets in about 30 min');
  });

  it('after a 429, later lookups in the same investigation fail fast without a request', async () => {
    const m = mockFetch(
      abuseRoute({
        '8.8.8.8': () => json(ERR_429, 429, quotaHeaders()),
        '9.9.9.9': () => json(UNREPORTED),
      }),
    );
    const ctx = ctxFor(m.fetch);
    const first = (await runErr(ip('8.8.8.8'), ctx)) as FetchError;
    const second = (await runErr(ip('9.9.9.9'), ctx)) as FetchError;
    expect(second).toBeInstanceOf(FetchError);
    expect(second.status).toBe(429);
    expect(second.message).toBe(first.message);
    expect(m.calls).toHaveLength(1);
    // A new investigation (fresh shared memo) tries again.
    const out = await abuseipdbModule.run(ip('9.9.9.9'), ctxFor(m.fetch));
    expect(out.severity).toBe('none');
  });

  it('the fail-fast lasts until the quota resets, with an up-to-date wait', async () => {
    let t = NOW;
    let exhausted = true;
    const m = mockFetch(
      abuseRoute({
        '8.8.8.8': () => (exhausted ? json(ERR_429, 429, quotaHeaders()) : json(UNREPORTED)),
        '9.9.9.9': () => json(UNREPORTED),
      }),
    );
    const ctx = makeCtx({ fetch: m.fetch, keys: { abuseipdb: KEY }, now: () => t });
    expect(((await runErr(ip('8.8.8.8'), ctx)) as FetchError).message).toContain('resets in about 7 h');

    // 5 h later, same investigation (e.g. a per-card refresh): still no request, and the wait is recomputed.
    t = NOW + 5 * HOUR;
    const held = (await runErr(ip('8.8.8.8'), ctx)) as FetchError;
    expect(held.status).toBe(429);
    expect(held.message).toContain('resets in about 2 h');
    expect(m.calls).toHaveLength(1);

    // After the reset time the module asks AbuseIPDB again.
    t = Date.parse('2026-11-26T00:00:01Z');
    exhausted = false;
    const out = await abuseipdbModule.run(ip('8.8.8.8'), ctx);
    expect(out.severity).toBe('none');
    expect(m.calls).toHaveLength(2);
  });

  it('without a reset time the fail-fast is short-lived', async () => {
    let t = NOW;
    const m = mockFetch(
      abuseRoute({
        '8.8.8.8': () => json(ERR_429, 429),
        '9.9.9.9': () => json(UNREPORTED),
      }),
    );
    const ctx = makeCtx({ fetch: m.fetch, keys: { abuseipdb: KEY }, now: () => t });
    await runErr(ip('8.8.8.8'), ctx);
    t = NOW + 5 * MINUTE;
    expect(((await runErr(ip('9.9.9.9'), ctx)) as FetchError).status).toBe(429);
    expect(m.calls).toHaveLength(1);
    t = NOW + 11 * MINUTE;
    expect((await abuseipdbModule.run(ip('9.9.9.9'), ctx)).severity).toBe('none');
    expect(m.calls).toHaveLength(2);
  });

  it('a key echoed in a 429 stays redacted, also in the fail-fast replay', async () => {
    const echo = { errors: [{ detail: `Daily rate limit exceeded for key ${KEY}.`, status: 429 }] };
    const m = mockFetch(abuseRoute({ '8.8.8.8': () => json(echo, 429, quotaHeaders()) }));
    const ctx = ctxFor(m.fetch);
    const first = (await runErr(ip('8.8.8.8'), ctx)) as FetchError;
    const second = (await runErr(ip('9.9.9.9'), ctx)) as FetchError;
    for (const err of [first, second]) {
      expect(err.status).toBe(429);
      expect(err.message).toContain('[redacted]');
      expect(err.message).not.toContain(KEY);
      expect(err.body ?? '').not.toContain(KEY);
    }
  });

  it('a cancelled lookup surfaces as aborted, not as an AbuseIPDB error', async () => {
    const ac = new AbortController();
    const m = mockFetch(() => {
      ac.abort();
      throw new DOMException('The operation was aborted.', 'AbortError');
    });
    const ctx = makeCtx({ fetch: m.fetch, keys: { abuseipdb: KEY }, now: () => NOW, signal: ac.signal });
    const err = (await runErr(ip('8.8.8.8'), ctx)) as FetchError;
    expect(err).toBeInstanceOf(FetchError);
    expect(err.kind).toBe('aborted');
    expect(err.message).toBe('Cancelled');
  });

  it('5xx -> provider-prefixed HTTP error', async () => {
    const m = mockFetch(abuseRoute({ '8.8.8.8': () => text('<html>Bad gateway</html>', 502) }));
    const err = (await runErr(ip('8.8.8.8'), ctxFor(m.fetch))) as FetchError;
    expect(err.kind).toBe('http');
    expect(err.status).toBe(502);
    expect(err.message).toBe('AbuseIPDB error (HTTP 502).');
  });

  it('network errors propagate', async () => {
    const m = mockFetch(() => {
      throw new TypeError('NetworkError when attempting to fetch resource.');
    });
    const err = (await runErr(ip('8.8.8.8'), ctxFor(m.fetch))) as FetchError;
    expect(err.kind).toBe('network');
  });
});

describe('abuseipdb 429 automatic retry (orchestrator http)', () => {
  /** A ctx whose http applies the module's rate limit like the orchestrator does, on a fake clock. */
  function limitedCtx(f: typeof fetch): Ctx {
    let t = NOW;
    const clock: Clock = {
      now: () => t,
      sleep: async (ms) => {
        t += ms;
      },
    };
    const http = createHttp({
      fetch: f,
      limiter: new RateLimiter(clock),
      signal: new AbortController().signal,
      defaultLimit: { key: 'abuseipdb', perMinute: abuseipdbModule.rateLimit!.perMinute },
      now: () => t,
    });
    return { ...makeCtx({ fetch: f, keys: { abuseipdb: KEY }, now: () => t }), ...http };
  }

  it('retries once, then reports the quota', async () => {
    const m = mockFetch(abuseRoute({ '8.8.8.8': () => json(ERR_429, 429, quotaHeaders('2')) }));
    const err = (await runErr(ip('8.8.8.8'), limitedCtx(m.fetch))) as FetchError;
    expect(m.calls).toHaveLength(2);
    expect(err.status).toBe(429);
    expect(err.message).toMatch(/^AbuseIPDB quota exhausted/);
  });

  it('a transient 429 recovers on the retry', async () => {
    let n = 0;
    const m = mockFetch(
      abuseRoute({
        '185.220.101.45': () => (n++ === 0 ? json(ERR_429, 429, { 'Retry-After': '1' }) : json(TOR_EXIT)),
      }),
    );
    const out = await abuseipdbModule.run(ip('185.220.101.45'), limitedCtx(m.fetch));
    expect(m.calls).toHaveLength(2);
    expect(out.severity).toBe('high');
  });
});

describe('abuseipdb input handling', () => {
  const noNetwork = () => mockFetch();

  it('skips non-IP entities', async () => {
    const m = noNetwork();
    const err = await runErr({ kind: 'domain', value: 'example.com', depth: 0 }, ctxFor(m.fetch));
    expect(err).toBeInstanceOf(SkipError);
    expect(m.calls).toHaveLength(0);
  });

  it('skips invalid IPs', async () => {
    const m = noNetwork();
    expect(await runErr(ip('999.1.1.1'), ctxFor(m.fetch))).toBeInstanceOf(SkipError);
    expect(m.calls).toHaveLength(0);
  });

  it.each(['10.0.0.1', '127.0.0.1', '192.168.1.10', 'fe80::1', '2001:db8::1'])('skips non-public %s without spending a check', async (addr) => {
    const m = noNetwork();
    const err = await runErr(ip(addr), ctxFor(m.fetch));
    expect(err).toBeInstanceOf(SkipError);
    expect((err as SkipError).message).toMatch(/public IPs/);
    expect(m.calls).toHaveLength(0);
  });

  it('skips (defensively) when the key is missing', async () => {
    const m = noNetwork();
    const err = await runErr(ip('8.8.8.8'), ctxFor(m.fetch, {}));
    expect(err).toBeInstanceOf(SkipError);
    expect((err as SkipError).message).toMatch(/API key/);
    expect(m.calls).toHaveLength(0);
  });

  it('trims the key and rejects one that cannot go in a header', async () => {
    const ok = mockFetch(abuseRoute({ '8.8.8.8': () => json(UNREPORTED) }));
    await abuseipdbModule.run(ip('8.8.8.8'), ctxFor(ok.fetch, { abuseipdb: `  ${KEY}\n` }));
    expect(header(ok.calls[0]!.init, 'Key')).toBe(KEY);

    const m = noNetwork();
    const err = (await runErr(ip('8.8.8.8'), ctxFor(m.fetch, { abuseipdb: 'abc déf' }))) as Error;
    expect(err.message).toMatch(/invalid characters/);
    expect(m.calls).toHaveLength(0);
  });

  it('keeps the key out of data, summary and facts', async () => {
    const m = mockFetch(abuseRoute({ '185.220.101.45': () => json(TOR_EXIT) }));
    const out = await abuseipdbModule.run(ip('185.220.101.45'), ctxFor(m.fetch));
    const dump = JSON.stringify([out, abuseipdbFacts(out.data)]);
    expect(dump).not.toContain(KEY);
  });
});

describe('abuseipdb key tester', () => {
  const http = (f: typeof fetch) => createHttp({ fetch: f, limiter: new RateLimiter(), signal: new AbortController().signal });
  const TEST_URL = `${API}?ipAddress=1.1.1.1&maxAgeInDays=1`;

  it('accepts a working key and reports the remaining daily checks', async () => {
    const m = mockFetch(
      abuseRoute({
        '1.1.1.1': () => json(WHITELISTED, 200, { 'X-RateLimit-Limit': '1000', 'X-RateLimit-Remaining': '999', 'X-RateLimit-Reset': RESET_EPOCH }),
      }),
    );
    await expect(abuseipdbKeyTest(KEY, http(m.fetch))).resolves.toBe('Key valid · 999 of 1,000 daily checks left.');
    expect(m.calls).toHaveLength(1);
    expect(m.calls[0]!.url).toBe(TEST_URL);
    expect(header(m.calls[0]!.init, 'Key')).toBe(KEY);
    expect(header(m.calls[0]!.init, 'Accept')).toBe('application/json');
  });

  it('works without rate-limit headers', async () => {
    const m = mockFetch(abuseRoute({ '1.1.1.1': () => json(WHITELISTED) }));
    await expect(abuseipdbKeyTest(KEY, http(m.fetch))).resolves.toBe('Key valid.');
  });

  it('reports remaining checks when only X-RateLimit-Remaining is present', async () => {
    const m = mockFetch(abuseRoute({ '1.1.1.1': () => json(WHITELISTED, 200, { 'X-RateLimit-Remaining': '42' }) }));
    await expect(abuseipdbKeyTest(KEY, http(m.fetch))).resolves.toBe('Key valid · 42 checks left today.');
  });

  it('explains a rejected key', async () => {
    const m = mockFetch(abuseRoute({ '1.1.1.1': () => json(ERR_401, 401) }));
    await expect(abuseipdbKeyTest(KEY, http(m.fetch))).rejects.toThrow(/rejected the API key \(HTTP 401\)/);
  });

  it('does not call a 200 that is not a check result a valid key', async () => {
    const m = mockFetch(abuseRoute({ '1.1.1.1': () => json({}, 200, { 'X-RateLimit-Remaining': '999' }) }));
    await expect(abuseipdbKeyTest(KEY, http(m.fetch))).rejects.toThrow(/^Unexpected response from AbuseIPDB/);
  });

  it('does not call an HTML 200 (captive portal, proxy) a valid key', async () => {
    const m = mockFetch(abuseRoute({ '1.1.1.1': () => text('<html>Sign in to the Wi-Fi</html>') }));
    await expect(abuseipdbKeyTest(KEY, http(m.fetch))).rejects.toThrow('Unexpected response from AbuseIPDB (not JSON).');
  });

  it('explains an exhausted quota', async () => {
    const m = mockFetch(abuseRoute({ '1.1.1.1': () => json(ERR_429, 429, quotaHeaders()) }));
    await expect(abuseipdbKeyTest(KEY, http(m.fetch))).rejects.toThrow(/quota exhausted \(HTTP 429\).*1,000 checks per day/);
    expect(m.calls).toHaveLength(1);
  });

  it('rejects an empty or unsendable key without a request', async () => {
    const m = mockFetch();
    await expect(abuseipdbKeyTest('   ', http(m.fetch))).rejects.toThrow('Enter an AbuseIPDB API key first.');
    await expect(abuseipdbKeyTest('key with spaces', http(m.fetch))).rejects.toThrow(/invalid characters/);
    expect(m.calls).toHaveLength(0);
  });
});

describe('abuseipdb through the orchestrator', () => {
  const ipsModule: Module = {
    id: 'ips',
    label: 'IPs',
    version: 1,
    accepts: ['domain'],
    ttl: HOUR,
    async run() {
      return { data: {}, pivots: [{ kind: 'ip', value: '185.220.101.45' }] };
    },
  };

  async function runInvestigation(f: typeof fetch, key: string | undefined) {
    const events: RunEvent[] = [];
    const deps: OrchestratorDeps = {
      modules: [ipsModule, abuseipdbModule as Module],
      isEnabled: () => true,
      allowActive: false,
      cache: memoryCache(),
      limiter: new RateLimiter(),
      settings: DEFAULT_SETTINGS,
      getKey: async (p) => (p === 'abuseipdb' ? key : undefined),
      fetch: f,
    };
    await investigate({ kind: 'domain', value: 'example.com' }, (e) => events.push(e), deps).done;
    const cards = events.filter((e): e is Extract<RunEvent, { type: 'card' }> => e.type === 'card').map((e) => e.card);
    return (id: string): CardState | undefined => cards.filter((c) => c.id === id).at(-1);
  }

  it('produces an ok card with severity for a pivoted IP', async () => {
    const m = mockFetch(abuseRoute({ '185.220.101.45': () => json(TOR_EXIT) }));
    const last = await runInvestigation(m.fetch, KEY);
    const card = last('abuseipdb|ip:185.220.101.45')!;
    expect(card.status).toBe('ok');
    expect(card.severity).toBe('high');
    expect(card.summary).toBe('Confidence 87% · 412 reports from 96 users · last 2026-11-20 · Tor exit');
    expect(m.calls).toHaveLength(1);
  });

  it('is skipped with a settings hint when no key is set', async () => {
    const m = mockFetch();
    const last = await runInvestigation(m.fetch, undefined);
    const card = last('abuseipdb|ip:185.220.101.45')!;
    expect(card.status).toBe('skipped');
    expect(card.skip?.reason).toBe('no-key');
    expect(m.calls).toHaveLength(0);
  });
});
