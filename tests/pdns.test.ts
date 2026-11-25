import { describe, expect, it } from 'vitest';
import { FetchError, createHttp } from '@/lib/http';
import { investigate, type OrchestratorDeps } from '@/lib/orchestrator';
import { RateLimiter } from '@/lib/ratelimit';
import { DEFAULT_SETTINGS } from '@/lib/settings';
import type { CardState, Entity, Fact, Module, RunEvent } from '@/lib/types';
import { HOUR } from '@/lib/types';
import {
  AUTH_LIMIT,
  MAX_PIVOTS,
  MAX_RECORDS,
  PUBLIC_LIMIT,
  mnemonicKeyTester,
  parseRecord,
  pdnsModule,
  type PdnsData,
} from '@/modules/pdns';
import { json, makeCtx, memoryCache, mockFetch, text, type Route } from './helpers';

const KEY = '1234/1/abcd1234ef012';
const t = (iso: string) => Date.parse(`${iso}T12:00:00Z`);
const domain: Entity = { kind: 'domain', value: 'example.com', depth: 0 };
const ip = (value: string): Entity => ({ kind: 'ip', value, depth: 1 });

/** A record shaped like the live API (see docs/research/pdns-m365-email.md §1). */
function rec(rrtype: string, query: string, answer: string, first: string, last: string, times = 10): Record<string, unknown> {
  return {
    query,
    answer,
    rrtype,
    rrclass: 'in',
    firstSeenTimestamp: t(first),
    lastSeenTimestamp: t(last),
    minTtl: 1,
    maxTtl: 300,
    times,
    tlp: 'white',
    customer: null,
    flags: ['partialResult'],
    createdTimestamp: t(first) + 23_000,
    lastUpdatedTimestamp: t(last) + 120_000,
  };
}

function envelope(data: unknown[], extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { responseCode: 200, limit: PUBLIC_LIMIT, offset: 0, count: data.length, metaData: {}, messages: [], size: data.length, data, ...extra };
}

/** Live shape (2026-11-25): HTTP 200, limit 0, message null. */
const NOT_FOUND = {
  responseCode: 200,
  limit: 0,
  offset: 0,
  count: 0,
  metaData: {},
  messages: [
    { message: null, messageTemplate: 'object.not.found', field: null, parameter: null, timestamp: 1795541064939, type: 'INFO' },
  ],
  size: 0,
  data: [],
};

const QUOTA = {
  responseCode: 402,
  limit: 0,
  offset: 0,
  count: 0,
  metaData: { millisUntilResourcesAvailable: 2 * HOUR - 5000 },
  messages: [{ message: 'Resource limit exceeded', messageTemplate: 'resource.limit.exceeded', type: 'ACTION_ERROR', field: null, parameter: {} }],
  size: 0,
  data: null,
};

/** Live response to a bogus Argus-API-Key (HTTP 401). */
const BAD_KEY = {
  responseCode: 401,
  limit: 0,
  offset: 0,
  count: 0,
  metaData: {},
  messages: [{ message: 'Invalid API key', messageTemplate: 'authentication.failed', type: 'ACTION_ERROR', field: null, parameter: null, timestamp: 1795606474368 }],
  data: null,
  size: 0,
};

/** Deliberately not in lastSeen order: the module sorts. */
const DOMAIN_RECORDS = [
  rec('a', 'example.com', '93.184.216.34', '2015-04-02', '2026-01-13', 9_000_000),
  rec('ns', 'example.com', 'a.iana-servers.net.', '2015-04-02', '2026-11-18'),
  rec('a', 'example.com', '104.20.23.154', '2026-04-10', '2026-11-20', 20744),
  rec('aaaa', 'example.com', '2606:2800:0220:0001:0248:1893:25C8:1946', '2015-04-02', '2026-01-13'),
  rec('a', 'example.com', '172.66.147.243', '2026-04-10', '2026-11-19'),
  rec('mx', 'example.com', '.', '2020-01-01', '2026-11-17'),
  rec('txt', 'example.com', 'v=spf1 -all', '2016-05-05', '2026-11-16'),
  rec('cname', 'www.example.com', 'example.com', '2015-04-02', '2026-11-15'),
];

function pdnsRoute(map: Record<string, unknown | ((u: URL, init: RequestInit) => Response)>): Route {
  return (u, init) => {
    if (u.host !== 'api.mnemonic.no' || !u.pathname.startsWith('/pdns/v3/')) return undefined;
    const q = decodeURIComponent(u.pathname.slice('/pdns/v3/'.length));
    const v = map[q];
    if (v === undefined) return undefined;
    return typeof v === 'function' ? (v as (u: URL, i: RequestInit) => Response)(u, init) : json(v);
  };
}

const headerOf = (init: RequestInit, name: string) => (init.headers as Record<string, string> | undefined)?.[name];
const fact = (facts: Fact[], prefix: string) => facts.find((f) => f.label.startsWith(prefix));
const values = (f: Fact | undefined) => (f ? (Array.isArray(f.value) ? f.value : [f.value]) : []);

async function run(e: Entity, routes: Route[], keys: Record<string, string> = {}) {
  const m = mockFetch(...routes);
  const ctx = makeCtx({ fetch: m.fetch, keys });
  const out = await pdnsModule.run(e, ctx);
  return { out, calls: m.calls, facts: pdnsModule.facts!(out.data, e) };
}

describe('pdns module metadata', () => {
  it('declares the contract the orchestrator relies on', () => {
    expect(pdnsModule.id).toBe('pdns');
    expect(pdnsModule.label).toBe('Passive DNS (Mnemonic)');
    expect(pdnsModule.accepts).toEqual(['domain', 'ip']);
    expect(pdnsModule.key).toBe('mnemonic');
    expect(pdnsModule.keyOptional).toBe(true);
    expect(pdnsModule.ttl).toBe(24 * HOUR);
    expect(pdnsModule.rateLimit).toEqual({ perMinute: 10 });
    expect(pdnsModule.active).toBeFalsy();
    // The real public-access limitations, not "may lack timestamps".
    expect(pdnsModule.note).toMatch(/TLP:WHITE/);
    expect(pdnsModule.note).toMatch(/1000 records/);
    expect(pdnsModule.note).toMatch(/10 lookups\/min and 1000\/day/);
  });
});

describe('pdns domain query', () => {
  it('unauthenticated: no key header, public limit, distinct answers per rrtype, no pivots', async () => {
    const { out, calls, facts } = await run(domain, [pdnsRoute({ 'example.com': envelope(DOMAIN_RECORDS, { count: 37 }) })]);

    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(`https://api.mnemonic.no/pdns/v3/example.com?limit=${PUBLIC_LIMIT}`);
    expect(headerOf(calls[0]!.init, 'Argus-API-Key')).toBeUndefined();
    expect(calls[0]!.init.credentials).toBe('omit');

    const d = out.data;
    expect(d.query).toBe('example.com');
    expect(d.authenticated).toBe(false);
    expect(d.total).toBe(37);
    expect(d.fetched).toBe(8);
    expect(d.truncated).toBe(true);
    expect(d.skipped).toBe(0);
    expect(d.firstSeen).toBe('2015-04-02T12:00:00.000Z');
    expect(d.lastSeen).toBe('2026-11-20T12:00:00.000Z');
    expect(d.distinctAnswers).toEqual({ a: 3, aaaa: 1, ns: 1, mx: 1, txt: 1 });
    expect(d.distinctNames).toEqual({ cname: 1 });

    // Sorted by lastSeen descending, normalised.
    expect(d.records.map((r) => r.answer)).toEqual([
      '104.20.23.154',
      '172.66.147.243',
      'a.iana-servers.net',
      '.',
      'v=spf1 -all',
      'example.com',
      '93.184.216.34',
      '2606:2800:220:1:248:1893:25c8:1946',
    ]);
    expect(d.records[0]).toEqual({
      rrtype: 'a',
      query: 'example.com',
      answer: '104.20.23.154',
      firstSeen: '2026-04-10T12:00:00.000Z',
      lastSeen: '2026-11-20T12:00:00.000Z',
      times: 20744,
    });

    // Historical IPs are facts only: never IP pivots from a domain query.
    expect(out.pivots).toBeUndefined();
    expect(out.summary).toBe('37 records · 4+ distinct IPs · seen 2015-04-02 → 2026-11-20');
    expect(() => JSON.parse(JSON.stringify(d)) as unknown).not.toThrow();

    expect(fact(facts, 'Records')).toEqual({ label: 'Records', value: '37 (first 8 fetched)', tone: 'warn' });
    // Truncated: the range and distinct counts only cover what was fetched.
    expect(fact(facts, 'Seen')!.value).toBe('2015-04-02 → 2026-11-20 (fetched records only)');
    expect(fact(facts, 'Access')!.value).toBe('Public (TLP:WHITE data only)');
    const a = fact(facts, 'A ·')!;
    expect(a.label).toBe('A · 3+ distinct');
    expect(a.pivot).toBe(true);
    expect(a.value).toEqual([
      '104.20.23.154 (2026-04-10 → 2026-11-20)',
      '172.66.147.243 (2026-04-10 → 2026-11-19)',
      '93.184.216.34 (2015-04-02 → 2026-01-13)',
    ]);
    expect(values(fact(facts, 'AAAA'))).toEqual(['2606:2800:220:1:248:1893:25c8:1946 (2015-04-02 → 2026-01-13)']);
    expect(fact(facts, 'TXT')!.pivot).toBeUndefined();
    const here = fact(facts, 'Pointing here')!;
    expect(here.value).toEqual(['www.example.com [CNAME] (2015-04-02 → 2026-11-15)']);
    // rrtype order: A, AAAA, NS, MX, TXT, then names pointing here.
    expect(facts.map((f) => f.label.split(' ·')[0])).toEqual(['Records', 'Seen', 'Access', 'A', 'AAAA', 'NS', 'MX', 'TXT', 'Pointing here']);
  });

  it('authenticated: sends Argus-API-Key and the private limit maximum', async () => {
    const { out, calls, facts } = await run(domain, [pdnsRoute({ 'example.com': envelope(DOMAIN_RECORDS) })], { mnemonic: `  ${KEY} ` });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(`https://api.mnemonic.no/pdns/v3/example.com?limit=${AUTH_LIMIT}`);
    expect(headerOf(calls[0]!.init, 'Argus-API-Key')).toBe(KEY);
    expect(out.data.authenticated).toBe(true);
    expect(out.data.truncated).toBe(false);
    expect(out.summary).toBe('8 records · 4 distinct IPs · seen 2015-04-02 → 2026-11-20');
    expect(fact(facts, 'Records')).toEqual({ label: 'Records', value: '8' });
    expect(fact(facts, 'Seen')!.value).toBe('2015-04-02 → 2026-11-20');
    expect(fact(facts, 'A ·')!.label).toBe('A · 3 distinct');
    expect(fact(facts, 'Access')!.value).toBe('Argus API key');
  });

  it('empty result (object.not.found INFO message) -> "No passive DNS records"', async () => {
    const { out, facts } = await run(domain, [pdnsRoute({ 'example.com': NOT_FOUND })]);
    expect(out.summary).toBe('No passive DNS records');
    expect(out.data.total).toBe(0);
    expect(out.data.records).toEqual([]);
    expect(out.data.firstSeen).toBeNull();
    expect(out.pivots).toBeUndefined();
    expect(facts.map((f) => f.label)).toEqual(['Records', 'Access']);
  });

  it('tolerates data:null on not-found', async () => {
    const { out } = await run(domain, [pdnsRoute({ 'example.com': { ...NOT_FOUND, data: null } })]);
    expect(out.summary).toBe('No passive DNS records');
  });

  it('caps stored records at 200 (most recent) but counts distinct answers over the whole page', async () => {
    const many = Array.from({ length: 250 }, (_, i) =>
      rec('a', 'example.com', `198.51.${Math.floor(i / 200)}.${i % 200}`, '2020-01-01', new Date(Date.UTC(2026, 0, 1) + i * 86_400_000).toISOString().slice(0, 10)),
    );
    const { out, facts } = await run(domain, [pdnsRoute({ 'example.com': envelope(many, { count: 2345 }) })]);
    const d = out.data;
    expect(d.records).toHaveLength(MAX_RECORDS);
    expect(d.records[0]!.answer).toBe('198.51.1.49'); // i = 249, newest
    expect(d.total).toBe(2345);
    expect(d.truncated).toBe(true);
    expect(d.distinctAnswers['a']).toBe(250);
    expect(out.summary).toMatch(/^2345 records · 250\+ distinct IPs · seen 2020-01-01 → /);
    expect(fact(facts, 'Shown')!.value).toBe('200 most recent of 250');
    const a = fact(facts, 'A ·')!;
    expect(a.label).toBe('A · 250+ distinct, 25 shown');
    expect(values(a)).toHaveLength(25);
    expect(JSON.stringify(d).length).toBeLessThan(40_000);
  });

  it('a full page is truncated even when count equals it (live: count is capped at 1000 without a key)', async () => {
    const full = Array.from({ length: PUBLIC_LIMIT }, (_, i) =>
      rec('a', 'example.com', `198.51.${Math.floor(i / 250)}.${i % 250}`, '2020-01-01', '2026-01-01'),
    );
    const { out, facts } = await run(domain, [pdnsRoute({ 'example.com': envelope(full, { count: PUBLIC_LIMIT }) })]);
    const d = out.data;
    expect(d.total).toBe(PUBLIC_LIMIT);
    expect(d.fetched).toBe(PUBLIC_LIMIT);
    expect(d.truncated).toBe(true);
    expect(out.summary).toBe('1000+ records · 1000+ distinct IPs · seen 2020-01-01 → 2026-01-01');
    expect(fact(facts, 'Records')).toEqual({
      label: 'Records',
      value: '1000+ (per-lookup limit reached; older records not fetched, a key raises the limit)',
      tone: 'warn',
    });
    expect(fact(facts, 'Seen')!.value).toBe('2020-01-01 → 2026-01-01 (fetched records only)');
  });

  it('one short of the page limit is complete', async () => {
    const page = Array.from({ length: PUBLIC_LIMIT - 1 }, (_, i) => rec('a', 'example.com', `198.51.${Math.floor(i / 250)}.${i % 250}`, '2020-01-01', '2026-01-01'));
    const { out } = await run(domain, [pdnsRoute({ 'example.com': envelope(page) })]);
    expect(out.data.truncated).toBe(false);
    expect(out.summary).toBe('999 records · 999 distinct IPs · seen 2020-01-01 → 2026-01-01');
  });
});

describe('pdns IP query', () => {
  const IP = '93.184.216.34';
  const ipRecords = [
    rec('a', 'example.com', IP, '2015-04-02', '2026-01-13'),
    rec('a', 'EXAMPLE.NET.', IP, '2015-04-02', '2026-01-12'),
    rec('a', '*.wild.example.org', IP, '2019-01-01', '2026-01-11'),
    rec('a', '_acme.example.org', IP, '2019-01-01', '2026-01-10'),
    // site0 last seen 2025-12-31, site1 2025-12-30, ...
    ...Array.from({ length: 30 }, (_, i) => rec('a', `site${i}.example.org`, IP, '2014-01-01', new Date(Date.UTC(2025, 11, 31) - i * 86_400_000).toISOString().slice(0, 10))),
    rec('ptr', '34.216.184.93.in-addr.arpa', 'example.com', '2018-01-01', '2018-02-01'),
  ];

  it('emits up to 25 domain pivots (valid hostnames, most recent first), never IP pivots', async () => {
    const { out, calls, facts } = await run(ip(IP), [pdnsRoute({ [IP]: envelope(ipRecords) })]);
    expect(calls[0]!.url).toBe(`https://api.mnemonic.no/pdns/v3/${IP}?limit=${PUBLIC_LIMIT}`);
    expect(headerOf(calls[0]!.init, 'Argus-API-Key')).toBeUndefined();

    const pivots = out.pivots!;
    expect(pivots).toHaveLength(MAX_PIVOTS);
    expect(pivots.every((p) => p.kind === 'domain')).toBe(true);
    expect(pivots[0]).toEqual({ kind: 'domain', value: 'example.com', note: 'Passive DNS, last seen 2026-01-13' });
    expect(pivots[1]!.value).toBe('example.net');
    const vals = pivots.map((p) => p.value);
    expect(new Set(vals).size).toBe(vals.length);
    expect(vals).not.toContain('*.wild.example.org');
    expect(vals).not.toContain('_acme.example.org');
    expect(vals.some((v) => v.endsWith('.arpa'))).toBe(false);

    expect(out.data.distinctNames).toEqual({ a: 34 });
    expect(out.data.distinctAnswers).toEqual({ ptr: 1 });
    expect(out.summary).toBe('35 records · 34 distinct domains · seen 2014-01-01 → 2026-01-13');

    const doms = fact(facts, 'Domains')!;
    expect(doms.label).toBe('Domains · 34 distinct, 25 shown');
    expect(doms.pivot).toBe(true);
    expect(values(doms)[0]).toBe('example.com (2015-04-02 → 2026-01-13)');
    // The wildcard name is still shown in facts, just not pivoted.
    expect(values(doms)).toContain('*.wild.example.org (2019-01-01 → 2026-01-11)');
    expect(values(fact(facts, 'PTR'))).toEqual(['34.216.184.93.in-addr.arpa → example.com (2018-01-01 → 2018-02-01)']);
    // Domains come before other record groups for an IP.
    expect(facts.findIndex((f) => f.label.startsWith('Domains'))).toBeLessThan(facts.findIndex((f) => f.label.startsWith('PTR')));
  });

  it('authenticated IP query sends the key', async () => {
    const { out, calls } = await run(ip(IP), [pdnsRoute({ [IP]: envelope(ipRecords.slice(0, 2)) })], { mnemonic: KEY });
    expect(headerOf(calls[0]!.init, 'Argus-API-Key')).toBe(KEY);
    expect(calls[0]!.url).toContain(`limit=${AUTH_LIMIT}`);
    expect(out.pivots!.map((p) => p.value)).toEqual(['example.com', 'example.net']);
  });

  it('URL-encodes IPv6 and matches normalised answers', async () => {
    const v6 = '2606:2800:220:1:248:1893:25c8:1946';
    const { out, calls } = await run(ip(v6), [
      pdnsRoute({ [v6]: envelope([rec('aaaa', 'example.com', '2606:2800:0220:0001:0248:1893:25C8:1946', '2015-04-02', '2026-01-13')]) }),
    ]);
    expect(calls[0]!.url).toBe(`https://api.mnemonic.no/pdns/v3/${encodeURIComponent(v6)}?limit=${PUBLIC_LIMIT}`);
    expect(calls[0]!.url).toContain('2606%3A2800%3A220');
    expect(out.pivots).toEqual([{ kind: 'domain', value: 'example.com', note: 'Passive DNS, last seen 2026-01-13' }]);
    expect(out.summary).toBe('1 record · 1 distinct domain · seen 2015-04-02 → 2026-01-13');
  });

  it('canonicalises a non-canonical IPv6 entity before querying and matching', async () => {
    const v6 = '2606:2800:220:1:248:1893:25c8:1946';
    const { out, calls } = await run(ip('2606:2800:0220:0001:0248:1893:25C8:1946'), [
      pdnsRoute({ [v6]: envelope([rec('aaaa', 'example.com', v6, '2015-04-02', '2026-01-13')]) }),
    ]);
    expect(calls[0]!.url).toBe(`https://api.mnemonic.no/pdns/v3/${encodeURIComponent(v6)}?limit=${PUBLIC_LIMIT}`);
    expect(out.data.query).toBe(v6);
    expect(out.pivots!.map((p) => p.value)).toEqual(['example.com']);
  });

  it('pivots only names with A/AAAA records for the IP', async () => {
    const { out, facts } = await run(ip(IP), [
      pdnsRoute({
        [IP]: envelope([
          rec('txt', 'notes.example.org', IP, '2020-01-01', '2026-02-01'),
          rec('a', 'example.com', IP, '2015-04-02', '2026-01-13'),
        ]),
      }),
    ]);
    expect(out.pivots!.map((p) => p.value)).toEqual(['example.com']);
    expect(out.summary).toBe('2 records · 1 distinct domain · seen 2015-04-02 → 2026-02-01');
    // Still listed in facts, with its record type.
    expect(values(fact(facts, 'Domains'))).toContain('notes.example.org [TXT] (2020-01-01 → 2026-02-01)');
  });

  it('IP with no history: no pivots', async () => {
    const { out } = await run(ip('198.51.100.7'), [pdnsRoute({ '198.51.100.7': NOT_FOUND })]);
    expect(out.pivots).toBeUndefined();
    expect(out.summary).toBe('No passive DNS records');
  });
});

describe('pdns parsing', () => {
  it('skips malformed records and keeps undated ones', async () => {
    const data = [
      null,
      'example.com A 1.2.3.4',
      42,
      { rrtype: 1, query: 'example.com', answer: '1.2.3.4' },
      { rrtype: 'a', query: 'example.com' },
      { rrtype: 'a', query: 'example.com', answer: { ip: '1.2.3.4' } },
      { rrtype: 'a', query: '   ', answer: '1.2.3.4' },
      { rrtype: 'a; drop', query: 'example.com', answer: '1.2.3.4' },
      { rrtype: 'A', query: 'Example.COM.', answer: '198.51.100.1', firstSeenTimestamp: 'garbage', lastSeenTimestamp: -5, times: 'many' },
      { rrtype: 'a', query: 'example.com', answer: '198.51.100.2', firstSeenTimestamp: 0, lastSeenTimestamp: String(t('2026-03-03')), times: 3 },
      rec('a', 'example.com', '198.51.100.3', '2026-01-01', '2026-02-02'),
    ];
    const { out, facts } = await run(domain, [pdnsRoute({ 'example.com': envelope(data) })]);
    const d = out.data;
    expect(d.fetched).toBe(11);
    expect(d.skipped).toBe(8);
    expect(d.records.map((r) => r.answer)).toEqual(['198.51.100.2', '198.51.100.3', '198.51.100.1']);
    expect(d.records[0]).toEqual({ rrtype: 'a', query: 'example.com', answer: '198.51.100.2', firstSeen: null, lastSeen: '2026-03-03T12:00:00.000Z', times: 3 });
    expect(d.records[2]).toEqual({ rrtype: 'a', query: 'example.com', answer: '198.51.100.1', firstSeen: null, lastSeen: null });
    expect(out.summary).toBe('11 records · 3 distinct IPs · seen 2026-01-01 → 2026-03-03');
    expect(fact(facts, 'Skipped')).toEqual({ label: 'Skipped', value: '8 malformed records', tone: 'warn' });
    expect(values(fact(facts, 'A ·'))).toEqual(['198.51.100.2 (last 2026-03-03)', '198.51.100.3 (2026-01-01 → 2026-02-02)', '198.51.100.1']);
  });

  it('parseRecord truncates oversized TXT answers', () => {
    const r = parseRecord({ rrtype: 'txt', query: 'example.com', answer: 'x'.repeat(5000) });
    expect(r!.answer).toHaveLength(512);
  });

  it('throws when every record is malformed (format change)', async () => {
    const err = await run(domain, [pdnsRoute({ 'example.com': envelope([{ foo: 1 }, { bar: 2 }]) })]).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/none could be parsed/);
  });

  it('throws a parse error when the envelope has no data array', async () => {
    const err = await run(domain, [pdnsRoute({ 'example.com': { responseCode: 200, count: 3, messages: [] } })]).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).kind).toBe('parse');
  });

  it('throws a parse error on a non-object body', async () => {
    const err = await run(domain, [pdnsRoute({ 'example.com': [] })]).catch((e: unknown) => e);
    expect((err as FetchError).kind).toBe('parse');
    const err2 = await run(domain, [(u) => (u.host === 'api.mnemonic.no' ? text('<html>maintenance</html>') : undefined)]).catch((e: unknown) => e);
    expect((err2 as FetchError).kind).toBe('parse');
  });
});

describe('pdns errors', () => {
  it('HTTP 402 quota exhaustion -> informative error with reset time', async () => {
    const err = await run(domain, [pdnsRoute({ 'example.com': () => json(QUOTA, 402) })]).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(FetchError);
    const fe = err as FetchError;
    expect(fe.kind).toBe('http');
    expect(fe.status).toBe(402);
    expect(fe.message).toMatch(/quota exhausted; resets in about 2 h/);
    expect(fe.message).toMatch(/10 lookups\/min and 1000\/day; an Argus API key raises this/);
  });

  it('in-body responseCode 402 on HTTP 200 is an error too', async () => {
    const err = await run(domain, [pdnsRoute({ 'example.com': { ...QUOTA, metaData: { millisUntilResourcesAvailable: 30_000 } } })], { mnemonic: KEY }).catch(
      (e: unknown) => e,
    );
    expect((err as FetchError).status).toBe(402);
    expect((err as FetchError).message).toMatch(/resets in under a minute\. Your Argus API key has used its request allowance/);
  });

  it('in-body 5xx responseCode surfaces the API message', async () => {
    const body = { responseCode: 503, messages: [{ message: 'Service temporarily unavailable', type: 'ACTION_ERROR' }], data: null };
    const err = await run(domain, [pdnsRoute({ 'example.com': body })]).catch((e: unknown) => e);
    expect((err as FetchError).status).toBe(503);
    expect((err as FetchError).message).toBe('Mnemonic PDNS error (HTTP 503) (Service temporarily unavailable).');
  });

  it('HTTP 429 -> rate-limit message', async () => {
    const err = await run(domain, [pdnsRoute({ 'example.com': () => json({ responseCode: 429, messages: [], data: null }, 429) })]).catch((e: unknown) => e);
    expect((err as FetchError).status).toBe(429);
    expect((err as FetchError).message).toMatch(/rate limit hit.*10 lookups per minute/);
  });

  it('HTTP 401 with a key -> tells the user to check the key (no retry)', async () => {
    const m = mockFetch(pdnsRoute({ 'example.com': () => json(BAD_KEY, 401) }));
    const err = await pdnsModule.run(domain, makeCtx({ fetch: m.fetch, keys: { mnemonic: KEY } })).catch((e: unknown) => e);
    expect(m.calls).toHaveLength(1);
    expect((err as FetchError).status).toBe(401);
    expect((err as FetchError).message).toMatch(/rejected the Argus API key \(HTTP 401\) \(Invalid API key\)/);
  });

  it('cancellation propagates as an aborted FetchError, without a request or a 412-style retry', async () => {
    const ac = new AbortController();
    ac.abort();
    const m = mockFetch(pdnsRoute({ 'example.com': envelope(DOMAIN_RECORDS) }));
    const err = await pdnsModule.run(domain, makeCtx({ fetch: m.fetch, signal: ac.signal, keys: { mnemonic: KEY } })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).kind).toBe('aborted');
    expect(m.calls).toHaveLength(0);
  });

  it('cancellation during the request is not swallowed', async () => {
    const ac = new AbortController();
    const m = mockFetch(
      pdnsRoute({
        'example.com': () => {
          ac.abort();
          throw new DOMException('The operation was aborted.', 'AbortError');
        },
      }),
    );
    const err = await pdnsModule.run(domain, makeCtx({ fetch: m.fetch, signal: ac.signal })).catch((e: unknown) => e);
    expect((err as FetchError).kind).toBe('aborted');
    expect(m.calls).toHaveLength(1);
  });

  it('HTTP 412 with a key falls back once to the public limit', async () => {
    const limits: string[] = [];
    const { out, calls } = await run(
      domain,
      [
        pdnsRoute({
          'example.com': (u: URL) => {
            limits.push(u.searchParams.get('limit') ?? '');
            return u.searchParams.get('limit') === String(AUTH_LIMIT)
              ? json({ responseCode: 412, messages: [{ message: 'Maximum result limit for public usage is 1000', type: 'FIELD_ERROR' }], data: null }, 412)
              : json(envelope(DOMAIN_RECORDS));
          },
        }),
      ],
      { mnemonic: KEY },
    );
    expect(limits).toEqual([String(AUTH_LIMIT), String(PUBLIC_LIMIT)]);
    expect(calls.every((c) => headerOf(c.init, 'Argus-API-Key') === KEY)).toBe(true);
    expect(out.data.records).toHaveLength(DOMAIN_RECORDS.length);
  });

  it('HTTP 412 without a key is reported, not retried', async () => {
    const body = { responseCode: 412, messages: [{ message: 'Maximum result limit for public usage is 1000', type: 'FIELD_ERROR' }], data: null };
    const m = mockFetch(pdnsRoute({ 'example.com': () => json(body, 412) }));
    const err = await pdnsModule.run(domain, makeCtx({ fetch: m.fetch })).catch((e: unknown) => e);
    expect(m.calls).toHaveLength(1);
    expect((err as FetchError).message).toBe('Mnemonic rejected the result limit (HTTP 412) (Maximum result limit for public usage is 1000).');
  });

  it('HTTP 5xx keeps the generic transport error', async () => {
    const err = await run(domain, [pdnsRoute({ 'example.com': () => text('<html>bad gateway</html>', 502) })]).catch((e: unknown) => e);
    expect((err as FetchError).status).toBe(502);
    expect((err as FetchError).message).toMatch(/^HTTP 502/);
  });

  it('rejects a key with characters that cannot be sent in a header, without a request', async () => {
    const m = mockFetch();
    const err = await pdnsModule.run(domain, makeCtx({ fetch: m.fetch, keys: { mnemonic: 'abcé def' } })).catch((e: unknown) => e);
    expect((err as Error).message).toMatch(/invalid characters/);
    expect(m.calls).toHaveLength(0);
  });

  it('network errors propagate', async () => {
    const m = mockFetch(() => {
      throw new TypeError('NetworkError when attempting to fetch resource.');
    });
    const err = await pdnsModule.run(domain, makeCtx({ fetch: m.fetch })).catch((e: unknown) => e);
    expect((err as FetchError).kind).toBe('network');
  });
});

describe('pdns key tester', () => {
  const http = (f: typeof fetch) => createHttp({ fetch: f, limiter: new RateLimiter(), signal: new AbortController().signal });

  it('accepts a working key', async () => {
    const m = mockFetch(pdnsRoute({ 'example.com': envelope([DOMAIN_RECORDS[0]], { count: 997, limit: 1 }) }));
    await expect(mnemonicKeyTester(KEY, http(m.fetch))).resolves.toBe('Key accepted (997 records for example.com).');
    expect(m.calls[0]!.url).toBe('https://api.mnemonic.no/pdns/v3/example.com?limit=1');
    expect(headerOf(m.calls[0]!.init, 'Argus-API-Key')).toBe(KEY);
  });

  it('explains a rejected key', async () => {
    const m = mockFetch(pdnsRoute({ 'example.com': () => json(BAD_KEY, 401) }));
    await expect(mnemonicKeyTester(KEY, http(m.fetch))).rejects.toThrow(/rejected the Argus API key \(HTTP 401\) \(Invalid API key\)/);
  });

  it('does not accept an in-body error code on HTTP 200', async () => {
    const m = mockFetch(pdnsRoute({ 'example.com': BAD_KEY }));
    await expect(mnemonicKeyTester(KEY, http(m.fetch))).rejects.toThrow(/rejected the Argus API key \(HTTP 401\) \(Invalid API key\)/);
  });
});

describe('pdns through the orchestrator', () => {
  it('runs without a key (keyOptional) and does not expand domain pivots from IPs', async () => {
    const events: RunEvent[] = [];
    const ipsModule: Module = {
      id: 'ips',
      label: 'IPs',
      version: 1,
      accepts: ['domain'],
      ttl: HOUR,
      async run() {
        return { data: {}, pivots: [{ kind: 'ip', value: '93.184.216.34' }] };
      },
    };
    const m = mockFetch(
      pdnsRoute({
        'example.com': envelope(DOMAIN_RECORDS),
        '93.184.216.34': envelope([rec('a', 'example.net', '93.184.216.34', '2015-04-02', '2026-01-12')]),
      }),
    );
    const deps: OrchestratorDeps = {
      modules: [ipsModule, pdnsModule as Module],
      isEnabled: () => true,
      allowActive: false,
      cache: memoryCache(),
      limiter: new RateLimiter(),
      settings: DEFAULT_SETTINGS,
      getKey: async () => undefined,
      fetch: m.fetch,
    };
    await investigate({ kind: 'domain', value: 'example.com' }, (e) => events.push(e), deps).done;

    const cards = events.filter((e): e is Extract<RunEvent, { type: 'card' }> => e.type === 'card').map((e) => e.card);
    const last = (id: string): CardState | undefined => cards.filter((c) => c.id === id).at(-1);
    expect(last('pdns|domain:example.com')!.status).toBe('ok');
    expect(last('pdns|ip:93.184.216.34')!.status).toBe('ok');
    expect((last('pdns|domain:example.com')!.data as PdnsData).authenticated).toBe(false);

    const entities = events.filter((e): e is Extract<RunEvent, { type: 'entity' }> => e.type === 'entity').map((e) => `${e.entity.kind}:${e.entity.value}`);
    expect(entities).toEqual(['domain:example.com', 'ip:93.184.216.34']);
    const pivots = events.filter((e): e is Extract<RunEvent, { type: 'pivot' }> => e.type === 'pivot' && e.from.moduleId === 'pdns');
    expect(pivots.map((p) => p.pivot.value)).toEqual(['example.net']);
    expect(m.calls).toHaveLength(2);
  });
});

describe('bareIndicator (copy button value)', () => {
  it.each([
    ['93.184.215.14 (2015-04-02 → 2026-11-20)', '93.184.215.14'],
    ['www.example.com [CNAME] (2020-01-01 → 2021-01-01)', 'www.example.com'],
    ['mail.example.com → 203.0.113.9 (2024-01-01 → 2024-02-01)', '203.0.113.9'],
    ['plain.example', 'plain.example'],
  ])('%s -> %s', async (line, expected) => {
    const { bareIndicator } = await import('@/modules/pdns');
    expect(bareIndicator(line)).toBe(expected);
  });
});
