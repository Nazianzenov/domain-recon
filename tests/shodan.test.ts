import { afterEach, describe, expect, it, vi } from 'vitest';
import { FetchError, createHttp, isAbortError } from '@/lib/http';
import { investigate, type OrchestratorDeps } from '@/lib/orchestrator';
import { RateLimiter } from '@/lib/ratelimit';
import { DEFAULT_SETTINGS } from '@/lib/settings';
import type { CardState, Entity, Fact, RunEvent } from '@/lib/types';
import { HOUR, SkipError } from '@/lib/types';
import {
  HOST_GAP_MS,
  MAX_PIVOTS,
  MAX_SERVICES,
  MAX_VULNS,
  parseHost,
  parseInternetDb,
  shodanKeyTest,
  shodanModule,
  type ShodanData,
} from '@/modules/shodan';
import { json, makeCtx, memoryCache, mockFetch, text, type Route } from './helpers';

const KEY = 'AbCdEfGhIjKlMnOpQrStUvWxYz012345';
const ip = (value: string): Entity => ({ kind: 'ip', value, depth: 1 });

// --- Fixtures shaped like the live APIs (docs/research/threat-intel.md §12) ---

const IDB_GOOGLE = { cpes: [], hostnames: ['dns.google'], ip: '8.8.8.8', ports: [53, 443], tags: ['pqc'], vulns: [] };
const IDB_NOT_FOUND = { detail: 'No information available' };

const IDB_SCANME = {
  cpes: ['cpe:/a:openbsd:openssh:6.6.1p1', 'cpe:/a:apache:http_server:2.4.7', 'cpe:/o:canonical:ubuntu_linux'],
  hostnames: ['scanme.nmap.org'],
  ip: '45.33.32.156',
  ports: [80, 22, 9929, 31337],
  tags: [],
  vulns: ['CVE-2016-8612', 'CVE-2023-25690', 'CVE-2017-15715', 'CVE-2023-31122'],
};

const IDB_C2 = {
  cpes: [],
  hostnames: [],
  ip: '139.180.203.104',
  ports: [443, 50050],
  tags: ['c2', 'self-signed'],
  vulns: [],
};

const IDB_V6 = { cpes: [], hostnames: ['dns.google'], ip: '2001:4860:4860::8888', ports: [53, 443], tags: [], vulns: [] };

const HOST_GOOGLE = {
  region_code: 'CA',
  ip: 134744072,
  ip_str: '8.8.8.8',
  org: 'Google',
  isp: 'Google LLC',
  asn: 'AS15169',
  os: null,
  ports: [53, 443],
  hostnames: ['dns.google'],
  domains: ['dns.google'],
  country_code: 'US',
  country_name: 'United States',
  city: 'Mountain View',
  last_update: '2026-11-25T07:26:00.000000',
  tags: ['pqc'],
  latitude: 37.4056,
  longitude: -122.0775,
  data: [
    {
      _shodan: { module: 'dns-udp', id: 'a1', crawler: 'c1', ptr: true },
      hash: -553166942,
      port: 53,
      transport: 'udp',
      dns: { resolver_hostname: null, recursive: true },
      timestamp: '2026-11-25T07:26:00.000000',
      ip_str: '8.8.8.8',
    },
    {
      _shodan: { module: 'https', id: 'a2' },
      port: 443,
      transport: 'tcp',
      product: 'Google Frontend',
      http: { html: '<html>'.padEnd(5000, 'x'), title: 'Google Public DNS' },
      ssl: { cert: { subject: { CN: 'dns.google' } } },
      timestamp: '2026-11-24T21:10:00.000000',
    },
    // Same port seen twice (e.g. a second banner without product): de-duplicated.
    { _shodan: { module: 'http' }, port: 443, transport: 'tcp', timestamp: '2026-11-20T00:00:00.000000' },
  ],
};

const HOST_SCANME = {
  ip: 757670044,
  ip_str: '45.33.32.156',
  org: 'Linode',
  isp: 'Akamai Connected Cloud',
  asn: 'AS63949',
  os: 'Linux',
  ports: [22, 80, 123, 9929, 31337],
  hostnames: ['scanme.nmap.org'],
  country_name: 'United States',
  city: 'Fremont',
  last_update: '2026-11-23T11:02:13.541202',
  tags: [],
  vulns: ['CVE-2016-8612', 'CVE-2024-38476'],
  data: [
    {
      _shodan: { module: 'ssh' },
      port: 22,
      transport: 'tcp',
      product: 'OpenSSH',
      version: '6.6.1p1 Ubuntu-2ubuntu2.13',
    },
    {
      _shodan: { module: 'http' },
      port: 80,
      transport: 'tcp',
      product: 'Apache httpd',
      version: '2.4.7',
      vulns: { 'CVE-2017-15715': { verified: false, cvss: 8.1 }, 'CVE-2016-8612': { verified: false } },
    },
    { _shodan: { module: 'ntp' }, port: 123, transport: 'udp' },
  ],
};

const HOST_NOT_FOUND = { error: 'No information available for that IP.' };
const HTML_401 = '<html><head><title>401 Unauthorized</title></head><body><h1>401 Unauthorized</h1></body></html>';
const API_INFO = {
  scan_credits: 100,
  usage_limits: { scan_credits: 100, query_credits: 100, monitored_ips: 16 },
  plan: 'dev',
  https: false,
  unlocked: true,
  query_credits: 98,
  monitored_ips: 0,
  unlocked_left: 98,
  telnet: false,
};

// --- Helpers ---

type Handler = unknown | ((u: URL, init: RequestInit) => Response);

const respond = (v: Handler, u: URL, init: RequestInit): Response =>
  typeof v === 'function' ? (v as (u: URL, i: RequestInit) => Response)(u, init) : json(v);

/** InternetDB route; a 404 handler is expressed with `json(IDB_NOT_FOUND, 404)`. */
function idbRoute(v: Handler): Route {
  return (u, init) => (u.host === 'internetdb.shodan.io' ? respond(v, u, init) : undefined);
}

function hostRoute(v: Handler): Route {
  return (u, init) => (u.host === 'api.shodan.io' && u.pathname.startsWith('/shodan/host/') ? respond(v, u, init) : undefined);
}

function infoRoute(v: Handler): Route {
  return (u, init) => (u.host === 'api.shodan.io' && u.pathname === '/api-info' ? respond(v, u, init) : undefined);
}

const fact = (facts: Fact[], prefix: string) => facts.find((f) => f.label.startsWith(prefix));
const values = (f: Fact | undefined) => (f ? (Array.isArray(f.value) ? f.value : [f.value]) : []);

async function run(e: Entity, routes: Route[], keys: Record<string, string> = {}) {
  const m = mockFetch(...routes);
  const ctx = makeCtx({ fetch: m.fetch, keys });
  const out = await shodanModule.run(e, ctx);
  return { out, calls: m.calls, facts: shodanModule.facts!(out.data, e) };
}

async function fails(e: Entity, routes: Route[], keys: Record<string, string> = {}): Promise<unknown> {
  const m = mockFetch(...routes);
  return shodanModule.run(e, makeCtx({ fetch: m.fetch, keys })).then(
    () => {
      throw new Error('expected run() to reject');
    },
    (err: unknown) => err,
  );
}

/** The key must never reach data, summary, facts or pivots. */
function expectNoKey(out: unknown, facts: Fact[]) {
  expect(JSON.stringify(out)).not.toContain(KEY);
  expect(JSON.stringify(facts)).not.toContain(KEY);
}

// ---------------------------------------------------------------------------

describe('shodan module metadata', () => {
  it('declares the contract the orchestrator relies on', () => {
    expect(shodanModule.id).toBe('shodan');
    expect(shodanModule.label).toBe('Shodan');
    expect(shodanModule.version).toBe(1);
    expect(shodanModule.accepts).toEqual(['ip']);
    expect(shodanModule.key).toBe('shodan');
    expect(shodanModule.keyOptional).toBe(true);
    expect(shodanModule.ttl).toBe(24 * HOUR);
    expect(shodanModule.active).toBeFalsy();
    expect(shodanModule.note).toMatch(/InternetDB/);
    expect(shodanModule.note).toMatch(/Membership/);
  });
});

describe('InternetDB only (no key)', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('parses a hit, makes exactly one keyless request and adds pivots/facts', async () => {
    const { out, calls, facts } = await run(ip('8.8.8.8'), [idbRoute(IDB_GOOGLE)]);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe('https://internetdb.shodan.io/8.8.8.8');
    expect(calls[0]!.init.method).toBe('GET');
    expect(calls[0]!.init.credentials).toBe('omit');

    const d = out.data;
    expect(d.ip).toBe('8.8.8.8');
    expect(d.internetdb).toEqual({
      ports: [53, 443],
      portCount: 2,
      hostnames: ['dns.google'],
      hostnameCount: 1,
      cpes: [],
      cpeCount: 0,
      tags: ['pqc'],
      vulns: [],
      vulnCount: 0,
    });
    expect(d.host).toBeNull();
    expect(d.hostStatus).toBe('no-key');
    expect(d.hostError).toBeUndefined();
    expect(d.guiUrl).toBe('https://www.shodan.io/host/8.8.8.8');

    expect(out.summary).toBe('Ports 53, 443 · tags: pqc');
    expect(out.severity).toBe('none');
    expect(out.pivots).toEqual([{ kind: 'domain', value: 'dns.google', note: 'Shodan hostname' }]);

    expect(values(fact(facts, 'Open ports'))).toEqual(['53, 443']);
    const hn = fact(facts, 'Hostnames');
    expect(hn?.pivot).toBe(true);
    expect(values(hn)).toEqual(['dns.google']);
    expect(fact(facts, 'Tags')?.tone).toBeUndefined();
    expect(values(fact(facts, 'Host API'))).toEqual(['Not queried (no Shodan API key)']);
    const link = fact(facts, 'Shodan');
    expect(link?.href).toBe('https://www.shodan.io/host/8.8.8.8');
    // Data is JSON-serialisable as-is.
    expect(JSON.parse(JSON.stringify(d))).toEqual(d);
  });

  it('404 "No information available" is no data, not an error', async () => {
    const { out, facts } = await run(ip('1.2.3.4'), [idbRoute(() => json(IDB_NOT_FOUND, 404))]);
    expect(out.data.internetdb).toBeNull();
    expect(out.data.internetdbError).toBeUndefined();
    expect(out.summary).toBe('No Shodan data');
    expect(out.severity).toBe('none');
    expect(out.pivots).toBeUndefined();
    expect(values(fact(facts, 'InternetDB'))).toEqual(['No information available']);
    expect(fact(facts, 'Open ports')).toBeUndefined();
    expect(fact(facts, 'Shodan')?.href).toBe('https://www.shodan.io/host/1.2.3.4');
  });

  it('IPv6: raw colons in the InternetDB path and GUI link', async () => {
    const { out, calls } = await run(ip('2001:4860:4860::8888'), [idbRoute(IDB_V6)]);
    expect(calls[0]!.url).toBe('https://internetdb.shodan.io/2001:4860:4860::8888');
    expect(out.data.ip).toBe('2001:4860:4860::8888');
    expect(out.data.guiUrl).toBe('https://www.shodan.io/host/2001:4860:4860::8888');
    expect(out.summary).toBe('Ports 53, 443');
  });

  it('canonicalises the IP before the lookup', async () => {
    const { calls, out } = await run(ip('2001:4860:4860:0:0:0:0:8888'), [idbRoute(IDB_V6)]);
    expect(calls[0]!.url).toBe('https://internetdb.shodan.io/2001:4860:4860::8888');
    expect(out.data.ip).toBe('2001:4860:4860::8888');
  });

  it('IPv4-mapped IPv6 is looked up as the IPv4 address (InternetDB, host API and GUI link)', async () => {
    const { calls, out } = await run(
      ip('::ffff:8.8.8.8'),
      [idbRoute(IDB_GOOGLE), hostRoute(HOST_GOOGLE)],
      { shodan: KEY },
    );
    expect(calls.map((c) => new URL(c.url).pathname).sort()).toEqual(['/8.8.8.8', '/shodan/host/8.8.8.8']);
    expect(out.data.ip).toBe('8.8.8.8');
    expect(out.data.guiUrl).toBe('https://www.shodan.io/host/8.8.8.8');
  });

  it('IPv4-mapped private addresses are still skipped', async () => {
    const m = mockFetch();
    await expect(shodanModule.run(ip('::ffff:192.168.1.1'), makeCtx({ fetch: m.fetch }))).rejects.toBeInstanceOf(SkipError);
    expect(m.calls).toHaveLength(0);
  });

  it('vulns -> low severity (exposure), newest CVEs first, warn facts, CPEs listed', async () => {
    const { out, facts } = await run(ip('45.33.32.156'), [idbRoute(IDB_SCANME)]);
    const idb = out.data.internetdb!;
    expect(idb.ports).toEqual([22, 80, 9929, 31337]);
    expect(idb.vulns).toEqual(['CVE-2023-31122', 'CVE-2023-25690', 'CVE-2017-15715', 'CVE-2016-8612']);
    expect(idb.vulnCount).toBe(4);
    expect(out.severity).toBe('low');
    expect(out.summary).toBe('Ports 22, 80, 9929, 31337 · 4 CVEs');
    const v = fact(facts, 'CVEs');
    expect(v?.tone).toBe('warn');
    expect(v?.label).toMatch(/unverified/);
    expect(values(v)).toHaveLength(4);
    expect(values(fact(facts, 'CPEs'))).toEqual(IDB_SCANME.cpes);
  });

  it('caps vulns at MAX_VULNS but keeps the full count', async () => {
    const vulns = Array.from({ length: 120 }, (_, i) => `CVE-2020-${1000 + i}`);
    const { out, facts } = await run(ip('45.33.32.156'), [idbRoute({ ...IDB_SCANME, vulns })]);
    const idb = out.data.internetdb!;
    expect(idb.vulns).toHaveLength(MAX_VULNS);
    expect(idb.vulnCount).toBe(120);
    expect(idb.vulns[0]).toBe('CVE-2020-1119');
    expect(out.summary).toContain('120 CVEs');
    expect(fact(facts, 'CVEs')?.label).toContain(`120, ${MAX_VULNS} shown`);
  });

  it('malicious tags -> high severity, explained first in the summary', async () => {
    const { out, facts } = await run(ip('139.180.203.104'), [idbRoute(IDB_C2)]);
    expect(out.severity).toBe('high');
    expect(out.summary).toBe('Shodan flags: c2 · Ports 443, 50050 · tags: self-signed');
    expect(fact(facts, 'Tags')?.tone).toBe('bad');
  });

  it.each(['malware', 'compromised', 'doublepulsar', 'botnet'])('tag %s -> high', async (tag) => {
    const { out } = await run(ip('139.180.203.104'), [idbRoute({ ...IDB_C2, tags: [tag] })]);
    expect(out.severity).toBe('high');
  });

  it('scanner tag -> low (weak signal), warn tone', async () => {
    const { out, facts } = await run(ip('139.180.203.104'), [idbRoute({ ...IDB_C2, tags: ['scanner'] })]);
    expect(out.severity).toBe('low');
    expect(fact(facts, 'Tags')?.tone).toBe('warn');
  });

  it('benign tags (cloud, cdn, vpn, tor, honeypot) stay none', async () => {
    const { out } = await run(ip('139.180.203.104'), [idbRoute({ ...IDB_C2, tags: ['cloud', 'cdn', 'vpn', 'tor', 'honeypot'] })]);
    expect(out.severity).toBe('none');
  });

  it('summary truncates long port lists', async () => {
    const ports = Array.from({ length: 30 }, (_, i) => 8000 + i);
    const { out } = await run(ip('139.180.203.104'), [idbRoute({ ...IDB_C2, tags: [], ports })]);
    expect(out.summary).toBe('Ports 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007 +22 more');
  });

  it('InternetDB rate limit (429 after the automatic retry) -> clear error', async () => {
    vi.useFakeTimers();
    const m = mockFetch(idbRoute(() => json({ detail: 'Too Many Requests' }, 429, { 'retry-after': '1' })));
    const p = shodanModule.run(ip('8.8.8.8'), makeCtx({ fetch: m.fetch })).catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(5_000);
    const err = await p;
    expect(m.calls).toHaveLength(2);
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).status).toBe(429);
    expect((err as FetchError).message).toMatch(/InternetDB rate limit/);
  });

  it('InternetDB 5xx -> error with status', async () => {
    const err = await fails(ip('8.8.8.8'), [idbRoute(() => json({ detail: 'Internal error' }, 502))]);
    expect((err as FetchError).status).toBe(502);
    expect((err as FetchError).message).toBe('Shodan InternetDB error (HTTP 502): Internal error.');
  });

  it.each([
    ['an array', []],
    ['a string', 'oops'],
    ['an object without InternetDB fields', { foo: 1 }],
  ])('malformed 200 payload (%s) -> parse error', async (_, body) => {
    const err = await fails(ip('8.8.8.8'), [idbRoute(body)]);
    expect((err as FetchError).kind).toBe('parse');
    expect((err as FetchError).message).toMatch(/unexpected response/);
  });

  it('non-JSON 200 -> parse error', async () => {
    const err = await fails(ip('8.8.8.8'), [idbRoute(() => text('<html>maintenance</html>'))]);
    expect((err as FetchError).kind).toBe('parse');
    expect((err as FetchError).message).toMatch(/not JSON/);
  });

  it('drops junk values inside fields', () => {
    const d = parseInternetDb({
      ip: '8.8.8.8',
      ports: [443, '22', -1, 70000, 1.5, 443, 80, null],
      hostnames: ['Dns.Google.', 1, null, '', 'bad host<script>', 'x'.repeat(300)],
      cpes: ['cpe:/a:nginx:nginx:1.25.3', 'not-a-cpe', 42],
      tags: ['Cloud', 'has space', 7],
      vulns: ['cve-2021-44228', '<img>', 3],
    })!;
    expect(d.ports).toEqual([80, 443]);
    expect(d.hostnames).toEqual(['dns.google']);
    expect(d.cpes).toEqual(['cpe:/a:nginx:nginx:1.25.3']);
    expect(d.tags).toEqual(['cloud']);
    expect(d.vulns).toEqual(['CVE-2021-44228']);
  });

  it('tolerates missing or wrongly typed fields', () => {
    const d = parseInternetDb({ ip: '8.8.8.8', ports: 'none', hostnames: {}, vulns: null })!;
    expect(d).toMatchObject({ ports: [], hostnames: [], cpes: [], tags: [], vulns: [], vulnCount: 0 });
  });

  it('skips non-IP and private/reserved entities without a request', async () => {
    const m = mockFetch();
    const ctx = makeCtx({ fetch: m.fetch });
    await expect(shodanModule.run({ kind: 'domain', value: 'example.com', depth: 0 }, ctx)).rejects.toBeInstanceOf(SkipError);
    await expect(shodanModule.run(ip('10.0.0.1'), ctx)).rejects.toBeInstanceOf(SkipError);
    await expect(shodanModule.run(ip('fe80::1'), ctx)).rejects.toBeInstanceOf(SkipError);
    await expect(shodanModule.run(ip('not-an-ip'), ctx)).rejects.toBeInstanceOf(SkipError);
    expect(m.calls).toHaveLength(0);
  });

  it('caps hostname pivots and only pivots real domain names', async () => {
    const hostnames = [
      '8-8-8-8.in-addr.arpa',
      'localhost',
      ...Array.from({ length: 30 }, (_, i) => `h${i}.example.net`),
    ];
    const { out } = await run(ip('8.8.8.8'), [idbRoute({ ...IDB_GOOGLE, hostnames })]);
    expect(out.pivots).toHaveLength(MAX_PIVOTS);
    expect(out.pivots![0]).toEqual({ kind: 'domain', value: 'h0.example.net', note: 'Shodan hostname' });
  });
});

describe('with an API key (InternetDB + host API)', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  const keys = { shodan: KEY };

  it('calls both endpoints; key only in the host query string', async () => {
    const { out, calls, facts } = await run(ip('8.8.8.8'), [idbRoute(IDB_GOOGLE), hostRoute(HOST_GOOGLE)], keys);
    expect(calls).toHaveLength(2);
    const idbCall = calls.find((c) => c.url.startsWith('https://internetdb.shodan.io/'))!;
    const hostCall = calls.find((c) => c.url.startsWith('https://api.shodan.io/'))!;
    expect(idbCall.url).toBe('https://internetdb.shodan.io/8.8.8.8');
    expect(idbCall.url).not.toContain(KEY);
    const u = new URL(hostCall.url);
    expect(u.pathname).toBe('/shodan/host/8.8.8.8');
    expect(u.searchParams.get('key')).toBe(KEY);
    expect(u.searchParams.has('minify')).toBe(false);
    // No key in any header of either request.
    for (const c of calls) expect(JSON.stringify(c.init.headers ?? {})).not.toContain(KEY);

    const h = out.data.host!;
    expect(out.data.hostStatus).toBe('ok');
    expect(h).toMatchObject({
      org: 'Google',
      isp: 'Google LLC',
      asn: 'AS15169',
      os: null,
      country: 'United States',
      city: 'Mountain View',
      lastUpdate: '2026-11-25T07:26:00Z',
      ports: [53, 443],
      serviceCount: 2,
    });
    expect(h.services).toEqual([
      { port: 53, transport: 'udp', product: null, version: null, module: 'dns-udp' },
      { port: 443, transport: 'tcp', product: 'Google Frontend', version: null, module: 'https' },
    ]);
    // Compact: no banner bodies stored.
    expect(JSON.stringify(out.data)).not.toContain('Google Public DNS');
    expect(JSON.stringify(out.data).length).toBeLessThan(1500);

    expect(out.summary).toBe('Ports 53, 443 · tags: pqc · Google');
    expect(out.severity).toBe('none');
    expect(values(fact(facts, 'Services'))).toEqual(['53/udp dns-udp', '443/tcp https · Google Frontend']);
    expect(values(fact(facts, 'Org / ASN'))).toEqual(['Google · AS15169']);
    expect(values(fact(facts, 'ISP'))).toEqual(['Google LLC']);
    expect(values(fact(facts, 'Location'))).toEqual(['Mountain View, United States']);
    expect(values(fact(facts, 'Last scanned'))).toEqual(['2026-11-25']);
    expect(fact(facts, 'Host API')).toBeUndefined();
    expectNoKey(out, facts);
  });

  it('URL-encodes the key', async () => {
    const odd = 'ab+c/d=e&f';
    const { calls } = await run(ip('8.8.8.8'), [idbRoute(IDB_GOOGLE), hostRoute(HOST_GOOGLE)], { shodan: odd });
    const hostCall = calls.find((c) => c.url.startsWith('https://api.shodan.io/'))!;
    expect(hostCall.url).toContain(`key=${encodeURIComponent(odd)}`);
    expect(new URL(hostCall.url).searchParams.get('key')).toBe(odd);
  });

  it('a whitespace-only key behaves like no key', async () => {
    const { calls, out } = await run(ip('8.8.8.8'), [idbRoute(IDB_GOOGLE)], { shodan: '   ' });
    expect(calls).toHaveLength(1);
    expect(out.data.hostStatus).toBe('no-key');
  });

  it('merges host vulns (top level + banners) with InternetDB and lists services', async () => {
    const { out, facts } = await run(ip('45.33.32.156'), [idbRoute(IDB_SCANME), hostRoute(HOST_SCANME)], keys);
    const h = out.data.host!;
    expect(h.vulns).toEqual(['CVE-2024-38476', 'CVE-2017-15715', 'CVE-2016-8612']);
    expect(h.vulnCount).toBe(3);
    expect(h.os).toBe('Linux');
    expect(h.services.map((s) => `${s.port}/${s.transport}`)).toEqual(['22/tcp', '80/tcp', '123/udp']);
    const all = values(fact(facts, 'CVEs'));
    expect(all).toEqual(['CVE-2024-38476', 'CVE-2023-31122', 'CVE-2023-25690', 'CVE-2017-15715', 'CVE-2016-8612']);
    expect(out.severity).toBe('low');
    expect(out.summary).toBe('Ports 22, 80, 123, 9929, 31337 · 5 CVEs · Linode');
    expect(values(fact(facts, 'Services'))).toContain('22/tcp ssh · OpenSSH 6.6.1p1 Ubuntu-2ubuntu2.13');
    expect(values(fact(facts, 'ISP'))).toEqual(['Akamai Connected Cloud']);
  });

  it('host tags alone can raise severity', async () => {
    const { out } = await run(
      ip('8.8.8.8'),
      [idbRoute(() => json(IDB_NOT_FOUND, 404)), hostRoute({ ...HOST_GOOGLE, tags: ['malware'] })],
      keys,
    );
    expect(out.data.internetdb).toBeNull();
    expect(out.severity).toBe('high');
    expect(out.summary).toMatch(/^Shodan flags: malware · /);
  });

  it('caps services at MAX_SERVICES and keeps the count', async () => {
    const data = Array.from({ length: 35 }, (_, i) => ({ _shodan: { module: 'http' }, port: 8000 + i, transport: 'tcp' }));
    const { out, facts } = await run(ip('8.8.8.8'), [idbRoute(IDB_GOOGLE), hostRoute({ ...HOST_GOOGLE, ports: [], data })], keys);
    expect(out.data.host!.services).toHaveLength(MAX_SERVICES);
    expect(out.data.host!.serviceCount).toBe(35);
    expect(out.data.host!.portCount).toBe(35);
    expect(fact(facts, 'Services')?.label).toBe(`Services · 35, ${MAX_SERVICES} shown`);
  });

  it('IPv6 host lookup keeps raw colons', async () => {
    const { calls } = await run(
      ip('2001:4860:4860::8888'),
      [idbRoute(IDB_V6), hostRoute({ ...HOST_GOOGLE, ip_str: '2001:4860:4860::8888' })],
      keys,
    );
    const hostCall = calls.find((c) => c.url.startsWith('https://api.shodan.io/'))!;
    expect(new URL(hostCall.url).pathname).toBe('/shodan/host/2001:4860:4860::8888');
  });

  it('host 404 -> not-found, InternetDB kept, no error', async () => {
    const { out, facts } = await run(ip('8.8.8.8'), [idbRoute(IDB_GOOGLE), hostRoute(() => json(HOST_NOT_FOUND, 404))], keys);
    expect(out.data.hostStatus).toBe('not-found');
    expect(out.data.host).toBeNull();
    expect(out.data.hostError).toBeUndefined();
    expect(out.data.internetdb?.ports).toEqual([53, 443]);
    expect(out.summary).toBe('Ports 53, 443 · tags: pqc');
    expect(values(fact(facts, 'Host API'))).toEqual(['No information available for this IP']);
  });

  it('both 404 -> "No Shodan data"', async () => {
    const { out } = await run(
      ip('1.2.3.4'),
      [idbRoute(() => json(IDB_NOT_FOUND, 404)), hostRoute(() => json(HOST_NOT_FOUND, 404))],
      keys,
    );
    expect(out.summary).toBe('No Shodan data');
    expect(out.severity).toBe('none');
  });

  it('invalid key (HTML 401) -> hostError, InternetDB data kept, key never echoed', async () => {
    const { out, facts } = await run(ip('8.8.8.8'), [idbRoute(IDB_GOOGLE), hostRoute(() => text(HTML_401, 401))], keys);
    expect(out.data.hostStatus).toBe('error');
    expect(out.data.host).toBeNull();
    expect(out.data.hostError).toMatch(/rejected the API key \(HTTP 401\)/);
    expect(out.data.internetdb?.ports).toEqual([53, 443]);
    expect(out.summary).toBe('Ports 53, 443 · tags: pqc · host lookup failed');
    const f = fact(facts, 'Host API');
    expect(f?.tone).toBe('warn');
    expect(values(f)[0]).toMatch(/rejected the API key/);
    expectNoKey(out, facts);
  });

  it('403 (no Membership) -> clear hostError', async () => {
    const { out } = await run(
      ip('8.8.8.8'),
      [idbRoute(IDB_GOOGLE), hostRoute(() => json({ error: 'Access denied (403 Forbidden)' }, 403))],
      keys,
    );
    expect(out.data.hostError).toMatch(/HTTP 403.*Membership/);
  });

  it('quota: 429 after the automatic retry -> hostError, InternetDB kept', async () => {
    vi.useFakeTimers();
    const m = mockFetch(
      idbRoute(IDB_GOOGLE),
      hostRoute(() => json({ error: 'Rate limit reached' }, 429, { 'retry-after': '1' })),
    );
    const p = shodanModule.run(ip('8.8.8.8'), makeCtx({ fetch: m.fetch, keys }));
    await vi.advanceTimersByTimeAsync(5_000);
    const out = await p;
    expect(m.calls.filter((c) => c.url.startsWith('https://api.shodan.io/'))).toHaveLength(2);
    expect(out.data.hostError).toMatch(/rate limit or quota hit \(HTTP 429\)/);
    expect(out.data.internetdb?.ports).toEqual([53, 443]);
  });

  it('other host errors keep the provider detail but never the key', async () => {
    const echo: Route = hostRoute(() => json({ error: `Invalid request for key ${KEY}` }, 400));
    const { out, facts } = await run(ip('8.8.8.8'), [idbRoute(IDB_GOOGLE), echo], keys);
    expect(out.data.hostError).toBe('Shodan host API error (HTTP 400): Invalid request for key [key].');
    expectNoKey(out, facts);
  });

  it('host network failure -> hostError without the URL', async () => {
    const boom: Route = (u) => {
      if (u.host === 'api.shodan.io') throw new TypeError('NetworkError when attempting to fetch resource.');
      return undefined;
    };
    const { out, facts } = await run(ip('8.8.8.8'), [idbRoute(IDB_GOOGLE), boom], keys);
    expect(out.data.hostError).toMatch(/^Shodan host API: Network error/);
    expect(out.data.hostError).not.toContain('api.shodan.io');
    expectNoKey(out, facts);
  });

  it.each([
    ['an array', []],
    ['an object without host fields', { foo: 'bar' }],
  ])('malformed host payload (%s) -> hostError, InternetDB kept', async (_, body) => {
    const { out } = await run(ip('8.8.8.8'), [idbRoute(IDB_GOOGLE), hostRoute(body)], keys);
    expect(out.data.hostStatus).toBe('error');
    expect(out.data.hostError).toMatch(/unexpected response/);
    expect(out.data.internetdb).not.toBeNull();
  });

  it('host succeeds while InternetDB fails -> data with internetdbError', async () => {
    const { out, facts } = await run(
      ip('8.8.8.8'),
      [idbRoute(() => json({ detail: 'Bad gateway' }, 502)), hostRoute(HOST_GOOGLE)],
      keys,
    );
    expect(out.data.internetdb).toBeNull();
    expect(out.data.internetdbError).toMatch(/HTTP 502/);
    expect(out.data.host?.org).toBe('Google');
    expect(out.summary).toBe('Ports 53, 443 · tags: pqc · Google · InternetDB failed');
    expect(fact(facts, 'InternetDB')?.tone).toBe('warn');
  });

  it('both fail -> one error naming both, without the key', async () => {
    const err = await fails(
      ip('8.8.8.8'),
      [idbRoute(() => json({ detail: 'Bad gateway' }, 502)), hostRoute(() => text(HTML_401, 401))],
      keys,
    );
    expect(err).toBeInstanceOf(FetchError);
    const fe = err as FetchError;
    expect(fe.status).toBe(502);
    expect(fe.message).toMatch(/InternetDB error \(HTTP 502\).*Host API: Shodan rejected the API key/);
    expect(fe.message).not.toContain(KEY);
    expect(fe.url).not.toContain(KEY);
  });

  it('a key with invalid characters is reported without a request', async () => {
    const { out, calls } = await run(ip('8.8.8.8'), [idbRoute(IDB_GOOGLE)], { shodan: 'abcédef' });
    expect(calls).toHaveLength(1);
    expect(out.data.hostError).toMatch(/invalid characters/);
  });

  it('uses separate rate-limit buckets for InternetDB and the host API', async () => {
    const acquire = vi.spyOn(RateLimiter.prototype, 'acquire');
    try {
      await run(ip('8.8.8.8'), [idbRoute(IDB_GOOGLE), hostRoute(HOST_GOOGLE)], keys);
      const buckets = acquire.mock.calls.map(([k, perMinute]) => `${k}:${perMinute}`).sort();
      expect(buckets).toEqual(['shodan-internetdb:60', 'shodan:60']);
    } finally {
      acquire.mockRestore();
    }
  });

  it('spaces host lookups within one investigation (1 req/s, no burst); InternetDB is not held back', async () => {
    vi.useFakeTimers();
    const hostAt: number[] = [];
    const idbAt: number[] = [];
    const m = mockFetch(
      idbRoute(() => {
        idbAt.push(Date.now());
        return json(IDB_GOOGLE);
      }),
      hostRoute(() => {
        hostAt.push(Date.now());
        return json(HOST_GOOGLE);
      }),
    );
    // One ctx = one investigation (shared memo), as the orchestrator does for concurrent IP cards.
    const ctx = makeCtx({ fetch: m.fetch, keys });
    const runs = Promise.all(['8.8.8.8', '8.8.4.4', '1.1.1.1'].map((v) => shodanModule.run(ip(v), ctx)));
    await vi.advanceTimersByTimeAsync(10_000);
    const outs = await runs;
    expect(outs.map((o) => o.data.hostStatus)).toEqual(['ok', 'ok', 'ok']);
    expect(hostAt).toHaveLength(3);
    expect(hostAt[1]! - hostAt[0]!).toBeGreaterThanOrEqual(HOST_GAP_MS);
    expect(hostAt[2]! - hostAt[1]!).toBeGreaterThanOrEqual(HOST_GAP_MS);
    expect(Math.max(...idbAt) - Math.min(...idbAt)).toBeLessThan(HOST_GAP_MS);
  });

  it('cancel during the host lookup propagates as an abort, without the key in the error', async () => {
    const ac = new AbortController();
    const m = mockFetch(
      idbRoute(IDB_GOOGLE),
      hostRoute(() => {
        ac.abort();
        throw new DOMException('The operation was aborted.', 'AbortError');
      }),
    );
    const err = await shodanModule.run(ip('8.8.8.8'), makeCtx({ fetch: m.fetch, keys, signal: ac.signal })).catch((e: unknown) => e);
    expect(isAbortError(err)).toBe(true);
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).url).toBe('https://api.shodan.io/shodan/host/8.8.8.8');
    expect(JSON.stringify(err)).not.toContain(KEY);
    expect(String((err as Error).message)).not.toContain(KEY);
  });

  it('cancel while waiting for the host slot aborts without sending the request', async () => {
    vi.useFakeTimers();
    const ac = new AbortController();
    const m = mockFetch(idbRoute(IDB_GOOGLE), hostRoute(HOST_GOOGLE));
    const ctx = makeCtx({ fetch: m.fetch, keys, signal: ac.signal });
    const first = shodanModule.run(ip('8.8.8.8'), ctx);
    const second = shodanModule.run(ip('8.8.4.4'), ctx).catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(100);
    expect((await first).data.hostStatus).toBe('ok');
    ac.abort();
    const err = await second;
    expect(isAbortError(err)).toBe(true);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(m.calls.filter((c) => c.url.startsWith('https://api.shodan.io/'))).toHaveLength(1);
  });

  it('a host-API abort is not turned into hostError (orchestrator does not cache it)', async () => {
    const m = mockFetch(
      idbRoute(IDB_GOOGLE),
      hostRoute(() => {
        throw new DOMException('The operation was aborted.', 'AbortError');
      }),
    );
    const cache = memoryCache();
    const store = vi.spyOn(cache, 'storeResult');
    const storeError = vi.spyOn(cache, 'storeError');
    const { investigation, done } = investigate({ kind: 'ip', value: '8.8.8.8' }, () => undefined, {
      modules: [shodanModule],
      isEnabled: () => true,
      allowActive: false,
      cache,
      limiter: new RateLimiter(),
      settings: DEFAULT_SETTINGS,
      getKey: async (p) => (p === 'shodan' ? KEY : undefined),
      fetch: (input, init) => {
        // Route the abort through the investigation's own signal.
        if (String(input).startsWith('https://api.shodan.io/')) investigation.cancel();
        return m.fetch(input, init);
      },
    });
    await done;
    expect(store).not.toHaveBeenCalled();
    expect(storeError).not.toHaveBeenCalled();
  });
});

describe('parseHost', () => {
  it('accepts numeric ASN, missing banners and naive timestamps', () => {
    const h = parseHost({ ip_str: '1.1.1.1', asn: 13335, ports: [80], last_update: '2026-11-01 10:00:00', country_code: 'AU' });
    expect(h.asn).toBe('AS13335');
    expect(h.services).toEqual([]);
    expect(h.ports).toEqual([80]);
    expect(h.lastUpdate).toBe('2026-11-01T10:00:00Z');
    expect(h.country).toBe('AU');
    expect(h.org).toBeNull();
  });

  it('rejects junk timestamps and ASNs', () => {
    const h = parseHost({ ip_str: '1.1.1.1', asn: 'Google', last_update: 'yesterday', data: [{ port: 'x' }, null] });
    expect(h.asn).toBeNull();
    expect(h.lastUpdate).toBeNull();
    expect(h.services).toEqual([]);
  });

  it('collapses control characters from banner strings and caps their length', () => {
    const h = parseHost({
      ip_str: '1.1.1.1',
      org: 'Evil\r\nCorp\u0000',
      data: [{ port: 80, transport: 'tcp', product: 'Apache\r\nX-Injected: 1', version: 'v'.repeat(500), _shodan: { module: 'http' } }],
    });
    expect(h.org).toBe('Evil Corp');
    expect(h.services[0]!.product).toBe('Apache X-Injected: 1');
    expect(h.services[0]!.version).toHaveLength(50);
  });

  it('host-level vulns map form and banner vulns are merged and de-duplicated', () => {
    const h = parseHost({
      ip_str: '1.1.1.1',
      vulns: { 'CVE-2021-44228': {}, 'cve-2019-0708': {} },
      data: [{ port: 443, vulns: { 'CVE-2021-44228': { verified: false } } }],
    });
    expect(h.vulns).toEqual(['CVE-2021-44228', 'CVE-2019-0708']);
    expect(h.vulnCount).toBe(2);
  });
});

describe('orchestrator integration', () => {
  function collect() {
    const cards = new Map<string, CardState>();
    const emit = (e: RunEvent) => {
      if (e.type === 'card') cards.set(e.card.id, e.card);
    };
    return { cards, emit };
  }

  function deps(f: typeof fetch, keys: Record<string, string> = {}): OrchestratorDeps {
    return {
      modules: [shodanModule],
      isEnabled: () => true,
      allowActive: false,
      cache: memoryCache(),
      limiter: new RateLimiter(),
      settings: DEFAULT_SETTINGS,
      getKey: async (p) => keys[p],
      fetch: f,
    };
  }

  it('runs without a key (keyOptional) and reports severity', async () => {
    const m = mockFetch(idbRoute(IDB_C2));
    const { cards, emit } = collect();
    const { done } = investigate({ kind: 'ip', value: '139.180.203.104' }, emit, deps(m.fetch));
    await done;
    const card = cards.get('shodan|ip:139.180.203.104');
    expect(card?.status).toBe('ok');
    expect(card?.severity).toBe('high');
    expect((card?.data as ShodanData).hostStatus).toBe('no-key');
  });

  it('with a key: the card never contains the key', async () => {
    const m = mockFetch(idbRoute(IDB_GOOGLE), hostRoute(() => text(HTML_401, 401)));
    const { cards, emit } = collect();
    const { done } = investigate({ kind: 'ip', value: '8.8.8.8' }, emit, deps(m.fetch, { shodan: KEY }));
    await done;
    const card = cards.get('shodan|ip:8.8.8.8');
    expect(card?.status).toBe('ok');
    expect(JSON.stringify(card)).not.toContain(KEY);
  });
});

describe('shodanKeyTest', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  const http = (f: typeof fetch) => createHttp({ fetch: f, limiter: new RateLimiter(), signal: new AbortController().signal });

  it('GET /api-info?key= and reports plan and credits', async () => {
    const m = mockFetch(infoRoute(API_INFO));
    const msg = await shodanKeyTest(KEY, http(m.fetch));
    expect(msg).toBe('Key valid · plan: dev · 98 query credits · 100 scan credits');
    expect(msg).not.toContain(KEY);
    expect(m.calls).toHaveLength(1);
    const u = new URL(m.calls[0]!.url);
    expect(u.origin + u.pathname).toBe('https://api.shodan.io/api-info');
    expect(u.searchParams.get('key')).toBe(KEY);
    expect(JSON.stringify(m.calls[0]!.init.headers ?? {})).not.toContain(KEY);
  });

  it('trims the key', async () => {
    const m = mockFetch(infoRoute(API_INFO));
    await shodanKeyTest(`  ${KEY}\n`, http(m.fetch));
    expect(new URL(m.calls[0]!.url).searchParams.get('key')).toBe(KEY);
  });

  it('bad key (HTML 401) -> clear error without the key', async () => {
    const m = mockFetch(infoRoute(() => text(HTML_401, 401)));
    const err = (await shodanKeyTest(KEY, http(m.fetch)).catch((e: unknown) => e)) as Error;
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toMatch(/rejected the API key \(HTTP 401\)/);
    expect(err.message).not.toContain(KEY);
  });

  it('403 -> rejected-key message without the key', async () => {
    const m = mockFetch(infoRoute(() => json({ error: `Access denied for ${KEY}` }, 403)));
    const err = (await shodanKeyTest(KEY, http(m.fetch)).catch((e: unknown) => e)) as Error;
    expect(err.message).toMatch(/rejected the API key \(HTTP 403\)/);
    expect(err.message).not.toContain(KEY);
  });

  it('other HTTP errors keep the provider detail with the key redacted', async () => {
    const m = mockFetch(infoRoute(() => json({ error: `Bad request for key ${KEY}` }, 400)));
    const err = (await shodanKeyTest(KEY, http(m.fetch)).catch((e: unknown) => e)) as Error;
    expect(err.message).toBe('Shodan error (HTTP 400): Bad request for key [key].');
  });

  it('HTML 200 (not JSON) -> unexpected-response error', async () => {
    const m = mockFetch(infoRoute(() => text('<html>maintenance</html>')));
    await expect(shodanKeyTest(KEY, http(m.fetch))).rejects.toThrow(/unexpected response \(not JSON\)/);
  });

  it('429 -> rate-limit message', async () => {
    const m = mockFetch(infoRoute(() => json({ error: 'Rate limit reached' }, 429, { 'retry-after': '0' })));
    vi.useFakeTimers();
    const p = shodanKeyTest(KEY, http(m.fetch)).catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(5_000);
    const err = (await p) as Error;
    expect(err.message).toMatch(/rate limit/i);
  });

  it('malformed response -> error', async () => {
    await expect(shodanKeyTest(KEY, http(mockFetch(infoRoute([])).fetch))).rejects.toThrow(/unexpected response/);
    await expect(shodanKeyTest(KEY, http(mockFetch(infoRoute({ foo: 1 })).fetch))).rejects.toThrow(/no plan or credits/);
  });

  it('empty key or invalid characters -> error without a request', async () => {
    const m = mockFetch();
    await expect(shodanKeyTest('   ', http(m.fetch))).rejects.toThrow(/Enter a Shodan API key/);
    await expect(shodanKeyTest('kéy', http(m.fetch))).rejects.toThrow(/invalid characters/);
    expect(m.calls).toHaveLength(0);
  });

  it('network failure -> "Could not reach Shodan"', async () => {
    const m = mockFetch(() => {
      throw new TypeError('NetworkError when attempting to fetch resource.');
    });
    await expect(shodanKeyTest(KEY, http(m.fetch))).rejects.toThrow(/Could not reach Shodan/);
  });
});
