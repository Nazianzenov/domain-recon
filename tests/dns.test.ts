import { describe, expect, it } from 'vitest';
import { FetchError, isAbortError } from '@/lib/http';
import type { Entity, Fact } from '@/lib/types';
import { MINUTE } from '@/lib/types';
import {
  dnsModule,
  dnsSummary,
  parseDmarc,
  parseGenericCaa,
  rnameToEmail,
  spfAllQualifier,
  type DnsData,
} from '@/modules/dns';
import { json, makeCtx, mockFetch, type Route } from './helpers';

// ---------------------------------------------------------------------------
// Fixture helpers (shapes from docs/research/dns-rdap.md and live probes on 2026-11-25)
// ---------------------------------------------------------------------------

const T = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, CAA: 257 } as const;
type TypeName = keyof typeof T;

const CF_HOST = 'cloudflare-dns.com';
const G_HOST = 'dns.google';
const COM_SOA = 'a.gtld-servers.net. nstld.verisign-grs.com. 1795606003 1800 900 604800 900';
const GITHUB_SOA = 'dns1.p08.nsone.net. hostmaster.nsone.net. 1656468023 43200 7200 1209600 3600';

const rr = (name: string, type: number, data: string, TTL = 300) => ({ name, type, TTL, data });

function answer(name: string, type: TypeName, answers: ReturnType<typeof rr>[], extra: Record<string, unknown> = {}) {
  return { Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name, type: T[type] }], Answer: answers, ...extra };
}

function nodata(name: string, type: TypeName, soaOwner: string, soa: string, pre: ReturnType<typeof rr>[] = []) {
  return {
    Status: 0,
    TC: false,
    RD: true,
    RA: true,
    AD: false,
    CD: false,
    Question: [{ name, type: T[type] }],
    ...(pre.length ? { Answer: pre } : {}),
    Authority: [rr(soaOwner, T.SOA, soa, 900)],
  };
}

function nxdomain(name: string, type: TypeName, pre: ReturnType<typeof rr>[] = []) {
  return {
    Status: 3,
    TC: false,
    RD: true,
    RA: true,
    AD: false,
    CD: false,
    Question: [{ name, type: T[type] }],
    ...(pre.length ? { Answer: pre } : {}),
    Authority: [rr('com', T.SOA, COM_SOA, 900)],
  };
}

type Zone = Partial<Record<string, unknown>>;
const key = (name: string, type: TypeName) => `${name} ${type}`;

/** Serve a zone (keyed "name TYPE") from one resolver host. Unknown keys fall through (-> unmocked). */
function serve(host: string, zone: Zone): Route {
  return (url) => {
    if (url.host !== host) return undefined;
    const name = url.searchParams.get('name') ?? '';
    const type = url.searchParams.get('type') ?? '';
    const body = zone[`${name} ${type}`];
    if (body === undefined) return undefined;
    return body instanceof Response ? body : json(body, 200, { 'content-type': host === CF_HOST ? 'application/dns-json' : 'application/json' });
  };
}

function down(host: string): Route {
  return (url) => {
    if (url.host === host) throw new TypeError('NetworkError when attempting to fetch resource.');
    return undefined;
  };
}

async function runDns(domain: string, ...routes: Route[]) {
  const m = mockFetch(...routes);
  const ctx = makeCtx({ fetch: m.fetch, root: domain, now: () => Date.parse('2026-11-25T12:00:00Z') });
  const entity: Entity = { kind: 'domain', value: domain, depth: 0 };
  const out = await dnsModule.run(entity, ctx);
  const facts = dnsModule.facts!(out.data, entity);
  return { out, data: out.data, facts, calls: m.calls };
}

const fact = (facts: Fact[], label: string) => facts.find((f) => f.label === label);
const factStarting = (facts: Fact[], prefix: string) => facts.find((f) => f.label.startsWith(prefix));

// ---------------------------------------------------------------------------
// github.com (live 2026-11-25, trimmed)
// ---------------------------------------------------------------------------

const GITHUB_SPF_CF =
  '"v=spf1 ip4:192.30.252.0/22 ip4:172.170.10.240/28 ip4:40.78.162.192/28 ip4:172.170.3.48/28 include:spf.protection.outlook.com include:_netblocks.google.com include:_netblocks2.google.com include:mail.zendesk.com include:_spf.salesforce.com include:servers." "mcsv.net include:mktomail.com include:sendgrid.net ip4:62.253.227.114 ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ~all"';
const GITHUB_SPF =
  'v=spf1 ip4:192.30.252.0/22 ip4:172.170.10.240/28 ip4:40.78.162.192/28 ip4:172.170.3.48/28 include:spf.protection.outlook.com include:_netblocks.google.com include:_netblocks2.google.com include:mail.zendesk.com include:_spf.salesforce.com include:servers.mcsv.net include:mktomail.com include:sendgrid.net ip4:62.253.227.114 ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ~all';
const GITHUB_DMARC = 'v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@github.com; ruf=mailto:dmarc@github.com; fo=1';

const GITHUB: Zone = {
  [key('github.com', 'A')]: answer('github.com', 'A', [rr('github.com', T.A, '140.82.121.4', 60)]),
  [key('github.com', 'AAAA')]: nodata('github.com', 'AAAA', 'github.com', GITHUB_SOA),
  [key('github.com', 'NS')]: answer(
    'github.com',
    'NS',
    [
      'ns-520.awsdns-01.net.',
      'dns1.p08.nsone.net.',
      'dns2.p08.nsone.net.',
      'ns-1283.awsdns-32.org.',
      'dns3.p08.nsone.net.',
      'dns4.p08.nsone.net.',
      'ns-1707.awsdns-21.co.uk.',
      'ns-421.awsdns-52.com.',
    ].map((d) => rr('github.com', T.NS, d, 1297)),
  ),
  [key('github.com', 'MX')]: answer(
    'github.com',
    'MX',
    ['10 alt4.aspmx.l.google.com.', '5 alt2.aspmx.l.google.com.', '1 aspmx.l.google.com.', '10 alt3.aspmx.l.google.com.', '5 alt1.aspmx.l.google.com.'].map(
      (d) => rr('github.com', T.MX, d),
    ),
  ),
  [key('github.com', 'TXT')]: answer(
    'github.com',
    'TXT',
    [
      '"MS=ms44452932"',
      GITHUB_SPF_CF,
      '"apple-domain-verification=RyQhdzTl6Z6x8ZP4"',
      '"docusign=087098e3-3d46-47b7-9b4e-8a23028154cd"',
      '"MS=ms44452932"', // duplicate (deduped)
    ].map((d) => rr('github.com', T.TXT, d)),
  ),
  [key('github.com', 'CNAME')]: nodata('github.com', 'CNAME', 'github.com', GITHUB_SOA),
  [key('github.com', 'SOA')]: answer('github.com', 'SOA', [rr('github.com', T.SOA, GITHUB_SOA, 3600)]),
  [key('github.com', 'CAA')]: answer(
    'github.com',
    'CAA',
    [
      '0 issue "digicert.com"',
      '0 issue "globalsign.com"',
      '0 issue "letsencrypt.org"',
      '0 issue "sectigo.com"',
      '0 issuewild "digicert.com"',
      '0 issuewild "letsencrypt.org"',
      '0 issuewild "sectigo.com"',
    ].map((d) => rr('github.com', T.CAA, d, 3600)),
  ),
  [key('_dmarc.github.com', 'TXT')]: answer('_dmarc.github.com', 'TXT', [rr('_dmarc.github.com', T.TXT, `"${GITHUB_DMARC}"`, 152)]),
};

describe('dnsModule metadata', () => {
  it('is a passive, keyless domain module with a 5 minute TTL', () => {
    expect(dnsModule.id).toBe('dns');
    expect(dnsModule.label).toBe('DNS (DoH)');
    expect(dnsModule.version).toBe(1);
    expect(dnsModule.accepts).toEqual(['domain']);
    expect(dnsModule.ttl).toBe(5 * MINUTE);
    expect(dnsModule.active).toBeFalsy();
    expect(dnsModule.key).toBeUndefined();
  });
});

describe('dnsModule.run: github.com', () => {
  it('runs exactly 9 lookups against Cloudflare only (never the domain itself)', async () => {
    const { calls } = await runDns('github.com', serve(CF_HOST, GITHUB));
    expect(calls).toHaveLength(9);
    expect(new Set(calls.map((c) => new URL(c.url).host))).toEqual(new Set([CF_HOST]));
    const asked = calls.map((c) => {
      const u = new URL(c.url);
      return `${u.searchParams.get('name')} ${u.searchParams.get('type')}`;
    });
    expect(asked.sort()).toEqual(Object.keys(GITHUB).sort());
    for (const c of calls) expect((c.init.headers as Record<string, string>)['accept']).toBe('application/dns-json');
  });

  it('parses every record type into compact data', async () => {
    const { data, out } = await runDns('github.com', serve(CF_HOST, GITHUB));
    expect(data).toEqual<DnsData>({
      resolvers: ['cloudflare'],
      apexStatus: 'NOERROR',
      dnssec: false,
      a: ['140.82.121.4'],
      aaaa: [],
      cname: [],
      ns: [
        'dns1.p08.nsone.net',
        'dns2.p08.nsone.net',
        'dns3.p08.nsone.net',
        'dns4.p08.nsone.net',
        'ns-1283.awsdns-32.org',
        'ns-1707.awsdns-21.co.uk',
        'ns-421.awsdns-52.com',
        'ns-520.awsdns-01.net',
      ],
      mx: [
        { preference: 1, exchange: 'aspmx.l.google.com' },
        { preference: 5, exchange: 'alt1.aspmx.l.google.com' },
        { preference: 5, exchange: 'alt2.aspmx.l.google.com' },
        { preference: 10, exchange: 'alt3.aspmx.l.google.com' },
        { preference: 10, exchange: 'alt4.aspmx.l.google.com' },
      ],
      txt: ['MS=ms44452932', GITHUB_SPF, 'apple-domain-verification=RyQhdzTl6Z6x8ZP4', 'docusign=087098e3-3d46-47b7-9b4e-8a23028154cd'],
      soa: {
        zone: 'github.com',
        mname: 'dns1.p08.nsone.net',
        rname: 'hostmaster.nsone.net',
        serial: 1656468023,
        refresh: 43200,
        retry: 7200,
        expire: 1209600,
        minimum: 3600,
      },
      caa: [
        { flags: 0, tag: 'issue', value: 'digicert.com' },
        { flags: 0, tag: 'issue', value: 'globalsign.com' },
        { flags: 0, tag: 'issue', value: 'letsencrypt.org' },
        { flags: 0, tag: 'issue', value: 'sectigo.com' },
        { flags: 0, tag: 'issuewild', value: 'digicert.com' },
        { flags: 0, tag: 'issuewild', value: 'letsencrypt.org' },
        { flags: 0, tag: 'issuewild', value: 'sectigo.com' },
      ],
      spf: GITHUB_SPF,
      spfCount: 1,
      dmarc: { record: GITHUB_DMARC, p: 'quarantine', sp: 'reject', pct: 100, rua: ['mailto:dmarc@github.com'] },
      dmarcCount: 1,
      errors: {},
    });
    expect(out.summary).toBe('1 A · 5 MX · SPF · DMARC p=quarantine');
    expect(out.pivots).toEqual([{ kind: 'ip', value: '140.82.121.4', note: 'A record' }]);
    // JSON-serialisable (cached in IndexedDB, exported).
    expect(JSON.parse(JSON.stringify(data))).toEqual(data);
  });

  it('facts: pivots, tones and readable SOA/CAA', async () => {
    const { facts } = await runDns('github.com', serve(CF_HOST, GITHUB));
    expect(fact(facts, 'Status')).toBeUndefined();
    expect(fact(facts, 'A')).toEqual({ label: 'A', value: ['140.82.121.4'], pivot: true });
    expect(fact(facts, 'AAAA')).toBeUndefined();
    expect(fact(facts, 'NS')?.pivot).toBe(true);
    expect(fact(facts, 'MX (by preference)')).toEqual({
      label: 'MX (by preference)',
      value: ['aspmx.l.google.com', 'alt1.aspmx.l.google.com', 'alt2.aspmx.l.google.com', 'alt3.aspmx.l.google.com', 'alt4.aspmx.l.google.com'],
      pivot: true,
    });
    expect(fact(facts, 'SPF')).toEqual({ label: 'SPF', value: GITHUB_SPF, tone: 'good' });
    expect(fact(facts, 'DMARC')).toEqual({ label: 'DMARC', value: GITHUB_DMARC, tone: 'good' });
    expect(fact(facts, 'DMARC reports (rua)')?.value).toEqual(['mailto:dmarc@github.com']);
    expect(fact(facts, 'CAA')?.value).toContain('issue letsencrypt.org');
    expect(fact(facts, 'CAA')?.value).toContain('issuewild sectigo.com');
    expect(fact(facts, 'SOA')?.value).toBe('dns1.p08.nsone.net (contact hostmaster@nsone.net, serial 1656468023)');
    expect(fact(facts, 'DNSSEC')).toEqual({ label: 'DNSSEC', value: 'no (answer not DNSSEC-validated)' });
    expect(fact(facts, 'Resolver')?.value).toBe('Cloudflare');
    expect(fact(facts, 'Lookup errors')).toBeUndefined();
    for (const f of facts) if (f.href !== undefined) expect(f.href).toMatch(/^https:\/\//);
  });
});

// ---------------------------------------------------------------------------
// CNAME chains, dual stack, dedupe
// ---------------------------------------------------------------------------

describe('dnsModule.run: CNAME chain', () => {
  const D = 'www.microsoft.com';
  const H1 = 'www.microsoft.com-c-3.edgekey.net';
  const H2 = 'www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net';
  const H3 = 'e13678.dscb.akamaiedge.net';
  const chain = [rr(D, T.CNAME, `${H1}.`, 3600), rr(H1, T.CNAME, `${H2}.`, 900), rr(H2, T.CNAME, `${H3}.`, 900)];
  const AKAMAI_SOA = 'n0dscb.akamaiedge.net. hostmaster.akamai.com. 1764072001 1000 1000 1000 1800';

  const zone: Zone = {
    [key(D, 'A')]: answer(D, 'A', [
      ...chain,
      rr(H3, T.A, '23.62.226.180', 20),
      rr(H3, T.A, '23.62.226.180', 20), // duplicate
      rr(H3, T.A, 'not-an-ip', 20), // junk
      rr(H3, T.A, '2a02:26f0:f4:389::356e', 20), // v6 under type 1: ignored
    ]),
    [key(D, 'AAAA')]: answer(D, 'AAAA', [
      ...chain,
      rr(H3, T.AAAA, '2A02:26F0:00F4:0389:0000:0000:0000:356E', 20),
      rr(H3, T.AAAA, '2a02:26f0:f4:389::356e', 20), // same address, canonical form
      rr(H3, T.AAAA, '23.62.226.180', 20), // v4 under type 28: ignored
    ]),
    [key(D, 'NS')]: nodata(D, 'NS', 'dscb.akamaiedge.net', AKAMAI_SOA, chain),
    [key(D, 'MX')]: nodata(D, 'MX', 'dscb.akamaiedge.net', AKAMAI_SOA, chain),
    [key(D, 'TXT')]: nodata(D, 'TXT', 'dscb.akamaiedge.net', AKAMAI_SOA, chain),
    [key(D, 'CNAME')]: answer(D, 'CNAME', [chain[0]!]),
    [key(D, 'SOA')]: nodata(D, 'SOA', 'dscb.akamaiedge.net', AKAMAI_SOA, chain),
    [key(D, 'CAA')]: nodata(D, 'CAA', 'dscb.akamaiedge.net', AKAMAI_SOA, chain),
    [key(`_dmarc.${D}`, 'TXT')]: nxdomain(`_dmarc.${D}`, 'TXT'),
  };

  it('follows the chain in order and pivots on deduped A/AAAA only', async () => {
    const { data, out, facts } = await runDns(D, serve(CF_HOST, zone));
    expect(data.cname).toEqual([H1, H2, H3]);
    expect(data.a).toEqual(['23.62.226.180']);
    expect(data.aaaa).toEqual(['2a02:26f0:f4:389::356e']);
    expect(out.pivots).toEqual([
      { kind: 'ip', value: '23.62.226.180', note: 'A record' },
      { kind: 'ip', value: '2a02:26f0:f4:389::356e', note: 'AAAA record' },
    ]);
    expect(data.apexStatus).toBe('NOERROR');
    expect(data.ns).toEqual([]);
    expect(data.mx).toEqual([]);
    expect(data.dmarc).toBeNull();
    expect(data.errors).toEqual({});
    // SOA from Authority on NODATA, labelled with its zone.
    expect(data.soa?.zone).toBe('dscb.akamaiedge.net');
    expect(fact(facts, 'SOA (zone dscb.akamaiedge.net)')?.value).toContain('hostmaster@akamai.com');
    expect(out.summary).toBe(`CNAME → ${H3} · 1 A · 1 AAAA`);
    expect(fact(facts, 'CNAME chain')).toEqual({ label: 'CNAME chain', value: [H1, H2, H3], pivot: true });
    expect(fact(facts, 'DMARC')?.value).toBe(`none at _dmarc.${D} (an organisational-domain policy may still apply)`);
    expect(fact(facts, 'CAA')?.value).toBe('none at this name (a parent-domain CAA may still apply)');
    expect(fact(facts, 'DMARC')?.tone).toBe('warn');
    expect(fact(facts, 'SPF')).toEqual({ label: 'SPF', value: 'none', tone: 'warn' });
  });

  it('survives a CNAME loop', async () => {
    const loop = [rr('a.example.com', T.CNAME, 'b.example.com.'), rr('b.example.com', T.CNAME, 'a.example.com.')];
    const z: Zone = {};
    for (const t of ['A', 'AAAA', 'NS', 'MX', 'TXT', 'SOA', 'CAA'] as const) z[key('a.example.com', t)] = { Status: 2, Answer: loop };
    z[key('a.example.com', 'CNAME')] = answer('a.example.com', 'CNAME', [loop[0]!]);
    z[key('_dmarc.a.example.com', 'TXT')] = nxdomain('_dmarc.a.example.com', 'TXT');
    const { data } = await runDns('a.example.com', serve(CF_HOST, z), serve(G_HOST, z));
    expect(data.cname).toEqual(['b.example.com']);
  });
});

// ---------------------------------------------------------------------------
// NXDOMAIN and dangling CNAME
// ---------------------------------------------------------------------------

describe('dnsModule.run: NXDOMAIN', () => {
  it('apex NXDOMAIN is a successful result with no pivots', async () => {
    const D = 'this-does-not-exist-zz9.com';
    const z: Zone = {};
    for (const t of ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CNAME', 'SOA', 'CAA'] as const) z[key(D, t)] = nxdomain(D, t);
    z[key(`_dmarc.${D}`, 'TXT')] = nxdomain(`_dmarc.${D}`, 'TXT');
    const { data, out, facts, calls } = await runDns(D, serve(CF_HOST, z));
    expect(calls).toHaveLength(9); // NXDOMAIN is an answer: no Google fallback
    expect(out.summary).toBe('NXDOMAIN (domain does not resolve)');
    expect(out.pivots).toBeUndefined();
    expect(data.apexStatus).toBe('NXDOMAIN');
    expect(data.soa).toBeNull(); // the Authority SOA belongs to "com", not this domain
    expect(data.errors).toEqual({});
    expect(fact(facts, 'Status')).toEqual({ label: 'Status', value: 'NXDOMAIN (domain does not resolve)', tone: 'warn' });
    expect(fact(facts, 'SPF')).toBeUndefined();
    expect(fact(facts, 'DMARC')).toBeUndefined();
    expect(fact(facts, 'CAA')).toBeUndefined();
    expect(fact(facts, 'DNSSEC')).toEqual({ label: 'DNSSEC', value: 'no (answer not DNSSEC-validated)' });

    // A validated NXDOMAIN (signed parent zone) must not read as "this domain is DNSSEC-signed".
    const signed = await runDns(D, serve(CF_HOST, { ...z, [key(D, 'A')]: { ...nxdomain(D, 'A'), AD: true } }));
    expect(signed.data.dnssec).toBe(true);
    expect(fact(signed.facts, 'DNSSEC')).toEqual({ label: 'DNSSEC', value: 'non-existence proof validated (AD flag)' });
  });

  it('dangling CNAME (Status 3 with the CNAME in Answer) is flagged as a takeover candidate', async () => {
    const D = 'shop.example.com';
    const target = 'example-shop.azurewebsites.net';
    const cn = rr(D, T.CNAME, `${target}.`, 3600);
    const z: Zone = {};
    for (const t of ['A', 'AAAA', 'NS', 'MX', 'TXT', 'SOA', 'CAA'] as const) z[key(D, t)] = nxdomain(D, t, [cn]);
    z[key(D, 'CNAME')] = answer(D, 'CNAME', [cn]);
    z[key(`_dmarc.${D}`, 'TXT')] = nxdomain(`_dmarc.${D}`, 'TXT');
    const { data, out, facts } = await runDns(D, serve(CF_HOST, z));
    expect(data.apexStatus).toBe('NXDOMAIN');
    expect(data.cname).toEqual([target]);
    expect(out.summary).toBe(`Dangling CNAME → ${target} (NXDOMAIN)`);
    expect(out.pivots).toBeUndefined();
    const status = fact(facts, 'Status');
    expect(status?.tone).toBe('bad');
    expect(status?.value).toContain('takeover');
  });
});

// ---------------------------------------------------------------------------
// Failures and fallback
// ---------------------------------------------------------------------------

describe('dnsModule.run: failures', () => {
  it('one lookup failing on both resolvers is recorded, the rest still render', async () => {
    const z = { ...GITHUB };
    delete z[key('github.com', 'MX')];
    const mxDown: Route = (url) => {
      if (url.searchParams.get('type') !== 'MX') return undefined;
      if (url.host === CF_HOST) throw new TypeError('NetworkError when attempting to fetch resource.');
      return new Response('<html>Server Error</html>', { status: 500, headers: { 'content-type': 'text/html' } });
    };
    const { data, out, facts } = await runDns('github.com', mxDown, serve(CF_HOST, z));
    expect(Object.keys(data.errors)).toEqual(['MX']);
    expect(data.errors.MX).toContain('HTTP 500');
    expect(data.mx).toEqual([]);
    expect(data.a).toEqual(['140.82.121.4']);
    expect(data.resolvers).toEqual(['cloudflare']);
    expect(out.summary).toBe('1 A · SPF · DMARC p=quarantine · 1 lookup failed');
    expect(fact(facts, 'Lookup errors')).toMatchObject({ tone: 'warn' });
    expect((fact(facts, 'Lookup errors')?.value as string[])[0]).toMatch(/^MX: HTTP 500/);
  });

  it('a failed TXT or DMARC lookup is reported as unknown, not as missing', async () => {
    const z = { ...GITHUB };
    delete z[key('github.com', 'TXT')];
    delete z[key('_dmarc.github.com', 'TXT')];
    const { data, facts } = await runDns('github.com', serve(CF_HOST, z), down(CF_HOST), down(G_HOST));
    expect(Object.keys(data.errors).sort()).toEqual(['DMARC', 'TXT']);
    expect(fact(facts, 'SPF')).toEqual({ label: 'SPF', value: 'unknown (TXT lookup failed)', tone: 'warn' });
    expect(fact(facts, 'DMARC')).toEqual({ label: 'DMARC', value: 'unknown (lookup failed)', tone: 'warn' });
  });

  it('throws a typed error when every lookup failed', async () => {
    const err = await runDns('github.com', down(CF_HOST), down(G_HOST)).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).kind).toBe('network');
    expect((err as FetchError).message).toMatch(/^All 9 DNS lookups failed: /);
  });

  it('rethrows cancellation instead of reporting per-type errors', async () => {
    const ac = new AbortController();
    ac.abort();
    const m = mockFetch(serve(CF_HOST, GITHUB));
    const ctx = makeCtx({ fetch: m.fetch, signal: ac.signal });
    const err = await dnsModule.run({ kind: 'domain', value: 'github.com', depth: 0 }, ctx).catch((e: unknown) => e);
    expect(isAbortError(err)).toBe(true);
    expect(m.calls).toHaveLength(0);
  });

  it('falls back to Google (unquoted TXT, trailing dots) when Cloudflare is down', async () => {
    const g: Zone = {
      [key('github.com', 'A')]: { Status: 0, AD: false, Answer: [rr('github.com.', T.A, '140.82.121.3', 60)] },
      [key('github.com', 'AAAA')]: { Status: 0, Authority: [rr('github.com.', T.SOA, GITHUB_SOA, 900)] },
      [key('github.com', 'NS')]: { Status: 0, Answer: [rr('github.com.', T.NS, 'dns1.p08.nsone.net.')] },
      [key('github.com', 'MX')]: { Status: 0, Answer: [rr('github.com.', T.MX, '1 aspmx.l.google.com.')] },
      [key('github.com', 'TXT')]: { Status: 0, Answer: [rr('github.com.', T.TXT, GITHUB_SPF, 105)] },
      [key('github.com', 'CNAME')]: { Status: 0, Authority: [rr('github.com.', T.SOA, GITHUB_SOA, 900)] },
      [key('github.com', 'SOA')]: { Status: 0, Answer: [rr('github.com.', T.SOA, GITHUB_SOA)] },
      [key('github.com', 'CAA')]: { Status: 0, Answer: [rr('github.com.', T.CAA, '0 issue "digicert.com"')] },
      [key('_dmarc.github.com', 'TXT')]: { Status: 0, Answer: [rr('_dmarc.github.com.', T.TXT, GITHUB_DMARC)], Comment: 'Response from 205.251.193.165.' },
    };
    const { data, out, facts, calls } = await runDns('github.com', down(CF_HOST), serve(G_HOST, g));
    expect(calls).toHaveLength(18);
    expect(data.resolvers).toEqual(['google']);
    expect(data.spf).toBe(GITHUB_SPF);
    expect(data.dmarc?.p).toBe('quarantine');
    expect(data.soa?.zone).toBe('github.com');
    expect(data.ns).toEqual(['dns1.p08.nsone.net']);
    expect(out.summary).toBe('1 A · 1 MX · SPF · DMARC p=quarantine');
    expect(fact(facts, 'Resolver')?.value).toBe('Google');
  });

  it('mixed resolvers when Cloudflare SERVFAILs one lookup', async () => {
    const z = { ...GITHUB, [key('github.com', 'CAA')]: { Status: 2, Comment: ['EDE(22): No Reachable Authority'] } };
    const g: Zone = { [key('github.com', 'CAA')]: { Status: 0, Answer: [rr('github.com.', T.CAA, '0 issue "digicert.com"')] } };
    const { data, facts } = await runDns('github.com', serve(CF_HOST, z), serve(G_HOST, g));
    expect(data.resolvers).toEqual(['cloudflare', 'google']);
    expect(data.caa).toEqual([{ flags: 0, tag: 'issue', value: 'digicert.com' }]);
    expect(data.errors).toEqual({});
    expect(fact(facts, 'Resolver')?.value).toBe('Cloudflare, Google (fallback)');
  });

  it('SERVFAIL from both resolvers everywhere is a result (broken delegation / DNSSEC bogus), not a throw', async () => {
    const D = 'dnssec-failed.org';
    const servfail = { Status: 2, Comment: ['EDE(9): DNSKEY Missing'] };
    const cf: Zone = {};
    const g: Zone = {};
    for (const t of ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CNAME', 'SOA', 'CAA'] as const) {
      cf[key(D, t)] = servfail;
      g[key(D, t)] = { Status: 2, Comment: 'DNSSEC validation failure. Please check http://dnsviz.net/d/dnssec-failed.org/dnssec/.' };
    }
    cf[key(`_dmarc.${D}`, 'TXT')] = servfail;
    g[key(`_dmarc.${D}`, 'TXT')] = { Status: 2 };
    const { data, out, facts } = await runDns(D, serve(CF_HOST, cf), serve(G_HOST, g));
    expect(data.apexStatus).toBe('SERVFAIL');
    expect(Object.keys(data.errors)).toHaveLength(9);
    expect(data.errors.A).toMatch(/^SERVFAIL: DNSSEC validation failure/);
    expect(data.errors.DMARC).toBe('SERVFAIL');
    expect(out.summary).toBe('SERVFAIL (resolvers could not resolve the domain)');
    expect(out.pivots).toBeUndefined();
    expect(fact(facts, 'Status')?.tone).toBe('warn');
    // A bogus signature SERVFAILs: "DNSSEC: no" would be wrong, there is simply no answer to judge.
    expect(fact(facts, 'DNSSEC')).toEqual({ label: 'DNSSEC', value: 'unknown (no answer to validate)' });
  });

  it('every apex lookup failing (only DMARC answered) is not reported as a resolver verdict', async () => {
    const D = 'github.com';
    const dmarcOnly: Zone = { [key('_dmarc.github.com', 'TXT')]: GITHUB[key('_dmarc.github.com', 'TXT')] };
    const { data, out, facts } = await runDns(D, serve(CF_HOST, dmarcOnly), down(CF_HOST), down(G_HOST));
    expect(data.apexStatus).toBe('UNKNOWN');
    expect(Object.keys(data.errors)).toHaveLength(8);
    expect(out.summary).toBe('DMARC p=quarantine · 8 lookups failed');
    expect(fact(facts, 'Status')).toEqual({ label: 'Status', value: 'unknown (every lookup at the domain failed)', tone: 'warn' });
    expect(fact(facts, 'DNSSEC')?.value).toBe('unknown (no answer to validate)');
    expect(fact(facts, 'SPF')?.value).toBe('unknown (TXT lookup failed)');

    const none: Zone = { [key('_dmarc.github.com', 'TXT')]: nxdomain('_dmarc.github.com', 'TXT') };
    const r2 = await runDns(D, serve(CF_HOST, none), down(CF_HOST), down(G_HOST));
    expect(r2.out.summary).toBe('8 lookups failed');
  });

  it('cancellation mid-run is rethrown even after some lookups already answered', async () => {
    const ac = new AbortController();
    const abortOnMx: Route = (url) => {
      if (url.searchParams.get('type') !== 'MX') return undefined;
      ac.abort();
      throw new DOMException('The operation was aborted.', 'AbortError');
    };
    const m = mockFetch(abortOnMx, serve(CF_HOST, GITHUB));
    const ctx = makeCtx({ fetch: m.fetch, signal: ac.signal });
    const err = await dnsModule.run({ kind: 'domain', value: 'github.com', depth: 0 }, ctx).catch((e: unknown) => e);
    expect(isAbortError(err)).toBe(true);
    // A, AAAA and NS were already in flight and answered before the cancel.
    expect(m.calls.length).toBeGreaterThan(1);
    expect(m.calls.some((c) => new URL(c.url).host === G_HOST)).toBe(false);
  });

  it('skips non-domain entities', async () => {
    const m = mockFetch();
    const ctx = makeCtx({ fetch: m.fetch });
    await expect(dnsModule.run({ kind: 'ip', value: '1.1.1.1', depth: 1 }, ctx)).rejects.toMatchObject({ name: 'SkipError' });
    expect(m.calls).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Email-auth edge cases, null MX, DNSSEC, caps
// ---------------------------------------------------------------------------

function simpleZone(D: string, over: Partial<Record<TypeName | 'DMARC', unknown>>): Zone {
  const SOA = `ns1.${D}. hostmaster.${D}. 2026112501 7200 3600 1209600 3600`;
  const z: Zone = {};
  for (const t of ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CNAME', 'SOA', 'CAA'] as const) z[key(D, t)] = over[t] ?? nodata(D, t, D, SOA);
  z[key(`_dmarc.${D}`, 'TXT')] = over.DMARC ?? nxdomain(`_dmarc.${D}`, 'TXT');
  return z;
}

describe('dnsModule.run: email auth and misc', () => {
  it('multiple SPF records, null MX and DMARC p=none are warned about', async () => {
    const D = 'example.net';
    const z = simpleZone(D, {
      A: answer(D, 'A', [rr(D, T.A, '93.184.215.14')]),
      MX: answer(D, 'MX', [rr(D, T.MX, '0 .')]),
      TXT: answer(D, 'TXT', [
        rr(D, T.TXT, '"v=spf1 -all"'),
        rr(D, T.TXT, '"V=SPF1 include:_spf.google.com ~all"'),
        rr(D, T.TXT, '"v=spf10 not-spf"'),
      ]),
      DMARC: answer(`_dmarc.${D}`, 'TXT', [
        rr(`_dmarc.${D}`, T.TXT, '"v=DMARC1; p=none; rua=mailto:a@example.net, mailto:reports@dmarc.example!10m"'),
        rr(`_dmarc.${D}`, T.TXT, '"google-site-verification=abc"'),
      ]),
    });
    const { data, out, facts } = await runDns(D, serve(CF_HOST, z));
    expect(data.spfCount).toBe(2);
    expect(data.spf).toBe('v=spf1 -all');
    expect(data.mx).toEqual([{ preference: 0, exchange: '' }]);
    expect(data.dmarc).toEqual({
      record: 'v=DMARC1; p=none; rua=mailto:a@example.net, mailto:reports@dmarc.example!10m',
      p: 'none',
      rua: ['mailto:a@example.net', 'mailto:reports@dmarc.example!10m'],
    });
    expect(data.dmarcCount).toBe(1);
    expect(out.summary).toBe('1 A · null MX · 2× SPF · DMARC p=none');
    expect(fact(facts, 'SPF')?.tone).toBe('warn');
    expect((fact(facts, 'SPF')?.value as string[])[0]).toContain('2 SPF records');
    expect(fact(facts, 'DMARC')?.tone).toBe('warn');
    expect(fact(facts, 'MX')).toEqual({ label: 'MX', value: 'null MX (domain accepts no mail, RFC 7505)' });
    expect(fact(facts, 'CAA')).toEqual({ label: 'CAA', value: 'none (any CA may issue)' });
    expect(fact(facts, 'DMARC')?.value).toBe('v=DMARC1; p=none; rua=mailto:a@example.net, mailto:reports@dmarc.example!10m');
  });

  it('multiple DMARC records and a missing p= are flagged', async () => {
    const D = 'example.org';
    const two = simpleZone(D, {
      DMARC: answer(`_dmarc.${D}`, 'TXT', [
        rr(`_dmarc.${D}`, T.TXT, '"v=DMARC1; p=reject"'),
        rr(`_dmarc.${D}`, T.TXT, '"v=DMARC1; p=none"'),
      ]),
    });
    const r1 = await runDns(D, serve(CF_HOST, two));
    expect(r1.data.dmarcCount).toBe(2);
    // Receivers ignore DMARC when several records exist: the summary must not claim p=reject.
    expect(r1.out.summary).toBe('no A/AAAA · 2× DMARC');
    expect(fact(r1.facts, 'DMARC')?.tone).toBe('warn');
    expect((fact(r1.facts, 'DMARC')?.value as string[])[0]).toContain('2 DMARC records');

    const noP = simpleZone(D, { DMARC: answer(`_dmarc.${D}`, 'TXT', [rr(`_dmarc.${D}`, T.TXT, '"v=DMARC1; rua=mailto:d@example.org"')]) });
    const r2 = await runDns(D, serve(CF_HOST, noP));
    expect(r2.data.dmarc?.p).toBeNull();
    expect(r2.out.summary).toContain('DMARC p=?');
    expect(fact(r2.facts, 'DMARC')?.tone).toBe('warn');
  });

  it('SPF +all is bad, ?all warns, -all is good; DMARC reject with pct<100 has no tone', async () => {
    const D = 'example.com';
    const mk = (spf: string, dmarc = 'v=DMARC1; p=reject') =>
      simpleZone(D, {
        TXT: answer(D, 'TXT', [rr(D, T.TXT, `"${spf}"`)]),
        DMARC: answer(`_dmarc.${D}`, 'TXT', [rr(`_dmarc.${D}`, T.TXT, `"${dmarc}"`)]),
      });
    expect(fact((await runDns(D, serve(CF_HOST, mk('v=spf1 +all')))).facts, 'SPF')?.tone).toBe('bad');
    expect(fact((await runDns(D, serve(CF_HOST, mk('v=spf1 a mx ?all')))).facts, 'SPF')?.tone).toBe('warn');
    expect(fact((await runDns(D, serve(CF_HOST, mk('v=spf1 include:_spf.google.com')))).facts, 'SPF')?.tone).toBe('warn');
    expect(fact((await runDns(D, serve(CF_HOST, mk('v=spf1 redirect=_spf.example.com')))).facts, 'SPF')?.tone).toBeUndefined();
    const r = await runDns(D, serve(CF_HOST, mk('v=spf1 -all', 'v=DMARC1; p=reject; pct=25')));
    expect(fact(r.facts, 'SPF')?.tone).toBe('good');
    expect(r.data.dmarc?.pct).toBe(25);
    expect(fact(r.facts, 'DMARC')?.tone).toBeUndefined();
  });

  it('DNSSEC: AD flag on the apex answer', async () => {
    const D = 'cloudflare.com';
    const z = simpleZone(D, {
      A: answer(D, 'A', [rr(D, T.A, '104.16.132.229'), rr(D, T.A, '104.16.133.229')], { AD: true }),
      AAAA: answer(D, 'AAAA', [rr(D, T.AAAA, '2606:4700::6810:84e5'), rr(D, T.AAAA, '2606:4700::6810:85e5')], { AD: true }),
    });
    const { data, out, facts } = await runDns(D, serve(CF_HOST, z));
    expect(data.dnssec).toBe(true);
    expect(fact(facts, 'DNSSEC')).toEqual({ label: 'DNSSEC', value: 'yes (resolver validated the answer, AD flag)', tone: 'good' });
    expect(out.summary).toBe('2 A · 2 AAAA');
    expect(out.pivots?.map((p) => p.value)).toEqual(['104.16.132.229', '104.16.133.229', '2606:4700::6810:84e5', '2606:4700::6810:85e5']);
  });

  it('caps long lists, truncates long TXT and records totals', async () => {
    const D = 'big.example';
    const long = `x-verification=${'a'.repeat(600)}`;
    const txt = [...Array.from({ length: 34 }, (_, i) => `"token-${i}=v"`), `"${long}"`];
    const a = Array.from({ length: 60 }, (_, i) => rr(D, T.A, `198.51.${Math.floor(i / 250)}.${(i % 250) + 1}`));
    const z = simpleZone(D, {
      A: answer(D, 'A', a),
      TXT: answer(
        D,
        'TXT',
        // Put the long one first so it survives the cap.
        [txt[txt.length - 1]!, ...txt.slice(0, -1)].map((d) => rr(D, T.TXT, d)),
      ),
    });
    const { data, out, facts } = await runDns(D, serve(CF_HOST, z));
    expect(data.a).toHaveLength(50);
    expect(data.txt).toHaveLength(30);
    expect(data.totals).toEqual({ a: 60, txt: 35 });
    expect(data.txt[0]!.length).toBe(512);
    expect(data.txt[0]!.endsWith('…')).toBe(true);
    expect(out.summary).toBe('60 A');
    expect(out.pivots).toHaveLength(50);
    expect(factStarting(facts, 'TXT')?.label).toBe('TXT (30 of 35)');
    expect(factStarting(facts, 'A (')?.label).toBe('A (50 of 60)');
    expect(JSON.stringify(data).length).toBeLessThan(20_000);
  });

  it('nothing but NODATA: "no A/AAAA"', async () => {
    const D = 'empty.example';
    const { out, data } = await runDns(D, serve(CF_HOST, simpleZone(D, {})));
    expect(out.summary).toBe('no A/AAAA');
    expect(out.pivots).toBeUndefined();
    expect(data.soa?.zone).toBe(D);
  });

  it('clips oversized DMARC and CAA values; several null MX entries still read as null MX', async () => {
    const D = 'example.com';
    const huge = 'x'.repeat(5000);
    const z = simpleZone(D, {
      MX: answer(D, 'MX', [rr(D, T.MX, '0 .'), rr(D, T.MX, '10 .')]),
      CAA: answer(D, 'CAA', [rr(D, T.CAA, `0 issue "${huge}"`)]),
      DMARC: answer(`_dmarc.${D}`, 'TXT', [rr(`_dmarc.${D}`, T.TXT, `"v=DMARC1; p=${huge}; sp=${huge}; rua=mailto:${huge}@x.example; x=${huge}"`)]),
    });
    const { data, out, facts } = await runDns(D, serve(CF_HOST, z));
    expect(data.caa[0]!.value.length).toBe(512);
    expect(data.dmarc!.record.length).toBe(1024);
    expect(data.dmarc!.p!.length).toBe(32);
    expect(data.dmarc!.sp!.length).toBe(32);
    expect(data.dmarc!.rua![0]!.length).toBe(256);
    expect(out.summary!.length).toBeLessThan(200);
    expect(JSON.stringify(data).length).toBeLessThan(4000);
    expect(fact(facts, 'MX')).toEqual({ label: 'MX', value: 'null MX (domain accepts no mail, RFC 7505)' });
    expect(out.summary).toContain('null MX');
  });

  it('CAA in RFC 3597 generic form is decoded', async () => {
    const D = 'example.com';
    const z = simpleZone(D, {
      CAA: answer(D, 'CAA', [rr(D, T.CAA, '\\# 15 00 05 69 73 73 75 65 70 6b 69 2e 67 6f 6f 67'), rr(D, T.CAA, 'garbage')]),
    });
    const { data } = await runDns(D, serve(CF_HOST, z));
    expect(data.caa).toEqual([{ flags: 0, tag: 'issue', value: 'pki.goog' }]);
  });
});

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

describe('parseDmarc', () => {
  it('parses tags case-insensitively', () => {
    expect(parseDmarc('V=DMARC1; P=Reject; SP=none; PCT=50; RUA=mailto:a@x.com')).toEqual({
      record: 'V=DMARC1; P=Reject; SP=none; PCT=50; RUA=mailto:a@x.com',
      p: 'reject',
      sp: 'none',
      pct: 50,
      rua: ['mailto:a@x.com'],
    });
    expect(parseDmarc('v = DMARC1 ;p=quarantine')?.p).toBe('quarantine');
  });

  it('ignores invalid pct, keeps the first duplicate tag, tolerates empty parts', () => {
    expect(parseDmarc('v=DMARC1; p=reject; pct=150')).toEqual({ record: 'v=DMARC1; p=reject; pct=150', p: 'reject' });
    expect(parseDmarc('v=DMARC1; p=reject; p=none;;')?.p).toBe('reject');
    expect(parseDmarc('v=DMARC1')).toEqual({ record: 'v=DMARC1', p: null });
  });

  it('rejects non-DMARC records', () => {
    expect(parseDmarc('v=DMARC10; p=reject')).toBeNull();
    expect(parseDmarc('v=spf1 -all')).toBeNull();
    expect(parseDmarc('p=reject; v=DMARC1')).toBeNull();
    expect(parseDmarc('')).toBeNull();
  });

  it('caps rua at 10 entries and dedupes', () => {
    const rua = Array.from({ length: 15 }, (_, i) => `mailto:r${i}@x.com`);
    const m = parseDmarc(`v=DMARC1; p=none; rua=${rua.join(',')},mailto:r0@x.com`);
    expect(m?.rua).toEqual(rua.slice(0, 10));
  });
});

describe('helpers', () => {
  it('spfAllQualifier', () => {
    expect(spfAllQualifier('v=spf1 -all')).toBe('-');
    expect(spfAllQualifier('v=spf1 mx ~all')).toBe('~');
    expect(spfAllQualifier('v=spf1 ?all')).toBe('?');
    expect(spfAllQualifier('v=spf1 +all')).toBe('+');
    expect(spfAllQualifier('v=spf1 all')).toBe('+');
    expect(spfAllQualifier('v=spf1 -ALL')).toBe('-');
    expect(spfAllQualifier('v=spf1 include:allow.example.com')).toBeNull();
    expect(spfAllQualifier('v=spf1 redirect=_spf.example.com')).toBeNull();
  });

  it('parseGenericCaa', () => {
    expect(parseGenericCaa('\\# 15 00 05 69 73 73 75 65 70 6b 69 2e 67 6f 6f 67')).toEqual({ flags: 0, tag: 'issue', value: 'pki.goog' });
    expect(parseGenericCaa('\\# 16 00 05 69 73 73 75 65 70 6b 69 2e 67 6f 6f 67')).toBeNull(); // length mismatch
    expect(parseGenericCaa('\\# 2 00 05')).toBeNull(); // tag longer than data
    expect(parseGenericCaa('0 issue "pki.goog"')).toBeNull();
  });

  it('rnameToEmail', () => {
    expect(rnameToEmail('hostmaster.nsone.net')).toBe('hostmaster@nsone.net');
    expect(rnameToEmail('dns-admin.google.com')).toBe('dns-admin@google.com');
    expect(rnameToEmail('john\\.doe.example.com')).toBe('john.doe@example.com');
    expect(rnameToEmail('localhost')).toBe('localhost');
  });

  it('dnsSummary: empty NOERROR, failed lookups only, partial failure', () => {
    const d: DnsData = {
      resolvers: ['cloudflare'],
      apexStatus: 'NOERROR',
      dnssec: false,
      a: [],
      aaaa: [],
      cname: [],
      ns: [],
      mx: [],
      txt: [],
      soa: null,
      caa: [],
      spf: null,
      spfCount: 0,
      dmarc: null,
      dmarcCount: 0,
      errors: {},
    };
    expect(dnsSummary(d)).toBe('no A/AAAA');
    expect(dnsSummary({ ...d, errors: { A: 'x', AAAA: 'y' } })).toBe('2 lookups failed');
    expect(dnsSummary({ ...d, a: ['1.2.3.4'], errors: { MX: 'x' } })).toBe('1 A · 1 lookup failed');
  });
});
