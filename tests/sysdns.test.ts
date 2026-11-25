import { beforeEach, describe, expect, it, vi } from 'vitest';
import { dohQuery } from '@/lib/doh';
import { ff } from '@/lib/firefox';
import { FetchError, isAbortError } from '@/lib/http';
import type { Fact } from '@/lib/types';
import { SkipError } from '@/lib/types';
import {
  MAX_ADDRESSES,
  compareAnswers,
  isSinkhole,
  nat64Embedded,
  sysdnsModule,
  systemLookup,
  type DohAnswer,
  type SysDnsData,
  type SystemAnswer,
} from '@/modules/sysdns';
import { json, makeCtx, mockFetch, type Route } from './helpers';

vi.mock('@/lib/firefox', () => ({ ff: { dns: { resolve: vi.fn() } } }));

const resolve = vi.mocked(ff.dns.resolve);

// ---------------------------------------------------------------------------
// DoH fixtures (shapes from docs/research/dns-rdap.md)

const RR_CODE = { A: 1, AAAA: 28 } as const;
type Spec = string[] | number | { cname: string; addrs: string[] };

const rr = (name: string, type: number, data: string, TTL = 300) => ({ name, type, TTL, data });
const SOA_COM = rr('com', 6, 'a.gtld-servers.net. nstld.verisign-grs.com. 1764070000 1800 900 604800 900', 900);

function dnsJson(name: string, type: number, status: number, answer: object[] = [], authority: object[] = []) {
  return {
    Status: status,
    TC: false,
    RD: true,
    RA: true,
    AD: false,
    CD: false,
    Question: [{ name, type }],
    ...(answer.length ? { Answer: answer } : {}),
    ...(authority.length ? { Authority: authority } : {}),
  };
}

function body(name: string, t: 'A' | 'AAAA', spec: Spec) {
  const code = RR_CODE[t];
  if (typeof spec === 'number') return dnsJson(name, code, spec, [], spec === 2 ? [] : [SOA_COM]);
  if (Array.isArray(spec)) return dnsJson(name, code, 0, spec.map((ip) => rr(name, code, ip)));
  // CNAME chain: the address records sit under the final target name.
  return dnsJson(name, code, 0, [rr(name, 5, `${spec.cname}.`, 3570), ...spec.addrs.map((ip) => rr(spec.cname, code, ip, 30))]);
}

/** Cloudflare DoH JSON for one name (A / AAAA). Unmatched requests fall through (and fail the test). */
function cloudflare(name: string, a: Spec, aaaa: Spec): Route {
  return (url, init) => {
    if (url.hostname !== 'cloudflare-dns.com' || url.searchParams.get('name') !== name) return undefined;
    expect((init.headers as Record<string, string>)['accept']).toBe('application/dns-json');
    const t = url.searchParams.get('type');
    if (t !== 'A' && t !== 'AAAA') return undefined;
    return json(body(name, t, t === 'A' ? a : aaaa), 200, { 'content-type': 'application/dns-json' });
  };
}

/** Google DoH JSON: names carry a trailing dot. */
function google(name: string, a: Spec, aaaa: Spec): Route {
  return (url) => {
    if (url.hostname !== 'dns.google' || url.searchParams.get('name') !== name) return undefined;
    const t = url.searchParams.get('type');
    if (t !== 'A' && t !== 'AAAA') return undefined;
    return json(body(`${name}.`, t, t === 'A' ? a : aaaa), 200, { 'content-type': 'application/json; charset=UTF-8' });
  };
}

async function run(domain: string, ...routes: Route[]) {
  const m = mockFetch(...routes);
  const ctx = makeCtx({ fetch: m.fetch, root: domain });
  const out = await sysdnsModule.run({ kind: 'domain', value: domain, depth: 0 }, ctx);
  return { out, data: out.data, calls: m.calls, ctx, facts: sysdnsModule.facts!(out.data, { kind: 'domain', value: domain, depth: 0 }) };
}

const fact = (facts: Fact[], label: string) => facts.find((f) => f.label === label);

const V4 = '93.184.215.14';
const V6 = '2606:2800:21f:cb07:6820:80da:af6b:8b2c';

beforeEach(() => {
  resolve.mockReset();
});

// ---------------------------------------------------------------------------

describe('sysdns module: metadata', () => {
  it('is an optional, passive, keyless domain module', () => {
    expect(sysdnsModule.id).toBe('sysdns');
    expect(sysdnsModule.label).toBe('System resolver vs DoH');
    expect(sysdnsModule.version).toBe(1);
    expect(sysdnsModule.accepts).toEqual(['domain']);
    expect(sysdnsModule.ttl).toBe(5 * 60_000);
    expect(sysdnsModule.defaultEnabled).toBe(false);
    expect(sysdnsModule.key).toBeUndefined();
    expect(sysdnsModule.active).toBeFalsy();
  });
});

describe('sysdns module: verdicts', () => {
  it('match: same A+AAAA sets; calls dns.resolve with disable_trr + bypass_cache; no pivots', async () => {
    resolve.mockResolvedValue({ addresses: [V4, V6], isTRR: false });
    const { out, data, calls, facts } = await run('example.com', cloudflare('example.com', [V4], [V6]));

    expect(resolve).toHaveBeenCalledWith('example.com', ['disable_trr', 'bypass_cache']);
    expect(calls.map((c) => new URL(c.url).searchParams.get('type')).sort()).toEqual(['A', 'AAAA']);
    // OPSEC: only the public DoH services are contacted, never the domain itself.
    expect(calls.every((c) => ['cloudflare-dns.com', 'dns.google'].includes(new URL(c.url).hostname))).toBe(true);
    expect(data.verdict).toBe('match');
    expect(data.system).toEqual({ addresses: [V4, V6], isTRR: false, status: 'ok' });
    expect(data.doh).toEqual({ a: [V4], aaaa: [V6], status: 'ok' });
    expect(data.common).toEqual([V4, V6]);
    expect(data.onlySystem).toEqual([]);
    expect(data.onlyDoh).toEqual([]);
    expect(data.compared).toBe('all');
    expect(out.summary).toBe('Match (2 addresses)');
    expect(out.pivots).toBeUndefined();
    expect(out.severity).toBe('none');
    expect(fact(facts, 'Verdict')).toMatchObject({ value: 'Match', tone: 'good' });
    expect(fact(facts, 'System resolver')).toMatchObject({ value: [V4, V6], pivot: true });
    expect(fact(facts, 'Public DoH A')?.value).toEqual([V4]);
    expect(fact(facts, 'Only system')).toBeUndefined();
    expect(JSON.parse(JSON.stringify(data))).toEqual(data);
  });

  it('match: canonicalises IPv6 and de-duplicates/filters junk from the system answer', async () => {
    resolve.mockResolvedValue({
      addresses: [V4, '2606:2800:021F:CB07:6820:80DA:AF6B:8B2C', V4, 42, 'not-an-ip'] as unknown as string[],
      isTRR: false,
    });
    const { data } = await run('example.com', cloudflare('example.com', [V4], [V6]));
    expect(data.system.addresses).toEqual([V4, V6]);
    expect(data.verdict).toBe('match');
  });

  it('match: IPv4-only system answer is compared on IPv4 only (no IPv6 connectivity)', async () => {
    resolve.mockResolvedValue({ addresses: [V4], isTRR: false });
    const { out, data, facts } = await run('example.com', cloudflare('example.com', [V4], [V6]));
    expect(data.verdict).toBe('match');
    expect(data.compared).toBe('ipv4');
    expect(data.onlyDoh).toEqual([]);
    expect(data.explanation).toContain('IPv6 not compared');
    expect(out.summary).toBe('Match (1 address)');
    expect(fact(facts, 'Compared')?.value).toContain('IPv4 only');
    // The DoH AAAA answer is still shown.
    expect(fact(facts, 'Public DoH AAAA')?.value).toEqual([V6]);
  });

  it('match: follows a CNAME chain and uses only address records', async () => {
    resolve.mockResolvedValue({ addresses: ['20.208.89.80'], isTRR: false });
    const { data } = await run(
      'www.github.com',
      cloudflare('www.github.com', { cname: 'github.com', addrs: ['20.208.89.80'] }, 0),
    );
    expect(data.doh).toEqual({ a: ['20.208.89.80'], aaaa: [], status: 'ok' });
    expect(data.verdict).toBe('match');
  });

  it('match: NXDOMAIN on both', async () => {
    resolve.mockRejectedValue({ message: 'NS_ERROR_UNKNOWN_HOST' });
    const { out, data } = await run('nope.example.com', cloudflare('nope.example.com', 3, 3));
    expect(data.system.status).toBe('nxdomain');
    expect(data.doh.status).toBe('nxdomain');
    expect(data.verdict).toBe('match');
    expect(out.summary).toBe('Match: NXDOMAIN on both');
  });

  it('overlap: some addresses in common (CDN / geo DNS), phrased cautiously', async () => {
    resolve.mockResolvedValue({ addresses: ['104.16.1.1', '104.16.2.2'], isTRR: false });
    const { out, data, facts } = await run('cdn.example.com', cloudflare('cdn.example.com', ['104.16.2.2', '104.16.3.3'], 0));
    expect(data.verdict).toBe('overlap');
    expect(data.common).toEqual(['104.16.2.2']);
    expect(data.onlySystem).toEqual(['104.16.1.1']);
    expect(data.onlyDoh).toEqual(['104.16.3.3']);
    expect(out.summary).toBe('Overlap: 1 common, 1 system-only (CDN/geo DNS?)');
    expect(data.explanation).toMatch(/CDN|geo/);
    expect(data.explanation).toContain('not necessarily tampering');
    expect(fact(facts, 'Verdict')?.tone).toBeUndefined();
    expect(fact(facts, 'Common')?.value).toEqual(['104.16.2.2']);
    expect(fact(facts, 'Only system')?.value).toEqual(['104.16.1.1']);
    expect(fact(facts, 'Only public DoH')?.value).toEqual(['104.16.3.3']);
  });

  it('mismatch: disjoint public answers', async () => {
    resolve.mockResolvedValue({ addresses: ['8.8.4.4', '1.0.0.1'], isTRR: false });
    const { out, data, facts } = await run('example.com', cloudflare('example.com', [V4], 0));
    expect(data.verdict).toBe('mismatch');
    expect(data.common).toEqual([]);
    expect(out.summary).toBe(`Mismatch: system returns 8.8.4.4 +1, DoH ${V4}`);
    expect(data.explanation).toContain('interception');
    expect(data.explanation).toContain('CDN');
    expect(fact(facts, 'Verdict')).toMatchObject({ value: 'Mismatch', tone: 'warn' });
  });

  it('split-horizon wins over mismatch when any disjoint system address is non-public', async () => {
    // 198.51.100.7 is documentation space (non-public); 8.8.4.4 is public.
    resolve.mockResolvedValue({ addresses: ['198.51.100.7', '8.8.4.4'], isTRR: false });
    const { out, data } = await run('example.com', cloudflare('example.com', [V4], 0));
    expect(data.verdict).toBe('split-horizon');
    expect(out.summary).toBe('Mismatch: system returns 198.51.100.7 (split-horizon?)');
  });

  it('blocked: system NS_ERROR_UNKNOWN_HOST (plain object rejection) while DoH resolves publicly', async () => {
    resolve.mockRejectedValue({ message: 'NS_ERROR_UNKNOWN_HOST' });
    const { out, data, facts } = await run('ads.example.com', cloudflare('ads.example.com', [V4], [V6]));
    expect(data.system).toEqual({ addresses: [], isTRR: false, status: 'nxdomain' });
    expect(data.verdict).toBe('blocked');
    expect(data.onlyDoh).toEqual([V4, V6]);
    expect(out.summary).toBe('Blocked: system NXDOMAIN, DoH resolves (local filtering?)');
    expect(data.explanation).toContain('local DNS filtering');
    expect(data.explanation).toContain('TRR mode 3');
    expect(data.explanation).toContain('transient');
    expect(fact(facts, 'System resolver')?.value).toBe('NXDOMAIN');
    expect(fact(facts, 'System resolver')?.pivot).toBeUndefined();
  });

  it('blocked: NS_ERROR_UNKNOWN_HOST as an Error instance', async () => {
    resolve.mockRejectedValue(new Error('NS_ERROR_UNKNOWN_HOST'));
    const { data } = await run('ads.example.com', cloudflare('ads.example.com', [V4], 0));
    expect(data.verdict).toBe('blocked');
  });

  it('blocked: sinkhole answers 0.0.0.0 / ::', async () => {
    resolve.mockResolvedValue({ addresses: ['0.0.0.0', '::'], isTRR: false });
    const { out, data } = await run('tracker.example.com', cloudflare('tracker.example.com', [V4], [V6]));
    expect(data.verdict).toBe('blocked');
    expect(data.compared).toBe('all');
    expect(out.summary).toBe('Blocked: system returns 0.0.0.0 +1 (local filtering?)');
    expect(data.explanation).toContain('sinkhole');
  });

  it('blocked: loopback sinkhole even when public DNS has no such name', async () => {
    resolve.mockResolvedValue({ addresses: ['127.0.0.1'], isTRR: false });
    const { data } = await run('dga-xyz.example.com', cloudflare('dga-xyz.example.com', 3, 3));
    expect(data.verdict).toBe('blocked');
    expect(data.explanation).toContain('NXDOMAIN');
  });

  it('split-horizon: system returns a private address while DoH returns public ones', async () => {
    resolve.mockResolvedValue({ addresses: ['10.1.2.3'], isTRR: false });
    const { out, data, facts } = await run('intranet.example.com', cloudflare('intranet.example.com', [V4], 0));
    expect(data.verdict).toBe('split-horizon');
    expect(out.summary).toBe('Mismatch: system returns 10.1.2.3 (split-horizon?)');
    expect(data.explanation).toContain('block page');
    expect(out.pivots).toBeUndefined();
    expect(fact(facts, 'Verdict')).toMatchObject({ value: 'Split-horizon', tone: 'warn' });
    expect(fact(facts, 'Only system')?.value).toEqual(['10.1.2.3']);
  });

  it('split-horizon: private system-only address alongside a common public one', async () => {
    resolve.mockResolvedValue({ addresses: ['192.168.10.5', V4], isTRR: false });
    const { data } = await run('vpn.example.com', cloudflare('vpn.example.com', [V4], 0));
    expect(data.verdict).toBe('split-horizon');
    expect(data.common).toEqual([V4]);
  });

  it('split-horizon: DoH NXDOMAIN while the system resolves', async () => {
    resolve.mockResolvedValue({ addresses: ['10.20.30.40'], isTRR: false });
    const { out, data } = await run('corp.example.com', cloudflare('corp.example.com', 3, 3));
    expect(data.doh.status).toBe('nxdomain');
    expect(data.verdict).toBe('split-horizon');
    expect(out.summary).toBe('Mismatch: system returns 10.20.30.40, public NXDOMAIN (split-horizon?)');
    expect(data.explanation).toContain('internal-only name');
  });

  it('split-horizon: DoH NODATA (NOERROR without A/AAAA) while the system resolves', async () => {
    resolve.mockResolvedValue({ addresses: ['203.0.113.9'], isTRR: false });
    const { data } = await run('mail.example.com', cloudflare('mail.example.com', 0, 0));
    expect(data.doh.status).toBe('nodata');
    expect(data.verdict).toBe('split-horizon');
    expect(data.explanation).not.toContain('NXDOMAIN hijacking');
  });

  it('DoH NXDOMAIN while the system returns a public address mentions NXDOMAIN hijacking', async () => {
    resolve.mockResolvedValue({ addresses: ['8.8.4.4'], isTRR: false });
    const { data } = await run('typo.example.com', cloudflare('typo.example.com', 3, 3));
    expect(data.verdict).toBe('split-horizon');
    expect(data.explanation).toContain('NXDOMAIN hijacking');
  });

  it('normalises the entity value (case, trailing dot) before resolving', async () => {
    resolve.mockResolvedValue({ addresses: [V4], isTRR: false });
    const { data } = await run('Example.COM.', cloudflare('example.com', [V4], 0));
    expect(resolve).toHaveBeenCalledWith('example.com', ['disable_trr', 'bypass_cache']);
    expect(data.verdict).toBe('match');
  });
});

describe('sysdns module: NAT64 / DNS64', () => {
  it('a DNS64-synthesised system answer matches the DoH IPv4 it embeds (not split-horizon)', async () => {
    resolve.mockResolvedValue({ addresses: ['64:ff9b::5db8:d70e'], isTRR: false });
    const { out, data } = await run('example.com', cloudflare('example.com', [V4], 0));
    expect(data.verdict).toBe('match');
    expect(data.common).toEqual(['64:ff9b::5db8:d70e']);
    expect(data.onlyDoh).toEqual([]);
    expect(out.summary).toBe('Match (1 address)');
    expect(data.explanation).toContain('NAT64');
  });

  it('disjoint NAT64 answer is judged on its embedded public IPv4: mismatch, not split-horizon', () => {
    const c = compareAnswers({ addresses: ['64:ff9b::102:304'], isTRR: false, status: 'ok' }, { a: ['5.6.7.8'], aaaa: [], status: 'ok' });
    expect(c.verdict).toBe('mismatch');
  });

  it('a 64:ff9b:: address that public DNS itself publishes compares as-is', () => {
    const c = compareAnswers(
      { addresses: ['64:ff9b::102:304'], isTRR: false, status: 'ok' },
      { a: ['1.2.3.4'], aaaa: ['64:ff9b::102:304'], status: 'ok' },
    );
    expect(c.verdict).toBe('match');
    expect(c.compared).toBe('ipv6');
  });

  it.each([
    ['64:ff9b::5db8:d70e', '93.184.215.14'],
    ['64:ff9b::a00:1', '10.0.0.1'],
    ['64:ff9b::5', '0.0.0.5'],
    ['64:ff9b::102:0', '1.2.0.0'],
    ['64:ff9b:1::102:304', null],
    ['64:ff9b::1:2:3', null],
    ['2606:2800:21f:cb07:6820:80da:af6b:8b2c', null],
    ['93.184.215.14', null],
  ])('nat64Embedded(%s) -> %s', (ip, expected) => {
    expect(nat64Embedded(ip)).toBe(expected);
  });
});

describe('sysdns module: cancellation', () => {
  it('an abort during the DoH lookups propagates (not swallowed or turned into data)', async () => {
    resolve.mockResolvedValue({ addresses: [V4], isTRR: false });
    const ac = new AbortController();
    ac.abort();
    const m = mockFetch(cloudflare('example.com', [V4], 0));
    const ctx = makeCtx({ fetch: m.fetch, signal: ac.signal });
    const err = await sysdnsModule.run({ kind: 'domain', value: 'example.com', depth: 0 }, ctx).catch((e: unknown) => e);
    expect(isAbortError(err)).toBe(true);
    expect(m.calls).toHaveLength(0);
  });

  it('cancelling stops waiting for a hung system lookup', async () => {
    resolve.mockReturnValue(new Promise(() => {}));
    const ac = new AbortController();
    const m = mockFetch(cloudflare('example.com', [V4], 0));
    const ctx = makeCtx({ fetch: m.fetch, signal: ac.signal });
    // DoH already memoised (e.g. by the DNS module): only the system lookup is pending.
    await dohQuery(ctx, 'example.com', 'A');
    await dohQuery(ctx, 'example.com', 'AAAA');
    const p = sysdnsModule.run({ kind: 'domain', value: 'example.com', depth: 0 }, ctx).catch((e: unknown) => e);
    ac.abort();
    expect(isAbortError(await p)).toBe(true);
  });
});

describe('sysdns module: TRR and resolver errors', () => {
  it('isTRR: says the answer came from Firefox DoH, not the system resolver', async () => {
    resolve.mockResolvedValue({ addresses: [V4, V6], isTRR: true });
    const { out, data, facts } = await run('example.com', cloudflare('example.com', [V4], [V6]));
    expect(data.system.isTRR).toBe(true);
    expect(data.verdict).toBe('match');
    expect(out.summary).toBe('Match (2 addresses) · via Firefox TRR');
    expect(data.explanation).toMatch(/^Firefox answered through its own DNS-over-HTTPS \(TRR\)/);
    expect(data.explanation).toContain('not your system resolver');
    expect(fact(facts, 'Answered by')).toMatchObject({ tone: 'warn' });
    expect(fact(facts, 'Firefox (TRR)')?.value).toEqual([V4, V6]);
    expect(fact(facts, 'System resolver')).toBeUndefined();
  });

  it('isTRR: truthy strings count, "false" does not', async () => {
    resolve.mockResolvedValue({ addresses: [V4], isTRR: 'https://mozilla.cloudflare-dns.com/dns-query' });
    expect((await systemLookup('example.com')).isTRR).toBe(true);
    resolve.mockResolvedValue({ addresses: [V4], isTRR: 'false' });
    expect((await systemLookup('example.com')).isTRR).toBe(false);
    resolve.mockResolvedValue({ addresses: [V4], isTRR: '' });
    expect((await systemLookup('example.com')).isTRR).toBe(false);
  });

  it('isTRR mismatch uses TRR wording', async () => {
    resolve.mockResolvedValue({ addresses: ['8.8.4.4'], isTRR: true });
    const { out, data, facts } = await run('example.com', cloudflare('example.com', [V4], 0));
    expect(data.verdict).toBe('mismatch');
    expect(out.summary).toBe(`Mismatch: TRR returns 8.8.4.4, DoH ${V4} · via Firefox TRR`);
    expect(fact(facts, 'Only TRR')?.value).toEqual(['8.8.4.4']);
  });

  it('other dns.resolve rejections are genuine errors (thrown, not skipped)', async () => {
    resolve.mockRejectedValue({ message: 'NS_ERROR_OFFLINE' });
    const m = mockFetch(cloudflare('example.com', [V4], [V6]));
    const ctx = makeCtx({ fetch: m.fetch });
    const err = await sysdnsModule.run({ kind: 'domain', value: 'example.com', depth: 0 }, ctx).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err).not.toBeInstanceOf(SkipError);
    expect((err as Error).message).toBe('System resolver failed: NS_ERROR_OFFLINE');
  });

  it('rejection without a message still yields a readable error', async () => {
    resolve.mockRejectedValue(undefined);
    await expect(systemLookup('example.com')).rejects.toThrow('System resolver failed: unknown error');
  });

  it('an unexpected dns.resolve result shape throws', async () => {
    resolve.mockResolvedValue(null as never);
    await expect(systemLookup('example.com')).rejects.toThrow('Unexpected answer');
    resolve.mockResolvedValue({ addresses: 'nope', isTRR: false } as never);
    await expect(systemLookup('example.com')).rejects.toThrow('Unexpected answer');
  });

  it('skips when the Firefox DNS API is unavailable', async () => {
    const api = ff as unknown as { dns: unknown };
    const saved = api.dns;
    api.dns = undefined;
    try {
      const m = mockFetch();
      const ctx = makeCtx({ fetch: m.fetch });
      const err = await sysdnsModule.run({ kind: 'domain', value: 'example.com', depth: 0 }, ctx).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(SkipError);
      expect(m.calls).toHaveLength(0);
    } finally {
      api.dns = saved;
    }
  });
});

describe('sysdns module: DoH side', () => {
  it('DoH SERVFAIL on Cloudflare and Google while the system resolves: mismatch (DNSSEC?)', async () => {
    resolve.mockResolvedValue({ addresses: [V4], isTRR: false });
    const { out, data, calls } = await run(
      'broken-dnssec.example.com',
      cloudflare('broken-dnssec.example.com', 2, 2),
      google('broken-dnssec.example.com', 2, 2),
    );
    expect(calls.some((c) => c.url.startsWith('https://dns.google/resolve?'))).toBe(true);
    expect(data.doh).toEqual({ a: [], aaaa: [], status: 'error', rcode: 'SERVFAIL' });
    expect(data.verdict).toBe('mismatch');
    expect(out.summary).toBe(`Mismatch: public DoH SERVFAIL, system returns ${V4}`);
    expect(data.explanation).toContain('DNSSEC');
  });

  it('Google fallback answers (trailing-dot names) compare normally', async () => {
    resolve.mockResolvedValue({ addresses: [V4], isTRR: false });
    const down: Route = (url) => (url.hostname === 'cloudflare-dns.com' ? json({ error: 'down' }, 503) : undefined);
    const { data } = await run('example.com', down, google('example.com', [V4], 0));
    expect(data.verdict).toBe('match');
  });

  it('DoH transport failure on both providers throws', async () => {
    resolve.mockResolvedValue({ addresses: [V4], isTRR: false });
    const m = mockFetch(() => json({ error: 'boom' }, 500));
    const ctx = makeCtx({ fetch: m.fetch });
    const err = await sysdnsModule.run({ kind: 'domain', value: 'example.com', depth: 0 }, ctx).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(FetchError);
  });

  it('system NXDOMAIN while DoH returns only private addresses: mismatch (rebinding protection)', async () => {
    resolve.mockRejectedValue({ message: 'NS_ERROR_UNKNOWN_HOST' });
    const { out, data } = await run('internal.example.com', cloudflare('internal.example.com', ['10.0.0.8'], 0));
    expect(data.verdict).toBe('mismatch');
    expect(data.explanation).toContain('rebinding');
    expect(out.summary).toBe('Mismatch: system NXDOMAIN, DoH only private 10.0.0.8');
  });

  it('reuses memoised DoH lookups (shared with the DNS module)', async () => {
    resolve.mockResolvedValue({ addresses: [V4], isTRR: false });
    const m = mockFetch(cloudflare('example.com', [V4], 0));
    const ctx = makeCtx({ fetch: m.fetch });
    await dohQuery(ctx, 'example.com', 'A');
    await dohQuery(ctx, 'example.com', 'AAAA');
    await sysdnsModule.run({ kind: 'domain', value: 'example.com', depth: 0 }, ctx);
    expect(m.calls).toHaveLength(2);
  });

  it('caps long address lists but records full counts', async () => {
    const many = Array.from({ length: 80 }, (_, i) => `93.184.${Math.floor(i / 250)}.${(i % 250) + 1}`);
    resolve.mockResolvedValue({ addresses: many, isTRR: false });
    const { data, facts } = await run('big.example.com', cloudflare('big.example.com', many, 0));
    expect(data.verdict).toBe('match');
    expect(data.system.addresses).toHaveLength(MAX_ADDRESSES);
    expect(data.doh.a).toHaveLength(MAX_ADDRESSES);
    expect(data.common).toHaveLength(MAX_ADDRESSES);
    expect(data.counts).toEqual({ system: 80, a: 80, aaaa: 0, common: 80, onlySystem: 0, onlyDoh: 0 });
    const sys = fact(facts, 'System resolver')!.value as string[];
    expect(sys.at(-1)).toBe('(+30 more not shown)');
    expect(fact(facts, 'Public DoH AAAA')?.value).toBe('no records');
  });
});

describe('compareAnswers (pure)', () => {
  const sys = (addresses: string[], status: SystemAnswer['status'] = addresses.length ? 'ok' : 'empty'): SystemAnswer => ({
    addresses,
    isTRR: false,
    status,
  });
  const doh = (a: string[], aaaa: string[] = [], status?: DohAnswer['status']): DohAnswer => ({
    a,
    aaaa,
    status: status ?? (a.length || aaaa.length ? 'ok' : 'nodata'),
  });

  it('system IPv4 only vs DoH IPv6 only compares everything (no family filter)', () => {
    const c = compareAnswers(sys(['8.8.4.4']), doh([], [V6]));
    expect(c.compared).toBe('all');
    expect(c.verdict).toBe('mismatch');
  });

  it('IPv6-only system answer is compared on IPv6 only', () => {
    const c = compareAnswers(sys([V6]), doh([V4], [V6]));
    expect(c.compared).toBe('ipv6');
    expect(c.verdict).toBe('match');
    expect(c.explanation).toContain('IPv4 not compared');
  });

  it('resolved-but-empty system answer while DoH resolves publicly is blocked', () => {
    const c = compareAnswers(sys([]), doh([V4]));
    expect(c.verdict).toBe('blocked');
    expect(c.summary).toBe('Blocked: system no address, DoH resolves (local filtering?)');
  });

  it('both private and disjoint: mismatch, not split-horizon', () => {
    const c = compareAnswers(sys(['10.0.0.1']), doh(['10.0.0.2']));
    expect(c.verdict).toBe('mismatch');
  });

  it('same private address on both sides is a match', () => {
    expect(compareAnswers(sys(['10.0.0.1']), doh(['10.0.0.1'])).verdict).toBe('match');
  });

  it('domain that publicly resolves to 127.0.0.1 matches (not blocked)', () => {
    expect(compareAnswers(sys(['127.0.0.1']), doh(['127.0.0.1'])).verdict).toBe('match');
  });

  it('neither side has an address (no NXDOMAIN) is a match with a readable summary', () => {
    const c = compareAnswers(sys([]), doh([], [], 'nodata'));
    expect(c.verdict).toBe('match');
    expect(c.summary).toBe('Match: no address on either');
  });

  it('pluralises the overlap explanation', () => {
    const c = compareAnswers(sys(['1.1.1.1', '1.0.0.1', '8.8.8.8']), doh(['1.1.1.1', '1.0.0.1', '9.9.9.9']));
    expect(c.verdict).toBe('overlap');
    expect(c.explanation).toMatch(/^2 addresses in common; 1 only from the system resolver, 1 only from public DoH/);
  });
});

describe('isSinkhole', () => {
  it.each([
    ['0.0.0.0', true],
    ['0.1.2.3', true],
    ['127.0.0.1', true],
    ['127.53.0.1', true],
    ['::', true],
    ['::1', true],
    ['0:0:0:0:0:0:0:1', true],
    ['10.0.0.1', false],
    ['93.184.215.14', false],
    ['fe80::1', false],
    ['garbage', false],
  ])('%s -> %s', (ip, expected) => {
    expect(isSinkhole(ip)).toBe(expected);
  });
});

describe('facts', () => {
  it('renders plain text facts with tones and no links', () => {
    const d: SysDnsData = {
      system: { addresses: ['10.1.2.3'], isTRR: false, status: 'ok' },
      doh: { a: [], aaaa: [], status: 'error', rcode: 'REFUSED' },
      onlySystem: ['10.1.2.3'],
      onlyDoh: [],
      common: [],
      compared: 'all',
      counts: { system: 1, a: 0, aaaa: 0, common: 0, onlySystem: 1, onlyDoh: 0 },
      verdict: 'mismatch',
      explanation: 'x',
    };
    const facts = sysdnsModule.facts!(d, { kind: 'domain', value: 'example.com', depth: 0 });
    expect(facts.every((f) => f.href === undefined)).toBe(true);
    expect(fact(facts, 'Public DoH A')?.value).toBe('REFUSED');
    expect(fact(facts, 'Only public DoH')).toBeUndefined();
    expect(fact(facts, 'Common')).toBeUndefined();
  });
});
