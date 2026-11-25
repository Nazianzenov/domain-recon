import { describe, expect, it } from 'vitest';
import {
  RR,
  dohQuery,
  parseCaa,
  parseDohJson,
  parseMx,
  parseSoa,
  parseTxt,
  recordsOf,
  stripDot,
  valuesOf,
} from '@/lib/doh';
import { FetchError } from '@/lib/http';
import { json, makeCtx, mockFetch, text, type Route } from './helpers';

/** GitHub's live SPF as Cloudflare returns it (2026-11-25): split mid-token at "include:servers." "mcsv.net". */
const GITHUB_SPF_CF =
  '"v=spf1 ip4:192.30.252.0/22 ip4:172.170.10.240/28 ip4:40.78.162.192/28 ip4:172.170.3.48/28 include:spf.protection.outlook.com include:_netblocks.google.com include:_netblocks2.google.com include:mail.zendesk.com include:_spf.salesforce.com include:servers." "mcsv.net include:mktomail.com include:sendgrid.net ip4:62.253.227.114 ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ~all"';
const GITHUB_SPF =
  'v=spf1 ip4:192.30.252.0/22 ip4:172.170.10.240/28 ip4:40.78.162.192/28 ip4:172.170.3.48/28 include:spf.protection.outlook.com include:_netblocks.google.com include:_netblocks2.google.com include:mail.zendesk.com include:_spf.salesforce.com include:servers.mcsv.net include:mktomail.com include:sendgrid.net ip4:62.253.227.114 ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ~all';

const CF_HOST = 'cloudflare-dns.com';
const G_HOST = 'dns.google';

/** Route answering only one resolver host. */
function on(host: string, fn: (name: string, type: string, init: RequestInit) => Response | undefined): Route {
  return (url, init) => {
    if (url.host !== host) return undefined;
    return fn(url.searchParams.get('name') ?? '', url.searchParams.get('type') ?? '', init);
  };
}

function networkDown(host: string): Route {
  return (url) => {
    if (url.host === host) throw new TypeError('NetworkError when attempting to fetch resource.');
    return undefined;
  };
}

const headerOf = (init: RequestInit, name: string) => (init.headers as Record<string, string>)[name];

describe('parseTxt', () => {
  it('returns the Google unquoted (already concatenated) form as-is', () => {
    expect(parseTxt('v=DMARC1; p=quarantine; rua=mailto:dmarc@github.com')).toBe(
      'v=DMARC1; p=quarantine; rua=mailto:dmarc@github.com',
    );
    expect(parseTxt(GITHUB_SPF)).toBe(GITHUB_SPF);
  });

  it('strips the quotes of a single Cloudflare chunk', () => {
    expect(parseTxt('"MS=ms44452932"')).toBe('MS=ms44452932');
  });

  it('joins Cloudflare multi-chunk records with no separator, even when split mid-token', () => {
    const out = parseTxt(GITHUB_SPF_CF);
    expect(out).toBe(GITHUB_SPF);
    expect(out).toContain('include:servers.mcsv.net');
    expect(out).not.toContain('servers. mcsv');
  });

  it('joins DKIM-style 2-chunk keys', () => {
    expect(parseTxt('"k=rsa; t=s; p=MIIBIjANBgkq" "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx"')).toBe(
      'k=rsa; t=s; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx',
    );
  });

  it('unescapes \\" and \\\\', () => {
    expect(parseTxt('"say \\"hi\\" and \\\\o/"')).toBe('say "hi" and \\o/');
  });

  it('decodes \\DDD decimal escapes (ASCII)', () => {
    expect(parseTxt('"v=spf1\\032-all"')).toBe('v=spf1 -all');
    expect(parseTxt('"v=DMARC1\\059 p=none"')).toBe('v=DMARC1; p=none');
    expect(parseTxt('"tab\\009end"')).toBe('tab\tend');
  });

  // BUG in src/lib/doh.ts (reported in sharedChangesNeeded): \DDD is an octet (RFC 1035 §5.1) but
  // parseTxt maps each one to a UTF-16 code unit, so UTF-8 multi-byte text decodes as Latin-1
  // mojibake ("cafÃ©"). Un-skip once parseTxt collects \DDD runs as bytes and UTF-8-decodes them.
  it('decodes \\DDD escapes as UTF-8 bytes, including sequences split across chunks', () => {
    expect(parseTxt('"caf\\195\\169"')).toBe('café');
    expect(parseTxt('"\\226\\128" "\\148 dash"')).toBe('— dash');
  });

  it('handles empty chunks, surrounding whitespace and an unterminated quote', () => {
    expect(parseTxt('""')).toBe('');
    expect(parseTxt('  "a" "b"  ')).toBe('ab');
    expect(parseTxt('"abc')).toBe('abc');
    expect(parseTxt('"trailing\\')).toBe('trailing\\');
  });
});

describe('parseMx / parseSoa / parseCaa / stripDot', () => {
  it('parseMx: preference + exchange without the trailing dot, lowercased', () => {
    expect(parseMx('10 smtp.google.com.')).toEqual({ preference: 10, exchange: 'smtp.google.com' });
    expect(parseMx(' 5 ALT1.ASPMX.L.Google.COM. ')).toEqual({ preference: 5, exchange: 'alt1.aspmx.l.google.com' });
  });

  it('parseMx: null MX (RFC 7505) has an empty exchange', () => {
    expect(parseMx('0 .')).toEqual({ preference: 0, exchange: '' });
  });

  it('parseMx: junk -> null', () => {
    expect(parseMx('smtp.google.com.')).toBeNull();
    expect(parseMx('ten smtp.google.com.')).toBeNull();
    expect(parseMx('10 a b')).toBeNull();
    expect(parseMx('')).toBeNull();
  });

  it('parseSoa: all seven fields', () => {
    expect(parseSoa('dns1.p08.nsone.net. hostmaster.nsone.net. 1656468023 43200 7200 1209600 3600')).toEqual({
      mname: 'dns1.p08.nsone.net',
      rname: 'hostmaster.nsone.net',
      serial: 1656468023,
      refresh: 43200,
      retry: 7200,
      expire: 1209600,
      minimum: 3600,
    });
  });

  it('parseSoa: too few fields or non-numeric timers -> null', () => {
    expect(parseSoa('ns1.google.com. dns-admin.google.com. 1 2 3 4')).toBeNull();
    expect(parseSoa('ns1.google.com. dns-admin.google.com. 1 2 3 4 x')).toBeNull();
    expect(parseSoa('')).toBeNull();
  });

  it('parseCaa: flags, lowercased tag, unquoted value', () => {
    expect(parseCaa('0 issue "digicert.com"')).toEqual({ flags: 0, tag: 'issue', value: 'digicert.com' });
    expect(parseCaa('0 issuewild "letsencrypt.org"')).toEqual({ flags: 0, tag: 'issuewild', value: 'letsencrypt.org' });
    expect(parseCaa('128 ISSUE ";"')).toEqual({ flags: 128, tag: 'issue', value: ';' });
    expect(parseCaa('0 iodef "mailto:security@example.com"')).toEqual({
      flags: 0,
      tag: 'iodef',
      value: 'mailto:security@example.com',
    });
    expect(parseCaa('0 issue "letsencrypt.org; validationmethods=dns-01"')?.value).toBe(
      'letsencrypt.org; validationmethods=dns-01',
    );
  });

  it('parseCaa: unquoted value and junk', () => {
    expect(parseCaa('0 issue pki.goog')).toEqual({ flags: 0, tag: 'issue', value: 'pki.goog' });
    expect(parseCaa('issue "pki.goog"')).toBeNull();
    expect(parseCaa('\\# 19 00 05 69 73 73 75 65')).toBeNull();
  });

  it('stripDot: trims, drops one trailing dot, lowercases', () => {
    expect(stripDot(' GitHub.COM. ')).toBe('github.com');
    expect(stripDot('github.com')).toBe('github.com');
  });
});

describe('parseDohJson', () => {
  it('normalises names, TXT, NS/CNAME targets and MX data', () => {
    const res = parseDohJson(
      {
        Status: 0,
        AD: true,
        Answer: [
          { name: 'GitHub.com.', type: 16, TTL: 105, data: '"a" "b"' },
          { name: 'github.com.', type: 2, TTL: 1297, data: 'DNS1.P08.NSONE.NET.' },
          { name: 'www.github.com', type: 5, TTL: 3570, data: 'github.com.' },
          { name: 'github.com', type: 15, TTL: 11, data: '1  ASPMX.L.GOOGLE.COM.' },
        ],
      },
      'GitHub.com.',
      'TXT',
      'google',
    );
    expect(res.name).toBe('github.com');
    expect(res.ad).toBe(true);
    expect(res.resolver).toBe('google');
    expect(res.answers.map((r) => [r.name, r.type, r.data])).toEqual([
      ['github.com', 16, 'ab'],
      ['github.com', 2, 'dns1.p08.nsone.net'],
      ['www.github.com', 5, 'github.com'],
      ['github.com', 15, '1 aspmx.l.google.com'],
    ]);
  });

  // BUG in src/lib/doh.ts (reported in sharedChangesNeeded): normRecords rewrites a null MX
  // ("0 .", RFC 7505) to "0 " because stripDot('.') is '', and parseMx cannot re-parse "0 ".
  // src/modules/dns.ts works around it locally. Un-skip once normRecords keeps "0 ." for an empty exchange.
  it('keeps a null MX re-parseable after normalisation', () => {
    const res = parseDohJson({ Status: 0, Answer: [{ name: 'example.net', type: 15, TTL: 300, data: '0 .' }] }, 'example.net', 'MX', 'cloudflare');
    expect(parseMx(res.answers[0]!.data)).toEqual({ preference: 0, exchange: '' });
  });

  it('skips malformed records and defaults a missing TTL to 0', () => {
    const res = parseDohJson(
      {
        Status: 0,
        Answer: [
          null,
          'junk',
          { name: 'x.com', type: '1', data: '1.2.3.4' },
          { name: 'x.com', type: 1, data: 42 },
          { type: 1, data: '1.2.3.4' },
          { name: 'x.com', type: 1, data: '5.6.7.8' },
        ],
        Authority: { not: 'an array' },
      },
      'x.com',
      'A',
      'cloudflare',
    );
    expect(res.answers).toEqual([{ name: 'x.com', type: 1, ttl: 0, data: '5.6.7.8' }]);
    expect(res.authority).toEqual([]);
    expect(res.ad).toBe(false);
  });

  it('Comment: Cloudflare array (joined) and Google string', () => {
    expect(parseDohJson({ Status: 2, Comment: ['EDE(9): DNSKEY Missing', 7, 'EDE(22): No Reachable Authority'] }, 'x.com', 'A', 'cloudflare').comment).toBe(
      'EDE(9): DNSKEY Missing; EDE(22): No Reachable Authority',
    );
    expect(parseDohJson({ Status: 0, Comment: 'Response from 216.239.38.10.' }, 'x.com', 'A', 'google').comment).toBe(
      'Response from 216.239.38.10.',
    );
    expect(parseDohJson({ Status: 0 }, 'x.com', 'A', 'google')).not.toHaveProperty('comment');
  });

  it('throws a parse FetchError on junk', () => {
    for (const junk of [null, 'x', 42, {}, { Status: '0' }, { error: 'Invalid query name' }]) {
      const err = (() => {
        try {
          parseDohJson(junk, 'x.com', 'A', 'cloudflare', 'https://cloudflare-dns.com/dns-query?name=x.com&type=A');
          return undefined;
        } catch (e) {
          return e;
        }
      })();
      expect(err).toBeInstanceOf(FetchError);
      expect((err as FetchError).kind).toBe('parse');
    }
  });
});

describe('dohQuery', () => {
  const GITHUB_A = { Status: 0, AD: false, Question: [{ name: 'github.com', type: 1 }], Answer: [{ name: 'github.com', type: 1, TTL: 60, data: '140.82.121.4' }] };

  it('queries Cloudflare with accept: application/dns-json and the encoded name/type', async () => {
    const m = mockFetch(on(CF_HOST, () => json(GITHUB_A, 200, { 'content-type': 'application/dns-json' })));
    const ctx = makeCtx({ fetch: m.fetch });
    const res = await dohQuery(ctx, 'github.com', 'A');
    expect(res.resolver).toBe('cloudflare');
    expect(valuesOf(res, 'A')).toEqual(['140.82.121.4']);
    expect(m.calls).toHaveLength(1);
    const call = m.calls[0]!;
    expect(call.url).toBe('https://cloudflare-dns.com/dns-query?name=github.com&type=A');
    expect(headerOf(call.init, 'accept')).toBe('application/dns-json');
    expect(call.init.credentials).toBe('omit');
  });

  it('URL-encodes the name', async () => {
    const m = mockFetch(on(CF_HOST, () => json({ Status: 3 })));
    const ctx = makeCtx({ fetch: m.fetch });
    await dohQuery(ctx, '_dmarc.example.com', 'TXT');
    await dohQuery(ctx, 'a&type=ANY#.example.com', 'TXT');
    expect(m.calls[0]!.url).toBe('https://cloudflare-dns.com/dns-query?name=_dmarc.example.com&type=TXT');
    const u = new URL(m.calls[1]!.url);
    expect(u.searchParams.get('name')).toBe('a&type=any#.example.com');
    expect(u.searchParams.getAll('type')).toEqual(['TXT']);
  });

  it('falls back to Google on a Cloudflare network error and normalises Google trailing dots', async () => {
    const m = mockFetch(
      networkDown(CF_HOST),
      on(G_HOST, (name, type) =>
        name === 'github.com' && type === 'TXT'
          ? json({
              Status: 0,
              Question: [{ name: 'github.com.', type: 16 }],
              Answer: [{ name: 'github.com.', type: 16, TTL: 105, data: GITHUB_SPF }],
              Comment: 'Response from 205.251.193.165.',
            })
          : undefined,
      ),
    );
    const ctx = makeCtx({ fetch: m.fetch });
    const res = await dohQuery(ctx, 'github.com', 'TXT');
    expect(res.resolver).toBe('google');
    expect(res.answers[0]).toEqual({ name: 'github.com', type: 16, ttl: 105, data: GITHUB_SPF });
    expect(m.calls.map((c) => new URL(c.url).host)).toEqual([CF_HOST, G_HOST]);
    const g = new URL(m.calls[1]!.url);
    expect(`${g.origin}${g.pathname}`).toBe('https://dns.google/resolve');
    expect(g.searchParams.get('name')).toBe('github.com');
    expect(g.searchParams.get('type')).toBe('TXT');
    expect(headerOf(m.calls[1]!.init, 'accept')).toBe('application/json');
  });

  // OPSEC BUG in src/lib/doh.ts (reported in sharedChangesNeeded): Google's JSON API forwards an
  // approximate client subnet (EDNS Client Subnet) to the queried domain's authoritative servers
  // unless edns_client_subnet=0.0.0.0/0 is sent, so the fallback leaks the investigator's network
  // to a target that runs its own nameservers. Cloudflare never sends ECS. Un-skip after the fix.
  it('disables EDNS Client Subnet on the Google fallback', async () => {
    const m = mockFetch(networkDown(CF_HOST), on(G_HOST, () => json({ Status: 0 })));
    await dohQuery(makeCtx({ fetch: m.fetch }), 'example.com', 'A');
    expect(new URL(m.calls[1]!.url).searchParams.get('edns_client_subnet')).toBe('0.0.0.0/0');
  });

  it('falls back to Google when Cloudflare answers SERVFAIL', async () => {
    const m = mockFetch(
      on(CF_HOST, () => json({ Status: 2, Comment: ['EDE(22): No Reachable Authority'] })),
      on(G_HOST, () => json({ Status: 0, Answer: [{ name: 'example.com.', type: 1, TTL: 300, data: '93.184.215.14' }] })),
    );
    const ctx = makeCtx({ fetch: m.fetch });
    const res = await dohQuery(ctx, 'example.com', 'A');
    expect(res.resolver).toBe('google');
    expect(res.status).toBe(0);
    expect(m.calls).toHaveLength(2);
  });

  it('returns Google SERVFAIL as an answer (status 2) when both resolvers fail to resolve', async () => {
    const m = mockFetch(
      on(CF_HOST, () => json({ Status: 2 })),
      on(G_HOST, () => json({ Status: 2, Comment: 'DNSSEC validation failure.' })),
    );
    const res = await dohQuery(makeCtx({ fetch: m.fetch }), 'dnssec-failed.org', 'A');
    expect(res.status).toBe(2);
    expect(res.resolver).toBe('google');
    expect(res.comment).toBe('DNSSEC validation failure.');
  });

  it('falls back on a Cloudflare 400 with an empty body and on a junk 200 body', async () => {
    const m1 = mockFetch(
      on(CF_HOST, () => new Response('', { status: 400 })),
      on(G_HOST, () => json({ Status: 0 })),
    );
    expect((await dohQuery(makeCtx({ fetch: m1.fetch }), 'example.com', 'A')).resolver).toBe('google');

    const m2 = mockFetch(
      on(CF_HOST, () => json({ hello: 'world' })),
      on(G_HOST, () => json({ Status: 0 })),
    );
    expect((await dohQuery(makeCtx({ fetch: m2.fetch }), 'example.com', 'A')).resolver).toBe('google');
  });

  it('throws the last error when both resolvers fail (Google 400 is HTML)', async () => {
    const m = mockFetch(networkDown(CF_HOST), on(G_HOST, () => text('<html><body>Bad Request</body></html>', 400)));
    const err = await dohQuery(makeCtx({ fetch: m.fetch }), 'example.com', 'A').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).kind).toBe('http');
    expect((err as FetchError).status).toBe(400);
    expect((err as FetchError).url).toContain('dns.google');
  });

  it('does not fall back when cancelled', async () => {
    const ac = new AbortController();
    ac.abort();
    const m = mockFetch(on(CF_HOST, () => json({ Status: 0 })), on(G_HOST, () => json({ Status: 0 })));
    const err = await dohQuery(makeCtx({ fetch: m.fetch, signal: ac.signal }), 'example.com', 'A').catch((e: unknown) => e);
    expect((err as FetchError).kind).toBe('aborted');
    expect(m.calls).toHaveLength(0);
  });

  it('memoises per name/type within a run, normalising case and the trailing dot', async () => {
    const m = mockFetch(on(CF_HOST, () => json(GITHUB_A)));
    const ctx = makeCtx({ fetch: m.fetch });
    const [a, b] = await Promise.all([dohQuery(ctx, 'github.com', 'A'), dohQuery(ctx, 'GitHub.COM.', 'A')]);
    const c = await dohQuery(ctx, 'github.com.', 'A');
    expect(a).toBe(b);
    expect(c).toBe(a);
    expect(m.calls).toHaveLength(1);
    expect(m.calls[0]!.url).toBe('https://cloudflare-dns.com/dns-query?name=github.com&type=A');

    await dohQuery(ctx, 'github.com', 'AAAA');
    expect(m.calls).toHaveLength(2);

    // A new investigation (new shared memo) fetches again.
    const ctx2 = makeCtx({ fetch: m.fetch });
    await dohQuery(ctx2, 'github.com', 'A');
    expect(m.calls).toHaveLength(3);
  });

  it('does not memoise failures', async () => {
    let up = false;
    const m = mockFetch((url) => {
      if (!up) throw new TypeError('offline');
      return url.host === CF_HOST ? json({ Status: 0 }) : undefined;
    });
    const ctx = makeCtx({ fetch: m.fetch });
    await expect(dohQuery(ctx, 'example.com', 'A')).rejects.toBeInstanceOf(FetchError);
    up = true;
    await expect(dohQuery(ctx, 'example.com', 'A')).resolves.toMatchObject({ status: 0 });
    expect(m.calls).toHaveLength(3);
  });

  it('CNAME chains: A records live under the final target, so filter by type', async () => {
    const m = mockFetch(
      on(CF_HOST, () =>
        json({
          Status: 0,
          Question: [{ name: 'www.github.com', type: 1 }],
          Answer: [
            { name: 'www.github.com', type: 5, TTL: 3570, data: 'github.com.' },
            { name: 'github.com', type: 1, TTL: 30, data: '20.208.89.80' },
          ],
        }),
      ),
    );
    const res = await dohQuery(makeCtx({ fetch: m.fetch }), 'www.github.com', 'A');
    expect(recordsOf(res, 'A')).toEqual([{ name: 'github.com', type: RR.A, ttl: 30, data: '20.208.89.80' }]);
    expect(valuesOf(res, 'CNAME')).toEqual(['github.com']);
  });

  it('dangling CNAME: Status 3 still carries the CNAME and is not retried on Google', async () => {
    const m = mockFetch(
      on(CF_HOST, () =>
        json({
          Status: 3,
          Question: [{ name: 'selector1._domainkey.microsoft.com', type: 16 }],
          Answer: [
            {
              name: 'selector1._domainkey.microsoft.com',
              type: 5,
              TTL: 3600,
              data: 'selector1-microsoft-com._domainkey.microsoft.onmicrosoft.com.',
            },
          ],
          Authority: [
            { name: 'onmicrosoft.com', type: 6, TTL: 900, data: 'ns1-bn.msft.net. azuredns-hostmaster.microsoft.com. 1 3600 300 2419200 300' },
          ],
        }),
      ),
    );
    const res = await dohQuery(makeCtx({ fetch: m.fetch }), 'selector1._domainkey.microsoft.com', 'TXT');
    expect(res.status).toBe(3);
    expect(recordsOf(res, 'TXT')).toEqual([]);
    expect(valuesOf(res, 'CNAME')).toEqual(['selector1-microsoft-com._domainkey.microsoft.onmicrosoft.com']);
    expect(res.authority[0]?.type).toBe(RR.SOA);
    expect(m.calls).toHaveLength(1);
  });

  it('NODATA: Status 0 with no Answer and an SOA in Authority', async () => {
    const m = mockFetch(
      on(CF_HOST, () =>
        json({
          Status: 0,
          Question: [{ name: 'github.com', type: 28 }],
          Authority: [{ name: 'github.com', type: 6, TTL: 3240, data: 'dns1.p08.nsone.net. hostmaster.nsone.net. 1656468023 43200 7200 1209600 3600' }],
        }),
      ),
    );
    const res = await dohQuery(makeCtx({ fetch: m.fetch }), 'github.com', 'AAAA');
    expect(res.status).toBe(0);
    expect(res.answers).toEqual([]);
    expect(recordsOf(res, 'AAAA')).toEqual([]);
    expect(res.authority).toHaveLength(1);
  });
});
