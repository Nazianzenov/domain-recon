import { describe, expect, it } from 'vitest';
import {
  SIGNATURES,
  detectProviders,
  formatSpfTerm,
  selectorsToQuery,
  spfIncludes,
  type Evidence,
} from '@/lib/email-signatures';
import { isAbortError } from '@/lib/http';
import { SkipError } from '@/lib/types';
import { emailModule, summaryOf, type EmailData } from '@/modules/email';
import { json, makeCtx, mockFetch, type Route } from './helpers';

const TYPES: Record<string, number> = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };
const DOMAIN = 'example.com';

function ev(over: Partial<Evidence> = {}): Evidence {
  return { spf: null, txt: [], mx: [], dkim: [], ...over };
}

function providerNames(e: Evidence): string[] {
  return detectProviders(e).providers.map((p) => p.provider);
}

// ---------------------------------------------------------------------------
// DoH fixtures

type Rec = { type: keyof typeof TYPES; data: string };
type Zone = Record<string, Rec[]>;

/**
 * Cloudflare DoH JSON as it really looks: TXT as quoted character-strings,
 * CNAME/MX targets with a trailing dot, NXDOMAIN with an SOA in Authority,
 * NODATA as Status 0 without Answer, and a TXT query on a CNAMEd name
 * returning the CNAME plus the target's TXT.
 */
function cloudflare(zone: Zone, opts: { fail?: (name: string, type: string) => Response | undefined } = {}): Route {
  return (url) => {
    if (url.hostname !== 'cloudflare-dns.com') return undefined;
    const name = (url.searchParams.get('name') ?? '').toLowerCase();
    const type = url.searchParams.get('type') ?? '';
    const forced = opts.fail?.(name, type);
    if (forced) return forced;
    const q = [{ name, type: TYPES[type] }];
    const base = { TC: false, RD: true, RA: true, AD: false, CD: false, Question: q };
    const recs = zone[name];
    if (!recs) {
      return json(
        {
          ...base,
          Status: 3,
          Authority: [{ name: DOMAIN, type: 6, TTL: 1800, data: 'ns1.example-dns.net. hostmaster.example.com. 2026112501 10800 3600 604800 1800' }],
        },
        200,
        { 'content-type': 'application/dns-json' },
      );
    }
    const answer: Array<{ name: string; type: number; TTL: number; data: string }> = [];
    const cname = recs.find((r) => r.type === 'CNAME');
    if (type === 'CNAME' || !cname) {
      for (const r of recs) if (r.type === type) answer.push({ name, type: TYPES[r.type]!, TTL: 300, data: r.data });
    } else {
      answer.push({ name, type: 5, TTL: 300, data: cname.data });
      const target = cname.data.replace(/\.$/, '');
      for (const r of zone[target] ?? []) if (r.type === type) answer.push({ name: target, type: TYPES[r.type]!, TTL: 300, data: r.data });
    }
    return json({ ...base, Status: 0, ...(answer.length ? { Answer: answer } : {}) }, 200, {
      'content-type': 'application/dns-json',
    });
  };
}

function google(handler: (name: string, type: string) => Response | undefined): Route {
  return (url) => {
    if (url.hostname !== 'dns.google') return undefined;
    return handler((url.searchParams.get('name') ?? '').toLowerCase(), url.searchParams.get('type') ?? '');
  };
}

/** A realistic mixed-provider zone (values in Cloudflare's wire presentation). */
const MIXED: Zone = {
  [DOMAIN]: [
    // Split across two character-strings, joined without a separator (RFC 7208 §3.3).
    { type: 'TXT', data: '"v=spf1 include:_spf.google.com include:sendgrid.net " "include:spf.protection.outlook.com ~all"' },
    { type: 'TXT', data: '"MS=ms48291736"' },
    { type: 'TXT', data: '"google-site-verification=rXOxyZounnZasA8Z7oaD3c14JdjS9aKSWvsR1EbUSIQ"' },
    { type: 'TXT', data: '"apple-domain-verification=Uw8DsWZcbQqPcvbb"' },
    { type: 'MX', data: '1 smtp.google.com.' },
    { type: 'MX', data: '10 example-com.mail.protection.outlook.com.' },
  ],
  [`s1._domainkey.${DOMAIN}`]: [{ type: 'CNAME', data: 's1.domainkey.u1234567.wl123.sendgrid.net.' }],
  [`s2._domainkey.${DOMAIN}`]: [{ type: 'CNAME', data: 's2.domainkey.u1234567.wl123.sendgrid.net.' }],
  [`selector1._domainkey.${DOMAIN}`]: [
    { type: 'CNAME', data: 'selector1-example-com._domainkey.contoso.onmicrosoft.com.' },
  ],
  [`google._domainkey.${DOMAIN}`]: [
    {
      type: 'TXT',
      data: '"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu6NwJ3b9xYWk2m0f6vIhH1q8kEJyPj3V4e7gS" "Lr0w2xq0Xz9cE8KzrGJQIDAQAB"',
    },
  ],
};

const SELECTOR_COUNT = selectorsToQuery().length;
const TXT_SELECTOR_COUNT = selectorsToQuery().filter((s) => s.txt).length;

// ---------------------------------------------------------------------------

describe('spfIncludes', () => {
  it('parses top-level include: mechanisms and the redirect= modifier', () => {
    expect(spfIncludes('v=spf1 ip4:192.0.2.0/24 include:_spf.google.com ~include:sendgrid.net a mx redirect=_spf.example.net')).toEqual([
      { type: 'include', domain: '_spf.google.com' },
      { type: 'include', domain: 'sendgrid.net', qualifier: '~' },
      { type: 'redirect', domain: '_spf.example.net' },
    ]);
  });

  it('is case-insensitive and tolerates trailing dots and extra whitespace', () => {
    expect(spfIncludes('  V=SPF1   INCLUDE:_SPF.Google.COM.\t+Include:SendGrid.Net   REDIRECT=Spf.Example.ORG.  ')).toEqual([
      { type: 'include', domain: '_spf.google.com' },
      { type: 'include', domain: 'sendgrid.net', qualifier: '+' },
      { type: 'redirect', domain: 'spf.example.org' },
    ]);
  });

  it('ignores other mechanisms, empty domains and missing input', () => {
    expect(spfIncludes('v=spf1 exists:%{i}._spf.example.com ptr include: -all')).toEqual([]);
    expect(spfIncludes(null)).toEqual([]);
    expect(spfIncludes(undefined)).toEqual([]);
    expect(spfIncludes('')).toEqual([]);
  });

  it('keeps macro includes verbatim (lowercased)', () => {
    expect(spfIncludes('v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email -all')).toEqual([
      { type: 'include', domain: '%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email' },
    ]);
  });

  it('formats terms back to SPF syntax', () => {
    expect(formatSpfTerm({ type: 'include', domain: 'sendgrid.net' })).toBe('include:sendgrid.net');
    expect(formatSpfTerm({ type: 'include', domain: 'sendgrid.net', qualifier: '?' })).toBe('?include:sendgrid.net');
    expect(formatSpfTerm({ type: 'redirect', domain: '_spf.google.com' })).toBe('redirect=_spf.google.com');
  });
});

describe('signature table', () => {
  it('is well-formed data: anchored-safe regexes without g/y flags, captures fit the groups', () => {
    for (const s of SIGNATURES) {
      expect(s.re.global || s.re.sticky, `${s.provider} ${s.type} ${s.name}`).toBe(false);
      const groups = new RegExp(`${s.re.source}|`).exec('')!.length - 1;
      expect(s.captures?.length ?? 0, `${s.provider} ${s.re}`).toBeLessThanOrEqual(groups);
      if (s.type === 'dkim') expect(s.record, `${s.provider} ${s.name}`).toMatch(/^(CNAME|TXT)$/);
      else expect(s.name).toBe('@');
      if (s.account) expect([...(s.captures ?? []), ...Object.keys(s.derive ?? {})]).toContain(s.account.capture);
    }
  });

  it('covers all six required providers', () => {
    const providers = new Set(SIGNATURES.map((s) => s.provider));
    for (const p of ['SendGrid', 'Mailgun', 'Amazon SES', 'Mailchimp', 'Mandrill', 'Google Workspace', 'Microsoft 365']) {
      expect(providers.has(p), p).toBe(true);
    }
  });

  it('selectorsToQuery is derived from the table, deduped, with TXT where expected', () => {
    const sels = selectorsToQuery();
    const names = sels.map((s) => s.selector);
    expect(new Set(names).size).toBe(names.length);
    expect(names).not.toContain('*');
    for (const n of ['s1', 's2', 'selector1', 'selector2', 'k1', 'k2', 'k3', 'mte1', 'mte2', 'pdk1', 'pdk2', 'google', 'mandrill']) {
      expect(names, n).toContain(n);
    }
    const byName = Object.fromEntries(sels.map((s) => [s.selector, s.txt]));
    expect(byName).toMatchObject({ google: true, mandrill: true, s1: false, selector1: false, k1: false });
  });

  it('selectorsToQuery merges duplicate selectors and their record types', () => {
    const sels = selectorsToQuery([
      { provider: 'A', type: 'dkim', name: 'X1', record: 'CNAME', re: /^a$/, weight: 3 },
      { provider: 'B', type: 'dkim', name: 'x1', record: 'TXT', re: /^b$/, weight: 3 },
      { provider: 'C', type: 'dkim', name: '*', record: 'CNAME', re: /^c$/, weight: 3 },
      { provider: 'D', type: 'spf', name: '@', re: /^d$/, weight: 3 },
    ]);
    expect(sels).toEqual([{ selector: 'x1', txt: true }]);
  });
});

describe('SendGrid account ID extraction', () => {
  const sg = (s1: string, s2?: string) =>
    detectProviders(ev({ dkim: [{ selector: 's1', cname: s1 }, ...(s2 ? [{ selector: 's2', cname: s2 }] : [])] }));

  it('extracts u<digits> from the s1.domainkey form', () => {
    const d = sg('s1.domainkey.u298828.wl079.sendgrid.net');
    expect(d.providers).toHaveLength(1);
    expect(d.providers[0]).toMatchObject({ provider: 'SendGrid', confidence: 'high', score: 3 });
    expect(d.providers[0]!.evidence[0]).toMatchObject({
      type: 'dkim',
      name: 's1',
      record: 'CNAME',
      value: 's1.domainkey.u298828.wl079.sendgrid.net',
      captures: { userId: 'u298828', wl: '079' },
    });
    expect(d.accountIds).toEqual([{ provider: 'SendGrid', kind: 'user ID', value: 'u298828', summary: true }]);
  });

  it('extracts from the bare u<id>.wl<nnn> form', () => {
    expect(sg('u1234567.wl123.sendgrid.net').accountIds.map((a) => a.value)).toEqual(['u1234567']);
  });

  it('is case-insensitive and trailing-dot tolerant', () => {
    const d = sg('S1.DOMAINKEY.U1234567.WL123.SENDGRID.NET.', 'U1234567.Wl123.SendGrid.Net.');
    expect(d.accountIds).toEqual([{ provider: 'SendGrid', kind: 'user ID', value: 'u1234567', summary: true }]);
    expect(d.providers[0]!.evidence.map((e) => e.value)).toEqual([
      's1.domainkey.u1234567.wl123.sendgrid.net',
      'u1234567.wl123.sendgrid.net',
    ]);
    expect(d.providers[0]!.score).toBe(6);
  });

  it('accepts the legacy wl label without digits', () => {
    expect(sg('s1.domainkey.u42.wl.sendgrid.net').accountIds[0]?.value).toBe('u42');
  });

  it('reports distinct IDs when s1 and s2 point to different users', () => {
    const d = sg('s1.domainkey.u111.wl1.sendgrid.net', 's2.domainkey.u222.wl1.sendgrid.net');
    expect(d.accountIds.map((a) => a.value)).toEqual(['u111', 'u222']);
  });

  it('does not extract from look-alike targets', () => {
    for (const t of [
      's1.domainkey.u1234567.wl123.sendgrid.net.evil.example',
      's1.domainkey.u1234567.wl123.notsendgrid.net',
      's1.domainkey.uabc.wl123.sendgrid.net',
      'sendgrid.net',
    ]) {
      const d = sg(t);
      expect(d.providers, t).toEqual([]);
      expect(d.accountIds, t).toEqual([]);
    }
  });

  it('only reads the s1/s2 selectors', () => {
    const d = detectProviders(ev({ dkim: [{ selector: 'k1', cname: 's1.domainkey.u1.wl1.sendgrid.net' }] }));
    expect(d.providers).toEqual([]);
  });
});

describe('detectProviders: required providers from realistic records', () => {
  it('SendGrid from an apex include only is medium confidence', () => {
    const d = detectProviders(ev({ spf: 'v=spf1 include:sendgrid.net ~all' }));
    expect(d.providers).toEqual([
      {
        provider: 'SendGrid',
        confidence: 'medium',
        score: 2,
        evidence: [
          { type: 'spf', name: '@', value: 'include:sendgrid.net', captures: {}, note: 'standard setup puts this on em####, not the apex' },
        ],
      },
    ]);
    expect(d.accountIds).toEqual([]);
  });

  it('Mailgun from SPF + MX, with the EU region and pdk DKIM', () => {
    const us = detectProviders(ev({ spf: 'v=spf1 include:mailgun.org ~all', mx: ['mxa.mailgun.org', 'mxb.mailgun.org'] }));
    expect(us.providers[0]).toMatchObject({ provider: 'Mailgun', confidence: 'high', score: 6 });
    expect(us.providers[0]!.evidence.map((e) => e.value)).toEqual(['include:mailgun.org', 'mxa.mailgun.org', 'mxb.mailgun.org']);

    const eu = detectProviders(
      ev({
        spf: 'v=spf1 include:eu.mailgun.org ~all',
        mx: ['mxa.eu.mailgun.org.'],
        dkim: [{ selector: 'pdk1', cname: 'pdk1._domainkey.a1b2c3d4.dkim1.mailgun.com.' }],
      }),
    );
    const hits = eu.providers[0]!.evidence;
    expect(hits[0]!.captures).toEqual({ region: 'eu' });
    expect(hits.find((h) => h.type === 'mx')!.captures).toEqual({ region: 'eu' });
    expect(us.providers[0]!.evidence[0]!.captures).toEqual({});
    expect(hits.find((h) => h.type === 'dkim')).toMatchObject({ name: 'pdk1', captures: { mgId: 'a1b2c3d4' } });
  });

  it('Amazon SES from SPF, inbound MX and an Easy DKIM token CNAME', () => {
    const spfOnly = detectProviders(ev({ spf: 'v=spf1 include:amazonses.com -all' }));
    expect(spfOnly.providers[0]).toMatchObject({ provider: 'Amazon SES', confidence: 'medium' });

    const mx = detectProviders(ev({ mx: ['inbound-smtp.eu-west-1.amazonaws.com'] }));
    expect(mx.providers[0]).toMatchObject({ provider: 'Amazon SES', confidence: 'high' });
    expect(mx.providers[0]!.evidence[0]!.captures).toEqual({ region: 'eu-west-1' });

    const token = 'abcdefghijklmnopqrstuvwxyz012345';
    const dkim = detectProviders(ev({ dkim: [{ selector: token, cname: `${token}.dkim.amazonses.com` }] }));
    expect(dkim.providers[0]).toMatchObject({ provider: 'Amazon SES', confidence: 'high' });
    expect(dkim.providers[0]!.evidence[0]).toMatchObject({ name: token, captures: { token } });

    const regional = detectProviders(ev({ dkim: [{ selector: token, cname: `${token}.dkim.us-west-2.amazonses.com` }] }));
    expect(regional.providers[0]!.evidence[0]!.captures).toEqual({ token, region: 'us-west-2' });
  });

  it('Mailchimp from k1/k2/k3 and Mandrill from mte1/mte2, legacy TXT key and verification TXT', () => {
    const mc = detectProviders(
      ev({
        dkim: [
          { selector: 'k1', cname: 'dkim.mcsv.net.' },
          { selector: 'k2', cname: 'dkim2.mcsv.net' },
          { selector: 'k3', cname: 'dkim3.mcsv.net' },
        ],
      }),
    );
    expect(mc.providers).toHaveLength(1);
    expect(mc.providers[0]).toMatchObject({ provider: 'Mailchimp', confidence: 'high', score: 9 });

    const md = detectProviders(
      ev({
        txt: ['mandrill_verify.AbCdEf_123-xyz'],
        dkim: [
          { selector: 'mte1', cname: 'dkim1.mandrillapp.com' },
          { selector: 'mte2', cname: 'dkim2.mandrillapp.com' },
          { selector: 'mandrill', txt: 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrLHiExVd55zd' },
        ],
      }),
    );
    expect(md.providers.map((p) => p.provider)).toEqual(['Mandrill']);
    expect(md.providers[0]!.evidence.map((e) => `${e.type}:${e.name}`)).toEqual(['dkim:mte1', 'dkim:mte2', 'dkim:mandrill', 'txt:@']);
    // Original case kept for display.
    expect(md.providers[0]!.evidence.at(-1)!.value).toBe('mandrill_verify.AbCdEf_123-xyz');
  });

  it('Google Workspace from MX (new and legacy), SPF and the google DKIM TXT', () => {
    expect(providerNames(ev({ mx: ['smtp.google.com'] }))).toEqual(['Google Workspace']);
    expect(providerNames(ev({ mx: ['ASPMX.L.GOOGLE.COM.', 'alt1.aspmx.l.google.com', 'aspmx2.googlemail.com'] }))).toEqual(['Google Workspace']);
    expect(providerNames(ev({ spf: 'v=spf1 redirect=_spf.google.com' }))).toEqual(['Google Workspace']);
    const dk = detectProviders(ev({ dkim: [{ selector: 'google', txt: 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA' }] }));
    expect(dk.providers[0]).toMatchObject({ provider: 'Google Workspace', confidence: 'medium', score: 2 });
    expect(dk.providers[0]!.evidence[0]).toMatchObject({ type: 'dkim', name: 'google', record: 'TXT' });
  });

  it('google-site-verification alone does not establish Google Workspace, but supports it', () => {
    const gsv = 'google-site-verification=rXOxyZounnZasA8Z7oaD3c14JdjS9aKSWvsR1EbUSIQ';
    expect(detectProviders(ev({ txt: [gsv] })).providers).toEqual([]);
    const both = detectProviders(ev({ txt: [gsv], dkim: [{ selector: 'google', txt: 'v=DKIM1; p=MIIB' }] }));
    expect(both.providers[0]).toMatchObject({ provider: 'Google Workspace', confidence: 'high', score: 3 });
    expect(both.providers[0]!.evidence.map((e) => e.type)).toEqual(['dkim', 'txt']);
  });

  it('Microsoft 365 from SPF, legacy and DNSSEC MX, MS= TXT', () => {
    const d = detectProviders(
      ev({
        spf: 'v=spf1 include:spf.protection.outlook.com -all',
        txt: ['MS=ms48291736', 'v=spf1 include:spf.protection.outlook.com -all'],
        mx: ['contoso-com.mail.protection.outlook.com.'],
      }),
    );
    expect(d.providers).toHaveLength(1);
    expect(d.providers[0]).toMatchObject({ provider: 'Microsoft 365', confidence: 'high', score: 8 });
    expect(d.providers[0]!.evidence.find((e) => e.type === 'mx')!.captures).toEqual({ mxToken: 'contoso-com' });

    const dnssec = detectProviders(ev({ mx: ['contosotest-com.o-v1.mx.microsoft'] }));
    expect(dnssec.providers[0]!.evidence[0]).toMatchObject({ captures: { mxToken: 'contosotest-com', partition: 'o-v1' }, note: 'DNSSEC MX' });

    const hexTxt = detectProviders(ev({ txt: [`MS=${'a1'.repeat(20)}`] }));
    expect(hexTxt.providers[0]).toMatchObject({ provider: 'Microsoft 365', confidence: 'medium' });
  });

  it('Microsoft 365 DKIM surfaces the initial onmicrosoft.com domain (old and new formats)', () => {
    const d = detectProviders(
      ev({
        dkim: [
          { selector: 'selector1', cname: 'selector1-microsoft-com._domainkey.microsoft.onmicrosoft.com.' },
          { selector: 'selector2', cname: 'selector2-contoso-com._domainkey.contoso.r-v1.dkim.mail.microsoft' },
        ],
      }),
    );
    const hits = d.providers[0]!.evidence;
    expect(hits[0]!.captures).toEqual({
      domainDashed: 'microsoft-com',
      initialDomainPrefix: 'microsoft',
      initialDomain: 'microsoft.onmicrosoft.com',
    });
    expect(hits[1]!.captures).toEqual({
      domainDashed: 'contoso-com',
      initialDomainPrefix: 'contoso',
      partition: 'r',
      initialDomain: 'contoso.onmicrosoft.com',
    });
    expect(d.accountIds).toEqual([
      { provider: 'Microsoft 365', kind: 'initial domain', value: 'microsoft.onmicrosoft.com', pivot: 'domain' },
      { provider: 'Microsoft 365', kind: 'initial domain', value: 'contoso.onmicrosoft.com', pivot: 'domain' },
    ]);
  });

  it('a few extras: HubSpot account ID, Proton Mail, Zoho Mail, Mimecast, Proofpoint', () => {
    const d = detectProviders(
      ev({
        spf: 'v=spf1 include:1234567.spf03.hubspotemail.net include:_spf.protonmail.ch include:spf-00123401.pphosted.com ~all',
        mx: ['mx.zoho.eu', 'eu-smtp-inbound-1.mimecast.com', 'mx0a-00123401.pphosted.com'],
      }),
    );
    expect(d.providers.map((p) => p.provider).sort()).toEqual(['HubSpot', 'Mimecast', 'Proofpoint', 'Proton Mail', 'Zoho Mail']);
    expect(d.accountIds).toEqual([{ provider: 'HubSpot', kind: 'account ID', value: '1234567' }]);
  });
});

describe('detectProviders: no false positives', () => {
  it('ignores unrelated and look-alike records', () => {
    const d = detectProviders({
      spf: 'v=spf1 ip4:192.0.2.10 include:sendgrid.net.evil.example include:notmailgun.org include:spf.protection.outlook.com.attacker.net a:mail.example.com -all',
      txt: [
        'v=spf1 ip4:192.0.2.10 -all',
        'apple-domain-verification=Uw8DsWZcbQqPcvbb',
        'facebook-domain-verification=9k2m5x0p1q',
        'docusign=1b0a6754-49b1-4db5-8540-d2c12664b289',
        'note: MS=ms12345678 mentioned in passing',
        'google-site-verification=abc',
      ],
      mx: ['mail.example.com', 'aspmx.l.google.com.evil.net', 'mx.sendgrid.net.example.org', 'fakemail.protection.outlook.com.example', ''],
      dkim: [
        { selector: 'k1', cname: 'dkim.mcsv.net.attacker.example' },
        { selector: 's1', cname: 's1.domainkey.example.net' },
        { selector: 'selector1', cname: 'selector1-example-com._domainkey.example.net' },
        { selector: 'mte1', cname: 'dkim1.mandrillapp.com.evil' },
        { selector: 'default', txt: 'v=DKIM1; k=rsa; p=MIIB' },
        { selector: 'google', cname: 'google._domainkey.example.net' },
      ],
    });
    expect(d).toEqual({ providers: [], accountIds: [] });
  });

  it('an ordinary self-hosted domain yields nothing', () => {
    expect(
      detectProviders(ev({ spf: 'v=spf1 mx a ip6:2001:db8::/32 -all', txt: ['v=spf1 mx a ip6:2001:db8::/32 -all'], mx: ['mail.example.org'] })),
    ).toEqual({ providers: [], accountIds: [] });
  });
});

describe('detectProviders: scoring and ordering', () => {
  it('sorts high before medium before low, then by score, then by name', () => {
    const d = detectProviders(
      ev({
        spf: 'v=spf1 include:_spf.google.com include:servers.mcsv.net include:sendgrid.net ~all',
        mx: ['smtp.google.com'],
        dkim: [{ selector: 'k1', cname: 'dkim.mcsv.net' }],
      }),
    );
    expect(d.providers.map((p) => [p.provider, p.confidence, p.score])).toEqual([
      ['Google Workspace', 'high', 6],
      ['Mailchimp', 'high', 5],
      ['SendGrid', 'medium', 2],
    ]);
  });

  it('counts each signature once even when it matches several values', () => {
    const d = detectProviders(ev({ mx: ['aspmx.l.google.com', 'alt1.aspmx.l.google.com', 'alt2.aspmx.l.google.com'] }));
    expect(d.providers[0]).toMatchObject({ score: 3 });
    expect(d.providers[0]!.evidence).toHaveLength(3);
  });

  it('reports low confidence for weight-1 evidence', () => {
    const d = detectProviders(ev({ txt: ['x'] }), [
      { provider: 'Weak', type: 'txt', name: '@', re: /^x$/, weight: 1 },
    ]);
    expect(d.providers[0]).toMatchObject({ provider: 'Weak', confidence: 'low', score: 1 });
  });

  it('caps long TXT values in evidence', () => {
    const key = `v=DKIM1; k=rsa; p=${'A'.repeat(400)}`;
    const d = detectProviders(ev({ dkim: [{ selector: 'google', txt: key }] }));
    const v = d.providers[0]!.evidence[0]!.value;
    expect(v.length).toBe(120);
    expect(v.endsWith('…')).toBe(true);
  });
});

// ---------------------------------------------------------------------------

describe('emailModule', () => {
  it('declares the expected metadata', () => {
    expect(emailModule).toMatchObject({ id: 'email', label: 'Email-sending providers', version: 1, accepts: ['domain'], ttl: 24 * 3_600_000 });
    expect(emailModule.active).toBeFalsy();
    expect(emailModule.key).toBeUndefined();
  });

  it('runs end to end against Cloudflare DoH (quoted TXT form)', async () => {
    const m = mockFetch(cloudflare(MIXED));
    const ctx = makeCtx({ fetch: m.fetch, root: DOMAIN });
    const out = await emailModule.run({ kind: 'domain', value: DOMAIN, depth: 0 }, ctx);
    const d = out.data;

    // Every lookup goes to the resolver, never to the target itself.
    expect(m.calls.every((c) => new URL(c.url).hostname === 'cloudflare-dns.com')).toBe(true);
    expect(m.calls.every((c) => (c.init.headers as Record<string, string>)['accept'] === 'application/dns-json')).toBe(true);
    expect(m.calls).toHaveLength(2 + SELECTOR_COUNT + TXT_SELECTOR_COUNT);
    expect(m.calls.map((c) => c.url)).toContain('https://cloudflare-dns.com/dns-query?name=s1._domainkey.example.com&type=CNAME');
    expect(m.calls.map((c) => c.url)).toContain('https://cloudflare-dns.com/dns-query?name=google._domainkey.example.com&type=TXT');

    expect(d.spf).toBe('v=spf1 include:_spf.google.com include:sendgrid.net include:spf.protection.outlook.com ~all');
    expect(d.spfIncludes.map((t) => t.domain)).toEqual(['_spf.google.com', 'sendgrid.net', 'spf.protection.outlook.com']);
    expect(d.mx).toEqual(['smtp.google.com', 'example-com.mail.protection.outlook.com']);
    expect(d.queriedSelectors).toBe(SELECTOR_COUNT);
    expect(d.dkim.map((k) => k.selector).sort()).toEqual(['google', 's1', 's2', 'selector1']);
    expect(d.dkim.find((k) => k.selector === 's1')).toEqual({ selector: 's1', cname: 's1.domainkey.u1234567.wl123.sendgrid.net' });
    expect(d.dkim.find((k) => k.selector === 'google')!.txt).toMatch(/^v=DKIM1; k=rsa; p=MIIB/);
    expect(d.failedLookups).toBeUndefined();

    expect(d.providers.map((p) => [p.provider, p.confidence])).toEqual([
      ['Microsoft 365', 'high'],
      ['Google Workspace', 'high'],
      ['SendGrid', 'high'],
    ]);
    expect(d.providers.map((p) => p.score)).toEqual([11, 9, 8]);
    expect(d.accountIds).toEqual([
      { provider: 'Microsoft 365', kind: 'initial domain', value: 'contoso.onmicrosoft.com', pivot: 'domain' },
      { provider: 'SendGrid', kind: 'user ID', value: 'u1234567', summary: true },
    ]);

    expect(out.summary).toBe('Microsoft 365 · Google Workspace · SendGrid (u1234567)');
    expect(out.pivots).toEqual([{ kind: 'domain', value: 'contoso.onmicrosoft.com', note: 'Microsoft 365 initial domain' }]);
    expect(emailModule.headline!(d, { kind: 'domain', value: DOMAIN, depth: 0 })).toEqual({
      emailProviders: ['Microsoft 365', 'Google Workspace', 'SendGrid'],
    });

    const facts = emailModule.facts!(d, { kind: 'domain', value: DOMAIN, depth: 0 });
    const sgId = facts.find((f) => f.label === 'SendGrid user ID');
    expect(sgId).toEqual({ label: 'SendGrid user ID', value: 'u1234567', pivot: true });
    expect(facts.find((f) => f.label === 'Microsoft 365 initial domain')).toMatchObject({ value: 'contoso.onmicrosoft.com', pivot: true });
    expect(facts.find((f) => f.label === 'SendGrid (high confidence)')!.value).toEqual([
      'DKIM s1._domainkey → s1.domainkey.u1234567.wl123.sendgrid.net (u<digits> = SendGrid user_id, may be a subuser)',
      'DKIM s2._domainkey → s2.domainkey.u1234567.wl123.sendgrid.net (u<digits> = SendGrid user_id, may be a subuser)',
      'SPF include:sendgrid.net (standard setup puts this on em####, not the apex)',
    ]);
    expect(facts.find((f) => f.label === 'SPF includes (top level, not expanded)')!.value).toEqual([
      'include:_spf.google.com',
      'include:sendgrid.net',
      'include:spf.protection.outlook.com',
    ]);
    expect(facts.find((f) => f.label.startsWith('DKIM selectors found'))!.label).toBe(`DKIM selectors found (4/${SELECTOR_COUNT} checked)`);
    // Facts are plain text, no links.
    expect(facts.every((f) => f.href === undefined)).toBe(true);
    // JSON-serialisable.
    expect(JSON.parse(JSON.stringify(d))).toEqual(d);
  });

  it('reads TXT selectors through a CNAME and dedupes lookups shared with other modules', async () => {
    const zone: Zone = {
      [DOMAIN]: [{ type: 'MX', data: '10 mxa.mailgun.org.' }],
      [`google._domainkey.${DOMAIN}`]: [{ type: 'CNAME', data: 'keys.dkimhost.example.' }],
      'keys.dkimhost.example': [{ type: 'TXT', data: '"v=DKIM1; p=MIGfMA0"' }],
    };
    const m = mockFetch(cloudflare(zone));
    const ctx = makeCtx({ fetch: m.fetch, root: DOMAIN });
    const out = await emailModule.run({ kind: 'domain', value: DOMAIN, depth: 0 }, ctx);
    expect(out.data.dkim).toEqual([{ selector: 'google', cname: 'keys.dkimhost.example', txt: 'v=DKIM1; p=MIGfMA0' }]);
    expect(out.data.spf).toBeNull();
    expect(out.data.providers.map((p) => p.provider)).toEqual(['Mailgun', 'Google Workspace']);

    // A second run in the same investigation is served from ctx.shared.
    const n = m.calls.length;
    await emailModule.run({ kind: 'domain', value: DOMAIN, depth: 0 }, ctx);
    expect(m.calls.length).toBe(n);
  });

  it('reports no providers for a plain domain', async () => {
    const zone: Zone = {
      [DOMAIN]: [
        { type: 'TXT', data: '"v=spf1 mx -all"' },
        { type: 'MX', data: '10 mail.example.com.' },
      ],
    };
    const ctx = makeCtx({ fetch: mockFetch(cloudflare(zone)).fetch, root: DOMAIN });
    const out = await emailModule.run({ kind: 'domain', value: DOMAIN, depth: 0 }, ctx);
    expect(out.summary).toBe('No known sending providers');
    expect(out.pivots).toBeUndefined();
    expect(out.data.providers).toEqual([]);
    expect(out.data.dkim).toEqual([]);
    expect(emailModule.headline!(out.data, { kind: 'domain', value: DOMAIN, depth: 0 })).toEqual({ emailProviders: [] });
    const facts = emailModule.facts!(out.data, { kind: 'domain', value: DOMAIN, depth: 0 });
    expect(facts[0]).toEqual({ label: 'Providers', value: 'No known sending providers detected' });
    expect(facts).toContainEqual({ label: 'SPF', value: 'No include:/redirect= terms' });
    expect(facts).toContainEqual({ label: `DKIM selectors found (0/${SELECTOR_COUNT} checked)`, value: 'None of the common selectors' });
  });

  it('drops a null MX and handles a missing SPF record', async () => {
    const zone: Zone = { [DOMAIN]: [{ type: 'MX', data: '0 .' }, { type: 'TXT', data: '"MS=ms12345678"' }] };
    const ctx = makeCtx({ fetch: mockFetch(cloudflare(zone)).fetch, root: DOMAIN });
    const out = await emailModule.run({ kind: 'domain', value: DOMAIN, depth: 0 }, ctx);
    expect(out.data.mx).toEqual([]);
    expect(out.data.spf).toBeNull();
    expect(out.summary).toBe('Microsoft 365');
    const facts = emailModule.facts!(out.data, { kind: 'domain', value: DOMAIN, depth: 0 });
    expect(facts).toContainEqual({ label: 'SPF', value: 'No SPF record at apex' });
    expect(facts.find((f) => f.label === 'MX')).toBeUndefined();
  });

  it('falls back to Google DoH (unquoted TXT form) when Cloudflare SERVFAILs', async () => {
    const m = mockFetch(
      (url) => (url.hostname === 'cloudflare-dns.com' ? json({ Status: 2, Comment: 'upstream timeout' }) : undefined),
      google((name, type) => {
        if (name === DOMAIN && type === 'TXT') {
          return json({ Status: 0, Answer: [{ name: `${DOMAIN}.`, type: 16, TTL: 300, data: 'v=spf1 include:mailgun.org ~all' }] });
        }
        if (name === `s1._domainkey.${DOMAIN}` && type === 'CNAME') {
          return json({ Status: 0, Answer: [{ name: `${name}.`, type: 5, TTL: 300, data: 'u7654321.wl001.sendgrid.net.' }] });
        }
        // The apex exists (NODATA); unknown selectors are NXDOMAIN.
        return json(name === DOMAIN ? { Status: 0 } : { Status: 3 });
      }),
    );
    const ctx = makeCtx({ fetch: m.fetch, root: DOMAIN });
    const out = await emailModule.run({ kind: 'domain', value: DOMAIN, depth: 0 }, ctx);
    expect(out.data.providers.map((p) => p.provider)).toEqual(['Mailgun', 'SendGrid']);
    expect(out.summary).toBe('Mailgun · SendGrid (u7654321)');
  });

  it('a failing lookup does not fail the module', async () => {
    const failName = `s1._domainkey.${DOMAIN}`;
    const m = mockFetch(
      cloudflare(MIXED, { fail: (name, type) => (name === failName && type === 'CNAME' ? json({ error: 'boom' }, 500) : undefined) }),
      google((name) => (name === failName ? json({ message: 'unavailable' }, 503) : undefined)),
    );
    const ctx = makeCtx({ fetch: m.fetch, root: DOMAIN });
    const out = await emailModule.run({ kind: 'domain', value: DOMAIN, depth: 0 }, ctx);
    expect(out.data.failedLookups).toHaveLength(1);
    expect(out.data.failedLookups![0]).toMatch(/^CNAME s1\._domainkey\.example\.com: HTTP 503/);
    // s2 still carries the SendGrid ID.
    expect(out.data.accountIds.map((a) => a.value)).toContain('u1234567');
    const facts = emailModule.facts!(out.data, { kind: 'domain', value: DOMAIN, depth: 0 });
    expect(facts.find((f) => f.label === 'Failed lookups')).toMatchObject({ tone: 'warn' });
    expect(out.summary).toBe('Microsoft 365 · Google Workspace · SendGrid (u1234567) · 1 lookup failed');
  });

  it('throws when every lookup fails', async () => {
    const m = mockFetch(
      (url) => (url.hostname === 'cloudflare-dns.com' ? json({ error: 'x' }, 500) : undefined),
      (url) => (url.hostname === 'dns.google' ? json({ error: 'y' }, 502) : undefined),
    );
    const ctx = makeCtx({ fetch: m.fetch, root: DOMAIN });
    await expect(emailModule.run({ kind: 'domain', value: DOMAIN, depth: 0 }, ctx)).rejects.toMatchObject({ kind: 'http', status: 502 });
  });

  it('treats a junk DoH body as a failed lookup', async () => {
    const m = mockFetch(
      (url) => (url.hostname === 'cloudflare-dns.com' ? json(['not', 'doh']) : undefined),
      (url) => (url.hostname === 'dns.google' ? json({ nope: true }) : undefined),
    );
    const ctx = makeCtx({ fetch: m.fetch, root: DOMAIN });
    await expect(emailModule.run({ kind: 'domain', value: DOMAIN, depth: 0 }, ctx)).rejects.toMatchObject({ kind: 'parse' });
  });

  it('skips a domain that does not exist', async () => {
    const ctx = makeCtx({ fetch: mockFetch(cloudflare({})).fetch, root: 'nope.example' });
    await expect(emailModule.run({ kind: 'domain', value: 'nope.example', depth: 0 }, ctx)).rejects.toBeInstanceOf(SkipError);
  });

  it('propagates cancellation', async () => {
    const ac = new AbortController();
    ac.abort();
    const ctx = makeCtx({ fetch: mockFetch(cloudflare(MIXED)).fetch, root: DOMAIN, signal: ac.signal });
    await expect(emailModule.run({ kind: 'domain', value: DOMAIN, depth: 0 }, ctx)).rejects.toMatchObject({ kind: 'aborted' });
  });

  it('does not return a result when cancelled after the lookups were sent', async () => {
    const ac = new AbortController();
    const ctx = makeCtx({ fetch: mockFetch(cloudflare(MIXED)).fetch, root: DOMAIN, signal: ac.signal });
    const p = emailModule.run({ kind: 'domain', value: DOMAIN, depth: 0 }, ctx);
    ac.abort(); // every fetch already started and will resolve normally
    await expect(p).rejects.toSatisfy(isAbortError);
  });

  it('ignores a wildcard CNAME that answers every guessed selector', async () => {
    const zone: Zone = { [DOMAIN]: [{ type: 'MX', data: '10 mail.example.com.' }] };
    for (const { selector } of selectorsToQuery()) {
      zone[`${selector}._domainkey.${DOMAIN}`] = [{ type: 'CNAME', data: 'parking.example-host.net.' }];
    }
    zone[`s1._domainkey.${DOMAIN}`] = [{ type: 'CNAME', data: 's1.domainkey.u1234567.wl123.sendgrid.net.' }];
    const ctx = makeCtx({ fetch: mockFetch(cloudflare(zone)).fetch, root: DOMAIN });
    const out = await emailModule.run({ kind: 'domain', value: DOMAIN, depth: 0 }, ctx);
    expect(out.data.dkimWildcard).toBe('parking.example-host.net');
    expect(out.data.dkim).toEqual([{ selector: 's1', cname: 's1.domainkey.u1234567.wl123.sendgrid.net' }]);
    expect(out.data.providers.map((p) => p.provider)).toEqual(['SendGrid']);
    const facts = emailModule.facts!(out.data, { kind: 'domain', value: DOMAIN, depth: 0 });
    expect(facts.find((f) => f.label.startsWith('DKIM selectors found'))).toEqual({
      label: `DKIM selectors found (1/${SELECTOR_COUNT} checked)`,
      value: ['s1 → s1.domainkey.u1234567.wl123.sendgrid.net'],
    });
    expect(facts.find((f) => f.label === 'DKIM wildcard')!.value).toMatch(/parking\.example-host\.net/);
  });

  it('does not report a non-DKIM TXT at a selector as a DKIM key', async () => {
    const zone: Zone = {
      [DOMAIN]: [{ type: 'MX', data: '10 mail.example.com.' }],
      // e.g. a wildcard "*.example.com TXT v=spf1 -all" on a parked domain
      [`google._domainkey.${DOMAIN}`]: [{ type: 'TXT', data: '"v=spf1 -all"' }],
      [`mandrill._domainkey.${DOMAIN}`]: [{ type: 'TXT', data: '"v=spf1 -all"' }],
    };
    const ctx = makeCtx({ fetch: mockFetch(cloudflare(zone)).fetch, root: DOMAIN });
    const out = await emailModule.run({ kind: 'domain', value: DOMAIN, depth: 0 }, ctx);
    expect(out.data.dkim).toEqual([]);
    expect(out.data.providers).toEqual([]);
  });

  it('says SPF/MX are unknown (not absent) when the apex lookups fail', async () => {
    const bad = (name: string, type: string) => name === DOMAIN && (type === 'TXT' || type === 'MX');
    const m = mockFetch(
      cloudflare(MIXED, { fail: (name, type) => (bad(name, type) ? json({ error: 'x' }, 500) : undefined) }),
      google((name, type) => (bad(name, type) ? json({ error: 'y' }, 500) : undefined)),
    );
    const ctx = makeCtx({ fetch: m.fetch, root: DOMAIN });
    const out = await emailModule.run({ kind: 'domain', value: DOMAIN, depth: 0 }, ctx);
    expect(out.data.unresolved).toEqual(['TXT', 'MX']);
    expect(out.data.spf).toBeNull();
    const facts = emailModule.facts!(out.data, { kind: 'domain', value: DOMAIN, depth: 0 });
    expect(facts).toContainEqual({ label: 'SPF', value: 'Unknown (apex TXT lookup failed)', tone: 'warn' });
    expect(facts).toContainEqual({ label: 'MX', value: 'Unknown (apex MX lookup failed)', tone: 'warn' });
    expect(facts.find((f) => f.value === 'No SPF record at apex')).toBeUndefined();
    // DKIM evidence still works.
    expect(out.summary).toBe('SendGrid (u1234567) · Microsoft 365 · Google Workspace · 2 lookups failed');
  });

  it('counts every failed lookup in the summary (no truncation)', async () => {
    const isSel = (name: string) => name.includes('._domainkey.');
    const m = mockFetch(
      cloudflare(MIXED, { fail: (name) => (isSel(name) ? json({ error: 'x' }, 500) : undefined) }),
      google((name) => (isSel(name) ? json({ error: 'y' }, 500) : undefined)),
    );
    const ctx = makeCtx({ fetch: m.fetch, root: DOMAIN });
    const out = await emailModule.run({ kind: 'domain', value: DOMAIN, depth: 0 }, ctx);
    const n = SELECTOR_COUNT + TXT_SELECTOR_COUNT;
    expect(n).toBeGreaterThan(10);
    expect(out.data.failedLookups).toHaveLength(n);
    expect(out.data.unresolved).toBeUndefined();
    expect(out.summary).toMatch(new RegExp(` · ${n} lookups failed$`));
  });

  it('summarises low confidence with "?", account IDs flagged for the summary, and caps the list', () => {
    const d: EmailData = {
      providers: ['A', 'B', 'C', 'D', 'E'].map((p, i) => ({
        provider: p,
        confidence: i === 3 ? ('low' as const) : ('high' as const),
        score: 5 - i,
        evidence: [],
      })),
      accountIds: [
        { provider: 'A', kind: 'user ID', value: 'u1', summary: true },
        { provider: 'A', kind: 'user ID', value: 'u2', summary: true },
        { provider: 'B', kind: 'initial domain', value: 'b.onmicrosoft.com', pivot: 'domain' },
      ],
      spf: null,
      spfIncludes: [],
      mx: [],
      dkim: [],
      queriedSelectors: 0,
    };
    expect(summaryOf(d)).toBe('A (u1, u2) · B · C · D? · +1 more');
    expect(summaryOf({ ...d, failedLookups: ['TXT example.com: HTTP 500'] })).toBe('A (u1, u2) · B · C · D? · +1 more · 1 lookup failed');
    expect(summaryOf({ ...d, providers: [], failedLookups: ['a', 'b'] })).toBe('No known sending providers · 2 lookups failed');
    expect(emailModule.headline!(d, { kind: 'domain', value: DOMAIN, depth: 0 }).emailProviders).toEqual(['A', 'B', 'C', 'D', 'E']);
  });

  it('caps the summary from a real run with many SPF providers', async () => {
    const zone: Zone = {
      [DOMAIN]: [
        {
          type: 'TXT',
          data: '"v=spf1 include:_spf.google.com include:mailgun.org include:spf.mtasv.net include:spf.mailjet.com include:mail.zendesk.com ~all"',
        },
      ],
    };
    const ctx = makeCtx({ fetch: mockFetch(cloudflare(zone)).fetch, root: DOMAIN });
    const out = await emailModule.run({ kind: 'domain', value: DOMAIN, depth: 0 }, ctx);
    expect(out.summary).toMatch(/^(?:[^·]+ · ){4}\+1 more$/);
    expect(out.data.providers).toHaveLength(5);
  });
});
