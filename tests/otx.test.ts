import { describe, expect, it } from 'vitest';
import { FetchError, createHttp } from '@/lib/http';
import { investigate, type OrchestratorDeps } from '@/lib/orchestrator';
import { RateLimiter } from '@/lib/ratelimit';
import { DEFAULT_SETTINGS } from '@/lib/settings';
import type { CardState, Ctx, Entity, Fact, Module, RunEvent } from '@/lib/types';
import { HOUR, SkipError } from '@/lib/types';
import {
  MAX_PDNS,
  MAX_PULSES,
  MAX_TAGS,
  inheritedFrom,
  otxKeyTest,
  otxModule,
  parsePulse,
  toIso,
  type OtxData,
} from '@/modules/otx';
import { json, makeCtx, memoryCache, mockFetch, text, type Route } from './helpers';

const KEY = '3f1c9e2a7b5d4c8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6';
const NOW = Date.parse('2026-11-25T12:00:00Z');
const API = 'https://otx.alienvault.com/api/v1';
const domain = (value: string): Entity => ({ kind: 'domain', value, depth: 0 });
const ip = (value: string): Entity => ({ kind: 'ip', value, depth: 1 });

// ---------------------------------------------------------------------------
// Fixtures shaped like the live API (docs/research/threat-intel.md §9, 2026-11-25)

let seq = 0;
function pulse(name: string, created: string, modified: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  seq++;
  return {
    id: `6b065c6748f2081b447f${String(6680 + seq).padStart(4, '0')}`,
    name,
    description: 'x'.repeat(5000),
    modified,
    created,
    tags: ['phishing'],
    references: ['https://example.org/report', 'y'.repeat(2000)],
    public: 1,
    adversary: '',
    targeted_countries: [],
    malware_families: [],
    attack_ids: [{ id: 'T1566', name: 'Phishing', display_name: 'T1566 - Phishing' }],
    industries: [],
    TLP: 'white',
    cloned_from: null,
    export_count: 0,
    upvotes_count: 0,
    downvotes_count: 0,
    votes_count: 0,
    locked: false,
    pulse_source: 'web',
    validator_count: 0,
    comment_count: 0,
    follower_count: 0,
    vote: 0,
    author: { username: 'AlienVault', id: '2', avatar_url: 'https://otx.alienvault.com/x.png', is_subscribed: false, is_following: false },
    indicator_type_counts: { domain: 12, URL: 30 },
    indicator_count: 42,
    is_author: false,
    is_subscribing: null,
    subscriber_count: 1234,
    modified_text: '7 hours ago ',
    is_modified: true,
    groups: [],
    in_group: false,
    threat_hunter_scannable: true,
    threat_hunter_has_agents: 1,
    related_indicator_type: 'domain',
    related_indicator_is_active: 1,
    ...extra,
  };
}

const RELATED = {
  alienvault: { adversary: [], malware_families: [], industries: [] },
  other: { adversary: [], malware_families: [], industries: [] },
};

function domainGeneral(d: string, pulses: unknown[], validation: unknown[] = [], count = pulses.length): Record<string, unknown> {
  return {
    sections: ['general', 'geo', 'url_list', 'passive_dns', 'malware', 'whois', 'http_scans'],
    whois: `http://whois.domaintools.com/${d}`,
    alexa: `http://www.alexa.com/siteinfo/${d}`,
    indicator: d,
    type: 'domain',
    type_title: 'Domain',
    validation,
    base_indicator: {},
    pulse_info: { count, pulses, references: [], related: RELATED },
    false_positive: [],
  };
}

const MANY_TAGS = Array.from({ length: 422 }, (_, i) => `tag${i}`);

/** Deliberately not in date order: the module sorts by latest activity. */
const PHISH_PULSES = [
  pulse('Credential phishing kit hosts', '2026-08-01T10:00:00.123000', '2026-08-03T11:00:00.000000', {
    tags: ['phishing', 'Phishing', 'office365', ...MANY_TAGS],
    TLP: 'green',
  }),
  pulse('Emotet epoch 5 C2 and droppers', '2026-09-14T08:30:00.500000', '2026-10-02T09:15:00.000000', {
    malware_families: [
      { id: 'Emotet', display_name: 'Emotet', target: null },
      { id: 'Win.Trojan.Qakbot', display_name: 'Qakbot', target: null },
    ],
    adversary: 'TA542',
    TLP: 'amber',
  }),
  pulse('Suspicious newly registered domains', '2026-05-01T09:09:49.460000', '2026-05-01T09:09:49.460000', {
    malware_families: ['Emotet', 'AgentTesla'],
    author: { username: 'some_user' },
  }),
];

const PHISH = 'secure-login-update.example';
const PHISH_GENERAL = domainGeneral(PHISH, PHISH_PULSES);

function pdnsRecord(address: string, hostname: string, type: string, first: string, last: string): Record<string, unknown> {
  return {
    address,
    first,
    last,
    hostname,
    record_type: type,
    indicator_link: `/indicator/ip/${address}`,
    flag_url: 'assets/images/flags/us.png',
    flag_title: 'United States',
    asset_type: 'IPv4',
    asn: 'AS15133 edgecast',
    suspicious: false,
    whitelisted_message: [],
    whitelisted: false,
  };
}

const PHISH_PDNS = {
  passive_dns: Array.from({ length: 40 }, (_, i) =>
    pdnsRecord(`203.0.113.${i + 1}`, PHISH, 'A', `2026-0${(i % 9) + 1}-01T10:00:00`, `2026-${String((i % 11) + 1).padStart(2, '0')}-15T08:00:00`),
  ),
  count: 25,
};

const EXAMPLE_ALLOW = domainGeneral(
  'example.com',
  Array.from({ length: 50 }, (_, i) =>
    pulse(`Pulse ${i}`, '2026-11-25T03:56:19.131000', `2026-11-${String(25 - (i % 20)).padStart(2, '0')}T04:05:49.670000`, {
      tags: ['TAXII'],
      TLP: 'green',
    }),
  ),
  [
    { source: 'akamai', message: 'Akamai rank: #1608', name: 'Akamai Popular Domain' },
    { source: 'majestic', message: 'Whitelisted domain example.com', name: 'Whitelisted domain' },
    { source: 'whitelist', message: 'Whitelisted domain example.com', name: 'Whitelisted domain' },
  ],
);

const IPV4_GENERAL = {
  whois: 'http://whois.domaintools.com/8.8.8.8',
  reputation: 0,
  indicator: '8.8.8.8',
  type: 'IPv4',
  type_title: 'IPv4',
  base_indicator: { id: 11911, indicator: '8.8.8.8', type: 'IPv4', title: '', description: '', content: '', access_type: 'public', access_reason: '' },
  pulse_info: { count: 0, pulses: [], references: [], related: RELATED },
  false_positive: [{ assessment: 'accepted', assessment_date: '2021-05-19T15:36:44.966000', report_date: '2021-03-16T14:46:19.003000' }],
  validation: [
    { source: 'false_positive', message: 'Known False Positive', name: 'Known False Positive' },
    { source: 'whitelist', message: 'contained in whitelisted prefix', name: 'Whitelisted IP' },
  ],
  asn: 'AS15169 google llc',
  city_data: true,
  city: null,
  region: null,
  continent_code: 'NA',
  country_code3: 'USA',
  country_code2: 'US',
  latitude: 37.751,
  longitude: -97.822,
  accuracy_radius: 1000,
  country_code: 'US',
  country_name: 'United States of America',
  flag_url: '/assets/images/flags/us.png',
  flag_title: 'United States of America',
  sections: ['general', 'geo', 'reputation', 'url_list', 'passive_dns', 'malware', 'nids_list', 'http_scans'],
};

const IPV6_GENERAL = {
  ...IPV4_GENERAL,
  indicator: '2001:4860:4860:0:0:0:0:8888',
  type: 'IPv6',
  type_title: 'IPv6',
  validation: [],
  false_positive: [],
  pulse_info: {
    count: 2,
    pulses: [pulse('Scanner infrastructure', '2026-11-01T00:00:00', '2026-11-20T00:00:00'), pulse('Honeypot hits', '2026-10-01T00:00:00', '2026-10-01T00:00:00')],
    references: [],
    related: RELATED,
  },
};

// ---------------------------------------------------------------------------
// Helpers

const generalRoute =
  (indicatorPath: string, res: () => Response): Route =>
  (u) =>
    u.href === `${API}/indicators/${indicatorPath}/general` ? res() : undefined;
const pdnsRoute =
  (d: string, res: () => Response, type: 'domain' | 'hostname' = 'domain'): Route =>
  (u) =>
    u.href === `${API}/indicators/${type}/${d}/passive_dns` ? res() : undefined;

/** Live shape of /indicators/hostname/{h}/general: like a domain plus OTX's registrable `domain`. */
function hostnameGeneral(h: string, registrable: string, pulses: unknown[], validation: unknown[] = []): Record<string, unknown> {
  return { ...domainGeneral(h, pulses, validation), type: 'hostname', type_title: 'Hostname', domain: registrable };
}

/** OTX copies the parent's validation onto every name under it (live: any *.github.io). */
const inheritedWhitelist = (parent: string) => [
  { source: 'whitelist', message: `Whitelisted domain ${parent}`, name: 'Whitelisted domain' },
  { source: 'majestic', message: `Whitelisted domain ${parent}`, name: 'Whitelisted domain' },
];
const EMPTY_PDNS = { passive_dns: [], count: 0 };

function ctxFor(...routes: Route[]) {
  const m = mockFetch(...routes);
  const ctx = makeCtx({ fetch: m.fetch, keys: { otx: KEY }, now: () => NOW });
  return { m, ctx };
}

function headerOf(init: RequestInit, name: string): string | undefined {
  return (init.headers as Record<string, string> | undefined)?.[name];
}

async function rejection(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (err) {
    return err;
  }
  throw new Error('expected a rejection');
}

function factMap(facts: Fact[]): Map<string, Fact> {
  return new Map(facts.map((f) => [f.label, f]));
}

// ---------------------------------------------------------------------------

describe('otx module: metadata', () => {
  it('declares the contract the orchestrator relies on', () => {
    expect(otxModule.id).toBe('otx');
    expect(otxModule.label).toBe('AlienVault OTX');
    expect(otxModule.version).toBe(1);
    expect(otxModule.key).toBe('otx');
    expect(otxModule.keyOptional).toBeUndefined();
    expect(otxModule.accepts).toEqual(['domain', 'ip']);
    expect(otxModule.ttl).toBe(24 * HOUR);
    expect(otxModule.rateLimit).toEqual({ perMinute: 30 });
  });
});

describe('otx module: domains', () => {
  it('fetches general + passive_dns concurrently with the key only in X-OTX-API-KEY', async () => {
    const { m, ctx } = ctxFor(generalRoute(`domain/${PHISH}`, () => json(PHISH_GENERAL)), pdnsRoute(PHISH, () => json(PHISH_PDNS)));
    const out = await otxModule.run(domain(PHISH), ctx);

    expect(m.calls.map((c) => c.url).sort()).toEqual([`${API}/indicators/domain/${PHISH}/general`, `${API}/indicators/domain/${PHISH}/passive_dns`]);
    for (const c of m.calls) {
      expect(headerOf(c.init, 'X-OTX-API-KEY')).toBe(KEY);
      expect(c.url).not.toContain(KEY);
      expect(c.init.credentials).toBe('omit');
      expect(c.init.method).toBe('GET');
    }
    expect(out.pivots).toBeUndefined();
    expect(JSON.stringify(out)).not.toContain(KEY);
  });

  it('keeps a compact digest: pulses sorted, tags capped, families/adversaries aggregated', async () => {
    const { ctx } = ctxFor(generalRoute(`domain/${PHISH}`, () => json(PHISH_GENERAL)), pdnsRoute(PHISH, () => json(PHISH_PDNS)));
    const out = await otxModule.run(domain(PHISH), ctx);
    const d = out.data;

    expect(d.indicator).toBe(PHISH);
    expect(d.type).toBe('domain');
    expect(d.found).toBe(true);
    expect(d.pulseCount).toBe(3);
    expect(d.latestPulse).toBe('2026-10-02T09:15:00.000Z');
    expect(d.pulses.map((p) => p.name)).toEqual(['Emotet epoch 5 C2 and droppers', 'Credential phishing kit hosts', 'Suspicious newly registered domains']);

    const [emotet, kit, newly] = d.pulses;
    expect(emotet).toMatchObject({
      created: '2026-09-14T08:30:00.500Z',
      modified: '2026-10-02T09:15:00.000Z',
      malwareFamilies: ['Emotet', 'Qakbot'],
      adversary: 'TA542',
      tlp: 'amber',
      author: 'AlienVault',
    });
    expect(emotet!.id).toMatch(/^[0-9a-f]{24}$/);
    expect(kit!.tags).toHaveLength(MAX_TAGS);
    expect(kit!.tags.slice(0, 3)).toEqual(['phishing', 'office365', 'tag0']); // case-insensitive dedupe
    expect(kit!.tagCount).toBe(424);
    expect(kit!.adversary).toBeUndefined();
    expect(newly!.malwareFamilies).toEqual(['Emotet', 'AgentTesla']);
    expect(newly!.author).toBe('some_user');

    expect(d.malwareFamilies).toEqual(['Emotet', 'Qakbot', 'AgentTesla']);
    expect(d.adversaries).toEqual(['TA542']);
    expect(d.validation).toEqual([]);
    expect(d.allowlisted).toBe(false);
    expect(d.country).toBeUndefined();

    // Passive DNS: reported count, capped records, most recently seen first.
    expect(d.passiveDns!.count).toBe(40); // count says 25 but 40 records came back
    expect(d.passiveDns!.records).toHaveLength(MAX_PDNS);
    expect(d.passiveDns!.records[0]).toEqual({
      address: '203.0.113.11',
      hostname: PHISH,
      recordType: 'A',
      first: '2026-02-01T10:00:00.000Z',
      last: '2026-11-15T08:00:00.000Z',
    });
    const lasts = d.passiveDns!.records.map((r) => r.last ?? '');
    expect([...lasts].sort().reverse()).toEqual(lasts);

    // No raw payload: no descriptions/references/attack ids.
    const s = JSON.stringify(d);
    expect(s).not.toContain('xxxxxxxxxx');
    expect(s).not.toContain('example.org/report');
    expect(s).not.toContain('T1566');
    expect(s.length).toBeLessThan(8000);
    expect(JSON.parse(s)).toEqual(d);
  });

  it('scores 1-4 pulses as low and phrases the summary carefully', async () => {
    const { ctx } = ctxFor(generalRoute(`domain/${PHISH}`, () => json(PHISH_GENERAL)), pdnsRoute(PHISH, () => json(PHISH_PDNS)));
    const out = await otxModule.run(domain(PHISH), ctx);
    expect(out.severity).toBe('low');
    expect(out.summary).toBe('In 3 OTX pulses (latest 2026-10-02) · malware: Emotet, Qakbot, AgentTesla · 40 passive DNS records');
    expect(out.data.assessment).toMatch(/3 community OTX pulses.*weak signal/);
  });

  it('scores a single pulse as low with singular wording', async () => {
    const g = domainGeneral(PHISH, [pulse('One report', '2026-11-01T00:00:00', '2026-11-02T00:00:00')]);
    const { ctx } = ctxFor(generalRoute(`domain/${PHISH}`, () => json(g)), pdnsRoute(PHISH, () => json({ passive_dns: [], count: 0 })));
    const out = await otxModule.run(domain(PHISH), ctx);
    expect(out.severity).toBe('low');
    expect(out.summary).toBe('In 1 OTX pulse (latest 2026-11-02) · 0 passive DNS records');
  });

  it('scores >= 5 recent pulses as medium', async () => {
    const pulses = Array.from({ length: 7 }, (_, i) => pulse(`Report ${i}`, '2026-06-01T00:00:00', `2026-11-${String(10 + i)}T00:00:00`));
    const g = domainGeneral(PHISH, pulses);
    const { ctx } = ctxFor(generalRoute(`domain/${PHISH}`, () => json(g)), pdnsRoute(PHISH, () => json({ passive_dns: [], count: 0 })));
    const out = await otxModule.run(domain(PHISH), ctx);
    expect(out.severity).toBe('medium');
    expect(out.summary).toBe('In 7 OTX pulses (latest 2026-11-16) · 0 passive DNS records');
    expect(out.data.assessment).toMatch(/user-contributed/);
  });

  it('uses pulse_info.count when the payload lists fewer pulses, and caps kept pulses', async () => {
    const pulses = Array.from({ length: 14 }, (_, i) => pulse(`Report ${i}`, '2026-06-01T00:00:00', `2026-10-${String(10 + i)}T00:00:00`));
    const g = domainGeneral(PHISH, pulses, [], 120);
    const { ctx } = ctxFor(generalRoute(`domain/${PHISH}`, () => json(g)), pdnsRoute(PHISH, () => json({ passive_dns: [], count: 0 })));
    const out = await otxModule.run(domain(PHISH), ctx);
    expect(out.data.pulseCount).toBe(120);
    expect(out.data.pulses).toHaveLength(MAX_PULSES);
    expect(out.data.pulses[0]!.name).toBe('Report 13');
    expect(out.severity).toBe('medium');
  });

  it('demotes >= 5 pulses that are all older than a year to low (old signal)', async () => {
    const pulses = Array.from({ length: 6 }, (_, i) => pulse(`Old report ${i}`, '2022-01-01T00:00:00', `2023-05-0${i + 1}T00:00:00`));
    const g = domainGeneral(PHISH, pulses);
    const { ctx } = ctxFor(generalRoute(`domain/${PHISH}`, () => json(g)), pdnsRoute(PHISH, () => json({ passive_dns: [], count: 0 })));
    const out = await otxModule.run(domain(PHISH), ctx);
    expect(out.severity).toBe('low');
    expect(out.summary).toBe('In 6 OTX pulses (latest 2023-05-06, over a year ago) · 0 passive DNS records');
    expect(out.data.assessment).toMatch(/old signal/);
    // The assessment fact follows the (demoted) severity, not the raw pulse count.
    const f = factMap(otxModule.facts!(out.data, domain(PHISH)));
    expect(f.get('Assessment')!.tone).toBe('warn');
  });

  it('treats an allow-listed domain as none even with many pulses, and says so', async () => {
    const { ctx } = ctxFor(
      generalRoute('domain/example.com', () => json(EXAMPLE_ALLOW)),
      pdnsRoute('example.com', () => json({ passive_dns: [pdnsRecord('93.184.215.14', 'example.com', 'A', '2024-01-02T10:00:00', '2026-11-20T08:00:00')], count: 1 })),
    );
    const out = await otxModule.run(domain('example.com'), ctx);
    expect(out.severity).toBe('none');
    expect(out.data.allowlisted).toBe(true);
    expect(out.data.pulseCount).toBe(50);
    expect(out.summary).toBe('Allow-listed by OTX · in 50 pulses (latest 2026-11-25), not scored · 1 passive DNS record');
    expect(out.data.assessment).toMatch(/^Allow-listed by OTX; its 50 pulses are not scored/);

    const f = factMap(otxModule.facts!(out.data, domain('example.com')));
    expect(f.get('Allow-listed')).toEqual({ label: 'Allow-listed', value: ['Whitelisted domain: Whitelisted domain example.com', 'Whitelisted domain: Whitelisted domain example.com'], tone: 'good' });
    expect(f.get('Validation')!.value).toEqual(['Akamai Popular Domain: Akamai rank: #1608']);
    expect(f.get('Assessment')!.tone).toBe('good');
  });

  it('does not treat popularity-only validation as an allow-list', async () => {
    const g = domainGeneral(PHISH, PHISH_PULSES, [{ source: 'akamai', message: 'Akamai rank: #90000', name: 'Akamai Popular Domain' }]);
    const { ctx } = ctxFor(generalRoute(`domain/${PHISH}`, () => json(g)), pdnsRoute(PHISH, () => json({ passive_dns: [], count: 0 })));
    const out = await otxModule.run(domain(PHISH), ctx);
    expect(out.data.allowlisted).toBe(false);
    expect(out.severity).toBe('low');
  });

  it('reports a clean domain with no pulses as none (live shape for an unknown domain)', async () => {
    const { ctx } = ctxFor(
      generalRoute('domain/nonexistent-zz9-test.com', () => json(domainGeneral('nonexistent-zz9-test.com', []))),
      pdnsRoute('nonexistent-zz9-test.com', () => json({ passive_dns: [], count: 0 })),
    );
    const out = await otxModule.run(domain('nonexistent-zz9-test.com'), ctx);
    expect(out.severity).toBe('none');
    expect(out.summary).toBe('No OTX pulses · 0 passive DNS records');
    expect(out.data.latestPulse).toBeNull();
    expect(out.data.assessment).toBe('Not listed in any OTX pulse.');
  });

  it('looks up subdomains on the hostname endpoints (live: /domain/ has 0 pulses for them), normalising the name', async () => {
    const pulses = Array.from({ length: 6 }, (_, i) => pulse(`TAXII ${i}`, '2026-11-01T00:00:00', `2026-11-2${i}T00:00:00`, { tags: ['TAXII'] }));
    const validation = [{ source: 'akamai', message: 'Akamai rank: #1608', name: 'Akamai Popular Domain' }, ...inheritedWhitelist('example.com')];
    const pd = {
      passive_dns: [pdnsRecord('WWW.Example.com.CDN.Cloudflare.net.', 'www.example.com', 'CNAME', '2025-12-09T01:37:59', '2025-12-17T20:29:36')],
      count: 146,
    };
    const { m, ctx } = ctxFor(
      generalRoute('hostname/www.example.com', () => json(hostnameGeneral('www.example.com', 'example.com', pulses, validation))),
      pdnsRoute('www.example.com', () => json(pd), 'hostname'),
    );
    const out = await otxModule.run(domain('WWW.Example.com.'), ctx);

    expect(m.calls.map((c) => c.url).sort()).toEqual([`${API}/indicators/hostname/www.example.com/general`, `${API}/indicators/hostname/www.example.com/passive_dns`]);
    for (const c of m.calls) expect(headerOf(c.init, 'X-OTX-API-KEY')).toBe(KEY);
    expect(out.data).toMatchObject({ indicator: 'www.example.com', type: 'hostname', pulseCount: 6, allowlisted: false, allowlistedParent: 'example.com' });
    expect(out.data.passiveDns).toEqual({
      count: 146,
      records: [{ address: 'www.example.com.cdn.cloudflare.net', hostname: 'www.example.com', recordType: 'CNAME', first: '2025-12-09T01:37:59.000Z', last: '2025-12-17T20:29:36.000Z' }],
    });
    // The parent's allow-list does not vouch for the hostname, but it keeps the score at low.
    expect(out.severity).toBe('low');
    expect(out.data.severity).toBe('low');
    expect(out.summary).toBe('In 6 OTX pulses (latest 2026-11-25) · parent example.com allow-listed · 146 passive DNS records');
    expect(out.data.assessment).toMatch(/weak signal.*allow-lists the parent domain example\.com; that does not vouch for this hostname/);

    const f = factMap(otxModule.facts!(out.data, domain('www.example.com')));
    expect(f.has('Allow-listed')).toBe(false);
    expect(f.get('Parent domain allow-listed')).toEqual({
      label: 'Parent domain allow-listed',
      value: ['Whitelisted domain: Whitelisted domain example.com', 'Whitelisted domain: Whitelisted domain example.com'],
    });
    expect(f.get('Validation')!.value).toEqual(['Akamai Popular Domain: Akamai rank: #1608']);
    expect(f.get('Assessment')!.tone).toBe('warn');
    expect(f.get('Open in OTX')!.href).toBe('https://otx.alienvault.com/indicator/hostname/www.example.com');
    expect((f.get('Passive DNS sample · 1 most recent')!.value as string[])[0]).toBe('www.example.com.cdn.cloudflare.net [CNAME] (2025-12-09 → 2025-12-17)');
  });

  it('does not let an inherited allow-list hide a listed hostname on a shared platform', async () => {
    const h = 'paypal-verify-account.github.io';
    const listed = hostnameGeneral(h, 'github.io', [pulse('PayPal credential phishing', '2026-11-20T00:00:00', '2026-11-21T00:00:00')], inheritedWhitelist('github.io'));
    const a = ctxFor(generalRoute(`hostname/${h}`, () => json(listed)), pdnsRoute(h, () => json(EMPTY_PDNS), 'hostname'));
    const out = await otxModule.run(domain(h), a.ctx);
    expect(out.data.allowlisted).toBe(false);
    expect(out.data.allowlistedParent).toBe('github.io');
    expect(out.severity).toBe('low');
    expect(out.summary).toBe('In 1 OTX pulse (latest 2026-11-21) · parent github.io allow-listed · 0 passive DNS records');

    // Not listed: none, and the summary still says only the parent is allow-listed.
    const clean = hostnameGeneral(h, 'github.io', [], inheritedWhitelist('github.io'));
    const b = ctxFor(generalRoute(`hostname/${h}`, () => json(clean)), pdnsRoute(h, () => json(EMPTY_PDNS), 'hostname'));
    const outB = await otxModule.run(domain(h), b.ctx);
    expect(outB.severity).toBe('none');
    expect(outB.summary).toBe('No OTX pulses · parent github.io allow-listed · 0 passive DNS records');
    expect(outB.data.assessment).toBe('Not listed in any OTX pulse. OTX allow-lists the parent domain github.io; that does not vouch for this hostname.');
  });

  it('redoes the lookup on the domain endpoints when OTX says a 3-label name is registrable (bbc.co.uk)', async () => {
    const own = [{ source: 'whitelist', message: 'Whitelisted domain bbc.co.uk', name: 'Whitelisted domain' }];
    const pulses = [pulse('News site in TAXII feed', '2026-10-01T00:00:00', '2026-10-05T00:00:00'), pulse('Another', '2026-09-01T00:00:00', '2026-09-01T00:00:00')];
    const { m, ctx } = ctxFor(
      generalRoute('hostname/bbc.co.uk', () => json(hostnameGeneral('bbc.co.uk', 'bbc.co.uk', [], own))),
      pdnsRoute('bbc.co.uk', () => json({ passive_dns: [], count: 99 }), 'hostname'),
      generalRoute('domain/bbc.co.uk', () => json(domainGeneral('bbc.co.uk', pulses, own))),
      pdnsRoute('bbc.co.uk', () => json({ passive_dns: [], count: 7 })),
    );
    const out = await otxModule.run(domain('bbc.co.uk'), ctx);
    expect(m.calls.map((c) => c.url).filter((u) => u.includes('/domain/'))).toEqual(
      expect.arrayContaining([`${API}/indicators/domain/bbc.co.uk/general`, `${API}/indicators/domain/bbc.co.uk/passive_dns`]),
    );
    expect(out.data.type).toBe('domain');
    expect(out.data.pulseCount).toBe(2);
    expect(out.data.passiveDns!.count).toBe(7); // the domain's passive DNS, not the discarded hostname one
    // The entry names the indicator itself: a real allow-list entry.
    expect(out.data.allowlisted).toBe(true);
    expect(out.data.allowlistedParent).toBeUndefined();
    expect(out.severity).toBe('none');
    expect(out.summary).toBe('Allow-listed by OTX · in 2 pulses (latest 2026-10-05), not scored · 7 passive DNS records');
    const f = factMap(otxModule.facts!(out.data, domain('bbc.co.uk')));
    expect(f.get('Open in OTX')!.href).toBe('https://otx.alienvault.com/indicator/domain/bbc.co.uk');
  });

  it('keeps 2-label names on the domain endpoint without a hostname request', async () => {
    const { m, ctx } = ctxFor(generalRoute('domain/example.org', () => json(domainGeneral('example.org', []))), pdnsRoute('example.org', () => json(EMPTY_PDNS)));
    await otxModule.run(domain('Example.ORG.'), ctx);
    expect(m.calls.map((c) => c.url).sort()).toEqual([`${API}/indicators/domain/example.org/general`, `${API}/indicators/domain/example.org/passive_dns`]);
  });

  it('maps a 404 to found:false with severity none instead of an error', async () => {
    const { ctx } = ctxFor(
      generalRoute(`domain/${PHISH}`, () => json({ detail: 'Not found.' }, 404)),
      pdnsRoute(PHISH, () => json({ detail: 'Not found.' }, 404)),
    );
    const out = await otxModule.run(domain(PHISH), ctx);
    expect(out.data.found).toBe(false);
    expect(out.data.pulseCount).toBe(0);
    expect(out.data.passiveDns).toEqual({ count: 0, records: [] });
    expect(out.severity).toBe('none');
    expect(out.summary).toBe('Not in OTX · 0 passive DNS records');
    const f = factMap(otxModule.facts!(out.data, domain(PHISH)));
    expect(f.get('Assessment')!.value).toBe('OTX has no record of this indicator.');
    expect(f.has('Pulses')).toBe(false);
  });

  it('survives a passive DNS failure (500) and notes it', async () => {
    const { ctx } = ctxFor(
      generalRoute(`domain/${PHISH}`, () => json(PHISH_GENERAL)),
      pdnsRoute(PHISH, () => json({ detail: 'Internal error' }, 500)),
    );
    const out = await otxModule.run(domain(PHISH), ctx);
    expect(out.data.pulseCount).toBe(3);
    expect(out.data.passiveDns!.error).toMatch(/OTX passive DNS lookup failed \(HTTP 500: Internal error\)/);
    expect(out.summary).toMatch(/· passive DNS unavailable$/);
    const f = factMap(otxModule.facts!(out.data, domain(PHISH)));
    expect(f.get('Passive DNS')).toMatchObject({ tone: 'warn' });
    expect(String(f.get('Passive DNS')!.value)).toMatch(/^Unavailable: /);
  });

  it('survives a passive DNS rate limit and a malformed passive DNS payload', async () => {
    const a = ctxFor(
      generalRoute(`domain/${PHISH}`, () => json(PHISH_GENERAL)),
      pdnsRoute(PHISH, () => json({ detail: 'Anonymous access to this endpoint is limited. Please authenticate.' }, 429)),
    );
    const outA = await otxModule.run(domain(PHISH), a.ctx);
    expect(outA.data.passiveDns!.error).toMatch(/rate limit or quota/);
    expect(outA.data.passiveDns!.error).not.toContain(KEY);

    const b = ctxFor(generalRoute(`domain/${PHISH}`, () => json(PHISH_GENERAL)), pdnsRoute(PHISH, () => json({ passive_dns: 'nope' })));
    const outB = await otxModule.run(domain(PHISH), b.ctx);
    expect(outB.data.passiveDns).toEqual({ count: 0, records: [], error: 'Unexpected passive DNS response from OTX' });
    expect(outB.severity).toBe('low');
  });

  it('skips junk passive DNS records', async () => {
    const pd = { passive_dns: [null, 5, { foo: 1 }, { address: '93.184.215.14', hostname: 'EXAMPLE.com.', record_type: 'a', first: 'junk', last: null }], count: 'x' };
    const { ctx } = ctxFor(generalRoute(`domain/${PHISH}`, () => json(PHISH_GENERAL)), pdnsRoute(PHISH, () => json(pd)));
    const out = await otxModule.run(domain(PHISH), ctx);
    expect(out.data.passiveDns).toEqual({
      count: 4,
      records: [{ address: '93.184.215.14', hostname: 'example.com', recordType: 'A', first: null, last: null }],
    });
  });
});

describe('otx module: IPs', () => {
  it('looks up IPv4 on /IPv4/ only (no passive DNS), with country/ASN and allow-list', async () => {
    const { m, ctx } = ctxFor(generalRoute('IPv4/8.8.8.8', () => json(IPV4_GENERAL)));
    const out = await otxModule.run(ip('8.8.8.8'), ctx);
    expect(m.calls.map((c) => c.url)).toEqual([`${API}/indicators/IPv4/8.8.8.8/general`]);
    expect(headerOf(m.calls[0]!.init, 'X-OTX-API-KEY')).toBe(KEY);
    expect(out.data).toMatchObject({
      indicator: '8.8.8.8',
      type: 'IPv4',
      found: true,
      pulseCount: 0,
      allowlisted: true,
      country: 'United States of America (US)',
      asn: 'AS15169 google llc',
    });
    expect(out.data.passiveDns).toBeUndefined();
    expect(out.severity).toBe('none');
    expect(out.summary).toBe('Allow-listed by OTX');
    expect(out.data.assessment).not.toMatch(/pulses are not scored/);

    const f = factMap(otxModule.facts!(out.data, ip('8.8.8.8')));
    expect(f.get('Allow-listed')!.value).toEqual(['Known False Positive', 'Whitelisted IP: contained in whitelisted prefix']);
    expect(f.get('Country')!.value).toBe('United States of America (US)');
    expect(f.get('ASN')!.value).toBe('AS15169 google llc');
    expect(f.get('Open in OTX')!.href).toBe('https://otx.alienvault.com/indicator/ip/8.8.8.8');
  });

  it('looks up IPv6 on /IPv6/ with the canonical, URL-encoded address', async () => {
    const enc = encodeURIComponent('2001:4860:4860::8888');
    const { m, ctx } = ctxFor(generalRoute(`IPv6/${enc}`, () => json(IPV6_GENERAL)));
    const out = await otxModule.run(ip('2001:4860:4860:0:0:0:0:8888'), ctx);
    expect(m.calls.map((c) => c.url)).toEqual([`${API}/indicators/IPv6/2001%3A4860%3A4860%3A%3A8888/general`]);
    expect(out.data.type).toBe('IPv6');
    expect(out.data.indicator).toBe('2001:4860:4860::8888');
    expect(out.data.pulseCount).toBe(2);
    expect(out.severity).toBe('low');
    expect(out.summary).toBe('In 2 OTX pulses (latest 2026-11-20)');
    const f = factMap(otxModule.facts!(out.data, ip('2001:4860:4860::8888')));
    expect(f.get('Open in OTX')!.href).toBe('https://otx.alienvault.com/indicator/ip/2001%3A4860%3A4860%3A%3A8888');
  });

  it('skips values that are not IPs', async () => {
    const { m, ctx } = ctxFor();
    await expect(otxModule.run(ip('not-an-ip'), ctx)).rejects.toBeInstanceOf(SkipError);
    expect(m.calls).toHaveLength(0);
  });
});

describe('otx module: errors', () => {
  it('maps 403 to an invalid-key message without leaking the key', async () => {
    const { ctx } = ctxFor(
      generalRoute(`domain/${PHISH}`, () => json({ detail: 'Authentication required' }, 403)),
      pdnsRoute(PHISH, () => json({ detail: 'Authentication required' }, 403)),
    );
    const err = await rejection(otxModule.run(domain(PHISH), ctx));
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).status).toBe(403);
    expect((err as FetchError).message).toBe('OTX rejected the API key (HTTP 403: Authentication required). Check the OTX key in settings.');
    expect((err as FetchError).message).not.toContain(KEY);
    expect((err as FetchError).url).not.toContain(KEY);
  });

  it('maps 401 the same way', async () => {
    const { ctx } = ctxFor(generalRoute('IPv4/1.2.3.4', () => json({ detail: 'Invalid token.' }, 401)));
    await expect(otxModule.run(ip('1.2.3.4'), ctx)).rejects.toThrow(/OTX rejected the API key \(HTTP 401: Invalid token\.\)/);
  });

  it('maps a 429 that persists after the automatic retry to a quota message', async () => {
    const m = mockFetch((u) => (u.pathname.endsWith('/general') ? json({ detail: 'Too many requests' }, 429, { 'retry-after': '0' }) : undefined));
    const base = makeCtx({ fetch: m.fetch, keys: { otx: KEY }, now: () => NOW });
    // As the orchestrator wires it: the module's rate limit enables the single 429 retry.
    const http = createHttp({ fetch: m.fetch, limiter: new RateLimiter(), signal: base.signal, defaultLimit: { key: 'otx', perMinute: 6000 } });
    const ctx: Ctx = { ...base, ...http };
    const err = await rejection(otxModule.run(ip('1.2.3.4'), ctx));
    expect(m.calls).toHaveLength(2);
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).status).toBe(429);
    expect((err as FetchError).message).toMatch(/^OTX rate limit or quota reached \(HTTP 429: Too many requests\) after waiting and retrying once/);
  });

  it('skips when OTX rejects the indicator as invalid (400)', async () => {
    const { ctx } = ctxFor(
      generalRoute('domain/foo.invalid', () => json({ detail: 'Invalid domain' }, 400)),
      pdnsRoute('foo.invalid', () => json({ detail: 'Invalid domain' }, 400)),
    );
    const err = await rejection(otxModule.run(domain('foo.invalid'), ctx));
    expect(err).toBeInstanceOf(SkipError);
    expect((err as Error).message).toBe('OTX does not accept "foo.invalid" as a valid domain indicator.');
  });

  it('labels other HTTP errors as OTX lookup failures', async () => {
    const { ctx } = ctxFor(generalRoute('IPv4/1.2.3.4', () => text('<html>Bad gateway</html>', 502)));
    await expect(otxModule.run(ip('1.2.3.4'), ctx)).rejects.toThrow('OTX lookup failed (HTTP 502).');
  });

  it('rejects a non-object general payload and invalid JSON', async () => {
    const a = ctxFor(generalRoute('IPv4/1.2.3.4', () => json([])));
    const errA = await rejection(otxModule.run(ip('1.2.3.4'), a.ctx));
    expect(errA).toBeInstanceOf(FetchError);
    expect((errA as FetchError).kind).toBe('parse');

    const b = ctxFor(generalRoute('IPv4/1.2.3.4', () => text('{"pulse_info": ', 200, 'application/json')));
    const errB = await rejection(otxModule.run(ip('1.2.3.4'), b.ctx));
    expect((errB as FetchError).kind).toBe('parse');
  });

  it('parses a malformed-but-object payload defensively', async () => {
    const junk = {
      pulse_info: { count: 'many', pulses: [null, 7, 'x', { name: 42, tags: 'nope', malware_families: [{}, null, 3, { display_name: ' Lumma\n Stealer ' }], TLP: 'GREEN!!', created: 'yesterday' }] },
      validation: 'none',
      asn: 123,
      country_code: 'usa-ish',
    };
    const { ctx } = ctxFor(generalRoute('IPv4/1.2.3.4', () => json(junk)));
    const out = await otxModule.run(ip('1.2.3.4'), ctx);
    expect(out.data.pulseCount).toBe(1);
    expect(out.data.pulses).toEqual([{ name: '(untitled pulse)', created: null, modified: null, tags: [], malwareFamilies: ['Lumma Stealer'] }]);
    expect(out.data.latestPulse).toBeNull();
    expect(out.data.validation).toEqual([]);
    expect(out.data.asn).toBeUndefined();
    expect(out.data.country).toBeUndefined();
    expect(out.severity).toBe('low');
    expect(out.summary).toBe('In 1 OTX pulse · malware: Lumma Stealer');

    const empty = ctxFor(generalRoute('IPv4/1.2.3.4', () => json({})));
    const outE = await otxModule.run(ip('1.2.3.4'), empty.ctx);
    expect(outE.data.pulseCount).toBe(0);
    expect(outE.severity).toBe('none');
  });

  it('skips defensively when the key is missing, and rejects keys with invalid characters', async () => {
    const m = mockFetch();
    const noKey = makeCtx({ fetch: m.fetch });
    await expect(otxModule.run(domain(PHISH), noKey)).rejects.toBeInstanceOf(SkipError);
    const badKey = makeCtx({ fetch: m.fetch, keys: { otx: 'abc defé' } });
    await expect(otxModule.run(domain(PHISH), badKey)).rejects.toThrow(/invalid characters/);
    expect(m.calls).toHaveLength(0);
  });

  it('propagates cancellation even though passive DNS errors are otherwise swallowed', async () => {
    const ac = new AbortController();
    const m = mockFetch(
      (u, init) =>
        new Promise<Response>((_, reject) => {
          void u;
          init.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
        }),
    );
    const ctx = makeCtx({ fetch: m.fetch, keys: { otx: KEY }, signal: ac.signal });
    const p = otxModule.run(domain(PHISH), ctx);
    ac.abort();
    const err = await rejection(p);
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).kind).toBe('aborted');
  });
});

describe('otx module: facts', () => {
  it('lists pulses with dates, tags, links, the passive DNS sample and the GUI link', async () => {
    const { ctx } = ctxFor(generalRoute(`domain/${PHISH}`, () => json(PHISH_GENERAL)), pdnsRoute(PHISH, () => json(PHISH_PDNS)));
    const out = await otxModule.run(domain(PHISH), ctx);
    const facts = otxModule.facts!(out.data, domain(PHISH));

    for (const f of facts) {
      if (f.href) expect(f.href).toMatch(/^https:\/\/otx\.alienvault\.com\//);
      const vals = Array.isArray(f.value) ? f.value : [f.value];
      for (const v of vals) expect(typeof v).toBe('string');
    }
    const f = factMap(facts);
    expect(f.get('Assessment')).toMatchObject({ tone: 'warn' });
    expect(f.get('Pulses')!.value).toBe('3 (latest 2026-10-02)');
    expect(f.get('Malware families')).toEqual({ label: 'Malware families', value: ['Emotet', 'Qakbot', 'AgentTesla'], tone: 'warn' });
    expect(f.get('Adversaries')!.value).toEqual(['TA542']);

    const pulses = facts.filter((x) => x.label.startsWith('Pulse ·'));
    expect(pulses.map((p) => p.label)).toEqual(['Pulse · 2026-10-02', 'Pulse · 2026-08-03', 'Pulse · 2026-05-01']);
    expect(pulses[0]!.value).toBe(
      'Emotet epoch 5 C2 and droppers · created 2026-09-14, modified 2026-10-02 · tags: phishing · malware: Emotet, Qakbot · adversary: TA542 · TLP:AMBER · by AlienVault',
    );
    expect(pulses[0]!.href).toBe(`https://otx.alienvault.com/pulse/${out.data.pulses[0]!.id}`);
    expect(pulses[1]!.value).toContain('tags: phishing, office365, tag0, tag1, tag2, tag3, tag4, tag5 (+416)');
    expect(pulses[2]!.value).toContain('created 2026-05-01 ·');

    expect(f.get('Passive DNS')!.value).toBe('40 records (30 kept)');
    const sample = f.get('Passive DNS sample · 15 most recent')!;
    expect(sample.pivot).toBe(true);
    expect((sample.value as string[])[0]).toBe('203.0.113.11 [A] (2026-02-01 → 2026-11-15)');
    expect(f.get('Open in OTX')).toEqual({
      label: 'Open in OTX',
      value: `https://otx.alienvault.com/indicator/domain/${PHISH}`,
      href: `https://otx.alienvault.com/indicator/domain/${PHISH}`,
    });
  });

  it('marks >= 5 pulses as bad in the assessment fact', async () => {
    const pulses = Array.from({ length: 5 }, (_, i) => pulse(`R${i}`, '2026-11-01T00:00:00', '2026-11-01T00:00:00'));
    const { ctx } = ctxFor(generalRoute(`domain/${PHISH}`, () => json(domainGeneral(PHISH, pulses))), pdnsRoute(PHISH, () => json({ passive_dns: [], count: 0 })));
    const out = await otxModule.run(domain(PHISH), ctx);
    const f = factMap(otxModule.facts!(out.data, domain(PHISH)));
    expect(f.get('Assessment')!.tone).toBe('bad');
    expect(f.has('Passive DNS sample · 0 most recent')).toBe(false);
  });
});

describe('otx helpers', () => {
  it('toIso handles OTX naive-UTC timestamps and rejects junk', () => {
    expect(toIso('2026-11-12T22:01:16.793000')).toBe('2026-11-12T22:01:16.793Z');
    expect(toIso('2026-11-12T22:01:16')).toBe('2026-11-12T22:01:16.000Z');
    expect(toIso('2026-11-12 22:01:16')).toBe('2026-11-12T22:01:16.000Z');
    expect(toIso('2026-11-12T22:01:16+02:00')).toBe('2026-11-12T20:01:16.000Z');
    expect(toIso('2026-11-12')).toBe('2026-11-12T00:00:00.000Z');
    expect(toIso('yesterday')).toBeNull();
    expect(toIso(1_700_000_000)).toBeNull();
    expect(toIso(undefined)).toBeNull();
  });

  it('inheritedFrom only flags entries that name a parent of a domain/hostname indicator', () => {
    const wl = (msg: string) => ({ source: 'whitelist', name: 'Whitelisted domain', message: msg });
    expect(inheritedFrom(wl('Whitelisted domain github.io'), { indicator: 'x.y.github.io', type: 'hostname' })).toBe('github.io');
    expect(inheritedFrom(wl('Whitelisted domain github.io'), { indicator: 'github.io', type: 'domain' })).toBeUndefined();
    expect(inheritedFrom(wl('Whitelisted domain www.example.com'), { indicator: 'www.example.com', type: 'hostname' })).toBeUndefined();
    // "notgithub.io" is not a parent of x.github.io.
    expect(inheritedFrom(wl('Whitelisted domain notgithub.io'), { indicator: 'x.github.io', type: 'hostname' })).toBeUndefined();
    expect(inheritedFrom({ source: 'false_positive', name: 'Known False Positive', message: 'Known False Positive' }, { indicator: 'x.github.io', type: 'hostname' })).toBeUndefined();
    // IPs never inherit: "18.8.8.8" ends with ".8.8.8" but that is not a parent.
    expect(inheritedFrom({ source: 'whitelist', name: 'Whitelisted IP', message: 'contained in whitelisted prefix 8.8.8' }, { indicator: '18.8.8.8', type: 'IPv4' })).toBeUndefined();
  });

  it('parsePulse drops invalid ids and odd TLP values', () => {
    expect(parsePulse({ id: '../../etc', name: 'n', TLP: 'red<script>' })).toEqual({ name: 'n', created: null, modified: null, tags: [] });
    expect(parsePulse(null)).toBeNull();
  });
});

describe('otx key tester', () => {
  const http = (f: typeof fetch) => createHttp({ fetch: f, limiter: new RateLimiter(), signal: new AbortController().signal });

  it('calls /api/v1/user/me with the key header and shows the username', async () => {
    const m = mockFetch((u) => (u.href === `${API}/user/me` ? json({ username: 'analyst42', user_id: 123456, pulse_count: 3, member_since: '2020-01-01' }) : undefined));
    await expect(otxKeyTest(` ${KEY} `, http(m.fetch))).resolves.toBe('Key accepted (signed in as analyst42).');
    expect(m.calls).toHaveLength(1);
    expect(headerOf(m.calls[0]!.init, 'X-OTX-API-KEY')).toBe(KEY);
    expect(m.calls[0]!.url).not.toContain(KEY);
  });

  it('accepts a response without a username', async () => {
    const m = mockFetch(() => json({ user_id: 1 }));
    await expect(otxKeyTest(KEY, http(m.fetch))).resolves.toBe('Key accepted.');
  });

  it('reports a rejected key (403 Authentication required)', async () => {
    const m = mockFetch(() => json({ detail: 'Authentication required' }, 403));
    const err = await rejection(otxKeyTest('bogus', http(m.fetch)));
    expect((err as Error).message).toBe('OTX rejected this key (HTTP 403: Authentication required).');
  });

  it('reports rate limiting, non-JSON and non-object responses, and empty keys', async () => {
    await expect(otxKeyTest(KEY, http(mockFetch(() => json({ detail: 'slow down' }, 429)).fetch))).rejects.toThrow(/rate limit/);
    await expect(otxKeyTest(KEY, http(mockFetch(() => text('<html>login</html>', 200)).fetch))).rejects.toThrow(/non-JSON/);
    await expect(otxKeyTest(KEY, http(mockFetch(() => json(['x'])).fetch))).rejects.toThrow(/unexpected response/);
    const none = mockFetch();
    await expect(otxKeyTest('   ', http(none.fetch))).rejects.toThrow(/Enter an OTX API key/);
    expect(none.calls).toHaveLength(0);
  });
});

describe('otx through the orchestrator', () => {
  function run(getKey: OrchestratorDeps['getKey'], f: typeof fetch) {
    const events: RunEvent[] = [];
    const deps: OrchestratorDeps = {
      modules: [otxModule as Module],
      isEnabled: () => true,
      allowActive: false,
      cache: memoryCache(),
      limiter: new RateLimiter(),
      settings: DEFAULT_SETTINGS,
      getKey,
      fetch: f,
      now: () => NOW,
    };
    const done = investigate({ kind: 'domain', value: PHISH }, (e) => events.push(e), deps).done;
    const last = (): CardState | undefined =>
      events.filter((e): e is Extract<RunEvent, { type: 'card' }> => e.type === 'card').map((e) => e.card).filter((c) => c.id === `otx|domain:${PHISH}`).at(-1);
    return { done, last };
  }

  it('is skipped with a hint when no key is set', async () => {
    const m = mockFetch();
    const r = run(async () => undefined, m.fetch);
    await r.done;
    expect(r.last()!.status).toBe('skipped');
    expect(r.last()!.skip!.reason).toBe('no-key');
    expect(m.calls).toHaveLength(0);
  });

  it('produces an ok card with summary and severity when keyed', async () => {
    const m = mockFetch(generalRoute(`domain/${PHISH}`, () => json(PHISH_GENERAL)), pdnsRoute(PHISH, () => json(PHISH_PDNS)));
    const r = run(async (p) => (p === 'otx' ? KEY : undefined), m.fetch);
    await r.done;
    const card = r.last()!;
    expect(card.status).toBe('ok');
    expect(card.severity).toBe('low');
    expect(card.summary).toMatch(/^In 3 OTX pulses/);
    expect((card.data as OtxData).pulseCount).toBe(3);
  });
});
