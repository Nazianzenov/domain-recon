import { describe, expect, it } from 'vitest';
import { FetchError } from '@/lib/http';
import {
  MAX_TEXT,
  buildDomainUrl,
  daysText,
  findRdapBases,
  formatInt,
  isProblemStatus,
  jcardEmail,
  jcardFn,
  jcardOrg,
  jcardProps,
  jcardTel,
  parseBootstrap,
  parseRdapDomain,
  type RdapBootstrap,
} from '@/lib/rdap';
import type { Entity, Fact } from '@/lib/types';
import { DAY, HOUR, SkipError } from '@/lib/types';
import { BOOTSTRAP_CACHE_KEY, BOOTSTRAP_LASTGOOD_KEY, BOOTSTRAP_URL, rdapModule, type RdapData } from '@/modules/rdap';
import { json, makeCtx, memoryCache, mockFetch, text, type Route } from './helpers';

// ---------------------------------------------------------------------------
// Fixtures (shapes from docs/research/dns-rdap.md, live 2026-11-25)

const NOW = Date.UTC(2026, 10, 25, 12, 0, 0); // 2026-11-25T12:00:00Z

const IANA_BOOTSTRAP = {
  description: 'RDAP bootstrap file for Domain Name System registrations',
  publication: '2026-11-20T23:00:03Z',
  version: '1.0',
  services: [
    [['com'], ['https://rdap.verisign.com/com/v1/']],
    [['net'], ['https://rdap.verisign.com/net/v1/']],
    [['charity', 'foundation', 'org', 'xn--c1avg', 'xn--nqv7f'], ['https://rdap.publicinterestregistry.org/rdap/']],
    [['uk'], ['https://rdap.nominet.uk/uk/']],
    [['kg'], ['http://rdap.cctld.kg/']],
  ],
};

/** Live Verisign .com answer (trimmed): thin registry, abuse nested under the registrar, UPPERCASE names. */
const VERISIGN_GOOGLE = {
  objectClassName: 'domain',
  handle: '2138514_DOMAIN_COM-VRSN',
  ldhName: 'GOOGLE.COM',
  links: [
    { value: 'https://rdap.verisign.com/com/v1/domain/GOOGLE.COM', rel: 'self', href: 'https://rdap.verisign.com/com/v1/domain/GOOGLE.COM', type: 'application/rdap+json' },
    { value: 'https://rdap.markmonitor.com/rdap/domain/GOOGLE.COM', rel: 'related', href: 'https://rdap.markmonitor.com/rdap/domain/GOOGLE.COM', type: 'application/rdap+json' },
  ],
  status: [
    'client delete prohibited',
    'client transfer prohibited',
    'client update prohibited',
    'server delete prohibited',
    'server transfer prohibited',
    'server update prohibited',
  ],
  entities: [
    {
      objectClassName: 'entity',
      handle: '292',
      roles: ['registrar'],
      publicIds: [{ type: 'IANA Registrar ID', identifier: '292' }],
      vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'MarkMonitor Inc.']]],
      entities: [
        {
          objectClassName: 'entity',
          roles: ['abuse'],
          vcardArray: [
            'vcard',
            [
              ['version', {}, 'text', '4.0'],
              ['fn', {}, 'text', ''],
              ['tel', { type: 'voice' }, 'uri', 'tel:+1.2086851750'],
              ['email', {}, 'text', 'abusecomplaints@markmonitor.com'],
            ],
          ],
        },
      ],
    },
  ],
  events: [
    { eventAction: 'registration', eventDate: '1997-09-15T04:00:00Z' },
    { eventAction: 'expiration', eventDate: '2028-09-14T04:00:00Z' },
    { eventAction: 'last changed', eventDate: '2019-09-09T15:39:04Z' },
    { eventAction: 'last update of RDAP database', eventDate: '2026-11-25T11:06:47Z' },
  ],
  secureDNS: { delegationSigned: false },
  nameservers: [
    { objectClassName: 'nameserver', ldhName: 'NS1.GOOGLE.COM' },
    { objectClassName: 'nameserver', ldhName: 'NS2.GOOGLE.COM' },
    { objectClassName: 'nameserver', ldhName: 'NS3.GOOGLE.COM' },
    { objectClassName: 'nameserver', ldhName: 'NS4.GOOGLE.COM' },
  ],
  rdapConformance: ['rdap_level_0', 'icann_rdap_technical_implementation_guide_1', 'icann_rdap_response_profile_1'],
  notices: [{ title: 'Terms of Service', description: ['Service subject to Terms of Use.'] }],
};

/** Nominet-style ccTLD answer: fewer events, top-level registrar without IANA ID, no abuse entity. */
function nominetRecord(name: string) {
  return {
    objectClassName: 'domain',
    handle: `${name.toUpperCase()}-NOMINET`,
    ldhName: name,
    status: ['active'],
    entities: [
      {
        objectClassName: 'entity',
        roles: ['registrar'],
        vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Example Registrar Ltd t/a Example'], ['url', {}, 'uri', 'https://registrar.example']]],
      },
    ],
    events: [
      { eventAction: 'registration', eventDate: '2026-11-10T09:30:00Z' },
      { eventAction: 'expiration', eventDate: '2026-12-10T09:30:00Z' },
      { eventAction: 'last changed', eventDate: '2026-11-11T00:00:00Z' },
    ],
    nameservers: [{ objectClassName: 'nameserver', ldhName: 'dns1.registrar-servers.example.' }],
  };
}

const RDAP_ORG_NO_SERVICE = {
  rdapConformance: ['rdap_level_0'],
  lang: 'en',
  errorCode: 404,
  title: 'No RDAP service is available for this resource',
};

// ---------------------------------------------------------------------------
// Helpers

const entity = (value: string): Entity => ({ kind: 'domain', value, depth: 0 });

/** Simulate fetch following rdap.org's 302: `Response.url` becomes the registry URL. */
function redirectedTo(res: Response, finalUrl: string): Response {
  Object.defineProperty(res, 'url', { value: finalUrl });
  return res;
}

const ianaRoute: Route = (u) => (u.href === BOOTSTRAP_URL ? json(IANA_BOOTSTRAP) : undefined);

function at(prefix: string, handler: (u: URL, init: RequestInit) => Response): Route {
  return (u, init) => (u.href.startsWith(prefix) ? handler(u, init) : undefined);
}

function cors(host: string): Route {
  return (u) => {
    if (u.host === host) throw new TypeError('NetworkError when attempting to fetch resource.');
    return undefined;
  };
}

function urls(calls: Array<{ url: string }>): string[] {
  return calls.map((c) => c.url);
}

function fact(facts: Fact[], label: string): Fact | undefined {
  return facts.find((f) => f.label === label);
}

async function run(value: string, ...routes: Route[]) {
  const m = mockFetch(...routes);
  const ctx = makeCtx({ fetch: m.fetch, now: () => NOW, root: value });
  const out = await rdapModule.run(entity(value), ctx);
  return { out, calls: m.calls, data: out.data };
}

// ---------------------------------------------------------------------------
// Bootstrap matching

describe('rdap bootstrap', () => {
  const boot = parseBootstrap(IANA_BOOTSTRAP)!;

  it('validates the IANA file and normalises it', () => {
    expect(boot.publication).toBe('2026-11-20T23:00:03Z');
    expect(boot.services).toHaveLength(5);
    expect(boot.services[0]).toEqual({ entries: ['com'], urls: ['https://rdap.verisign.com/com/v1/'] });
    // The normalised form round-trips (it is what the raw cache stores).
    expect(parseBootstrap(JSON.parse(JSON.stringify(boot)))).toEqual(boot);
  });

  it('rejects junk and drops invalid entries', () => {
    expect(parseBootstrap(null)).toBeNull();
    expect(parseBootstrap('nope')).toBeNull();
    expect(parseBootstrap({ services: 'x' })).toBeNull();
    expect(parseBootstrap({ services: [] })).toBeNull();
    expect(parseBootstrap({ services: [[['com'], ['javascript:alert(1)', 'ftp://x/']]] })).toBeNull();
    const b = parseBootstrap({
      services: [
        'garbage',
        [['COM.', 42, 'bad label!'], ['https://rdap.verisign.com/com/v1', 'not a url', 7]],
        [['org'], []],
        [null, ['https://x.example/']],
      ],
    });
    expect(b).toEqual({ publication: null, services: [{ entries: ['com'], urls: ['https://rdap.verisign.com/com/v1/'] }] });
  });

  it('matches the TLD for a registrable domain and for deep subdomains', () => {
    expect(findRdapBases(boot, 'google.com')).toEqual({ suffix: 'com', suffixLabels: 1, bases: ['https://rdap.verisign.com/com/v1/'] });
    expect(findRdapBases(boot, 'www.shop.example.co.uk')?.bases).toEqual(['https://rdap.nominet.uk/uk/']);
    expect(findRdapBases(boot, 'example.org')?.suffix).toBe('org');
  });

  it('picks the longest suffix and handles multi-label entries', () => {
    const b: RdapBootstrap = {
      publication: null,
      services: [
        { entries: ['uk'], urls: ['https://rdap.nominet.uk/uk/'] },
        { entries: ['co.uk', 'example.com'], urls: ['https://rdap.second-level.example/'] },
        { entries: ['com'], urls: ['https://rdap.verisign.com/com/v1/'] },
      ],
    };
    expect(findRdapBases(b, 'shop.example.co.uk')).toEqual({ suffix: 'co.uk', suffixLabels: 2, bases: ['https://rdap.second-level.example/'] });
    expect(findRdapBases(b, 'example.uk')?.suffix).toBe('uk');
    expect(findRdapBases(b, 'www.example.com')?.suffix).toBe('example.com');
    // Label boundaries: "example.com" must not match "badexample.com".
    expect(findRdapBases(b, 'badexample.com')?.suffix).toBe('com');
    expect(findRdapBases(b, 'co.uk')?.suffix).toBe('co.uk');
  });

  it('returns null when nothing matches (de, io... are absent from the IANA file)', () => {
    expect(findRdapBases(boot, 'denic.de')).toBeNull();
    expect(findRdapBases(boot, 'github.io')).toBeNull();
    expect(findRdapBases(boot, '')).toBeNull();
    // "com" is not a suffix of "dotcom" as a label.
    expect(findRdapBases(boot, 'example.dotcom')).toBeNull();
  });

  it('is case-insensitive and ignores a trailing dot', () => {
    expect(findRdapBases(boot, 'WWW.Google.COM.')?.suffix).toBe('com');
    const upper = parseBootstrap({ services: [[['COM'], ['https://rdap.verisign.com/com/v1/']]] })!;
    expect(findRdapBases(upper, 'google.com')?.suffix).toBe('com');
  });

  it('matches IDN TLDs in A-label form, converting Unicode input first', () => {
    expect(findRdapBases(boot, 'xn--e1afmkfd.xn--c1avg')?.bases).toEqual(['https://rdap.publicinterestregistry.org/rdap/']);
    expect(findRdapBases(boot, 'XN--E1AFMKFD.XN--C1AVG')?.suffix).toBe('xn--c1avg');
    expect(findRdapBases(boot, 'пример.орг')?.suffix).toBe('xn--c1avg');
  });

  it('prefers https bases and keeps http ones as a last resort', () => {
    const b = parseBootstrap({ services: [[['mg'], ['http://rdap.nic.mg/', 'https://rdap.nic.mg/']]] })!;
    expect(findRdapBases(b, 'x.mg')?.bases).toEqual(['https://rdap.nic.mg/', 'http://rdap.nic.mg/']);
    expect(findRdapBases(boot, 'example.kg')?.bases).toEqual(['http://rdap.cctld.kg/']);
  });

  it('builds query URLs with or without a trailing slash on the base', () => {
    expect(buildDomainUrl('https://rdap.verisign.com/com/v1/', 'google.com')).toBe('https://rdap.verisign.com/com/v1/domain/google.com');
    expect(buildDomainUrl('https://rdap.verisign.com/com/v1', 'google.com')).toBe('https://rdap.verisign.com/com/v1/domain/google.com');
    expect(buildDomainUrl('https://rdap.example/', 'Bücher.example')).toBe('https://rdap.example/domain/xn--bcher-kva.example');
    // Bootstrap normalisation adds the slash RFC 9224 requires.
    expect(parseBootstrap({ services: [[['x'], ['https://rdap.x/base']]] })!.services[0]!.urls).toEqual(['https://rdap.x/base/']);
  });
});

// ---------------------------------------------------------------------------
// jCard

describe('jCard helpers', () => {
  const abuse = VERISIGN_GOOGLE.entities[0]!.entities[0]!.vcardArray;

  it('reads fn/email/tel from the Verisign abuse entity (empty fn, tel URI)', () => {
    expect(jcardFn(abuse)).toBeNull();
    expect(jcardEmail(abuse)).toBe('abusecomplaints@markmonitor.com');
    expect(jcardTel(abuse)).toBe('+1.2086851750');
  });

  it('handles text tel, fax ordering, mailto, org and property-name case', () => {
    const v = [
      'vcard',
      [
        ['VERSION', {}, 'text', '4.0'],
        ['FN', {}, 'text', '  Registrar Name  '],
        ['org', {}, 'text', ['Registrar Org', 'Unit']],
        ['tel', { type: ['fax', 'work'] }, 'uri', 'tel:+44.1111'],
        ['tel', { type: 'work' }, 'text', '+44.2222'],
        ['email', {}, 'text', 'mailto:Abuse@Registrar.example'],
      ],
    ];
    expect(jcardFn(v)).toBe('Registrar Name');
    expect(jcardOrg(v)).toBe('Registrar Org');
    expect(jcardTel(v)).toBe('+44.2222');
    expect(jcardEmail(v)).toBe('Abuse@Registrar.example');
    expect(jcardTel(['vcard', [['tel', {}, 'uri', 'tel:+1-555-0100;ext=42']]])).toBe('+1-555-0100');
  });

  it('tolerates missing or malformed vcardArray (JSContact-only entities)', () => {
    for (const bad of [undefined, null, 'vcard', [], ['vcard'], ['notvcard', []], ['vcard', [['fn'], [1, {}, 'text', 'x'], 'junk']]]) {
      expect(jcardProps(bad)).toEqual([]);
      expect(jcardFn(bad)).toBeNull();
      expect(jcardEmail(bad)).toBeNull();
      expect(jcardTel(bad)).toBeNull();
    }
    expect(jcardEmail(['vcard', [['email', {}, 'text', 42]]])).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Domain object parsing

describe('parseRdapDomain', () => {
  it('normalises a realistic Verisign .com response', () => {
    const r = parseRdapDomain(VERISIGN_GOOGLE, NOW);
    expect(r.ldhName).toBe('google.com');
    expect(r.unicodeName).toBeNull();
    expect(r.handle).toBe('2138514_DOMAIN_COM-VRSN');
    expect(r.events).toEqual({
      registration: '1997-09-15T04:00:00.000Z',
      reregistration: null,
      expiration: '2028-09-14T04:00:00.000Z',
      lastChanged: '2019-09-09T15:39:04.000Z',
      transfer: null,
      rdapUpdated: '2026-11-25T11:06:47.000Z',
    });
    expect(r.ageDays).toBe(10663);
    expect(r.daysToExpiry).toBe(658);
    expect(r.registrar).toEqual({ name: 'MarkMonitor Inc.', ianaId: '292', url: null });
    expect(r.abuse).toEqual({ email: 'abusecomplaints@markmonitor.com', phone: '+1.2086851750' });
    expect(r.nameservers).toEqual(['ns1.google.com', 'ns2.google.com', 'ns3.google.com', 'ns4.google.com']);
    expect(r.nameserverCount).toBe(4);
    expect(r.status).toContain('client transfer prohibited');
    expect(r.delegationSigned).toBe(false);
    // JSON-serialisable (cached in IndexedDB, exported).
    expect(JSON.parse(JSON.stringify(r))).toEqual(r);
  });

  it('finds a top-level abuse entity and an abuse entity nested elsewhere', () => {
    const top = parseRdapDomain(
      { ldhName: 'x.org', entities: [{ roles: ['ABUSE'], vcardArray: ['vcard', [['email', {}, 'text', 'abuse@pir.example']]] }] },
      NOW,
    );
    expect(top.abuse).toEqual({ email: 'abuse@pir.example', phone: null });
    expect(top.registrar).toBeNull();
    const deep = parseRdapDomain(
      {
        ldhName: 'x.org',
        entities: [{ roles: ['registrant'], entities: [{ roles: ['abuse'], vcardArray: ['vcard', [['tel', {}, 'text', '+1.5550100']]] }] }],
      },
      NOW,
    );
    expect(deep.abuse).toEqual({ email: null, phone: '+1.5550100' });
    // An abuse entity with nothing usable is skipped.
    expect(parseRdapDomain({ entities: [{ roles: ['abuse'], vcardArray: ['vcard', [['fn', {}, 'text', '']]] }] }, NOW).abuse).toBeNull();
  });

  it('tolerates missing and malformed fields (ccTLD-style sparse records)', () => {
    const r = parseRdapDomain(
      {
        objectClassName: 'domain',
        ldhName: 42,
        unicodeName: 'bücher.example.',
        events: [
          { eventAction: 'registration', eventDate: 'not a date' },
          { eventAction: 'expiration' },
          'junk',
          { eventAction: 'last update of RDAP database', eventDate: '2026-11-25T00:00:00Z' },
        ],
        entities: 'nope',
        nameservers: [{ ldhName: 'A.NS.EXAMPLE.' }, { ldhName: 'a.ns.example' }, {}, null, { ldhName: '' }],
        status: ['active', 7, '', 'active'],
        secureDNS: { delegationSigned: 'yes' },
        publicIds: 3,
      },
      NOW,
    );
    expect(r.ldhName).toBeNull();
    expect(r.unicodeName).toBe('bücher.example');
    expect(r.events.registration).toBeNull();
    expect(r.events.lastChanged).toBeNull(); // RDAP-database update is not "last changed"
    expect(r.events.rdapUpdated).toBe('2026-11-25T00:00:00.000Z');
    expect(r.ageDays).toBeNull();
    expect(r.daysToExpiry).toBeNull();
    expect(r.registrar).toBeNull();
    expect(r.abuse).toBeNull();
    expect(r.nameservers).toEqual(['a.ns.example']);
    expect(r.status).toEqual(['active']);
    expect(r.delegationSigned).toBeNull();
  });

  it('caps nameservers but records the total; picks earliest registration', () => {
    const r = parseRdapDomain(
      {
        nameservers: Array.from({ length: 25 }, (_, i) => ({ ldhName: `NS${i}.EXAMPLE.NET` })),
        events: [
          { eventAction: 'registration', eventDate: '2020-01-02T00:00:00Z' },
          { eventAction: 'Registration', eventDate: '2010-01-02T00:00:00Z' },
          { eventAction: 'reregistration', eventDate: '2024-05-01T00:00:00Z' },
          { eventAction: 'expiration', eventDate: '2026-11-20T12:00:00Z' },
        ],
        registrar: 'ignored',
      },
      NOW,
    );
    expect(r.nameservers).toHaveLength(20);
    expect(r.nameserverCount).toBe(25);
    expect(r.events.registration).toBe('2010-01-02T00:00:00.000Z');
    expect(r.events.reregistration).toBe('2024-05-01T00:00:00.000Z');
    expect(r.daysToExpiry).toBe(-5);
  });

  it('ignores prototype-named event actions and clips oversized strings', () => {
    const r = parseRdapDomain(
      {
        ldhName: 'x.com',
        events: [
          { eventAction: 'constructor', eventDate: '2020-01-01T00:00:00Z' },
          { eventAction: '__proto__', eventDate: '2020-01-01T00:00:00Z' },
          { eventAction: 'hasOwnProperty', eventDate: '2020-01-01T00:00:00Z' },
        ],
        entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'R'.repeat(5000)]]] }],
        status: ['s'.repeat(5000)],
      },
      NOW,
    );
    expect(Object.keys(r.events).sort()).toEqual(['expiration', 'lastChanged', 'rdapUpdated', 'registration', 'reregistration', 'transfer']);
    expect(Object.values(r.events).every((v) => v === null)).toBe(true);
    expect(r.registrar!.name!.length).toBe(MAX_TEXT);
    expect(r.status[0]!.length).toBe(MAX_TEXT);
  });

  it('throws on non-object input', () => {
    expect(() => parseRdapDomain(null, NOW)).toThrow();
    expect(() => parseRdapDomain([VERISIGN_GOOGLE], NOW)).toThrow();
    expect(() => parseRdapDomain('{}', NOW)).toThrow();
  });

  it('status and number helpers', () => {
    expect(isProblemStatus('client hold')).toBe(true);
    expect(isProblemStatus('clientHold')).toBe(true);
    expect(isProblemStatus('pending delete')).toBe(true);
    expect(isProblemStatus('redemption period')).toBe(true);
    expect(isProblemStatus('inactive')).toBe(true);
    expect(isProblemStatus('client transfer prohibited')).toBe(false);
    expect(isProblemStatus('active')).toBe(false);
    expect(formatInt(2093)).toBe('2,093');
    expect(formatInt(1234567)).toBe('1,234,567');
    expect(formatInt(12)).toBe('12');
    expect(formatInt(-1500)).toBe('-1,500');
    expect(daysText(1)).toBe('1 day');
    expect(daysText(0)).toBe('0 days');
    expect(daysText(2093)).toBe('2,093 days');
  });
});

// ---------------------------------------------------------------------------
// Module

describe('rdap module', () => {
  it('declares the expected contract', () => {
    expect(rdapModule.id).toBe('rdap');
    expect(rdapModule.label).toBe('RDAP (registration)');
    expect(rdapModule.version).toBe(1);
    expect(rdapModule.accepts).toEqual(['domain']);
    expect(rdapModule.ttl).toBe(24 * HOUR);
    expect(rdapModule.active).toBeFalsy();
    expect(rdapModule.key).toBeUndefined();
  });

  it('queries the bootstrap server and parses a .com record (abuse nested under registrar)', async () => {
    const { out, calls, data } = await run(
      'google.com',
      ianaRoute,
      at('https://rdap.verisign.com/com/v1/domain/', () => json(VERISIGN_GOOGLE, 200, { 'content-type': 'application/rdap+json' })),
    );
    expect(urls(calls)).toEqual([BOOTSTRAP_URL, 'https://rdap.verisign.com/com/v1/domain/google.com']);
    expect((calls[1]!.init.headers as Record<string, string>)['accept']).toContain('application/rdap+json');
    expect(calls[1]!.init.credentials).toBe('omit');
    expect(data.found).toBe(true);
    expect(data.via).toBe('bootstrap');
    expect(data.bootstrapSuffix).toBe('com');
    expect(data.queriedName).toBe('google.com');
    expect(data.tried).toEqual(['google.com']);
    expect(data.queryUrl).toBe('https://rdap.verisign.com/com/v1/domain/google.com');
    expect(data.fallbackReason).toBeNull();
    expect(data.record?.registrar?.name).toBe('MarkMonitor Inc.');
    expect(data.record?.abuse?.email).toBe('abusecomplaints@markmonitor.com');
    expect(out.summary).toBe('Registered 1997-09-15 (10,663 days) · MarkMonitor Inc. · expires 2028-09-14');
    expect(out.pivots).toBeUndefined();
    expect(JSON.parse(JSON.stringify(data))).toEqual(data);

    expect(rdapModule.headline!(data, entity('google.com'))).toEqual({
      registrationFor: 'google.com',
      domainAgeDays: 10663,
      registeredOn: '1997-09-15',
      registrar: 'MarkMonitor Inc.',
    });

    const facts = rdapModule.facts!(data, entity('google.com'));
    expect(fact(facts, 'Domain age')).toEqual({ label: 'Domain age', value: '10,663 days (registered 1997-09-15)' });
    expect(fact(facts, 'Registrar')?.value).toBe('MarkMonitor Inc.');
    expect(fact(facts, 'IANA registrar ID')?.value).toBe('292');
    expect(fact(facts, 'Abuse email')).toMatchObject({ value: 'abusecomplaints@markmonitor.com', pivot: true });
    expect(fact(facts, 'Abuse phone')).toMatchObject({ value: '+1.2086851750', pivot: true });
    expect(fact(facts, 'Nameservers')).toMatchObject({ value: ['ns1.google.com', 'ns2.google.com', 'ns3.google.com', 'ns4.google.com'], pivot: true });
    expect(fact(facts, 'Status')?.tone).toBeUndefined();
    expect(fact(facts, 'Expires')).toEqual({ label: 'Expires', value: '2028-09-14 (in 658 days)' });
    expect(fact(facts, 'Last changed')?.value).toBe('2019-09-09');
    expect(fact(facts, 'DNSSEC (delegation)')?.value).toBe('unsigned');
    expect(fact(facts, 'RDAP server')).toEqual({
      label: 'RDAP server',
      value: 'rdap.verisign.com',
      href: 'https://rdap.verisign.com/com/v1/domain/google.com',
    });
    expect(fact(facts, 'Record for')).toBeUndefined();
    for (const f of facts) if (f.href) expect(f.href.startsWith('https://')).toBe(true);
  });

  it('retries subdomains with the leftmost label stripped on 404 (empty 404 body)', async () => {
    const { out, calls, data } = await run(
      'www.shop.example.co.uk',
      ianaRoute,
      at('https://rdap.nominet.uk/uk/domain/', (u) =>
        u.pathname.endsWith('/example.co.uk') ? json(nominetRecord('example.co.uk')) : new Response(null, { status: 404 }),
      ),
    );
    expect(urls(calls).slice(1)).toEqual([
      'https://rdap.nominet.uk/uk/domain/www.shop.example.co.uk',
      'https://rdap.nominet.uk/uk/domain/shop.example.co.uk',
      'https://rdap.nominet.uk/uk/domain/example.co.uk',
    ]);
    expect(data.found).toBe(true);
    expect(data.queriedName).toBe('example.co.uk');
    expect(data.tried).toEqual(['www.shop.example.co.uk', 'shop.example.co.uk', 'example.co.uk']);
    // The parent's record is labelled as such, not presented as the subdomain's own registration.
    expect(out.summary).toBe('example.co.uk: Registered 2026-11-10 (15 days) · Example Registrar Ltd t/a Example · expires 2026-12-10');

    const facts = rdapModule.facts!(data, entity('www.shop.example.co.uk'));
    expect(fact(facts, 'Domain age')?.tone).toBe('bad');
    expect(fact(facts, 'Record for')).toMatchObject({ value: 'example.co.uk', pivot: true });
    expect(fact(facts, 'Expires')).toMatchObject({ value: '2026-12-10 (in 14 days)', tone: 'warn' });
    expect(fact(facts, 'Registrar URL')?.value).toBe('https://registrar.example');
    expect(fact(facts, 'Registrar URL')?.href).toBeUndefined();
    expect(fact(facts, 'IANA registrar ID')).toBeUndefined();
    expect(fact(facts, 'Nameservers')?.value).toEqual(['dns1.registrar-servers.example']);
  });

  it('returns found:false (not an error) after at most 4 attempts', async () => {
    const { out, calls, data } = await run(
      'a.b.c.d.example.com',
      ianaRoute,
      at('https://rdap.verisign.com/', () => new Response(null, { status: 404 })),
    );
    expect(urls(calls).slice(1)).toEqual([
      'https://rdap.verisign.com/com/v1/domain/a.b.c.d.example.com',
      'https://rdap.verisign.com/com/v1/domain/b.c.d.example.com',
      'https://rdap.verisign.com/com/v1/domain/c.d.example.com',
      'https://rdap.verisign.com/com/v1/domain/d.example.com',
    ]);
    expect(data.found).toBe(false);
    expect(data.record).toBeNull();
    expect(data.queriedName).toBe('d.example.com');
    expect(data.serverUrl).toBe('https://rdap.verisign.com/com/v1/domain/d.example.com');
    expect(out.summary).toBe('Not found in RDAP');
    expect(rdapModule.headline!(data, entity('a.b.c.d.example.com'))).toEqual({});
    const facts = rdapModule.facts!(data, entity('a.b.c.d.example.com'));
    expect(fact(facts, 'Status')?.value).toBe('Not found in RDAP');
    expect(fact(facts, 'Names tried')?.value).toHaveLength(4);
  });

  it('stops at <suffix>+1 labels and treats a 404 HTML page as not found', async () => {
    const { calls, data } = await run(
      'www.unregistered-name.com',
      ianaRoute,
      at('https://rdap.verisign.com/', () => text('<html><body>Not Found</body></html>', 404)),
    );
    expect(urls(calls).slice(1)).toEqual([
      'https://rdap.verisign.com/com/v1/domain/www.unregistered-name.com',
      'https://rdap.verisign.com/com/v1/domain/unregistered-name.com',
    ]);
    expect(data.found).toBe(false);
    expect(data.queriedName).toBe('unregistered-name.com');
  });

  it('treats a 400 for a subdomain as "try the parent", but not at the registrable level', async () => {
    const badRequest = () => json({ errorCode: 400, title: 'Bad Request', description: ['Not a registrable domain'] }, 400);
    const { calls, data } = await run(
      'login.example.org',
      ianaRoute,
      at('https://rdap.publicinterestregistry.org/rdap/domain/login.example.org', badRequest),
      at('https://rdap.publicinterestregistry.org/rdap/domain/example.org', () => json({ ...VERISIGN_GOOGLE, ldhName: 'EXAMPLE.ORG' })),
    );
    expect(urls(calls).slice(1)).toEqual([
      'https://rdap.publicinterestregistry.org/rdap/domain/login.example.org',
      'https://rdap.publicinterestregistry.org/rdap/domain/example.org',
    ]);
    expect(data.found).toBe(true);
    expect(data.via).toBe('bootstrap');
    expect(data.queriedName).toBe('example.org');

    // A 400 for the registrable name itself is a genuine error (after the rdap.org fallback).
    const m = mockFetch(ianaRoute, at('https://rdap.publicinterestregistry.org/', badRequest), at('https://rdap.org/', badRequest));
    const err = await rdapModule.run(entity('example.org'), makeCtx({ fetch: m.fetch, now: () => NOW })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).status).toBe(400);
    expect((err as FetchError).message).toContain('rdap.publicinterestregistry.org');
  });

  it('survives a throwing raw cache', async () => {
    const m = mockFetch(ianaRoute, at('https://rdap.verisign.com/', () => json(VERISIGN_GOOGLE)));
    const ctx = makeCtx({ fetch: m.fetch, now: () => NOW });
    ctx.rawCache = {
      get: () => Promise.reject(new Error('IndexedDB unavailable')),
      set: () => Promise.reject(new Error('IndexedDB unavailable')),
    };
    const out = await rdapModule.run(entity('google.com'), ctx);
    expect(out.data.via).toBe('bootstrap');
    expect(urls(m.calls)[0]).toBe(BOOTSTRAP_URL);
  });

  it('falls back to rdap.org when the registry blocks the request (CORS -> network error)', async () => {
    const { out, calls, data } = await run(
      'www.example.co.uk',
      ianaRoute,
      cors('rdap.nominet.uk'),
      at('https://rdap.org/domain/', (u) =>
        u.pathname === '/domain/example.co.uk'
          ? redirectedTo(json(nominetRecord('example.co.uk')), 'https://rdap.nominet.uk/uk/domain/example.co.uk')
          : redirectedTo(new Response(null, { status: 404 }), `https://rdap.nominet.uk/uk/domain/${u.pathname.split('/').pop()}`),
      ),
    );
    // The dead registry is not retried for the parent name.
    expect(urls(calls).slice(1)).toEqual([
      'https://rdap.nominet.uk/uk/domain/www.example.co.uk',
      'https://rdap.org/domain/www.example.co.uk',
      'https://rdap.org/domain/example.co.uk',
    ]);
    expect(data.found).toBe(true);
    expect(data.via).toBe('rdap.org');
    expect(data.queryUrl).toBe('https://rdap.org/domain/example.co.uk');
    expect(data.serverUrl).toBe('https://rdap.nominet.uk/uk/domain/example.co.uk');
    expect(data.fallbackReason).toMatch(/^rdap\.nominet\.uk: Network error/);
    expect(out.summary).toContain('Registered 2026-11-10');
    const facts = rdapModule.facts!(data, entity('www.example.co.uk'));
    expect(fact(facts, 'RDAP server')).toEqual({
      label: 'RDAP server',
      value: 'rdap.nominet.uk (via rdap.org)',
      href: 'https://rdap.org/domain/example.co.uk',
    });
  });

  it('throws a typed error when both the registry and rdap.org fail', async () => {
    const m = mockFetch(ianaRoute, cors('rdap.verisign.com'), cors('rdap.org'));
    const ctx = makeCtx({ fetch: m.fetch, now: () => NOW });
    const err = await rdapModule.run(entity('example.com'), ctx).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).kind).toBe('network');
    expect((err as FetchError).message).toContain('rdap.verisign.com');
  });

  it('goes straight to rdap.org when the bootstrap fetch fails', async () => {
    const { calls, data } = await run(
      'google.com',
      at(BOOTSTRAP_URL, () => text('upstream error', 503)),
      at('https://rdap.org/domain/google.com', () =>
        redirectedTo(json(VERISIGN_GOOGLE), 'https://rdap.verisign.com/com/v1/domain/google.com'),
      ),
    );
    expect(urls(calls)).toEqual([BOOTSTRAP_URL, 'https://rdap.org/domain/google.com']);
    expect(data.found).toBe(true);
    expect(data.via).toBe('rdap.org');
    expect(data.bootstrapSuffix).toBeNull();
    expect(data.fallbackReason).toBe('IANA bootstrap unavailable');
    expect(data.record?.ageDays).toBe(10663);
  });

  it('treats an invalid bootstrap body like a failed fetch', async () => {
    const { calls, data } = await run(
      'google.com',
      at(BOOTSTRAP_URL, () => json({ services: 'broken' })),
      at('https://rdap.org/', () => redirectedTo(json(VERISIGN_GOOGLE), 'https://rdap.verisign.com/com/v1/domain/google.com')),
    );
    expect(calls).toHaveLength(2);
    expect(data.via).toBe('rdap.org');
  });

  it('skips when rdap.org itself has no service (bootstrap unavailable)', async () => {
    const m = mockFetch(
      at(BOOTSTRAP_URL, () => {
        throw new TypeError('offline');
      }),
      at('https://rdap.org/', () => json(RDAP_ORG_NO_SERVICE, 404)),
    );
    const err = await rdapModule.run(entity('denic.de'), makeCtx({ fetch: m.fetch, now: () => NOW })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SkipError);
    expect((err as Error).message).toContain('.de');
  });

  it('reports an error (not "no RDAP") when the listed registry fails and rdap.org has no server', async () => {
    const m = mockFetch(ianaRoute, cors('rdap.verisign.com'), at('https://rdap.org/', () => json(RDAP_ORG_NO_SERVICE, 404)));
    const err = await rdapModule.run(entity('example.com'), makeCtx({ fetch: m.fetch, now: () => NOW })).catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(SkipError);
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).message).toContain('rdap.verisign.com');
  });

  it('OPSEC: never contacts an RDAP server that belongs to the investigated domain', async () => {
    for (const value of ['verisign.com', 'www.verisign.com', 'rdap.nominet.uk']) {
      const m = mockFetch(ianaRoute);
      const err = await rdapModule.run(entity(value), makeCtx({ fetch: m.fetch, now: () => NOW })).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(SkipError);
      expect((err as Error).message).toContain('belongs to the investigated domain');
      expect(urls(m.calls)).toEqual([BOOTSTRAP_URL]);
    }
    // rdap.org itself is not used as a fallback when it is the target.
    const m = mockFetch(at(BOOTSTRAP_URL, () => text('down', 503)));
    const err = await rdapModule.run(entity('rdap.org'), makeCtx({ fetch: m.fetch, now: () => NOW })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SkipError);
    expect(urls(m.calls)).toEqual([BOOTSTRAP_URL]);
  });

  it('labels a record whose ldhName differs from the investigated name', async () => {
    // Some registries answer a subdomain query with the registered parent's record.
    const { out, data } = await run(
      'login.example.com',
      ianaRoute,
      at('https://rdap.verisign.com/', () => json({ ...VERISIGN_GOOGLE, ldhName: 'EXAMPLE.COM' })),
    );
    expect(data.queriedName).toBe('login.example.com');
    expect(out.summary).toMatch(/^example\.com: Registered 1997-09-15/);
    expect(fact(rdapModule.facts!(data, entity('login.example.com')), 'Record for')?.value).toBe('example.com');
  });

  it('skips TLDs missing from the bootstrap without contacting rdap.org', async () => {
    const m = mockFetch(ianaRoute);
    const err = await rdapModule.run(entity('www.github.io'), makeCtx({ fetch: m.fetch, now: () => NOW })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SkipError);
    expect((err as Error).message).toContain('.io');
    expect(urls(m.calls)).toEqual([BOOTSTRAP_URL]);
  });

  it('upgrades http bootstrap bases to https', async () => {
    const { calls, data } = await run(
      'example.kg',
      ianaRoute,
      at('https://rdap.cctld.kg/domain/example.kg', () => json({ ...nominetRecord('example.kg'), ldhName: 'EXAMPLE.KG' })),
    );
    expect(urls(calls)[1]).toBe('https://rdap.cctld.kg/domain/example.kg');
    expect(data.record?.ldhName).toBe('example.kg');
  });

  it('falls back when the registry returns a non-domain body', async () => {
    const { data } = await run(
      'google.com',
      ianaRoute,
      at('https://rdap.verisign.com/', () => json({ objectClassName: 'entity', handle: 'x' })),
      at('https://rdap.org/', () => redirectedTo(json(VERISIGN_GOOGLE), 'https://rdap.verisign.com/com/v1/domain/google.com')),
    );
    expect(data.via).toBe('rdap.org');
    expect(data.fallbackReason).toContain('Unexpected RDAP response');
  });

  it('propagates cancellation without falling back', async () => {
    const ac = new AbortController();
    const m = mockFetch(
      ianaRoute,
      at('https://rdap.verisign.com/', () => {
        ac.abort();
        throw new DOMException('Aborted', 'AbortError');
      }),
    );
    const err = await rdapModule
      .run(entity('google.com'), makeCtx({ fetch: m.fetch, now: () => NOW, signal: ac.signal }))
      .catch((e: unknown) => e);
    expect((err as FetchError).kind).toBe('aborted');
    expect(urls(m.calls).some((u) => u.startsWith('https://rdap.org/'))).toBe(false);
  });

  it('tones: warn for hold statuses and young domains, bad for expired', () => {
    const base: RdapData = {
      found: true,
      queriedName: 'example.com',
      tried: ['example.com'],
      queryUrl: 'https://rdap.verisign.com/com/v1/domain/example.com',
      serverUrl: 'https://rdap.verisign.com/com/v1/domain/example.com',
      via: 'bootstrap',
      bootstrapSuffix: 'com',
      fallbackReason: null,
      record: parseRdapDomain(
        {
          ldhName: 'example.com',
          status: ['client hold', 'redemption period'],
          events: [
            { eventAction: 'registration', eventDate: '2026-07-01T00:00:00Z' },
            { eventAction: 'expiration', eventDate: '2026-11-01T00:00:00Z' },
          ],
          secureDNS: { delegationSigned: true },
        },
        NOW,
      ),
    };
    const facts = rdapModule.facts!(base, entity('example.com'));
    expect(fact(facts, 'Domain age')).toMatchObject({ value: '147 days (registered 2026-07-01)', tone: 'warn' });
    expect(fact(facts, 'Status')).toMatchObject({ value: ['client hold', 'redemption period'], tone: 'warn' });
    expect(fact(facts, 'Expires')).toMatchObject({ value: '2026-11-01 (expired 25 days ago)', tone: 'bad' });
    expect(fact(facts, 'DNSSEC (delegation)')).toMatchObject({ value: 'signed', tone: 'good' });
  });
});

// ---------------------------------------------------------------------------
// Bootstrap caching

describe('rdap bootstrap caching', () => {
  it('caches the IANA file for 24 h in the raw cache across investigations', async () => {
    let t = NOW;
    const clock = () => t;
    const cache = memoryCache(clock);
    const m = mockFetch(ianaRoute, at('https://rdap.verisign.com/', () => json(VERISIGN_GOOGLE)));
    const ianaCalls = () => m.calls.filter((c) => c.url === BOOTSTRAP_URL).length;

    await rdapModule.run(entity('google.com'), makeCtx({ fetch: m.fetch, now: clock, cache }));
    expect(ianaCalls()).toBe(1);
    expect(await cache.getRaw(BOOTSTRAP_CACHE_KEY, DAY)).toMatchObject({ publication: '2026-11-20T23:00:03Z' });

    // New investigation (fresh ctx.shared) 23 h later: served from the raw cache.
    t = NOW + 23 * HOUR;
    await rdapModule.run(entity('google.com'), makeCtx({ fetch: m.fetch, now: clock, cache }));
    expect(ianaCalls()).toBe(1);

    // 25 h after the fetch: expired, fetched again.
    t = NOW + 25 * HOUR;
    await rdapModule.run(entity('google.com'), makeCtx({ fetch: m.fetch, now: clock, cache }));
    expect(ianaCalls()).toBe(2);
  });

  it('falls back to the last good bootstrap (not rdap.org) when IANA is unreachable', async () => {
    let t = NOW;
    const clock = () => t;
    const cache = memoryCache(clock);
    const ok = mockFetch(ianaRoute, at('https://rdap.verisign.com/', () => json(VERISIGN_GOOGLE)));
    await rdapModule.run(entity('google.com'), makeCtx({ fetch: ok.fetch, now: clock, cache }));
    expect(await cache.getRaw(BOOTSTRAP_LASTGOOD_KEY, 30 * DAY)).toBeDefined();

    // Two days later the 24 h copy has expired and IANA is down.
    t = NOW + 2 * DAY;
    const down = mockFetch(
      (u) => (u.href === BOOTSTRAP_URL ? Promise.reject(new TypeError('NetworkError')) : undefined),
      at('https://rdap.verisign.com/', () => json(VERISIGN_GOOGLE)),
    );
    const out = await rdapModule.run(entity('google.com'), makeCtx({ fetch: down.fetch, now: clock, cache }));
    expect(out.data.found).toBe(true);
    expect(out.data.via).toBe('bootstrap');
    expect(down.calls.some((c) => c.url.startsWith('https://rdap.org/'))).toBe(false);
  });

  it('ignores a corrupt cached copy and refetches', async () => {
    const cache = memoryCache(() => NOW);
    await cache.setRaw(BOOTSTRAP_CACHE_KEY, { services: 'corrupt' }, DAY);
    const m = mockFetch(ianaRoute, at('https://rdap.verisign.com/', () => json(VERISIGN_GOOGLE)));
    const out = await rdapModule.run(entity('google.com'), makeCtx({ fetch: m.fetch, now: () => NOW, cache }));
    expect(out.data.found).toBe(true);
    expect(m.calls.filter((c) => c.url === BOOTSTRAP_URL)).toHaveLength(1);
  });

  it('concurrent runs in one investigation fetch the bootstrap once', async () => {
    const m = mockFetch(
      ianaRoute,
      at('https://rdap.verisign.com/', () => json(VERISIGN_GOOGLE)),
      at('https://rdap.publicinterestregistry.org/', () => json({ ...VERISIGN_GOOGLE, ldhName: 'EXAMPLE.ORG' })),
    );
    const ctx = makeCtx({ fetch: m.fetch, now: () => NOW });
    const [a, b] = await Promise.all([rdapModule.run(entity('google.com'), ctx), rdapModule.run(entity('example.org'), ctx)]);
    expect(a.data.found && b.data.found).toBe(true);
    expect(b.data.record?.ldhName).toBe('example.org');
    expect(m.calls.filter((c) => c.url === BOOTSTRAP_URL)).toHaveLength(1);
  });
});
