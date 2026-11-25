import { describe, expect, it } from 'vitest';
import { RR, type RRType } from '@/lib/doh';
import { FetchError, isAbortError } from '@/lib/http';
import {
  dashedDomain,
  detectConsumer,
  dnsSignals,
  formatRegion,
  guessIdp,
  hasEopSpf,
  isConsumerDomain,
  isGenericIdpHost,
  isMsVerificationTxt,
  isOrgIdpHost,
  matchEopMx,
  parseDkimTarget,
  parseIssuer,
  parseOpenIdConfig,
  parseOpenIdError,
  parseUserRealm,
  type M365Dns,
} from '@/lib/m365';
import type { Fact } from '@/lib/types';
import { m365Module, type M365Data } from '@/modules/m365';
import { json, makeCtx, mockFetch, text, type Route } from './helpers';

// ------------------------------------------------------------------ fixtures
// Shapes from docs/research/pdns-m365-email.md §2-3 and live responses (2026-11-25).

const MS_TENANT = '72f988bf-86f1-41af-91ab-2d7cd011db47';
const CONTOSO_TENANT = '5b2c9e1a-3f4d-4e8b-9c7a-1d2e3f4a5b6c';
const DOD_TENANT = 'fae6d70f-954b-4811-92b6-0530d6f84c43';

function oidcConfig(tenant: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    token_endpoint: `https://login.microsoftonline.com/${tenant}/oauth2/token`,
    token_endpoint_auth_methods_supported: ['client_secret_post', 'private_key_jwt', 'client_secret_basic'],
    jwks_uri: 'https://login.microsoftonline.com/common/discovery/keys',
    response_modes_supported: ['query', 'fragment', 'form_post'],
    subject_types_supported: ['pairwise'],
    id_token_signing_alg_values_supported: ['RS256'],
    issuer: `https://sts.windows.net/${tenant}/`,
    tenant_region_scope: 'WW',
    cloud_instance_name: 'microsoftonline.com',
    cloud_graph_host_name: 'graph.windows.net',
    msgraph_host: 'graph.microsoft.com',
    rbac_url: 'https://pas.windows.net',
    ...extra,
  };
}

const AADSTS90002 = (d: string) => ({
  error: 'invalid_tenant',
  error_description: `AADSTS90002: Tenant '${d}' not found. Check to make sure you have the correct tenant ID and are signing into the correct cloud. Trace ID: bb29e0c9-259c-42ed-8694-f98a27bb5800 Correlation ID: 18c01362-8e2b-4043-85a4-fd0a92666e2d Timestamp: 2026-11-25 11:26:46Z`,
  error_codes: [90002],
  timestamp: '2026-11-25 11:26:46Z',
  trace_id: 'bb29e0c9-259c-42ed-8694-f98a27bb5800',
  correlation_id: '18c01362-8e2b-4043-85a4-fd0a92666e2d',
  error_uri: 'https://login.microsoftonline.com/error?code=90002',
});

const REALM_MANAGED_MS = {
  State: 4,
  UserState: 1,
  Login: 'probe@microsoft.com',
  NameSpaceType: 'Managed',
  DomainName: 'microsoft.com',
  FederationBrandName: 'Microsoft',
  CloudInstanceName: 'microsoftonline.com',
  CloudInstanceIssuerUri: 'urn:federation:MicrosoftOnline',
};

const REALM_FEDERATED_CONTOSO = {
  State: 3,
  UserState: 2,
  Login: 'probe@contoso.com',
  NameSpaceType: 'Federated',
  DomainName: 'contoso.com',
  FederationGlobalVersion: -1,
  AuthURL:
    'https://adfs.contoso.com/adfs/ls/?username=probe%40contoso.com&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=',
  FederationBrandName: 'Contoso Ltd',
  CloudInstanceName: 'microsoftonline.com',
  CloudInstanceIssuerUri: 'urn:federation:MicrosoftOnline',
};

const REALM_UNKNOWN = (d: string) => ({ State: 4, UserState: 1, Login: `probe@${d}`, NameSpaceType: 'Unknown' });

const REALM_CONSUMER = (d: string) => ({
  State: 3,
  UserState: 2,
  Login: `probe@${d}`,
  NameSpaceType: 'Federated',
  DomainName: 'live.com',
  FederationGlobalVersion: -1,
  AuthURL: `https://login.live.com/login.srf?username=probe%40${d}&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=`,
  FederationBrandName: 'Windows Live',
  AuthNForwardType: 1,
  CloudInstanceName: 'microsoftonline.com',
  CloudInstanceIssuerUri: 'urn:federation:MicrosoftOnline',
});

// ------------------------------------------------------------------ mocks

/** DNS zone keyed by `${name}|${TYPE}` with Cloudflare-style presentation data. */
type Zone = Record<string, string[]>;

/** Cloudflare + Google DoH mock. `fail` keys answer 503 on both resolvers. */
function doh(zone: Zone, fail: string[] = []): Route {
  return (url) => {
    if (url.hostname !== 'cloudflare-dns.com' && url.hostname !== 'dns.google') return undefined;
    const name = url.searchParams.get('name') ?? '';
    const type = (url.searchParams.get('type') ?? '') as RRType;
    const key = `${name}|${type}`;
    if (fail.includes(key)) return json({ error: 'upstream unavailable' }, 503);
    const answers = zone[key] ?? [];
    return json({
      Status: 0,
      TC: false,
      RD: true,
      RA: true,
      AD: false,
      CD: false,
      Question: [{ name, type: RR[type] }],
      ...(answers.length
        ? { Answer: answers.map((data) => ({ name, type: RR[type], TTL: 3600, data })) }
        : { Authority: [{ name, type: 6, TTL: 900, data: 'ns1.example. hostmaster.example. 1 7200 3600 1209600 3600' }] }),
    });
  };
}

function login(d: string, oidc: () => Response, realm: () => Response): Route {
  return (url) => {
    if (url.hostname !== 'login.microsoftonline.com') return undefined;
    if (url.pathname === `/${d}/.well-known/openid-configuration`) return oidc();
    if (url.pathname === '/getuserrealm.srf') return realm();
    return undefined;
  };
}

const ALLOWED_HOSTS = new Set(['login.microsoftonline.com', 'cloudflare-dns.com', 'dns.google']);

async function runFor(d: string, routes: Route[], signal?: AbortSignal) {
  const m = mockFetch(...routes);
  const ctx = makeCtx({ fetch: m.fetch, root: d, ...(signal ? { signal } : {}) });
  const out = await m365Module.run({ kind: 'domain', value: d, depth: 0 }, ctx);
  return { out, data: out.data, calls: m.calls };
}

const fact = (facts: Fact[], label: string) => facts.find((f) => f.label === label);
const factsOf = (data: M365Data, d: string) => m365Module.facts!(data, { kind: 'domain', value: d, depth: 0 });

const MS_ZONE: Zone = {
  'microsoft.com|MX': ['10 microsoft-com.mail.protection.outlook.com.'],
  'microsoft.com|TXT': [
    '"MS=ms44614987"',
    '"v=spf1 include:_spf-a.microsoft.com include:_spf-b.microsoft.com include:_spf-c.microsoft.com include:_spf-ssg-a.msft.net include:spf-a.hotmail.com include:_spf1-meo.microsoft.com -all"',
    '"google-site-verification=abc123"',
  ],
  'autodiscover.microsoft.com|CNAME': ['autodiscover.outlook.com.'],
  'selector1._domainkey.microsoft.com|CNAME': ['selector1-microsoft-com._domainkey.microsoft.onmicrosoft.com.'],
  'selector2._domainkey.microsoft.com|CNAME': ['selector2-microsoft-com._domainkey.microsoft.onmicrosoft.com.'],
};

const emptyDns = (over: Partial<M365Dns> = {}): M365Dns => ({
  mxEop: null,
  mx: [],
  mxTotal: 0,
  msTxt: [],
  spf: false,
  autodiscover: null,
  dkim: { selector1: null, selector2: null, initialDomain: null },
  failed: [],
  ...over,
});

// ------------------------------------------------------------------ parsers

describe('parseIssuer', () => {
  it('parses a v1 issuer (sts.windows.net)', () => {
    expect(parseIssuer(`https://sts.windows.net/${MS_TENANT}/`)).toEqual({
      tenantId: MS_TENANT,
      host: 'sts.windows.net',
      version: 'v1',
    });
  });

  it('parses a v2 issuer (login.microsoftonline.com/<guid>/v2.0)', () => {
    expect(parseIssuer(`https://login.microsoftonline.com/${MS_TENANT}/v2.0`)).toEqual({
      tenantId: MS_TENANT,
      host: 'login.microsoftonline.com',
      version: 'v2',
    });
    expect(parseIssuer(`https://login.microsoftonline.com/${MS_TENANT}/v2.0/`)?.version).toBe('v2');
  });

  it('handles sovereign hosts without hard-coding them', () => {
    expect(parseIssuer(`https://login.microsoftonline.us/${DOD_TENANT}/v2.0`)).toEqual({
      tenantId: DOD_TENANT,
      host: 'login.microsoftonline.us',
      version: 'v2',
    });
    expect(parseIssuer(`https://login.partner.microsoftonline.cn/${MS_TENANT}/v2.0`)?.host).toBe(
      'login.partner.microsoftonline.cn',
    );
    expect(parseIssuer(`https://sts.chinacloudapi.cn/${MS_TENANT}/`)).toMatchObject({ version: 'v1' });
  });

  it('lowercases the GUID and host', () => {
    expect(parseIssuer(`https://STS.Windows.NET/${MS_TENANT.toUpperCase()}/`)).toEqual({
      tenantId: MS_TENANT,
      host: 'sts.windows.net',
      version: 'v1',
    });
  });

  it('rejects garbage', () => {
    for (const bad of [
      null,
      undefined,
      42,
      {},
      '',
      '   ',
      'not a url',
      'https://sts.windows.net/',
      'https://login.microsoftonline.com/{tenantid}/v2.0',
      'https://sts.windows.net/------------------------------------/',
      `https://sts.windows.net/${MS_TENANT}x/`,
      `https://sts.windows.net/${MS_TENANT.slice(0, 35)}/`,
      `http://sts.windows.net/${MS_TENANT}/`,
      `javascript:alert(1)//${MS_TENANT}/`,
      `ftp://sts.windows.net/${MS_TENANT}/`,
    ]) {
      expect(parseIssuer(bad), String(bad)).toBeNull();
    }
  });
});

describe('parseOpenIdConfig / parseOpenIdError', () => {
  it('extracts tenant, region and cloud fields', () => {
    const cfg = parseOpenIdConfig(
      oidcConfig(DOD_TENANT, {
        tenant_region_scope: 'USGov',
        tenant_region_sub_scope: 'DOD',
        cloud_instance_name: 'microsoftonline.us',
        cloud_graph_host_name: 'graph.microsoftazure.us',
        msgraph_host: 'dod-graph.microsoft.us',
      }),
    );
    expect(cfg).toEqual({
      issuer: `https://sts.windows.net/${DOD_TENANT}/`,
      tenantId: DOD_TENANT,
      issuerHost: 'sts.windows.net',
      issuerVersion: 'v1',
      regionScope: 'USGov',
      regionSubScope: 'DOD',
      cloudInstance: 'microsoftonline.us',
      cloudGraphHost: 'graph.microsoftazure.us',
      msgraphHost: 'dod-graph.microsoft.us',
    });
    expect(formatRegion(cfg!.regionScope, cfg!.regionSubScope)).toBe('USGov (DOD)');
  });

  it('tolerates missing or mistyped optional fields', () => {
    const cfg = parseOpenIdConfig({
      issuer: `https://sts.windows.net/${MS_TENANT}/`,
      tenant_region_scope: 7,
      tenant_region_sub_scope: '<script>',
      cloud_instance_name: ['x'],
    });
    expect(cfg).toMatchObject({ tenantId: MS_TENANT, regionScope: null, regionSubScope: null, cloudInstance: null });
  });

  it('returns null without a usable issuer', () => {
    expect(parseOpenIdConfig(null)).toBeNull();
    expect(parseOpenIdConfig('oops')).toBeNull();
    expect(parseOpenIdConfig([oidcConfig(MS_TENANT)])).toBeNull();
    expect(parseOpenIdConfig({ issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0' })).toBeNull();
    expect(parseOpenIdConfig(AADSTS90002('x.com'))).toBeNull();
  });

  it('parses Entra ID error bodies', () => {
    expect(parseOpenIdError(AADSTS90002('x.com'))).toEqual({ error: 'invalid_tenant', code: 'AADSTS90002' });
    expect(
      parseOpenIdError({
        error: 'invalid_request',
        error_description: 'AADSTS50059: No tenant-identifying information found in either the request or implied by any provided credentials.',
      }),
    ).toEqual({ error: 'invalid_request', code: 'AADSTS50059' });
    expect(parseOpenIdError({ error_codes: ['x', 900023] })).toEqual({ error: null, code: 'AADSTS900023' });
    expect(parseOpenIdError({ hello: 'world' })).toBeNull();
    expect(parseOpenIdError(null)).toBeNull();
  });
});

describe('parseUserRealm', () => {
  it('parses a managed realm', () => {
    expect(parseUserRealm(REALM_MANAGED_MS)).toEqual({
      namespaceType: 'Managed',
      domainName: 'microsoft.com',
      federationBrandName: 'Microsoft',
      cloudInstance: 'microsoftonline.com',
      authUrl: null,
      authUrlHost: null,
    });
  });

  it('parses a federated realm and its AuthURL host', () => {
    const r = parseUserRealm(REALM_FEDERATED_CONTOSO)!;
    expect(r.namespaceType).toBe('Federated');
    expect(r.federationBrandName).toBe('Contoso Ltd');
    expect(r.authUrlHost).toBe('adfs.contoso.com');
    expect(guessIdp(r.authUrl, r.authUrlHost)).toBe('AD FS');
  });

  it('parses an unknown namespace', () => {
    expect(parseUserRealm(REALM_UNKNOWN('nx.com'))).toMatchObject({
      namespaceType: 'Unknown',
      domainName: null,
      authUrlHost: null,
    });
  });

  it('rejects junk and unsafe AuthURLs', () => {
    expect(parseUserRealm(null)).toBeNull();
    expect(parseUserRealm([])).toBeNull();
    expect(parseUserRealm({ State: 4 })).toBeNull();
    expect(parseUserRealm({ NameSpaceType: 12 })).toBeNull();
    const r = parseUserRealm({ NameSpaceType: 'Federated', AuthURL: 'javascript:alert(1)', DomainName: 'not a host!' });
    expect(r).toMatchObject({ namespaceType: 'Federated', authUrl: null, authUrlHost: null, domainName: null });
  });

  it('guesses common IdPs from the AuthURL', () => {
    expect(guessIdp('https://contoso.okta.com/app/office365/abc/sso/wsfed/passive', 'contoso.okta.com')).toBe('Okta');
    expect(guessIdp('https://accounts.google.com/o/saml2/idp?idpid=C01abc', 'accounts.google.com')).toBe(
      'Google Workspace',
    );
    expect(guessIdp('https://login.live.com/login.srf', 'login.live.com')).toBe('Microsoft account (consumer)');
    expect(guessIdp('https://idp.example.org/saml', 'idp.example.org')).toBeNull();
    expect(guessIdp(null, null)).toBeNull();
    // AD FS needs its /adfs/ path or an "adfs" host label; "sts." alone is also PingFederate/Shibboleth.
    expect(guessIdp('https://sts.example.org/idp/prp.wsf', 'sts.example.org')).toBeNull();
    expect(guessIdp('https://fs.example.org/sso', 'fs.example.org')).toBeNull();
    expect(guessIdp('https://sts.example.org/adfs/ls/', 'sts.example.org')).toBe('AD FS');
    expect(guessIdp('https://adfs2.example.org/x', 'adfs2.example.org')).toBe('AD FS');
    expect(isGenericIdpHost('accounts.google.com')).toBe(true);
    expect(isGenericIdpHost('auth.pingone.eu')).toBe(true);
    expect(isGenericIdpHost('sso.jumpcloud.com')).toBe(true);
    expect(isGenericIdpHost('contoso.okta.com')).toBe(false);
  });

  it('only org-specific, named AuthURL hosts are pivot-worthy', () => {
    expect(isOrgIdpHost('adfs.contoso.com')).toBe(true);
    expect(isOrgIdpHost('contoso.okta.com')).toBe(true);
    expect(isOrgIdpHost('accounts.google.com')).toBe(false);
    expect(isOrgIdpHost('login.live.com')).toBe(false);
    // An IP-literal AuthURL host passes the hostname check but is not a domain.
    expect(parseUserRealm({ NameSpaceType: 'Federated', AuthURL: 'https://10.1.2.3/adfs/ls/' })?.authUrlHost).toBe('10.1.2.3');
    expect(isOrgIdpHost('10.1.2.3')).toBe(false);
  });
});

describe('DNS corroboration parsers', () => {
  it('recognises Exchange Online MX hosts (legacy and mx.microsoft)', () => {
    expect(matchEopMx('contoso-com.mail.protection.outlook.com.')).toMatchObject({
      host: 'contoso-com.mail.protection.outlook.com',
      token: 'contoso-com',
      flavor: 'Exchange Online Protection',
    });
    expect(matchEopMx('contosotest-com.o-v1.mx.microsoft')).toMatchObject({
      token: 'contosotest-com',
      flavor: 'Exchange Online (DNSSEC MX)',
    });
    expect(matchEopMx('Contoso-de.mail.protection.outlook.de')?.token).toBe('contoso-de');
    expect(matchEopMx('contoso-com.mail.eo.outlook.com')).not.toBeNull();
    expect(matchEopMx('eu-smtp-inbound-1.mimecast.com')).toBeNull();
    expect(matchEopMx('mail.protection.outlook.com.evil.example')).toBeNull();
    expect(matchEopMx('')).toBeNull();
  });

  it('recognises MS= verification TXT and the EOP SPF include', () => {
    expect(isMsVerificationTxt('MS=ms44614987')).toBe(true);
    expect(isMsVerificationTxt('ms=MS12345678')).toBe(true);
    expect(isMsVerificationTxt(`MS=${'a1'.repeat(20)}`)).toBe(true);
    expect(isMsVerificationTxt('MS=ms')).toBe(false);
    expect(isMsVerificationTxt('v=spf1 -all')).toBe(false);
    expect(hasEopSpf('v=spf1 include:spf.protection.outlook.com -all')).toBe(true);
    expect(hasEopSpf('v=spf1 ip4:1.2.3.4 ~include:spf.protection.outlook.com ~all')).toBe(true);
    expect(hasEopSpf('v=spf1 include:spf.protection.outlook.com.evil.example -all')).toBe(false);
    expect(hasEopSpf('include:spf.protection.outlook.com')).toBe(false);
  });

  it('extracts the initial onmicrosoft.com domain from DKIM CNAME targets', () => {
    expect(parseDkimTarget('selector1-microsoft-com._domainkey.microsoft.onmicrosoft.com.')).toEqual({
      selector: 1,
      domainDashed: 'microsoft-com',
      initialDomain: 'microsoft.onmicrosoft.com',
      format: 'onmicrosoft',
    });
    // New format (custom domains added since May 2025).
    expect(parseDkimTarget('selector2-contoso-co-uk._domainkey.contosoltd.r-v1.dkim.mail.microsoft')).toEqual({
      selector: 2,
      domainDashed: 'contoso-co-uk',
      initialDomain: 'contosoltd.onmicrosoft.com',
      format: 'dkim.mail.microsoft',
    });
    expect(parseDkimTarget('selector1-agency-gov._domainkey.agency.onmicrosoft.us')?.initialDomain).toBe(
      'agency.onmicrosoft.us',
    );
    expect(parseDkimTarget('s1.domainkey.u298828.wl079.sendgrid.net')).toBeNull();
    expect(parseDkimTarget('selector3-x-com._domainkey.x.onmicrosoft.com')).toBeNull();
    expect(parseDkimTarget(null)).toBeNull();
    expect(dashedDomain('Contoso.co.uk')).toBe('contoso-co-uk');
  });

  it('builds a human-readable signal list', () => {
    const signals = dnsSignals(
      emptyDns({
        mxEop: 'contoso-com.mail.protection.outlook.com',
        msTxt: ['MS=ms12345678'],
        spf: true,
        autodiscover: 'autodiscover.outlook.com',
        dkim: {
          selector1: 'selector1-contoso-com._domainkey.contoso.onmicrosoft.com',
          selector2: 'something.else.example',
          initialDomain: 'contoso.onmicrosoft.com',
        },
      }),
    );
    expect(signals).toEqual([
      'MX → Exchange Online Protection: contoso-com.mail.protection.outlook.com',
      'Domain-verification TXT MS=ms12345678',
      'SPF includes spf.protection.outlook.com',
      'autodiscover CNAME → autodiscover.outlook.com',
      'DKIM selector1 CNAME → selector1-contoso-com._domainkey.contoso.onmicrosoft.com (initial domain contoso.onmicrosoft.com)',
    ]);
    expect(dnsSignals(emptyDns({ autodiscover: 'mail.contoso.com', mx: ['mx.contoso.com'], mxTotal: 1 }))).toEqual([]);
  });
});

describe('consumer detection', () => {
  it('flags known consumer domains, MSA tenant GUIDs and live.com realms', () => {
    expect(isConsumerDomain('outlook.com')).toBe(true);
    expect(isConsumerDomain('Hotmail.co.uk.')).toBe(true);
    expect(isConsumerDomain('outlook.co.uk')).toBe(false); // a normal Managed org tenant (live check)
    expect(detectConsumer('gmail.com', '9cd80435-793b-4f48-844b-6b3f37d1c1f3', null)).toBe(true);
    expect(detectConsumer('example.net', null, { domainName: 'live.com', authUrlHost: null })).toBe(true);
    expect(detectConsumer('example.net', null, { domainName: null, authUrlHost: 'login.live.com' })).toBe(true);
    expect(detectConsumer('contoso.com', CONTOSO_TENANT, { domainName: 'contoso.com', authUrlHost: 'adfs.contoso.com' })).toBe(
      false,
    );
  });

  it('uses the MSA tenant GUID only as a fallback to the realm', () => {
    const msa = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a';
    // Realm lookup failed: the GUID decides.
    expect(detectConsumer('example.net', msa, null)).toBe(true);
    // Realm points elsewhere: still consumer.
    expect(detectConsumer('example.net', msa, { domainName: 'other.example', authUrlHost: null })).toBe(true);
    // Realm confirms the domain itself as an ordinary org realm: a Microsoft-owned org domain, not MSA.
    expect(detectConsumer('Example.NET.', msa, { domainName: 'example.net', authUrlHost: null })).toBe(false);
    // ...unless that realm is federated to login.live.com.
    expect(detectConsumer('example.net', msa, { domainName: 'example.net', authUrlHost: 'login.live.com' })).toBe(true);
  });
});

// ------------------------------------------------------------------ module

describe('m365Module', () => {
  it('has the expected metadata', () => {
    expect(m365Module).toMatchObject({ id: 'm365', version: 1, accepts: ['domain'], ttl: 7 * 24 * 3600 * 1000 });
    expect(m365Module.active).toBeFalsy();
    expect(m365Module.key).toBeUndefined();
  });

  it('managed tenant with full DNS corroboration (microsoft.com)', async () => {
    const d = 'microsoft.com';
    const { out, data, calls } = await runFor(d, [
      login(d, () => json(oidcConfig(MS_TENANT)), () => json(REALM_MANAGED_MS)),
      doh(MS_ZONE),
    ]);

    expect(data).toMatchObject({
      tenant: true,
      tenantId: MS_TENANT,
      issuerHost: 'sts.windows.net',
      cloudInstance: 'microsoftonline.com',
      region: { scope: 'WW', subScope: null },
      namespaceType: 'Managed',
      federationBrandName: 'Microsoft',
      authUrlHost: null,
      consumerDomain: false,
      noTenantReason: null,
      realmError: null,
      notes: [],
    });
    expect(data.dns).toEqual({
      mxEop: 'microsoft-com.mail.protection.outlook.com',
      mx: ['microsoft-com.mail.protection.outlook.com'],
      mxTotal: 1,
      msTxt: ['MS=ms44614987'],
      spf: false,
      autodiscover: 'autodiscover.outlook.com',
      dkim: {
        selector1: 'selector1-microsoft-com._domainkey.microsoft.onmicrosoft.com',
        selector2: 'selector2-microsoft-com._domainkey.microsoft.onmicrosoft.com',
        initialDomain: 'microsoft.onmicrosoft.com',
      },
      failed: [],
    });
    expect(data.signals).toHaveLength(5);
    expect(out.summary).toBe('Tenant 72f988bf… · Managed · WW · MX→EOP');
    expect(out.pivots).toEqual([{ kind: 'domain', value: 'microsoft.onmicrosoft.com', note: 'M365 initial domain (DKIM)' }]);
    expect(JSON.parse(JSON.stringify(data))).toEqual(data);

    expect(m365Module.headline!(data, { kind: 'domain', value: d, depth: 0 })).toEqual({
      m365: { tenant: true, tenantId: MS_TENANT, namespaceType: 'Managed', region: 'WW' },
    });

    const facts = factsOf(data, d);
    expect(fact(facts, 'Tenant ID')).toEqual({ label: 'Tenant ID', value: MS_TENANT, pivot: true });
    expect(fact(facts, 'Initial domain')).toMatchObject({ value: 'microsoft.onmicrosoft.com', pivot: true });
    expect(fact(facts, 'MX')).toMatchObject({ tone: 'good' });
    expect(fact(facts, 'Autodiscover CNAME')).toMatchObject({ value: 'autodiscover.outlook.com', tone: 'good' });
    expect(fact(facts, 'DKIM selector2')).toMatchObject({ tone: 'good' });
    expect(fact(facts, 'Note')).toBeUndefined();
    for (const f of facts) expect(f.href).toBeUndefined();

    // Only resolvers and Microsoft's login service; never the domain itself.
    for (const c of calls) expect(ALLOWED_HOSTS.has(new URL(c.url).hostname), c.url).toBe(true);
    const realmCall = calls.find((c) => c.url.includes('getuserrealm.srf'))!;
    const u = new URL(realmCall.url);
    expect(realmCall.url).toContain('login=probe%40microsoft.com');
    expect([...u.searchParams.keys()]).toEqual(['login', 'json']);
    expect(u.searchParams.get('login')).toBe('probe@microsoft.com');
    expect(u.searchParams.get('json')).toBe('1');
    // Nothing else is sent: plain GET, no body, no headers beyond accept.
    expect(realmCall.init.method).toBe('GET');
    expect(realmCall.init.body).toBeUndefined();
    expect(Object.keys(realmCall.init.headers as Record<string, string>)).toEqual(['accept']);
    const oidcCall = calls.find((c) => c.url.includes('openid-configuration'))!;
    expect(oidcCall.url).toBe('https://login.microsoftonline.com/microsoft.com/.well-known/openid-configuration');
    for (const c of calls) expect(c.init.credentials).toBe('omit');
  });

  it('federation via a shared IdP host or an IP literal yields no domain pivot', async () => {
    const d = 'corp.example';
    const realm = (authUrl: string) => ({ ...REALM_FEDERATED_CONTOSO, Login: `probe@${d}`, DomainName: d, AuthURL: authUrl });

    const google = await runFor(d, [
      login(d, () => json(oidcConfig(CONTOSO_TENANT)), () => json(realm('https://accounts.google.com/o/saml2/idp?idpid=C01abc'))),
      doh({}),
    ]);
    expect(google.data).toMatchObject({ tenant: true, authUrlHost: 'accounts.google.com', idp: 'Google Workspace' });
    expect(google.out.pivots).toBeUndefined();
    expect(fact(factsOf(google.data, d), 'Auth URL host')).toMatchObject({ value: 'accounts.google.com', pivot: false });

    const ip = await runFor(d, [
      login(d, () => json(oidcConfig(CONTOSO_TENANT)), () => json(realm('https://10.1.2.3/adfs/ls/?username=probe%40corp.example'))),
      doh({}),
    ]);
    expect(ip.data).toMatchObject({ authUrlHost: '10.1.2.3', idp: 'AD FS' });
    expect(ip.out.pivots).toBeUndefined();
  });

  it('a Microsoft-owned tenant whose realm names the domain itself is reported as a tenant, not MSA', async () => {
    const d = 'msft-service.example';
    const msa = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a';
    const { data } = await runFor(d, [
      login(d, () => json(oidcConfig(msa)), () => json({ ...REALM_MANAGED_MS, Login: `probe@${d}`, DomainName: d })),
      doh({}),
    ]);
    expect(data).toMatchObject({ tenant: true, consumerDomain: false, tenantId: msa });
  });

  it('federated tenant: AuthURL host, IdP, region, new-format DKIM and DNSSEC MX', async () => {
    const d = 'contoso.com';
    const zone: Zone = {
      'contoso.com|MX': ['20 backup.contoso.com.', '10 contoso-com.o-v1.mx.microsoft.'],
      // Cloudflare returns split TXT character-strings quoted.
      'contoso.com|TXT': ['"MS=ms83920174"', '"v=spf1 include:spf.protection." "outlook.com -all"'],
      'autodiscover.contoso.com|CNAME': ['autodiscover.outlook.com.'],
      'selector1._domainkey.contoso.com|CNAME': ['selector1-contoso-com._domainkey.contosoltd.n-v1.dkim.mail.microsoft.'],
      'selector2._domainkey.contoso.com|CNAME': ['selector2-contoso-com._domainkey.contosoltd.n-v1.dkim.mail.microsoft.'],
    };
    const { out, data } = await runFor(d, [
      login(d, () => json(oidcConfig(CONTOSO_TENANT, { tenant_region_scope: 'NA' })), () => json(REALM_FEDERATED_CONTOSO)),
      doh(zone),
    ]);
    expect(data).toMatchObject({
      tenant: true,
      namespaceType: 'Federated',
      federationBrandName: 'Contoso Ltd',
      authUrlHost: 'adfs.contoso.com',
      idp: 'AD FS',
      region: { scope: 'NA', subScope: null },
    });
    expect(data.dns.mx).toEqual(['contoso-com.o-v1.mx.microsoft', 'backup.contoso.com']);
    expect(data.dns.mxEop).toBe('contoso-com.o-v1.mx.microsoft');
    expect(data.dns.spf).toBe(true);
    expect(data.dns.msTxt).toEqual(['MS=ms83920174']);
    expect(data.dns.dkim.initialDomain).toBe('contosoltd.onmicrosoft.com');
    expect(out.summary).toBe('Tenant 5b2c9e1a… · Federated (adfs.contoso.com) · NA · MX→EOP');
    expect(out.pivots).toEqual([
      { kind: 'domain', value: 'contosoltd.onmicrosoft.com', note: 'M365 initial domain (DKIM)' },
      { kind: 'domain', value: 'adfs.contoso.com', note: 'Federation IdP (AuthURL host)' },
    ]);
    const facts = factsOf(data, d);
    expect(fact(facts, 'Auth URL host')).toMatchObject({ value: 'adfs.contoso.com', pivot: true });
    expect(fact(facts, 'Federation brand')).toMatchObject({ value: 'Contoso Ltd' });
    expect(fact(facts, 'Namespace type')).toMatchObject({ value: 'Federated' });
    expect(fact(facts, 'Region')).toMatchObject({ value: 'NA' });
    expect(fact(facts, 'SPF')).toMatchObject({ tone: 'good' });
    expect(m365Module.headline!(data, { kind: 'domain', value: d, depth: 0 })).toEqual({
      m365: { tenant: true, tenantId: CONTOSO_TENANT, namespaceType: 'Federated', region: 'NA' },
    });
  });

  it('sovereign (US Gov) tenant keeps region sub-scope and cloud instance', async () => {
    const d = 'agency.mil';
    const cfg = oidcConfig(DOD_TENANT, {
      tenant_region_scope: 'USGov',
      tenant_region_sub_scope: 'DOD',
      cloud_instance_name: 'microsoftonline.us',
      msgraph_host: 'dod-graph.microsoft.us',
    });
    const { out, data } = await runFor(d, [
      login(d, () => json(cfg), () => json({ ...REALM_MANAGED_MS, Login: `probe@${d}`, DomainName: d, CloudInstanceName: 'microsoftonline.us' })),
      doh({}),
    ]);
    expect(data.cloudInstance).toBe('microsoftonline.us');
    expect(data.graphHost).toBe('dod-graph.microsoft.us');
    expect(out.summary).toBe('Tenant fae6d70f… · Managed · USGov (DOD)');
    // Tenant with no MX at all is called out.
    expect(data.notes).toEqual(['Tenant exists but the domain has no MX records (not used for Exchange Online mail).']);
    expect(m365Module.headline!(data, { kind: 'domain', value: d, depth: 0 }).m365?.region).toBe('USGov (DOD)');
  });

  it('OIDC HTTP 400 (AADSTS90002) means no tenant', async () => {
    const d = 'nonexistent-zzq-example.com';
    const { out, data } = await runFor(d, [
      login(d, () => json(AADSTS90002(d), 400), () => json(REALM_UNKNOWN(d))),
      doh({ [`${d}|MX`]: ['10 mx.nonexistent-zzq-example.com.'] }),
    ]);
    expect(data).toMatchObject({
      tenant: false,
      tenantId: null,
      issuerHost: null,
      namespaceType: 'Unknown',
      consumerDomain: false,
      noTenantReason: 'AADSTS90002',
      notes: [],
      signals: [],
    });
    expect(out.summary).toBe('No Entra ID tenant');
    expect(out.pivots).toBeUndefined();
    expect(m365Module.headline!(data, { kind: 'domain', value: d, depth: 0 })).toEqual({
      m365: { tenant: false, namespaceType: 'Unknown' },
    });
    const facts = factsOf(data, d);
    expect(fact(facts, 'Tenant')).toMatchObject({ value: 'No Entra ID tenant (AADSTS90002)' });
    expect(fact(facts, 'Tenant ID')).toBeUndefined();
    expect(fact(facts, 'MX (not Microsoft)')).toMatchObject({ value: ['mx.nonexistent-zzq-example.com'] });
  });

  it('OIDC 400/404 with a non-JSON body is still "no tenant"', async () => {
    const d = 'example.org';
    const { data } = await runFor(d, [
      login(d, () => text('<html>Bad Request</html>', 400), () => json(REALM_UNKNOWN(d))),
      doh({}),
    ]);
    expect(data.tenant).toBe(false);
    expect(data.noTenantReason).toBe('HTTP 400');

    const { data: d404 } = await runFor(d, [
      login(d, () => json({ error: 'not_found' }, 404), () => json(REALM_UNKNOWN(d))),
      doh({}),
    ]);
    expect(d404.tenant).toBe(false);
    expect(d404.noTenantReason).toBe('not_found');
  });

  it('no tenant but DNS still points at Microsoft 365: mismatch note', async () => {
    const d = 'former.example';
    const { out, data } = await runFor(d, [
      login(d, () => json(AADSTS90002(d), 400), () => json(REALM_UNKNOWN(d))),
      doh({
        [`${d}|MX`]: ['0 former-example.mail.protection.outlook.com.'],
        [`selector1._domainkey.${d}|CNAME`]: ['selector1-former-example._domainkey.formerco.onmicrosoft.com.'],
      }),
    ]);
    expect(data.tenant).toBe(false);
    expect(data.signals).toHaveLength(2);
    expect(data.notes).toEqual([
      'No Entra ID tenant claims this domain, but DNS still points to Microsoft 365 (stale records, or the domain was removed from its tenant).',
    ]);
    expect(out.summary).toBe('No Entra ID tenant · DNS points to M365');
    expect(fact(factsOf(data, d), 'Note')).toMatchObject({ tone: 'warn' });
  });

  it('tenant exists but MX points elsewhere: mismatch note', async () => {
    const d = 'contoso.com';
    const { out, data } = await runFor(d, [
      login(d, () => json(oidcConfig(CONTOSO_TENANT, { tenant_region_scope: 'EU' })), () => json(REALM_FEDERATED_CONTOSO)),
      doh({ 'contoso.com|MX': ['10 eu-smtp-inbound-1.mimecast.com.', '10 eu-smtp-inbound-2.mimecast.com.'] }),
    ]);
    expect(data.dns.mxEop).toBeNull();
    expect(data.notes[0]).toBe(
      'Tenant exists but MX points elsewhere (eu-smtp-inbound-1.mimecast.com +1): third-party mail gateway, or mailboxes not in Exchange Online.',
    );
    expect(out.summary).toBe('Tenant 5b2c9e1a… · Federated (adfs.contoso.com) · EU · MX elsewhere');
    expect(fact(factsOf(data, d), 'MX (not Microsoft)')?.value).toEqual([
      'eu-smtp-inbound-1.mimecast.com',
      'eu-smtp-inbound-2.mimecast.com',
    ]);
  });

  it('flags OIDC/realm disagreement and differing DKIM tenants', async () => {
    const d = 'odd.example';
    const { data } = await runFor(d, [
      login(d, () => json(oidcConfig(CONTOSO_TENANT)), () => json(REALM_UNKNOWN(d))),
      doh({
        [`${d}|MX`]: ['10 odd-example.mail.protection.outlook.com.'],
        [`selector1._domainkey.${d}|CNAME`]: ['selector1-odd-example._domainkey.tenanta.onmicrosoft.com.'],
        [`selector2._domainkey.${d}|CNAME`]: ['selector2-odd-example._domainkey.tenantb.onmicrosoft.com.'],
      }),
    ]);
    expect(data.dns.dkim.initialDomain).toBe('tenanta.onmicrosoft.com');
    expect(data.notes).toEqual([
      'OIDC discovery found a tenant but the user-realm lookup reports namespace "Unknown".',
      'DKIM selectors point to different tenants (tenanta.onmicrosoft.com vs tenantb.onmicrosoft.com).',
    ]);
    expect(fact(factsOf(data, d), 'Namespace type')).toMatchObject({ value: 'Unknown', tone: 'warn' });
  });

  it('consumer domain (outlook.com) is flagged, not reported as an org tenant', async () => {
    const d = 'outlook.com';
    const msa = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a';
    const { out, data } = await runFor(d, [
      login(d, () => json(oidcConfig(msa)), () => json(REALM_CONSUMER(d))),
      doh({ 'outlook.com|MX': ['5 outlook-com.olc.protection.outlook.com.'] }),
    ]);
    expect(data).toMatchObject({
      tenant: false,
      consumerDomain: true,
      tenantId: msa,
      authUrlHost: 'login.live.com',
      realmDomain: 'live.com',
      notes: [],
    });
    expect(out.summary).toBe('Consumer Microsoft account domain (MSA) · no org tenant');
    expect(out.pivots).toBeUndefined();
    expect(m365Module.headline!(data, { kind: 'domain', value: d, depth: 0 })).toEqual({
      m365: { tenant: false, namespaceType: 'Consumer (MSA)' },
    });
    const facts = factsOf(data, d);
    expect(fact(facts, 'Tenant ID')).toBeUndefined();
    expect(fact(facts, 'MSA tenant ID')).toEqual({ label: 'MSA tenant ID', value: msa });
    expect(fact(facts, 'Auth URL host')).toMatchObject({ pivot: false });
  });

  it('consumer flag also comes from the realm / MSA tenant GUID (gmail.com)', async () => {
    const d = 'gmail.com';
    const { data } = await runFor(d, [
      login(d, () => json(oidcConfig('9cd80435-793b-4f48-844b-6b3f37d1c1f3')), () => json(REALM_CONSUMER(d))),
      doh({ 'gmail.com|MX': ['5 gmail-smtp-in.l.google.com.'] }),
    ]);
    expect(data.consumerDomain).toBe(true);
    expect(data.tenant).toBe(false);
  });

  it('throws on genuine OIDC failures (5xx, garbage 200)', async () => {
    const d = 'contoso.com';
    const err = await runFor(d, [
      login(d, () => json({ error: 'temporarily_unavailable' }, 503), () => json(REALM_FEDERATED_CONTOSO)),
      doh(MS_ZONE),
    ]).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(FetchError);
    expect((err as FetchError).status).toBe(503);

    const err2 = await runFor(d, [
      login(d, () => json({ hello: 'world' }), () => json(REALM_FEDERATED_CONTOSO)),
      doh({}),
    ]).catch((e: unknown) => e);
    expect(err2).toBeInstanceOf(Error);
    expect((err2 as Error).message).toMatch(/Unexpected OpenID configuration/);
  });

  it('a failing user-realm lookup is recorded, not fatal', async () => {
    const d = 'microsoft.com';
    const { out, data } = await runFor(d, [
      login(d, () => json(oidcConfig(MS_TENANT)), () => text('<html>oops</html>', 500)),
      doh(MS_ZONE),
    ]);
    expect(data.tenant).toBe(true);
    expect(data.namespaceType).toBeNull();
    expect(data.realmError).toMatch(/HTTP 500/);
    expect(out.summary).toBe('Tenant 72f988bf… · WW · MX→EOP');
    expect(fact(factsOf(data, d), 'User-realm lookup')).toMatchObject({ tone: 'warn' });

    const { data: junk } = await runFor(d, [
      login(d, () => json(oidcConfig(MS_TENANT)), () => json({ State: 4 })),
      doh(MS_ZONE),
    ]);
    expect(junk.realmError).toBe('Unexpected user-realm response');
  });

  it('failing DNS lookups do not fail the module', async () => {
    const d = 'microsoft.com';
    const { out, data } = await runFor(d, [
      login(d, () => json(oidcConfig(MS_TENANT)), () => json(REALM_MANAGED_MS)),
      doh(MS_ZONE, ['microsoft.com|MX', 'selector1._domainkey.microsoft.com|CNAME']),
    ]);
    expect(data.tenant).toBe(true);
    expect(data.dns.failed.sort()).toEqual(['DKIM selector1', 'MX']);
    expect(data.dns.mx).toEqual([]);
    expect(data.dns.dkim.selector1).toBeNull();
    // selector2 still yields the initial domain.
    expect(data.dns.dkim.initialDomain).toBe('microsoft.onmicrosoft.com');
    // A failed MX lookup is not "no MX" and not "MX elsewhere".
    expect(data.notes).toEqual([]);
    expect(out.summary).toBe('Tenant 72f988bf… · Managed · WW');
    const facts = factsOf(data, d);
    expect(fact(facts, 'MX')).toEqual({ label: 'MX', value: 'lookup failed', tone: 'warn' });
    expect(fact(facts, 'DNS lookups failed')).toMatchObject({ value: ['DKIM selector1'], tone: 'warn' });
  });

  it('caps long MX lists but records the total', async () => {
    const d = 'big.example';
    const mx = Array.from({ length: 14 }, (_, i) => `${i + 1} mx${i + 1}.big.example.`);
    const { data } = await runFor(d, [
      login(d, () => json(oidcConfig(CONTOSO_TENANT)), () => json(REALM_UNKNOWN(d))),
      doh({ [`${d}|MX`]: mx }),
    ]);
    expect(data.dns.mx).toHaveLength(10);
    expect(data.dns.mxTotal).toBe(14);
    expect(fact(factsOf(data, d), 'MX (not Microsoft)')?.value).toContain('… 4 more');
  });

  it('cancellation propagates instead of caching a partial result', async () => {
    const ac = new AbortController();
    ac.abort();
    const d = 'contoso.com';
    const err = await runFor(
      d,
      [login(d, () => json(oidcConfig(CONTOSO_TENANT)), () => json(REALM_FEDERATED_CONTOSO)), doh({})],
      ac.signal,
    ).catch((e: unknown) => e);
    expect(isAbortError(err)).toBe(true);
  });

  it('a cancel during the (non-fatal) realm lookup is not swallowed', async () => {
    const ac = new AbortController();
    const d = 'contoso.com';
    const realmAborts: Route = (url) => {
      if (url.hostname !== 'login.microsoftonline.com' || url.pathname !== '/getuserrealm.srf') return undefined;
      ac.abort();
      return Promise.reject(new DOMException('The operation was aborted.', 'AbortError'));
    };
    const err = await runFor(
      d,
      [realmAborts, login(d, () => json(oidcConfig(CONTOSO_TENANT)), () => json(REALM_FEDERATED_CONTOSO)), doh(MS_ZONE)],
      ac.signal,
    ).then(
      () => 'resolved',
      (e: unknown) => e,
    );
    expect(err).not.toBe('resolved');
    expect(isAbortError(err)).toBe(true);
  });
});
