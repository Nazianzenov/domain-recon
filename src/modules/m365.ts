import { dohQuery, parseMx, recordsOf, stripDot, valuesOf, type DohResult, type RRType } from '@/lib/doh';
import { FetchError, isAbortError } from '@/lib/http';
import {
  MAX_MS_TXT,
  MAX_MX,
  detectConsumer,
  dnsSignals,
  formatRegion,
  guessIdp,
  hasEopSpf,
  hasM365Dns,
  isGenericIdpHost,
  isM365Autodiscover,
  isMsVerificationTxt,
  isOrgIdpHost,
  matchEopMx,
  parseDkimTarget,
  parseOpenIdConfig,
  parseOpenIdError,
  parseUserRealm,
  type M365Dns,
  type OpenIdConfig,
  type UserRealm,
} from '@/lib/m365';
import type { Ctx, Entity, Fact, JsonResponse, Module, Pivot } from '@/lib/types';
import { DAY } from '@/lib/types';

export interface M365Data {
  /** An organisational Entra ID tenant claims this domain (false for consumer/MSA domains). */
  tenant: boolean;
  /** Tenant GUID from the OIDC issuer (for consumer domains: Microsoft's own tenant). */
  tenantId: string | null;
  issuerHost: string | null;
  cloudInstance: string | null;
  region: { scope: string | null; subScope: string | null };
  /** From getuserrealm: Managed | Federated | Unknown. */
  namespaceType: string | null;
  federationBrandName: string | null;
  authUrlHost: string | null;
  /** Domain maps to Microsoft's consumer (Microsoft account) tenant. */
  consumerDomain: boolean;
  dns: M365Dns;
  /** Human-readable DNS corroboration list. */
  signals: string[];
  /** Extensions beyond the spec shape. */
  authUrl: string | null;
  /** Identity-provider product guessed from the AuthURL. */
  idp: string | null;
  /** DomainName the realm resolved to (differs for consumer domains and some subdomains). */
  realmDomain: string | null;
  graphHost: string | null;
  /** Why OIDC discovery found no tenant, e.g. "AADSTS90002". */
  noTenantReason: string | null;
  /** getuserrealm failed (the module still reports OIDC + DNS). */
  realmError: string | null;
  /** Mismatch / consistency notes. */
  notes: string[];
}

const LOGIN = 'https://login.microsoftonline.com';

type Oidc = { kind: 'tenant'; cfg: OpenIdConfig } | { kind: 'none'; reason: string };

function errorMessage(err: unknown): string {
  return (err instanceof Error ? err.message : String(err)).slice(0, 200);
}

/**
 * OIDC discovery. Unknown tenants answer HTTP 400 (AADSTS90002 / 50059 /
 * 900023 ...): that is "no tenant", not a failure. Anything else unexpected throws.
 */
async function discoverTenant(ctx: Ctx, d: string): Promise<Oidc> {
  const url = `${LOGIN}/${encodeURIComponent(d)}/.well-known/openid-configuration`;
  let res: JsonResponse<unknown>;
  try {
    res = await ctx.fetchJson<unknown>(url, { okStatuses: [400, 404] });
  } catch (err) {
    // 400/404 with a non-JSON body: still no tenant.
    if (err instanceof FetchError && err.kind === 'parse' && (err.status === 400 || err.status === 404)) {
      return { kind: 'none', reason: `HTTP ${err.status}` };
    }
    throw err;
  }
  if (res.status === 400 || res.status === 404) {
    const e = parseOpenIdError(res.data);
    return { kind: 'none', reason: e?.code ?? e?.error ?? `HTTP ${res.status}` };
  }
  const cfg = parseOpenIdConfig(res.data);
  if (cfg) return { kind: 'tenant', cfg };
  const e = parseOpenIdError(res.data);
  if (e) return { kind: 'none', reason: e.code ?? e.error ?? 'error' };
  throw new Error('Unexpected OpenID configuration response (no tenant issuer)');
}

/** getuserrealm.srf (undocumented). A failure is recorded, never fatal. */
async function lookupRealm(ctx: Ctx, d: string): Promise<{ realm: UserRealm | null; error: string | null }> {
  // Fixed fake local-part; nothing else is sent.
  const url = `${LOGIN}/getuserrealm.srf?login=${encodeURIComponent(`probe@${d}`)}&json=1`;
  try {
    const res = await ctx.fetchJson<unknown>(url);
    const realm = parseUserRealm(res.data);
    return realm ? { realm, error: null } : { realm: null, error: 'Unexpected user-realm response' };
  } catch (err) {
    if (isAbortError(err)) throw err;
    return { realm: null, error: errorMessage(err) };
  }
}

/** DoH lookup that records failures instead of throwing (except cancellation). */
async function safeDoh(ctx: Ctx, name: string, type: RRType, label: string, failed: string[]): Promise<DohResult | null> {
  try {
    const res = await dohQuery(ctx, name, type);
    // NOERROR and NXDOMAIN are answers; SERVFAIL/REFUSED/... are failures.
    if (res.status !== 0 && res.status !== 3) {
      failed.push(label);
      return null;
    }
    return res;
  } catch (err) {
    if (isAbortError(err)) throw err;
    failed.push(label);
    return null;
  }
}

function cnameTarget(res: DohResult | null, name: string): string | null {
  if (!res) return null;
  const recs = recordsOf(res, 'CNAME');
  const own = recs.find((r) => r.name === name) ?? recs[0];
  return own ? stripDot(own.data) || null : null;
}

async function collectDns(ctx: Ctx, d: string): Promise<M365Dns> {
  const failed: string[] = [];
  const auto = `autodiscover.${d}`;
  const s1 = `selector1._domainkey.${d}`;
  const s2 = `selector2._domainkey.${d}`;
  const [mxRes, txtRes, autoRes, s1Res, s2Res] = await Promise.all([
    safeDoh(ctx, d, 'MX', 'MX', failed),
    safeDoh(ctx, d, 'TXT', 'TXT', failed),
    safeDoh(ctx, auto, 'CNAME', 'autodiscover CNAME', failed),
    safeDoh(ctx, s1, 'CNAME', 'DKIM selector1', failed),
    safeDoh(ctx, s2, 'CNAME', 'DKIM selector2', failed),
  ]);

  const mxs = (mxRes ? valuesOf(mxRes, 'MX') : [])
    .map(parseMx)
    .filter((m): m is NonNullable<typeof m> => m !== null && m.exchange !== '')
    .sort((a, b) => a.preference - b.preference)
    .map((m) => m.exchange);
  const mx = [...new Set(mxs)];
  const mxEop = mx.find((h) => matchEopMx(h)) ?? null;

  const txts = txtRes ? valuesOf(txtRes, 'TXT') : [];
  const msAll = [...new Set(txts.map((t) => t.trim()).filter(isMsVerificationTxt))];

  const selector1 = cnameTarget(s1Res, s1);
  const selector2 = cnameTarget(s2Res, s2);
  const initialDomain = parseDkimTarget(selector1)?.initialDomain ?? parseDkimTarget(selector2)?.initialDomain ?? null;

  return {
    mxEop,
    mx: mx.slice(0, MAX_MX),
    mxTotal: mx.length,
    msTxt: msAll.slice(0, MAX_MS_TXT),
    spf: txts.some(hasEopSpf),
    autodiscover: cnameTarget(autoRes, auto),
    dkim: { selector1, selector2, initialDomain },
    failed,
  };
}

function buildNotes(d: string, data: Omit<M365Data, 'notes'>, oidcTenant: boolean): string[] {
  const notes: string[] = [];
  const { dns } = data;
  const mxOk = !dns.failed.includes('MX');
  if (data.tenant) {
    if (mxOk && dns.mxTotal > 0 && !dns.mxEop) {
      const more = dns.mxTotal > 1 ? ` +${dns.mxTotal - 1}` : '';
      notes.push(
        `Tenant exists but MX points elsewhere (${dns.mx[0] ?? ''}${more}): third-party mail gateway, or mailboxes not in Exchange Online.`,
      );
    } else if (mxOk && dns.mxTotal === 0) {
      notes.push('Tenant exists but the domain has no MX records (not used for Exchange Online mail).');
    }
    if (data.namespaceType === 'Unknown') {
      notes.push('OIDC discovery found a tenant but the user-realm lookup reports namespace "Unknown".');
    }
  } else if (!data.consumerDomain) {
    if (hasM365Dns(dns)) {
      notes.push(
        'No Entra ID tenant claims this domain, but DNS still points to Microsoft 365 (stale records, or the domain was removed from its tenant).',
      );
    }
    if (!oidcTenant && (data.namespaceType === 'Managed' || data.namespaceType === 'Federated')) {
      notes.push(`User-realm lookup reports ${data.namespaceType}, but OIDC discovery found no tenant.`);
    }
  }
  if (!data.consumerDomain && data.realmDomain && data.realmDomain !== d) {
    notes.push(`User realm resolved to ${data.realmDomain}, not ${d}.`);
  }
  const p1 = parseDkimTarget(dns.dkim.selector1);
  const p2 = parseDkimTarget(dns.dkim.selector2);
  if (p1 && p2 && p1.initialDomain !== p2.initialDomain) {
    notes.push(`DKIM selectors point to different tenants (${p1.initialDomain} vs ${p2.initialDomain}).`);
  }
  return notes;
}

function summarize(data: M365Data): string {
  if (data.consumerDomain) return 'Consumer Microsoft account domain (MSA) · no org tenant';
  if (!data.tenant) return `No Entra ID tenant${hasM365Dns(data.dns) ? ' · DNS points to M365' : ''}`;
  const parts: string[] = [];
  parts.push(data.tenantId ? `Tenant ${data.tenantId.slice(0, 8)}…` : 'Tenant');
  if (data.namespaceType) {
    parts.push(
      data.namespaceType === 'Federated' && data.authUrlHost ? `Federated (${data.authUrlHost})` : data.namespaceType,
    );
  }
  const region = formatRegion(data.region.scope, data.region.subScope);
  if (region) parts.push(region);
  if (data.dns.mxEop) parts.push('MX→EOP');
  else if (data.dns.mxTotal > 0) parts.push('MX elsewhere');
  return parts.join(' · ');
}

function dnsFacts(dns: M365Dns): Fact[] {
  const facts: Fact[] = [];
  if (dns.failed.includes('MX')) {
    facts.push({ label: 'MX', value: 'lookup failed', tone: 'warn' });
  } else if (dns.mxEop) {
    const flavor = matchEopMx(dns.mxEop)?.flavor ?? 'Exchange Online Protection';
    facts.push({ label: 'MX', value: `${dns.mxEop} (${flavor})`, tone: 'good' });
  } else if (dns.mx.length) {
    const more = dns.mxTotal > dns.mx.length ? [`… ${dns.mxTotal - dns.mx.length} more`] : [];
    facts.push({ label: 'MX (not Microsoft)', value: [...dns.mx, ...more] });
  } else {
    facts.push({ label: 'MX', value: 'none' });
  }
  if (dns.msTxt.length) facts.push({ label: 'MS= verification TXT', value: dns.msTxt, tone: 'good' });
  if (dns.spf) facts.push({ label: 'SPF', value: 'includes spf.protection.outlook.com', tone: 'good' });
  if (dns.autodiscover) {
    const m365 = isM365Autodiscover(dns.autodiscover);
    facts.push({ label: 'Autodiscover CNAME', value: dns.autodiscover, ...(m365 ? { tone: 'good' as const } : {}) });
  }
  for (const [label, target] of [
    ['DKIM selector1', dns.dkim.selector1],
    ['DKIM selector2', dns.dkim.selector2],
  ] as const) {
    if (target) facts.push({ label, value: target, ...(parseDkimTarget(target) ? { tone: 'good' as const } : {}) });
  }
  const otherFailures = dns.failed.filter((f) => f !== 'MX');
  if (otherFailures.length) facts.push({ label: 'DNS lookups failed', value: otherFailures, tone: 'warn' });
  return facts;
}

export const m365Module: Module<M365Data> = {
  id: 'm365',
  label: 'Microsoft 365 / Entra ID tenant',
  version: 1,
  accepts: ['domain'],
  ttl: 7 * DAY,
  rateLimit: { perMinute: 30 },
  async run(e: Entity, ctx: Ctx) {
    const d = stripDot(e.value);
    const [oidcR, realmR, dnsR] = await Promise.allSettled([
      discoverTenant(ctx, d),
      lookupRealm(ctx, d),
      collectDns(ctx, d),
    ]);
    // Never cache a result assembled from half-cancelled lookups.
    if (ctx.signal.aborted) throw new FetchError('aborted', 'Cancelled', LOGIN);
    if (oidcR.status === 'rejected') throw oidcR.reason;
    if (realmR.status === 'rejected') throw realmR.reason;
    if (dnsR.status === 'rejected') throw dnsR.reason;

    const oidc = oidcR.value;
    const { realm, error: realmError } = realmR.value;
    const dns = dnsR.value;
    const cfg = oidc.kind === 'tenant' ? oidc.cfg : null;
    const tenantId = cfg?.tenantId ?? null;
    const consumerDomain = detectConsumer(d, tenantId, realm);

    const base: Omit<M365Data, 'notes'> = {
      tenant: !!cfg && !consumerDomain,
      tenantId,
      issuerHost: cfg?.issuerHost ?? null,
      cloudInstance: cfg?.cloudInstance ?? realm?.cloudInstance ?? null,
      region: { scope: cfg?.regionScope ?? null, subScope: cfg?.regionSubScope ?? null },
      namespaceType: realm?.namespaceType ?? null,
      federationBrandName: realm?.federationBrandName ?? null,
      authUrlHost: realm?.authUrlHost ?? null,
      consumerDomain,
      dns,
      signals: dnsSignals(dns),
      authUrl: realm?.authUrl ?? null,
      idp: guessIdp(realm?.authUrl ?? null, realm?.authUrlHost ?? null),
      realmDomain: realm?.domainName ?? null,
      graphHost: cfg?.msgraphHost ?? cfg?.cloudGraphHost ?? null,
      noTenantReason: oidc.kind === 'none' ? oidc.reason : null,
      realmError,
    };
    const data: M365Data = { ...base, notes: buildNotes(d, base, !!cfg) };

    const pivots: Pivot[] = [];
    if (!consumerDomain) {
      if (dns.dkim.initialDomain) {
        pivots.push({ kind: 'domain', value: dns.dkim.initialDomain, note: 'M365 initial domain (DKIM)' });
      }
      if (data.authUrlHost && data.namespaceType === 'Federated' && isOrgIdpHost(data.authUrlHost)) {
        pivots.push({ kind: 'domain', value: data.authUrlHost, note: 'Federation IdP (AuthURL host)' });
      }
    }

    return { data, summary: summarize(data), ...(pivots.length ? { pivots } : {}) };
  },

  facts(data) {
    const facts: Fact[] = [];
    if (data.consumerDomain) {
      facts.push({
        label: 'Tenant',
        value: "Consumer Microsoft account (MSA) domain: resolves to Microsoft's consumer tenant, not an organisation's",
      });
      if (data.tenantId) facts.push({ label: 'MSA tenant ID', value: data.tenantId });
    } else if (data.tenant && data.tenantId) {
      facts.push({ label: 'Tenant ID', value: data.tenantId, pivot: true });
    } else {
      facts.push({
        label: 'Tenant',
        value: `No Entra ID tenant${data.noTenantReason ? ` (${data.noTenantReason})` : ''}`,
      });
    }
    if (data.namespaceType) {
      const conflict = data.tenant && data.namespaceType === 'Unknown';
      facts.push({ label: 'Namespace type', value: data.namespaceType, ...(conflict ? { tone: 'warn' as const } : {}) });
    }
    if (data.federationBrandName) facts.push({ label: 'Federation brand', value: data.federationBrandName });
    if (data.authUrlHost) {
      // A shared IdP host (accounts.google.com, login.live.com) is not an indicator of this organisation.
      facts.push({
        label: 'Auth URL host',
        value: data.authUrlHost,
        pivot: !data.consumerDomain && !isGenericIdpHost(data.authUrlHost),
      });
      if (data.idp) facts.push({ label: 'Identity provider', value: data.idp });
    }
    const region = formatRegion(data.region.scope, data.region.subScope);
    if (region) facts.push({ label: 'Region', value: region });
    if (data.cloudInstance) facts.push({ label: 'Cloud instance', value: data.cloudInstance });
    if (data.issuerHost) facts.push({ label: 'Issuer host', value: data.issuerHost });
    if (data.dns.dkim.initialDomain) {
      facts.push({ label: 'Initial domain', value: data.dns.dkim.initialDomain, pivot: !data.consumerDomain });
    }
    facts.push(...dnsFacts(data.dns));
    if (data.realmError) facts.push({ label: 'User-realm lookup', value: `failed: ${data.realmError}`, tone: 'warn' });
    for (const n of data.notes) facts.push({ label: 'Note', value: n, tone: 'warn' });
    return facts;
  },

  headline(data) {
    const region = formatRegion(data.region.scope, data.region.subScope);
    if (data.consumerDomain) return { m365: { tenant: false, namespaceType: 'Consumer (MSA)' } };
    return {
      m365: {
        tenant: data.tenant,
        ...(data.tenant && data.tenantId ? { tenantId: data.tenantId } : {}),
        ...(data.namespaceType ? { namespaceType: data.namespaceType } : {}),
        ...(data.tenant && region ? { region } : {}),
      },
    };
  },
};
