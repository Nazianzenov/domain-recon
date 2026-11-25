/**
 * Pure parsers for Microsoft 365 / Entra ID tenant discovery (no network).
 * See docs/research/pdns-m365-email.md sections 2 and 3.
 *
 * Every input is unknown JSON or DNS presentation data: all fields are
 * validated and length-capped before use.
 */

import { isIPv4 } from './ip';

/** Exact GUID shape; never `[0-9a-f-]{36}` (that matches 36 dashes). */
const GUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const GUID_IN_PATH_RE = new RegExp(`/(${GUID})(?=/|$)`, 'i');

/**
 * Microsoft-owned tenants that consumer (MSA) domains resolve to. Verified
 * live 2026-11-25: outlook.com -> f8cdef31-..., hotmail.com and gmail.com ->
 * 9cd80435-...; 9188040d-... is the documented "consumers" tenant.
 */
export const CONSUMER_TENANT_IDS: ReadonlySet<string> = new Set([
  'f8cdef31-a31e-4b4a-93e4-5f571e91255a',
  '9cd80435-793b-4f48-844b-6b3f37d1c1f3',
  '9188040d-6c67-4c5b-b112-36a304b66dad',
]);

/**
 * Microsoft account (consumer) email domains. Each was verified live
 * (getuserrealm -> Federated, DomainName "live.com", AuthURL login.live.com).
 * Deliberately exact: outlook.co.uk, for instance, is an ordinary Managed org
 * tenant. The runtime realm check catches the rest (and gmail.com).
 */
export const CONSUMER_DOMAINS: ReadonlySet<string> = new Set([
  'outlook.com',
  'hotmail.com',
  'live.com',
  'msn.com',
  'windowslive.com',
  'outlook.fr',
  'outlook.de',
  'outlook.es',
  'outlook.it',
  'outlook.jp',
  'outlook.com.au',
  'hotmail.co.uk',
  'hotmail.fr',
  'hotmail.de',
  'hotmail.it',
  'hotmail.es',
  'hotmail.co.jp',
  'live.co.uk',
  'live.fr',
  'live.de',
  'live.nl',
  'live.it',
  'live.ca',
  'live.com.au',
]);

/** Host of the Microsoft account (consumer) sign-in service. */
export const MSA_LOGIN_HOST = 'login.live.com';

// ---------------------------------------------------------------- helpers

/** A trimmed, length-capped string, or null for anything else / empty. */
export function str(v: unknown, max = 200): string | null {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  return s ? s.slice(0, max) : null;
}

/** A short identifier-like token (region codes, namespace types), else null. */
function token(v: unknown, max = 40): string | null {
  const s = str(v, 200);
  return s && s.length <= max && /^[A-Za-z0-9._-]+$/.test(s) ? s : null;
}

/** A plausible DNS hostname (lowercase, no trailing dot), else null. */
export function hostname(v: unknown): string | null {
  const s = str(v, 260);
  if (!s) return null;
  const h = s.toLowerCase().replace(/\.$/, '');
  return h.length <= 253 && /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$/.test(h) ? h : null;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** contoso.co.uk -> contoso-co-uk (the dashed form Microsoft uses in MX/DKIM). */
export function dashedDomain(d: string): string {
  return d.toLowerCase().replace(/\./g, '-');
}

// ---------------------------------------------------------------- OIDC

export interface IssuerInfo {
  /** Lowercase tenant GUID. */
  tenantId: string;
  /** Issuer host, e.g. sts.windows.net or login.microsoftonline.us. */
  host: string;
  version: 'v1' | 'v2';
}

/**
 * Parse an Entra ID issuer:
 * - v1 `https://sts.windows.net/<guid>/`
 * - v2 `https://login.microsoftonline.com/<guid>/v2.0`
 * - sovereign hosts (login.microsoftonline.us, login.partner.microsoftonline.cn, ...)
 * The host is never hard-coded; the GUID is pulled from the path.
 */
export function parseIssuer(issuer: unknown): IssuerInfo | null {
  const s = str(issuer, 500);
  if (!s) return null;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || !hostname(u.hostname)) return null;
  const m = GUID_IN_PATH_RE.exec(u.pathname);
  if (!m) return null;
  const rest = u.pathname.slice(m.index + m[0].length);
  return {
    tenantId: m[1]!.toLowerCase(),
    host: u.hostname.toLowerCase(),
    version: /^\/v2\.0\/?$/i.test(rest) ? 'v2' : 'v1',
  };
}

export interface OpenIdConfig {
  issuer: string;
  tenantId: string;
  issuerHost: string;
  issuerVersion: 'v1' | 'v2';
  /** tenant_region_scope: WW, NA, EU, SA, USGov, ... */
  regionScope: string | null;
  /** tenant_region_sub_scope: GCC, DOD (often absent). */
  regionSubScope: string | null;
  /** cloud_instance_name: microsoftonline.com, microsoftonline.us, ... */
  cloudInstance: string | null;
  cloudGraphHost: string | null;
  msgraphHost: string | null;
}

/** Parse a `.well-known/openid-configuration` document. Null when there is no usable tenant issuer. */
export function parseOpenIdConfig(json: unknown): OpenIdConfig | null {
  if (!isObject(json)) return null;
  const issuer = parseIssuer(json['issuer']);
  if (!issuer) return null;
  return {
    issuer: str(json['issuer'], 300)!,
    tenantId: issuer.tenantId,
    issuerHost: issuer.host,
    issuerVersion: issuer.version,
    regionScope: token(json['tenant_region_scope']),
    regionSubScope: token(json['tenant_region_sub_scope']),
    cloudInstance: hostname(json['cloud_instance_name']),
    cloudGraphHost: hostname(json['cloud_graph_host_name']),
    msgraphHost: hostname(json['msgraph_host']),
  };
}

export interface OpenIdError {
  /** OAuth error string, e.g. invalid_tenant. */
  error: string | null;
  /** e.g. "AADSTS90002" (from error_codes or the description). */
  code: string | null;
}

/**
 * Parse an Entra ID error body (HTTP 400 for unknown tenants):
 * `{"error":"invalid_tenant","error_description":"AADSTS90002: Tenant 'x' not found...","error_codes":[90002]}`.
 * Null when the body is not an OAuth-style error.
 */
export function parseOpenIdError(json: unknown): OpenIdError | null {
  if (!isObject(json)) return null;
  const error = token(json['error'], 80);
  const codes = Array.isArray(json['error_codes']) ? json['error_codes'] : [];
  const first = codes.find((c): c is number => typeof c === 'number' && Number.isInteger(c) && c > 0 && c < 1e7);
  const fromDesc = /\bAADSTS(\d{4,7})\b/.exec(str(json['error_description'], 2000) ?? '')?.[1];
  const code = first !== undefined ? `AADSTS${first}` : fromDesc ? `AADSTS${fromDesc}` : null;
  if (!error && !code) return null;
  return { error, code };
}

// ---------------------------------------------------------------- user realm

export interface UserRealm {
  /** Managed | Federated | Unknown (other short tokens are kept verbatim). */
  namespaceType: string;
  domainName: string | null;
  federationBrandName: string | null;
  cloudInstance: string | null;
  /** Federated only: the IdP sign-in URL (capped), http(s) only. */
  authUrl: string | null;
  authUrlHost: string | null;
}

/** Parse `getuserrealm.srf?...&json=1`. Null when NameSpaceType is missing. */
export function parseUserRealm(json: unknown): UserRealm | null {
  if (!isObject(json)) return null;
  const namespaceType = token(json['NameSpaceType']);
  if (!namespaceType) return null;
  let authUrl: string | null = null;
  let authUrlHost: string | null = null;
  const rawAuth = str(json['AuthURL'], 2000);
  if (rawAuth) {
    try {
      const u = new URL(rawAuth);
      const h = hostname(u.hostname);
      if ((u.protocol === 'https:' || u.protocol === 'http:') && h) {
        authUrlHost = h;
        authUrl = rawAuth.slice(0, 300);
      }
    } catch {
      /* not a URL: ignore */
    }
  }
  return {
    namespaceType,
    domainName: hostname(json['DomainName']),
    federationBrandName: str(json['FederationBrandName'], 120),
    cloudInstance: hostname(json['CloudInstanceName']),
    authUrl,
    authUrlHost,
  };
}

/** Best-effort IdP product from a federation AuthURL. */
export function guessIdp(authUrl: string | null, host: string | null): string | null {
  if (!host) return null;
  let path = '';
  try {
    if (authUrl) path = new URL(authUrl).pathname.toLowerCase();
  } catch {
    /* ignore */
  }
  if (host === MSA_LOGIN_HOST) return 'Microsoft account (consumer)';
  if (/(^|\.)okta(preview|-emea|-gov)?\.com$/.test(host)) return 'Okta';
  if (host === 'accounts.google.com') return 'Google Workspace';
  if (/(^|\.)onelogin\.com$/.test(host)) return 'OneLogin';
  if (/(^|\.)(pingone\.(com|eu|asia|ca)|pingidentity\.com)$/.test(host)) return 'Ping Identity';
  if (/(^|\.)duosecurity\.com$/.test(host)) return 'Duo';
  if (/(^|\.)(idaptive\.app|cyberark\.cloud)$/.test(host)) return 'CyberArk';
  if (/(^|\.)jumpcloud\.com$/.test(host)) return 'JumpCloud';
  if (/(^|\.)auth0\.com$/.test(host)) return 'Auth0';
  // The /adfs/ path is AD FS's own; a bare "sts."/"fs." host is also used by
  // PingFederate, Shibboleth, ... so only an "adfs" host label counts.
  if (path.startsWith('/adfs/') || /^adfs\d*\./.test(host)) return 'AD FS';
  return null;
}

/** Shared IdP hosts that identify a product, not an organisation (not worth pivoting on). */
export function isGenericIdpHost(host: string): boolean {
  return (
    host === MSA_LOGIN_HOST ||
    host === 'accounts.google.com' ||
    host === 'sso.connect.pingidentity.com' ||
    host === 'sso.jumpcloud.com' ||
    host === 'login.windows.net' ||
    host === 'login.microsoft.com' ||
    /^auth\.pingone\.(com|eu|asia|ca)$/.test(host) ||
    /(^|\.)login\.microsoftonline\.[a-z.]+$/.test(host)
  );
}

/**
 * An AuthURL host worth a `domain` pivot: organisation-specific (not a shared
 * IdP host) and an actual name, not an IP literal (`https://10.1.2.3/adfs/ls`
 * passes the hostname check but is not a domain).
 */
export function isOrgIdpHost(host: string): boolean {
  return !isGenericIdpHost(host) && !isIPv4(host);
}

// ---------------------------------------------------------------- consumer

export function isConsumerDomain(d: string): boolean {
  return CONSUMER_DOMAINS.has(d.toLowerCase().replace(/\.$/, ''));
}

/**
 * Consumer (MSA) domains resolve to a Microsoft-owned OIDC tenant and a
 * realm federated to login.live.com with DomainName "live.com".
 * The tenant GUID alone is only a fallback (e.g. when the realm lookup
 * failed): Microsoft-owned tenants also hold ordinary org domains, so a realm
 * that names the domain itself as its own (non-MSA) realm wins.
 */
export function detectConsumer(
  d: string,
  tenantId: string | null,
  realm: Pick<UserRealm, 'domainName' | 'authUrlHost'> | null,
): boolean {
  const domain = d.toLowerCase().replace(/\.$/, '');
  if (isConsumerDomain(domain)) return true;
  if (realm?.authUrlHost === MSA_LOGIN_HOST || realm?.domainName === 'live.com') return true;
  return tenantId !== null && CONSUMER_TENANT_IDS.has(tenantId) && realm?.domainName !== domain;
}

// ---------------------------------------------------------------- DNS

export interface EopMx {
  host: string;
  /** MX token (usually the dashed domain, not guaranteed). */
  token: string;
  flavor: string;
}

const EOP_MX: ReadonlyArray<{ re: RegExp; flavor: string }> = [
  { re: /^([a-z0-9-]+)\.mail\.protection\.outlook\.(?:com|de)$/, flavor: 'Exchange Online Protection' },
  { re: /^([a-z0-9-]+)\.mail\.eo\.outlook\.com$/, flavor: 'Exchange Online Protection (legacy)' },
  // GCC High: low confidence per research, harmless to recognise.
  { re: /^([a-z0-9-]+)\.mail\.protection\.office365\.us$/, flavor: 'Exchange Online Protection (US Government)' },
  // New DNSSEC-enabled MX, e.g. contosotest-com.o-v1.mx.microsoft
  { re: /^([a-z0-9-]+)\.[a-z0-9-]+\.mx\.microsoft$/, flavor: 'Exchange Online (DNSSEC MX)' },
];

/** Recognise an Exchange Online Protection MX host. */
export function matchEopMx(exchange: string): EopMx | null {
  const host = hostname(exchange);
  if (!host) return null;
  for (const { re, flavor } of EOP_MX) {
    const m = re.exec(host);
    if (m) return { host, token: m[1]!, flavor };
  }
  return null;
}

/** `MS=ms12345678` (and the live 40-hex variant) domain-verification TXT. */
export function isMsVerificationTxt(txt: string): boolean {
  return /^ms=(?:ms\d{4,12}|[0-9a-f]{40})$/i.test(txt.trim());
}

/** SPF record that authorises Exchange Online. */
export function hasEopSpf(txt: string): boolean {
  const t = txt.trim().toLowerCase();
  return /^v=spf1(\s|$)/.test(t) && /(?:^|\s)[+~?]?include:spf\.protection\.outlook\.com(?=\s|$)/.test(t);
}

export function isM365Autodiscover(target: string | null): boolean {
  return hostname(target) === 'autodiscover.outlook.com';
}

export interface DkimTarget {
  selector: 1 | 2;
  /** The domain part as Microsoft dashed it (e.g. contoso-com). */
  domainDashed: string;
  /** The tenant's initial domain, e.g. contoso.onmicrosoft.com. */
  initialDomain: string;
  format: 'onmicrosoft' | 'dkim.mail.microsoft';
}

/**
 * Parse an M365 DKIM selector CNAME target:
 * - old: `selector1-contoso-com._domainkey.contoso.onmicrosoft.com`
 * - new (custom domains added since May 2025):
 *   `selector1-contoso-com._domainkey.contoso.n-v1.dkim.mail.microsoft`
 * In both, the initial domain is `<prefix>.onmicrosoft.com`. The `.onmicrosoft.us`
 * (GCC High) suffix is accepted too and kept as-is.
 */
export function parseDkimTarget(target: string | null): DkimTarget | null {
  const h = hostname(target);
  if (!h) return null;
  let m = /^selector([12])-([a-z0-9-]+)\._domainkey\.([a-z0-9-]+)\.onmicrosoft\.(com|us)$/.exec(h);
  if (m) {
    return {
      selector: m[1] === '1' ? 1 : 2,
      domainDashed: m[2]!,
      initialDomain: `${m[3]!}.onmicrosoft.${m[4]!}`,
      format: 'onmicrosoft',
    };
  }
  m = /^selector([12])-([a-z0-9-]+)\._domainkey\.([a-z0-9-]+)\.[a-z0-9]-v1\.dkim\.mail\.microsoft$/.exec(h);
  if (m) {
    return {
      selector: m[1] === '1' ? 1 : 2,
      domainDashed: m[2]!,
      initialDomain: `${m[3]!}.onmicrosoft.com`,
      format: 'dkim.mail.microsoft',
    };
  }
  return null;
}

export interface M365Dns {
  /** First (lowest preference) MX that is Exchange Online Protection. */
  mxEop: string | null;
  /** All MX exchanges by preference (capped at MAX_MX). */
  mx: string[];
  mxTotal: number;
  /** MS=ms... verification TXT values (capped). */
  msTxt: string[];
  /** SPF includes spf.protection.outlook.com. */
  spf: boolean;
  /** autodiscover.<d> CNAME target (any), or null. */
  autodiscover: string | null;
  dkim: { selector1: string | null; selector2: string | null; initialDomain: string | null };
  /** Lookups that failed (e.g. "MX"); a failing lookup never fails the module. */
  failed: string[];
}

export const MAX_MX = 10;
export const MAX_MS_TXT = 5;

/** Human-readable corroboration list (only positive Microsoft 365 signals). */
export function dnsSignals(dns: M365Dns): string[] {
  const out: string[] = [];
  if (dns.mxEop) {
    const flavor = matchEopMx(dns.mxEop)?.flavor ?? 'Exchange Online Protection';
    out.push(`MX → ${flavor}: ${dns.mxEop}`);
  }
  if (dns.msTxt.length) out.push(`Domain-verification TXT ${dns.msTxt.join(', ')}`);
  if (dns.spf) out.push('SPF includes spf.protection.outlook.com');
  if (isM365Autodiscover(dns.autodiscover)) out.push('autodiscover CNAME → autodiscover.outlook.com');
  for (const [name, target] of [
    ['selector1', dns.dkim.selector1],
    ['selector2', dns.dkim.selector2],
  ] as const) {
    const p = parseDkimTarget(target);
    if (p) out.push(`DKIM ${name} CNAME → ${target} (initial domain ${p.initialDomain})`);
  }
  return out;
}

/** True when DNS points at Microsoft 365 in any way. */
export function hasM365Dns(dns: M365Dns): boolean {
  return dnsSignals(dns).length > 0;
}

/** "NA", "USGov (DOD)" or null. */
export function formatRegion(scope: string | null, subScope: string | null): string | null {
  if (!scope) return subScope;
  return subScope ? `${scope} (${subScope})` : scope;
}
