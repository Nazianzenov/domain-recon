import { FetchError, isAbortError } from '@/lib/http';
import {
  buildDomainUrl,
  daysText,
  findRdapBases,
  isProblemStatus,
  isRdapDomainObject,
  isoDay,
  parseBootstrap,
  parseRdapDomain,
  toAsciiName,
  type RdapBootstrap,
  type RdapDomain,
} from '@/lib/rdap';
import type { Ctx, Fact, Headline, JsonResponse, Module, RequestOpts } from '@/lib/types';
import { HOUR, SkipError } from '@/lib/types';

export const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
export const BOOTSTRAP_CACHE_KEY = 'rdap-bootstrap-dns';
export const BOOTSTRAP_TTL = 24 * HOUR;
export const RDAP_ORG = 'https://rdap.org/domain/';
/** Total queries per investigation, the original name included. */
export const MAX_ATTEMPTS = 4;

const ACCEPT = 'application/rdap+json, application/json';

export interface RdapData {
  found: boolean;
  /** Name whose record is shown (a parent of the investigated name after 404 retries), or the last name tried. */
  queriedName: string;
  /** Every name queried, in order. */
  tried: string[];
  /** URL we built for the answering query (https). */
  queryUrl: string | null;
  /** Final URL after redirects (rdap.org answers with a 302 to the registry). */
  serverUrl: string | null;
  via: 'bootstrap' | 'rdap.org';
  /** Matched IANA bootstrap entry; null when the bootstrap was unavailable. */
  bootstrapSuffix: string | null;
  /** Why the authoritative server was bypassed, if it was. */
  fallbackReason: string | null;
  record: RdapDomain | null;
}

type QueryResult =
  | { kind: 'found'; json: unknown; queryUrl: string; serverUrl: string; via: RdapData['via'] }
  | { kind: 'not-found'; queryUrl: string; serverUrl: string; via: RdapData['via'] }
  | { kind: 'no-service' };

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/** True when `url`'s host is `domain` or one of its subdomains. */
function isUnder(url: string, domain: string): boolean {
  let h: string;
  try {
    h = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  return h === domain || h.endsWith(`.${domain}`);
}

/** The name the shown record is for (the registry's ldhName, else the name we queried). */
function recordName(d: RdapData): string {
  return d.record?.ldhName ?? d.queriedName;
}

/**
 * IANA dns.json: raw cache (24 h) -> network, memoised per investigation so
 * concurrent callers share one fetch. Returns null when unavailable (the
 * caller falls back to rdap.org); only cancellation propagates.
 */
/** Last successfully fetched bootstrap, kept for 30 days as a fallback when IANA is unreachable. */
export const BOOTSTRAP_LASTGOOD_KEY = 'rdap-bootstrap-dns-lastgood';
const BOOTSTRAP_LASTGOOD_TTL = 30 * 24 * HOUR;

export async function loadBootstrap(ctx: Ctx): Promise<RdapBootstrap | null> {
  try {
    return await ctx.shared.memo('rdap:bootstrap', async () => {
      const cached = parseBootstrap(await ctx.rawCache.get<unknown>(BOOTSTRAP_CACHE_KEY, BOOTSTRAP_TTL).catch(() => undefined));
      if (cached) return cached;
      try {
        const res = await ctx.fetchJson<unknown>(BOOTSTRAP_URL, { rateLimit: false });
        const parsed = parseBootstrap(res.data);
        if (!parsed) throw new Error('Invalid IANA RDAP bootstrap file');
        await ctx.rawCache.set(BOOTSTRAP_CACHE_KEY, parsed, BOOTSTRAP_TTL).catch(() => undefined);
        await ctx.rawCache.set(BOOTSTRAP_LASTGOOD_KEY, parsed, BOOTSTRAP_LASTGOOD_TTL).catch(() => undefined);
        return parsed;
      } catch (err) {
        if (isAbortError(err)) throw err;
        // IANA unreachable: an older copy still lets findRdapBases (and its "never query the
        // investigated domain's own registry" filter) work instead of blindly using rdap.org.
        const lastGood = parseBootstrap(
          await ctx.rawCache.get<unknown>(BOOTSTRAP_LASTGOOD_KEY, BOOTSTRAP_LASTGOOD_TTL).catch(() => undefined),
        );
        if (lastGood) return lastGood;
        throw err;
      }
    });
  } catch (err) {
    if (isAbortError(err)) throw err;
    return null;
  }
}

/** Firefox MV3's default CSP has upgrade-insecure-requests; the two http:// bases (kg, mg) answer on https too. */
function httpsBase(base: string): string {
  return base.replace(/^http:\/\//i, 'https://');
}

function rdapOpts(rateKey: string, perMinute: number): RequestOpts {
  return { headers: { accept: ACCEPT }, okStatuses: [404], rateLimit: { key: rateKey, perMinute } };
}

function describeError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  return msg.length > 200 ? `${msg.slice(0, 197)}...` : msg;
}

/**
 * "Not found" beyond a plain 404: a 404 whose body was HTML (parse error), and
 * a 400/422 for a name below the registrable level (some registries reject
 * subdomain queries as malformed) while a parent name remains to try.
 */
function isNotFoundError(err: unknown, canStrip: boolean): boolean {
  if (!(err instanceof FetchError)) return false;
  if (err.kind === 'parse' && err.status === 404) return true;
  return canStrip && err.kind === 'http' && (err.status === 400 || err.status === 422);
}

async function queryAuthoritative(
  ctx: Ctx,
  base: string,
  name: string,
  canStrip: boolean,
): Promise<{ kind: 'found' | 'not-found'; json: unknown; queryUrl: string; serverUrl: string }> {
  const url = buildDomainUrl(base, name);
  try {
    const res = await ctx.fetchJson<unknown>(url, rdapOpts(`rdap:${hostOf(url)}`, 30));
    if (res.status === 404) return { kind: 'not-found', json: null, queryUrl: url, serverUrl: res.url };
    if (!isRdapDomainObject(res.data)) {
      throw new FetchError('parse', `Unexpected RDAP response from ${hostOf(url)}`, url, res.status);
    }
    return { kind: 'found', json: res.data, queryUrl: url, serverUrl: res.url };
  } catch (err) {
    if (isNotFoundError(err, canStrip)) return { kind: 'not-found', json: null, queryUrl: url, serverUrl: url };
    throw err;
  }
}

async function queryRdapOrg(ctx: Ctx, name: string, canStrip: boolean): Promise<QueryResult> {
  const url = `${RDAP_ORG}${encodeURIComponent(name)}`;
  let res: JsonResponse<unknown>;
  try {
    // rdap.org: 10 requests / 10 s, then 429.
    res = await ctx.fetchJson<unknown>(url, rdapOpts('rdap.org', 10));
  } catch (err) {
    if (isNotFoundError(err, canStrip)) return { kind: 'not-found', queryUrl: url, serverUrl: err instanceof FetchError ? err.url : url, via: 'rdap.org' };
    throw err;
  }
  if (res.status === 404) {
    // rdap.org redirects (302) to the registry; a 404 from rdap.org itself
    // means it knows no RDAP server for this name.
    if (hostOf(res.url) === 'rdap.org') return { kind: 'no-service' };
    return { kind: 'not-found', queryUrl: url, serverUrl: res.url, via: 'rdap.org' };
  }
  if (!isRdapDomainObject(res.data)) {
    throw new FetchError('parse', `Unexpected RDAP response from ${hostOf(res.url)}`, res.url, res.status);
  }
  return { kind: 'found', json: res.data, queryUrl: url, serverUrl: res.url, via: 'rdap.org' };
}

export const rdapModule: Module<RdapData> = {
  id: 'rdap',
  label: 'RDAP (registration)',
  version: 1,
  accepts: ['domain'],
  ttl: 24 * HOUR,

  async run(e, ctx) {
    const domain = toAsciiName(e.value);
    const bootstrap = await loadBootstrap(ctx);
    const match = bootstrap ? findRdapBases(bootstrap, domain) : null;
    const tld = domain.split('.').pop() ?? domain;
    if (bootstrap && !match) {
      // rdap.org uses the same IANA file, so it would only answer 404 here.
      throw new SkipError(`No RDAP service is published for .${tld} (not in the IANA bootstrap file).`);
    }

    // Subdomains are not registered objects: strip the leftmost label on 404
    // while the name is longer than <bootstrap suffix> + 1 label.
    const minLabels = (match?.suffixLabels ?? 1) + 1;
    const canStrip = (name: string) => name.split('.').length > minLabels;

    // OPSEC: this passive check must never contact the investigated domain's
    // own servers (investigating verisign.com would query rdap.verisign.com).
    const registrable = domain.split('.').slice(-minLabels).join('.');
    const allBases = (match?.bases ?? []).map(httpsBase).filter((b, i, a) => a.indexOf(b) === i);
    const bases = allBases.filter((b) => !isUnder(b, registrable));
    if (allBases.length && !bases.length) {
      // rdap.org would only redirect to the same server.
      throw new SkipError(
        `The RDAP server for .${tld} (${hostOf(allBases[0]!)}) belongs to the investigated domain, so this passive check does not contact it.`,
      );
    }
    const dead = new Set<string>();
    let fallbackReason: string | null = bootstrap ? null : 'IANA bootstrap unavailable';

    const query = async (name: string): Promise<QueryResult> => {
      for (const base of bases) {
        if (dead.has(base)) continue;
        try {
          const r = await queryAuthoritative(ctx, base, name, canStrip(name));
          return r.kind === 'found'
            ? { kind: 'found', json: r.json, queryUrl: r.queryUrl, serverUrl: r.serverUrl, via: 'bootstrap' }
            : { kind: 'not-found', queryUrl: r.queryUrl, serverUrl: r.serverUrl, via: 'bootstrap' };
        } catch (err) {
          if (isAbortError(err)) throw err;
          // Typically a registry without CORS headers (FetchError 'network'):
          // we only hold host permissions for data.iana.org and rdap.org.
          dead.add(base);
          fallbackReason = `${hostOf(base)}: ${describeError(err)}`;
        }
      }
      if (isUnder(RDAP_ORG, registrable)) {
        throw new SkipError(`rdap.org is the investigated domain, so this passive check does not use it as a fallback (${fallbackReason}).`);
      }
      try {
        return await queryRdapOrg(ctx, name, canStrip(name));
      } catch (err) {
        if (fallbackReason && err instanceof FetchError && err.kind !== 'aborted') {
          throw new FetchError(err.kind, `${err.message} (after ${fallbackReason})`, err.url, err.status, err.body);
        }
        throw err;
      }
    };

    const tried: string[] = [];
    let name = domain;
    let last: Extract<QueryResult, { kind: 'not-found' }> | null = null;
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      tried.push(name);
      const r = await query(name);
      if (r.kind === 'no-service') {
        if (match) {
          // IANA lists a server but it failed, and rdap.org does not know it: an error, not "no RDAP".
          throw new FetchError('http', `rdap.org has no RDAP server for .${tld} (after ${fallbackReason})`, `${RDAP_ORG}${encodeURIComponent(name)}`, 404);
        }
        throw new SkipError(`No RDAP service is available for .${tld} (rdap.org has no server for it).`);
      }
      if (r.kind === 'found') {
        const record = parseRdapDomain(r.json, ctx.now());
        const data: RdapData = {
          found: true,
          queriedName: name,
          tried,
          queryUrl: r.queryUrl,
          serverUrl: r.serverUrl,
          via: r.via,
          bootstrapSuffix: match?.suffix ?? null,
          fallbackReason: r.via === 'rdap.org' ? fallbackReason : null,
          record,
        };
        return { data, summary: summarize(data) };
      }
      last = r;
      if (!canStrip(name)) break;
      name = name.split('.').slice(1).join('.');
    }

    const data: RdapData = {
      found: false,
      queriedName: tried[tried.length - 1] ?? domain,
      tried,
      queryUrl: last?.queryUrl ?? null,
      serverUrl: last?.serverUrl ?? null,
      via: last?.via ?? 'bootstrap',
      bootstrapSuffix: match?.suffix ?? null,
      fallbackReason: last?.via === 'rdap.org' ? fallbackReason : null,
      record: null,
    };
    return { data, summary: summarize(data) };
  },

  facts: (d, e) => rdapFacts(d, e.value),

  headline(d) {
    const r = d.found ? d.record : null;
    if (!r) return {};
    const h: Partial<Headline> = { registrationFor: d.queriedName };
    if (r.ageDays !== null) h.domainAgeDays = r.ageDays;
    const reg = isoDay(r.events.registration);
    if (reg) h.registeredOn = reg;
    if (r.registrar?.name) h.registrar = r.registrar.name;
    return h;
  },
};

export function summarize(d: RdapData): string {
  const r = d.record;
  if (!d.found || !r) return 'Not found in RDAP';
  const parts: string[] = [];
  const reg = isoDay(r.events.registration);
  if (reg) parts.push(`Registered ${reg}${r.ageDays !== null ? ` (${daysText(r.ageDays)})` : ''}`);
  if (r.registrar?.name) parts.push(r.registrar.name);
  const exp = isoDay(r.events.expiration);
  if (exp) parts.push(r.daysToExpiry !== null && r.daysToExpiry < 0 ? `expired ${exp}` : `expires ${exp}`);
  const text = parts.length ? parts.join(' · ') : 'RDAP record found (no registration data)';
  // A parent's record (subdomain retry) must not read as the investigated name's own registration.
  const name = recordName(d);
  return d.tried[0] !== undefined && name !== d.tried[0] ? `${name}: ${text}` : text;
}

function expiryText(r: RdapDomain): string {
  const day = isoDay(r.events.expiration) ?? '';
  const n = r.daysToExpiry;
  if (n === null) return day;
  if (n < 0) return `${day} (expired ${daysText(-n)} ago)`;
  return `${day} (in ${daysText(n)})`;
}

export function rdapFacts(d: RdapData, entity: string): Fact[] {
  const facts: Fact[] = [];
  const server: Fact | null = d.serverUrl
    ? {
        label: 'RDAP server',
        value: `${hostOf(d.serverUrl)}${d.via === 'rdap.org' ? ' (via rdap.org)' : ''}`,
        ...(d.queryUrl?.startsWith('https://') ? { href: d.queryUrl } : {}),
      }
    : null;

  const r = d.found ? d.record : null;
  if (!r) {
    facts.push({ label: 'Status', value: 'Not found in RDAP' });
    facts.push({ label: 'Names tried', value: d.tried });
    if (server) facts.push(server);
    if (d.fallbackReason) facts.push({ label: 'Fallback reason', value: d.fallbackReason });
    return facts;
  }

  if (r.ageDays !== null) {
    const reg = isoDay(r.events.registration);
    facts.push({
      label: 'Domain age',
      value: `${daysText(r.ageDays)}${reg ? ` (registered ${reg})` : ''}`,
      ...(r.ageDays < 30 ? { tone: 'bad' as const } : r.ageDays < 180 ? { tone: 'warn' as const } : {}),
    });
  } else {
    facts.push({ label: 'Domain age', value: 'Unknown (no registration event)' });
  }
  const recName = recordName(d);
  if (recName !== toAsciiName(entity)) facts.push({ label: 'Record for', value: recName, pivot: true });
  if (r.events.reregistration) facts.push({ label: 'Re-registered', value: isoDay(r.events.reregistration) ?? '' });
  if (r.registrar?.name) facts.push({ label: 'Registrar', value: r.registrar.name });
  if (r.registrar?.ianaId) facts.push({ label: 'IANA registrar ID', value: r.registrar.ianaId });
  if (r.registrar?.url) facts.push({ label: 'Registrar URL', value: r.registrar.url });
  if (r.abuse?.email) facts.push({ label: 'Abuse email', value: r.abuse.email, pivot: true });
  if (r.abuse?.phone) facts.push({ label: 'Abuse phone', value: r.abuse.phone, pivot: true });
  if (r.nameservers.length) {
    const label = r.nameserverCount > r.nameservers.length ? `Nameservers (${r.nameservers.length} of ${r.nameserverCount})` : 'Nameservers';
    facts.push({ label, value: r.nameservers, pivot: true });
  }
  if (r.status.length) {
    facts.push({ label: 'Status', value: r.status, ...(r.status.some(isProblemStatus) ? { tone: 'warn' as const } : {}) });
  }
  if (r.events.expiration) {
    const n = r.daysToExpiry;
    facts.push({
      label: 'Expires',
      value: expiryText(r),
      ...(n !== null && n < 0 ? { tone: 'bad' as const } : n !== null && n < 30 ? { tone: 'warn' as const } : {}),
    });
  }
  if (r.events.lastChanged) facts.push({ label: 'Last changed', value: isoDay(r.events.lastChanged) ?? '' });
  if (r.events.transfer) facts.push({ label: 'Last transfer', value: isoDay(r.events.transfer) ?? '' });
  if (r.delegationSigned !== null) {
    facts.push({ label: 'DNSSEC (delegation)', value: r.delegationSigned ? 'signed' : 'unsigned', ...(r.delegationSigned ? { tone: 'good' as const } : {}) });
  }
  if (server) facts.push(server);
  if (d.fallbackReason) facts.push({ label: 'Fallback reason', value: d.fallbackReason });
  return facts;
}
