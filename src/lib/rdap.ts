/**
 * Pure RDAP helpers: IANA bootstrap validation + matching (RFC 9224), URL
 * building, jCard extraction (RFC 7095) and normalisation of an RDAP domain
 * object (RFC 9083) into a compact, JSON-serialisable shape.
 *
 * Live quirks handled (docs/research/dns-rdap.md):
 * - Verisign sends `ldhName` UPPERCASE (domain and nameservers): lowercased.
 * - The abuse contact is nested in the registrar entity's `entities[]`.
 * - jCard `fn` may be "" and `tel` may be a `tel:` URI.
 * - Any event may be missing (ccTLDs); "last update of RDAP database" is not
 *   "last changed".
 */

export const DAY_MS = 86_400_000;
export const MAX_NAMESERVERS = 20;
export const MAX_STATUSES = 20;
/** Cap on any single server-supplied string we keep (names, emails, statuses...). */
export const MAX_TEXT = 300;

function clip(s: string): string {
  return s.length > MAX_TEXT ? `${s.slice(0, MAX_TEXT - 1)}…` : s;
}

// ---------------------------------------------------------------------------
// Bootstrap (RFC 9224)

export interface RdapService {
  /** Lowercase A-label suffixes without a trailing dot (usually single TLD labels). */
  entries: string[];
  /** Base URLs, each ending with '/'. */
  urls: string[];
}

export interface RdapBootstrap {
  publication: string | null;
  services: RdapService[];
}

export interface RdapMatch {
  /** The bootstrap entry that matched, e.g. "com" or "co.uk". */
  suffix: string;
  suffixLabels: number;
  /** Base URLs for the matched service, https first. */
  bases: string[];
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function normName(s: string): string {
  return s.trim().replace(/\.+$/, '').toLowerCase();
}

/** Lowercase, strip the trailing dot and convert any U-labels to A-labels. */
export function toAsciiName(name: string): string {
  const n = normName(name);
  if (!/[^\x00-\x7f]/.test(n)) return n;
  try {
    return new URL(`http://${n}`).hostname;
  } catch {
    return n;
  }
}

function normBase(u: string): string | null {
  const s = u.trim();
  let url: URL;
  try {
    url = new URL(s);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  if (url.username || url.password || url.search || url.hash) return null;
  return url.href.endsWith('/') ? url.href : `${url.href}/`;
}

const ENTRY_RE = /^[a-z0-9-]+(?:\.[a-z0-9-]+)*$/;

/**
 * Validate the IANA `dns.json` bootstrap (or a cached copy of our normalised
 * form). Junk entries are dropped; returns null when nothing usable is left.
 */
export function parseBootstrap(json: unknown): RdapBootstrap | null {
  if (!isRecord(json) || !Array.isArray(json['services'])) return null;
  const services: RdapService[] = [];
  for (const svc of json['services'] as unknown[]) {
    let rawEntries: unknown;
    let rawUrls: unknown;
    if (Array.isArray(svc)) {
      // IANA form: [[labels...], [urls...]]
      rawEntries = svc[0];
      rawUrls = svc[1];
    } else if (isRecord(svc)) {
      // Our cached normalised form.
      rawEntries = svc['entries'];
      rawUrls = svc['urls'];
    } else {
      continue;
    }
    if (!Array.isArray(rawEntries) || !Array.isArray(rawUrls)) continue;
    const entries = [
      ...new Set(
        rawEntries
          .filter((x): x is string => typeof x === 'string')
          .map(normName)
          .filter((x) => ENTRY_RE.test(x)),
      ),
    ];
    const urls = [
      ...new Set(
        rawUrls.filter((x): x is string => typeof x === 'string').map(normBase).filter((x): x is string => x !== null),
      ),
    ];
    if (entries.length && urls.length) services.push({ entries, urls });
  }
  if (!services.length) return null;
  const pub = json['publication'];
  return { publication: typeof pub === 'string' ? pub : null, services };
}

/** https bases first (RFC 9224 §3: prefer https when several are listed), order otherwise kept. */
export function preferHttps(urls: readonly string[]): string[] {
  return [...urls.filter((u) => u.startsWith('https:')), ...urls.filter((u) => !u.startsWith('https:'))];
}

/**
 * Longest-suffix match of `domain` against the bootstrap entries, label by
 * label from the right (so "example.com" never matches "badexample.com").
 * Case-insensitive; Unicode names are converted to A-labels first.
 */
export function findRdapBases(bootstrap: RdapBootstrap, domain: string): RdapMatch | null {
  const name = toAsciiName(domain);
  if (!name) return null;
  const labels = name.split('.');
  for (let i = 0; i < labels.length; i++) {
    const suffix = labels.slice(i).join('.');
    for (const svc of bootstrap.services) {
      if (svc.entries.includes(suffix)) {
        return { suffix, suffixLabels: labels.length - i, bases: preferHttps(svc.urls) };
      }
    }
  }
  return null;
}

/** `base + "domain/" + name`, whether or not the base ends with '/'. */
export function buildDomainUrl(base: string, name: string): string {
  const b = base.endsWith('/') ? base : `${base}/`;
  return `${b}domain/${encodeURIComponent(toAsciiName(name))}`;
}

// ---------------------------------------------------------------------------
// jCard (RFC 7095)

export interface JCardProp {
  name: string;
  params: Record<string, unknown>;
  type: string;
  value: unknown;
}

/** Properties of a `["vcard", [[name, params, type, value], ...]]` array; [] for anything malformed. */
export function jcardProps(vcardArray: unknown): JCardProp[] {
  if (!Array.isArray(vcardArray) || vcardArray[0] !== 'vcard' || !Array.isArray(vcardArray[1])) return [];
  const out: JCardProp[] = [];
  for (const p of vcardArray[1] as unknown[]) {
    if (!Array.isArray(p) || p.length < 4 || typeof p[0] !== 'string') continue;
    out.push({
      name: p[0].toLowerCase(),
      params: isRecord(p[1]) ? p[1] : {},
      type: typeof p[2] === 'string' ? p[2].toLowerCase() : '',
      value: p[3],
    });
  }
  return out;
}

function firstString(v: unknown): string | null {
  if (typeof v === 'string') return clip(v.trim()) || null;
  if (Array.isArray(v)) {
    for (const x of v) {
      const s = firstString(x);
      if (s) return s;
    }
  }
  return null;
}

function paramTypes(params: Record<string, unknown>): string[] {
  const t = params['type'];
  const list = Array.isArray(t) ? t : [t];
  return list.filter((x): x is string => typeof x === 'string').map((x) => x.toLowerCase());
}

/** Formatted name; null when missing or empty (Verisign's abuse entity has fn ""). */
export function jcardFn(vcardArray: unknown): string | null {
  for (const p of jcardProps(vcardArray)) {
    if (p.name === 'fn') {
      const s = firstString(p.value);
      if (s) return s;
    }
  }
  return null;
}

/** Organisation name (structured value: first component). */
export function jcardOrg(vcardArray: unknown): string | null {
  for (const p of jcardProps(vcardArray)) {
    if (p.name === 'org') {
      const s = firstString(p.value);
      if (s) return s;
    }
  }
  return null;
}

export function jcardEmail(vcardArray: unknown): string | null {
  for (const p of jcardProps(vcardArray)) {
    if (p.name !== 'email') continue;
    const s = firstString(p.value)?.replace(/^mailto:/i, '').trim();
    if (s) return s;
  }
  return null;
}

/** Voice number preferred over fax; `tel:` URI prefix (and URI params) stripped. */
export function jcardTel(vcardArray: unknown): string | null {
  const tels = jcardProps(vcardArray).filter((p) => p.name === 'tel');
  const ordered = [...tels.filter((p) => !paramTypes(p.params).includes('fax')), ...tels.filter((p) => paramTypes(p.params).includes('fax'))];
  for (const p of ordered) {
    let s = firstString(p.value);
    if (!s) continue;
    if (/^tel:/i.test(s)) s = s.slice(4).split(';')[0]!.trim();
    if (s) return s;
  }
  return null;
}

export function jcardUrl(vcardArray: unknown): string | null {
  for (const p of jcardProps(vcardArray)) {
    if (p.name !== 'url') continue;
    const s = firstString(p.value);
    if (s && /^https?:\/\//i.test(s)) return s;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Domain object (RFC 9083)

export interface RdapEvents {
  registration: string | null;
  reregistration: string | null;
  expiration: string | null;
  lastChanged: string | null;
  transfer: string | null;
  /** "last update of RDAP database": freshness of the record, not a domain change. */
  rdapUpdated: string | null;
}

export interface RdapRegistrar {
  name: string | null;
  ianaId: string | null;
  url: string | null;
}

export interface RdapAbuse {
  email: string | null;
  phone: string | null;
}

export interface RdapDomain {
  ldhName: string | null;
  unicodeName: string | null;
  handle: string | null;
  events: RdapEvents;
  /** floor((now - registration) / day); null without a registration event. */
  ageDays: number | null;
  /** floor((expiration - now) / day); negative once expired. */
  daysToExpiry: number | null;
  registrar: RdapRegistrar | null;
  abuse: RdapAbuse | null;
  /** Lowercase, de-duplicated, capped at MAX_NAMESERVERS. */
  nameservers: string[];
  nameserverCount: number;
  status: string[];
  /** secureDNS.delegationSigned; null when absent. */
  delegationSigned: boolean | null;
}

function toIso(v: unknown): string | null {
  if (typeof v !== 'string' || !v.trim()) return null;
  const ms = Date.parse(v.trim());
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

function records(v: unknown): Record<string, unknown>[] {
  return Array.isArray(v) ? v.filter(isRecord) : [];
}

function rolesOf(entity: Record<string, unknown>): string[] {
  const r = entity['roles'];
  return Array.isArray(r) ? r.filter((x): x is string => typeof x === 'string').map((x) => x.trim().toLowerCase()) : [];
}

function str(v: unknown): string | null {
  return typeof v === 'string' && v.trim() ? clip(v.trim()) : null;
}

/** eventAction -> field. A Map, so server strings like "constructor" never hit Object.prototype. */
const EVENT_KEYS = new Map<string, keyof RdapEvents>([
  ['registration', 'registration'],
  ['reregistration', 'reregistration'],
  ['expiration', 'expiration'],
  ['last changed', 'lastChanged'],
  ['transfer', 'transfer'],
  ['last update of rdap database', 'rdapUpdated'],
]);

function parseEvents(raw: unknown): RdapEvents {
  const out: RdapEvents = {
    registration: null,
    reregistration: null,
    expiration: null,
    lastChanged: null,
    transfer: null,
    rdapUpdated: null,
  };
  for (const ev of records(raw)) {
    const action = typeof ev['eventAction'] === 'string' ? ev['eventAction'].trim().toLowerCase() : '';
    const key = EVENT_KEYS.get(action);
    const iso = toIso(ev['eventDate']);
    if (!key || !iso) continue;
    const prev = out[key];
    // Duplicates are rare; keep the earliest registration and the latest of everything else.
    if (prev === null || (key === 'registration' ? iso < prev : iso > prev)) out[key] = iso;
  }
  return out;
}

function parseRegistrar(entity: Record<string, unknown>): RdapRegistrar {
  const vcard = entity['vcardArray'];
  let ianaId: string | null = null;
  for (const pid of records(entity['publicIds'])) {
    const type = typeof pid['type'] === 'string' ? pid['type'].trim().toLowerCase() : '';
    const id = pid['identifier'];
    if (type === 'iana registrar id' && (typeof id === 'string' || typeof id === 'number')) {
      const s = String(id).trim();
      if (s) {
        ianaId = s;
        break;
      }
    }
  }
  return { name: jcardFn(vcard) ?? jcardOrg(vcard), ianaId, url: jcardUrl(vcard) };
}

function abuseFrom(entity: Record<string, unknown>): RdapAbuse | null {
  const v = entity['vcardArray'];
  const email = jcardEmail(v);
  const phone = jcardTel(v);
  return email || phone ? { email, phone } : null;
}

/** Abuse contact: registrar-nested first (ICANN profile), then top level, then anywhere (depth <= 3). */
function findAbuse(top: Record<string, unknown>[], registrar: Record<string, unknown> | undefined): RdapAbuse | null {
  const candidates: Record<string, unknown>[] = [];
  if (registrar) candidates.push(...records(registrar['entities']).filter((e) => rolesOf(e).includes('abuse')));
  candidates.push(...top.filter((e) => rolesOf(e).includes('abuse')));
  let level = top;
  for (let depth = 0; depth < 3 && level.length; depth++) {
    const next = level.flatMap((e) => records(e['entities']));
    candidates.push(...next.filter((e) => rolesOf(e).includes('abuse')));
    level = next;
  }
  for (const c of candidates) {
    const a = abuseFrom(c);
    if (a) return a;
  }
  return null;
}

/** Normalise an RDAP domain object. Throws on non-object input; tolerates every missing field. */
export function parseRdapDomain(json: unknown, nowMs: number): RdapDomain {
  if (!isRecord(json)) throw new Error('RDAP response is not a JSON object');

  const events = parseEvents(json['events']);
  const regMs = events.registration ? Date.parse(events.registration) : NaN;
  const expMs = events.expiration ? Date.parse(events.expiration) : NaN;

  const top = records(json['entities']);
  const registrarEntity = top.find((e) => rolesOf(e).includes('registrar'));

  const ns: string[] = [];
  for (const n of records(json['nameservers'])) {
    const name = str(n['ldhName']);
    if (!name) continue;
    const lc = normName(name);
    if (lc && !ns.includes(lc)) ns.push(lc);
  }

  const status: string[] = [];
  if (Array.isArray(json['status'])) {
    for (const s of json['status'] as unknown[]) {
      const v = str(s);
      if (v && !status.includes(v)) status.push(v);
    }
  }

  const secure = json['secureDNS'];
  const signed = isRecord(secure) && typeof secure['delegationSigned'] === 'boolean' ? secure['delegationSigned'] : null;

  const ldh = str(json['ldhName']);
  const uni = str(json['unicodeName']);

  return {
    ldhName: ldh ? normName(ldh) : null,
    unicodeName: uni ? uni.replace(/\.+$/, '') : null,
    handle: str(json['handle']),
    events,
    ageDays: Number.isFinite(regMs) ? Math.max(0, Math.floor((nowMs - regMs) / DAY_MS)) : null,
    daysToExpiry: Number.isFinite(expMs) ? Math.floor((expMs - nowMs) / DAY_MS) : null,
    registrar: registrarEntity ? parseRegistrar(registrarEntity) : null,
    abuse: findAbuse(top, registrarEntity),
    nameservers: ns.slice(0, MAX_NAMESERVERS),
    nameserverCount: ns.length,
    status: status.slice(0, MAX_STATUSES),
    delegationSigned: signed,
  };
}

/** Plausibly a domain object (some servers omit objectClassName). */
export function isRdapDomainObject(json: unknown): boolean {
  if (!isRecord(json)) return false;
  const cls = json['objectClassName'];
  if (typeof cls === 'string') return cls.toLowerCase() === 'domain';
  return typeof json['ldhName'] === 'string' || typeof json['unicodeName'] === 'string';
}

const HOLD_STATUSES = new Set(['clienthold', 'serverhold', 'pendingdelete', 'redemptionperiod', 'inactive']);

/** RDAP ("client hold") and EPP ("clientHold") spellings both match. */
export function isProblemStatus(s: string): boolean {
  return HOLD_STATUSES.has(s.toLowerCase().replace(/[\s_-]+/g, ''));
}

/** 2093 -> "2,093" (locale-independent). */
export function formatInt(n: number): string {
  const sign = n < 0 ? '-' : '';
  return sign + String(Math.abs(Math.trunc(n))).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/** 1 -> "1 day", 2093 -> "2,093 days". */
export function daysText(n: number): string {
  return `${formatInt(n)} day${Math.abs(Math.trunc(n)) === 1 ? '' : 's'}`;
}

/** ISO timestamp -> YYYY-MM-DD (UTC). */
export function isoDay(iso: string | null): string | null {
  return iso ? iso.slice(0, 10) : null;
}
