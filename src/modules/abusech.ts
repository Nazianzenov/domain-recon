import { FetchError, type Http } from '@/lib/http';
import { isIPv6, normalizeIp } from '@/lib/ip';
import type { KeyTester } from '@/lib/keytest';
import type { Ctx, Entity, Fact, Module, Severity } from '@/lib/types';
import { DAY, HOUR, SkipError } from '@/lib/types';

/**
 * abuse.ch community APIs: URLhaus (malware-distribution URLs per host) and
 * ThreatFox (IOCs). See docs/research/threat-intel.md §11.
 *
 * - Both require the `Auth-Key` header (one free key from auth.abuse.ch works
 *   for both). No key -> HTTP 401 {"error":"Unauthorized"} (octet-stream);
 *   bad key -> HTTP 403 {"query_status":"unknown_auth_key"}.
 * - URLhaus: POST form `host=` -> query_status ok | no_results | invalid_host |
 *   http_post_expected. Numbers come back as strings, urls[] is capped at 100,
 *   `blacklists` is absent for IPv4 hosts.
 * - ThreatFox: POST JSON search_ioc. `exact_match` defaults to false (substring
 *   search), so it is always sent as true; an IP still matches its ip:port IOCs
 *   (documented example). IOCs older than 6 months are expired from the API.
 *   Undocumented: `no_result` with `data` as a string, `illegal_search_term`.
 * - Rate limits: "fair use" only. Both modules share the `abusech` bucket.
 */

export const URLHAUS_API = 'https://urlhaus-api.abuse.ch/v1/host/';
export const THREATFOX_API = 'https://threatfox-api.abuse.ch/api/v1/';
/** URLs kept in `data` (online first, then newest). */
export const MAX_URLS = 20;
/** IOCs kept in `data` (highest confidence first, then most recent). */
export const MAX_IOCS = 20;
/** URLhaus URLs whose newest entry is older than this are an old signal. */
export const STALE_AFTER_MS = 365 * DAY;
/** ThreatFox confidence (0-100) treated as "malicious with good confidence". */
export const HIGH_CONFIDENCE = 75;
const MAX_TAGS = 10;
const MAX_TOP_TAGS = 15;
const MAX_MALWARE = 10;
const MAX_REFERENCES = 5;
const RATE_LIMIT = { perMinute: 30 };

type Service = 'URLhaus' | 'ThreatFox';

// ---------------------------------------------------------------------------
// Defensive parsing helpers

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * C0/C1 controls, zero-width characters, line/paragraph separators, bidi
 * marks/embeddings/overrides/isolates and the BOM would garble or spoof
 * plain-text rendering. Written as escapes: literal bidi characters in source
 * are themselves a "Trojan Source" hazard.
 */
const UNSAFE_CHARS = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g;

/** Trimmed, control-free, length-capped string, or null. */
function clean(v: unknown, max = 200): string | null {
  if (typeof v !== 'string') return null;
  const s = v.replace(UNSAFE_CHARS, '').trim();
  return s ? s.slice(0, max) : null;
}

/** Finite number from a number or a digit string (abuse.ch sends counts as strings). */
function num(v: unknown): number | undefined {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string' && /^\s*\d{1,15}\s*$/.test(v)) return Number(v);
  return undefined;
}

/** abuse.ch timestamps ("2019-01-15 07:09:01 UTC") -> ISO 8601; anything else -> null. */
export function abuseTime(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const m = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.\d+)?\s*(?:UTC|Z|\+00:?00)?$/i.exec(v.trim());
  if (!m) return null;
  const t = Date.parse(`${m[1]}T${m[2]}Z`);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

function tagList(v: unknown, max = MAX_TAGS): string[] {
  const list: unknown[] = Array.isArray(v) ? v : typeof v === 'string' ? v.split(',') : [];
  const out: string[] = [];
  for (const t of list) {
    if (out.length >= max) break;
    const c = clean(t, 64);
    if (c && !out.includes(c)) out.push(c);
  }
  return out;
}

/** An absolute http(s) URL (as text; never rendered as a link), or null. */
function webUrl(v: unknown, max = 500): string | null {
  const s = clean(v, max);
  if (!s) return null;
  try {
    const u = new URL(s);
    return u.protocol === 'https:' || u.protocol === 'http:' ? s : null;
  } catch {
    return null;
  }
}

const day = (iso: string) => iso.slice(0, 10);

function plural(n: number, word: string, many = `${word}s`): string {
  return `${n} ${n === 1 ? word : many}`;
}

function newest(values: Array<string | null>): string | null {
  let best: string | null = null;
  for (const v of values) if (v && (!best || v > best)) best = v;
  return best;
}

// ---------------------------------------------------------------------------
// Links to the providers' web pages (built here, https only)

export function urlhausHostLink(host: string): string {
  return `https://urlhaus.abuse.ch/host/${encodeURIComponent(host)}/`;
}

export function threatfoxSearchLink(value: string): string {
  return `https://threatfox.abuse.ch/browse.php?search=${encodeURIComponent(`ioc:${value}`)}`;
}

export function threatfoxIocLink(id: string): string {
  return `https://threatfox.abuse.ch/ioc/${encodeURIComponent(id)}/`;
}

// ---------------------------------------------------------------------------
// Requests and errors

const INVALID_KEY_MSG =
  'abuse.ch rejected the Auth-Key (unknown_auth_key). Check the key in settings; free keys are issued at auth.abuse.ch.';

function queryStatusOf(body: string | undefined): string | null {
  if (!body) return null;
  try {
    const j: unknown = JSON.parse(body);
    return isObj(j) ? clean(j['query_status'], 60) : null;
  } catch {
    return null;
  }
}

/** Clear messages for abuse.ch HTTP errors; other failures pass through unchanged. */
export function abusechError(service: Service, err: unknown): unknown {
  if (!(err instanceof FetchError) || err.kind !== 'http' || err.status === undefined) return err;
  const status = err.status;
  const qs = queryStatusOf(err.body);
  let msg: string;
  if (qs === 'unknown_auth_key') {
    msg = INVALID_KEY_MSG;
  } else if (status === 401) {
    msg = 'abuse.ch refused the request (HTTP 401 Unauthorized): the Auth-Key is missing or was not accepted. Check your abuse.ch Auth-Key in settings.';
  } else if (status === 403) {
    msg = `abuse.ch refused the request (HTTP 403${qs ? `: ${qs}` : ''}). Check your abuse.ch Auth-Key in settings.`;
  } else if (status === 429) {
    msg = `${service} rate limit or quota exceeded (HTTP 429). abuse.ch only promises fair use; wait a few minutes and try again.`;
  } else if (status >= 500) {
    msg = `${service} is unavailable (HTTP ${status}). Try again later.`;
  } else {
    msg = `${service} error (HTTP ${status}${qs ? `: ${qs}` : ''}).`;
  }
  return new FetchError('http', msg, err.url, status, err.body);
}

function checkKeyChars(key: string): void {
  // Header values must be visible ASCII; anything else surfaces as a confusing network error.
  if (!/^[\x21-\x7e]+$/.test(key)) {
    throw new Error('The abuse.ch Auth-Key contains invalid characters. Re-enter it in settings.');
  }
}

async function authKey(ctx: Ctx): Promise<string> {
  const key = (await ctx.getKey('abusech'))?.trim();
  if (!key) throw new SkipError('Add an abuse.ch Auth-Key in settings to enable this check.');
  checkKeyChars(key);
  return key;
}

type Poster = Pick<Http, 'fetchJson'>;

async function post(
  http: Poster,
  service: Service,
  url: string,
  key: string,
  body: string | URLSearchParams,
  headers: Record<string, string> = {},
): Promise<unknown> {
  try {
    const res = await http.fetchJson<unknown>(url, {
      method: 'POST',
      headers: { ...headers, 'Auth-Key': key },
      body,
    });
    return res.data;
  } catch (err) {
    throw abusechError(service, err);
  }
}

function postThreatfox(http: Poster, key: string, payload: Record<string, unknown>): Promise<unknown> {
  return post(http, 'ThreatFox', THREATFOX_API, key, JSON.stringify(payload), { 'Content-Type': 'application/json' });
}

function envelope(service: Service, url: string, data: unknown): { obj: Obj; status: string | null } {
  if (!isObj(data)) throw new FetchError('parse', `Unexpected response from ${service} (not a JSON object).`, url);
  return { obj: data, status: clean(data['query_status'], 60) };
}

function unexpectedStatus(service: Service, url: string, status: string | null): FetchError {
  return new FetchError(
    'parse',
    `Unexpected response from ${service} (${status ? `query_status "${status}"` : 'no query_status'}).`,
    url,
  );
}

/** Canonical lookup value: lowercase domain without trailing dot, or canonical IP. */
function lookupValue(e: Entity): string {
  if (e.kind === 'ip') {
    const ip = normalizeIp(e.value);
    if (!ip) throw new SkipError('Not a valid IP address.');
    return ip;
  }
  if (e.kind === 'domain') {
    const d = e.value.trim().toLowerCase().replace(/\.$/, '');
    if (!d || d.length > 253 || /[\s/?#@\\]/.test(d)) throw new SkipError('Not a valid domain name.');
    return d;
  }
  throw new SkipError('abuse.ch lookups need a domain or an IP address.');
}

// ---------------------------------------------------------------------------
// URLhaus

export type UrlStatus = 'online' | 'offline' | 'unknown';

export interface UrlhausUrl {
  /** The malware URL as reported (exports defang it). */
  url: string;
  url_status: UrlStatus;
  threat: string | null;
  tags: string[];
  /** ISO 8601. */
  date_added: string | null;
}

export interface UrlhausBlacklists {
  spamhaus_dbl: string | null;
  surbl: string | null;
}

export interface UrlhausData {
  host: string;
  status: 'ok' | 'no_results';
  /** Malware URLs URLhaus has observed on the host (url_count). */
  urlCount: number;
  /** URL entries in the response (URLhaus returns at most 100). */
  urlsReturned: number;
  /** Online URLs among those returned. */
  onlineCount: number;
  /** ISO 8601 (`firstseen`). */
  firstSeen: string | null;
  /** Newest `date_added` among the returned URLs. */
  lastAdded: string | null;
  /** Spamhaus DBL / SURBL status; null when not returned (always for IPv4 hosts). */
  blacklists: UrlhausBlacklists | null;
  /** Most frequent tags across the returned URLs (malware families, file types). */
  topTags: string[];
  /** Up to MAX_URLS, online first, then newest. */
  urls: UrlhausUrl[];
  /** Malformed URL entries dropped while parsing. */
  skipped: number;
  /** `urlhaus_reference` (validated to be an https link on urlhaus.abuse.ch). */
  reference: string | null;
}

function parseUrlEntry(v: unknown): UrlhausUrl | null {
  if (!isObj(v)) return null;
  const url = clean(v['url'], 2048);
  if (!url) return null;
  const s = clean(v['url_status'], 20)?.toLowerCase();
  return {
    url,
    url_status: s === 'online' || s === 'offline' ? s : 'unknown',
    threat: clean(v['threat'], 60),
    tags: tagList(v['tags']),
    date_added: abuseTime(v['date_added']),
  };
}

function parseBlacklists(v: unknown): UrlhausBlacklists | null {
  if (!isObj(v)) return null;
  return { spamhaus_dbl: clean(v['spamhaus_dbl'], 60), surbl: clean(v['surbl'], 60) };
}

function urlhausReference(v: unknown): string | null {
  const s = clean(v, 300);
  if (!s) return null;
  try {
    const u = new URL(s);
    return u.protocol === 'https:' && u.hostname === 'urlhaus.abuse.ch' ? u.href : null;
  } catch {
    return null;
  }
}

/**
 * Documented Spamhaus DBL listing codes (urlhaus-api.abuse.ch). Anything else
 * ("not listed", or an undocumented value such as a lookup error) is not
 * treated as a listing, so an unexpected value never raises severity.
 * A Map, not an object literal: provider strings must not hit Object.prototype.
 */
const DBL_TEXT = new Map<string, string>([
  ['spammer_domain', 'spam domain'],
  ['phishing_domain', 'phishing domain'],
  ['botnet_cc_domain', 'botnet C&C domain'],
  ['abused_legit_spam', 'compromised site used for spam'],
  ['abused_legit_malware', 'compromised site used for malware'],
  ['abused_legit_phishing', 'compromised site used for phishing'],
  ['abused_legit_botnetcc', 'compromised site used for botnet C&C'],
  ['abused_redirector', 'abused redirector or URL shortener'],
]);

const NOT_LISTED = 'not listed';
const dblListed = (v: string | null): v is string => !!v && DBL_TEXT.has(v.toLowerCase());
/** SURBL is documented as `listed` | `not listed`. */
const surblListed = (v: string | null): v is string => !!v && v.toLowerCase() === 'listed';

export function isBlacklisted(b: UrlhausBlacklists | null): boolean {
  return !!b && (dblListed(b.spamhaus_dbl) || surblListed(b.surbl));
}

function emptyUrlhaus(host: string): UrlhausData {
  return {
    host,
    status: 'no_results',
    urlCount: 0,
    urlsReturned: 0,
    onlineCount: 0,
    firstSeen: null,
    lastAdded: null,
    blacklists: null,
    topTags: [],
    urls: [],
    skipped: 0,
    reference: null,
  };
}

function topTags(urls: UrlhausUrl[]): string[] {
  const counts = new Map<string, number>();
  for (const u of urls) for (const t of u.tags) counts.set(t, (counts.get(t) ?? 0) + 1);
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, MAX_TOP_TAGS)
    .map(([t]) => t);
}

const STATUS_RANK: Record<UrlStatus, number> = { online: 0, unknown: 1, offline: 2 };

/** Parse a URLhaus /v1/host/ response body. Throws for statuses that are not results. */
export function parseUrlhaus(host: string, raw: unknown, url = URLHAUS_API): UrlhausData {
  const { obj, status } = envelope('URLhaus', url, raw);
  switch (status) {
    case 'ok':
      break;
    case 'no_results':
      return emptyUrlhaus(host);
    case 'invalid_host':
      throw new SkipError(
        isIPv6(host)
          ? 'URLhaus host lookups support IPv4 addresses and host names, not IPv6 (invalid_host).'
          : 'URLhaus does not accept this value as a host (invalid_host).',
      );
    case 'unknown_auth_key':
      throw new Error(INVALID_KEY_MSG);
    case 'http_post_expected':
      throw new Error('URLhaus did not receive a POST request (http_post_expected); a proxy or redirect may have changed it.');
    default:
      throw unexpectedStatus('URLhaus', url, status);
  }

  const list = Array.isArray(obj['urls']) ? obj['urls'] : [];
  const parsed: UrlhausUrl[] = [];
  for (const u of list) {
    const p = parseUrlEntry(u);
    if (p) parsed.push(p);
  }
  // A format change must not turn into "N malware URLs, none online" (online status unknown).
  if (list.length > 0 && parsed.length === 0) {
    throw new FetchError(
      'parse',
      `URLhaus returned ${plural(list.length, 'URL entry', 'URL entries')} but none could be parsed (API format change?).`,
      url,
    );
  }
  parsed.sort(
    (a, b) =>
      STATUS_RANK[a.url_status] - STATUS_RANK[b.url_status] ||
      (b.date_added ?? '').localeCompare(a.date_added ?? '') ||
      a.url.localeCompare(b.url),
  );
  const count = num(obj['url_count']);
  return {
    host,
    status: 'ok',
    urlCount: Math.max(count !== undefined ? Math.floor(count) : 0, list.length),
    urlsReturned: list.length,
    onlineCount: parsed.filter((u) => u.url_status === 'online').length,
    firstSeen: abuseTime(obj['firstseen']),
    lastAdded: newest(parsed.map((u) => u.date_added)),
    blacklists: parseBlacklists(obj['blacklists']),
    topTags: topTags(parsed),
    urls: parsed.slice(0, MAX_URLS),
    skipped: list.length - parsed.length,
    reference: urlhausReference(obj['urlhaus_reference']),
  };
}

function isStale(iso: string | null, now: number): boolean {
  if (!iso) return false;
  const t = Date.parse(iso);
  return Number.isFinite(t) && now - t > STALE_AFTER_MS;
}

/**
 * online URLs -> high; any URLs -> medium; blacklisted only -> low; else none.
 * Old-signal downgrade: medium becomes low when every URL is offline and the
 * newest is over a year old, unless a blacklist lists the host now. It only
 * applies when URLhaus returned (and we parsed) every URL: the API caps the
 * list at 100 and does not document its order, so with a truncated list the
 * newest date is unknown.
 */
export function urlhausSeverity(d: UrlhausData, now: number): Severity {
  if (d.status !== 'ok') return 'none';
  if (d.onlineCount > 0) return 'high';
  const blacklisted = isBlacklisted(d.blacklists);
  if (d.urlCount > 0) {
    const complete = d.urlsReturned >= d.urlCount && d.skipped === 0;
    return complete && isStale(d.lastAdded, now) && !blacklisted ? 'low' : 'medium';
  }
  return blacklisted ? 'low' : 'none';
}

function dblText(v: string): string {
  return DBL_TEXT.get(v.toLowerCase()) ?? v.replace(/_/g, ' ');
}

function blacklistSummary(b: UrlhausBlacklists | null): string[] {
  if (!b) return [];
  const out: string[] = [];
  if (dblListed(b.spamhaus_dbl)) out.push(`Spamhaus DBL: ${dblText(b.spamhaus_dbl)}`);
  if (surblListed(b.surbl)) out.push('SURBL: listed');
  return out;
}

export function urlhausSummary(d: UrlhausData, severity: Severity): string {
  if (d.status !== 'ok') return 'Not listed in URLhaus';
  const parts: string[] = [];
  if (d.urlCount > 0) {
    parts.push(plural(d.urlCount, 'malware URL'));
    parts.push(d.onlineCount > 0 ? `${d.onlineCount} online` : 'none online');
    if (d.lastAdded) parts.push(`newest ${day(d.lastAdded)}${severity === 'low' ? ' (old signal)' : ''}`);
  } else {
    parts.push('Known to URLhaus, no malware URLs');
  }
  parts.push(...blacklistSummary(d.blacklists));
  return parts.join(' · ');
}

/** Listed -> warn; "not listed" -> good; missing or undocumented values -> neutral text. */
function blacklistFact(label: string, v: string | null, listed: boolean, describe?: (s: string) => string): Fact {
  if (!v) return { label, value: 'unknown' };
  if (listed) return { label, value: describe ? `${v} (${describe(v)})` : v, tone: 'warn' };
  return v.toLowerCase() === NOT_LISTED ? { label, value: v, tone: 'good' } : { label, value: v };
}

export function urlhausFacts(d: UrlhausData): Fact[] {
  if (d.status !== 'ok') return [{ label: 'URLhaus', value: 'Not listed', tone: 'good' }];
  const hasUrls = d.urlCount > 0;
  const headTone: Fact['tone'] = d.onlineCount > 0 ? 'bad' : hasUrls || isBlacklisted(d.blacklists) ? 'warn' : undefined;
  const facts: Fact[] = [
    {
      label: 'URLhaus',
      value: hasUrls ? 'Listed (view host on URLhaus)' : 'Known host, no malware URLs (view on URLhaus)',
      href: urlhausHostLink(d.host),
      ...(headTone ? { tone: headTone } : {}),
    },
    {
      label: 'Malware URLs',
      value: d.urlsReturned < d.urlCount ? `${d.urlCount} (${d.urlsReturned} returned by the API)` : String(d.urlCount),
    },
    {
      label: 'Online',
      value: d.urlsReturned < d.urlCount ? `${d.onlineCount} of ${d.urlsReturned} returned` : String(d.onlineCount),
      ...(d.onlineCount > 0 ? { tone: 'bad' as const } : {}),
    },
  ];
  if (d.firstSeen) facts.push({ label: 'First seen', value: day(d.firstSeen) });
  if (d.lastAdded) facts.push({ label: 'Newest URL added', value: day(d.lastAdded) });
  if (d.blacklists) {
    facts.push(blacklistFact('Spamhaus DBL', d.blacklists.spamhaus_dbl, dblListed(d.blacklists.spamhaus_dbl), dblText));
    facts.push(blacklistFact('SURBL', d.blacklists.surbl, surblListed(d.blacklists.surbl)));
  }
  if (d.topTags.length) facts.push({ label: 'Tags', value: d.topTags.join(', ') });
  if (d.skipped > 0) {
    facts.push({ label: 'Skipped', value: plural(d.skipped, 'malformed URL entry', 'malformed URL entries'), tone: 'warn' });
  }
  if (d.urls.length && d.urls.length < d.urlsReturned - d.skipped) {
    facts.push({ label: 'Shown', value: `${d.urls.length} of ${d.urlsReturned - d.skipped} URLs (online first, then newest)` });
  }
  for (const u of d.urls) {
    const label = [u.url_status, u.date_added ? day(u.date_added) : null, u.threat, u.tags.length ? u.tags.join(', ') : null]
      .filter((x): x is string => !!x)
      .join(' · ');
    facts.push({ label, value: u.url, pivot: true, ...(u.url_status === 'online' ? { tone: 'bad' as const } : {}) });
  }
  return facts;
}

export const urlhausModule: Module<UrlhausData> = {
  id: 'urlhaus',
  label: 'URLhaus (abuse.ch)',
  version: 1,
  accepts: ['domain', 'ip'],
  key: 'abusech',
  ttl: 24 * HOUR,
  rateLimit: RATE_LIMIT,

  async run(e, ctx) {
    const host = lookupValue(e);
    const key = await authKey(ctx);
    const raw = await post(ctx, 'URLhaus', URLHAUS_API, key, new URLSearchParams({ host }));
    const data = parseUrlhaus(host, raw);
    const severity = urlhausSeverity(data, ctx.now());
    return { data, severity, summary: urlhausSummary(data, severity) };
  },

  facts: (d) => urlhausFacts(d),
};

// ---------------------------------------------------------------------------
// ThreatFox

export interface ThreatfoxIoc {
  /** ThreatFox IOC id (digits), used for the IOC page link. */
  id: string | null;
  ioc: string;
  ioc_type: string | null;
  threat_type: string | null;
  malware_printable: string | null;
  /** 0-100. */
  confidence_level: number | null;
  /** ISO 8601. */
  first_seen: string | null;
  last_seen: string | null;
  /** External reference URL (shown as text, never linked). */
  reference: string | null;
  tags: string[];
}

export interface ThreatfoxData {
  query: string;
  status: 'ok' | 'no_results';
  /** IOCs returned (valid entries). */
  count: number;
  /** Malformed IOC entries dropped while parsing. */
  skipped: number;
  maxConfidence: number | null;
  /** Distinct malware families across all IOCs. */
  malware: string[];
  /** Distinct threat types across all IOCs. */
  threatTypes: string[];
  /** Newest last_seen (or first_seen) across all IOCs, ISO 8601. */
  lastSeen: string | null;
  /** Up to MAX_IOCS, highest confidence first, then most recent. */
  iocs: ThreatfoxIoc[];
}

function parseIoc(v: unknown): ThreatfoxIoc | null {
  if (!isObj(v)) return null;
  const ioc = clean(v['ioc'], 2048);
  if (!ioc) return null;
  const rawId = v['id'];
  const id = typeof rawId === 'number' && Number.isInteger(rawId) ? String(rawId) : clean(rawId, 20);
  const conf = num(v['confidence_level']);
  return {
    id: id && /^\d{1,15}$/.test(id) ? id : null,
    ioc,
    ioc_type: clean(v['ioc_type'], 40),
    threat_type: clean(v['threat_type'], 60),
    malware_printable: clean(v['malware_printable'], 100),
    confidence_level: conf === undefined ? null : Math.max(0, Math.min(100, Math.round(conf))),
    first_seen: abuseTime(v['first_seen']),
    last_seen: abuseTime(v['last_seen']),
    reference: webUrl(v['reference']),
    tags: tagList(v['tags']),
  };
}

const iocSeen = (i: ThreatfoxIoc) => i.last_seen ?? i.first_seen;

function emptyThreatfox(query: string): ThreatfoxData {
  return { query, status: 'no_results', count: 0, skipped: 0, maxConfidence: null, malware: [], threatTypes: [], lastSeen: null, iocs: [] };
}

function distinct(values: Array<string | null>, max: number): string[] {
  const out: string[] = [];
  for (const v of values) {
    if (out.length >= max) break;
    if (v && !out.includes(v)) out.push(v);
  }
  return out;
}

/** Parse a ThreatFox search_ioc response body. Throws for statuses that are not results. */
export function parseThreatfox(query: string, raw: unknown, url = THREATFOX_API): ThreatfoxData {
  const { obj, status } = envelope('ThreatFox', url, raw);
  switch (status) {
    case 'ok':
      break;
    // Undocumented but reported: "no_result" with `data` as a message string.
    case 'no_result':
    case 'no_results':
      return emptyThreatfox(query);
    case 'illegal_search_term':
      throw new SkipError('ThreatFox does not accept this value as a search term (illegal_search_term).');
    case 'unknown_auth_key':
      throw new Error(INVALID_KEY_MSG);
    default:
      throw unexpectedStatus('ThreatFox', url, status);
  }

  const list = obj['data'];
  if (list === null || list === undefined || typeof list === 'string') return emptyThreatfox(query);
  if (!Array.isArray(list)) throw new FetchError('parse', 'Unexpected response from ThreatFox (data is not a list).', url);
  const parsed: ThreatfoxIoc[] = [];
  for (const v of list) {
    const p = parseIoc(v);
    if (p) parsed.push(p);
  }
  if (list.length > 0 && parsed.length === 0) {
    throw new FetchError('parse', `ThreatFox returned ${plural(list.length, 'IOC')} but none could be parsed (API format change?).`, url);
  }
  parsed.sort(
    (a, b) =>
      (b.confidence_level ?? -1) - (a.confidence_level ?? -1) ||
      (iocSeen(b) ?? '').localeCompare(iocSeen(a) ?? '') ||
      a.ioc.localeCompare(b.ioc),
  );
  const confidences = parsed.map((i) => i.confidence_level).filter((c): c is number => c !== null);
  return {
    query,
    status: parsed.length ? 'ok' : 'no_results',
    count: parsed.length,
    skipped: list.length - parsed.length,
    maxConfidence: confidences.length ? Math.max(...confidences) : null,
    malware: distinct(parsed.map((i) => i.malware_printable), MAX_MALWARE),
    threatTypes: distinct(parsed.map((i) => i.threat_type), MAX_MALWARE),
    lastSeen: newest(parsed.map(iocSeen)),
    iocs: parsed.slice(0, MAX_IOCS),
  };
}

/** Any IOC with confidence >= 75 -> high; any IOC -> medium; else none. */
export function threatfoxSeverity(d: ThreatfoxData): Severity {
  if (d.count === 0) return 'none';
  return (d.maxConfidence ?? 0) >= HIGH_CONFIDENCE ? 'high' : 'medium';
}

const THREAT_TEXT = new Map<string, string>([
  ['botnet_cc', 'botnet C&C'],
  ['payload_delivery', 'payload delivery'],
  ['cc_skimming', 'card skimming'],
]);

function threatText(t: string): string {
  return THREAT_TEXT.get(t.toLowerCase()) ?? t.replace(/_/g, ' ');
}

export function threatfoxSummary(d: ThreatfoxData): string {
  if (d.count === 0) return 'Not listed in ThreatFox';
  const parts = [plural(d.count, 'IOC')];
  if (d.malware.length) {
    parts.push(d.malware.slice(0, 3).join(', ') + (d.malware.length > 3 ? ` +${d.malware.length - 3} more` : ''));
  }
  if (d.threatTypes.length) parts.push(d.threatTypes.slice(0, 3).map(threatText).join(', '));
  if (d.maxConfidence !== null) parts.push(`confidence up to ${d.maxConfidence}%`);
  if (d.lastSeen) parts.push(`last seen ${day(d.lastSeen)}`);
  return parts.join(' · ');
}

function seenRange(i: ThreatfoxIoc): string | null {
  if (i.first_seen && i.last_seen && day(i.first_seen) !== day(i.last_seen)) return `${day(i.first_seen)} → ${day(i.last_seen)}`;
  const s = iocSeen(i);
  return s ? day(s) : null;
}

export function threatfoxFacts(d: ThreatfoxData): Fact[] {
  const search = threatfoxSearchLink(d.query);
  if (d.count === 0) {
    return [{ label: 'ThreatFox', value: 'Not listed (ThreatFox keeps IOCs for 6 months)', tone: 'good', href: search }];
  }
  const high = (d.maxConfidence ?? 0) >= HIGH_CONFIDENCE;
  const facts: Fact[] = [
    { label: 'ThreatFox', value: 'Listed (search ThreatFox)', href: search, tone: high ? 'bad' : 'warn' },
    { label: 'IOCs', value: d.iocs.length < d.count ? `${d.count} (${d.iocs.length} shown)` : String(d.count) },
  ];
  if (d.malware.length) facts.push({ label: 'Malware', value: d.malware.join(', ') });
  if (d.threatTypes.length) facts.push({ label: 'Threat types', value: d.threatTypes.map(threatText).join(', ') });
  if (d.maxConfidence !== null) {
    facts.push({ label: 'Max confidence', value: `${d.maxConfidence}%`, tone: high ? 'bad' : 'warn' });
  }
  const tags = distinct(d.iocs.flatMap((i) => i.tags), MAX_TOP_TAGS);
  if (tags.length) facts.push({ label: 'Tags', value: tags.join(', ') });
  if (d.skipped > 0) {
    facts.push({ label: 'Skipped', value: plural(d.skipped, 'malformed IOC entry', 'malformed IOC entries'), tone: 'warn' });
  }
  for (const i of d.iocs) {
    const label = [
      i.malware_printable ?? 'IOC',
      i.ioc_type,
      i.threat_type ? threatText(i.threat_type) : null,
      i.confidence_level !== null ? `${i.confidence_level}%` : null,
      seenRange(i),
    ]
      .filter((x): x is string => !!x)
      .join(' · ');
    facts.push({
      label,
      value: i.ioc,
      pivot: true,
      ...(i.id ? { href: threatfoxIocLink(i.id) } : {}),
      tone: (i.confidence_level ?? 0) >= HIGH_CONFIDENCE ? 'bad' : 'warn',
    });
  }
  const refs = distinct(d.iocs.map((i) => i.reference), MAX_REFERENCES);
  if (refs.length) facts.push({ label: 'References', value: refs });
  return facts;
}

export const threatfoxModule: Module<ThreatfoxData> = {
  id: 'threatfox',
  label: 'ThreatFox (abuse.ch)',
  version: 1,
  accepts: ['domain', 'ip'],
  key: 'abusech',
  ttl: 24 * HOUR,
  rateLimit: RATE_LIMIT,
  note: 'ThreatFox only exposes IOCs from the last 6 months, so "not listed" does not mean never listed.',

  async run(e, ctx) {
    const value = lookupValue(e);
    const key = await authKey(ctx);
    const raw = await postThreatfox(ctx, key, { query: 'search_ioc', search_term: value, exact_match: true });
    const data = parseThreatfox(value, raw);
    return { data, severity: threatfoxSeverity(data), summary: threatfoxSummary(data) };
  },

  facts: (d) => threatfoxFacts(d),
};

// ---------------------------------------------------------------------------
// Settings-page "Test" (the lead registers it for 'abusech')

/** One cheap authenticated call: ThreatFox `types` (documented, small payload). */
export const abusechKeyTest: KeyTester = async (key, http) => {
  const k = key.trim();
  if (!k) throw new Error('Enter your abuse.ch Auth-Key first.');
  checkKeyChars(k);
  const raw = await postThreatfox(http, k, { query: 'types' });
  if (!isObj(raw)) throw new Error('Unexpected response from ThreatFox while testing the key.');
  const status = clean(raw['query_status'], 60);
  if (status === 'unknown_auth_key') throw new Error(INVALID_KEY_MSG);
  if (status !== 'ok') {
    throw new Error(`Unexpected response from ThreatFox while testing the key${status ? ` (query_status "${status}")` : ''}.`);
  }
  const types = raw['data'];
  const n = isObj(types) ? Object.keys(types).length : Array.isArray(types) ? types.length : 0;
  // Only ThreatFox was called: say what was verified (URLhaus uses the same abuse.ch key).
  return `Auth-Key accepted by abuse.ch ThreatFox${n ? ` (${n} IOC types)` : ''}. URLhaus uses the same key.`;
};
