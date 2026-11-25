import { FetchError, type Http } from '@/lib/http';
import { isPublicIp, normalizeIp } from '@/lib/ip';
import type { KeyTester } from '@/lib/keytest';
import type { Ctx, Fact, JsonResponse, Module, Severity } from '@/lib/types';
import { DAY, HOUR, MINUTE, SkipError } from '@/lib/types';

/**
 * AbuseIPDB reputation check (APIv2). See docs/research/threat-intel.md §10.
 *
 * - GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=90
 *   with headers `Key: <key>` and `Accept: application/json`. IPv4 and IPv6
 *   are both accepted; the address is URL-encoded with encodeURIComponent.
 *   IPv4-mapped IPv6 (::ffff:a.b.c.d) is checked as the IPv4 address.
 * - An address nobody reported is not a 404: it is a 200 with
 *   abuseConfidenceScore 0 and totalReports 0.
 * - Errors use `{"errors":[{"detail","status"}]}`: 401 bad key (undocumented,
 *   seen live), 422 bad parameters, 429 daily quota (free plan 1,000 checks/day)
 *   with X-RateLimit-* and Retry-After headers.
 * - `verbose` is not requested: it adds every individual report in the window,
 *   which can be very large for noisy addresses.
 */

const API = 'https://api.abuseipdb.com/api/v2/check';
const GUI = 'https://www.abuseipdb.com/check/';
/** Report window the score and counts cover. */
export const MAX_AGE_DAYS = 90;
/** Reverse-DNS hostnames kept in `data`. */
export const MAX_HOSTNAMES = 10;
/** Address used by the settings-page key test (a cheap, well-known public IP). */
export const TEST_IP = '1.1.1.1';
const MAX_STR = 200;
const MAX_DETAIL = 300;
/** Error statuses whose JSON body and rate-limit headers we read ourselves. */
const HANDLED_ERRORS = [401, 403, 422, 429];
/** Per-investigation flag: once the daily quota is gone, later lookups fail fast. */
const QUOTA_MEMO = 'abuseipdb:quota';
/** How long lookups fail fast after a 429 that gave no reset time. */
const QUOTA_HOLD = 10 * MINUTE;

export interface AbuseIpdbData {
  /** The address that was checked (canonical form). */
  ipAddress: string;
  /** 0-100. */
  abuseConfidenceScore: number;
  /** Reports within the last `maxAgeInDays` days. */
  totalReports: number;
  numDistinctUsers: number;
  /** ISO 8601 (UTC) or null when never reported in the window. */
  lastReportedAt: string | null;
  countryCode: string | null;
  isp: string | null;
  domain: string | null;
  usageType: string | null;
  /** AbuseIPDB's allow-list; null when the API did not say. */
  isWhitelisted: boolean | null;
  isTor: boolean;
  isPublic: boolean | null;
  /** At most MAX_HOSTNAMES. */
  hostnames: string[];
  /** Hostnames the API returned before capping. */
  hostnamesTotal: number;
  maxAgeInDays: number;
  /** AbuseIPDB web page for the address. */
  guiUrl: string;
}

// ---------------------------------------------------------------------------
// Defensive JSON helpers

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function finiteNumber(v: unknown): number | undefined {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string' && /^\s*-?\d{1,15}(\.\d+)?\s*$/.test(v)) return Number(v);
  return undefined;
}

/** Non-negative integer count; junk -> 0. */
function count(v: unknown): number {
  const n = finiteNumber(v);
  return n !== undefined && n > 0 ? Math.floor(n) : 0;
}

function text(v: unknown): string | null {
  const s = str(v)?.trim().slice(0, MAX_STR);
  return s ? s : null;
}

function bool(v: unknown): boolean | null {
  return typeof v === 'boolean' ? v : null;
}

function toIso(v: unknown): string | null {
  const s = str(v);
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

function cleanHostnames(v: unknown): { list: string[]; total: number } {
  if (!Array.isArray(v)) return { list: [], total: 0 };
  const seen = new Set<string>();
  for (const h of v) {
    const s = str(h)?.trim().toLowerCase().replace(/\.$/, '');
    if (s && s.length <= 253 && /^[a-z0-9._-]+$/.test(s)) seen.add(s);
  }
  const all = [...seen];
  return { list: all.slice(0, MAX_HOSTNAMES), total: all.length };
}

/**
 * `::ffff:a.b.c.d` (normalizeIp gives `::ffff:xxxx:yyyy`) is an IPv4 address in
 * IPv6 clothing: AbuseIPDB's reports are filed against the IPv4 form.
 */
export function unmapIPv4(ip: string): string {
  const m = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(ip);
  if (!m) return ip;
  const hi = parseInt(m[1]!, 16);
  const lo = parseInt(m[2]!, 16);
  return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
}

export function guiUrl(ip: string): string {
  return `${GUI}${encodeURIComponent(ip)}`;
}

/** Turn the `data` object of a check response into compact module data. Throws on an unusable payload. */
export function parseCheck(body: unknown, queried: string, url: string, maxAgeInDays = MAX_AGE_DAYS): AbuseIpdbData {
  const d = isObj(body) ? body['data'] : undefined;
  if (!isObj(d)) {
    const detail = errorDetail(body);
    throw new FetchError('parse', `Unexpected response from AbuseIPDB (no check result)${detail ? `: ${detail}` : ''}.`, url);
  }
  const score = finiteNumber(d['abuseConfidenceScore']);
  if (score === undefined) throw new FetchError('parse', 'Unexpected response from AbuseIPDB (no abuseConfidenceScore).', url);

  const returned = str(d['ipAddress']);
  const ipAddress = (returned ? normalizeIp(returned) : null) ?? queried;
  const hostnames = cleanHostnames(d['hostnames']);
  return {
    ipAddress,
    abuseConfidenceScore: Math.min(100, Math.max(0, Math.round(score))),
    totalReports: count(d['totalReports']),
    numDistinctUsers: count(d['numDistinctUsers']),
    lastReportedAt: toIso(d['lastReportedAt']),
    countryCode: text(d['countryCode'])?.toUpperCase().slice(0, 8) ?? null,
    isp: text(d['isp']),
    domain: text(d['domain'])?.toLowerCase() ?? null,
    usageType: text(d['usageType']),
    isWhitelisted: bool(d['isWhitelisted']),
    isTor: d['isTor'] === true,
    isPublic: bool(d['isPublic']),
    hostnames: hostnames.list,
    hostnamesTotal: hostnames.total,
    maxAgeInDays,
    guiUrl: guiUrl(ipAddress),
  };
}

// ---------------------------------------------------------------------------
// Verdict

/** Allow-listed -> none; score >= 75 high; >= 25 medium; any score or report -> low; else none. */
export function abuseipdbSeverity(d: Pick<AbuseIpdbData, 'isWhitelisted' | 'abuseConfidenceScore' | 'totalReports'>): Severity {
  if (d.isWhitelisted) return 'none';
  if (d.abuseConfidenceScore >= 75) return 'high';
  if (d.abuseConfidenceScore >= 25) return 'medium';
  if (d.abuseConfidenceScore > 0 || d.totalReports > 0) return 'low';
  return 'none';
}

function plural(n: number, word: string): string {
  return `${n.toLocaleString('en-US')} ${word}${n === 1 ? '' : 's'}`;
}

const day = (iso: string) => iso.slice(0, 10);

export function summarise(d: AbuseIpdbData): string {
  const parts: string[] = [];
  if (d.isWhitelisted) parts.push('Allow-listed by AbuseIPDB');
  if (d.abuseConfidenceScore === 0 && d.totalReports === 0) {
    parts.push(`No reports in the last ${d.maxAgeInDays} days`);
  } else {
    parts.push(`Confidence ${d.abuseConfidenceScore}%`);
    // The score can outlive the report window: don't print "0 reports from 0 users".
    if (d.totalReports === 0) parts.push(`no reports in the last ${d.maxAgeInDays} days`);
    else parts.push(`${plural(d.totalReports, 'report')} from ${plural(d.numDistinctUsers, 'user')}`);
    if (d.lastReportedAt) parts.push(`last ${day(d.lastReportedAt)}`);
  }
  if (d.isTor) parts.push('Tor exit');
  if (d.isPublic === false) parts.push('not a public address');
  return parts.join(' · ');
}

export function abuseipdbFacts(d: AbuseIpdbData): Fact[] {
  const sev = abuseipdbSeverity(d);
  const tone: Fact['tone'] = d.isWhitelisted
    ? undefined
    : sev === 'high'
      ? 'bad'
      : sev === 'medium' || sev === 'low'
        ? 'warn'
        : 'good';
  const facts: Fact[] = [
    { label: 'Abuse confidence', value: `${d.abuseConfidenceScore}%`, ...(tone ? { tone } : {}) },
    {
      label: `Reports (${d.maxAgeInDays} days)`,
      value: d.totalReports === 0 ? 'None' : `${d.totalReports.toLocaleString('en-US')} from ${plural(d.numDistinctUsers, 'distinct user')}`,
    },
  ];
  if (d.lastReportedAt) facts.push({ label: 'Last reported', value: `${d.lastReportedAt.slice(0, 16).replace('T', ' ')} UTC` });
  if (d.isWhitelisted) facts.push({ label: 'Allow-listed', value: 'Yes (AbuseIPDB treats this address as trusted)', tone: 'good' });
  if (d.isTor) facts.push({ label: 'Tor exit node', value: 'Yes', tone: 'warn' });
  if (d.isPublic === false) facts.push({ label: 'Public address', value: 'No (private or reserved range)', tone: 'warn' });
  if (d.usageType) facts.push({ label: 'Usage type', value: d.usageType });
  if (d.isp) facts.push({ label: 'ISP', value: d.isp });
  if (d.domain) facts.push({ label: 'ISP domain', value: d.domain });
  if (d.countryCode) facts.push({ label: 'Country', value: d.countryCode });
  if (d.hostnames.length) {
    facts.push({
      label: d.hostnamesTotal > d.hostnames.length ? `Hostnames (${d.hostnames.length} of ${d.hostnamesTotal})` : 'Hostnames',
      value: d.hostnames,
      pivot: true,
    });
  }
  facts.push({ label: 'AbuseIPDB', value: `abuseipdb.com/check/${d.ipAddress}`, href: d.guiUrl });
  return facts;
}

// ---------------------------------------------------------------------------
// Errors

function parseBody(body: string | undefined): unknown {
  if (!body) return undefined;
  try {
    return JSON.parse(body) as unknown;
  } catch {
    return undefined;
  }
}

/** `errors[].detail` (first three), or a top-level message. */
function errorDetail(body: unknown): string | undefined {
  if (!isObj(body)) return undefined;
  const out: string[] = [];
  const errs = body['errors'];
  if (Array.isArray(errs)) {
    for (const e of errs.slice(0, 3)) {
      const d = isObj(e) ? str(e['detail'])?.trim() : undefined;
      if (d) out.push(d.replace(/\.$/, ''));
    }
  }
  if (!out.length) {
    const m = str(body['message'])?.trim() ?? str(body['detail'])?.trim();
    if (m) out.push(m.replace(/\.$/, ''));
  }
  const s = out.join('; ').slice(0, MAX_DETAIL);
  return s || undefined;
}

function formatWait(ms: number): string {
  if (ms < MINUTE) return 'under a minute';
  if (ms < HOUR) return `about ${Math.ceil(ms / MINUTE)} min`;
  return `about ${Math.ceil(ms / HOUR)} h`;
}

/** Time until the quota resets, from X-RateLimit-Reset (epoch) or Retry-After (seconds); at most a day. */
function resetIn(headers: Headers | undefined, now: number): number | undefined {
  if (!headers) return undefined;
  const reset = finiteNumber(headers.get('x-ratelimit-reset'));
  if (reset !== undefined && reset > 0) {
    const ms = (reset > 1e12 ? reset : reset * 1000) - now;
    if (ms > 0) return Math.min(ms, DAY);
  }
  const retry = finiteNumber(headers.get('retry-after'));
  return retry !== undefined && retry > 0 ? Math.min(retry * 1000, DAY) : undefined;
}

/** A final 429: the daily check quota is used up. Carries what is needed to fail later lookups fast. */
class QuotaError extends FetchError {
  constructor(
    message: string,
    url: string,
    body: string | undefined,
    /** The provider's own words, already cleaned. */
    readonly detail: string | undefined,
    /** Epoch ms when the quota resets, when the response said. */
    readonly resetAt: number | undefined,
  ) {
    super('http', message, url, 429, body);
  }
}

function quotaMessage(detail: string | undefined, waitMs: number | undefined): string {
  return (
    `AbuseIPDB quota exhausted (HTTP 429)${detail ? `: ${detail}` : ''}. The free plan allows 1,000 checks per day` +
    `${waitMs !== undefined && waitMs > 0 ? `; the quota resets in ${formatWait(waitMs)}` : ''}.`
  );
}

function apiError(status: number, detail: string | undefined, url: string, now: number, headers?: Headers, body?: string): FetchError {
  const said = detail ? `: ${detail}` : '';
  let msg: string;
  switch (status) {
    case 401:
      msg = `AbuseIPDB rejected the API key (HTTP 401)${said}. Check the key in settings (an APIv2 key is required).`;
      break;
    case 403:
      msg = `AbuseIPDB refused the request (HTTP 403)${said}. Check the API key and your AbuseIPDB account.`;
      break;
    case 422:
      msg = `AbuseIPDB rejected the lookup (HTTP 422)${said}.`;
      break;
    case 429: {
      // "See headers for additional details" points at something the user never sees.
      const clean = detail?.replace(/[.\s]*See headers for additional details[.\s]*$/i, '').trim() || undefined;
      const wait = resetIn(headers, now);
      return new QuotaError(quotaMessage(clean, wait), url, body, clean, wait !== undefined ? now + wait : undefined);
    }
    default:
      msg = `AbuseIPDB error (HTTP ${status})${said}.`;
  }
  return new FetchError('http', msg, url, status, body);
}

/** Never let the key leak into a message, even if a provider echoes it. */
function redact(err: unknown, key: string): unknown {
  if (!(err instanceof FetchError) || !key || !(err.message.includes(key) || err.body?.includes(key))) return err;
  const scrub = (s: string) => s.split(key).join('[redacted]');
  const body = err.body !== undefined ? scrub(err.body) : undefined;
  if (err instanceof QuotaError) {
    return new QuotaError(scrub(err.message), err.url, body, err.detail !== undefined ? scrub(err.detail) : undefined, err.resetAt);
  }
  return new FetchError(err.kind, scrub(err.message), err.url, err.status, body);
}

function checkUrl(ip: string, maxAgeInDays: number): string {
  return `${API}?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=${maxAgeInDays}`;
}

async function requestCheck(
  http: Pick<Http, 'fetchJson'>,
  ip: string,
  key: string,
  maxAgeInDays: number,
  now: () => number,
  rateLimit?: false,
): Promise<JsonResponse<unknown>> {
  const url = checkUrl(ip, maxAgeInDays);
  let res: JsonResponse<unknown>;
  try {
    res = await http.fetchJson<unknown>(url, {
      // Lowercase `accept` replaces fetchJson's default instead of adding a second Accept header.
      headers: { Key: key, accept: 'application/json' },
      okStatuses: HANDLED_ERRORS,
      ...(rateLimit === false ? { rateLimit: false as const } : {}),
    });
  } catch (err) {
    if (err instanceof FetchError && err.status !== undefined && (err.status < 200 || err.status > 299)) {
      // Other HTTP errors (5xx...), or a non-JSON body on a handled status (e.g. an HTML 401).
      if (err.kind === 'http' || err.kind === 'parse') {
        throw redact(apiError(err.status, errorDetail(parseBody(err.body)), url, now(), undefined, err.body), key);
      }
    }
    if (err instanceof FetchError && err.kind === 'parse') {
      throw new FetchError('parse', 'Unexpected response from AbuseIPDB (not JSON).', url, err.status);
    }
    throw redact(err, key);
  }
  if (res.status < 200 || res.status > 299) {
    throw redact(apiError(res.status, errorDetail(res.data), url, now(), res.headers), key);
  }
  return res;
}

function validKey(raw: string | undefined): string | undefined {
  const key = raw?.trim();
  if (!key) return undefined;
  // Header values must be visible ASCII; anything else would surface as a confusing network error.
  if (!/^[\x21-\x7e]+$/.test(key)) throw new Error('The AbuseIPDB API key contains invalid characters. Re-enter it in settings.');
  return key;
}

// ---------------------------------------------------------------------------

interface QuotaState {
  /**
   * Set by a final 429. Until `until`, later lookups in this investigation
   * (including per-card refreshes) fail fast without spending a request.
   */
  exhausted?: { detail: string | undefined; resetAt: number | undefined; until: number };
}

export const abuseipdbModule: Module<AbuseIpdbData> = {
  id: 'abuseipdb',
  label: 'AbuseIPDB',
  version: 1,
  accepts: ['ip'],
  key: 'abuseipdb',
  ttl: 24 * HOUR,
  // Free plan: 1,000 checks/day; no per-minute limit is documented. Keeps bursts polite.
  rateLimit: { perMinute: 30 },
  note: `Score and report counts cover the last ${MAX_AGE_DAYS} days. The free plan allows 1,000 checks per day.`,

  async run(e, ctx: Ctx) {
    if (e.kind !== 'ip') throw new SkipError('AbuseIPDB checks IP addresses only.');
    const normalized = normalizeIp(e.value);
    if (!normalized) throw new SkipError('Not a valid IP address.');
    if (!isPublicIp(normalized)) throw new SkipError('Private or reserved address: AbuseIPDB only tracks public IPs.');
    const ip = unmapIPv4(normalized);
    const key = validKey(await ctx.getKey('abuseipdb'));
    if (!key) throw new SkipError('Add an AbuseIPDB API key in settings to enable this check.');

    const url = checkUrl(ip, MAX_AGE_DAYS);
    const quota = await ctx.shared.memo<QuotaState>(QUOTA_MEMO, async () => ({}));
    const held = quota.exhausted;
    if (held) {
      const now = ctx.now();
      if (now < held.until) {
        throw new FetchError('http', quotaMessage(held.detail, held.resetAt !== undefined ? held.resetAt - now : undefined), url, 429);
      }
      delete quota.exhausted;
    }

    let res: JsonResponse<unknown>;
    try {
      res = await requestCheck(ctx, ip, key, MAX_AGE_DAYS, () => ctx.now());
    } catch (err) {
      if (err instanceof FetchError && err.status === 429) {
        const resetAt = err instanceof QuotaError ? err.resetAt : undefined;
        quota.exhausted = {
          detail: err instanceof QuotaError ? err.detail : undefined,
          resetAt,
          until: resetAt ?? ctx.now() + QUOTA_HOLD,
        };
      }
      throw err;
    }
    let data: AbuseIpdbData;
    try {
      data = parseCheck(res.data, ip, url);
    } catch (err) {
      throw redact(err, key);
    }
    return { data, summary: summarise(data), severity: abuseipdbSeverity(data) };
  },

  facts: abuseipdbFacts,
};

/** Settings-page "Test": one check of a well-known public IP (uses 1 of the daily checks). */
export const abuseipdbKeyTest: KeyTester = async (rawKey, http) => {
  const key = validKey(rawKey);
  if (!key) throw new Error('Enter an AbuseIPDB API key first.');
  const res = await requestCheck(http, TEST_IP, key, 1, () => Date.now(), false);
  // A 200 proves the key only if it really is a check result (not e.g. `{}` from a proxy).
  try {
    parseCheck(res.data, TEST_IP, res.url, 1);
  } catch (err) {
    throw redact(err, key);
  }
  const remaining = finiteNumber(res.headers.get('x-ratelimit-remaining'));
  const limit = finiteNumber(res.headers.get('x-ratelimit-limit'));
  if (remaining === undefined || remaining < 0) return 'Key valid.';
  const left = Math.floor(remaining).toLocaleString('en-US');
  return limit !== undefined && limit > 0
    ? `Key valid · ${left} of ${Math.floor(limit).toLocaleString('en-US')} daily checks left.`
    : `Key valid · ${left} checks left today.`;
};
