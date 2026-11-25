import { FetchError, isAbortError } from '@/lib/http';
import { normalizeIp } from '@/lib/ip';
import type { KeyTester } from '@/lib/keytest';
import type { Ctx, Entity, Fact, Module, Pivot, Severity } from '@/lib/types';
import { HOUR, MINUTE, SkipError } from '@/lib/types';

/**
 * VirusTotal API v3. See docs/research/threat-intel.md §8.
 *
 * - Auth: `x-apikey` header on every call.
 * - Domain: GET /domains/{d} then (only when found) one page of
 *   /domains/{d}/resolutions; resolutions become IP pivots.
 * - IP (v4 and v6): GET /ip_addresses/{ip}.
 * - 404 NotFoundError = "not in VirusTotal": a result (found:false), not an error.
 * - Public API: 4 requests/min and 500/day (daily quota resets 00:00 UTC),
 *   non-commercial use only, and every queried indicator joins the VT dataset.
 */

const API = 'https://www.virustotal.com/api/v3';
const GUI = 'https://www.virustotal.com/gui';
/** One page of resolutions. The docs give no maximum; 40 is the usual relationship ceiling. */
/** Cache TTL for a verdict whose resolutions call failed. */
const PARTIAL_TTL = 10 * MINUTE;

export const RESOLUTIONS_LIMIT = 40;
export const MAX_CATEGORIES = 12;
export const MAX_TAGS = 20;
export const MAX_FLAGGED = 20;
const MAX_STR = 200;
const MAX_TAG_LEN = 64;
/** Year 10000 in unix seconds: beyond this Date#toISOString changes format. */
const MAX_UNIX_S = 253_402_300_800;

export interface VtStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout: number;
}

export interface VtResolution {
  ip: string;
  /** When VirusTotal last saw the domain resolve to this IP. */
  date: string | null;
}

export interface VtEngineHit {
  engine: string;
  category: 'malicious' | 'suspicious';
  /** The engine's label, e.g. "phishing". */
  result: string | null;
}

export interface VtData {
  kind: 'domain' | 'ip';
  /** The normalised value that was looked up. */
  indicator: string;
  /** false = VirusTotal has no object for this indicator (HTTP 404). */
  found: boolean;
  /** last_analysis_stats; null when not found or never analysed. */
  stats: VtStats | null;
  /** Engines in the last analysis (sum of the stats). */
  engines: number;
  /** Community reputation score (negative is bad). */
  reputation: number | null;
  votes: { harmless: number; malicious: number } | null;
  /** Distinct vendor categories (capped). */
  categories: string[];
  tags: string[];
  /** Engines that flagged the indicator, malicious first (capped). */
  flaggedBy: VtEngineHit[];
  registrar?: string;
  creationDate?: string;
  lastAnalysisDate?: string;
  asOwner?: string;
  asn?: number;
  country?: string;
  network?: string;
  /** Domain only: distinct IPs, most recently seen first (capped at RESOLUTIONS_LIMIT). */
  resolutions: VtResolution[];
  /** Total resolutions VirusTotal reports (meta.count); null when unknown. */
  resolutionsTotal: number | null;
  /** More resolutions exist beyond the page we fetched. */
  resolutionsTruncated: boolean;
  /** The resolutions call failed; the domain verdict is still valid. */
  resolutionsError?: string;
  guiUrl: string;
}

// ---------------------------------------------------------------------------
// Defensive JSON helpers

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function clip(s: string, n = MAX_STR): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

/** Trimmed non-empty string, clipped. */
function str(v: unknown, n = MAX_STR): string | undefined {
  if (typeof v !== 'string') return undefined;
  const t = v.trim();
  return t ? clip(t, n) : undefined;
}

function finite(v: unknown): number | undefined {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string' && /^-?\d{1,15}$/.test(v.trim())) return Number(v.trim());
  return undefined;
}

function count(v: unknown): number | undefined {
  const n = finite(v);
  return n !== undefined && n >= 0 ? Math.floor(n) : undefined;
}

/** Unix seconds -> ISO; 0, negatives and junk -> undefined. */
function unixToIso(v: unknown): string | undefined {
  const n = finite(v);
  if (n === undefined || n <= 0 || n >= MAX_UNIX_S) return undefined;
  return new Date(Math.floor(n) * 1000).toISOString();
}

const STAT_KEYS = ['malicious', 'suspicious', 'harmless', 'undetected', 'timeout'] as const;

export function parseStats(v: unknown): VtStats | null {
  if (!isObj(v)) return null;
  if (!STAT_KEYS.some((k) => count(v[k]) !== undefined)) return null;
  return {
    malicious: count(v['malicious']) ?? 0,
    suspicious: count(v['suspicious']) ?? 0,
    harmless: count(v['harmless']) ?? 0,
    undetected: count(v['undetected']) ?? 0,
    timeout: count(v['timeout']) ?? 0,
  };
}

function engineTotal(s: VtStats | null): number {
  return s ? s.malicious + s.suspicious + s.harmless + s.undetected + s.timeout : 0;
}

/** Distinct strings (case-insensitive, first spelling wins), capped. */
function distinct(values: unknown[], max: number, len = MAX_STR): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const v of values) {
    if (out.length >= max) break;
    const s = str(v, len);
    if (!s) continue;
    const k = s.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(s);
  }
  return out;
}

function parseCategories(v: unknown): string[] {
  return isObj(v) ? distinct(Object.values(v), MAX_CATEGORIES) : [];
}

function parseTags(v: unknown): string[] {
  return Array.isArray(v) ? distinct(v, MAX_TAGS, MAX_TAG_LEN) : [];
}

function parseVotes(v: unknown): VtData['votes'] {
  if (!isObj(v)) return null;
  const harmless = count(v['harmless']);
  const malicious = count(v['malicious']);
  if (harmless === undefined && malicious === undefined) return null;
  return { harmless: harmless ?? 0, malicious: malicious ?? 0 };
}

export function parseFlagged(v: unknown): VtEngineHit[] {
  if (!isObj(v)) return [];
  const hits: VtEngineHit[] = [];
  for (const [name, r] of Object.entries(v)) {
    if (!isObj(r)) continue;
    const category = r['category'];
    if (category !== 'malicious' && category !== 'suspicious') continue;
    const engine = str(r['engine_name'], 80) ?? str(name, 80);
    if (!engine) continue;
    hits.push({ engine, category, result: str(r['result'], 80) ?? null });
  }
  hits.sort((a, b) =>
    a.category === b.category ? a.engine.localeCompare(b.engine) : a.category === 'malicious' ? -1 : 1,
  );
  return hits.slice(0, MAX_FLAGGED);
}

// ---------------------------------------------------------------------------
// Errors

function parseBody(body: string | undefined): Obj | undefined {
  if (!body) return undefined;
  try {
    const j: unknown = JSON.parse(body);
    return isObj(j) ? j : undefined;
  } catch {
    return undefined;
  }
}

/** VirusTotal error bodies are always {"error":{"code","message"}}. */
function errorInfo(body: string | undefined): { code?: string; message?: string } {
  const err = parseBody(body)?.['error'];
  if (!isObj(err)) return {};
  const code = str(err['code'], 60);
  const message = str(err['message'], 160);
  return { ...(code ? { code } : {}), ...(message ? { message } : {}) };
}

const QUOTA_HINT = 'The public API allows 4 lookups/min and 500/day; the daily quota resets at 00:00 UTC.';

/** Clear message for an HTTP error from VirusTotal (never includes the key). */
export function vtErrorMessage(status: number, body: string | undefined): string {
  const { code, message } = errorInfo(body);
  const detail = message ? `: ${message}` : '';
  switch (status) {
    case 401:
      if (code === 'UserNotActiveError') return 'VirusTotal says this account is not active (UserNotActiveError). Check your VirusTotal account.';
      if (code === 'AuthenticationRequiredError') return 'VirusTotal did not receive an API key (AuthenticationRequiredError). Re-enter it in settings.';
      return `VirusTotal rejected the API key (${code ?? 'HTTP 401'}${detail}). Check it in settings.`;
    case 403:
      return `VirusTotal refused access (${code ?? 'HTTP 403'}${detail}). The key may not be allowed to use this endpoint.`;
    case 429:
      if (code === 'TooManyRequestsError') return `VirusTotal is rate limiting requests (TooManyRequestsError). Try again in a minute.`;
      return `VirusTotal quota exceeded (${code ?? 'HTTP 429'}). ${QUOTA_HINT}`;
    case 400:
      return `VirusTotal rejected the lookup (${code ?? 'HTTP 400'}${detail}).`;
    case 503:
      return `VirusTotal is temporarily unavailable (${code ?? 'HTTP 503'}). Try again later.`;
    default:
      return `VirusTotal error (HTTP ${status}${code ? ` ${code}` : ''}${detail}).`;
  }
}

function redact(s: string, key: string): string {
  return s.split(key).join('[key]');
}

/** Provider-specific message; the raw body is dropped and the key never survives into the message. */
function mapError(err: unknown, key: string): unknown {
  if (err instanceof FetchError && err.kind === 'http' && err.status !== undefined) {
    // Redact before vtErrorMessage clips the detail, so no partial key can survive.
    const body = err.body === undefined ? undefined : redact(err.body, key);
    return new FetchError('http', vtErrorMessage(err.status, body), err.url, err.status);
  }
  return err;
}

// ---------------------------------------------------------------------------
// Requests

/** Path segment: percent-encoded, but colons (legal in a segment) stay raw for IPv6. */
function seg(v: string): string {
  return encodeURIComponent(v).replace(/%3A/gi, ':');
}

async function getJson(ctx: Ctx, url: string, key: string): Promise<{ status: number; data: unknown }> {
  try {
    const res = await ctx.fetchJson<unknown>(url, { headers: { 'x-apikey': key }, okStatuses: [404] });
    return { status: res.status, data: res.data };
  } catch (err) {
    // A 404 is "not found" whatever its body looks like.
    if (err instanceof FetchError && err.kind === 'parse' && err.status === 404) return { status: 404, data: null };
    throw mapError(err, key);
  }
}

/** attributes of a domain / ip_address object, or null when VirusTotal has no such object. */
async function getObject(ctx: Ctx, url: string, key: string): Promise<Obj | null> {
  const { status, data } = await getJson(ctx, url, key);
  if (status === 404) return null;
  const obj = isObj(data) ? data['data'] : undefined;
  const attrs = isObj(obj) ? obj['attributes'] : undefined;
  if (!isObj(attrs)) throw new FetchError('parse', 'Unexpected response from VirusTotal (no data.attributes object)', url, status);
  return attrs;
}

interface ResolutionPage {
  list: VtResolution[];
  total: number | null;
  truncated: boolean;
}

export function parseResolutions(data: unknown, url: string): ResolutionPage {
  const list = isObj(data) ? data['data'] : undefined;
  if (!Array.isArray(list)) throw new FetchError('parse', 'Unexpected resolutions response from VirusTotal (no data array)', url);
  const byIp = new Map<string, VtResolution>();
  for (const item of list) {
    const attrs = isObj(item) ? item['attributes'] : undefined;
    if (!isObj(attrs)) continue;
    const raw = attrs['ip_address'];
    const ip = typeof raw === 'string' ? normalizeIp(raw) : null;
    if (!ip) continue;
    const date = unixToIso(attrs['date']) ?? null;
    const prev = byIp.get(ip);
    if (!prev || (date && (!prev.date || date > prev.date))) byIp.set(ip, { ip, date });
  }
  const resolutions = [...byIp.values()]
    .sort((a, b) => (a.date === b.date ? 0 : !a.date ? 1 : !b.date ? -1 : a.date < b.date ? 1 : -1))
    .slice(0, RESOLUTIONS_LIMIT);
  const meta = isObj(data) ? data['meta'] : undefined;
  const links = isObj(data) ? data['links'] : undefined;
  const metaCount = isObj(meta) ? count(meta['count']) : undefined;
  const next = (isObj(links) && str(links['next'])) || (isObj(meta) && str(meta['cursor']));
  const total = metaCount !== undefined ? Math.max(metaCount, list.length) : null;
  return { list: resolutions, total, truncated: !!next || (total !== null && total > list.length) };
}

async function getResolutions(ctx: Ctx, domain: string, key: string): Promise<ResolutionPage> {
  const url = `${API}/domains/${seg(domain)}/resolutions?limit=${RESOLUTIONS_LIMIT}`;
  const { status, data } = await getJson(ctx, url, key);
  if (status === 404) return { list: [], total: 0, truncated: false };
  return parseResolutions(data, url);
}

// ---------------------------------------------------------------------------
// Data, severity, summary

export function guiUrl(kind: VtData['kind'], indicator: string): string {
  return `${GUI}/${kind === 'ip' ? 'ip-address' : 'domain'}/${seg(indicator)}`;
}

function emptyData(kind: VtData['kind'], indicator: string): VtData {
  return {
    kind,
    indicator,
    found: false,
    stats: null,
    engines: 0,
    reputation: null,
    votes: null,
    categories: [],
    tags: [],
    flaggedBy: [],
    resolutions: [],
    // Unknown until the resolutions call succeeds (never made for IPs or unknown domains).
    resolutionsTotal: null,
    resolutionsTruncated: false,
    guiUrl: guiUrl(kind, indicator),
  };
}

export function buildData(kind: VtData['kind'], indicator: string, attrs: Obj | null): VtData {
  const d = emptyData(kind, indicator);
  if (!attrs) return d;
  const stats = parseStats(attrs['last_analysis_stats']);
  const rep = finite(attrs['reputation']);
  const registrar = kind === 'domain' ? str(attrs['registrar']) : undefined;
  const creationDate = kind === 'domain' ? unixToIso(attrs['creation_date']) : undefined;
  const lastAnalysisDate = unixToIso(attrs['last_analysis_date']);
  const asOwner = kind === 'ip' ? str(attrs['as_owner']) : undefined;
  const asn = kind === 'ip' ? count(attrs['asn']) : undefined;
  const country = kind === 'ip' ? str(attrs['country'], 8) : undefined;
  const network = kind === 'ip' ? str(attrs['network'], 64) : undefined;
  return {
    ...d,
    found: true,
    stats,
    engines: engineTotal(stats),
    reputation: rep !== undefined ? Math.trunc(rep) : null,
    votes: parseVotes(attrs['total_votes']),
    categories: parseCategories(attrs['categories']),
    tags: parseTags(attrs['tags']),
    flaggedBy: parseFlagged(attrs['last_analysis_results']),
    ...(registrar ? { registrar } : {}),
    ...(creationDate ? { creationDate } : {}),
    ...(lastAnalysisDate ? { lastAnalysisDate } : {}),
    ...(asOwner ? { asOwner } : {}),
    ...(asn !== undefined ? { asn } : {}),
    ...(country ? { country } : {}),
    ...(network ? { network } : {}),
  };
}

/**
 * Conservative mapping from engine detections: a single engine is often a
 * false positive, so "high" needs at least five.
 */
export function severityOf(stats: VtStats | null): Severity {
  if (!stats) return 'none';
  if (stats.malicious >= 5) return 'high';
  if (stats.malicious >= 1 || stats.suspicious >= 3) return 'medium';
  if (stats.suspicious >= 1) return 'low';
  return 'none';
}

function plural(n: number | string, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

function resolutionCount(d: VtData): string | number {
  if (d.resolutionsTotal !== null) return d.resolutionsTotal;
  return d.resolutionsTruncated ? `${d.resolutions.length}+` : d.resolutions.length;
}

function asLabel(d: VtData): string | undefined {
  if (d.asn !== undefined) return d.asOwner ? `AS${d.asn} ${d.asOwner}` : `AS${d.asn}`;
  return d.asOwner;
}

/** Stats from at least one engine. An all-zero last_analysis_stats means "not scanned yet", not "clean". */
function analysed(d: VtData): d is VtData & { stats: VtStats } {
  return d.stats !== null && d.engines > 0;
}

export function summarise(d: VtData): string {
  if (!d.found) return 'Not in VirusTotal';
  const parts: string[] = [];
  if (analysed(d)) {
    parts.push(`${d.stats.malicious}/${d.engines} malicious`);
    if (d.stats.suspicious > 0) parts.push(`${d.stats.suspicious} suspicious`);
  } else {
    parts.push('no analysis yet');
  }
  if (d.reputation !== null) parts.push(`reputation ${d.reputation}`);
  if (d.kind === 'domain') {
    parts.push(d.resolutionsError ? 'resolutions unavailable' : plural(resolutionCount(d), 'resolution'));
  } else {
    const as = asLabel(d);
    if (as) parts.push(as);
  }
  return parts.join(' · ');
}

function pivotsOf(d: VtData): Pivot[] {
  return d.resolutions.map((r) => ({
    kind: 'ip' as const,
    value: r.ip,
    note: r.date ? `VirusTotal resolution, last seen ${r.date.slice(0, 10)}` : 'VirusTotal resolution',
  }));
}

// ---------------------------------------------------------------------------
// Facts

const day = (iso: string) => iso.slice(0, 10);

export function virustotalFacts(d: VtData): Fact[] {
  const facts: Fact[] = [];
  if (!d.found) {
    facts.push({
      label: 'Status',
      value: `Not in VirusTotal: it has no record of this ${d.kind === 'ip' ? 'IP address' : 'domain'}.`,
    });
  } else if (!analysed(d)) {
    facts.push({ label: 'Detections', value: 'No analysis yet' });
  } else {
    const s = d.stats;
    const tone = s.malicious > 0 ? 'bad' : s.suspicious > 0 ? 'warn' : 'good';
    facts.push({
      label: 'Detections',
      value: `${s.malicious}/${d.engines} malicious${s.suspicious > 0 ? `, ${s.suspicious} suspicious` : ''}`,
      tone,
    });
    facts.push({
      label: 'Engine breakdown',
      value: `${s.harmless} harmless · ${s.undetected} undetected · ${s.timeout} timeout`,
    });
  }
  if (d.flaggedBy.length) {
    facts.push({
      label: 'Flagged by',
      value: d.flaggedBy.map((h) => `${h.engine}: ${h.result && h.result !== h.category ? `${h.result} (${h.category})` : h.category}`),
      tone: d.flaggedBy.some((h) => h.category === 'malicious') ? 'bad' : 'warn',
    });
  }
  if (d.lastAnalysisDate) facts.push({ label: 'Last analysis', value: day(d.lastAnalysisDate) });
  if (d.reputation !== null) {
    facts.push({
      label: 'Reputation',
      value: `${d.reputation} (community score; negative is bad)`,
      ...(d.reputation < 0 ? { tone: 'warn' as const } : {}),
    });
  }
  if (d.votes && (d.votes.harmless > 0 || d.votes.malicious > 0)) {
    facts.push({
      label: 'Community votes',
      value: `${d.votes.malicious} malicious · ${d.votes.harmless} harmless`,
      ...(d.votes.malicious > d.votes.harmless ? { tone: 'warn' as const } : {}),
    });
  }
  if (d.categories.length) facts.push({ label: 'Categories', value: d.categories });
  if (d.tags.length) facts.push({ label: 'Tags', value: d.tags });
  if (d.registrar) facts.push({ label: 'Registrar', value: d.registrar });
  if (d.creationDate) facts.push({ label: 'Created', value: day(d.creationDate) });
  const as = asLabel(d);
  if (as) facts.push({ label: 'AS', value: as });
  if (d.network) facts.push({ label: 'Network', value: d.network });
  if (d.country) facts.push({ label: 'Country', value: d.country });
  if (d.kind === 'domain' && d.found) {
    if (d.resolutionsError) {
      facts.push({ label: 'Resolutions', value: `Unavailable: ${d.resolutionsError}`, tone: 'warn' });
    } else if (d.resolutions.length) {
      const total = resolutionCount(d);
      const shown = d.resolutions.length;
      facts.push({
        label: `Resolutions · ${total} total${d.resolutionsTruncated || shown !== total ? `, ${shown} most recent shown` : ''}`,
        value: d.resolutions.map((r) => (r.date ? `${r.ip} (last ${day(r.date)})` : r.ip)),
        pivot: true,
      });
    } else {
      facts.push({ label: 'Resolutions', value: 'None recorded' });
    }
  }
  facts.push({ label: 'VirusTotal', value: d.guiUrl, href: d.guiUrl });
  return facts;
}

// ---------------------------------------------------------------------------

const KEY_CHARS = /^[\x21-\x7e]+$/;

async function apiKey(ctx: Ctx): Promise<string> {
  const key = (await ctx.getKey('virustotal'))?.trim();
  if (!key) throw new SkipError('Add a VirusTotal API key in settings to enable this check.');
  // Header values must be visible ASCII; anything else would surface as a confusing network error.
  if (!KEY_CHARS.test(key)) throw new Error('The VirusTotal API key contains invalid characters. Re-enter it in settings.');
  return key;
}

function indicatorOf(e: Entity): { kind: VtData['kind']; value: string } {
  if (e.kind === 'ip') {
    const ip = normalizeIp(e.value);
    if (!ip) throw new SkipError('Not a valid IP address.');
    return { kind: 'ip', value: ip };
  }
  if (e.kind === 'domain') {
    const value = e.value.trim().toLowerCase().replace(/\.$/, '');
    if (!value) throw new SkipError('Nothing to look up.');
    return { kind: 'domain', value };
  }
  throw new SkipError('VirusTotal lookups need a domain or an IP address.');
}

export const virustotalModule: Module<VtData> = {
  id: 'virustotal',
  label: 'VirusTotal',
  version: 1,
  accepts: ['domain', 'ip'],
  key: 'virustotal',
  ttl: 24 * HOUR,
  rateLimit: { perMinute: 4 },
  note:
    'Queried domains and IPs are shared with VirusTotal and join its dataset. ' +
    'Public API: 4 lookups/min and 500/day, non-commercial use only.',

  async run(e, ctx) {
    const { kind, value } = indicatorOf(e);
    const key = await apiKey(ctx);

    if (kind === 'ip') {
      const attrs = await getObject(ctx, `${API}/ip_addresses/${seg(value)}`, key);
      const data = buildData('ip', value, attrs);
      return { data, summary: summarise(data), severity: severityOf(data.stats) };
    }

    const attrs = await getObject(ctx, `${API}/domains/${seg(value)}`, key);
    let data = buildData('domain', value, attrs);
    // Not in VirusTotal: its resolutions are empty too, so save the quota.
    if (data.found) {
      try {
        const page = await getResolutions(ctx, value, key);
        data = { ...data, resolutions: page.list, resolutionsTotal: page.total, resolutionsTruncated: page.truncated };
      } catch (err) {
        if (isAbortError(err)) throw err;
        // Keep the verdict; the resolutions are a secondary signal.
        const msg = err instanceof Error ? err.message : String(err);
        data = { ...data, resolutionsTotal: null, resolutionsError: clip(msg) };
      }
    }
    const pivots = pivotsOf(data);
    return {
      data,
      summary: summarise(data),
      severity: severityOf(data.stats),
      ...(pivots.length ? { pivots } : {}),
      // Partial result (resolutions failed): retry soon instead of caching it for 24 h.
      ...(data.resolutionsError ? { ttl: PARTIAL_TTL } : {}),
    };
  },

  facts: virustotalFacts,
};

// ---------------------------------------------------------------------------
// Settings "Test" button

function quotaOf(data: unknown, name: string): { allowed: number; used: number } | undefined {
  const root = isObj(data) ? data['data'] : undefined;
  const q = isObj(root) ? root[name] : undefined;
  if (!isObj(q)) return undefined;
  // Group-inherited keys report user.allowed = 0 and the real allowance on the group.
  for (const who of ['user', 'group']) {
    const o = q[who];
    if (!isObj(o)) continue;
    const allowed = count(o['allowed']);
    const used = count(o['used']);
    if (allowed !== undefined && allowed > 0) return { allowed, used: used ?? 0 };
  }
  return undefined;
}

/** The key as typed and as it appears in the request URL. */
function redactKey(s: string, key: string): string {
  const encoded = encodeURIComponent(key);
  const once = redact(s, key);
  return encoded === key ? once : redact(once, encoded);
}

/**
 * GET /users/{key}/overall_quotas: validates the key and costs no quota.
 * Errors are plain Errors with the key redacted (the request URL contains it).
 */
export const virustotalKeyTest: KeyTester = async (rawKey, http) => {
  const key = rawKey.trim();
  if (!key) throw new Error('Enter a VirusTotal API key first.');
  if (!KEY_CHARS.test(key)) throw new Error('The VirusTotal API key contains invalid characters.');
  let data: unknown;
  try {
    const res = await http.fetchJson<unknown>(`${API}/users/${encodeURIComponent(key)}/overall_quotas`, {
      headers: { 'x-apikey': key },
      rateLimit: false,
    });
    data = res.data;
  } catch (err) {
    if (err instanceof FetchError && err.kind === 'http' && err.status !== undefined) {
      const msg =
        err.status === 404
          ? 'VirusTotal does not recognise this API key (user not found).'
          : vtErrorMessage(err.status, err.body === undefined ? undefined : redactKey(err.body, key));
      throw new Error(msg);
    }
    throw new Error(redactKey(err instanceof Error ? err.message : String(err), key));
  }
  const daily = quotaOf(data, 'api_requests_daily');
  if (!daily) return 'Key accepted by VirusTotal.';
  const left = Math.max(0, daily.allowed - daily.used);
  return `Key accepted by VirusTotal: ${daily.used} of ${daily.allowed} daily requests used (${left} left; resets 00:00 UTC).`;
};
