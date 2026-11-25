import { FetchError, extractErrorMessage, isAbortError } from '@/lib/http';
import { isIPv4, isPublicIp, normalizeIp } from '@/lib/ip';
import type { KeyTester } from '@/lib/keytest';
import { realClock } from '@/lib/ratelimit';
import type { Ctx, Fact, Module, Pivot, Severity } from '@/lib/types';
import { HOUR, MINUTE, SkipError } from '@/lib/types';

/**
 * Shodan. See docs/research/threat-intel.md §12.
 *
 * - Always: keyless InternetDB, GET https://internetdb.shodan.io/{ip}
 *   ({ip, ports, hostnames, cpes, tags, vulns}). 404 {"detail":"No information
 *   available"} means no data (also returned for malformed input). Refreshed
 *   weekly; free for non-commercial use. IPv6 works with raw colons.
 * - With a key: GET https://api.shodan.io/shodan/host/{ip}?key=... (the key can
 *   only go in the query string). Needs a paid Membership, 1 req/s, no query
 *   credits. Bad key -> 401 with an HTML body; unknown IP -> 404
 *   {"error":"No information available for that IP."}. Responses are
 *   CDN-cached, so a 200 does not prove the key works (the key tester uses
 *   /api-info instead). A host-API failure never loses the InternetDB part.
 *
 * Banners (`data[]`) are requested (no `minify`) because they are the only
 * source of per-port product/version; only a compact summary is kept.
 *
 * The shared token bucket allows a burst of `perMinute` requests, but the host
 * API allows 1 req/s with no burst (extra requests get 429). Host lookups in
 * one investigation are therefore also spaced by HOST_GAP_MS (see hostTurn).
 */

const INTERNETDB = 'https://internetdb.shodan.io/';
const API = 'https://api.shodan.io';
const GUI = 'https://www.shodan.io/host/';

const INTERNETDB_LIMIT = { key: 'shodan-internetdb', perMinute: 60 };
const HOST_LIMIT = { key: 'shodan', perMinute: 60 };
/** Full banners can be large for busy hosts. */
const HOST_TIMEOUT_MS = 30_000;
/** Minimum gap between host-API requests in one investigation (1 req/s plus margin for jitter). */
export const HOST_GAP_MS = 1_100;
const HOST_GATE_MEMO = 'shodan:host-gate';

export const MAX_PORTS = 100;
export const MAX_HOSTNAMES = 50;
export const MAX_CPES = 50;
export const MAX_TAGS = 30;
export const MAX_VULNS = 50;
export const MAX_SERVICES = 20;
/** Hostname pivots emitted per IP (display-only). */
export const MAX_PIVOTS = 10;
/** Ports listed in the one-line summary. */
const SUMMARY_PORTS = 8;

/**
 * Tags meaning Shodan saw the host acting maliciously or infected
 * (Malware Hunter callbacks, offensive C2 frameworks, ransom notes,
 * DoublePulsar implant). See https://datapedia.shodan.io/. 'botnet' is listed
 * because the spec names botnet-like tags.
 */
export const MALICIOUS_TAGS: readonly string[] = ['malware', 'c2', 'compromised', 'doublepulsar', 'botnet'];
/** Weak reputation signal: the IP was observed scanning the Internet (benign research scanners included). */
export const SUSPICIOUS_TAGS: readonly string[] = ['scanner'];

export interface InternetDbData {
  /** Sorted, at most MAX_PORTS. */
  ports: number[];
  portCount: number;
  hostnames: string[];
  hostnameCount: number;
  cpes: string[];
  cpeCount: number;
  tags: string[];
  /** CVE ids, newest first, at most MAX_VULNS. */
  vulns: string[];
  vulnCount: number;
}

export interface ShodanService {
  port: number;
  transport: string | null;
  product: string | null;
  version: string | null;
  /** Shodan's protocol module, e.g. "https", "ssh", "dns-udp". */
  module: string | null;
}

export interface HostData {
  org: string | null;
  isp: string | null;
  /** "AS15169" */
  asn: string | null;
  os: string | null;
  country: string | null;
  city: string | null;
  /** ISO 8601 (UTC). */
  lastUpdate: string | null;
  ports: number[];
  portCount: number;
  /** One per port/transport, sorted by port, at most MAX_SERVICES. */
  services: ShodanService[];
  serviceCount: number;
  hostnames: string[];
  hostnameCount: number;
  tags: string[];
  vulns: string[];
  vulnCount: number;
}

/** no-key: host API not queried; ok: data; not-found: 404 from Shodan; error: see hostError. */
export type HostStatus = 'no-key' | 'ok' | 'not-found' | 'error';

export interface ShodanData {
  ip: string;
  /** null = InternetDB has no information (404) or the request failed (see internetdbError). */
  internetdb: InternetDbData | null;
  internetdbError?: string;
  host: HostData | null;
  hostStatus: HostStatus;
  hostError?: string;
  guiUrl: string;
}

// ---------------------------------------------------------------------------
// Defensive JSON helpers

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Trimmed, length-capped string with control characters (CR/LF etc. from banners) collapsed to a space. */
function str(v: unknown, max = 200): string | null {
  if (typeof v !== 'string') return null;
  const t = v.replace(/[\u0000-\u001f\u007f-\u009f]+/g, ' ').trim();
  return t ? t.slice(0, max).trim() : null;
}

function finiteNumber(v: unknown): number | undefined {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string' && /^-?\d{1,15}$/.test(v.trim())) return Number(v);
  return undefined;
}

function isPort(v: unknown): v is number {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 65535;
}

function portList(v: unknown): number[] {
  if (!Array.isArray(v)) return [];
  return [...new Set(v.filter(isPort))].sort((a, b) => a - b);
}

/** Map + filter + de-duplicate (first occurrence wins). */
function strList(v: unknown, clean: (s: string) => string | null): string[] {
  if (!Array.isArray(v)) return [];
  const out = new Set<string>();
  for (const x of v) {
    if (typeof x !== 'string') continue;
    const c = clean(x);
    if (c) out.add(c);
  }
  return [...out];
}

function cleanHostname(s: string): string | null {
  const h = s.trim().toLowerCase().replace(/\.$/, '');
  return h.length > 0 && h.length <= 253 && /^[a-z0-9_.-]+$/.test(h) ? h : null;
}

function cleanTag(s: string): string | null {
  const t = s.trim().toLowerCase();
  return /^[a-z0-9][a-z0-9_-]{0,31}$/.test(t) ? t : null;
}

function cleanCpe(s: string): string | null {
  const c = s.trim();
  return /^cpe:/i.test(c) && c.length <= 200 && !/[\s<>]/.test(c) ? c : null;
}

function cleanVuln(s: string): string | null {
  const v = s.trim().toUpperCase();
  return /^[A-Z0-9][A-Z0-9._:-]{2,39}$/.test(v) ? v : null;
}

function cveParts(s: string): [number, number] {
  const m = /^CVE-(\d{4})-(\d+)$/.exec(s);
  return m ? [Number(m[1]), Number(m[2])] : [0, 0];
}

/** Newest CVEs first (year, then sequence number). */
function sortVulns(list: string[]): string[] {
  return [...list].sort((a, b) => {
    const [ya, na] = cveParts(a);
    const [yb, nb] = cveParts(b);
    return yb - ya || nb - na || a.localeCompare(b);
  });
}

/** Shodan's `vulns` is a CVE list at host level and a {CVE: details} map inside banners. */
function vulnIds(v: unknown): string[] {
  if (Array.isArray(v)) return strList(v, cleanVuln);
  if (isObj(v)) return strList(Object.keys(v), cleanVuln);
  return [];
}

/** "2026-11-25T07:26:00.000000" (UTC without zone) -> "2026-11-25T07:26:00Z". */
function shodanTime(v: unknown): string | null {
  const s = str(v, 64);
  if (!s) return null;
  const m = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})/.exec(s);
  if (!m) return null;
  const iso = `${m[1]}T${m[2]}Z`;
  return Number.isFinite(Date.parse(iso)) ? iso : null;
}

function asnOf(v: unknown): string | null {
  if (typeof v === 'number' && Number.isInteger(v) && v >= 0) return `AS${v}`;
  const s = str(v, 32);
  if (!s) return null;
  const m = /^(?:AS)?(\d{1,10})$/i.exec(s);
  return m ? `AS${m[1]}` : null;
}

function hasAnyField(raw: Obj, ...keys: string[]): boolean {
  return keys.some((k) => k in raw);
}

// ---------------------------------------------------------------------------
// Parsers

/**
 * InternetDB 200 or 404 body -> compact data, or null when Shodan has no
 * information. Throws on a payload that is not InternetDB-shaped.
 */
export function parseInternetDb(raw: unknown): InternetDbData | null {
  if (!isObj(raw)) throw new Error('not a JSON object');
  if (!hasAnyField(raw, 'ports', 'hostnames', 'cpes', 'tags', 'vulns')) {
    if (typeof raw['detail'] === 'string') return null;
    throw new Error('missing ports/hostnames/cpes/tags/vulns');
  }
  const ports = portList(raw['ports']);
  const hostnames = strList(raw['hostnames'], cleanHostname);
  const cpes = strList(raw['cpes'], cleanCpe);
  const tags = strList(raw['tags'], cleanTag);
  const vulns = sortVulns(vulnIds(raw['vulns']));
  return {
    ports: ports.slice(0, MAX_PORTS),
    portCount: ports.length,
    hostnames: hostnames.slice(0, MAX_HOSTNAMES),
    hostnameCount: hostnames.length,
    cpes: cpes.slice(0, MAX_CPES),
    cpeCount: cpes.length,
    tags: tags.slice(0, MAX_TAGS),
    vulns: vulns.slice(0, MAX_VULNS),
    vulnCount: vulns.length,
  };
}

function parseService(b: unknown): ShodanService | null {
  if (!isObj(b) || !isPort(b['port'])) return null;
  const meta = b['_shodan'];
  return {
    port: b['port'],
    transport: str(b['transport'], 8)?.toLowerCase() ?? null,
    product: str(b['product'], 100),
    version: str(b['version'], 50),
    module: isObj(meta) ? str(meta['module'], 40) : null,
  };
}

/** Host API 200 body -> compact data. Throws on a payload that is not host-shaped. */
export function parseHost(raw: unknown): HostData {
  if (!isObj(raw)) throw new Error('not a JSON object');
  if (!hasAnyField(raw, 'ip_str', 'ip', 'ports', 'data')) throw new Error('missing ip_str/ports/data');

  const banners = Array.isArray(raw['data']) ? raw['data'] : [];
  const byKey = new Map<string, ShodanService>();
  const bannerVulns: string[] = [];
  for (const b of banners) {
    const s = parseService(b);
    if (!s) continue;
    const key = `${s.port}/${s.transport ?? ''}`;
    const prev = byKey.get(key);
    // Prefer the banner that identified a product.
    if (!prev || (!prev.product && s.product)) byKey.set(key, s);
    if (isObj(b)) bannerVulns.push(...vulnIds(b['vulns']));
  }
  const services = [...byKey.values()].sort((a, b) => a.port - b.port || (a.transport ?? '').localeCompare(b.transport ?? ''));

  const ports = [...new Set([...portList(raw['ports']), ...services.map((s) => s.port)])].sort((a, b) => a - b);
  const hostnames = strList(raw['hostnames'], cleanHostname);
  const tags = strList(raw['tags'], cleanTag);
  const top = vulnIds(raw['vulns']);
  const vulns = sortVulns([...new Set([...top, ...bannerVulns])]);

  return {
    org: str(raw['org']),
    isp: str(raw['isp']),
    asn: asnOf(raw['asn']),
    os: str(raw['os'], 100),
    country: str(raw['country_name'], 100) ?? str(raw['country_code'], 8),
    city: str(raw['city'], 100),
    lastUpdate: shodanTime(raw['last_update']),
    ports: ports.slice(0, MAX_PORTS),
    portCount: ports.length,
    services: services.slice(0, MAX_SERVICES),
    serviceCount: services.length,
    hostnames: hostnames.slice(0, MAX_HOSTNAMES),
    hostnameCount: hostnames.length,
    tags: tags.slice(0, MAX_TAGS),
    vulns: vulns.slice(0, MAX_VULNS),
    vulnCount: vulns.length,
  };
}

// ---------------------------------------------------------------------------
// Requests

/** Path form of a validated IP: encoded, but colons kept raw (verified live; legal in a path segment). */
function pathIp(ip: string): string {
  return encodeURIComponent(ip).replace(/%3A/gi, ':');
}

/** IPv4-mapped IPv6 (canonical "::ffff:808:808") -> "8.8.8.8": Shodan indexes the IPv4 address. */
function unmapIPv4(ip: string): string {
  const m = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(ip);
  if (!m) return ip;
  const hi = parseInt(m[1]!, 16);
  const lo = parseInt(m[2]!, 16);
  return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
}

/**
 * Wait for this investigation's next host-API slot. The shared token bucket
 * would let up to `perMinute` requests go at once, but Shodan answers 429 to
 * everything over 1 req/s. Rejects (AbortError) when the run is cancelled.
 */
async function hostTurn(ctx: Ctx): Promise<void> {
  const gate = await ctx.shared.memo<{ next: number }>(HOST_GATE_MEMO, async () => ({ next: 0 }));
  const now = ctx.now();
  const at = Math.max(now, gate.next);
  gate.next = at + HOST_GAP_MS;
  if (at > now) await realClock.sleep(at - now, ctx.signal);
}

/** Never let the key reach a message (FetchError details or bodies could echo the URL). */
function redact(msg: string, key: string | undefined): string {
  if (!key) return msg;
  let out = msg.split(key).join('[key]');
  const enc = encodeURIComponent(key);
  if (enc !== key) out = out.split(enc).join('[key]');
  return out;
}

function detailOf(err: FetchError): string {
  const d = err.body ? extractErrorMessage(err.body) : undefined;
  return d ? `: ${d.slice(0, 150)}` : '';
}

function internetDbMessage(err: unknown): string {
  if (err instanceof FetchError) {
    if (err.kind === 'http') {
      if (err.status === 429) return 'Shodan InternetDB rate limit hit (HTTP 429), even after a retry. Try again in a minute.';
      if (err.status === 422) return 'Shodan InternetDB rejected the IP address (HTTP 422).';
      return `Shodan InternetDB error (HTTP ${err.status ?? '?'})${detailOf(err)}.`;
    }
    if (err.kind === 'parse') return 'Shodan InternetDB returned an unexpected response (not JSON).';
    return `Shodan InternetDB: ${err.message}`;
  }
  return `Shodan InternetDB returned an unexpected response (${err instanceof Error ? err.message : String(err)}).`;
}

function hostMessage(err: unknown, key: string): string {
  let msg: string;
  if (err instanceof FetchError) {
    switch (err.kind) {
      case 'http':
        switch (err.status) {
          case 401:
            msg = 'Shodan rejected the API key (HTTP 401). Check it in settings; InternetDB results are shown without it.';
            break;
          case 403:
            msg = 'Shodan denied the host lookup (HTTP 403). Host lookups need a paid Shodan Membership or API plan.';
            break;
          case 429:
            msg = 'Shodan host API rate limit or quota hit (HTTP 429), even after a retry. Try again later.';
            break;
          default:
            msg = `Shodan host API error (HTTP ${err.status ?? '?'})${detailOf(err)}.`;
        }
        break;
      case 'timeout':
        msg = `Shodan host API timed out after ${HOST_TIMEOUT_MS / 1000}s.`;
        break;
      case 'parse':
        msg = 'Shodan host API returned an unexpected response (not JSON).';
        break;
      default:
        msg = `Shodan host API: ${err.message}`;
    }
  } else {
    msg = `Shodan host API returned an unexpected response (${err instanceof Error ? err.message : String(err)}).`;
  }
  return redact(msg, key);
}

type IdbResult = { ok: true; data: InternetDbData | null } | { ok: false; error: FetchError };

async function fetchInternetDb(ctx: Ctx, ip: string): Promise<IdbResult> {
  const url = `${INTERNETDB}${pathIp(ip)}`;
  try {
    const res = await ctx.fetchJson<unknown>(url, { okStatuses: [404], rateLimit: INTERNETDB_LIMIT });
    if (res.status === 404) return { ok: true, data: null };
    try {
      return { ok: true, data: parseInternetDb(res.data) };
    } catch (err) {
      return { ok: false, error: new FetchError('parse', internetDbMessage(err), url, res.status) };
    }
  } catch (err) {
    if (isAbortError(err)) throw err;
    const status = err instanceof FetchError ? err.status : undefined;
    const kind = err instanceof FetchError ? err.kind : 'network';
    return { ok: false, error: new FetchError(kind, internetDbMessage(err), url, status) };
  }
}

interface HostResult {
  status: HostStatus;
  data: HostData | null;
  error?: string;
}

/** Shodan keys are printable ASCII; anything else (e.g. a lone surrogate) would make encodeURIComponent throw. */
const KEY_RE = /^[\x21-\x7e]+$/;
const BAD_KEY_CHARS = 'The Shodan API key contains invalid characters. Re-enter it in settings.';

async function fetchHost(ctx: Ctx, ip: string, key: string): Promise<HostResult> {
  if (!KEY_RE.test(key)) return { status: 'error', data: null, error: BAD_KEY_CHARS };
  const safeUrl = `${API}/shodan/host/${pathIp(ip)}`;
  const url = `${safeUrl}?key=${encodeURIComponent(key)}`;
  try {
    await hostTurn(ctx);
    const res = await ctx.fetchJson<unknown>(url, {
      okStatuses: [404],
      rateLimit: HOST_LIMIT,
      timeoutMs: HOST_TIMEOUT_MS,
    });
    if (res.status === 404) return { status: 'not-found', data: null };
    try {
      return { status: 'ok', data: parseHost(res.data) };
    } catch (err) {
      return { status: 'error', data: null, error: hostMessage(err, key) };
    }
  } catch (err) {
    // Propagate cancellation (never cached), but not the http layer's error: its .url carries the key.
    if (isAbortError(err)) throw new FetchError('aborted', 'Cancelled', safeUrl);
    return { status: 'error', data: null, error: hostMessage(err, key) };
  }
}

async function apiKey(ctx: Ctx): Promise<string | undefined> {
  const key = (await ctx.getKey('shodan'))?.trim();
  return key ? key : undefined;
}

// ---------------------------------------------------------------------------
// Derived views (shared by summary, severity and facts)

function union<T>(a: readonly T[] | undefined, b: readonly T[] | undefined): T[] {
  return [...new Set([...(a ?? []), ...(b ?? [])])];
}

function allTags(d: ShodanData): string[] {
  return union(d.internetdb?.tags, d.host?.tags);
}

function allPorts(d: ShodanData): { list: number[]; count: number } {
  const list = union(d.internetdb?.ports, d.host?.ports).sort((a, b) => a - b);
  return { list, count: Math.max(list.length, d.internetdb?.portCount ?? 0, d.host?.portCount ?? 0) };
}

function allVulns(d: ShodanData): { list: string[]; count: number } {
  const list = sortVulns(union(d.internetdb?.vulns, d.host?.vulns)).slice(0, MAX_VULNS);
  return { list, count: Math.max(list.length, d.internetdb?.vulnCount ?? 0, d.host?.vulnCount ?? 0) };
}

function allHostnames(d: ShodanData): { list: string[]; count: number } {
  const list = union(d.internetdb?.hostnames, d.host?.hostnames).slice(0, MAX_HOSTNAMES);
  return { list, count: Math.max(list.length, d.internetdb?.hostnameCount ?? 0, d.host?.hostnameCount ?? 0) };
}

export function shodanSeverity(d: ShodanData): Severity {
  const tags = allTags(d);
  if (tags.some((t) => MALICIOUS_TAGS.includes(t))) return 'high';
  // Known CVEs are exposure, not reputation; a scanning IP is a weak signal.
  if (allVulns(d).count > 0 || tags.some((t) => SUSPICIOUS_TAGS.includes(t))) return 'low';
  return 'none';
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

export function summarise(d: ShodanData): string {
  if (!d.internetdb && !d.host) {
    if (d.hostError) return 'No Shodan data · host lookup failed';
    return d.internetdbError ? 'No Shodan data · InternetDB failed' : 'No Shodan data';
  }
  const parts: string[] = [];
  const tags = allTags(d);
  const bad = tags.filter((t) => MALICIOUS_TAGS.includes(t));
  if (bad.length) parts.push(`Shodan flags: ${bad.join(', ')}`);

  const ports = allPorts(d);
  if (ports.count === 0) {
    parts.push('No open ports seen');
  } else {
    const shown = ports.list.slice(0, SUMMARY_PORTS);
    const more = ports.count - shown.length;
    parts.push(`${ports.count === 1 ? 'Port' : 'Ports'} ${shown.join(', ')}${more > 0 ? ` +${more} more` : ''}`);
  }

  const vulns = allVulns(d).count;
  if (vulns > 0) parts.push(plural(vulns, 'CVE'));

  const other = tags.filter((t) => !bad.includes(t));
  if (other.length) parts.push(`tags: ${other.slice(0, 6).join(', ')}${other.length > 6 ? ', …' : ''}`);

  const org = d.host?.org ?? d.host?.isp;
  if (org) parts.push(org);
  if (d.hostError) parts.push('host lookup failed');
  else if (d.internetdbError) parts.push('InternetDB failed');
  return parts.join(' · ');
}

/** Real DNS names only (skips IP-like and reverse-zone names). */
function pivotable(h: string): boolean {
  if (h.length > 253 || isIPv4(h) || h.endsWith('.arpa')) return false;
  const labels = h.split('.');
  if (labels.length < 2) return false;
  if (!labels.every((l) => /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/.test(l))) return false;
  const tld = labels[labels.length - 1] ?? '';
  return /^[a-z]{2,63}$/.test(tld) || /^xn--[a-z0-9-]+$/.test(tld);
}

function hostnamePivots(d: ShodanData): Pivot[] {
  return allHostnames(d)
    .list.filter(pivotable)
    .slice(0, MAX_PIVOTS)
    .map((value) => ({ kind: 'domain', value, note: 'Shodan hostname' }));
}

// ---------------------------------------------------------------------------
// Facts

function countLabel(name: string, count: number, shown: number): string {
  return shown < count ? `${name} · ${count}, ${shown} shown` : name;
}

function serviceLine(s: ShodanService): string {
  let line = `${s.port}/${s.transport ?? 'tcp'}`;
  if (s.module) line += ` ${s.module}`;
  if (s.product) line += ` · ${s.product}${s.version ? ` ${s.version}` : ''}`;
  return line;
}

export function shodanFacts(d: ShodanData): Fact[] {
  const facts: Fact[] = [];
  const tags = allTags(d);
  if (tags.length) {
    const bad = tags.some((t) => MALICIOUS_TAGS.includes(t));
    const warn = tags.some((t) => SUSPICIOUS_TAGS.includes(t));
    facts.push({ label: 'Tags', value: tags, ...(bad ? { tone: 'bad' as const } : warn ? { tone: 'warn' as const } : {}) });
  }

  if (d.internetdb || d.host) {
    const ports = allPorts(d);
    facts.push({
      label: countLabel('Open ports', ports.count, ports.list.length),
      value: ports.list.length ? ports.list.join(', ') : 'none seen',
    });
  }

  const h = d.host;
  if (h?.services.length) {
    facts.push({ label: countLabel('Services', h.serviceCount, h.services.length), value: h.services.map(serviceLine) });
  }

  const hostnames = allHostnames(d);
  if (hostnames.list.length) {
    facts.push({ label: countLabel('Hostnames', hostnames.count, hostnames.list.length), value: hostnames.list, pivot: true });
  }

  const cpes = d.internetdb?.cpes ?? [];
  if (cpes.length) {
    facts.push({ label: countLabel('CPEs', d.internetdb?.cpeCount ?? cpes.length, cpes.length), value: cpes });
  }

  const vulns = allVulns(d);
  if (vulns.list.length) {
    facts.push({
      label: countLabel('CVEs (inferred from versions, unverified)', vulns.count, vulns.list.length),
      value: vulns.list,
      tone: 'warn',
    });
  }

  if (h) {
    const org = [h.org, h.asn].filter((x): x is string => !!x).join(' · ');
    if (org) facts.push({ label: 'Org / ASN', value: org });
    if (h.isp && h.isp !== h.org) facts.push({ label: 'ISP', value: h.isp });
    const place = [h.city, h.country].filter((x): x is string => !!x).join(', ');
    if (place) facts.push({ label: 'Location', value: place });
    if (h.os) facts.push({ label: 'OS', value: h.os });
    if (h.lastUpdate) facts.push({ label: 'Last scanned', value: h.lastUpdate.slice(0, 10) });
  }

  if (d.internetdbError) facts.push({ label: 'InternetDB', value: d.internetdbError, tone: 'warn' });
  else if (!d.internetdb) facts.push({ label: 'InternetDB', value: 'No information available' });

  switch (d.hostStatus) {
    case 'no-key':
      facts.push({ label: 'Host API', value: 'Not queried (no Shodan API key)' });
      break;
    case 'not-found':
      facts.push({ label: 'Host API', value: 'No information available for this IP' });
      break;
    case 'error':
      facts.push({ label: 'Host API', value: d.hostError ?? 'Lookup failed', tone: 'warn' });
      break;
    case 'ok':
      break;
  }

  facts.push({ label: 'Shodan', value: 'View host on shodan.io', href: d.guiUrl });
  return facts;
}

// ---------------------------------------------------------------------------

export const shodanModule: Module<ShodanData> = {
  id: 'shodan',
  label: 'Shodan',
  version: 1,
  accepts: ['ip'],
  key: 'shodan',
  keyOptional: true,
  ttl: 24 * HOUR,
  // Host API: 1 request/second. Each request also sets its own bucket.
  rateLimit: { perMinute: 60 },
  note:
    'Works without a key via Shodan InternetDB (free for non-commercial use, refreshed weekly). ' +
    'An API key adds the host lookup (services, org, ASN), which needs a paid Shodan Membership.',

  async run(e, ctx) {
    if (e.kind !== 'ip') throw new SkipError('Shodan looks up IP addresses only.');
    const normalized = normalizeIp(e.value);
    if (!normalized) throw new SkipError('Not a valid IP address.');
    if (!isPublicIp(normalized)) throw new SkipError('Private or reserved IP address: Shodan has no data for it.');
    const ip = unmapIPv4(normalized);
    const key = await apiKey(ctx);

    const [idb, host] = await Promise.all([
      fetchInternetDb(ctx, ip),
      key ? fetchHost(ctx, ip, key) : Promise.resolve<HostResult>({ status: 'no-key', data: null }),
    ]);

    if (!idb.ok && host.status !== 'ok' && host.status !== 'not-found') {
      // Nothing usable from either source.
      const also = host.error ? ` Host API: ${host.error}` : '';
      throw new FetchError(idb.error.kind, `${idb.error.message}${also}`, idb.error.url, idb.error.status);
    }

    const data: ShodanData = {
      ip,
      internetdb: idb.ok ? idb.data : null,
      ...(idb.ok ? {} : { internetdbError: idb.error.message }),
      host: host.data,
      hostStatus: host.status,
      ...(host.error ? { hostError: host.error } : {}),
      guiUrl: `${GUI}${pathIp(ip)}`,
    };
    const pivots = hostnamePivots(data);
    return {
      data,
      summary: summarise(data),
      severity: shodanSeverity(data),
      ...(pivots.length ? { pivots } : {}),
      // Partial result (one of the two lookups failed): retry soon instead of caching it for 24 h.
      ...(data.hostError || data.internetdbError ? { ttl: 10 * MINUTE } : {}),
    };
  },

  facts: shodanFacts,
};

// ---------------------------------------------------------------------------

/**
 * Settings-page "Test": /api-info is not CDN-cached (host lookups are, and are
 * served even for bogus keys) and returns 401 for a bad key.
 */
export const shodanKeyTest: KeyTester = async (key, http) => {
  const k = key.trim();
  if (!k) throw new Error('Enter a Shodan API key first.');
  if (!KEY_RE.test(k)) throw new Error(BAD_KEY_CHARS);
  let data: unknown;
  try {
    const res = await http.fetchJson<unknown>(`${API}/api-info?key=${encodeURIComponent(k)}`, { rateLimit: HOST_LIMIT });
    data = res.data;
  } catch (err) {
    if (err instanceof FetchError) {
      let msg: string;
      if (err.kind === 'http' && (err.status === 401 || err.status === 403)) {
        msg = `Shodan rejected the API key (HTTP ${err.status}). Copy it again from account.shodan.io.`;
      } else if (err.kind === 'http' && err.status === 429) {
        msg = 'Shodan rate limit hit (HTTP 429). Wait a few seconds and test again.';
      } else if (err.kind === 'http') {
        msg = `Shodan error (HTTP ${err.status ?? '?'})${detailOf(err)}.`;
      } else if (err.kind === 'parse') {
        msg = 'Shodan returned an unexpected response (not JSON).';
      } else {
        msg = `Could not reach Shodan: ${err.message}`;
      }
      throw new Error(redact(msg, k));
    }
    throw err;
  }
  if (!isObj(data)) throw new Error('Shodan returned an unexpected response (no account information).');
  const plan = str(data['plan'], 40);
  const query = finiteNumber(data['query_credits']);
  const scan = finiteNumber(data['scan_credits']);
  if (plan === null && query === undefined && scan === undefined) {
    throw new Error('Shodan returned an unexpected response (no plan or credits).');
  }
  const parts = [`Key valid${plan ? ` · plan: ${plan}` : ''}`];
  if (query !== undefined) parts.push(`${query} query credits`);
  if (scan !== undefined) parts.push(`${scan} scan credits`);
  return parts.join(' · ');
};
