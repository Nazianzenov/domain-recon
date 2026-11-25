import { FetchError } from '@/lib/http';
import { isIPv4, normalizeIp } from '@/lib/ip';
import type { KeyTester } from '@/lib/keytest';
import type { Ctx, Entity, Fact, Module, Pivot } from '@/lib/types';
import { HOUR, MINUTE, SkipError } from '@/lib/types';

/**
 * Passive DNS from Mnemonic (PDNS v3). See docs/research/pdns-m365-email.md §1.
 *
 * - GET https://api.mnemonic.no/pdns/v3/{query}?limit=N matches the value as
 *   either the record's query (owner name) or its answer, sorted by
 *   lastSeenTimestamp descending.
 * - Public use: TLP:WHITE data only, limit <= 1000, 10 req/min and 1000/day.
 *   With an Argus-API-Key header: limit <= 10000. Over the limit -> HTTP 412;
 *   quota exhausted -> HTTP 402 with metaData.millisUntilResourcesAvailable.
 * - No match -> HTTP 200, data:[] and an INFO message "object.not.found".
 *
 * One request per entity (first page only, documented maximum limit).
 */

const API = 'https://api.mnemonic.no/pdns/v3/';
/** Documented `limit` maximum without a key (higher returns HTTP 412). */
export const PUBLIC_LIMIT = 1000;
/** Documented `limit` maximum with an Argus API key. */
export const AUTH_LIMIT = 10_000;
/** Records kept in `data` (most recent first). */
export const MAX_RECORDS = 200;
/** Domain pivots emitted for an IP query (display-only). */
export const MAX_PIVOTS = 25;
/** Lines per fact group in the expanded card. */
const MAX_LINES = 25;
/** Up to 10 000 records can take a while to serialise server-side. */
const TIMEOUT_MS = 30_000;
const MAX_ANSWER_LEN = 512;
const MAX_NAME_LEN = 255;
/** Year 10000: beyond this Date#toISOString changes format. */
const MAX_TS = 253_402_300_800_000;

export interface PdnsRecord {
  /** Lowercase rrtype as Mnemonic reports it (a, aaaa, cname, mx, ...). */
  rrtype: string;
  /** Owner name: lowercase, no trailing dot. */
  query: string;
  /** Normalised answer (canonical IP for a/aaaa, lowercase name for name types, raw otherwise). */
  answer: string;
  firstSeen: string | null;
  lastSeen: string | null;
  /** How many times the record was observed. */
  times?: number;
}

export interface PdnsData {
  /** The value that was looked up (domain or IP). */
  query: string;
  /** An Argus API key was sent. */
  authenticated: boolean;
  /** Total matches the server reports (`count`), at least the number returned. A lower bound when the page was full. */
  total: number;
  /** Records returned in the single page we fetched (valid + malformed). */
  fetched: number;
  /** The server holds (or may hold) more records than we fetched: `count` exceeds the page, or the page was full. */
  truncated: boolean;
  /** Malformed records dropped while parsing. */
  skipped: number;
  /** Earliest first-seen / latest last-seen over every fetched record. */
  firstSeen: string | null;
  lastSeen: string | null;
  /** Distinct answers per rrtype for records whose owner name is the investigated value. */
  distinctAnswers: Record<string, number>;
  /** Distinct owner names per rrtype for records whose answer is the investigated value. */
  distinctNames: Record<string, number>;
  /** At most MAX_RECORDS, sorted by lastSeen descending. */
  records: PdnsRecord[];
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
  if (typeof v === 'string' && /^\d{1,16}$/.test(v)) return Number(v);
  return undefined;
}

/** Epoch ms -> ISO string; 0, negatives and junk -> null. */
function toIso(v: unknown): string | null {
  const n = finiteNumber(v);
  if (n === undefined || n <= 0 || n >= MAX_TS) return null;
  return new Date(Math.floor(n)).toISOString();
}

function cleanName(s: string): string {
  return s.trim().toLowerCase().replace(/\.$/, '').slice(0, MAX_NAME_LEN);
}

/** Answers that are host names (normalised like owner names). */
const NAME_TYPES = new Set(['cname', 'ns', 'mx', 'ptr', 'dname', 'srv']);
/** Answers worth marking as copyable indicators. */
const INDICATOR_TYPES = new Set(['a', 'aaaa', 'cname', 'ns', 'mx', 'ptr', 'dname']);
const RR_ORDER = ['a', 'aaaa', 'cname', 'ns', 'mx', 'txt', 'soa', 'srv', 'ptr', 'caa'];

function normaliseAnswer(rrtype: string, raw: string): string {
  const t = raw.trim();
  if (rrtype === 'a' || rrtype === 'aaaa') return normalizeIp(t) ?? t.toLowerCase().slice(0, MAX_ANSWER_LEN);
  // A bare "." (null MX, RFC 7505) is a legitimate answer, so keep it rather than emptying it.
  if (NAME_TYPES.has(rrtype)) return cleanName(t) || t;
  return t.slice(0, MAX_ANSWER_LEN);
}

export function parseRecord(raw: unknown): PdnsRecord | null {
  if (!isObj(raw)) return null;
  const rrtype = str(raw['rrtype'])?.trim().toLowerCase();
  if (!rrtype || !/^[a-z0-9-]{1,16}$/.test(rrtype)) return null;
  const q = str(raw['query']);
  const a = str(raw['answer']);
  if (q === undefined || a === undefined) return null;
  const query = cleanName(q);
  const answer = normaliseAnswer(rrtype, a);
  if (!query || !answer) return null;
  const rec: PdnsRecord = {
    rrtype,
    query,
    answer,
    firstSeen: toIso(raw['firstSeenTimestamp']),
    lastSeen: toIso(raw['lastSeenTimestamp']),
  };
  const times = finiteNumber(raw['times']);
  if (times !== undefined && times >= 0) rec.times = Math.floor(times);
  return rec;
}

/** Most recent first; undated records last; deterministic tie-break. */
function compareRecords(x: PdnsRecord, y: PdnsRecord): number {
  const a = x.lastSeen ?? '';
  const b = y.lastSeen ?? '';
  if (a !== b) return a < b ? 1 : -1;
  const fa = x.firstSeen ?? '';
  const fb = y.firstSeen ?? '';
  if (fa !== fb) return fa < fb ? 1 : -1;
  return `${x.rrtype} ${x.query} ${x.answer}`.localeCompare(`${y.rrtype} ${y.query} ${y.answer}`);
}

/** The record's answer is the investigated value (e.g. a domain resolving to the queried IP). */
function isReverse(r: PdnsRecord, value: string): boolean {
  return r.answer === value && r.query !== value;
}

function hostname(s: string): boolean {
  if (s.length > 253 || isIPv4(s) || s.endsWith('.arpa')) return false;
  const labels = s.split('.');
  if (labels.length < 2) return false;
  if (!labels.every((l) => /^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(l))) return false;
  const tld = labels[labels.length - 1] ?? '';
  return /^[a-z]{2,63}$/.test(tld) || /^xn--[a-z0-9-]+$/.test(tld);
}

// ---------------------------------------------------------------------------
// Envelope + errors

interface ArgusMessage {
  message?: string;
  template?: string;
  type?: string;
}

function messagesOf(env: Obj | undefined): ArgusMessage[] {
  const list = env?.['messages'];
  if (!Array.isArray(list)) return [];
  const out: ArgusMessage[] = [];
  for (const m of list) {
    if (!isObj(m)) continue;
    const message = str(m['message']);
    const template = str(m['messageTemplate']);
    const type = str(m['type']);
    out.push({
      ...(message ? { message } : {}),
      ...(template ? { template } : {}),
      ...(type ? { type } : {}),
    });
  }
  return out;
}

function envelopeDetail(env: Obj | undefined): string | undefined {
  const msgs = messagesOf(env);
  const m = msgs.find((x) => x.type !== 'INFO' && (x.message || x.template)) ?? msgs.find((x) => x.message || x.template);
  const text = m?.message ?? m?.template;
  return text ? text.slice(0, 200) : undefined;
}

function parseBody(body: string | undefined): Obj | undefined {
  if (!body) return undefined;
  try {
    const j: unknown = JSON.parse(body);
    return isObj(j) ? j : undefined;
  } catch {
    return undefined;
  }
}

function formatWait(ms: number): string {
  if (ms < MINUTE) return 'under a minute';
  if (ms < HOUR) return `about ${Math.ceil(ms / MINUTE)} min`;
  return `about ${Math.ceil(ms / HOUR)} h`;
}

/** Informative error for an HTTP status or an in-body responseCode. */
function apiError(status: number, env: Obj | undefined, url: string, authenticated: boolean, body?: string): FetchError {
  const detail = envelopeDetail(env);
  const suffix = detail ? ` (${detail})` : '';
  let msg: string;
  switch (status) {
    case 402: {
      const meta = env?.['metaData'];
      const wait = isObj(meta) ? finiteNumber(meta['millisUntilResourcesAvailable']) : undefined;
      msg =
        `Mnemonic PDNS quota exhausted${wait !== undefined && wait > 0 ? `; resets in ${formatWait(wait)}` : ''}. ` +
        (authenticated
          ? 'Your Argus API key has used its request allowance.'
          : 'Public use allows 10 lookups/min and 1000/day; an Argus API key raises this.');
      break;
    }
    case 429:
      msg = `Mnemonic PDNS rate limit hit${suffix}. Public use allows 10 lookups per minute; try again shortly.`;
      break;
    case 401:
    case 403:
      msg = authenticated
        ? `Mnemonic rejected the Argus API key (HTTP ${status})${suffix}. Check it in settings, or remove it to use public access.`
        : `Mnemonic refused the request (HTTP ${status})${suffix}.`;
      break;
    case 412:
      msg = `Mnemonic rejected the result limit (HTTP 412)${suffix}.`;
      break;
    default:
      msg = `Mnemonic PDNS error (HTTP ${status})${suffix}.`;
  }
  return new FetchError('http', msg, url, status, body);
}

interface Page {
  raw: unknown[];
  count: number | undefined;
  /** The `limit` the page was requested with. */
  limit: number;
}

async function fetchPage(ctx: Ctx, value: string, key: string | undefined, limit: number): Promise<Page> {
  const url = `${API}${encodeURIComponent(value)}?limit=${limit}`;
  const authenticated = key !== undefined;
  let data: unknown;
  try {
    const res = await ctx.fetchJson<unknown>(url, {
      timeoutMs: TIMEOUT_MS,
      ...(key ? { headers: { 'Argus-API-Key': key } } : {}),
    });
    data = res.data;
  } catch (err) {
    if (err instanceof FetchError && err.kind === 'http' && err.status !== undefined && err.status < 500) {
      throw apiError(err.status, parseBody(err.body), url, authenticated, err.body);
    }
    throw err;
  }

  if (!isObj(data)) throw new FetchError('parse', 'Unexpected response from Mnemonic PDNS (no JSON object)', url);
  const code = finiteNumber(data['responseCode']);
  if (code !== undefined && (code < 200 || code > 299)) throw apiError(code, data, url, authenticated);

  const notFound = messagesOf(data).some((m) => m.template === 'object.not.found');
  const list = data['data'];
  if (!Array.isArray(list)) {
    if (notFound || list === null) return { raw: [], count: 0, limit };
    throw new FetchError('parse', 'Unexpected response from Mnemonic PDNS (missing data array)', url);
  }
  const count = finiteNumber(data['count']);
  return { raw: list, count: count !== undefined && count >= 0 ? Math.floor(count) : undefined, limit };
}

// ---------------------------------------------------------------------------
// Aggregation

function distinctBy(records: PdnsRecord[], pick: (r: PdnsRecord) => string | null): Record<string, number> {
  const sets = new Map<string, Set<string>>();
  for (const r of records) {
    const v = pick(r);
    if (v === null) continue;
    let s = sets.get(r.rrtype);
    if (!s) sets.set(r.rrtype, (s = new Set()));
    s.add(v);
  }
  const out: Record<string, number> = {};
  for (const [k, s] of sets) out[k] = s.size;
  return out;
}

function sum(o: Record<string, number>, keys?: string[]): number {
  return Object.entries(o).reduce((acc, [k, v]) => (keys && !keys.includes(k) ? acc : acc + v), 0);
}

export function buildData(value: string, authenticated: boolean, page: Page): PdnsData {
  const valid: PdnsRecord[] = [];
  for (const raw of page.raw) {
    const r = parseRecord(raw);
    if (r) valid.push(r);
  }
  valid.sort(compareRecords);
  const fetched = page.raw.length;
  const total = Math.max(page.count ?? fetched, fetched);
  // `count` is capped at the access tier's maximum (live: exactly 1000 for 8.8.8.8 and
  // google.com without a key), so a full page means "at least this many", not "all of them".
  const truncated = total > fetched || (page.limit > 0 && fetched >= page.limit);

  let firstSeen: string | null = null;
  let lastSeen: string | null = null;
  for (const r of valid) {
    if (r.firstSeen && (!firstSeen || r.firstSeen < firstSeen)) firstSeen = r.firstSeen;
    if (r.lastSeen && (!lastSeen || r.lastSeen > lastSeen)) lastSeen = r.lastSeen;
  }

  return {
    query: value,
    authenticated,
    total,
    fetched,
    truncated,
    skipped: fetched - valid.length,
    firstSeen,
    lastSeen,
    distinctAnswers: distinctBy(valid, (r) => (isReverse(r, value) ? null : r.answer)),
    distinctNames: distinctBy(valid, (r) => (isReverse(r, value) ? r.query : null)),
    records: valid.slice(0, MAX_RECORDS),
  };
}

const day = (iso: string) => iso.slice(0, 10);

function range(first: string | null, last: string | null): string {
  if (first && last) return `${day(first)} → ${day(last)}`;
  if (last) return `last ${day(last)}`;
  if (first) return `first ${day(first)}`;
  return '';
}

function plural(n: number, word: string, more = false): string {
  return `${n}${more ? '+' : ''} ${word}${n === 1 && !more ? '' : 's'}`;
}

export function summarise(d: PdnsData, kind: Entity['kind']): string {
  if (d.total === 0) return 'No passive DNS records';
  // A full page with count == fetched: the real total is unknown (count is capped).
  const parts = [plural(d.total, 'record', d.truncated && d.total <= d.fetched)];
  if (kind === 'ip') {
    const n = sum(d.distinctNames, ['a', 'aaaa']);
    if (n > 0) parts.push(plural(n, 'distinct domain', d.truncated));
  } else {
    const n = sum(d.distinctAnswers, ['a', 'aaaa']);
    if (n > 0) parts.push(plural(n, 'distinct IP', d.truncated));
  }
  if (d.firstSeen && d.lastSeen) parts.push(`seen ${day(d.firstSeen)} → ${day(d.lastSeen)}`);
  else if (d.lastSeen) parts.push(`last seen ${day(d.lastSeen)}`);
  return parts.join(' · ');
}

/** Distinct domains seen resolving (A/AAAA) to the IP, most recently seen first. */
function domainPivots(records: PdnsRecord[], ip: string): Pivot[] {
  const out: Pivot[] = [];
  const seen = new Set<string>();
  for (const r of records) {
    if (out.length >= MAX_PIVOTS) break;
    // Only address records: a TXT whose text happens to equal the IP is not "resolving to" it.
    if (r.rrtype !== 'a' && r.rrtype !== 'aaaa') continue;
    if (!isReverse(r, ip) || seen.has(r.query) || !hostname(r.query)) continue;
    seen.add(r.query);
    out.push({
      kind: 'domain',
      value: r.query,
      note: r.lastSeen ? `Passive DNS, last seen ${day(r.lastSeen)}` : 'Passive DNS',
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Facts

interface Line {
  text: string;
  first: string | null;
  last: string | null;
}

/** Merge duplicate texts (keeping the widest first/last range) and format "value (first → last)". */
function lines(items: Line[]): string[] {
  const merged = new Map<string, Line>();
  for (const it of items) {
    const prev = merged.get(it.text);
    if (!prev) {
      merged.set(it.text, { ...it });
      continue;
    }
    if (it.first && (!prev.first || it.first < prev.first)) prev.first = it.first;
    if (it.last && (!prev.last || it.last > prev.last)) prev.last = it.last;
  }
  return [...merged.values()].map((l) => {
    const r = range(l.first, l.last);
    return r ? `${l.text} (${r})` : l.text;
  });
}

/** Bare indicator for the copy button: drop the date range, the [RR] suffix and any 'query → ' prefix. */
export function bareIndicator(line: string): string {
  let v = line.replace(/ \([^()]*\)$/, '').replace(/ \[[A-Z0-9]+\]$/, '');
  const arrow = v.lastIndexOf(' → ');
  if (arrow >= 0) v = v.slice(arrow + 3);
  return v.trim();
}

function groupLabel(name: string, distinct: number, shown: number, more: boolean): string {
  return `${name} · ${distinct}${more ? '+' : ''} distinct${shown < distinct ? `, ${shown} shown` : ''}`;
}

function rrRank(t: string): number {
  const i = RR_ORDER.indexOf(t);
  return i < 0 ? RR_ORDER.length : i;
}

const rrOrder = (a: string, b: string): number => rrRank(a) - rrRank(b) || a.localeCompare(b);

export function pdnsFacts(d: PdnsData, e: Entity): Fact[] {
  const facts: Fact[] = [];
  facts.push(
    !d.truncated
      ? { label: 'Records', value: String(d.total) }
      : d.total > d.fetched
        ? { label: 'Records', value: `${d.total} (first ${d.fetched} fetched)`, tone: 'warn' }
        : {
            label: 'Records',
            value: `${d.total}+ (per-lookup limit reached; older records not fetched${d.authenticated ? '' : ', a key raises the limit'})`,
            tone: 'warn',
          },
  );
  if (d.records.length < d.fetched - d.skipped) {
    facts.push({ label: 'Shown', value: `${d.records.length} most recent of ${d.fetched - d.skipped}` });
  }
  const seen = range(d.firstSeen, d.lastSeen);
  if (seen) facts.push({ label: 'Seen', value: d.truncated ? `${seen} (fetched records only)` : seen });
  facts.push({ label: 'Access', value: d.authenticated ? 'Argus API key' : 'Public (TLP:WHITE data only)' });
  if (d.skipped > 0) facts.push({ label: 'Skipped', value: plural(d.skipped, 'malformed record'), tone: 'warn' });

  const value = d.query;
  const forward = new Map<string, Line[]>();
  const reverse: Array<Line & { rrtype: string }> = [];
  for (const r of d.records) {
    if (isReverse(r, value)) {
      reverse.push({ text: r.query, first: r.firstSeen, last: r.lastSeen, rrtype: r.rrtype });
      continue;
    }
    // For a domain, its own answers; for an IP, anything not pointing at it (e.g. PTR).
    const text = r.query === value ? r.answer : `${r.query} → ${r.answer}`;
    const list = forward.get(r.rrtype) ?? [];
    list.push({ text, first: r.firstSeen, last: r.lastSeen });
    forward.set(r.rrtype, list);
  }

  const reverseFact = (): Fact | undefined => {
    if (!reverse.length) return undefined;
    const ipish = e.kind === 'ip';
    const all = lines(
      reverse.map((l) => ({
        ...l,
        text: ipish && (l.rrtype === 'a' || l.rrtype === 'aaaa') ? l.text : `${l.text} [${l.rrtype.toUpperCase()}]`,
      })),
    );
    const distinct = Math.max(sum(d.distinctNames), all.length);
    const shown = all.slice(0, MAX_LINES);
    return {
      label: groupLabel(ipish ? 'Domains' : 'Pointing here', distinct, shown.length, d.truncated),
      value: shown,
      pivot: true,
      copy: shown.map(bareIndicator),
    };
  };

  if (e.kind === 'ip') {
    const f = reverseFact();
    if (f) facts.push(f);
  }
  for (const rr of [...forward.keys()].sort(rrOrder)) {
    const all = lines(forward.get(rr) ?? []);
    const distinct = Math.max(d.distinctAnswers[rr] ?? 0, all.length);
    const shown = all.slice(0, MAX_LINES);
    facts.push({
      label: groupLabel(rr.toUpperCase(), distinct, shown.length, d.truncated),
      value: shown,
      ...(INDICATOR_TYPES.has(rr) ? { pivot: true, copy: shown.map(bareIndicator) } : {}),
    });
  }
  if (e.kind !== 'ip') {
    const f = reverseFact();
    if (f) facts.push(f);
  }
  return facts;
}

// ---------------------------------------------------------------------------

async function apiKey(ctx: Ctx): Promise<string | undefined> {
  const key = (await ctx.getKey('mnemonic'))?.trim();
  if (!key) return undefined;
  // Header values must be visible ASCII; anything else would surface as a confusing network error.
  if (!/^[\x21-\x7e]+$/.test(key)) throw new Error('The Mnemonic API key contains invalid characters. Re-enter it in settings.');
  return key;
}

export const pdnsModule: Module<PdnsData> = {
  id: 'pdns',
  label: 'Passive DNS (Mnemonic)',
  version: 1,
  accepts: ['domain', 'ip'],
  key: 'mnemonic',
  keyOptional: true,
  ttl: 24 * HOUR,
  // Public quota: 10 requests/min and 1000/day.
  rateLimit: { perMinute: 10 },
  note:
    'Without an Argus API key Mnemonic serves TLP:WHITE data only, at most 1000 records per lookup, ' +
    'within a 10 lookups/min and 1000/day quota. First/last-seen dates are included either way.',

  async run(e, ctx) {
    if (e.kind !== 'domain' && e.kind !== 'ip') throw new SkipError('Passive DNS needs a domain or an IP.');
    const value = e.kind === 'ip' ? (normalizeIp(e.value) ?? e.value) : cleanName(e.value);
    if (!value) throw new SkipError('Nothing to look up.');
    const key = await apiKey(ctx);

    let page: Page;
    try {
      page = await fetchPage(ctx, value, key, key ? AUTH_LIMIT : PUBLIC_LIMIT);
    } catch (err) {
      // A key on a public-tier allowance: fall back once to the public maximum.
      if (key && err instanceof FetchError && err.status === 412) {
        page = await fetchPage(ctx, value, key, PUBLIC_LIMIT);
      } else {
        throw err;
      }
    }

    const data = buildData(value, key !== undefined, page);
    if (data.fetched > 0 && data.skipped === data.fetched) {
      throw new Error(`Mnemonic PDNS returned ${data.fetched} records but none could be parsed (API format change?).`);
    }
    const pivots = e.kind === 'ip' ? domainPivots(data.records, value) : [];
    return {
      data,
      summary: summarise(data, e.kind),
      ...(pivots.length ? { pivots } : {}),
    };
  },

  facts: pdnsFacts,
};

/** Settings-page "Test" for the Mnemonic key (the lead registers it via registerKeyTester). */
export const mnemonicKeyTester: KeyTester = async (key, http) => {
  let data: unknown;
  try {
    const res = await http.fetchJson<unknown>(`${API}${encodeURIComponent('example.com')}?limit=1`, {
      headers: { 'Argus-API-Key': key },
      rateLimit: false,
    });
    data = res.data;
  } catch (err) {
    // Live: a bad key is HTTP 401 {"messages":[{"message":"Invalid API key","messageTemplate":"authentication.failed"}]}.
    if (err instanceof FetchError && err.kind === 'http' && err.status !== undefined) {
      throw apiError(err.status, parseBody(err.body), err.url, true, err.body);
    }
    throw err;
  }
  const env = isObj(data) ? data : undefined;
  const code = finiteNumber(env?.['responseCode']);
  if (code !== undefined && (code < 200 || code > 299)) throw apiError(code, env, `${API}example.com?limit=1`, true);
  const count = finiteNumber(env?.['count']);
  return `Key accepted${count !== undefined ? ` (${count} records for example.com)` : ''}.`;
};
