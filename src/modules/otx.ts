import { FetchError, extractErrorMessage, isAbortError } from '@/lib/http';
import { isIPv4, isIPv6, normalizeIp } from '@/lib/ip';
import type { KeyTester } from '@/lib/keytest';
import type { Ctx, Entity, Fact, JsonResponse, Module, Severity } from '@/lib/types';
import { DAY, HOUR, SkipError } from '@/lib/types';

/**
 * AlienVault OTX indicator lookups. See docs/research/threat-intel.md §9.
 *
 * - Auth: `X-OTX-API-KEY` header (as the official SDK sends it).
 * - Domain: /indicators/domain/{d}/general + /passive_dns (concurrently; a
 *   passive DNS failure is recorded, never fatal). Unknown names return 200
 *   with pulse count 0.
 * - Subdomains: OTX files them as `hostname` indicators. [live 2026-11-25]
 *   /indicators/domain/www.example.com/general answers 200 with 0 pulses while
 *   /indicators/hostname/www.example.com/general lists 50, so names with 3+
 *   labels use /indicators/hostname/{h}/... . The hostname payload carries
 *   OTX's registrable `domain`; when that equals the name itself (bbc.co.uk)
 *   the lookup is redone on the domain endpoints, where its pulses live.
 * - A hostname inherits its parent's validation ("Whitelisted domain
 *   github.io" on any *.github.io name), so such allow-list entries do not
 *   vouch for the hostname and do not zero its severity.
 * - IP: /indicators/IPv4/{ip}/general or /indicators/IPv6/{ip}/general.
 * - `general` is not paginated (example.com: 428 KB, pulses with 400+ tags),
 *   so only a compact digest is kept.
 * - Bad key -> 403 {"detail":"Authentication required"}; invalid indicator -> 400.
 */

const BASE = 'https://otx.alienvault.com';
const API = `${BASE}/api/v1`;
const KEY_HEADER = 'X-OTX-API-KEY';

/** Pulses kept in `data` (most recently modified first). */
export const MAX_PULSES = 10;
/** Tags kept per pulse (OTX pulses can carry hundreds). */
export const MAX_TAGS = 8;
/** Malware family names kept per pulse. */
const MAX_PULSE_FAMILIES = 5;
/** Distinct malware families / adversaries aggregated over all pulses. */
export const MAX_FAMILIES = 10;
const MAX_ADVERSARIES = 5;
/** Passive DNS records kept (most recently seen first). */
export const MAX_PDNS = 30;
/** Passive DNS lines shown in the expanded card. */
const MAX_PDNS_LINES = 15;
const MAX_VALIDATION = 10;
/** Pulse count at which the signal counts as "medium". */
export const MEDIUM_PULSES = 5;
/** Pulse activity older than this is treated as an old signal (medium -> low). */
export const OLD_SIGNAL_MS = 365 * DAY;

export type OtxIndicatorType = 'domain' | 'hostname' | 'IPv4' | 'IPv6';

export interface OtxPulse {
  /** 24-hex pulse id, only when it looks valid (used for the pulse link). */
  id?: string;
  name: string;
  created: string | null;
  modified: string | null;
  /** At most MAX_TAGS. */
  tags: string[];
  /** Distinct tags on the pulse, when more than were kept. */
  tagCount?: number;
  adversary?: string;
  malwareFamilies?: string[];
  /** Lowercase TLP colour (white, green, amber, red). */
  tlp?: string;
  author?: string;
}

export interface OtxValidation {
  source: string;
  name: string;
  message: string;
}

export interface OtxPdnsRecord {
  address: string;
  hostname: string;
  recordType: string;
  first: string | null;
  last: string | null;
}

export interface OtxPassiveDns {
  /** Total records OTX reports (falls back to the array length). */
  count: number;
  /** At most MAX_PDNS, most recently seen first. */
  records: OtxPdnsRecord[];
  /** Set when the passive DNS request failed (the module still succeeds). */
  error?: string;
}

export interface OtxData {
  indicator: string;
  type: OtxIndicatorType;
  /** false when OTX answered 404 for the indicator. */
  found: boolean;
  /** pulse_info.count (the number of community pulses listing the indicator). */
  pulseCount: number;
  /** Latest created/modified date over every pulse in the payload (ISO). */
  latestPulse: string | null;
  /** At most MAX_PULSES, most recently modified first. */
  pulses: OtxPulse[];
  /** Distinct malware family names over all pulses (at most MAX_FAMILIES). */
  malwareFamilies: string[];
  /** Distinct adversary names over all pulses. */
  adversaries: string[];
  validation: OtxValidation[];
  /** A validation entry allow-lists this indicator itself (whitelist / allowlist / known false positive). */
  allowlisted: boolean;
  /**
   * Hostnames: the parent domain whose allow-list entry OTX copied onto this
   * name (set only when nothing allow-lists the name itself). Not a verdict
   * on the hostname: any *.github.io name carries github.io's entry.
   */
  allowlistedParent?: string;
  /** IPs only. */
  country?: string;
  asn?: string;
  /** Domains and hostnames only. */
  passiveDns?: OtxPassiveDns;
  /** Severity given to the card (kept so fact tones match it). */
  severity: Severity;
  /** Plain-text reason for the severity. */
  assessment: string;
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

function count(v: unknown): number | undefined {
  if (typeof v === 'number' && Number.isFinite(v) && v >= 0) return Math.floor(v);
  if (typeof v === 'string' && /^\d{1,12}$/.test(v)) return Number(v);
  return undefined;
}

/** Collapse whitespace/control characters and cap length. */
function clean(v: unknown, max: number): string {
  const s = str(v);
  if (!s) return '';
  const t = s.replace(/[\u0000-\u001f\u007f\s]+/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/** OTX timestamps are naive UTC ("2026-11-12T22:01:16.793000"). Junk -> null. */
export function toIso(v: unknown): string | null {
  const s = str(v)?.trim();
  if (!s) return null;
  const m = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}(?::\d{2})?)(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$/.exec(s);
  let t: number;
  if (m) {
    const frac = m[3] ? `.${m[3].slice(0, 3).padEnd(3, '0')}` : '';
    t = Date.parse(`${m[1]}T${m[2]}${frac}${m[4] ?? 'Z'}`);
  } else if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
    t = Date.parse(`${s}T00:00:00Z`);
  } else {
    return null;
  }
  if (!Number.isFinite(t) || t <= 0 || t >= 253_402_300_800_000) return null;
  return new Date(t).toISOString();
}

function uniqueCapped(values: Iterable<string>, max: number): { kept: string[]; total: number } {
  const seen = new Set<string>();
  const kept: string[] = [];
  for (const v of values) {
    if (!v) continue;
    const k = v.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    if (kept.length < max) kept.push(v);
  }
  return { kept, total: seen.size };
}

// ---------------------------------------------------------------------------
// Parsing

function familyName(v: unknown): string {
  if (typeof v === 'string') return clean(v, 80);
  if (isObj(v)) return clean(v['display_name'], 80) || clean(v['name'], 80) || clean(v['id'], 80);
  return '';
}

export function parsePulse(raw: unknown): OtxPulse | null {
  if (!isObj(raw)) return null;
  const name = clean(raw['name'], 200) || '(untitled pulse)';
  const id = str(raw['id']);
  const rawTags = raw['tags'];
  const rawFamilies = raw['malware_families'];
  const rawAuthor = raw['author'];
  const tags = uniqueCapped(Array.isArray(rawTags) ? rawTags.map((t) => clean(t, 48)) : [], MAX_TAGS);
  const families = Array.isArray(rawFamilies) ? uniqueCapped(rawFamilies.map(familyName), MAX_PULSE_FAMILIES).kept : [];
  const adversary = clean(raw['adversary'], 100);
  const tlp = (str(raw['TLP']) ?? str(raw['tlp']) ?? '').trim().toLowerCase();
  const author = isObj(rawAuthor) ? clean(rawAuthor['username'], 64) : clean(raw['author_name'], 64);
  return {
    ...(id && /^[0-9a-f]{24}$/i.test(id) ? { id: id.toLowerCase() } : {}),
    name,
    created: toIso(raw['created']),
    modified: toIso(raw['modified']),
    tags: tags.kept,
    ...(tags.total > tags.kept.length ? { tagCount: tags.total } : {}),
    ...(adversary ? { adversary } : {}),
    ...(families.length ? { malwareFamilies: families } : {}),
    ...(/^[a-z+]{1,16}$/.test(tlp) ? { tlp } : {}),
    ...(author ? { author } : {}),
  };
}

const activity = (p: OtxPulse): string => {
  const a = p.modified ?? '';
  const b = p.created ?? '';
  return a > b ? a : b;
};

function comparePulses(x: OtxPulse, y: OtxPulse): number {
  const a = activity(x);
  const b = activity(y);
  if (a !== b) return a < b ? 1 : -1;
  return x.name.localeCompare(y.name);
}

export function parseValidation(raw: unknown): OtxValidation[] {
  if (!Array.isArray(raw)) return [];
  const out: OtxValidation[] = [];
  for (const v of raw) {
    if (out.length >= MAX_VALIDATION) break;
    if (!isObj(v)) continue;
    const source = clean(v['source'], 40).toLowerCase();
    const name = clean(v['name'], 100);
    const message = clean(v['message'], 200);
    if (!source && !name && !message) continue;
    out.push({ source, name, message });
  }
  return out;
}

const ALLOW_SOURCES = new Set(['whitelist', 'allowlist', 'false_positive']);
const ALLOW_RE = /white-?list|allow-?list|false.positive/i;

export function isAllowEntry(v: OtxValidation): boolean {
  return ALLOW_SOURCES.has(v.source) || ALLOW_RE.test(`${v.name} ${v.message}`);
}

const NAME_RE = /[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+/g;

/**
 * For a domain/hostname indicator: the parent domain a validation entry names
 * ("Whitelisted domain github.io" on foo.github.io), when it names a parent
 * and not the indicator itself. OTX copies a domain's validation onto every
 * name under it, so such an entry says nothing about the hostname.
 */
export function inheritedFrom(v: OtxValidation, d: Pick<OtxData, 'indicator' | 'type'>): string | undefined {
  if (d.type !== 'domain' && d.type !== 'hostname') return undefined;
  const names: string[] = `${v.name} ${v.message}`.toLowerCase().match(NAME_RE) ?? [];
  if (names.includes(d.indicator)) return undefined;
  return names.find((n) => d.indicator.endsWith(`.${n}`));
}

/** Allow-list entries for the indicator itself (`own`) and those inherited from a parent domain. */
function allowEntries(d: Pick<OtxData, 'indicator' | 'type' | 'validation'>): { own: OtxValidation[]; inherited: OtxValidation[]; parent?: string } {
  const own: OtxValidation[] = [];
  const inherited: OtxValidation[] = [];
  let parent: string | undefined;
  for (const v of d.validation) {
    if (!isAllowEntry(v)) continue;
    const p = inheritedFrom(v, d);
    if (p) {
      inherited.push(v);
      // The closest (longest) parent named.
      if (!parent || p.length > parent.length) parent = p;
    } else {
      own.push(v);
    }
  }
  return { own, inherited, ...(parent ? { parent } : {}) };
}

export function parsePdnsRecord(raw: unknown): OtxPdnsRecord | null {
  if (!isObj(raw)) return null;
  const address = clean(raw['address'], 255);
  const hostname = clean(raw['hostname'], 255).toLowerCase().replace(/\.$/, '');
  if (!address && !hostname) return null;
  const recordType = clean(raw['record_type'], 12).toUpperCase();
  const ip = normalizeIp(address);
  return {
    // CNAME/NS targets are hostnames: same form as `hostname`.
    address: ip ?? address.toLowerCase().replace(/\.$/, ''),
    hostname,
    recordType: /^[A-Z0-9]{1,12}$/.test(recordType) ? recordType : '?',
    first: toIso(raw['first']),
    last: toIso(raw['last']),
  };
}

export function parsePassiveDns(raw: unknown): OtxPassiveDns {
  const list: unknown = isObj(raw) ? raw['passive_dns'] : undefined;
  if (!isObj(raw) || !Array.isArray(list)) {
    return { count: 0, records: [], error: 'Unexpected passive DNS response from OTX' };
  }
  const records: OtxPdnsRecord[] = [];
  for (const r of list) {
    const rec = parsePdnsRecord(r);
    if (rec) records.push(rec);
  }
  records.sort((a, b) => {
    const x = a.last ?? '';
    const y = b.last ?? '';
    if (x !== y) return x < y ? 1 : -1;
    return `${a.hostname} ${a.address}`.localeCompare(`${b.hostname} ${b.address}`);
  });
  const reported = count(raw['count']);
  return {
    count: Math.max(reported ?? list.length, records.length),
    records: records.slice(0, MAX_PDNS),
  };
}

interface General {
  pulseCount: number;
  latestPulse: string | null;
  pulses: OtxPulse[];
  malwareFamilies: string[];
  adversaries: string[];
  validation: OtxValidation[];
  allowlisted: boolean;
  allowlistedParent?: string;
  country?: string;
  asn?: string;
}

export function parseGeneral(raw: Obj, type: OtxIndicatorType, indicator: string): General {
  const rawInfo = raw['pulse_info'];
  const info: Obj = isObj(rawInfo) ? rawInfo : {};
  const pulseList = info['pulses'];
  const rawPulses: unknown[] = Array.isArray(pulseList) ? pulseList : [];
  const pulses: OtxPulse[] = [];
  for (const p of rawPulses) {
    const parsed = parsePulse(p);
    if (parsed) pulses.push(parsed);
  }
  pulses.sort(comparePulses);
  const reported = count(info['count']);
  const pulseCount = Math.max(reported ?? pulses.length, pulses.length);

  let latestPulse: string | null = null;
  for (const p of pulses) {
    const a = activity(p);
    if (a && (!latestPulse || a > latestPulse)) latestPulse = a;
  }

  // Aggregate over every pulse in the payload (not just the kept ones); the
  // per-pulse family lists are already capped, which is fine for a digest.
  const malwareFamilies = uniqueCapped(
    pulses.flatMap((p) => p.malwareFamilies ?? []),
    MAX_FAMILIES,
  ).kept;
  const adversaries = uniqueCapped(
    pulses.map((p) => p.adversary ?? ''),
    MAX_ADVERSARIES,
  ).kept;

  const validation = parseValidation(raw['validation']);
  const allow = allowEntries({ indicator, type, validation });
  const out: General = {
    pulseCount,
    latestPulse,
    pulses: pulses.slice(0, MAX_PULSES),
    malwareFamilies,
    adversaries,
    validation,
    allowlisted: allow.own.length > 0,
    ...(!allow.own.length && allow.parent ? { allowlistedParent: allow.parent } : {}),
  };

  if (type === 'IPv4' || type === 'IPv6') {
    const code = clean(raw['country_code'], 3).toUpperCase();
    const name = clean(raw['country_name'], 80);
    const country = name && /^[A-Z]{2,3}$/.test(code) ? `${name} (${code})` : name || (/^[A-Z]{2,3}$/.test(code) ? code : '');
    if (country) out.country = country;
    const asn = clean(raw['asn'], 100);
    if (asn) out.asn = asn;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Severity + summary

const day = (iso: string) => iso.slice(0, 10);

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

function isOld(d: Pick<OtxData, 'latestPulse'>, now: number): boolean {
  if (!d.latestPulse) return false;
  return now - Date.parse(d.latestPulse) > OLD_SIGNAL_MS;
}

/**
 * Conservative scoring: OTX pulses are community-contributed and noisy.
 * Allow-listed -> none; 0 pulses -> none; 1-4 -> low; >= 5 -> medium,
 * unless every pulse is older than a year (old signal -> low). A hostname
 * whose parent domain is allow-listed stays at most low: the parent entry
 * does not vouch for it, but pulses on popular domains are often noise.
 * OTX never yields 'high' on its own.
 */
export function assess(d: Omit<OtxData, 'assessment' | 'severity'>, now: number): { severity: Severity; reason: string } {
  if (!d.found) return { severity: 'none', reason: 'OTX has no record of this indicator.' };
  if (d.allowlisted) {
    return {
      severity: 'none',
      reason:
        `Allow-listed by OTX${d.pulseCount ? `; its ${plural(d.pulseCount, 'pulse')} are not scored` : ''}. ` +
        'Popular or infrastructure indicators often appear in pulses as noise.',
    };
  }
  const parent = d.allowlistedParent
    ? ` OTX allow-lists the parent domain ${d.allowlistedParent}; that does not vouch for this hostname.`
    : '';
  if (d.pulseCount === 0) return { severity: 'none', reason: `Not listed in any OTX pulse.${parent}` };
  const listed = `Listed in ${plural(d.pulseCount, 'community OTX pulse')}`;
  if (d.allowlistedParent) {
    return { severity: 'low', reason: `${listed} (weak signal: pulses on hostnames of popular domains are often noise).${parent}` };
  }
  if (d.pulseCount >= MEDIUM_PULSES) {
    if (isOld(d, now)) {
      return { severity: 'low', reason: `${listed}, but none updated in the last year (old signal).` };
    }
    return { severity: 'medium', reason: `${listed}. Pulses are user-contributed: review them before acting.` };
  }
  return { severity: 'low', reason: `${listed} (fewer than ${MEDIUM_PULSES}: weak signal). Pulses are user-contributed.` };
}

export function summarise(d: OtxData, now: number): string {
  const parts: string[] = [];
  if (!d.found) {
    parts.push('Not in OTX');
  } else {
    const latest = d.latestPulse ? ` (latest ${day(d.latestPulse)}${isOld(d, now) ? ', over a year ago' : ''})` : '';
    if (d.allowlisted) {
      parts.push('Allow-listed by OTX');
      if (d.pulseCount > 0) parts.push(`in ${plural(d.pulseCount, 'pulse')}${latest}, not scored`);
    } else if (d.pulseCount === 0) {
      parts.push('No OTX pulses');
      if (d.allowlistedParent) parts.push(`parent ${d.allowlistedParent} allow-listed`);
    } else {
      parts.push(`In ${plural(d.pulseCount, 'OTX pulse')}${latest}`);
      if (d.allowlistedParent) parts.push(`parent ${d.allowlistedParent} allow-listed`);
      if (d.malwareFamilies.length) {
        const shown = d.malwareFamilies.slice(0, 3);
        const more = d.malwareFamilies.length - shown.length;
        parts.push(`malware: ${shown.join(', ')}${more > 0 ? ` +${more}` : ''}`);
      }
    }
  }
  if (d.passiveDns) {
    parts.push(d.passiveDns.error ? 'passive DNS unavailable' : plural(d.passiveDns.count, 'passive DNS record'));
  }
  return parts.join(' · ');
}

// ---------------------------------------------------------------------------
// Facts

function guiUrl(d: Pick<OtxData, 'type' | 'indicator'>): string {
  const section = d.type === 'domain' || d.type === 'hostname' ? d.type : 'ip';
  return `${BASE}/indicator/${section}/${encodeURIComponent(d.indicator)}`;
}

function pulseLine(p: OtxPulse): string {
  const bits: string[] = [p.name];
  const created = p.created ? day(p.created) : null;
  const modified = p.modified ? day(p.modified) : null;
  if (created && modified && created !== modified) bits.push(`created ${created}, modified ${modified}`);
  else if (created ?? modified) bits.push(`created ${created ?? modified}`);
  if (p.tags.length) bits.push(`tags: ${p.tags.join(', ')}${p.tagCount ? ` (+${p.tagCount - p.tags.length})` : ''}`);
  if (p.malwareFamilies?.length) bits.push(`malware: ${p.malwareFamilies.join(', ')}`);
  if (p.adversary) bits.push(`adversary: ${p.adversary}`);
  if (p.tlp) bits.push(`TLP:${p.tlp.toUpperCase()}`);
  if (p.author) bits.push(`by ${p.author}`);
  return bits.join(' · ');
}

function pdnsLine(r: OtxPdnsRecord, d: OtxData): string {
  const range = r.first && r.last ? `${day(r.first)} → ${day(r.last)}` : r.last ? `last ${day(r.last)}` : r.first ? `first ${day(r.first)}` : '';
  const target = r.hostname && r.hostname !== d.indicator ? `${r.hostname} → ${r.address}` : r.address || r.hostname;
  return `${target} [${r.recordType}]${range ? ` (${range})` : ''}`;
}

export function otxFacts(d: OtxData): Fact[] {
  const facts: Fact[] = [];
  const sev = d.found ? assessTone(d) : undefined;
  facts.push({ label: 'Assessment', value: d.assessment, ...(sev ? { tone: sev } : {}) });

  if (d.found) {
    facts.push({
      label: 'Pulses',
      value: `${d.pulseCount}${d.latestPulse ? ` (latest ${day(d.latestPulse)})` : ''}${
        d.pulses.length < d.pulseCount ? `; ${d.pulses.length} most recent shown` : ''
      }`,
    });
  }

  const allow = allowEntries(d);
  const other = d.validation.filter((v) => !isAllowEntry(v));
  const vLine = (v: OtxValidation) => (v.name && v.message && v.name !== v.message ? `${v.name}: ${v.message}` : v.message || v.name || v.source);
  if (allow.own.length) facts.push({ label: 'Allow-listed', value: allow.own.map(vLine), tone: 'good' });
  if (allow.inherited.length) {
    // No 'good' tone: OTX copies the parent's entry onto every name under it.
    facts.push({ label: 'Parent domain allow-listed', value: allow.inherited.map(vLine) });
  }
  if (other.length) facts.push({ label: 'Validation', value: other.map(vLine) });

  if (d.malwareFamilies.length) facts.push({ label: 'Malware families', value: d.malwareFamilies, ...(d.allowlisted ? {} : { tone: 'warn' as const }) });
  if (d.adversaries.length) facts.push({ label: 'Adversaries', value: d.adversaries });

  for (const p of d.pulses) {
    const date = activity(p);
    facts.push({
      label: `Pulse${date ? ` · ${day(date)}` : ''}`,
      value: pulseLine(p),
      ...(p.id ? { href: `${BASE}/pulse/${encodeURIComponent(p.id)}` } : {}),
    });
  }

  if (d.country) facts.push({ label: 'Country', value: d.country });
  if (d.asn) facts.push({ label: 'ASN', value: d.asn });

  if (d.passiveDns) {
    const p = d.passiveDns;
    if (p.error) {
      facts.push({ label: 'Passive DNS', value: `Unavailable: ${p.error}`, tone: 'warn' });
    } else {
      facts.push({ label: 'Passive DNS', value: `${plural(p.count, 'record')}${p.records.length < p.count ? ` (${p.records.length} kept)` : ''}` });
      const lines = p.records.slice(0, MAX_PDNS_LINES).map((r) => pdnsLine(r, d));
      if (lines.length) {
        facts.push({ label: `Passive DNS sample · ${lines.length} most recent`, value: lines, pivot: true });
      }
    }
  }

  facts.push({ label: 'Open in OTX', value: guiUrl(d), href: guiUrl(d) });
  return facts;
}

/** Tone of the assessment fact; follows the stored severity (an old signal is 'low', so 'warn'). */
function assessTone(d: OtxData): Fact['tone'] {
  if (d.severity === 'none' || d.severity === 'info') return 'good';
  return d.severity === 'low' ? 'warn' : 'bad';
}

// ---------------------------------------------------------------------------
// Requests + errors

function bodyDetail(body: string | undefined): string {
  const d = body ? extractErrorMessage(body) : undefined;
  return d ? `: ${d.slice(0, 160)}` : '';
}

/** Rewrites provider HTTP errors into clear messages (never includes the key). */
function otxError(err: unknown, what: string): unknown {
  if (!(err instanceof FetchError) || err.kind !== 'http' || err.status === undefined) return err;
  const s = err.status;
  const detail = bodyDetail(err.body);
  let msg: string;
  if (s === 401 || s === 403) msg = `OTX rejected the API key (HTTP ${s}${detail}). Check the OTX key in settings.`;
  else if (s === 429) msg = `OTX rate limit or quota reached (HTTP 429${detail}) after waiting and retrying once. Try again later.`;
  else msg = `OTX ${what} failed (HTTP ${s}${detail}).`;
  return new FetchError('http', msg, err.url, s, err.body);
}

function errorText(err: unknown): string {
  const e = otxError(err, 'passive DNS lookup');
  return (e instanceof Error ? e.message : String(e)).slice(0, 240);
}

async function apiKey(ctx: Ctx): Promise<string> {
  const key = (await ctx.getKey('otx'))?.trim();
  if (!key) throw new SkipError('Add an AlienVault OTX API key in settings to enable this check.');
  checkKeyChars(key);
  return key;
}

function checkKeyChars(key: string): void {
  // Header values must be visible ASCII; anything else would surface as a confusing network error.
  if (!/^[\x21-\x7e]+$/.test(key)) throw new Error('The OTX API key contains invalid characters. Re-enter it in settings.');
}

function target(e: Entity): Target {
  if (e.kind === 'ip') {
    const ip = normalizeIp(e.value);
    if (ip && isIPv4(ip)) return { type: 'IPv4', value: ip };
    if (ip && isIPv6(ip)) return { type: 'IPv6', value: ip };
    throw new SkipError('Not a valid IP address.');
  }
  if (e.kind === 'domain') {
    const d = e.value.trim().toLowerCase().replace(/\.$/, '');
    if (!d) throw new SkipError('Nothing to look up.');
    // 3+ labels: most likely a subdomain, which OTX files as a hostname
    // (run() switches back to /domain/ when OTX says it is registrable).
    return { type: d.split('.').length > 2 ? 'hostname' : 'domain', value: d };
  }
  throw new SkipError('OTX lookups need a domain or an IP.');
}

const typeWord = (t: OtxIndicatorType): string => (t === 'IPv4' || t === 'IPv6' ? 'IP' : t);

async function fetchGeneral(ctx: Ctx, url: string, headers: Record<string, string>, t: Target): Promise<JsonResponse<unknown>> {
  let res: JsonResponse<unknown>;
  try {
    res = await ctx.fetchJson<unknown>(url, { headers, okStatuses: [404] });
  } catch (err) {
    if (err instanceof FetchError && err.kind === 'http' && err.status === 400) {
      throw new SkipError(`OTX does not accept "${t.value}" as a valid ${typeWord(t.type)} indicator.`);
    }
    throw otxError(err, 'lookup');
  }
  if (res.status !== 404 && !isObj(res.data)) {
    throw new FetchError('parse', 'Unexpected response from OTX (no JSON object).', res.url, res.status);
  }
  return res;
}

type Target = { type: OtxIndicatorType; value: string };

/** Starts `general` and (for names) `passive_dns` concurrently. */
function startLookup(ctx: Ctx, t: Target, headers: Record<string, string>) {
  const base = `${API}/indicators/${t.type}/${encodeURIComponent(t.value)}`;
  const general = fetchGeneral(ctx, `${base}/general`, headers, t);
  const pdns = t.type === 'domain' || t.type === 'hostname' ? fetchPassiveDns(ctx, `${base}/passive_dns`, headers) : undefined;
  // Mark as handled: if `general` fails (or the lookup is redone) it is never awaited.
  pdns?.catch(() => undefined);
  return { general, pdns };
}

async function fetchPassiveDns(ctx: Ctx, url: string, headers: Record<string, string>): Promise<OtxPassiveDns> {
  try {
    const res = await ctx.fetchJson<unknown>(url, { headers, okStatuses: [404] });
    if (res.status === 404) return { count: 0, records: [] };
    return parsePassiveDns(res.data);
  } catch (err) {
    if (isAbortError(err) || ctx.signal.aborted) throw err;
    return { count: 0, records: [], error: errorText(err) };
  }
}

export const otxModule: Module<OtxData> = {
  id: 'otx',
  label: 'AlienVault OTX',
  version: 1,
  accepts: ['domain', 'ip'],
  key: 'otx',
  ttl: 24 * HOUR,
  // OTX documents no limit; stay well below what the SDK tolerates.
  rateLimit: { perMinute: 30 },
  note: 'OTX pulses are community-contributed threat reports. Being listed in a pulse is a lead, not a verdict.',

  async run(e, ctx) {
    const key = await apiKey(ctx);
    let t = target(e);
    const headers = { [KEY_HEADER]: key };

    let lookup = startLookup(ctx, t, headers);
    let res = await lookup.general;
    if (t.type === 'hostname' && res.status !== 404 && isObj(res.data)) {
      const registrable = clean(res.data['domain'], 253).toLowerCase().replace(/\.$/, '');
      if (registrable === t.value) {
        // OTX's own suffix rules say this name is registrable (e.g. bbc.co.uk):
        // its pulses are under /domain/ (/hostname/ answers with 0 pulses).
        t = { type: 'domain', value: t.value };
        lookup = startLookup(ctx, t, headers);
        res = await lookup.general;
      }
    }

    const found = res.status !== 404;
    const general = parseGeneral(found && isObj(res.data) ? res.data : {}, t.type, t.value);
    const passiveDns = lookup.pdns ? await lookup.pdns : undefined;

    const base0: Omit<OtxData, 'assessment' | 'severity'> = {
      indicator: t.value,
      type: t.type,
      found,
      ...general,
      ...(passiveDns ? { passiveDns } : {}),
    };
    const now = ctx.now();
    const { severity, reason } = assess(base0, now);
    const data: OtxData = { ...base0, severity, assessment: reason };
    // No pivots: VirusTotal and DNS already provide resolved IPs.
    return { data, summary: summarise(data, now), severity };
  },

  facts: otxFacts,
};

/** Settings-page "Test" for the OTX key (the lead registers it via registerKeyTester). */
export const otxKeyTest: KeyTester = async (key, http) => {
  const k = key.trim();
  if (!k) throw new Error('Enter an OTX API key first.');
  checkKeyChars(k);
  let data: unknown;
  try {
    const res = await http.fetchJson<unknown>(`${API}/user/me`, { headers: { [KEY_HEADER]: k } });
    data = res.data;
  } catch (err) {
    if (err instanceof FetchError && (err.status === 401 || err.status === 403)) {
      throw new Error(`OTX rejected this key (HTTP ${err.status}${bodyDetail(err.body)}).`);
    }
    if (err instanceof FetchError && err.status === 429) {
      throw new Error('OTX rate limit reached; wait a minute and test again.');
    }
    if (err instanceof FetchError && err.kind === 'parse') {
      throw new Error('OTX returned an unexpected (non-JSON) response; the key could not be verified.');
    }
    throw err;
  }
  if (!isObj(data)) throw new Error('OTX returned an unexpected response; the key could not be verified.');
  const user = clean(data['username'], 64);
  return user ? `Key accepted (signed in as ${user}).` : 'Key accepted.';
};
