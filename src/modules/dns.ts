import { RCODE, dohQuery, parseCaa, parseMx, parseSoa, recordsOf, stripDot } from '@/lib/doh';
import type { DohResult, RRType, Soa } from '@/lib/doh';
import { FetchError, isAbortError } from '@/lib/http';
import { normalizeIp } from '@/lib/ip';
import type { Fact, Module, Pivot } from '@/lib/types';
import { MINUTE, SkipError } from '@/lib/types';

/**
 * Module 1 "Active DNS (DoH)": the domain's current records via the shared
 * DoH client (Cloudflare, Google fallback). Passive: only public resolvers
 * are contacted, never the domain's own servers.
 */

export type DnsLookup = RRType | 'DMARC';

export interface CaaRecord {
  flags: number;
  tag: string;
  value: string;
}

export interface DmarcPolicy {
  /** The raw record (unquoted, chunks joined). */
  record: string;
  /** Lowercased `p=` value; null when the tag is missing (receivers fall back to none). */
  p: string | null;
  sp?: string;
  pct?: number;
  rua?: string[];
}

type CappedList = 'a' | 'aaaa' | 'ns' | 'mx' | 'txt' | 'caa';

export interface DnsData {
  /** Resolvers that answered at least one lookup (Google only appears after a Cloudflare failure). */
  resolvers: Array<DohResult['resolver']>;
  /** rcode name of the apex lookup (A, or the first apex lookup that answered); 'UNKNOWN' when none returned. */
  apexStatus: string;
  /** AD flag on the apex lookup: the resolver validated the answer with DNSSEC. */
  dnssec: boolean;
  a: string[];
  aaaa: string[];
  /** CNAME chain starting at the domain (targets only, in order). */
  cname: string[];
  ns: string[];
  /** Sorted by preference. A null MX (RFC 7505) is `{ preference: 0, exchange: '' }`. */
  mx: Array<{ preference: number; exchange: string }>;
  txt: string[];
  /** `zone` is the owner name of the SOA (the zone that contains the domain). */
  soa: (Soa & { zone: string }) | null;
  caa: CaaRecord[];
  /** First TXT record starting with v=spf1 (case-insensitive). */
  spf: string | null;
  /** More than one SPF record is a misconfiguration (RFC 7208 §4.5 permerror). */
  spfCount: number;
  dmarc: DmarcPolicy | null;
  /** More than one DMARC record makes receivers ignore DMARC (RFC 7489 §6.6.3). */
  dmarcCount: number;
  /** Per-lookup failures (transport errors or SERVFAIL/REFUSED answers). */
  errors: Partial<Record<DnsLookup, string>>;
  /** Total counts for lists that were capped. */
  totals?: Partial<Record<CappedList, number>>;
}

const LOOKUPS: ReadonlyArray<{ id: DnsLookup; type: RRType }> = [
  { id: 'A', type: 'A' },
  { id: 'AAAA', type: 'AAAA' },
  { id: 'NS', type: 'NS' },
  { id: 'MX', type: 'MX' },
  { id: 'TXT', type: 'TXT' },
  { id: 'CNAME', type: 'CNAME' },
  { id: 'SOA', type: 'SOA' },
  { id: 'CAA', type: 'CAA' },
  { id: 'DMARC', type: 'TXT' },
];

const APEX_ORDER: readonly DnsLookup[] = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CNAME', 'SOA', 'CAA'];

const CAPS: Record<CappedList, number> = { a: 50, aaaa: 50, ns: 20, mx: 20, txt: 30, caa: 20 };
const MAX_TXT_LEN = 512;
const MAX_SPF_LEN = 2048;
const MAX_CHAIN = 16;
const MAX_RUA = 10;
const MAX_ERR_LEN = 200;
/** A DNS message can carry ~64 KB of TXT/CAA data; keep cached data and the summary line bounded. */
const MAX_DMARC_LEN = 1024;
const MAX_TAG_LEN = 32;
const MAX_URI_LEN = 256;

const SPF_RE = /^v=spf1(?:\s|$)/i;
const DMARC_RE = /^v\s*=\s*DMARC1\s*(?:;|$)/i;

function rcodeName(status: number): string {
  return RCODE[status] ?? `RCODE ${status}`;
}

function errMessage(err: unknown): string {
  const msg = err instanceof Error ? err.message || err.name : String(err);
  return msg.length > MAX_ERR_LEN ? `${msg.slice(0, MAX_ERR_LEN - 1)}…` : msg;
}

function clip(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function uniq<T>(xs: readonly T[], key: (x: T) => string = String): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const x of xs) {
    const k = key(x);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(x);
  }
  return out;
}

/** Parse a DMARC TXT record (tags are case-insensitive, values trimmed). Null if it is not DMARC. */
export function parseDmarc(record: string): DmarcPolicy | null {
  const rec = record.trim();
  if (!DMARC_RE.test(rec)) return null;
  const tags = new Map<string, string>();
  for (const part of rec.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim().toLowerCase();
    if (k && !tags.has(k)) tags.set(k, part.slice(eq + 1).trim());
  }
  const p = tags.get('p')?.toLowerCase();
  const out: DmarcPolicy = { record: clip(rec, MAX_DMARC_LEN), p: p ? clip(p, MAX_TAG_LEN) : null };
  const sp = tags.get('sp')?.toLowerCase();
  if (sp) out.sp = clip(sp, MAX_TAG_LEN);
  const pctRaw = tags.get('pct');
  if (pctRaw !== undefined && /^\d{1,3}$/.test(pctRaw)) {
    const pct = Number(pctRaw);
    if (pct <= 100) out.pct = pct;
  }
  const rua = (tags.get('rua') ?? '')
    .split(',')
    .map((u) => clip(u.trim(), MAX_URI_LEN))
    .filter(Boolean);
  if (rua.length) out.rua = uniq(rua).slice(0, MAX_RUA);
  return out;
}

/** CAA in RFC 3597 generic form (`\# 19 00 05 69 73 73 75 65 ...`), which some resolvers emit. */
export function parseGenericCaa(data: string): CaaRecord | null {
  const m = /^\\#\s+(\d+)\s+([0-9a-f\s]+)$/i.exec(data.trim());
  if (!m) return null;
  const hex = m[2]!.replace(/\s+/g, '');
  if (hex.length % 2 !== 0 || hex.length / 2 !== Number(m[1])) return null;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  const flags = bytes[0];
  const tagLen = bytes[1];
  if (flags === undefined || tagLen === undefined || tagLen < 1 || 2 + tagLen > bytes.length) return null;
  const dec = new TextDecoder();
  const tag = dec.decode(bytes.subarray(2, 2 + tagLen)).toLowerCase();
  if (!/^[a-z0-9]+$/.test(tag)) return null;
  return { flags, tag, value: dec.decode(bytes.subarray(2 + tagLen)) };
}

/** SOA RNAME (dns-admin.google.com) as a mailbox (dns-admin@google.com); `\.` escapes a dot in the local part. */
export function rnameToEmail(rname: string): string {
  const m = /^((?:[^.\\]|\\.)+)\.(.+)$/.exec(rname);
  if (!m) return rname;
  return `${m[1]!.replace(/\\(.)/g, '$1')}@${m[2]}`;
}

/** The `all` qualifier of an SPF record, or null when there is no `all` mechanism. */
export function spfAllQualifier(spf: string): '+' | '-' | '~' | '?' | null {
  const m = /(?:^|\s)([+\-~?]?)all(?=\s|$)/i.exec(spf);
  if (!m) return null;
  return (m[1] || '+') as '+' | '-' | '~' | '?';
}

function capList<T>(list: T[], key: CappedList, totals: Partial<Record<CappedList, number>>): T[] {
  if (list.length <= CAPS[key]) return list;
  totals[key] = list.length;
  return list.slice(0, CAPS[key]);
}

/** Follow CNAME records from `start` across every lookup's Answer section. */
function cnameChain(start: string, results: Partial<Record<DnsLookup, DohResult>>): string[] {
  const next = new Map<string, string>();
  for (const id of APEX_ORDER) {
    const res = results[id];
    if (!res) continue;
    for (const r of recordsOf(res, 'CNAME')) {
      const target = stripDot(r.data);
      if (target && !next.has(r.name)) next.set(r.name, target);
    }
  }
  const chain: string[] = [];
  const seen = new Set([start]);
  let cur = start;
  while (chain.length < MAX_CHAIN) {
    const t = next.get(cur);
    if (!t || seen.has(t)) break;
    chain.push(t);
    seen.add(t);
    cur = t;
  }
  return chain;
}

function ips(res: DohResult | undefined, type: 'A' | 'AAAA'): string[] {
  if (!res) return [];
  const out: string[] = [];
  for (const r of recordsOf(res, type)) {
    const ip = normalizeIp(r.data);
    if (!ip) continue;
    if ((type === 'A') === ip.includes(':')) continue; // an AAAA value under type 1, or vice versa
    out.push(ip);
  }
  return uniq(out);
}

/**
 * parseMx plus the null MX (RFC 7505). The shared client normalises MX data to
 * `${preference} ${exchange}`, which turns "0 ." into "0 " that parseMx rejects.
 */
function mxOf(data: string): { preference: number; exchange: string } | null {
  const m = parseMx(data);
  if (m) return m;
  const n = /^(\d+)\s*\.?$/.exec(data.trim());
  return n ? { preference: Number(n[1]), exchange: '' } : null;
}

function txtValues(res: DohResult | undefined): string[] {
  return res ? recordsOf(res, 'TXT').map((r) => r.data) : [];
}

function count(d: DnsData, key: CappedList): number {
  return d.totals?.[key] ?? d[key].length;
}

function isNullMx(d: DnsData): boolean {
  return d.mx.length > 0 && d.mx.every((m) => m.exchange === '');
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

export function dnsSummary(d: DnsData): string {
  if (d.apexStatus === 'NXDOMAIN') {
    const last = d.cname.at(-1);
    return last ? `Dangling CNAME → ${last} (NXDOMAIN)` : 'NXDOMAIN (domain does not resolve)';
  }
  const parts: string[] = [];
  const last = d.cname.at(-1);
  if (last) parts.push(`CNAME → ${last}`);
  const a = count(d, 'a');
  const aaaa = count(d, 'aaaa');
  if (a) parts.push(`${a} A`);
  if (aaaa) parts.push(`${aaaa} AAAA`);
  if (!a && !aaaa && !d.errors.A && !d.errors.AAAA && d.apexStatus === 'NOERROR') parts.push('no A/AAAA');
  if (isNullMx(d)) parts.push('null MX');
  else if (d.mx.length) parts.push(`${count(d, 'mx')} MX`);
  if (d.spfCount === 1) parts.push('SPF');
  else if (d.spfCount > 1) parts.push(`${d.spfCount}× SPF`);
  // Several DMARC records make receivers ignore DMARC, so the first record's p= would overclaim.
  if (d.dmarcCount > 1) parts.push(`${d.dmarcCount}× DMARC`);
  else if (d.dmarc) parts.push(`DMARC p=${d.dmarc.p ?? '?'}`);
  const nErr = Object.keys(d.errors).length;
  // UNKNOWN: no apex lookup returned anything, so the error count is the honest summary.
  if (d.apexStatus !== 'NOERROR' && d.apexStatus !== 'UNKNOWN' && parts.length === 0) {
    return `${d.apexStatus} (resolvers could not resolve the domain)`;
  }
  if (nErr) parts.push(`${plural(nErr, 'lookup')} failed`);
  return parts.length ? parts.join(' · ') : 'No records';
}

function spfFact(d: DnsData): Fact {
  if (!d.spf) {
    return d.errors.TXT
      ? { label: 'SPF', value: 'unknown (TXT lookup failed)', tone: 'warn' }
      : { label: 'SPF', value: 'none', tone: 'warn' };
  }
  if (d.spfCount > 1) {
    return {
      label: 'SPF',
      value: [`${d.spfCount} SPF records published (invalid: RFC 7208 permerror)`, d.spf],
      tone: 'warn',
    };
  }
  const q = spfAllQualifier(d.spf);
  let tone: Fact['tone'];
  if (q === '-' || q === '~') tone = 'good';
  else if (q === '+') tone = 'bad';
  else if (q === '?' || !/(?:^|\s)redirect=/i.test(d.spf)) tone = 'warn';
  return { label: 'SPF', value: d.spf, ...(tone ? { tone } : {}) };
}

function dmarcFacts(d: DnsData, domain: string): Fact[] {
  const m = d.dmarc;
  if (!m) {
    if (d.errors.DMARC) return [{ label: 'DMARC', value: 'unknown (lookup failed)', tone: 'warn' }];
    const orgHint = domain.split('.').length > 2 ? ' (an organisational-domain policy may still apply)' : '';
    return [{ label: 'DMARC', value: `none at _dmarc.${domain}${orgHint}`, tone: 'warn' }];
  }
  let tone: Fact['tone'];
  let value: string | string[] = m.record;
  if (d.dmarcCount > 1) {
    tone = 'warn';
    value = [`${d.dmarcCount} DMARC records published (receivers ignore DMARC)`, m.record];
  } else if (m.p === null) {
    tone = 'warn';
    value = ['p= missing (treated as none)', m.record];
  } else if (m.p === 'none') {
    tone = 'warn';
  } else if (m.p === 'reject' || m.p === 'quarantine') {
    tone = m.pct !== undefined && m.pct < 100 ? undefined : 'good';
  } else {
    tone = 'warn';
  }
  const out: Fact[] = [{ label: 'DMARC', value, ...(tone ? { tone } : {}) }];
  if (m.rua?.length) out.push({ label: 'DMARC reports (rua)', value: m.rua });
  return out;
}

function capLabel(label: string, d: DnsData, key: CappedList): string {
  const total = d.totals?.[key];
  return total ? `${label} (${d[key].length} of ${total})` : label;
}

const RESOLVER_NAME: Record<DohResult['resolver'], string> = { cloudflare: 'Cloudflare', google: 'Google' };
const RESOLVER_ORDER: ReadonlyArray<DohResult['resolver']> = ['cloudflare', 'google'];

export const dnsModule: Module<DnsData> = {
  id: 'dns',
  label: 'DNS (DoH)',
  version: 1,
  accepts: ['domain'],
  ttl: 5 * MINUTE,
  // Current A/AAAA answers claim the per-domain IP cap before historical resolutions.
  primaryPivots: true,

  async run(e, ctx) {
    if (e.kind !== 'domain') throw new SkipError('DNS lookups apply to domains only.');
    const domain = stripDot(e.value);
    if (!domain) throw new SkipError('Empty domain.');

    const settled = await Promise.allSettled(
      LOOKUPS.map((l) => dohQuery(ctx, l.id === 'DMARC' ? `_dmarc.${domain}` : domain, l.type)),
    );

    const results: Partial<Record<DnsLookup, DohResult>> = {};
    const errors: Partial<Record<DnsLookup, string>> = {};
    let firstErr: unknown;
    for (let i = 0; i < LOOKUPS.length; i++) {
      const l = LOOKUPS[i]!;
      const s = settled[i]!;
      if (s.status === 'rejected') {
        if (isAbortError(s.reason)) throw s.reason;
        errors[l.id] = errMessage(s.reason);
        firstErr ??= s.reason;
        continue;
      }
      results[l.id] = s.value;
      // NOERROR and NXDOMAIN are answers; anything else (SERVFAIL from both resolvers, REFUSED...) is a failure.
      if (s.value.status !== 0 && s.value.status !== 3) {
        const c = s.value.comment ? `: ${s.value.comment}` : '';
        errors[l.id] = clip(`${rcodeName(s.value.status)}${c}`, MAX_ERR_LEN);
      }
    }
    if (ctx.signal.aborted) throw new FetchError('aborted', 'Cancelled', '');

    if (Object.keys(results).length === 0) {
      const msg = `All ${LOOKUPS.length} DNS lookups failed: ${errMessage(firstErr)}`;
      throw firstErr instanceof FetchError ? new FetchError(firstErr.kind, msg, firstErr.url, firstErr.status) : new Error(msg);
    }

    // Apex status: the first apex lookup with a real answer (NOERROR/NXDOMAIN), else the first that returned anything.
    const answered = APEX_ORDER.map((id) => results[id]).filter((r): r is DohResult => r !== undefined);
    const ref = answered.find((r) => r.status === 0 || r.status === 3) ?? answered[0];
    const apexStatus = ref ? rcodeName(ref.status) : 'UNKNOWN';
    const nx = apexStatus === 'NXDOMAIN';

    const totals: Partial<Record<CappedList, number>> = {};

    const mx = uniq(
      (results.MX ? recordsOf(results.MX, 'MX') : [])
        .map((r) => mxOf(r.data))
        .filter((m): m is NonNullable<typeof m> => m !== null && Number.isInteger(m.preference)),
      (m) => `${m.preference} ${m.exchange}`,
    ).sort((x, y) => x.preference - y.preference || x.exchange.localeCompare(y.exchange));

    const txtAll = uniq(txtValues(results.TXT));
    const spfs = txtAll.filter((t) => SPF_RE.test(t.trim()));

    const dmarcs = uniq(txtValues(results.DMARC))
      .map(parseDmarc)
      .filter((m): m is DmarcPolicy => m !== null);

    const caa = uniq(
      (results.CAA ? recordsOf(results.CAA, 'CAA') : [])
        .map((r) => parseCaa(r.data) ?? parseGenericCaa(r.data))
        .filter((c): c is CaaRecord => c !== null && Number.isInteger(c.flags))
        .map((c) => ({ flags: c.flags, tag: clip(c.tag, MAX_TAG_LEN), value: clip(c.value, MAX_TXT_LEN) })),
      (c) => `${c.flags} ${c.tag} ${c.value}`,
    );

    let soa: DnsData['soa'] = null;
    const soaRes = results.SOA;
    if (soaRes) {
      // Answer first; on NODATA (a name below the zone apex) the Authority SOA names the enclosing zone.
      // On NXDOMAIN the Authority SOA is the parent zone's (e.g. "com"), which says nothing about this domain.
      const rec =
        recordsOf(soaRes, 'SOA')[0] ??
        (soaRes.status === 0 ? soaRes.authority.find((r) => r.type === 6) : undefined);
      const parsed = rec ? parseSoa(rec.data) : null;
      if (rec && parsed) soa = { ...parsed, zone: rec.name };
    }

    const data: DnsData = {
      resolvers: RESOLVER_ORDER.filter((name) => LOOKUPS.some((l) => results[l.id]?.resolver === name)),
      apexStatus,
      dnssec: ref?.ad ?? false,
      a: capList(ips(results.A, 'A'), 'a', totals),
      aaaa: capList(ips(results.AAAA, 'AAAA'), 'aaaa', totals),
      cname: cnameChain(domain, results),
      ns: capList(
        uniq((results.NS ? recordsOf(results.NS, 'NS') : []).map((r) => stripDot(r.data)).filter(Boolean)).sort(),
        'ns',
        totals,
      ),
      mx: capList(mx, 'mx', totals),
      txt: capList(
        txtAll.map((t) => clip(t, MAX_TXT_LEN)),
        'txt',
        totals,
      ),
      soa,
      caa: capList(caa, 'caa', totals),
      spf: spfs[0] !== undefined ? clip(spfs[0].trim(), MAX_SPF_LEN) : null,
      spfCount: spfs.length,
      dmarc: dmarcs[0] ?? null,
      dmarcCount: dmarcs.length,
      errors,
      ...(Object.keys(totals).length ? { totals } : {}),
    };

    const pivots: Pivot[] = nx
      ? []
      : [
          ...data.a.map((value): Pivot => ({ kind: 'ip', value, note: 'A record' })),
          ...data.aaaa.map((value): Pivot => ({ kind: 'ip', value, note: 'AAAA record' })),
        ];

    return { data, summary: dnsSummary(data), ...(pivots.length ? { pivots } : {}) };
  },

  facts(d, e) {
    const domain = stripDot(e.value);
    const nx = d.apexStatus === 'NXDOMAIN';
    const f: Fact[] = [];

    if (d.apexStatus !== 'NOERROR') {
      const value = nx
        ? d.cname.length
          ? `NXDOMAIN: dangling CNAME, ${d.cname.at(-1)} does not exist (possible subdomain takeover)`
          : 'NXDOMAIN (domain does not resolve)'
        : d.apexStatus === 'UNKNOWN'
          ? 'unknown (every lookup at the domain failed)'
          : `${d.apexStatus} (resolvers could not resolve the domain)`;
      f.push({ label: 'Status', value, tone: nx && d.cname.length ? 'bad' : 'warn' });
    }
    if (d.cname.length) f.push({ label: 'CNAME chain', value: d.cname, pivot: true });
    if (d.a.length) f.push({ label: capLabel('A', d, 'a'), value: d.a, pivot: true });
    if (d.aaaa.length) f.push({ label: capLabel('AAAA', d, 'aaaa'), value: d.aaaa, pivot: true });
    if (d.ns.length) f.push({ label: capLabel('NS', d, 'ns'), value: d.ns, pivot: true });
    if (isNullMx(d)) {
      f.push({ label: 'MX', value: 'null MX (domain accepts no mail, RFC 7505)' });
    } else if (d.mx.length) {
      const hosts = d.mx.map((m) => m.exchange).filter(Boolean);
      f.push({ label: capLabel('MX (by preference)', d, 'mx'), value: hosts, pivot: true });
    }
    if (!nx) {
      f.push(spfFact(d));
      f.push(...dmarcFacts(d, domain));
    }
    if (d.txt.length) f.push({ label: capLabel('TXT', d, 'txt'), value: d.txt });
    if (d.caa.length) {
      f.push({
        label: capLabel('CAA', d, 'caa'),
        value: d.caa.map((c) => `${c.flags ? `${c.flags} ` : ''}${c.tag} ${c.value}`),
      });
    } else if (!nx && !d.errors.CAA) {
      // CAA is tree-climbing (RFC 8659): below the registered domain a parent's records still apply.
      const sub = domain.split('.').length > 2;
      f.push({ label: 'CAA', value: sub ? 'none at this name (a parent-domain CAA may still apply)' : 'none (any CA may issue)' });
    }
    if (d.soa) {
      const s = d.soa;
      f.push({
        label: s.zone && s.zone !== domain ? `SOA (zone ${s.zone})` : 'SOA',
        value: `${s.mname} (contact ${rnameToEmail(s.rname)}, serial ${s.serial})`,
      });
    }
    // AD on NXDOMAIN only proves the (signed) parent zone's denial, not that this domain is signed;
    // with no NOERROR/NXDOMAIN answer (e.g. SERVFAIL from a bogus signature) there is nothing to judge.
    if (d.apexStatus !== 'NOERROR' && !nx) {
      f.push({ label: 'DNSSEC', value: 'unknown (no answer to validate)' });
    } else if (!d.dnssec) {
      f.push({ label: 'DNSSEC', value: 'no (answer not DNSSEC-validated)' });
    } else if (nx) {
      f.push({ label: 'DNSSEC', value: 'non-existence proof validated (AD flag)' });
    } else {
      f.push({ label: 'DNSSEC', value: 'yes (resolver validated the answer, AD flag)', tone: 'good' });
    }
    if (d.resolvers.length) {
      f.push({
        label: 'Resolver',
        value: d.resolvers.map((r) => (r === 'google' && d.resolvers.length > 1 ? 'Google (fallback)' : RESOLVER_NAME[r])).join(', '),
      });
    }
    const errs = Object.entries(d.errors).filter((x): x is [string, string] => typeof x[1] === 'string');
    if (errs.length) {
      f.push({ label: 'Lookup errors', value: errs.map(([k, v]) => `${k}: ${v}`), tone: 'warn' });
    }
    return f;
  },
};
