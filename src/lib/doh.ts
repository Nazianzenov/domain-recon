import { FetchError } from './http';
import type { Ctx } from './types';

/**
 * DNS-over-HTTPS JSON client shared by the DNS, M365, email-provider and
 * system-resolver modules. Cloudflare first, Google as fallback; results are
 * memoised per investigation so modules never repeat a lookup.
 *
 * Provider quirks handled here (see docs/research/dns-rdap.md):
 * - Cloudflare requires `accept: application/dns-json` (400 otherwise).
 * - Cloudflare returns TXT as quoted character-strings ("a" "b"); Google
 *   returns them unquoted and already concatenated.
 * - Google suffixes names with a dot; Cloudflare echoes the query name.
 * - A dangling CNAME yields Status 3 (NXDOMAIN) with the CNAME in Answer.
 */

export const RR = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, CAA: 257 } as const;
export type RRType = keyof typeof RR;

export const RCODE: Readonly<Record<number, string>> = {
  0: 'NOERROR',
  1: 'FORMERR',
  2: 'SERVFAIL',
  3: 'NXDOMAIN',
  4: 'NOTIMP',
  5: 'REFUSED',
};

export interface DohRecord {
  /** Owner name, lowercase, no trailing dot. */
  name: string;
  type: number;
  ttl: number;
  /** Raw presentation data; for TXT this is already unquoted and joined. Target names have no trailing dot. */
  data: string;
}

export interface DohResult {
  name: string;
  type: RRType;
  /** DNS rcode (0 NOERROR, 3 NXDOMAIN...). */
  status: number;
  answers: DohRecord[];
  authority: DohRecord[];
  resolver: 'cloudflare' | 'google';
  /** DNSSEC-validated (AD bit). */
  ad: boolean;
  comment?: string;
}

interface RawRecord {
  name?: unknown;
  type?: unknown;
  TTL?: unknown;
  data?: unknown;
}

interface RawDoh {
  Status?: unknown;
  AD?: unknown;
  Answer?: unknown;
  Authority?: unknown;
  Comment?: unknown;
}

export function stripDot(s: string): string {
  return s.trim().replace(/\.$/, '').toLowerCase();
}

/**
 * TXT data -> single string. Accepts Cloudflare's quoted chunks
 * (`"v=spf1 include:servers." "mcsv.net ~all"`, joined with no separator per
 * RFC 7208 §3.3, with \" \\ and \DDD escapes) and Google's unquoted form.
 */
export function parseTxt(data: string): string {
  const s = data.trim();
  if (!s.startsWith('"')) return s;
  let out = '';
  // \DDD escapes are octets (RFC 1035 §5.1): collect runs and UTF-8-decode them.
  // Not flushed at chunk boundaries: a 255-byte split can fall inside a UTF-8 sequence.
  let bytes: number[] = [];
  const flush = () => {
    if (bytes.length) {
      out += new TextDecoder().decode(new Uint8Array(bytes));
      bytes = [];
    }
  };
  let i = 0;
  while (i < s.length) {
    if (s[i] !== '"') {
      i++;
      continue;
    }
    i++; // opening quote
    while (i < s.length && s[i] !== '"') {
      if (s[i] === '\\' && i + 1 < s.length) {
        const ddd = /^\d{3}/.exec(s.slice(i + 1, i + 4));
        if (ddd) {
          bytes.push(Number(ddd[0]) & 0xff);
          i += 4;
        } else {
          flush();
          out += s[i + 1];
          i += 2;
        }
        continue;
      }
      flush();
      out += s[i];
      i++;
    }
    i++; // closing quote
  }
  flush();
  return out;
}

export function parseMx(data: string): { preference: number; exchange: string } | null {
  const m = /^(\d+)\s+(\S+)$/.exec(data.trim());
  return m ? { preference: Number(m[1]), exchange: stripDot(m[2]!) } : null;
}

export interface Soa {
  mname: string;
  rname: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  minimum: number;
}

export function parseSoa(data: string): Soa | null {
  const p = data.trim().split(/\s+/);
  if (p.length < 7) return null;
  const n = p.slice(2, 7).map(Number);
  if (n.some((x) => !Number.isFinite(x))) return null;
  return {
    mname: stripDot(p[0]!),
    rname: stripDot(p[1]!),
    serial: n[0]!,
    refresh: n[1]!,
    retry: n[2]!,
    expire: n[3]!,
    minimum: n[4]!,
  };
}

export function parseCaa(data: string): { flags: number; tag: string; value: string } | null {
  const m = /^(\d+)\s+([a-z0-9]+)\s+(.*)$/i.exec(data.trim());
  if (!m) return null;
  return { flags: Number(m[1]), tag: m[2]!.toLowerCase(), value: parseTxt(m[3]!) };
}

function normRecords(raw: unknown): DohRecord[] {
  if (!Array.isArray(raw)) return [];
  const out: DohRecord[] = [];
  for (const r of raw as RawRecord[]) {
    if (!r || typeof r.name !== 'string' || typeof r.type !== 'number' || typeof r.data !== 'string') continue;
    const type = r.type;
    let data = r.data;
    if (type === RR.TXT) data = parseTxt(data);
    else if (type === RR.CNAME || type === RR.NS) data = stripDot(data);
    else if (type === RR.MX) {
      const mx = parseMx(data);
      // Null MX (RFC 7505) is "0 ." -> keep the dot so the value stays re-parseable.
      if (mx) data = `${mx.preference} ${mx.exchange || '.'}`;
    }
    out.push({ name: stripDot(r.name), type, ttl: typeof r.TTL === 'number' ? r.TTL : 0, data });
  }
  return out;
}

/** Parse a Cloudflare/Google JSON body into a DohResult. Throws FetchError('parse') on junk. */
export function parseDohJson(json: unknown, name: string, type: RRType, resolver: DohResult['resolver'], url = ''): DohResult {
  if (!json || typeof json !== 'object' || typeof (json as RawDoh).Status !== 'number') {
    throw new FetchError('parse', `Unexpected DoH response from ${resolver}`, url);
  }
  const j = json as RawDoh;
  const comment = Array.isArray(j.Comment)
    ? j.Comment.filter((c): c is string => typeof c === 'string').join('; ')
    : typeof j.Comment === 'string'
      ? j.Comment
      : undefined;
  return {
    name: stripDot(name),
    type,
    status: j.Status as number,
    answers: normRecords(j.Answer),
    authority: normRecords(j.Authority),
    resolver,
    ad: j.AD === true,
    ...(comment ? { comment } : {}),
  };
}

const ENDPOINTS: ReadonlyArray<{ resolver: DohResult['resolver']; url: (n: string, t: RRType) => string; accept: string }> = [
  {
    resolver: 'cloudflare',
    url: (n, t) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}`,
    accept: 'application/dns-json',
  },
  {
    resolver: 'google',
    // OPSEC: Google forwards an approximate client subnet (ECS) to the target's
    // authoritative nameservers by default; 0.0.0.0/0 disables it.
    url: (n, t) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}&edns_client_subnet=0.0.0.0/0`,
    accept: 'application/json',
  },
];

/**
 * Resolve `name`/`type` via DoH. Falls back to Google when Cloudflare fails
 * at the transport level or answers SERVFAIL. Memoised per investigation.
 * `name` must be ASCII (punycode).
 */
export function dohQuery(ctx: Pick<Ctx, 'fetchJson' | 'shared'>, name: string, type: RRType): Promise<DohResult> {
  const n = stripDot(name);
  return ctx.shared.memo(`doh:${type}:${n}`, async () => {
    let lastErr: unknown;
    let servfail: DohResult | undefined;
    for (const ep of ENDPOINTS) {
      const url = ep.url(n, type);
      try {
        const res = await ctx.fetchJson<unknown>(url, { headers: { accept: ep.accept }, rateLimit: false });
        const parsed = parseDohJson(res.data, n, type, ep.resolver, url);
        if (parsed.status === 2 && ep.resolver === 'cloudflare') {
          servfail = parsed; // try Google, but keep this answer (and its EDE comment) if Google fails
          continue;
        }
        return parsed;
      } catch (err) {
        if (err instanceof FetchError && err.kind === 'aborted') throw err;
        lastErr = err;
      }
    }
    if (servfail) return servfail;
    throw lastErr instanceof Error ? lastErr : new Error('DoH lookup failed');
  });
}

/** Records of one type from the Answer section (CNAME chains are skipped unless asked for). */
export function recordsOf(res: DohResult, type: RRType): DohRecord[] {
  return res.answers.filter((r) => r.type === RR[type]);
}

/** Values of one type from the Answer section. */
export function valuesOf(res: DohResult, type: RRType): string[] {
  return recordsOf(res, type).map((r) => r.data);
}
