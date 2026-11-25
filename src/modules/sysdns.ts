import { RCODE, dohQuery, recordsOf, stripDot, type DohResult } from '@/lib/doh';
import { ff, type DnsResolveFlag } from '@/lib/firefox';
import { isIPv4, isPublicIp, normalizeIp } from '@/lib/ip';
import type { Fact, Module } from '@/lib/types';
import { MINUTE, SkipError } from '@/lib/types';

/**
 * Module 2: "System resolver vs DoH" (optional, off by default).
 *
 * Resolves the domain with Firefox's browser.dns.resolve() (the OS / network
 * resolver, TRR disabled, cache bypassed) and compares the address set with
 * public DoH A/AAAA answers (memoised, so it shares the DNS module's lookups).
 * A difference points at local filtering (sinkholes), split-horizon DNS, or
 * just CDN/geo DNS, so the wording stays cautious.
 *
 * No pivots: system-only addresses can be internal and must never be sent to
 * third parties. See docs/research/firefox-platform.md section 4.
 */

export type SysDnsVerdict = 'match' | 'overlap' | 'mismatch' | 'blocked' | 'split-horizon';
/** ok: addresses returned; nxdomain: NS_ERROR_UNKNOWN_HOST; empty: resolved but no usable address. */
export type SystemStatus = 'ok' | 'nxdomain' | 'empty';
/** ok: addresses; nodata: NOERROR without A/AAAA; nxdomain: rcode 3; error: SERVFAIL/REFUSED/... */
export type DohStatus = 'ok' | 'nodata' | 'nxdomain' | 'error';
/** Address families compared. A system answer without IPv6 is compared on IPv4 only (and vice versa). */
export type ComparedFamilies = 'all' | 'ipv4' | 'ipv6';

export interface SystemAnswer {
  addresses: string[];
  /** The answer came from Firefox's own DoH (TRR), not the system resolver. */
  isTRR: boolean;
  status: SystemStatus;
}

export interface DohAnswer {
  a: string[];
  aaaa: string[];
  status: DohStatus;
  /** rcode name when status is 'error' (e.g. SERVFAIL). */
  rcode?: string;
}

export interface SysDnsData {
  system: SystemAnswer;
  doh: DohAnswer;
  onlySystem: string[];
  onlyDoh: string[];
  common: string[];
  compared: ComparedFamilies;
  /** Full sizes before lists were capped. */
  counts: { system: number; a: number; aaaa: number; common: number; onlySystem: number; onlyDoh: number };
  verdict: SysDnsVerdict;
  explanation: string;
}

export interface Comparison {
  verdict: SysDnsVerdict;
  explanation: string;
  summary: string;
  common: string[];
  onlySystem: string[];
  onlyDoh: string[];
  compared: ComparedFamilies;
}

/** Cap for every stored address list (full counts are kept in `counts`). */
export const MAX_ADDRESSES = 50;
const RESOLVE_FLAGS: readonly DnsResolveFlag[] = ['disable_trr', 'bypass_cache'];

const VERDICT_LABEL: Readonly<Record<SysDnsVerdict, string>> = {
  match: 'Match',
  overlap: 'Overlap',
  mismatch: 'Mismatch',
  blocked: 'Blocked',
  'split-horizon': 'Split-horizon',
};

const VERDICT_TONE: Readonly<Record<SysDnsVerdict, Fact['tone']>> = {
  match: 'good',
  overlap: undefined,
  mismatch: 'warn',
  blocked: 'warn',
  'split-horizon': 'warn',
};

// ---------------------------------------------------------------------------
// helpers

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (err && typeof err === 'object') {
    const m = (err as { message?: unknown }).message;
    if (typeof m === 'string') return m;
  }
  return typeof err === 'string' ? err : '';
}

/** Canonical, de-duplicated IPs; drops anything that is not an address (and IPv6 zone ids). */
function uniqIps(raw: readonly unknown[]): string[] {
  const seen = new Set<string>();
  for (const v of raw) {
    if (typeof v !== 'string') continue;
    const ip = normalizeIp(v.replace(/%.*$/, ''));
    if (ip) seen.add(ip);
  }
  return [...seen];
}

const isV6 = (ip: string): boolean => !isIPv4(ip);

/** Unspecified or loopback: what DNS sinkholes (Pi-hole, AdGuard, hosts-file blockers) answer. */
export function isSinkhole(ip: string): boolean {
  const n = normalizeIp(ip);
  if (!n) return false;
  if (isIPv4(n)) {
    const first = Number(n.split('.')[0]);
    return first === 0 || first === 127;
  }
  return n === '::' || n === '::1';
}

/**
 * IPv4 address embedded in an RFC 6052 well-known-prefix NAT64 address
 * (64:ff9b::/96, synthesised by DNS64 on IPv6-only networks), else null.
 * Expects the canonical form from normalizeIp.
 */
export function nat64Embedded(ip: string): string | null {
  const m = /^64:ff9b::(?:([0-9a-f]{1,4}):)?([0-9a-f]{1,4})?$/.exec(ip);
  if (!m) return null;
  const hi = parseInt(m[1] ?? '0', 16);
  const lo = parseInt(m[2] ?? '0', 16);
  return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
}

/** Stop waiting for `p` when the run is cancelled (browser.dns.resolve itself cannot be aborted). */
function untilAborted<T>(p: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new DOMException('Aborted', 'AbortError'));
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(new DOMException('Aborted', 'AbortError'));
    signal.addEventListener('abort', onAbort, { once: true });
    p.then(
      (v) => {
        signal.removeEventListener('abort', onAbort);
        resolve(v);
      },
      (err: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(err);
      },
    );
  });
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** "a, b, c and 2 more" for explanations. */
function listText(list: readonly string[], max = 4): string {
  if (list.length <= max) return list.join(', ');
  return `${list.slice(0, max).join(', ')} and ${list.length - max} more`;
}

/** "a" or "a +2" for one-line summaries. */
function short(list: readonly string[]): string {
  const first = list[0] ?? '';
  return list.length > 1 ? `${first} +${list.length - 1}` : first;
}

function cap(list: readonly string[]): string[] {
  return list.slice(0, MAX_ADDRESSES);
}

// ---------------------------------------------------------------------------
// lookups

/**
 * Firefox's resolver with TRR disabled and the cache bypassed. NS_ERROR_UNKNOWN_HOST
 * is an answer (status 'nxdomain'), every other rejection is a failure.
 */
export async function systemLookup(host: string): Promise<SystemAnswer> {
  let rec: unknown;
  try {
    rec = await ff.dns.resolve(host, [...RESOLVE_FLAGS]);
  } catch (err) {
    const msg = errorMessage(err);
    if (/\bNS_ERROR_UNKNOWN_HOST\b/.test(msg)) return { addresses: [], isTRR: false, status: 'nxdomain' };
    throw new Error(`System resolver failed: ${msg || 'unknown error'}`);
  }
  if (!rec || typeof rec !== 'object' || !Array.isArray((rec as { addresses?: unknown }).addresses)) {
    throw new Error('Unexpected answer from browser.dns.resolve()');
  }
  const r = rec as { addresses: unknown[]; isTRR?: unknown };
  const addresses = uniqIps(r.addresses);
  const isTRR =
    r.isTRR === true || (typeof r.isTRR === 'string' && r.isTRR !== '' && r.isTRR.toLowerCase() !== 'false');
  return { addresses, isTRR, status: addresses.length > 0 ? 'ok' : 'empty' };
}

/** Collapse the DoH A and AAAA results (CNAME chains are skipped by type). */
export function dohAnswer(a: DohResult, aaaa: DohResult): DohAnswer {
  const v4 = uniqIps(recordsOf(a, 'A').map((r) => r.data)).filter(isIPv4);
  const v6 = uniqIps(recordsOf(aaaa, 'AAAA').map((r) => r.data)).filter(isV6);
  if (v4.length > 0 || v6.length > 0) return { a: v4, aaaa: v6, status: 'ok' };
  if (a.status === 3 || aaaa.status === 3) return { a: v4, aaaa: v6, status: 'nxdomain' };
  if (a.status === 0 && aaaa.status === 0) return { a: v4, aaaa: v6, status: 'nodata' };
  const bad = a.status !== 0 ? a.status : aaaa.status;
  return { a: v4, aaaa: v6, status: 'error', rcode: RCODE[bad] ?? `RCODE ${bad}` };
}

// ---------------------------------------------------------------------------
// classification

/**
 * Pure comparison of the two answers. Order of checks:
 * match -> system has nothing -> system sinkholes -> public has nothing ->
 * system-only private addresses -> overlap -> mismatch.
 */
export function compareAnswers(sys: SystemAnswer, doh: DohAnswer): Comparison {
  // DNS64 (IPv6-only networks) answers 64:ff9b::<IPv4>: compare the embedded IPv4.
  const key = (ip: string): string => (doh.aaaa.includes(ip) ? ip : (nat64Embedded(ip) ?? ip));
  const sysKeys = sys.addresses.map(key);
  const nat64 = sys.addresses.some((ip, i) => sysKeys[i] !== ip);
  const sysV4 = sysKeys.some(isIPv4);
  const sysV6 = sysKeys.some(isV6);
  let compared: ComparedFamilies = 'all';
  if (sys.addresses.length > 0 && doh.a.length > 0 && doh.aaaa.length > 0) {
    if (!sysV6) compared = 'ipv4';
    else if (!sysV4) compared = 'ipv6';
  }
  const dohCmp = compared === 'ipv4' ? doh.a : compared === 'ipv6' ? doh.aaaa : [...doh.a, ...doh.aaaa];

  const sysSet = new Set(sysKeys);
  const dohSet = new Set(dohCmp);
  const common = sys.addresses.filter((ip) => dohSet.has(key(ip)));
  const onlySystem = sys.addresses.filter((ip) => !dohSet.has(key(ip)));
  const onlyDoh = dohCmp.filter((ip) => !sysSet.has(ip));
  const dohPublic = dohCmp.filter(isPublicIp);

  const who = sys.isTRR ? "Firefox's own DoH (TRR)" : 'The system resolver';
  const whoLc = sys.isTRR ? "Firefox's own DoH (TRR)" : 'the system resolver';
  const tag = sys.isTRR ? 'TRR' : 'system';
  const sysNone = sys.status === 'nxdomain' ? 'NXDOMAIN' : 'no address';
  const dohNone =
    doh.status === 'nxdomain'
      ? 'says the name does not exist (NXDOMAIN)'
      : doh.status === 'error'
        ? `fails (${doh.rcode ?? 'error'})`
        : 'has no address for it';

  const result = (verdict: SysDnsVerdict, explanation: string, summary: string): Comparison => {
    let exp = explanation;
    if (sys.isTRR) {
      exp =
        'Firefox answered through its own DNS-over-HTTPS (TRR) even with TRR disabled for this lookup ' +
        '(possibly DoH-only mode), so this compares two DoH services, not your system resolver. ' +
        exp;
    }
    if (nat64) {
      exp += ' NAT64 addresses (64:ff9b::/96, from DNS64 on an IPv6-only network) were compared as the IPv4 addresses they embed.';
    }
    if (compared === 'ipv4') {
      exp += ' IPv6 not compared: the system resolver returned no IPv6 addresses (normal without IPv6 connectivity).';
    } else if (compared === 'ipv6') {
      exp += ' IPv4 not compared: the system resolver returned only IPv6 addresses.';
    }
    return {
      verdict,
      explanation: exp,
      summary: sys.isTRR ? `${summary} · via Firefox TRR` : summary,
      common,
      onlySystem,
      onlyDoh,
      compared,
    };
  };

  // 1. Same address sets (including "neither has one").
  if (onlySystem.length === 0 && onlyDoh.length === 0) {
    if (sys.addresses.length === 0) {
      if (sys.status === 'nxdomain' && doh.status === 'nxdomain') {
        return result('match', 'Neither resolver knows this name (NXDOMAIN on both).', 'Match: NXDOMAIN on both');
      }
      return result(
        'match',
        `Neither resolver returns an address (${tag}: ${sysNone}; public DoH ${dohNone}).`,
        'Match: no address on either',
      );
    }
    const n = sys.addresses.length;
    return result(
      'match',
      `Both resolvers return the same ${plural(n, 'address', 'addresses')}: no sign of local DNS filtering or split-horizon DNS.`,
      `Match (${plural(n, 'address', 'addresses')})`,
    );
  }

  // 2. The system has no answer while public DNS does.
  if (sys.addresses.length === 0) {
    if (dohPublic.length > 0) {
      const mode3 = sys.isTRR
        ? ''
        : ' If Firefox is set to DoH-only mode (TRR mode 3), lookups that bypass TRR can also fail like this.';
      const transient =
        sys.status === 'nxdomain'
          ? ' Firefox reports NXDOMAIN, empty answers and failed lookups alike (NS_ERROR_UNKNOWN_HOST), so re-run to rule out a transient resolver failure.'
          : '';
      return result(
        'blocked',
        `${who} returns ${sysNone} while public DNS resolves it to ${listText(dohCmp)}. ` +
          'Likely blocked by local DNS filtering (Pi-hole/AdGuard, corporate or ISP filter, security software).' +
          transient +
          mode3,
        `Blocked: ${tag} ${sysNone}, DoH resolves (local filtering?)`,
      );
    }
    return result(
      'mismatch',
      `${who} returns ${sysNone} while public DNS returns only non-public addresses (${listText(dohCmp)}). ` +
        'Some local resolvers drop private answers for public names (DNS-rebinding protection).',
      `Mismatch: ${tag} ${sysNone}, DoH only private ${short(dohCmp)}`,
    );
  }

  // 3. Sinkhole answers (0.0.0.0, ::, 127.x, ::1).
  if (sys.addresses.every(isSinkhole)) {
    const pub = dohCmp.length > 0 ? `resolves it to ${listText(dohCmp)}` : dohNone;
    return result(
      'blocked',
      `${who} returns ${listText(sys.addresses)} (${sys.addresses.length === 1 ? 'a sinkhole address' : 'sinkhole addresses'}) while public DNS ${pub}. ` +
        'Typical of DNS-based blocking (Pi-hole/AdGuard, hosts file, corporate or ISP filter).',
      `Blocked: ${tag} returns ${short(sys.addresses)} (local filtering?)`,
    );
  }

  // 4. The system answers while public DNS has nothing comparable.
  if (dohCmp.length === 0) {
    if (doh.status === 'error') {
      return result(
        'mismatch',
        `Public DoH ${dohNone} while ${whoLc} resolves it to ${listText(sys.addresses)}. ` +
          'Often a DNSSEC validation failure that a non-validating local resolver ignores.',
        `Mismatch: public DoH ${doh.rcode ?? 'error'}, ${tag} returns ${short(sys.addresses)}`,
      );
    }
    const hijack =
      doh.status === 'nxdomain' && sys.addresses.some((ip) => isPublicIp(key(ip)))
        ? ' Public addresses can also mean the resolver redirects non-existent names to a search or ad page (NXDOMAIN hijacking).'
        : '';
    return result(
      'split-horizon',
      `${who} resolves it to ${listText(sys.addresses)} but public DNS ${dohNone}. ` +
        'Typical of an internal-only name (split-horizon DNS) or a local hosts-file/override entry.' +
        hijack,
      `Mismatch: ${tag} returns ${short(sys.addresses)}, public ${doh.status === 'nxdomain' ? 'NXDOMAIN' : 'no address'} (split-horizon?)`,
    );
  }

  // 5. System-only private addresses while public DNS has public ones.
  const sysOnlyPrivate = onlySystem.filter((ip) => !isPublicIp(key(ip)) && !isSinkhole(ip));
  if (sysOnlyPrivate.length > 0 && dohPublic.length > 0) {
    return result(
      'split-horizon',
      `${who} returns private ${sysOnlyPrivate.length === 1 ? 'address' : 'addresses'} ${listText(sysOnlyPrivate)} ` +
        `that public DNS does not (public: ${listText(dohCmp)}). Typical of split-horizon (internal) DNS; ` +
        'a filtering resolver redirecting to a local block page looks the same.',
      `Mismatch: ${tag} returns ${short(sysOnlyPrivate)} (split-horizon?)`,
    );
  }

  // 6. Partial overlap: usually CDN / geo DNS.
  if (common.length > 0) {
    return result(
      'overlap',
      `${plural(common.length, 'address', 'addresses')} in common; ${onlySystem.length} only from ${whoLc}, ` +
        `${onlyDoh.length} only from public DoH. Usually CDN or geo-DNS load balancing (resolvers in different places ` +
        'get different subsets), not necessarily tampering.',
      `Overlap: ${common.length} common, ${onlySystem.length} ${tag}-only (CDN/geo DNS?)`,
    );
  }

  // 7. Disjoint answers.
  return result(
    'mismatch',
    `No address in common: ${whoLc} returns ${listText(onlySystem)}, ` +
      `public DoH ${listText(onlyDoh)}. Large CDNs and geo DNS can do this; for a site without a CDN it may ` +
      "indicate DNS interception or hijacking, or a filtering resolver's block page.",
    `Mismatch: ${tag} returns ${short(onlySystem)}, DoH ${short(onlyDoh)}`,
  );
}

// ---------------------------------------------------------------------------
// facts

function addrValue(list: readonly string[], total: number, empty: string): string | string[] {
  if (list.length === 0) return empty;
  return total > list.length ? [...list, `(+${total - list.length} more not shown)`] : [...list];
}

function dohEmpty(doh: DohAnswer): string {
  switch (doh.status) {
    case 'nxdomain':
      return 'NXDOMAIN';
    case 'error':
      return doh.rcode ?? 'error';
    default:
      return 'no records';
  }
}

function buildFacts(d: SysDnsData): Fact[] {
  const tone = VERDICT_TONE[d.verdict];
  const facts: Fact[] = [
    { label: 'Verdict', value: VERDICT_LABEL[d.verdict] ?? d.verdict, ...(tone ? { tone } : {}) },
    { label: 'Explanation', value: d.explanation },
  ];
  if (d.system.isTRR) {
    facts.push({ label: 'Answered by', value: 'Firefox DoH (TRR), not the system resolver', tone: 'warn' });
  }
  const sysEmpty = d.system.status === 'nxdomain' ? 'NXDOMAIN' : 'no addresses';
  facts.push({
    label: d.system.isTRR ? 'Firefox (TRR)' : 'System resolver',
    value: addrValue(d.system.addresses, d.counts.system, sysEmpty),
    ...(d.system.addresses.length > 0 ? { pivot: true } : {}),
  });
  const empty = dohEmpty(d.doh);
  facts.push({
    label: 'Public DoH A',
    value: addrValue(d.doh.a, d.counts.a, empty),
    ...(d.doh.a.length > 0 ? { pivot: true } : {}),
  });
  facts.push({
    label: 'Public DoH AAAA',
    value: addrValue(d.doh.aaaa, d.counts.aaaa, empty),
    ...(d.doh.aaaa.length > 0 ? { pivot: true } : {}),
  });
  if (d.verdict !== 'match') {
    if (d.common.length > 0) {
      facts.push({ label: 'Common', value: addrValue(d.common, d.counts.common, ''), pivot: true });
    }
    if (d.onlySystem.length > 0) {
      facts.push({
        label: d.system.isTRR ? 'Only TRR' : 'Only system',
        value: addrValue(d.onlySystem, d.counts.onlySystem, ''),
        pivot: true,
      });
    }
    if (d.onlyDoh.length > 0) {
      facts.push({ label: 'Only public DoH', value: addrValue(d.onlyDoh, d.counts.onlyDoh, ''), pivot: true });
    }
  }
  if (d.compared !== 'all') {
    facts.push({
      label: 'Compared',
      value: d.compared === 'ipv4' ? 'IPv4 only (system returned no IPv6)' : 'IPv6 only (system returned no IPv4)',
    });
  }
  return facts;
}

// ---------------------------------------------------------------------------
// module

export const sysdnsModule: Module<SysDnsData> = {
  id: 'sysdns',
  label: 'System resolver vs DoH',
  version: 1,
  accepts: ['domain'],
  ttl: 5 * MINUTE,
  defaultEnabled: false,
  note:
    "Uses your own network's DNS resolver (router, ISP or corporate DNS), which sees the lookup; the domain's nameservers may see a query from that resolver.",

  async run(e, ctx) {
    if (typeof ff?.dns?.resolve !== 'function') {
      throw new SkipError('Firefox DNS API unavailable (needs Firefox and the "dns" permission).');
    }
    const host = stripDot(e.value);
    if (!host) throw new SkipError('Empty domain.');
    const [sys, a, aaaa] = await Promise.all([
      untilAborted(systemLookup(host), ctx.signal),
      dohQuery(ctx, host, 'A'),
      dohQuery(ctx, host, 'AAAA'),
    ]);
    const doh = dohAnswer(a, aaaa);
    const cmp = compareAnswers(sys, doh);

    const data: SysDnsData = {
      system: { addresses: cap(sys.addresses), isTRR: sys.isTRR, status: sys.status },
      doh: {
        a: cap(doh.a),
        aaaa: cap(doh.aaaa),
        status: doh.status,
        ...(doh.rcode !== undefined ? { rcode: doh.rcode } : {}),
      },
      onlySystem: cap(cmp.onlySystem),
      onlyDoh: cap(cmp.onlyDoh),
      common: cap(cmp.common),
      compared: cmp.compared,
      counts: {
        system: sys.addresses.length,
        a: doh.a.length,
        aaaa: doh.aaaa.length,
        common: cmp.common.length,
        onlySystem: cmp.onlySystem.length,
        onlyDoh: cmp.onlyDoh.length,
      },
      verdict: cmp.verdict,
      explanation: cmp.explanation,
    };
    // No pivots: system-only addresses may be internal and must not reach third parties.
    return { data, summary: cmp.summary, severity: 'none' };
  },

  facts: (d) => buildFacts(d),
};
