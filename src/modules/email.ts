import { RCODE, dohQuery, parseMx, recordsOf, stripDot, valuesOf } from '@/lib/doh';
import type { DohResult, RRType } from '@/lib/doh';
import { detectProviders, formatSpfTerm, selectorsToQuery, spfIncludes } from '@/lib/email-signatures';
import type { AccountId, DkimEvidence, EvidenceHit, ProviderHit, SpfTerm } from '@/lib/email-signatures';
import { isAbortError } from '@/lib/http';
import type { Fact, Module, Pivot } from '@/lib/types';
import { HOUR, MINUTE, SkipError } from '@/lib/types';

export interface EmailData {
  providers: ProviderHit[];
  accountIds: AccountId[];
  /** Apex SPF record (first one if several; capped). */
  spf: string | null;
  /** Top-level include:/redirect= terms (not expanded). */
  spfIncludes: SpfTerm[];
  /** MX exchanges by preference (null MX dropped). */
  mx: string[];
  /** Selectors where a CNAME or DKIM key TXT was found (TXT values capped; wildcard answers excluded). */
  dkim: DkimEvidence[];
  queriedSelectors: number;
  /** CNAME target returned for many selectors at once: a wildcard record, not DKIM evidence. */
  dkimWildcard?: string;
  /** Apex lookups that failed, so SPF/verification TXT or MX are unknown (not absent). */
  unresolved?: Array<'TXT' | 'MX'>;
  /** Lookups that failed (transport error or SERVFAIL); absent when all succeeded. Bounded by the selector table. */
  failedLookups?: string[];
}

const MAX_SPF = 1000;
const MAX_TXT = 120;
const MAX_SUMMARY = 4;
/** No provider points several distinct selectors at one host, so 3+ identical targets mean a wildcard. */
const WILDCARD_MIN = 3;

const cap = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const isSpf = (t: string): boolean => /^v=spf1(?:\s|$)/i.test(t.trim());
const isDkimKey = (t: string): boolean => /^\s*v=dkim1\b|(?:^|;)\s*p=/i.test(t);
const errMsg = (err: unknown): string => (err instanceof Error ? err.message : String(err));

/** First CNAME target for `name` (DoH may also list chain records). */
function cnameOf(res: DohResult | null, name: string): string | undefined {
  if (!res) return undefined;
  const recs = recordsOf(res, 'CNAME');
  return (recs.find((r) => r.name === name) ?? recs[0])?.data || undefined;
}

/**
 * The DKIM key TXT at a selector, if any. Other TXT values (e.g. a wildcard
 * `*.domain TXT "v=spf1 -all"`) are not DKIM selectors.
 */
function dkimTxtOf(res: DohResult | null): string | undefined {
  if (!res) return undefined;
  return valuesOf(res, 'TXT').find(isDkimKey);
}

/** A CNAME target shared by WILDCARD_MIN+ selectors (`*.domain` or `*._domainkey.domain`). */
function wildcardTarget(dkim: DkimEvidence[]): string | undefined {
  const n = new Map<string, number>();
  for (const d of dkim) if (d.cname) n.set(d.cname, (n.get(d.cname) ?? 0) + 1);
  for (const [target, count] of n) if (count >= WILDCARD_MIN) return target;
  return undefined;
}

function evidenceLine(h: EvidenceHit): string {
  const note = h.note ? ` (${h.note})` : '';
  switch (h.type) {
    case 'spf':
      return `SPF ${h.value}${note}`;
    case 'mx':
      return `MX ${h.value}${note}`;
    case 'txt':
      return `TXT ${h.value}${note}`;
    case 'dkim':
      return h.record === 'TXT'
        ? `DKIM ${h.name}._domainkey TXT ${h.value}${note}`
        : `DKIM ${h.name}._domainkey → ${h.value}${note}`;
  }
}

/** One-liner for the collapsed card. Exported for tests. */
export function summaryOf(d: EmailData): string {
  const nFailed = d.failedLookups?.length ?? 0;
  const failed = nFailed ? ` · ${nFailed} lookup${nFailed === 1 ? '' : 's'} failed` : '';
  if (d.providers.length === 0) return `No known sending providers${failed}`;
  const parts = d.providers.slice(0, MAX_SUMMARY).map((p) => {
    const ids = d.accountIds.filter((a) => a.provider === p.provider && a.summary).map((a) => a.value);
    const name = p.confidence === 'low' ? `${p.provider}?` : p.provider;
    return ids.length ? `${name} (${ids.join(', ')})` : name;
  });
  const more = d.providers.length - MAX_SUMMARY;
  return parts.join(' · ') + (more > 0 ? ` · +${more} more` : '') + failed;
}

/**
 * Module 6: email-sending providers from apex SPF/TXT/MX and DKIM CNAME/TXT at
 * well-known selectors, matched against the data-driven signature table.
 * Passive: only DoH resolvers are contacted.
 */
export const emailModule: Module<EmailData> = {
  id: 'email',
  label: 'Email-sending providers',
  version: 1,
  accepts: ['domain'],
  ttl: 24 * HOUR,

  async run(e, ctx) {
    if (e.kind !== 'domain') throw new SkipError('Email providers apply to domains only.');
    const domain = stripDot(e.value);
    const selectors = selectorsToQuery();

    const failed: string[] = [];
    let firstErr: unknown;
    let abortErr: unknown;
    let total = 0;
    const look = async (name: string, type: RRType): Promise<DohResult | null> => {
      total++;
      try {
        const res = await dohQuery(ctx, name, type);
        if (res.status !== 0 && res.status !== 3) {
          failed.push(`${type} ${name}: ${RCODE[res.status] ?? `rcode ${res.status}`}`);
          firstErr ??= new Error(`DNS ${type} ${name}: ${RCODE[res.status] ?? `rcode ${res.status}`}`);
          return null;
        }
        return res;
      } catch (err) {
        if (isAbortError(err)) abortErr ??= err;
        else {
          failed.push(`${type} ${name}: ${errMsg(err)}`);
          firstErr ??= err;
        }
        return null;
      }
    };

    const [txtRes, mxRes, selRes] = await Promise.all([
      look(domain, 'TXT'),
      look(domain, 'MX'),
      Promise.all(
        selectors.map(async ({ selector, txt }) => {
          const name = `${selector}._domainkey.${domain}`;
          const [c, t] = await Promise.all([look(name, 'CNAME'), txt ? look(name, 'TXT') : Promise.resolve(null)]);
          return { selector, name, c, t };
        }),
      ),
    ]);

    if (abortErr !== undefined || ctx.signal.aborted) throw abortErr ?? new DOMException('Aborted', 'AbortError');
    if (failed.length === total) throw firstErr instanceof Error ? firstErr : new Error('All DNS lookups failed');
    if (txtRes?.status === 3 || mxRes?.status === 3) throw new SkipError(`${domain} does not resolve (NXDOMAIN).`);
    const unresolved: Array<'TXT' | 'MX'> = [...(txtRes ? [] : ['TXT' as const]), ...(mxRes ? [] : ['MX' as const])];

    const txt = txtRes ? valuesOf(txtRes, 'TXT') : [];
    const spf = txt.find(isSpf) ?? null;
    const mx = (mxRes ? recordsOf(mxRes, 'MX') : [])
      .map((r) => parseMx(r.data))
      .filter((m): m is NonNullable<typeof m> => m !== null && m.exchange !== '')
      .sort((a, b) => a.preference - b.preference)
      .map((m) => m.exchange)
      .filter((h, i, a) => a.indexOf(h) === i);

    const found: DkimEvidence[] = [];
    for (const { selector, name, c, t } of selRes) {
      const cname = cnameOf(c, name) ?? cnameOf(t, name);
      const key = dkimTxtOf(t);
      if (cname || key) found.push({ selector, ...(cname ? { cname } : {}), ...(key ? { txt: key } : {}) });
    }
    // A wildcard answers every selector we guess: drop those answers instead of reporting them as DKIM setups.
    const dkimWildcard = wildcardTarget(found);
    const dkim = dkimWildcard ? found.filter((d) => d.cname !== dkimWildcard) : found;

    const det = detectProviders({ spf, txt, mx, dkim });

    const data: EmailData = {
      providers: det.providers,
      accountIds: det.accountIds,
      spf: spf ? cap(spf, MAX_SPF) : null,
      spfIncludes: spfIncludes(spf),
      mx,
      dkim: dkim.map((d) => ({ ...d, ...(d.txt ? { txt: cap(d.txt, MAX_TXT) } : {}) })),
      queriedSelectors: selectors.length,
      ...(dkimWildcard ? { dkimWildcard } : {}),
      ...(unresolved.length ? { unresolved } : {}),
      ...(failed.length ? { failedLookups: failed } : {}),
    };

    const pivots: Pivot[] = [];
    for (const a of det.accountIds) {
      if (a.pivot === 'domain' && !pivots.some((p) => p.value === a.value)) {
        pivots.push({ kind: 'domain', value: a.value, note: `${a.provider} ${a.kind}` });
      }
    }

    return {
      data,
      summary: summaryOf(data),
      ...(pivots.length ? { pivots } : {}),
      // Some DNS lookups failed: retry soon instead of caching a partial picture for 24 h.
      ...(data.failedLookups?.length ? { ttl: 10 * MINUTE } : {}),
    };
  },

  facts(d) {
    const out: Fact[] = [];
    if (d.providers.length === 0) {
      out.push({ label: 'Providers', value: 'No known sending providers detected' });
    }
    for (const p of d.providers) {
      out.push({ label: `${p.provider} (${p.confidence} confidence)`, value: p.evidence.map(evidenceLine) });
    }
    for (const a of d.accountIds) {
      out.push({ label: `${a.provider} ${a.kind}`, value: a.value, pivot: true });
    }
    const txtUnknown = d.unresolved?.includes('TXT') ?? false;
    out.push(
      d.spfIncludes.length
        ? { label: 'SPF includes (top level, not expanded)', value: d.spfIncludes.map(formatSpfTerm) }
        : txtUnknown
          ? { label: 'SPF', value: 'Unknown (apex TXT lookup failed)', tone: 'warn' }
          : { label: 'SPF', value: d.spf ? 'No include:/redirect= terms' : 'No SPF record at apex' },
    );
    if (d.mx.length) out.push({ label: 'MX', value: d.mx });
    else if (d.unresolved?.includes('MX')) out.push({ label: 'MX', value: 'Unknown (apex MX lookup failed)', tone: 'warn' });
    out.push({
      label: `DKIM selectors found (${d.dkim.length}/${d.queriedSelectors} checked)`,
      value: d.dkim.length
        ? d.dkim.map((k) => (k.cname ? `${k.selector} → ${k.cname}` : `${k.selector} TXT ${k.txt ?? ''}`))
        : 'None of the common selectors',
    });
    if (d.dkimWildcard) {
      out.push({ label: 'DKIM wildcard', value: `Guessed selectors all resolve to ${d.dkimWildcard} (wildcard record); ignored` });
    }
    if (d.failedLookups?.length) {
      out.push({ label: 'Failed lookups', value: d.failedLookups, tone: 'warn' });
    }
    return out;
  },

  headline(d) {
    // providers are already ordered high/medium before low.
    return { emailProviders: d.providers.map((p) => p.provider) };
  },
};
