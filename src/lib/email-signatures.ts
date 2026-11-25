import { stripDot } from './doh';

/**
 * Email-sending provider signatures (data, not provider code) and a pure
 * detector over apex SPF / TXT / MX and DKIM selector records.
 *
 * Source: docs/research/pdns-m365-email.md sections 3-5 (checked 2026-11-25).
 * The "extras" block at the end holds a few cheap SPF/MX/TXT-only signatures
 * for well-known providers that need no additional DNS queries.
 *
 * Matching rules:
 * - Every value is lowercased and trimmed before matching; MX and CNAME
 *   targets also lose their trailing dot. Regexes are written lowercase and
 *   anchored, so `sendgrid.net.evil.example` never matches `sendgrid.net`.
 * - `spf` signatures match the *domain* of each top-level include:/redirect=
 *   term (see spfIncludes), not the raw record text.
 * - `dkim` signatures match the CNAME target (record 'CNAME') or the joined
 *   TXT value (record 'TXT') found at `<name>._domainkey.<domain>`. `name: '*'`
 *   matches any selector (for selectors learned elsewhere, e.g. SES tokens).
 * - `supporting` signatures add to a provider's score but never establish a
 *   provider on their own (google-site-verification is not Workspace-specific).
 */

export type EvidenceType = 'spf' | 'mx' | 'dkim' | 'txt';
export type DkimRecord = 'CNAME' | 'TXT';
export type Confidence = 'low' | 'medium' | 'high';

export interface Signature {
  provider: string;
  type: EvidenceType;
  /** Selector for dkim; '@' (apex) otherwise. */
  name: string;
  /** dkim only: which record at the selector carries the evidence. */
  record?: DkimRecord;
  /** Anchored, lowercase, never global/sticky. */
  re: RegExp;
  /** Names for the regex capture groups, in order. Empty/undefined groups are dropped. */
  captures?: string[];
  /** Extra captures built from templates, e.g. `{initialDomainPrefix}.onmicrosoft.com`. */
  derive?: Record<string, string>;
  /** A capture that identifies the customer account (exposed as an account ID). */
  account?: {
    kind: string;
    capture: string;
    /** Show the value next to the provider name in the one-line summary. */
    summary?: boolean;
    /** Also emit the value as a pivot of this entity kind. */
    pivot?: 'domain';
  };
  weight: 1 | 2 | 3;
  supporting?: boolean;
  note?: string;
}

/** Matches the domain of an SPF include:/redirect= term exactly. */
const host = (h: string): RegExp => new RegExp(`^${h.replace(/\./g, '\\.')}$`);
/** Any DKIM public-key TXT (`p=` tag present, possibly empty = revoked). */
const DKIM_KEY = /(?:^|;)\s*p=/;

const M365_DKIM =
  /^selector[12]-([a-z0-9-]+)\._domainkey\.([a-z0-9-]+)\.(?:onmicrosoft\.com|([a-z0-9])-v1\.dkim\.mail\.microsoft)$/;
const SENDGRID_DKIM = /^(?:s\d\.domainkey\.)?(u\d+)\.wl(\d*)\.sendgrid\.net$/;
const MAILGUN_PDK = (n: 1 | 2): RegExp =>
  new RegExp(`^pdk${n}\\._domainkey\\.([a-z0-9]+)\\.dkim\\d*\\.(?:eu\\.)?mailgun\\.(?:com|org)$`);

const m365Dkim = (selector: string): Signature => ({
  provider: 'Microsoft 365',
  type: 'dkim',
  name: selector,
  record: 'CNAME',
  re: M365_DKIM,
  captures: ['domainDashed', 'initialDomainPrefix', 'partition'],
  derive: { initialDomain: '{initialDomainPrefix}.onmicrosoft.com' },
  account: { kind: 'initial domain', capture: 'initialDomain', pivot: 'domain' },
  weight: 3,
});

const sendgridDkim = (selector: string): Signature => ({
  provider: 'SendGrid',
  type: 'dkim',
  name: selector,
  record: 'CNAME',
  re: SENDGRID_DKIM,
  captures: ['userId', 'wl'],
  account: { kind: 'user ID', capture: 'userId', summary: true },
  weight: 3,
  note: 'u<digits> = SendGrid user_id, may be a subuser',
});

export const SIGNATURES: readonly Signature[] = [
  // Microsoft 365
  { provider: 'Microsoft 365', type: 'spf', name: '@', re: host('spf.protection.outlook.com'), weight: 3 },
  {
    provider: 'Microsoft 365',
    type: 'mx',
    name: '@',
    re: /^([a-z0-9-]+)\.mail\.(?:protection\.outlook\.(?:com|de)|eo\.outlook\.com)$/,
    captures: ['mxToken'],
    weight: 3,
  },
  {
    provider: 'Microsoft 365',
    type: 'mx',
    name: '@',
    re: /^([a-z0-9-]+)\.([a-z0-9-]+)\.mx\.microsoft$/,
    captures: ['mxToken', 'partition'],
    weight: 3,
    note: 'DNSSEC MX',
  },
  {
    provider: 'Microsoft 365',
    type: 'mx',
    name: '@',
    re: /^([a-z0-9-]+)\.mail\.protection\.office365\.us$/,
    captures: ['mxToken'],
    weight: 3,
    note: 'GCC High',
  },
  { provider: 'Microsoft 365', type: 'txt', name: '@', re: /^ms=(?:ms\d{6,10}|[0-9a-f]{40})$/, weight: 2, note: 'domain verification' },
  m365Dkim('selector1'),
  m365Dkim('selector2'),

  // SendGrid (Twilio)
  sendgridDkim('s1'),
  sendgridDkim('s2'),
  { provider: 'SendGrid', type: 'spf', name: '@', re: host('sendgrid.net'), weight: 2, note: 'standard setup puts this on em####, not the apex' },

  // Mailgun
  { provider: 'Mailgun', type: 'spf', name: '@', re: /^(?:(eu)\.)?mailgun\.org$/, captures: ['region'], weight: 3 },
  { provider: 'Mailgun', type: 'mx', name: '@', re: /^mx[ab]\.(?:(eu)\.)?mailgun\.org$/, captures: ['region'], weight: 3 },
  { provider: 'Mailgun', type: 'dkim', name: 'pdk1', record: 'CNAME', re: MAILGUN_PDK(1), captures: ['mgId'], weight: 3 },
  { provider: 'Mailgun', type: 'dkim', name: 'pdk2', record: 'CNAME', re: MAILGUN_PDK(2), captures: ['mgId'], weight: 3 },

  // Amazon SES
  { provider: 'Amazon SES', type: 'spf', name: '@', re: host('amazonses.com'), weight: 2, note: 'normally on the MAIL FROM subdomain' },
  { provider: 'Amazon SES', type: 'mx', name: '@', re: /^inbound-smtp\.([a-z0-9-]+)\.amazonaws\.com$/, captures: ['region'], weight: 3, note: 'SES inbound' },
  {
    provider: 'Amazon SES',
    type: 'mx',
    name: '@',
    re: /^feedback-smtp\.([a-z0-9-]+)\.amazonses\.com$/,
    captures: ['region'],
    weight: 3,
    note: 'MAIL FROM feedback MX',
  },
  {
    provider: 'Amazon SES',
    type: 'dkim',
    name: '*',
    record: 'CNAME',
    re: /^([a-z0-9]{32})\.dkim(?:\.([a-z0-9-]+))?\.amazonses\.com$/,
    captures: ['token', 'region'],
    weight: 3,
    note: 'Easy DKIM token selector',
  },

  // Mailchimp
  { provider: 'Mailchimp', type: 'dkim', name: 'k1', record: 'CNAME', re: /^dkim\.mcsv\.net$/, weight: 3, note: 'legacy selector' },
  { provider: 'Mailchimp', type: 'dkim', name: 'k2', record: 'CNAME', re: /^dkim2\.mcsv\.net$/, weight: 3 },
  { provider: 'Mailchimp', type: 'dkim', name: 'k3', record: 'CNAME', re: /^dkim3\.mcsv\.net$/, weight: 3 },
  { provider: 'Mailchimp', type: 'spf', name: '@', re: host('servers.mcsv.net'), weight: 2 },

  // Mandrill (Mailchimp Transactional)
  { provider: 'Mandrill', type: 'dkim', name: 'mte1', record: 'CNAME', re: /^dkim1\.mandrillapp\.com$/, weight: 3 },
  { provider: 'Mandrill', type: 'dkim', name: 'mte2', record: 'CNAME', re: /^dkim2\.mandrillapp\.com$/, weight: 3 },
  { provider: 'Mandrill', type: 'dkim', name: 'mandrill', record: 'TXT', re: DKIM_KEY, weight: 2, note: 'legacy TXT key' },
  { provider: 'Mandrill', type: 'spf', name: '@', re: host('spf.mandrillapp.com'), weight: 2 },
  { provider: 'Mandrill', type: 'txt', name: '@', re: /^mandrill_verify\.[a-z0-9_-]+$/, weight: 2, note: 'domain verification' },

  // Google Workspace
  { provider: 'Google Workspace', type: 'spf', name: '@', re: host('_spf.google.com'), weight: 3 },
  {
    provider: 'Google Workspace',
    type: 'mx',
    name: '@',
    re: /^(?:smtp\.google\.com|(?:alt[1-4]\.)?aspmx\.l\.google\.com|aspmx[2-5]\.googlemail\.com)$/,
    weight: 3,
  },
  { provider: 'Google Workspace', type: 'dkim', name: 'google', record: 'TXT', re: DKIM_KEY, weight: 2, note: 'default selector (customisable)' },
  {
    provider: 'Google Workspace',
    type: 'txt',
    name: '@',
    re: /^google-site-verification=/,
    weight: 1,
    supporting: true,
    note: 'not Workspace-specific',
  },

  // Extras: SPF/MX/TXT only (no extra DNS queries).
  { provider: 'Zoho Mail', type: 'spf', name: '@', re: /^(?:one\.)?zoho(?:mail)?\.(?:com|eu|in|com\.au|jp|com\.cn|sa|ca)$/, weight: 3 },
  { provider: 'Zoho Mail', type: 'mx', name: '@', re: /^mx[23]?\.zoho\.(?:com|eu|in|com\.au|jp|com\.cn|sa|ca)$/, weight: 3 },
  { provider: 'Zoho Mail', type: 'txt', name: '@', re: /^zoho-verification=/, weight: 2, note: 'domain verification' },
  { provider: 'Proton Mail', type: 'spf', name: '@', re: host('_spf.protonmail.ch'), weight: 3 },
  { provider: 'Proton Mail', type: 'mx', name: '@', re: /^(?:mail|mailsec)\.protonmail\.ch$/, weight: 3 },
  { provider: 'Proton Mail', type: 'txt', name: '@', re: /^protonmail-verification=/, weight: 2, note: 'domain verification' },
  { provider: 'Fastmail', type: 'spf', name: '@', re: host('spf.messagingengine.com'), weight: 3 },
  { provider: 'Fastmail', type: 'mx', name: '@', re: /^in[12]-smtp\.messagingengine\.com$/, weight: 3 },
  { provider: 'Postmark', type: 'spf', name: '@', re: host('spf.mtasv.net'), weight: 3 },
  { provider: 'SparkPost', type: 'spf', name: '@', re: /^(?:_spf\.)?sparkpostmail\.com$/, weight: 3 },
  { provider: 'Mailjet', type: 'spf', name: '@', re: host('spf.mailjet.com'), weight: 3 },
  { provider: 'Brevo', type: 'spf', name: '@', re: /^(?:spf\.)?(?:sendinblue|brevo)\.com$/, weight: 3 },
  { provider: 'Brevo', type: 'txt', name: '@', re: /^(?:brevo|sendinblue)-code:/, weight: 2, note: 'domain verification' },
  {
    provider: 'HubSpot',
    type: 'spf',
    name: '@',
    re: /^(\d+)\.spf\d+\.hubspotemail\.net$/,
    captures: ['hubId'],
    account: { kind: 'account ID', capture: 'hubId' },
    weight: 3,
  },
  { provider: 'Zendesk', type: 'spf', name: '@', re: host('mail.zendesk.com'), weight: 3 },
  { provider: 'Salesforce', type: 'spf', name: '@', re: host('_spf.salesforce.com'), weight: 3 },
  { provider: 'Salesforce Marketing Cloud', type: 'spf', name: '@', re: host('cust-spf.exacttarget.com'), weight: 3 },
  { provider: 'Mimecast', type: 'spf', name: '@', re: /^(?:[a-z]{2}\.)?_netblocks\.mimecast\.com$/, weight: 3 },
  { provider: 'Mimecast', type: 'mx', name: '@', re: /^[a-z0-9-]+\.mimecast\.(?:com|co\.za)$/, weight: 3 },
  { provider: 'Proofpoint', type: 'spf', name: '@', re: /^[a-z0-9-]+\.(?:pphosted|ppe-hosted)\.com$/, weight: 3 },
  { provider: 'Proofpoint', type: 'mx', name: '@', re: /^(?:[a-z0-9-]+\.)+(?:pphosted|ppe-hosted)\.com$/, weight: 3 },
];

export interface DkimEvidence {
  selector: string;
  cname?: string;
  txt?: string;
}

export interface Evidence {
  /** The apex SPF record (or null). Only top-level include:/redirect= terms are used. */
  spf: string | null;
  /** All apex TXT values (joined character-strings). */
  txt: string[];
  /** MX exchange hostnames. */
  mx: string[];
  /** Records found at `<selector>._domainkey.<domain>`. */
  dkim: DkimEvidence[];
}

export interface EvidenceHit {
  type: EvidenceType;
  /** Selector for dkim, '@' otherwise. */
  name: string;
  /** dkim only. */
  record?: DkimRecord;
  /** The matched value, normalised (SPF as `include:x` / `redirect=x`, TXT capped). */
  value: string;
  captures: Record<string, string>;
  note?: string;
}

export interface ProviderHit {
  provider: string;
  confidence: Confidence;
  score: number;
  evidence: EvidenceHit[];
}

export interface AccountId {
  provider: string;
  kind: string;
  value: string;
  summary?: boolean;
  pivot?: 'domain';
}

export interface Detection {
  providers: ProviderHit[];
  accountIds: AccountId[];
}

export interface SpfTerm {
  type: 'include' | 'redirect';
  /** Lowercase, no trailing dot (macros kept verbatim). */
  domain: string;
  /** Only when written explicitly (`~include:x`). */
  qualifier?: '+' | '-' | '~' | '?';
}

/** Top-level include: mechanisms and redirect= modifier of an SPF record (no recursion). */
export function spfIncludes(spf: string | null | undefined): SpfTerm[] {
  if (!spf) return [];
  const out: SpfTerm[] = [];
  for (const term of spf.trim().split(/\s+/)) {
    const inc = /^([+\-~?]?)include:(.+)$/i.exec(term);
    if (inc) {
      const domain = stripDot(inc[2]!);
      if (!domain) continue;
      const q = inc[1] as '' | '+' | '-' | '~' | '?';
      out.push({ type: 'include', domain, ...(q ? { qualifier: q } : {}) });
      continue;
    }
    const red = /^redirect=(.+)$/i.exec(term);
    if (red) {
      const domain = stripDot(red[1]!);
      if (domain) out.push({ type: 'redirect', domain });
    }
  }
  return out;
}

export function formatSpfTerm(t: SpfTerm): string {
  return t.type === 'include' ? `${t.qualifier ?? ''}include:${t.domain}` : `redirect=${t.domain}`;
}

/** Selectors the table can recognise, deduped; `txt` when any signature expects a TXT key there. */
export function selectorsToQuery(signatures: readonly Signature[] = SIGNATURES): Array<{ selector: string; txt: boolean }> {
  const map = new Map<string, boolean>();
  for (const s of signatures) {
    if (s.type !== 'dkim' || s.name === '*') continue;
    const sel = s.name.toLowerCase();
    map.set(sel, (map.get(sel) ?? false) || s.record === 'TXT');
  }
  return [...map].map(([selector, txt]) => ({ selector, txt }));
}

const MAX_VALUE = 120;
const cap = (s: string): string => (s.length > MAX_VALUE ? `${s.slice(0, MAX_VALUE - 1)}…` : s);

interface Candidate {
  name: string;
  record?: DkimRecord;
  value: string;
  match: string;
}

function candidates(sig: Signature, ev: Evidence, spfTerms: SpfTerm[]): Candidate[] {
  switch (sig.type) {
    case 'spf':
      return spfTerms.map((t) => ({ name: '@', value: formatSpfTerm(t), match: t.domain }));
    case 'txt':
      return ev.txt.map((v) => ({ name: '@', value: cap(v.trim()), match: v.trim().toLowerCase() }));
    case 'mx':
      return ev.mx.map((v) => stripDot(v)).filter(Boolean).map((h) => ({ name: '@', value: h, match: h }));
    case 'dkim': {
      const want = sig.name.toLowerCase();
      const out: Candidate[] = [];
      for (const d of ev.dkim) {
        const sel = d.selector.toLowerCase();
        if (want !== '*' && sel !== want) continue;
        if (sig.record === 'TXT') {
          if (d.txt) out.push({ name: sel, record: 'TXT', value: cap(d.txt.trim()), match: d.txt.trim().toLowerCase() });
        } else if (d.cname) {
          const c = stripDot(d.cname);
          if (c) out.push({ name: sel, record: 'CNAME', value: c, match: c });
        }
      }
      return out;
    }
  }
}

function fill(template: string, caps: Record<string, string>): string | null {
  let ok = true;
  const out = template.replace(/\{(\w+)\}/g, (_, k: string) => {
    const v = caps[k];
    if (v === undefined) ok = false;
    return v ?? '';
  });
  return ok ? out : null;
}

function confidenceOf(score: number): Confidence {
  return score >= 3 ? 'high' : score >= 2 ? 'medium' : 'low';
}

const RANK: Record<Confidence, number> = { high: 0, medium: 1, low: 2 };

/** Pure: match evidence against the signature table. Providers sorted by score (desc), then name. */
export function detectProviders(ev: Evidence, signatures: readonly Signature[] = SIGNATURES): Detection {
  const spfTerms = spfIncludes(ev.spf);
  const acc = new Map<string, { score: number; established: boolean; evidence: EvidenceHit[]; seen: Set<string> }>();
  const accounts: AccountId[] = [];
  const accountSeen = new Set<string>();

  for (const sig of signatures) {
    let matched = false;
    for (const c of candidates(sig, ev, spfTerms)) {
      const m = sig.re.exec(c.match);
      if (!m) continue;
      const caps: Record<string, string> = {};
      sig.captures?.forEach((n, i) => {
        const v = m[i + 1];
        if (v) caps[n] = v;
      });
      for (const [k, tpl] of Object.entries(sig.derive ?? {})) {
        const v = fill(tpl, caps);
        if (v) caps[k] = v;
      }
      let p = acc.get(sig.provider);
      if (!p) {
        p = { score: 0, established: false, evidence: [], seen: new Set() };
        acc.set(sig.provider, p);
      }
      if (!matched) {
        p.score += sig.weight;
        if (!sig.supporting) p.established = true;
        matched = true;
      }
      const key = `${sig.type}|${c.name}|${c.record ?? ''}|${c.value}`;
      if (!p.seen.has(key)) {
        p.seen.add(key);
        p.evidence.push({
          type: sig.type,
          name: c.name,
          ...(c.record ? { record: c.record } : {}),
          value: c.value,
          captures: caps,
          ...(sig.note ? { note: sig.note } : {}),
        });
      }
      const a = sig.account;
      const av = a ? caps[a.capture] : undefined;
      if (a && av) {
        const k = `${sig.provider}|${a.kind}|${av}`;
        if (!accountSeen.has(k)) {
          accountSeen.add(k);
          accounts.push({
            provider: sig.provider,
            kind: a.kind,
            value: av,
            ...(a.summary ? { summary: true } : {}),
            ...(a.pivot ? { pivot: a.pivot } : {}),
          });
        }
      }
    }
  }

  const providers: ProviderHit[] = [...acc]
    .filter(([, p]) => p.established)
    .map(([provider, p]) => ({ provider, confidence: confidenceOf(p.score), score: p.score, evidence: p.evidence }))
    .sort((a, b) => RANK[a.confidence] - RANK[b.confidence] || b.score - a.score || a.provider.localeCompare(b.provider));
  const names = new Set(providers.map((p) => p.provider));
  return { providers, accountIds: accounts.filter((a) => names.has(a.provider)) };
}
