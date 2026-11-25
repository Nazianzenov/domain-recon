import type { Headline } from './types';

/**
 * Correlation verdict, computed in code (never by the model): combine the
 * AI's brand identification with registration age, the M365 tenant check,
 * page signals and the domain itself.
 */

export type VerdictLevel = 'likely-impersonation' | 'suspicious' | 'consistent' | 'inconclusive';

export interface Signal {
  text: string;
  weight: 'strong' | 'medium' | 'weak' | 'mitigating';
}

export interface Verdict {
  level: VerdictLevel;
  title: string;
  brand: string | null;
  officialDomains: string[];
  signals: Signal[];
}

export interface KnownBrand {
  name: string;
  /**
   * Normalised brand names (see normBrand) that identify this brand exactly.
   * Ambiguous everyday words (apple, chase, ups, meta, teams, adobe...) only
   * ever match as the WHOLE name, so "Big Apple Pizza" or "Meta Real Estate"
   * are not taken for the big brand.
   */
  aliases: string[];
  /** Distinctive leading words: "<prefix>" or "<prefix> <anything>" matches ("Microsoft Teams"). */
  prefixes?: string[];
  /** Official registrable domains (and their subdomains). */
  domains: string[];
  /** Registrable-domain patterns for ccTLD families (google.de, google.co.uk...). */
  patterns?: RegExp[];
  /**
   * Official domains whose SUBDOMAINS are customer-controlled hosting (Azure
   * storage, SharePoint tenants, S3...). Anyone can publish there, so such a
   * name is never "official" even though it sits under an official domain.
   */
  shared?: string[];
  /** Brand whose own domains run on Microsoft 365 (no tenant on a "Microsoft" domain is a signal). */
  microsoft?: boolean;
}

/**
 * ccTLDs sold as generic names or once given away free: "google.io" or
 * "google.tk" in a pattern would be a look-alike anyone may hold.
 */
const OPEN_CC = '(?:ac|ag|ai|am|bz|cc|cf|co|fm|ga|gg|gq|io|la|ly|me|ml|ms|mu|nu|sc|sh|so|st|su|tk|to|tv|vc|ws)';
const CC = String.raw`(?!${OPEN_CC}$)(?:[a-z]{2}|com?\.[a-z]{2})`;

/** Small built-in table so the official-domain check doesn't rely on the model alone. */
export const KNOWN_BRANDS: KnownBrand[] = [
  {
    name: 'Microsoft',
    aliases: [
      'outlook', 'outlook web access', 'outlook web app', 'microsoft outlook', 'azure', 'entra', 'entra id', 'azure ad',
      'azure active directory', 'bing', 'microsoft teams', 'msn', 'office online',
    ],
    prefixes: ['microsoft', 'office 365', 'o365', 'onedrive', 'sharepoint', 'hotmail', 'xbox', 'skype'],
    domains: [
      'microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com', 'office.net', 'live.com', 'outlook.com',
      'hotmail.com', 'sharepoint.com', 'onedrive.com', 'azure.com', 'windows.net', 'msn.com', 'bing.com', 'skype.com',
      'xbox.com', 'microsoft365.com', 'cloud.microsoft', 'msauth.net', 'msftauth.net',
    ],
    shared: ['sharepoint.com', 'core.windows.net', 'cloudapp.azure.com'],
    microsoft: true,
  },
  {
    name: 'Google',
    aliases: [],
    prefixes: ['google', 'gmail', 'youtube'],
    domains: ['google.com', 'gmail.com', 'youtube.com', 'googleusercontent.com', 'withgoogle.com'],
    patterns: [new RegExp(`^google\\.${CC}$`)],
    shared: ['googleusercontent.com'],
  },
  {
    name: 'Apple',
    aliases: ['apple', 'apple id', 'apple account', 'apple support', 'apple pay', 'apple store', 'app store', 'apple music'],
    prefixes: ['icloud', 'itunes'],
    domains: ['apple.com', 'icloud.com', 'itunes.com'],
  },
  {
    name: 'Amazon',
    aliases: ['amazon', 'prime video'],
    prefixes: ['aws', 'amazon web services', 'amazon prime', 'amazon seller', 'amazon pay', 'amazon business', 'amazon account'],
    // Explicit list: Amazon does not hold amazon.<every ccTLD>.
    domains: [
      'amazon.com', 'amazonaws.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.ca',
      'amazon.com.mx', 'amazon.com.br', 'amazon.co.jp', 'amazon.in', 'amazon.com.au', 'amazon.nl', 'amazon.se', 'amazon.pl',
      'amazon.sg', 'amazon.ae', 'amazon.sa', 'amazon.eg', 'amazon.com.tr', 'amazon.com.be', 'amazon.cn', 'amazon.co.za',
      'amazon.ie',
    ],
    shared: ['amazonaws.com'],
  },
  { name: 'PayPal', aliases: [], prefixes: ['paypal'], domains: ['paypal.com', 'paypal.me', 'paypalobjects.com'] },
  {
    name: 'Meta',
    aliases: ['meta', 'meta platforms', 'facebook messenger'],
    prefixes: ['facebook', 'instagram', 'whatsapp', 'meta business', 'meta for business', 'meta verified', 'meta accounts'],
    domains: ['facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com', 'meta.com', 'messenger.com'],
  },
  { name: 'Netflix', aliases: [], prefixes: ['netflix'], domains: ['netflix.com'] },
  { name: 'LinkedIn', aliases: [], prefixes: ['linkedin'], domains: ['linkedin.com'] },
  { name: 'DHL', aliases: [], prefixes: ['dhl'], domains: ['dhl.com', 'dhl.de'] },
  { name: 'DocuSign', aliases: [], prefixes: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
  { name: 'Dropbox', aliases: [], prefixes: ['dropbox'], domains: ['dropbox.com'] },
  {
    name: 'Adobe',
    aliases: ['adobe', 'adobe systems'],
    prefixes: ['adobe acrobat', 'adobe sign', 'adobe document cloud', 'adobe creative cloud', 'adobe pdf', 'adobe express', 'adobe account'],
    domains: ['adobe.com'],
  },
  { name: 'Okta', aliases: [], prefixes: ['okta'], domains: ['okta.com', 'oktacdn.com'] },
  { name: 'Coinbase', aliases: [], prefixes: ['coinbase'], domains: ['coinbase.com'] },
  { name: 'Binance', aliases: [], prefixes: ['binance'], domains: ['binance.com'] },
  {
    name: 'Chase',
    aliases: ['chase', 'chase bank', 'chase online'],
    prefixes: ['jpmorgan', 'jp morgan'],
    domains: ['chase.com', 'jpmorganchase.com'],
  },
  { name: 'Wells Fargo', aliases: [], prefixes: ['wells fargo'], domains: ['wellsfargo.com'] },
  { name: 'Bank of America', aliases: [], prefixes: ['bank of america'], domains: ['bankofamerica.com'] },
  {
    name: 'UPS',
    aliases: ['ups', 'ups store'],
    prefixes: ['united parcel service'],
    domains: ['ups.com', 'theupsstore.com'],
  },
  { name: 'FedEx', aliases: [], prefixes: ['fedex'], domains: ['fedex.com'] },
  {
    name: 'USPS',
    aliases: ['united states postal service', 'us postal service'],
    prefixes: ['usps'],
    domains: ['usps.com'],
  },
];

/** Lower-case, punctuation-free brand name without "The"/legal-form noise: "Amazon.com, Inc." -> "amazon". */
export function normBrand(s: string): string {
  return s
    .normalize('NFKC')
    .toLowerCase()
    .replace(/\.(?:com|net|org)\b/g, ' ')
    .replace(/['’`]/g, '')
    .replace(/&/g, ' and ')
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .trim()
    .replace(/^the\s+/, '')
    .replace(/(?:\s+and)?\s+(?:inc|incorporated|corp|corporation|llc|ltd|limited|plc|co|company|gmbh|ag|sa|nv|bv)$/, '')
    .trim();
}

/** "Office 365 (Microsoft)" / "Microsoft / DocuSign" -> each name on its own, normalised. */
function brandCandidates(raw: string): string[] {
  const out = new Set<string>();
  const inner = [...raw.matchAll(/\(([^)]*)\)|\[([^\]]*)\]/g)].map((m) => m[1] ?? m[2] ?? '');
  const outer = raw.replace(/\([^)]*\)|\[[^\]]*\]/g, ' ');
  for (const chunk of [outer, ...inner]) {
    for (const part of chunk.split(/[/|,;]|\s[-–—]\s/)) {
      const n = normBrand(part);
      if (n) out.add(n);
    }
  }
  return [...out];
}

/** The built-in brand the AI's brand string names, if any (whole names / distinctive prefixes only). */
export function findKnownBrand(brand: string): KnownBrand | undefined {
  for (const c of brandCandidates(brand)) {
    const hit = KNOWN_BRANDS.find(
      (k) => k.aliases.includes(c) || (k.prefixes ?? []).some((p) => c === p || c.startsWith(`${p} `)),
    );
    if (hit) return hit;
  }
  return undefined;
}

/** `domain` is `official` or a subdomain of it (label boundaries respected). */
export function domainMatches(domain: string, official: string): boolean {
  return domain === official || domain.endsWith(`.${official}`);
}

const normHost = (h: string) => h.trim().toLowerCase().replace(/\.+$/, '');

function matchesPattern(domain: string, re: RegExp): boolean {
  const labels = domain.split('.');
  // test every suffix with at least two labels: www.google.co.uk -> google.co.uk
  for (let i = 0; i <= labels.length - 2; i++) {
    if (re.test(labels.slice(i).join('.'))) return true;
  }
  return false;
}

/** The shared-hosting suffix `host` sits under as a customer subdomain ("www." of the suffix itself excepted). */
function sharedParent(k: KnownBrand, host: string): string | null {
  for (const s of k.shared ?? []) {
    if (host !== s && host !== `www.${s}` && host.endsWith(`.${s}`)) return s;
  }
  return null;
}

function isKnownOfficial(k: KnownBrand, host: string): boolean {
  if (sharedParent(k, host)) return false;
  return k.domains.some((o) => domainMatches(host, o)) || !!k.patterns?.some((p) => matchesPattern(host, p));
}

export interface VerdictInput {
  /** ASCII (punycode) investigated domain. */
  domain: string;
  isIdn: boolean;
  headline: Partial<Headline>;
}

/**
 * How the investigated name relates to the brand's official domains:
 * - shared: customer-controlled subdomain of an official hosting domain
 * - mismatch: official domains are known (table or AI) and this is not one
 * - ai-claimed: unknown brand; only the AI says this is the official domain
 * - unknown: unknown brand and no official domain from the AI
 */
type Status = 'shared' | 'mismatch' | 'ai-claimed' | 'unknown';

export function correlate({ domain: rawDomain, isIdn, headline }: VerdictInput): Verdict | null {
  const b = headline.brand;
  if (!b) return null;
  const signals: Signal[] = [];
  if (!b.brand || !(b.confidence >= 0.5)) {
    return {
      level: 'inconclusive',
      title: b.brand ? `Brand unclear (${b.brand}, ${Math.round(b.confidence * 100)}%)` : 'No brand identified',
      brand: b.brand,
      officialDomains: [],
      signals: b.brand ? [{ text: `AI confidence only ${Math.round(b.confidence * 100)}%`, weight: 'weak' }] : [],
    };
  }

  const brand = b.brand;
  const pct = Math.round(b.confidence * 100);
  const domain = normHost(rawDomain);
  // The built-in table always wins: the model (steerable by the page) cannot add official domains for a known brand.
  const known = findKnownBrand(brand);
  const aiDomain = !known && b.expectedDomain ? normHost(b.expectedDomain) : null;
  const officialDomains = known ? [...known.domains] : aiDomain ? [aiDomain] : [];
  const isOfficialHost = (h: string): boolean =>
    known ? isKnownOfficial(known, normHost(h)) : !!aiDomain && domainMatches(normHost(h), aiDomain);

  if (known && isKnownOfficial(known, domain)) {
    signals.push({ text: `${domain} is an official ${brand} domain`, weight: 'mitigating' });
    return { level: 'consistent', title: `Consistent: official ${brand} domain`, brand, officialDomains, signals };
  }

  const shared = known ? sharedParent(known, domain) : null;
  const status: Status = shared
    ? 'shared'
    : known
      ? 'mismatch'
      : aiDomain
        ? domainMatches(domain, aiDomain)
          ? 'ai-claimed'
          : 'mismatch'
        : 'unknown';

  const list = `${officialDomains.slice(0, 3).join(', ')}${officialDomains.length > 3 ? '…' : ''}`;
  if (status === 'shared') {
    signals.push({
      text: `${domain} is customer-controlled hosting under ${shared}: anyone can publish there, so ${brand} branding does not show ${brand} runs it`,
      weight: 'weak',
    });
  } else if (status === 'mismatch') {
    signals.push({
      text: `AI identified ${brand} (${pct}%), but ${domain} is not an official ${brand} domain (${known ? '' : 'per the AI: '}${list})`,
      weight: 'weak',
    });
  } else if (status === 'ai-claimed') {
    // Mitigating only: the page itself can steer the model into naming this domain.
    signals.push({ text: `AI identified ${brand} (${pct}%) and names ${domain} as its official domain (not independently verified)`, weight: 'mitigating' });
  } else {
    signals.push({ text: `AI identified ${brand} (${pct}%); official domain unknown`, weight: 'weak' });
  }

  const age = headline.domainAgeDays;
  const regFor = headline.registrationFor ? normHost(headline.registrationFor) : null;
  const parent = regFor && regFor !== domain ? regFor : null;
  if (age !== undefined) {
    const days = `${age} day${age === 1 ? '' : 's'}`;
    if (parent) {
      // Subdomain of another registration. A young parent is alarming whoever holds it (attackers
      // put phishing on subdomains of fresh domains); an old one (weebly.com) says nothing about
      // who controls this name, so it is neither alarming nor reassuring.
      if (age < 30) signals.push({ text: `Parent domain ${parent} registered only ${days} ago`, weight: 'strong' });
      else signals.push({ text: `Registration data is for the parent ${parent} (${days} old), not this name`, weight: 'weak' });
    } else if (age < 30) signals.push({ text: `Registered only ${days} ago`, weight: 'strong' });
    else if (age < 180) signals.push({ text: `Registered ${age} days ago (under 6 months)`, weight: 'weak' });
    else if (age > 3 * 365) signals.push({ text: `Registered ${Math.floor(age / 365)} years ago`, weight: 'mitigating' });
  }

  if (known?.microsoft && headline.m365 && !headline.m365.tenant) {
    signals.push(
      parent
        ? { text: `No Microsoft 365 / Entra ID tenant for this name (tenants normally sit on the registered domain, here ${parent})`, weight: 'weak' }
        : { text: 'No Microsoft 365 / Entra ID tenant for this domain', weight: 'medium' },
    );
  }

  const page = headline.page;
  if (page) {
    const finalHost = page.finalHost ? normHost(page.finalHost) : null;
    const redirected = !!finalHost && !domainMatches(finalHost, domain) && !domainMatches(domain, finalHost);
    if (finalHost && redirected && isOfficialHost(finalHost)) {
      // The analysed page (and its forms) belongs to the official site, not to this domain.
      signals.push({ text: `Homepage redirects to ${finalHost}, an official ${brand} domain (the page signals describe that site)`, weight: 'weak' });
    } else {
      // A password form posting to the brand's own login host is SSO, not exfiltration.
      const offsite = page.offsiteFormHosts.filter((h) => !isOfficialHost(h));
      if (page.hasPasswordInput && offsite.length) {
        signals.push({ text: `Password form submits to another host: ${offsite.slice(0, 3).join(', ')}`, weight: 'strong' });
      } else if (page.hasPasswordInput && status === 'mismatch') {
        signals.push({ text: `Password field on a non-official ${brand} domain`, weight: 'medium' });
      } else if (page.hasPasswordInput && status === 'shared') {
        signals.push({ text: `Password field on customer-controlled hosting with ${brand} branding`, weight: 'medium' });
      } else if (page.hasPasswordInput && status === 'unknown') {
        signals.push({ text: 'Password field on the page', weight: 'weak' });
      }
      if (redirected) signals.push({ text: `Homepage redirects to ${finalHost}`, weight: 'weak' });
    }
  }

  if (isIdn) {
    signals.push(
      status === 'ai-claimed'
        ? { text: 'Internationalised (punycode) domain', weight: 'weak' }
        : { text: 'Internationalised (punycode) domain: possible look-alike characters', weight: 'medium' },
    );
  }

  if (b.impersonation === 'high') signals.push({ text: 'AI rates impersonation likelihood high', weight: 'strong' });
  else if (b.impersonation === 'medium') signals.push({ text: 'AI rates impersonation likelihood medium', weight: 'medium' });
  else signals.push({ text: 'AI rates impersonation likelihood low', weight: 'mitigating' });

  const strong = signals.filter((s) => s.weight === 'strong').length;
  const medium = signals.filter((s) => s.weight === 'medium').length;
  let level: VerdictLevel;
  if (strong >= 2 || (strong >= 1 && medium >= 1)) level = 'likely-impersonation';
  else if (strong >= 1 || medium >= 1) level = 'suspicious';
  else level = status === 'ai-claimed' ? 'consistent' : 'inconclusive';
  // "Impersonation" needs an official domain this one is shown not to be; without one, cap the claim.
  if (level === 'likely-impersonation' && (status === 'ai-claimed' || status === 'unknown')) level = 'suspicious';

  return { level, title: titleFor(level, status, brand), brand, officialDomains, signals };
}

function titleFor(level: VerdictLevel, status: Status, brand: string): string {
  if (level === 'likely-impersonation') return `Likely impersonation of ${brand}`;
  if (level === 'consistent') return `Consistent: official ${brand} domain per the AI (not verified)`;
  if (level === 'suspicious') {
    if (status === 'mismatch') return `Suspicious: ${brand} branding on a non-official domain`;
    if (status === 'shared') return `Suspicious: ${brand} branding on customer-controlled hosting`;
    return `Suspicious signals on a ${brand} page (official domain ${status === 'ai-claimed' ? 'not verified' : 'unknown'})`;
  }
  if (status === 'mismatch') return `Mentions ${brand}; no strong impersonation signals`;
  if (status === 'shared') return `${brand} branding on customer-controlled hosting; no strong signals`;
  return `${brand} page; official domain unknown, no strong signals`;
}
