import { isIPv4, isIPv6 } from './ip';
import { toUnicode } from './punycode';

export type NormalizeResult =
  | {
      ok: true;
      /** ASCII (punycode) hostname: what every module queries. */
      domain: string;
      /** Unicode form for display (equal to `domain` for plain ASCII names). */
      unicode: string;
      /** True when the Unicode and punycode forms differ. */
      isIdn: boolean;
    }
  | { ok: false; error: string };

/** Undo common defanging: example[.]com, hxxps://, [:]//, user[@]example[.]com ... */
export function refang(s: string): string {
  return s
    .replace(/\s*\[\s*(?:\.|dot)\s*\]\s*|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}/gi, '.')
    .replace(/\\\./g, '.')
    .replace(/\[\s*:\/\/\s*\]/g, '://')
    .replace(/\[\s*:\s*\]/g, ':')
    .replace(/\[\s*\/\s*\]/g, '/')
    .replace(/\s*\[\s*(?:@|at)\s*\]\s*|\(\s*(?:@|at)\s*\)|\{\s*(?:@|at)\s*\}/gi, '@')
    .replace(/\bh(?:xx|\*\*|__)p(s?)(?=:\/\/)/gi, 'http$1')
    .replace(/\bfxp(?=:\/\/)/gi, 'ftp');
}

const SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;
const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
/**
 * Wrapping punctuation from pasted text, including typographic quotes and
 * brackets and a sentence-final full stop. Not ':' (it would eat the "::" of
 * an IPv6 literal such as 2001:db8::).
 */
const TRIM_RE =
  /^[\s<>"'`(\[{,;‘’“”«»「」『』【】（]+|[\s<>"'`)\]},;.!?‘’“”«»「」『』【】）…。]+$/g;
/** Hostname-looking tokens: contain a dot (ASCII or one UTS #46 maps to a dot) or an @. */
const HOSTISH_RE = /[.@。．｡]/;

/**
 * Hostname as the browser's URL parser sees it. Any scheme is replaced by http://
 * so IDNA mapping and IPv4 number parsing (0x7f.1, 2130706433) always apply; for
 * non-special schemes the parser would return an opaque, percent-encoded host.
 * Userinfo and email local parts are dropped by the parser itself (the host is
 * what follows the last @ before the first / ? # or \).
 */
function hostFromToken(token: string): string | null {
  const url = SCHEME_RE.test(token) ? token.replace(SCHEME_RE, 'http://') : `http://${token}`;
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/** Bare or bracketed IPv6 literal, with an optional :port, /prefix or %zone. */
function isIPv6Token(t: string): boolean {
  const v = t
    .replace(/^\[/, '')
    .replace(/\](?::\d*)?(?:[/?#].*)?$/, '')
    .replace(/\/\d{1,3}$/, '')
    .replace(/%[\w.~-]*$/, '');
  return isIPv6(v);
}

export const IP_ERROR = 'That is an IP address. Enter a domain; its IPs are investigated automatically.';
const NO_HOST = 'Could not find a valid hostname in that input.';

function fromToken(token: string): NormalizeResult {
  if (isIPv6Token(token)) return { ok: false, error: IP_ERROR };

  let host = hostFromToken(token);
  if (host === null) return { ok: false, error: NO_HOST };
  if (host.startsWith('[') || isIPv4(host)) return { ok: false, error: IP_ERROR };
  host = host.replace(/\.$/, '').toLowerCase();

  if (!host) return { ok: false, error: NO_HOST };
  if (host.length > 253) return { ok: false, error: 'Hostname is longer than 253 characters.' };
  const labels = host.split('.');
  if (labels.length < 2) return { ok: false, error: 'Enter a fully qualified domain (e.g. example.com).' };
  for (const l of labels) {
    if (!LABEL_RE.test(l)) {
      return { ok: false, error: `Invalid hostname label "${l || '(empty)'}".` };
    }
  }
  const tld = labels[labels.length - 1]!;
  if (/^\d+$/.test(tld)) return { ok: false, error: 'The top-level domain cannot be numeric.' };
  if (!/^[a-z]{2,63}$/.test(tld) && !/^xn--[a-z0-9-]+$/.test(tld)) {
    return { ok: false, error: `"${tld}" is not a valid top-level domain.` };
  }

  const unicode = toUnicode(host);
  return { ok: true, domain: host, unicode, isIdn: unicode !== host };
}

/**
 * Accept a domain, URL, email address or defanged text; return the ASCII and
 * Unicode hostnames, or an inline error message. In pasted sentences the first
 * token that yields a valid hostname wins (URLs first, then host-like tokens),
 * so "Mr. Smith reported evil.example" finds evil.example.
 */
export function normalizeInput(raw: string): NormalizeResult {
  const refanged = refang(raw.normalize('NFC')).trim();
  if (!refanged) return { ok: false, error: 'Enter a domain or URL.' };

  const tokens = refanged
    .split(/\s+/)
    .map((t) => {
      const s = t.replace(TRIM_RE, '');
      // Keep the closing bracket of an IPv6 URL host: http://[2001:db8::1]
      return s.lastIndexOf('[') > s.lastIndexOf(']') && t.lastIndexOf(']') > t.lastIndexOf('[') ? `${s}]` : s;
    })
    .filter(Boolean);
  if (!tokens.length) return { ok: false, error: NO_HOST };

  const urls = tokens.filter((t) => SCHEME_RE.test(t));
  const hostish = tokens.filter((t) => !SCHEME_RE.test(t) && (HOSTISH_RE.test(t) || isIPv6Token(t)));
  const candidates = urls.length + hostish.length ? [...urls, ...hostish] : [tokens[0]!];

  let first: NormalizeResult | undefined;
  let sawIp = false;
  for (const c of candidates) {
    const r = fromToken(c);
    if (r.ok) return r;
    if (r.error === IP_ERROR) sawIp = true;
    first ??= r;
  }
  return sawIp ? { ok: false, error: IP_ERROR } : (first ?? { ok: false, error: NO_HOST });
}
