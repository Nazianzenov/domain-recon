import { isIPv6 } from './ip';

/**
 * Defang indicators so exported reports are safe to paste into tickets/chat:
 *   https://evil.example/x  -> hxxps://evil[.]example/x
 *   evil.example            -> evil[.]example
 *   аррӏе.com (IDN)         -> аррӏе[.]com
 *   1.2.3.4                 -> 1[.]2[.]3[.]4
 *   2001:db8::1             -> 2001[:]db8[:][:]1
 *   user@evil.example       -> user[@]evil[.]example
 * Already-defanged text is left alone (idempotent). Matching is deliberately
 * permissive: defanging a little prose ("Node[.]js") is harmless, a live dot is not.
 */

/** Label characters in any script (plus `_`, which browsers accept in hostnames). */
const LBL = String.raw`[\p{L}\p{M}\p{N}_-]`;
/** Dots, including the ideographic/fullwidth full stops that UTS #46 maps to "." in hostnames. */
const SEP = String.raw`[.。．｡]`;
const SEP_G = new RegExp(SEP, 'gu');
/** Separators, skipping ones already defanged as "[.]" (partly defanged input). */
const SEP_OR_DEFANGED_G = new RegExp(String.raw`\[\.\]|${SEP}`, 'gu');
const dotsAll = (s: string) => s.replace(SEP_OR_DEFANGED_G, '[.]');
/** Alphabetic TLD in any script, or an A-label. */
const TLD = String.raw`(?:xn--[a-z0-9-]+|\p{L}[\p{L}\p{M}]{1,62})`;
/**
 * At most 126 labels before the TLD (the DNS maximum) keeps matching linear;
 * the lookbehind stops a match from starting inside a label. A trailing `_` or
 * `-` may follow the TLD (`_evil.example_` is italics in chat apps).
 */
const HOST = String.raw`(?<!${LBL})(?:${LBL}+${SEP}){1,126}${TLD}(?![\p{L}\p{M}\p{N}])`;

/** Scheme not preceded by another scheme character ("_https://" counts, "sftp://" does not). */
const URL_RE = /(?<![a-z0-9+.-])(https?|ftp):\/\/([^\s/?#"'<>`]+)/giu;
const LOCAL = String.raw`[\p{L}\p{M}\p{N}._%+'-]`;
const EMAIL_RE = new RegExp(String.raw`(?<!${LOCAL})(${LOCAL}+)@(${HOST})`, 'giu');
/**
 * Dotted quads, zero-padded (192.168.001.001) and fullwidth forms included.
 * Not part of a longer dotted number: OIDs and versions like 1.3.6.1.4.1 stay.
 */
const D = String.raw`[0-9０-９]`;
const IPV4_RE = new RegExp(String.raw`(?<![\p{L}\p{N}]|\p{N}${SEP})${D}{1,3}(?:${SEP}${D}{1,3}){3}(?![\p{L}\p{N}]|${SEP}${D})`, 'gu');
const HOST_RE = new RegExp(HOST, 'giu');
/** Up to 8 colons ("1:2:3:4:5:6:7::"); brackets around it (URL hosts) are fine. */
const IPV6_CANDIDATE_RE = /(?<![\w:])(?:[0-9a-f]{0,4}:){2,8}[0-9a-f]{0,4}(?![\w:])/gi;

const NON_ASCII_RE = /[^\x00-\x7f]/;

/**
 * Ideographic/fullwidth stops only count as separators when the TLD is ASCII
 * (after NFKC, so fullwidth "ｃｏｍ" qualifies): browsers resolve "evil。com",
 * while CJK prose such as "日本語。次の文" is left alone.
 */
function defangHost(h: string): string {
  const parts = h.split(SEP_G);
  const tld = parts[parts.length - 1] ?? '';
  return NON_ASCII_RE.test(tld.normalize('NFKC')) ? h.replace(/\./g, '[.]') : h.replace(SEP_G, '[.]');
}

/** https -> hxxps, HTTP -> HXXP, ftp -> fxp. */
const defangScheme = (scheme: string) => scheme.replace(/t/gi, (t) => (t === 'T' ? 'X' : 'x'));

export function defangText(input: string): string {
  let s = input;
  // URLs: scheme and every dot of the authority (userinfo, host, port).
  s = s.replace(URL_RE, (_m, scheme: string, host: string) => `${defangScheme(scheme)}://${dotsAll(host)}`);
  s = s.replace(EMAIL_RE, (_m, user: string, domain: string) => `${user}[@]${defangHost(domain)}`);
  s = s.replace(IPV4_RE, (m) => m.replace(SEP_G, '[.]'));
  s = s.replace(HOST_RE, defangHost);
  s = s.replace(IPV6_CANDIDATE_RE, (m) => (/[0-9a-f]/i.test(m) && isIPv6(m) ? m.replace(/:/g, '[:]') : m));
  return s;
}

/**
 * Deep-defang every string value and every object key (module data can be keyed
 * by page-controlled strings such as Open Graph properties, and the IP-cap map is
 * keyed by domain). Values with toJSON (Date, URL) are defanged in their JSON form.
 */
export function defangDeep<T>(value: T): T {
  if (typeof value === 'string') return defangText(value) as T;
  if (Array.isArray(value)) return value.map((v) => defangDeep(v)) as T;
  if (value && typeof value === 'object') {
    const toJSON = (value as { toJSON?: unknown }).toJSON;
    if (typeof toJSON === 'function') return defangDeep(toJSON.call(value) as unknown) as T;
    // Null prototype: a "__proto__" key (JSON.parse creates them) stays an ordinary key.
    const out = Object.create(null) as Record<string, unknown>;
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[defangText(k)] = defangDeep(v);
    return out as T;
  }
  return value;
}
