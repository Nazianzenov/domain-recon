/**
 * Punycode (RFC 3492) decoder for display only. Encoding to ASCII is done by
 * the browser's URL parser (`new URL()`), which also applies IDNA mapping;
 * browsers expose no toUnicode(), so we decode A-labels ourselves.
 */

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - TMIN) * TMAX) >> 1) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
}

function basicToDigit(cp: number): number {
  if (cp >= 0x30 && cp < 0x3a) return cp - 22; // 0-9 -> 26-35
  if (cp >= 0x41 && cp < 0x5b) return cp - 0x41; // A-Z
  if (cp >= 0x61 && cp < 0x7b) return cp - 0x61; // a-z
  return BASE;
}

/** Decode one Punycode label (without the "xn--" prefix). Throws on malformed input. */
export function decodeLabel(input: string): string {
  const output: number[] = [];
  let i = 0;
  let n = INITIAL_N;
  let bias = INITIAL_BIAS;
  let basic = input.lastIndexOf('-');
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) {
    const c = input.charCodeAt(j);
    if (c >= 0x80) throw new RangeError('Illegal input >= 0x80');
    output.push(c);
  }
  for (let index = basic > 0 ? basic + 1 : 0; index < input.length; ) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) throw new RangeError('Invalid input');
      const digit = basicToDigit(input.charCodeAt(index++));
      if (digit >= BASE) throw new RangeError('Invalid input');
      i += digit * w;
      if (i > 0x7fffffff) throw new RangeError('Overflow');
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
      if (w > 0x7fffffff) throw new RangeError('Overflow');
    }
    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    n += Math.floor(i / out);
    if (n > 0x10ffff) throw new RangeError('Overflow');
    if (n >= 0xd800 && n <= 0xdfff) throw new RangeError('Surrogate code point');
    i %= out;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

/**
 * A decoded label is shown only if it could be a real U-label: non-empty, with at
 * least one non-ASCII code point (`xn--a-` decodes to plain "a", which would let
 * `xn--a-.com` display as "a.com"), and nothing invisible or separator-like
 * (controls, format characters such as bidi overrides, spaces, dot look-alikes).
 */
const UNSAFE_DISPLAY_RE = /[\p{C}\p{Z}.。．｡․﹒]/u;

function displayable(u: string): boolean {
  return u.length > 0 && /[^\x00-\x7f]/.test(u) && !UNSAFE_DISPLAY_RE.test(u);
}

/** Convert an ASCII hostname to Unicode for display; invalid labels are left as-is. */
export function toUnicode(hostname: string): string {
  return hostname
    .split('.')
    .map((label) => {
      if (!/^xn--/i.test(label)) return label;
      try {
        const u = decodeLabel(label.slice(4).toLowerCase());
        return displayable(u) ? u : label;
      } catch {
        return label;
      }
    })
    .join('.');
}
