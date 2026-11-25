import { isAbortError } from './http';
import { isPublicIp, normalizeIp } from './ip';
import type { Ctx, TextResponse } from './types';

/**
 * ACTIVE helpers: these contact the investigated site directly. Only active
 * (OPSEC-gated) modules may call them. Results are memoised per
 * investigation so the favicon and AI modules share one homepage fetch and
 * one favicon download.
 */

const HTML_MAX_BYTES = 2 * 1024 * 1024;
const ICON_MAX_BYTES = 1024 * 1024;
const MAX_LINK_CANDIDATES = 3;
const ERROR_STATUSES = Array.from({ length: 200 }, (_, i) => 400 + i);

export interface Homepage {
  requestedUrl: string;
  /** Final URL after redirects. */
  url: string;
  status: number;
  contentType: string | null;
  html: string;
  /** Final host differs from the requested one (e.g. redirect to a login provider). */
  redirectedOffsite: boolean;
}

/**
 * GET https://<domain>/ (error statuses still return their body). Plain-HTTP
 * sites cannot be fetched: the default MV3 CSP upgrades insecure requests.
 */
export function getHomepage(ctx: Pick<Ctx, 'fetchText' | 'shared'>, domain: string): Promise<Homepage> {
  return ctx.shared.memo(`homepage:${domain}`, async () => {
    const requestedUrl = `https://${domain}/`;
    const res: TextResponse = await ctx.fetchText(requestedUrl, {
      okStatuses: ERROR_STATUSES,
      maxBytes: HTML_MAX_BYTES,
      rateLimit: false,
    });
    let finalHost = domain;
    try {
      finalHost = new URL(res.url).hostname;
    } catch {
      /* keep requested host */
    }
    return {
      requestedUrl,
      url: res.url || requestedUrl,
      status: res.status,
      contentType: res.contentType,
      html: res.text,
      redirectedOffsite: finalHost !== domain && !finalHost.endsWith(`.${domain}`) && !domain.endsWith(`.${finalHost}`),
    };
  });
}

/** Parse fetched HTML into an inert Document (never attached, scripts never run, nothing loads). */
export function parseHtml(html: string): Document {
  return new DOMParser().parseFromString(html, 'text/html');
}

/** Structural subset of Document/Element used by the extractors (lets tests use fakes). */
export interface ElLike {
  getAttribute(name: string): string | null;
}
export interface DocLike {
  querySelector(sel: string): ElLike | null;
  querySelectorAll(sel: string): Iterable<ElLike> | ArrayLike<ElLike>;
}

export interface IconCandidate {
  url: string;
  source: 'link' | 'default';
  rel?: string;
  sizes?: string;
  type?: string;
}

function toArray<T>(x: Iterable<T> | ArrayLike<T>): T[] {
  return Array.from(x as ArrayLike<T>);
}

function resolveUrl(href: string, base: string): string | null {
  try {
    const u = new URL(href.trim(), base);
    return u.protocol === 'https:' || u.protocol === 'http:' || u.protocol === 'data:' ? u.href : null;
  } catch {
    return null;
  }
}

/**
 * <link rel~="icon"> candidates in document order (honouring <base href>),
 * followed by /favicon.ico at the page's origin.
 */
export function iconCandidates(doc: DocLike, pageUrl: string): IconCandidate[] {
  const baseHref = doc.querySelector('base[href]')?.getAttribute('href');
  const base = (baseHref && resolveUrl(baseHref, pageUrl)) || pageUrl;
  const out: IconCandidate[] = [];
  const seen = new Set<string>();
  for (const el of toArray(doc.querySelectorAll('link[rel][href]'))) {
    const rel = (el.getAttribute('rel') ?? '').toLowerCase();
    if (!rel.split(/\s+/).includes('icon')) continue;
    const url = resolveUrl(el.getAttribute('href') ?? '', base);
    if (!url || seen.has(url)) continue;
    seen.add(url);
    const sizes = el.getAttribute('sizes');
    const type = el.getAttribute('type');
    out.push({ url, source: 'link', rel, ...(sizes ? { sizes } : {}), ...(type ? { type } : {}) });
  }
  try {
    const def = new URL('/favicon.ico', pageUrl).href;
    if (!seen.has(def)) out.push({ url: def, source: 'default' });
  } catch {
    /* ignore */
  }
  return out;
}

/** Names that only resolve inside a network (RFC 6761/6762/8375, ICANN .internal, common intranet suffixes). */
const INTERNAL_SUFFIX_RE = /\.(?:localhost|local|internal|intranet|lan|corp|private|home\.arpa)$/;

/**
 * A fetched page decides which icon URLs we request. Refuse loopback,
 * private and reserved IP literals and intranet-style names, so a hostile
 * page cannot make the investigator's browser probe their own network.
 */
export function isInternalHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  const ip = normalizeIp(h);
  if (ip) return !isPublicIp(ip);
  return !h.includes('.') || INTERNAL_SUFFIX_RE.test(h);
}

/** No C0 control bytes (other than tab/LF/VT/FF/CR/ESC) in the sample: text, not an image. */
function looksLikeText(sample: Uint8Array): boolean {
  if (sample.length === 0) return false;
  for (const c of sample) {
    if (c < 0x09 || (c > 0x0d && c < 0x20 && c !== 0x1b)) return false;
  }
  return true;
}

/** Skip an XML declaration, comments and an SVG doctype before the root element. */
function rootMarkup(bytes: Uint8Array): string {
  let s = new TextDecoder().decode(bytes.subarray(0, 1024)).trimStart();
  for (;;) {
    const m = /^(?:<\?xml[\s\S]*?\?>|<!--[\s\S]*?-->|<!doctype\s+svg[^>]*>)\s*/i.exec(s);
    if (!m) return s;
    s = s.slice(m[0].length);
  }
}

/** Recognise real image bytes (rejects soft-404 HTML/text served as /favicon.ico). */
export function sniffImage(bytes: Uint8Array, contentType: string | null): string | null {
  const b = bytes;
  const startsWith = (...sig: number[]) => sig.every((v, i) => b[i] === v);
  if (startsWith(0x00, 0x00, 0x01, 0x00)) return 'image/x-icon';
  if (startsWith(0x89, 0x50, 0x4e, 0x47)) return 'image/png';
  if (startsWith(0x47, 0x49, 0x46, 0x38)) return 'image/gif';
  if (startsWith(0xff, 0xd8, 0xff)) return 'image/jpeg';
  if (startsWith(0x42, 0x4d)) return 'image/bmp';
  if (startsWith(0x52, 0x49, 0x46, 0x46) && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return 'image/webp';
  if (/^<svg[\s>/]/i.test(rootMarkup(b))) return 'image/svg+xml';
  const ct = (contentType ?? '').split(';')[0]!.trim().toLowerCase();
  // Other image types are trusted only when the bytes are binary: a soft 404 is
  // markup, JSON or plain text whatever Content-Type the server claims.
  if (ct.startsWith('image/') && !looksLikeText(b.subarray(0, 512))) return ct;
  return null;
}

/** URL percent-decoding to raw bytes (decodeURIComponent rejects non-UTF-8 octets such as %89). */
function percentDecodeBytes(s: string): Uint8Array {
  const out: number[] = [];
  const enc = new TextEncoder();
  for (let i = 0; i < s.length; ) {
    const c = s.charCodeAt(i);
    if (c === 0x25 && /^[0-9a-f]{2}$/i.test(s.slice(i + 1, i + 3))) {
      out.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 3;
    } else if (c < 0x80) {
      out.push(c);
      i += 1;
    } else {
      const ch = String.fromCodePoint(s.codePointAt(i)!);
      for (const x of enc.encode(ch)) out.push(x);
      i += ch.length;
    }
  }
  return new Uint8Array(out);
}

/** data: URL body -> bytes, as the Fetch standard does: percent-decode, then (if ;base64) forgiving base64. */
export function decodeDataUri(uri: string): { bytes: Uint8Array; contentType: string } | null {
  const m = /^data:([^,]*?)(;\s*base64)?\s*,(.*)$/is.exec(uri);
  if (!m) return null;
  const contentType = (m[1]!.trim() || 'text/plain').toLowerCase();
  try {
    const raw = percentDecodeBytes(m[3]!);
    if (m[2]) {
      let s = '';
      for (const x of raw) s += String.fromCharCode(x);
      const bin = atob(s.replace(/[\t\n\f\r ]+/g, ''));
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return { bytes, contentType };
    }
    return { bytes: raw, contentType };
  } catch {
    return null;
  }
}

export interface FaviconBytes {
  url: string;
  source: IconCandidate['source'];
  contentType: string;
  bytes: Uint8Array;
}

export interface FaviconFetch {
  pageUrl: string | null;
  pageStatus: number | null;
  pageError?: string;
  /** Up to two icons: the first working <link> icon and /favicon.ico (when it exists). */
  icons: FaviconBytes[];
  attempts: Array<{ url: string; outcome: string }>;
}

async function fetchIcon(ctx: Pick<Ctx, 'fetchBytes'>, c: IconCandidate): Promise<FaviconBytes> {
  if (c.url.startsWith('data:')) {
    // Same cap as a fetched icon (percent-encoding needs at most 3 chars per byte).
    if (c.url.length > ICON_MAX_BYTES * 3) throw new Error('data: URI too large');
    const d = decodeDataUri(c.url);
    if (!d || d.bytes.length === 0) throw new Error('undecodable data: URI');
    if (d.bytes.length > ICON_MAX_BYTES) throw new Error('data: URI too large');
    const ct = sniffImage(d.bytes, d.contentType);
    if (!ct) throw new Error('data: URI is not an image');
    return { url: 'data:', source: c.source, contentType: ct, bytes: d.bytes };
  }
  let host = '';
  try {
    host = new URL(c.url).hostname;
  } catch {
    throw new Error('invalid URL');
  }
  if (isInternalHost(host)) throw new Error('refused: private or internal host');
  const res = await ctx.fetchBytes(c.url, { maxBytes: ICON_MAX_BYTES, rateLimit: false });
  if (res.bytes.length === 0) throw new Error('empty response');
  const ct = sniffImage(res.bytes, res.contentType);
  if (!ct) throw new Error(`not an image (${res.contentType ?? 'no content-type'})`);
  return { url: res.url || c.url, source: c.source, contentType: ct, bytes: res.bytes };
}

/**
 * Homepage -> <link rel~=icon> (max 3 tried) -> /favicon.ico. Memoised per
 * run; the bytes stay in memory for the AI module and are never cached.
 */
export function getFavicons(
  ctx: Pick<Ctx, 'fetchText' | 'fetchBytes' | 'shared'>,
  domain: string,
  parse: (html: string) => DocLike = parseHtml,
): Promise<FaviconFetch> {
  return ctx.shared.memo(`favicons:${domain}`, async () => {
    const out: FaviconFetch = { pageUrl: null, pageStatus: null, icons: [], attempts: [] };
    let candidates: IconCandidate[] = [];
    try {
      const hp = await getHomepage(ctx, domain);
      out.pageUrl = hp.url;
      out.pageStatus = hp.status;
      candidates = iconCandidates(parse(hp.html), hp.url);
    } catch (err) {
      if (isAbortError(err)) throw err;
      out.pageError = err instanceof Error ? err.message : String(err);
      candidates = [{ url: `https://${domain}/favicon.ico`, source: 'default' }];
    }
    const links = candidates.filter((c) => c.source === 'link').slice(0, MAX_LINK_CANDIDATES);
    const def = candidates.find((c) => c.source === 'default');
    for (const c of links) {
      try {
        out.icons.push(await fetchIcon(ctx, c));
        out.attempts.push({ url: c.url.slice(0, 200), outcome: 'ok' });
        break;
      } catch (err) {
        if (isAbortError(err)) throw err;
        out.attempts.push({ url: c.url.slice(0, 200), outcome: err instanceof Error ? err.message : String(err) });
      }
    }
    if (def && !out.icons.some((i) => i.url === def.url)) {
      try {
        out.icons.push(await fetchIcon(ctx, def));
        out.attempts.push({ url: def.url.slice(0, 200), outcome: 'ok' });
      } catch (err) {
        if (isAbortError(err)) throw err;
        out.attempts.push({ url: def.url.slice(0, 200), outcome: err instanceof Error ? err.message : String(err) });
      }
    }
    return out;
  });
}
