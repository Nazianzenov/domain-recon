import { toBase64 } from './favhash';

/**
 * Compact evidence pack for the AI brand check, built from the fetched
 * homepage. Raw HTML is never sent: only these extracted fields.
 */

export const TEXT_LIMIT = 4000;

export interface PageView {
  title(): string | null;
  /** <meta name=...> or <meta property=...> content. */
  meta(key: string): string | null;
  /** All og:* meta properties. */
  openGraph(): Array<[string, string]>;
  /** Visible body text (scripts/styles/templates removed), whitespace collapsed. */
  text(): string;
  images(): Array<{ alt: string; src: string; cls: string; id: string }>;
  /**
   * `submitActions`: formaction attributes of the form's submit buttons, which
   * override `action` when that button submits (a common way to hide the real target).
   */
  forms(): Array<{ action: string | null; method: string | null; hasPassword: boolean; submitActions?: string[] }>;
  passwordInputs(): number;
  /** <base href>: relative URLs (images, non-empty form actions) resolve against it. */
  baseHref?(): string | null;
}

export interface Evidence {
  url: string;
  status: number;
  title: string | null;
  description: string | null;
  openGraph: Record<string, string>;
  text: string;
  textTruncated: boolean;
  logos: Array<{ alt: string; src: string }>;
  forms: Array<{ actionHost: string | null; method: string; hasPassword: boolean }>;
  /** Every host a form (or a submit button's formaction) submits to. */
  formActionHosts: string[];
  /** Hosts that forms containing a password field submit to. */
  passwordFormHosts: string[];
  hasPasswordInput: boolean;
  favicon: { width: number; height: number } | null;
}

/**
 * First n UTF-16 units without splitting a surrogate pair: a lone surrogate
 * in the JSON body makes the Messages API reject the request (400).
 */
export function cut(s: string, n: number): string {
  if (s.length <= n) return s;
  const last = s.charCodeAt(n - 1);
  return s.slice(0, last >= 0xd800 && last <= 0xdbff ? n - 1 : n);
}
const clip = (s: string, n: number) => (s.length > n ? `${cut(s, n)}…` : s);
const clean = (s: string | null | undefined) => (s ?? '').replace(/\s+/g, ' ').trim();

/**
 * Host a form submits to. HTML: an empty/missing action submits to the
 * document's own URL; a non-empty relative one resolves against <base href>.
 */
function hostOf(href: string | null, base: string, pageUrl: string): string | null {
  try {
    const h = href?.trim();
    const u = h ? new URL(h, base) : new URL(pageUrl);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.hostname.replace(/\.+$/, '') : null;
  } catch {
    return null;
  }
}

function resolveBase(href: string | null | undefined, pageUrl: string): string {
  if (!href || !href.trim()) return pageUrl;
  try {
    const u = new URL(href.trim(), pageUrl);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : pageUrl;
  } catch {
    return pageUrl;
  }
}

const isDataUri = (s: string) => /^\s*data:/i.test(s);

function srcFor(src: string, base: string): string {
  if (isDataUri(src)) return 'data:… (inline image)';
  try {
    return clip(new URL(src, base).href, 200);
  } catch {
    return clip(src, 200);
  }
}

/**
 * Is `host` the investigated domain, one of its subdomains, or a parent of it?
 * Label boundaries only: evil-example.com is not example.com.
 */
export function isSameSite(host: string, domain: string): boolean {
  const h = host.toLowerCase().replace(/\.+$/, '');
  const d = domain.toLowerCase().replace(/\.+$/, '');
  if (!h || !d) return false;
  // A bare TLD ("com") is nobody's parent site.
  return h === d || h.endsWith(`.${d}`) || (h.includes('.') && d.endsWith(`.${h}`));
}

/** og:* properties whose value is a URL (resolved, and never sent when it is a data: URI). */
const OG_URL_KEY = /^og:(?:url|(?:image|video|audio)(?::url|:secure_url)?)$/;

export function buildEvidence(view: PageView, pageUrl: string, status: number): Evidence {
  const base = resolveBase(view.baseHref?.(), pageUrl);
  const og: Record<string, string> = {};
  for (const [k, v] of view.openGraph().slice(0, 12)) {
    if (OG_URL_KEY.test(k) || isDataUri(v)) og[k] = srcFor(v, base);
    else og[k] = clip(clean(v), 300);
  }
  const fullText = clean(view.text());
  const logos = view
    .images()
    .filter((i) => /logo|brand/i.test(`${i.alt} ${i.src} ${i.cls} ${i.id}`))
    .slice(0, 5)
    .map((i) => ({ alt: clip(clean(i.alt), 120), src: srcFor(i.src, base) }));
  const forms: Evidence['forms'] = [];
  const formActionHosts = new Set<string>();
  const passwordFormHosts = new Set<string>();
  // Targets are collected from more forms than are listed, so decoy forms cannot push the
  // credential form out of view.
  for (const [i, f] of view.forms().slice(0, 100).entries()) {
    const actionHost = hostOf(f.action, base, pageUrl);
    if (i < 10) forms.push({ actionHost, method: (f.method ?? 'get').toLowerCase(), hasPassword: f.hasPassword });
    const hosts = [actionHost, ...(f.submitActions ?? []).slice(0, 5).map((a) => hostOf(a, base, pageUrl))];
    for (const h of hosts) {
      if (!h) continue;
      formActionHosts.add(h);
      if (f.hasPassword) passwordFormHosts.add(h);
    }
  }
  return {
    url: pageUrl,
    status,
    title: clip(clean(view.title()), 300) || null,
    description: clip(clean(view.meta('description')), 500) || null,
    openGraph: og,
    text: cut(fullText, TEXT_LIMIT),
    textTruncated: fullText.length > TEXT_LIMIT,
    logos,
    forms,
    formActionHosts: [...formActionHosts],
    passwordFormHosts: [...passwordFormHosts],
    hasPasswordInput: view.passwordInputs() > 0,
    favicon: null,
  };
}

/**
 * Make untrusted text unable to open or close any tag, our <page_content>
 * wrapper included. Every "<" (and its full-width/small look-alikes) becomes
 * "‹", which covers case, whitespace, attribute and zero-width-character
 * variants alike. Idempotent.
 */
export function escapeForWrapper(s: string): string {
  return s.replace(/[<＜﹤]/g, '‹');
}

/** Render the evidence as the untrusted block placed inside <page_content> tags. */
export function renderEvidence(e: Evidence): string {
  const lines = [
    `URL: ${e.url}`,
    `HTTP status: ${e.status}`,
    `Title: ${e.title ?? '(none)'}`,
    `Meta description: ${e.description ?? '(none)'}`,
  ];
  const og = Object.entries(e.openGraph);
  lines.push(`Open Graph: ${og.length ? og.map(([k, v]) => `${k}=${v}`).join(' | ') : '(none)'}`);
  lines.push(
    `Logo images: ${e.logos.length ? e.logos.map((l) => `alt="${l.alt}" src=${l.src}`).join(' | ') : '(none found)'}`,
  );
  lines.push(
    `Forms: ${e.forms.length}${e.forms.length ? ` (submit to: ${e.formActionHosts.join(', ') || 'same page'})` : ''}`,
  );
  lines.push(`Password input present: ${e.hasPasswordInput ? 'yes' : 'no'}`);
  lines.push(`Favicon image attached: ${e.favicon ? `yes (${e.favicon.width}x${e.favicon.height} PNG)` : 'no'}`);
  lines.push(`Visible text (first ${TEXT_LIMIT} characters${e.textTruncated ? ', truncated' : ''}):`);
  lines.push(e.text || '(no visible text)');
  return escapeForWrapper(lines.join('\n'));
}

/** Browser implementation of PageView over an inert DOMParser document. */
export function domPageView(doc: Document): PageView {
  return {
    title: () => doc.title || null,
    meta: (key) =>
      doc.querySelector(`meta[name="${key}" i]`)?.getAttribute('content') ??
      doc.querySelector(`meta[property="${key}" i]`)?.getAttribute('content') ??
      null,
    openGraph: () =>
      Array.from(doc.querySelectorAll('meta[property^="og:" i][content]')).map(
        (m) => [(m.getAttribute('property') ?? '').toLowerCase(), m.getAttribute('content') ?? ''] as [string, string],
      ),
    text: () => {
      const body = doc.body;
      if (!body) return '';
      const clone = body.cloneNode(true) as HTMLElement;
      clone.querySelectorAll('script,style,noscript,template,svg,iframe,object,canvas').forEach((n) => n.remove());
      return clone.textContent ?? '';
    },
    images: () =>
      Array.from(doc.querySelectorAll('img')).map((img) => ({
        alt: img.getAttribute('alt') ?? '',
        src: img.getAttribute('src') ?? '',
        cls: img.getAttribute('class') ?? '',
        id: img.getAttribute('id') ?? '',
      })),
    forms: () =>
      Array.from(doc.querySelectorAll('form')).map((f) => ({
        action: f.getAttribute('action'),
        method: f.getAttribute('method'),
        hasPassword: !!f.querySelector('input[type="password" i]'),
        submitActions: Array.from(f.querySelectorAll('button[formaction], input[formaction]')).map(
          (b) => b.getAttribute('formaction') ?? '',
        ),
      })),
    passwordInputs: () => doc.querySelectorAll('input[type="password" i]').length,
    baseHref: () => doc.querySelector('base[href]')?.getAttribute('href') ?? null,
  };
}

/**
 * Favicon -> PNG via OffscreenCanvas for the vision input. Tiny icons are
 * upscaled (nearest-neighbour) to 64 px, large ones capped at 256 px.
 * Returns null when the image cannot be decoded (e.g. some SVG/ICO files).
 */
export async function faviconToPng(
  bytes: Uint8Array,
  contentType: string,
): Promise<{ base64: string; width: number; height: number } | null> {
  if (typeof OffscreenCanvas === 'undefined' || typeof createImageBitmap === 'undefined') return null;
  let bmp: ImageBitmap | undefined;
  try {
    bmp = await createImageBitmap(new Blob([bytes.slice()], { type: contentType }));
    if (!bmp.width || !bmp.height) return null;
    const max = Math.max(bmp.width, bmp.height);
    const scale = max < 64 ? 64 / max : max > 256 ? 256 / max : 1;
    const w = Math.max(1, Math.round(bmp.width * scale));
    const h = Math.max(1, Math.round(bmp.height * scale));
    const canvas = new OffscreenCanvas(w, h);
    const g = canvas.getContext('2d');
    if (!g) return null;
    g.imageSmoothingEnabled = scale < 1;
    g.drawImage(bmp, 0, 0, w, h);
    const blob = await canvas.convertToBlob({ type: 'image/png' });
    return { base64: toBase64(new Uint8Array(await blob.arrayBuffer())), width: w, height: h };
  } catch {
    return null;
  } finally {
    bmp?.close();
  }
}
