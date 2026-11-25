import { describe, expect, it } from 'vitest';
import { decodeDataUri, iconCandidates, isInternalHost, sniffImage, type DocLike } from '@/lib/homepage';
import { FAVICON_MISS_TTL, createFaviconModule } from '@/modules/favicon';
import fixtures from './fixtures/favicon-hashes.json';
import { bytes, makeCtx, mockFetch, text } from './helpers';

/**
 * Node has no DOMParser; production uses the browser's. This fake extracts
 * <link>/<base> attributes only, which is all iconCandidates() reads.
 */
function fakeParse(html: string): DocLike {
  const tags = [...html.matchAll(/<(link|base)\b([^>]*)>/gi)].map((m) => {
    const attrs: Record<string, string> = {};
    for (const a of m[2]!.matchAll(/([a-z-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)) {
      attrs[a[1]!.toLowerCase()] = a[2] ?? a[3] ?? a[4] ?? '';
    }
    return { tag: m[1]!.toLowerCase(), attrs };
  });
  const el = (attrs: Record<string, string>) => ({ getAttribute: (n: string) => attrs[n.toLowerCase()] ?? null });
  return {
    querySelector: (sel) => {
      const b = sel.startsWith('base') ? tags.find((t) => t.tag === 'base' && t.attrs['href'] !== undefined) : undefined;
      return b ? el(b.attrs) : null;
    },
    querySelectorAll: () =>
      tags.filter((t) => t.tag === 'link' && t.attrs['rel'] !== undefined && t.attrs['href'] !== undefined).map((t) => el(t.attrs)),
  };
}

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// A real-looking ICO: valid header + fixture payload so hashes are predictable.
const ICO = hexToBytes('00000100' + fixtures.favicon[9]!.hex.slice(8));
const PNG = hexToBytes('89504e470d0a1a0a' + '00'.repeat(24));

describe('iconCandidates', () => {
  it('finds rel~=icon links in order, resolves against <base>, appends /favicon.ico', () => {
    const doc = fakeParse(`
      <base href="https://cdn.example.com/assets/">
      <link rel="apple-touch-icon" href="/apple.png">
      <link rel="SHORTCUT ICON" href="fav.ico">
      <link rel="icon" sizes="32x32" type="image/png" href="https://static.example.com/i32.png">
      <link rel="icon" href="fav.ico">
      <link rel="stylesheet" href="x.css">
      <link rel="mask-icon" href="mask.svg">`);
    const c = iconCandidates(doc, 'https://www.example.com/home');
    expect(c.map((x) => x.url)).toEqual([
      'https://cdn.example.com/assets/fav.ico',
      'https://static.example.com/i32.png',
      'https://www.example.com/favicon.ico',
    ]);
    expect(c[1]).toMatchObject({ source: 'link', sizes: '32x32', type: 'image/png' });
    expect(c[2]!.source).toBe('default');
  });

  it('keeps data: URIs and drops javascript: hrefs', () => {
    const doc = fakeParse(`<link rel="icon" href="javascript:alert(1)"><link rel="icon" href="data:image/png;base64,iVBORw0KGgo=">`);
    const c = iconCandidates(doc, 'https://example.com/');
    expect(c.map((x) => x.url)).toEqual(['data:image/png;base64,iVBORw0KGgo=', 'https://example.com/favicon.ico']);
  });
});

describe('sniffImage / decodeDataUri', () => {
  it.each([
    [ICO, null, 'image/x-icon'],
    [PNG, 'text/plain', 'image/png'],
    [new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"></svg>'), 'image/svg+xml', 'image/svg+xml'],
    [new TextEncoder().encode('<!doctype html><html>Not found</html>'), 'image/x-icon', null],
    [new TextEncoder().encode('<html>soft 404</html>'), 'text/html', null],
  ])('sniff %#', (b, ct, expected) => {
    expect(sniffImage(b, ct)).toBe(expected);
  });

  it('decodes base64 and percent-encoded data URIs', () => {
    expect(decodeDataUri('data:image/png;base64,iVBORw0KGgo=')?.bytes.slice(0, 4)).toEqual(new Uint8Array([0x89, 0x50, 0x4e, 0x47]));
    expect(decodeDataUri('data:image/svg+xml,%3Csvg%3E%3C/svg%3E')?.contentType).toBe('image/svg+xml');
    expect(decodeDataUri('nope')).toBeNull();
  });

  it('percent-decodes data: URIs to raw bytes (non-UTF-8 octets) and before base64', () => {
    // decodeURIComponent throws on %89, so a percent-encoded PNG was "undecodable".
    expect(decodeDataUri('data:image/png,%89PNG%0D%0A%1A%0A')?.bytes).toEqual(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
    // UTF-8 text stays UTF-8.
    expect(new TextDecoder().decode(decodeDataUri('data:image/svg+xml,<svg>é</svg>')!.bytes)).toBe('<svg>é</svg>');
    // %2B / %3D inside base64 (Fetch standard: percent-decode first).
    expect(decodeDataUri('data:image/png;base64,iVBORw0KGgo%3D')?.bytes.slice(0, 4)).toEqual(new Uint8Array([0x89, 0x50, 0x4e, 0x47]));
    expect(decodeDataUri('data:image/png;base64,***')).toBeNull();
  });

  it('rejects text bodies whatever the Content-Type claims, accepts unknown binary image types', () => {
    const enc = (s: string) => new TextEncoder().encode(s);
    expect(sniffImage(enc('Not Found'), 'image/png')).toBeNull();
    expect(sniffImage(enc('{"error":"not found"}'), 'image/x-icon')).toBeNull();
    expect(sniffImage(enc('<head><title>404</title></head>'), 'image/x-icon')).toBeNull();
    expect(sniffImage(enc('<!-- soft 404 --><html></html>'), 'image/vnd.microsoft.icon')).toBeNull();
    // AVIF: ftyp box, binary.
    const avif = new Uint8Array([0, 0, 0, 0x1c, ...enc('ftypavif'), 0, 0, 0, 0]);
    expect(sniffImage(avif, 'image/avif')).toBe('image/avif');
    expect(sniffImage(avif, 'application/octet-stream')).toBeNull();
  });

  it('recognises SVGs behind an XML declaration, comments or an SVG doctype', () => {
    const svg = (s: string) => sniffImage(new TextEncoder().encode(s), 'text/plain');
    expect(svg('<?xml version="1.0"?>\n<!-- Generator: Adobe Illustrator -->\n<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n<svg xmlns="http://www.w3.org/2000/svg"/>')).toBe('image/svg+xml');
    expect(svg('<!-- icon --><svg viewBox="0 0 1 1"></svg>')).toBe('image/svg+xml');
    expect(svg('<svgx></svgx>')).toBeNull();
    expect(svg('<!doctype html><svg></svg>')).toBeNull();
  });
});

describe('isInternalHost', () => {
  it.each([
    ['127.0.0.1', true],
    ['192.168.1.1', true],
    ['[::1]', true],
    ['[fd00::1]', true],
    ['localhost', true],
    ['intranet', true],
    ['printer.local', true],
    ['nas.home.arpa', true],
    ['db.internal', true],
    ['8.8.8.8', false],
    ['[2606:4700::1111]', false],
    ['example.com', false],
    ['cdn.example.co.uk.', false],
  ])('%s -> %s', (host, expected) => {
    expect(isInternalHost(host)).toBe(expected);
  });
});

describe('favicon module', () => {
  const mod = createFaviconModule(fakeParse);
  const entity = { kind: 'domain' as const, value: 'example.com', depth: 0 };

  it('is active (OPSEC-gated)', () => {
    expect(mod.active).toBe(true);
  });

  it('hashes the link icon and /favicon.ico, emits hash pivots and a Shodan link', async () => {
    const m = mockFetch(
      (u) => (u.href === 'https://example.com/' ? text('<link rel="icon" href="/static/icon.png">') : undefined),
      (u) => (u.pathname === '/static/icon.png' ? bytes(PNG, 200, 'image/png') : undefined),
      (u) => (u.pathname === '/favicon.ico' ? bytes(ICO) : undefined),
    );
    const out = await mod.run(entity, makeCtx({ fetch: m.fetch }));
    expect(out.data.icons).toHaveLength(2);
    const ico = out.data.icons.find((i) => i.source === 'default')!;
    const { mmh3 } = await import('@/lib/favhash').then((x) => ({ mmh3: x.shodanFaviconHash(ICO) }));
    expect(ico.mmh3).toBe(mmh3);
    expect(ico.shodanUrl).toBe(`https://www.shodan.io/search?query=http.favicon.hash%3A${mmh3}`);
    expect(out.pivots?.filter((p) => p.kind === 'hash')).toHaveLength(6);
    expect(out.pivots?.[0]?.note).toContain('mmh3');
    // never sends cookies/referrer to the target
    expect(m.calls.every((c) => c.init.credentials === 'omit' && c.init.referrerPolicy === 'no-referrer')).toBe(true);
  });

  it('matches the Python fixture for /favicon.ico bytes', async () => {
    const raw = hexToBytes(fixtures.favicon[0 + 1]!.hex); // "one byte" is not an image: wrap it as an ICO payload
    const icoBytes = new Uint8Array([0, 0, 1, 0, ...raw]);
    const m = mockFetch(
      (u) => (u.pathname === '/' ? text('<html></html>') : undefined),
      (u) => (u.pathname === '/favicon.ico' ? bytes(icoBytes) : undefined),
    );
    const out = await mod.run(entity, makeCtx({ fetch: m.fetch }));
    const { shodanFaviconHash, md5Hex } = await import('@/lib/favhash');
    expect(out.data.icons[0]).toMatchObject({ mmh3: shodanFaviconHash(icoBytes), md5: md5Hex(icoBytes), source: 'default' });
  });

  it('dedupes identical link icon and /favicon.ico', async () => {
    const m = mockFetch(
      (u) => (u.pathname === '/' ? text('<link rel="icon" href="/favicon.ico?v=2">') : undefined),
      (u) => (u.pathname === '/favicon.ico' ? bytes(ICO) : undefined),
    );
    const out = await mod.run(entity, makeCtx({ fetch: m.fetch }));
    expect(out.data.icons).toHaveLength(1);
  });

  it('falls back to /favicon.ico when the homepage fails, and rejects soft-404 HTML', async () => {
    const m = mockFetch(
      (u) => (u.pathname === '/' ? Promise.reject(new TypeError('NetworkError')) : undefined),
      (u) => (u.pathname === '/favicon.ico' ? text('<!doctype html><title>404</title>', 200) : undefined),
    );
    const out = await mod.run(entity, makeCtx({ fetch: m.fetch }));
    expect(out.data.icons).toHaveLength(0);
    expect(out.data.pageError).toMatch(/Network/);
    expect(out.summary).toMatch(/No favicon/);
    expect(out.data.attempts[0]!.outcome).toMatch(/not an image/);
  });

  it('decodes an inline data: icon without fetching it', async () => {
    const m = mockFetch(
      (u) => (u.pathname === '/' ? text('<link rel="icon" href="data:image/png;base64,iVBORw0KGgoAAAAA">') : undefined),
      (u) => (u.pathname === '/favicon.ico' ? new Response('', { status: 404 }) : undefined),
    );
    const out = await mod.run(entity, makeCtx({ fetch: m.fetch }));
    expect(out.data.icons[0]).toMatchObject({ url: 'data:', contentType: 'image/png' });
    expect(m.calls.some((c) => c.url.startsWith('data:'))).toBe(false);
  });

  it('refuses icon URLs on private or internal hosts without contacting them', async () => {
    const m = mockFetch(
      (u) =>
        u.href === 'https://example.com/'
          ? text('<link rel="icon" href="https://192.168.0.1/admin/reboot"><link rel="icon" href="http://localhost:8080/x.ico"><link rel="icon" href="/ok.png">')
          : undefined,
      (u) => (u.pathname === '/ok.png' ? bytes(PNG, 200, 'image/png') : undefined),
      (u) => (u.pathname === '/favicon.ico' ? new Response('', { status: 404 }) : undefined),
    );
    const out = await mod.run(entity, makeCtx({ fetch: m.fetch }));
    expect(m.calls.some((c) => /192\.168|localhost/.test(c.url))).toBe(false);
    expect(out.data.attempts.filter((a) => /refused/.test(a.outcome))).toHaveLength(2);
    expect(out.data.icons[0]).toMatchObject({ url: 'https://example.com/ok.png', contentType: 'image/png' });
  });

  it('a redirect to an internal host does not lead to a /favicon.ico request there', async () => {
    const page = text('<html></html>');
    Object.defineProperty(page, 'url', { value: 'https://10.0.0.5/login' });
    const m = mockFetch((u) => (u.href === 'https://example.com/' ? page : undefined));
    const out = await mod.run(entity, makeCtx({ fetch: m.fetch }));
    expect(m.calls).toHaveLength(1);
    expect(out.data.attempts).toEqual([{ url: 'https://10.0.0.5/favicon.ico', outcome: 'refused: private or internal host' }]);
  });

  it('caps inline data: icons like fetched ones', async () => {
    const big = `data:image/png;base64,${'A'.repeat(1_500_000)}`;
    const m = mockFetch(
      (u) => (u.pathname === '/' ? text(`<link rel="icon" href="${big}">`) : undefined),
      (u) => (u.pathname === '/favicon.ico' ? new Response('', { status: 404 }) : undefined),
    );
    const out = await mod.run(entity, makeCtx({ fetch: m.fetch }));
    expect(out.data.icons).toHaveLength(0);
    expect(out.data.attempts[0]!.outcome).toMatch(/too large/);
  });

  it('caches a miss or a failed homepage for an hour, not the module week', async () => {
    const miss = mockFetch(
      (u) => (u.pathname === '/' ? Promise.reject(new TypeError('NetworkError')) : undefined),
      (u) => (u.pathname === '/favicon.ico' ? bytes(ICO) : undefined),
    );
    const partial = await mod.run(entity, makeCtx({ fetch: miss.fetch }));
    expect(partial.data.icons).toHaveLength(1);
    expect(partial.ttl).toBe(FAVICON_MISS_TTL);

    const none = mockFetch(
      (u) => (u.pathname === '/' ? text('<html></html>') : undefined),
      (u) => (u.pathname === '/favicon.ico' ? new Response('', { status: 503 }) : undefined),
    );
    expect((await mod.run(entity, makeCtx({ fetch: none.fetch }))).ttl).toBe(FAVICON_MISS_TTL);

    const ok = mockFetch(
      (u) => (u.pathname === '/' ? text('<html></html>') : undefined),
      (u) => (u.pathname === '/favicon.ico' ? bytes(ICO) : undefined),
    );
    expect((await mod.run(entity, makeCtx({ fetch: ok.fetch }))).ttl).toBeUndefined();
    expect(FAVICON_MISS_TTL).toBeLessThan(mod.ttl);
  });

  it('shares one homepage + favicon fetch per run (for the AI module)', async () => {
    const m = mockFetch(
      (u) => (u.pathname === '/' ? text('<html></html>') : undefined),
      (u) => (u.pathname === '/favicon.ico' ? bytes(ICO) : undefined),
    );
    const ctx = makeCtx({ fetch: m.fetch });
    await mod.run(entity, ctx);
    const { getFavicons } = await import('@/lib/homepage');
    const again = await getFavicons(ctx, 'example.com', fakeParse);
    expect(again.icons[0]!.bytes).toEqual(ICO);
    expect(m.calls).toHaveLength(2);
  });
});
