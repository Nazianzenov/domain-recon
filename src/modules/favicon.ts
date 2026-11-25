import { faviconHashes, shodanSearchUrl } from '@/lib/favhash';
import { getFavicons, type DocLike, parseHtml } from '@/lib/homepage';
import type { Fact, Module, Pivot } from '@/lib/types';
import { DAY, HOUR } from '@/lib/types';

/**
 * TTL for a result without icons or with a failed homepage fetch: often
 * transient (timeout, 5xx, site briefly down), so not worth a week, but long
 * enough not to re-contact the target on every look.
 */
export const FAVICON_MISS_TTL = HOUR;

export interface FaviconIcon {
  url: string;
  source: 'link' | 'default';
  contentType: string;
  size: number;
  mmh3: number;
  md5: string;
  sha256: string;
  shodanUrl: string;
}

export interface FaviconData {
  pageUrl: string | null;
  pageStatus: number | null;
  pageError?: string;
  icons: FaviconIcon[];
  attempts: Array<{ url: string; outcome: string }>;
}

/** Factory so tests can inject an HTML parser (Node has no DOMParser). */
export function createFaviconModule(parse: (html: string) => DocLike = parseHtml): Module<FaviconData> {
  return {
    id: 'favicon',
    label: 'Favicon hashes',
    // v2: soft-404 text served as image/* is no longer hashed; byte-exact data: URIs.
    version: 2,
    accepts: ['domain'],
    ttl: 7 * DAY,
    active: true,
    note: 'Active: fetches the homepage and favicon from the target. HTTP-only sites cannot be fetched (MV3 upgrades insecure requests).',
    async run(e, ctx) {
      const fetched = await getFavicons(ctx, e.value, parse);
      const icons: FaviconIcon[] = [];
      const seen = new Set<string>();
      for (const icon of fetched.icons) {
        const h = await faviconHashes(icon.bytes);
        if (seen.has(h.sha256)) continue; // link icon and /favicon.ico can be the same file
        seen.add(h.sha256);
        icons.push({
          url: icon.url,
          source: icon.source,
          contentType: icon.contentType,
          size: icon.bytes.length,
          ...h,
          shodanUrl: shodanSearchUrl(h.mmh3),
        });
      }
      const data: FaviconData = {
        pageUrl: fetched.pageUrl,
        pageStatus: fetched.pageStatus,
        ...(fetched.pageError ? { pageError: fetched.pageError } : {}),
        icons,
        attempts: fetched.attempts,
      };
      if (icons.length === 0) {
        return {
          data,
          summary: fetched.pageError ? `No favicon (homepage failed: ${fetched.pageError})` : 'No favicon found',
          ttl: FAVICON_MISS_TTL,
        };
      }
      const pivots: Pivot[] = icons.flatMap((i) => [
        { kind: 'hash' as const, value: String(i.mmh3), note: `Shodan favicon mmh3 (${i.source === 'link' ? 'link icon' : '/favicon.ico'})` },
        { kind: 'hash' as const, value: i.md5, note: 'favicon MD5' },
        { kind: 'hash' as const, value: i.sha256, note: 'favicon SHA-256' },
      ]);
      const p = icons[0]!;
      return {
        data,
        pivots,
        summary: `mmh3 ${p.mmh3} · ${p.contentType.replace('image/', '')} ${p.size} B${icons.length > 1 ? ` · +${icons.length - 1} more` : ''}`,
        // Homepage failed: only /favicon.ico was tried, the page's own icon may be missing.
        ...(fetched.pageError ? { ttl: FAVICON_MISS_TTL } : {}),
      };
    },
    facts(d) {
      const facts: Fact[] = [];
      if (d.pageUrl) facts.push({ label: 'Homepage', value: `${d.pageUrl} (HTTP ${d.pageStatus ?? '?'})` });
      if (d.pageError) facts.push({ label: 'Homepage error', value: d.pageError, tone: 'warn' });
      for (const i of d.icons) {
        const where = i.source === 'link' ? 'Link icon' : '/favicon.ico';
        facts.push({ label: where, value: `${i.url === 'data:' ? 'inline data: URI' : i.url} · ${i.contentType} · ${i.size} B` });
        facts.push({ label: 'Shodan mmh3', value: String(i.mmh3), pivot: true, href: i.shodanUrl });
        facts.push({ label: 'MD5', value: i.md5, pivot: true });
        facts.push({ label: 'SHA-256', value: i.sha256, pivot: true });
      }
      const failed = d.attempts.filter((a) => a.outcome !== 'ok');
      if (failed.length) facts.push({ label: 'Skipped', value: failed.map((a) => `${a.url}: ${a.outcome}`) });
      return facts;
    },
  };
}

export const faviconModule = createFaviconModule();
