import { readdirSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import config from '../wxt.config';
import { ACTIVE_HOST_PERMISSIONS, FIXED_HOST_PERMISSIONS } from '@/lib/origins';
import { PROVIDERS } from '@/lib/settings';
import type { Entity, Module, ProviderKey } from '@/lib/types';
import { MODULES, getModule } from '@/modules';
import { createClaudeModule } from '@/modules/claude';
import { createFaviconModule } from '@/modules/favicon';
import { json, makeCtx, mockFetch, text } from './helpers';

// sysdns calls browser.dns.resolve; the AI module checks the data-collection consent.
vi.mock('@/lib/firefox', () => ({
  ff: {
    dns: { resolve: vi.fn(async () => ({ addresses: ['93.184.215.14'], isTRR: false })) },
    permissions: { contains: vi.fn(async () => true) },
  },
}));

/** WebExtension match pattern (the subset used here: scheme://host/*). */
function matchesPattern(pattern: string, url: URL): boolean {
  const m = /^(\*|https?):\/\/(\*|[a-z0-9.-]+)\/\*$/.exec(pattern);
  if (!m) throw new Error(`Unsupported match pattern ${pattern}`);
  const scheme = m[1] ?? '';
  const host = m[2] ?? '';
  const schemeOk = scheme === '*' ? url.protocol === 'http:' || url.protocol === 'https:' : url.protocol === `${scheme}:`;
  return schemeOk && (host === '*' || url.hostname === host);
}

const coveredByFixed = (url: URL) => FIXED_HOST_PERMISSIONS.some((p) => matchesPattern(p, url));

const TARGET = 'recon-target.com';
const TARGET_IP = '93.184.215.14';
/** TLD registry RDAP server from the IANA bootstrap: reached without a host permission (CORS). */
const REGISTRY = 'rdap.registry.test';
const KEYS: Record<ProviderKey, string> = {
  virustotal: 'vt-key',
  otx: 'otx-key',
  abuseipdb: 'abuseipdb-key',
  abusech: 'abusech-key',
  shodan: 'shodan-key',
  mnemonic: 'mnemonic-key',
  anthropic: 'anthropic-key',
};

const isTarget = (url: URL) => url.hostname === TARGET || url.hostname.endsWith(`.${TARGET}`) || url.hostname === TARGET_IP;

/** Answers every provider with "nothing found" / failures that push modules onto their fallbacks. */
function providerRoutes(url: URL): Response | undefined {
  switch (url.hostname) {
    case 'cloudflare-dns.com':
      return json({ error: 'unavailable' }, 503); // forces the dns.google fallback
    case 'dns.google':
      return json({ Status: 3, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: url.searchParams.get('name'), type: 1 }] });
    case 'data.iana.org':
      return json({ version: '1.0', publication: '2026-11-01T00:00:00Z', services: [[['com'], [`https://${REGISTRY}/`]]] });
    case REGISTRY:
      return json({ errorCode: 503 }, 503); // forces the rdap.org fallback
    default:
      return isTarget(url) ? undefined : json({}, 404);
  }
}

const targetSite = (url: URL): Response | undefined =>
  isTarget(url) ? (url.pathname === '/' ? text('<html><head><title>Hi</title></head><body>Hi</body></html>') : json({}, 404)) : undefined;

async function runAll(mods: readonly Module[], entity: Entity, routes = [providerRoutes]): Promise<URL[]> {
  const { fetch, calls } = mockFetch(...routes);
  for (const m of mods.filter((x) => x.accepts.includes(entity.kind))) {
    const ctx = makeCtx({ fetch, root: TARGET, keys: KEYS });
    // Errors are expected (every API answers 404 here); only the requests matter.
    await m.run(entity, ctx).catch(() => undefined);
  }
  return calls.map((c) => new URL(c.url));
}

const domainEntity: Entity = { kind: 'domain', value: TARGET, depth: 0 };
const ipEntity: Entity = { kind: 'ip', value: TARGET_IP, depth: 1 };
const passive = MODULES.filter((m) => !m.active);

describe('manifest (wxt.config.ts)', () => {
  interface ManifestShape {
    permissions?: string[];
    host_permissions?: string[];
    optional_host_permissions?: string[];
    action?: Record<string, unknown>;
    content_security_policy?: unknown;
    content_scripts?: unknown;
    browser_specific_settings?: {
      gecko?: { id?: string; strict_min_version?: string; data_collection_permissions?: unknown };
    };
  }
  const manifest = (config as unknown as { manifest: ManifestShape }).manifest;

  it('requests exactly storage + dns and the fixed API origins', () => {
    expect([...(manifest.permissions ?? [])].sort()).toEqual(['dns', 'storage']);
    expect(manifest.host_permissions).toEqual([...FIXED_HOST_PERMISSIONS]);
    expect(manifest.optional_host_permissions).toEqual(['*://*/*']);
    expect([...ACTIVE_HOST_PERMISSIONS]).toEqual(['*://*/*']);
  });

  it('fixed origins are specific https hosts', () => {
    for (const p of FIXED_HOST_PERMISSIONS) expect(p).toMatch(/^https:\/\/[a-z0-9-]+(\.[a-z0-9-]+)+\/\*$/);
    expect(new Set(FIXED_HOST_PERMISSIONS).size).toBe(FIXED_HOST_PERMISSIONS.length);
  });

  it('toolbar button toggles the sidebar (no popup), default CSP, no content scripts', () => {
    expect(manifest.action).toBeDefined();
    expect(manifest.action?.['default_popup']).toBeUndefined();
    expect(manifest.content_security_policy).toBeUndefined();
    expect(manifest.content_scripts).toBeUndefined();
  });

  it('declares Firefox 140+ built-in data consent honestly', () => {
    const gecko = manifest.browser_specific_settings?.gecko;
    expect(gecko?.strict_min_version).toBe('140.0');
    // Mozilla accepts an email-like ID or a GUID in braces.
    expect(gecko?.id).toMatch(/^(?:[\w.-]+@[\w.-]+|\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\})$/i);
    expect(gecko?.data_collection_permissions).toEqual({ required: ['browsingActivity'], optional: ['websiteContent'] });
  });
});

describe('module registry (src/modules/index.ts)', () => {
  it('has unique ids and getModule finds each', () => {
    const ids = MODULES.map((m) => m.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(getModule(id)?.id).toBe(id);
  });

  it('registers every module exported from src/modules (dummy.ts is test-only)', async () => {
    const dir = new URL('../src/modules/', import.meta.url);
    const exported = new Set<string>();
    for (const file of readdirSync(dir).filter((f) => f.endsWith('.ts') && f !== 'index.ts' && f !== 'dummy.ts')) {
      const mod: Record<string, unknown> = await import(/* @vite-ignore */ new URL(file, dir).href);
      for (const v of Object.values(mod)) {
        if (v && typeof v === 'object' && typeof (v as Module).id === 'string' && typeof (v as Module).run === 'function') {
          exported.add((v as Module).id);
        }
      }
    }
    expect(exported.size).toBeGreaterThan(0);
    expect([...exported].sort()).toEqual(MODULES.map((m) => m.id).sort());
    expect(getModule('dummy')).toBeUndefined();
  });

  it('only the favicon and AI modules are active; the system resolver is opt-in', () => {
    expect(MODULES.filter((m) => m.active).map((m) => m.id).sort()).toEqual(['claude', 'favicon']);
    expect(MODULES.filter((m) => m.defaultEnabled === false).map((m) => m.id)).toEqual(['sysdns']);
  });

  it('every provider key a module needs has a settings entry', () => {
    const settingsKeys = new Set(PROVIDERS.map((p) => p.key));
    for (const m of MODULES) if (m.key) expect(settingsKeys.has(m.key)).toBe(true);
  });
});

describe('OPSEC and host permissions', () => {
  it('passive modules never contact the investigated domain or IP', async () => {
    const urls = [...(await runAll(passive, domainEntity)), ...(await runAll(passive, ipEntity))];
    expect(urls.length).toBeGreaterThan(0);
    expect(urls.filter(isTarget).map((u) => u.href)).toEqual([]);
  });

  it('passive modules only call fixed API origins, or RDAP registries over CORS', async () => {
    const urls = [...(await runAll(passive, domainEntity)), ...(await runAll(passive, ipEntity))];
    const uncovered = urls.filter((u) => !coveredByFixed(u) && u.hostname !== REGISTRY).map((u) => u.href);
    expect(uncovered).toEqual([]);
    expect(urls.some((u) => u.hostname === REGISTRY)).toBe(true);
  });

  it('active modules contact the target (optional *://*/* grant) and, for the AI check, Anthropic only', async () => {
    const active = [
      createFaviconModule(() => ({ querySelector: () => null, querySelectorAll: () => [] })),
      createClaudeModule({
        hasConsent: async () => true,
        pageView: () => ({
          title: () => 'Hi',
          meta: () => null,
          openGraph: () => [],
          text: () => 'Hi',
          images: () => [],
          forms: () => [],
          passwordInputs: () => 0,
        }),
        toPng: async () => null,
      }),
    ];
    const urls = await runAll(active, domainEntity, [targetSite, providerRoutes]);
    expect(urls.some(isTarget)).toBe(true);
    for (const u of urls) {
      if (isTarget(u)) expect(ACTIVE_HOST_PERMISSIONS.some((p) => matchesPattern(p, u))).toBe(true);
      else expect(u.origin).toBe('https://api.anthropic.com');
    }
  });

  it('every fixed host permission is used by some module', async () => {
    const active = createClaudeModule({
      hasConsent: async () => true,
      pageView: () => ({
        title: () => null,
        meta: () => null,
        openGraph: () => [],
        text: () => '',
        images: () => [],
        forms: () => [],
        passwordInputs: () => 0,
      }),
      toPng: async () => null,
    });
    const urls = [
      ...(await runAll(passive, domainEntity)),
      ...(await runAll(passive, ipEntity)),
      ...(await runAll([active], domainEntity, [targetSite, providerRoutes])),
    ];
    const unused = FIXED_HOST_PERMISSIONS.filter((p) => !urls.some((u) => matchesPattern(p, u)));
    expect(unused).toEqual([]);
  });
});
