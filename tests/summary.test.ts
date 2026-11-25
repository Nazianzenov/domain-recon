import { describe, expect, it } from 'vitest';
import { deriveSummary, formatAgo } from '@/lib/summary';
import type { CardState, Entity, Headline, Module, Severity } from '@/lib/types';
import { DAY } from '@/lib/types';

const root: Entity = { kind: 'domain', value: 'example.com', depth: 0 };
const ip: Entity = { kind: 'ip', value: '192.0.2.1', depth: 1 };

function mod(id: string, headline?: (d: unknown) => Partial<Headline>): Module {
  return {
    id,
    label: id.toUpperCase(),
    version: 1,
    accepts: ['domain', 'ip'],
    ttl: DAY,
    run: async () => ({ data: {} }),
    ...(headline ? { headline: (d: unknown) => headline(d) } : {}),
  };
}

function card(m: Module, e: Entity, over: Partial<CardState> = {}): CardState {
  return { id: `${m.id}|${e.kind}:${e.value}`, moduleId: m.id, label: m.label, entity: e, status: 'ok', data: {}, ...over };
}

const rdap = mod('rdap', () => ({ domainAgeDays: 5, registrar: 'Reg A' }));
const other = mod('other', () => ({ domainAgeDays: 999, registrar: 'Reg B', emailProviders: ['Google Workspace'] }));
const email = mod('email', () => ({ emailProviders: ['Microsoft 365', 'Google Workspace'] }));
const rep = mod('rep');
const rep2 = mod('rep2');
const MODULES = [rdap, other, email, rep, rep2];

describe('deriveSummary', () => {
  it('merges scalar headline fields in registry order, not card arrival order', () => {
    // "other" arrives first but rdap is earlier in the registry: rdap wins.
    const view = deriveSummary([card(other, root), card(email, root), card(rdap, root)], MODULES, [root]);
    expect(view.headline.domainAgeDays).toBe(5);
    expect(view.headline.registrar).toBe('Reg A');
  });

  it('unions emailProviders across modules without duplicates, in registry order', () => {
    const view = deriveSummary([card(email, root), card(other, root)], MODULES, [root]);
    expect(view.headline.emailProviders).toEqual(['Google Workspace', 'Microsoft 365']);
  });

  it('ignores a malformed (non-array) emailProviders contribution', () => {
    const bad = mod('rdap', () => ({ emailProviders: 'Gmail' as unknown as string[] }));
    const view = deriveSummary([card(bad, root), card(email, root)], [bad, email], [root]);
    expect(view.headline.emailProviders).toEqual(['Microsoft 365', 'Google Workspace']);
  });

  it('uses only root-domain cards with data for the headline', () => {
    const view = deriveSummary(
      [
        card(rdap, ip), // depth 1: not a headline source
        card(other, root, { status: 'running', data: undefined }),
        card(email, root, { status: 'error', error: { kind: 'network', message: 'x' }, data: undefined }),
      ],
      MODULES,
      [root, ip],
    );
    expect(view.headline).toEqual({});
    expect(view.ipCount).toBe(1);
  });

  it('keeps the stale data of a failed revalidation, and cached data', () => {
    const view = deriveSummary(
      [
        card(rdap, root, { status: 'error', stale: true, error: { kind: 'timeout', message: 't' } }),
        card(email, root, { status: 'cached' }),
      ],
      MODULES,
      [root],
    );
    expect(view.headline.domainAgeDays).toBe(5);
    expect(view.headline.emailProviders).toEqual(['Microsoft 365', 'Google Workspace']);
  });

  it('survives a throwing headline()', () => {
    const boom = mod('rdap', () => {
      throw new Error('bad data');
    });
    const view = deriveSummary([card(boom, root), card(email, root)], [boom, email], [root]);
    expect(view.headline.emailProviders).toEqual(['Microsoft 365', 'Google Workspace']);
  });

  it('picks the worst severity across all entities; ties go to the registry-first module', () => {
    const sev = (m: Module, e: Entity, severity: Severity, summary?: string) =>
      card(m, e, { severity, ...(summary ? { summary } : {}) });
    const view = deriveSummary(
      [sev(rep2, ip, 'high', 'second'), sev(rep, root, 'medium'), sev(rep, ip, 'high', 'first'), sev(email, root, 'info')],
      MODULES,
      [root, ip],
    );
    expect(view.worst).toEqual({ severity: 'high', label: 'REP', entity: ip, summary: 'first' });
  });

  it('reports no worst hit for info/none severities or cards without data', () => {
    const view = deriveSummary(
      [
        card(rep, root, { severity: 'info' }),
        card(rep2, root, { severity: 'none' }),
        card(email, ip, { severity: 'high', status: 'error', data: undefined }),
      ],
      MODULES,
      [root, ip],
    );
    expect(view.worst).toBeUndefined();
  });
});

describe('formatAgo', () => {
  it('formats durations', () => {
    expect(formatAgo(-5_000)).toBe('just now');
    expect(formatAgo(59_999)).toBe('just now');
    expect(formatAgo(5 * 60_000)).toBe('5m ago');
    expect(formatAgo(3 * 3_600_000)).toBe('3h ago');
    expect(formatAgo(3 * DAY)).toBe('3d ago');
  });
});
