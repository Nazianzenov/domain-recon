import type { CardState, Entity, Headline, Module, Severity } from './types';

export const SEVERITY_RANK: Record<Severity, number> = { none: 0, info: 1, low: 2, medium: 3, high: 4 };

export interface SummaryView {
  headline: Partial<Headline>;
  /** Number of IP entities discovered (investigated). */
  ipCount: number;
  worst?: { severity: Severity; label: string; entity: Entity; summary?: string };
}

function hasData(c: CardState): boolean {
  return c.data !== undefined && (c.status === 'ok' || c.status === 'cached' || (c.status === 'error' && !!c.stale));
}

/**
 * Merge module headline contributions (root-domain cards, registry order;
 * list fields are unioned) and find the worst reputation hit across all cards.
 */
export function deriveSummary(cards: readonly CardState[], modules: readonly Module[], entities: readonly Entity[]): SummaryView {
  const order = new Map(modules.map((m, i) => [m.id, i] as const));
  const byOrder = [...cards].sort((a, b) => (order.get(a.moduleId) ?? 999) - (order.get(b.moduleId) ?? 999));
  const headline: Partial<Headline> = {};
  let worst: SummaryView['worst'];

  for (const c of byOrder) {
    if (!hasData(c)) continue;
    const m = modules.find((x) => x.id === c.moduleId);
    if (c.entity.depth === 0 && m?.headline) {
      let part: Partial<Headline> = {};
      try {
        part = m.headline(c.data, c.entity);
      } catch {
        part = {};
      }
      for (const [k, v] of Object.entries(part) as Array<[keyof Headline, unknown]>) {
        if (v === undefined) continue;
        if (k === 'emailProviders') {
          if (!Array.isArray(v)) continue;
          const merged = new Set([...(headline.emailProviders ?? []), ...v.filter((x): x is string => typeof x === 'string')]);
          headline.emailProviders = [...merged];
        } else if (headline[k] === undefined) {
          (headline as Record<string, unknown>)[k] = v;
        }
      }
    }
    if (c.severity && c.severity !== 'none' && c.severity !== 'info') {
      if (!worst || SEVERITY_RANK[c.severity] > SEVERITY_RANK[worst.severity]) {
        worst = { severity: c.severity, label: c.label, entity: c.entity, ...(c.summary ? { summary: c.summary } : {}) };
      }
    }
  }

  return {
    headline,
    ipCount: entities.filter((e) => e.kind === 'ip').length,
    ...(worst ? { worst } : {}),
  };
}

export function formatAgo(ms: number): string {
  if (ms < 60_000) return 'just now';
  const m = Math.floor(ms / 60_000);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}
