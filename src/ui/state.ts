import { entityKey } from '@/lib/orchestrator';
import type { CardState, Entity, Pivot, RunEvent } from '@/lib/types';

export interface RootInfo {
  domain: string;
  unicode: string;
  isIdn: boolean;
}

export interface PivotRow {
  pivot: Pivot;
  sources: string[];
}

export interface RunState {
  root: RootInfo | null;
  entities: Entity[];
  cards: Record<string, CardState>;
  pivots: Record<string, PivotRow>;
  capped: Record<string, string[]>;
  running: boolean;
  cancelled: boolean;
  startedAt: number | null;
}

export const initialRunState: RunState = {
  root: null,
  entities: [],
  cards: {},
  pivots: {},
  capped: {},
  running: false,
  cancelled: false,
  startedAt: null,
};

export type RunAction =
  | { type: 'reset'; root: RootInfo; at: number }
  | { type: 'event'; event: RunEvent }
  | { type: 'running' };

export function runReducer(s: RunState, a: RunAction): RunState {
  switch (a.type) {
    case 'reset':
      return { ...initialRunState, root: a.root, running: true, startedAt: a.at };
    case 'running':
      return { ...s, running: true, cancelled: false };
    case 'event': {
      const ev = a.event;
      switch (ev.type) {
        case 'entity':
          if (s.entities.some((e) => entityKey(e) === entityKey(ev.entity))) return s;
          return { ...s, entities: [...s.entities, ev.entity] };
        case 'card':
          return { ...s, cards: { ...s.cards, [ev.card.id]: ev.card } };
        case 'pivot': {
          const k = entityKey(ev.pivot);
          const row = s.pivots[k];
          const src = ev.from.moduleId;
          if (row?.sources.includes(src)) return s;
          const next: PivotRow = row
            ? { pivot: { ...row.pivot, ...(ev.pivot.note && !row.pivot.note ? { note: ev.pivot.note } : {}) }, sources: [...row.sources, src] }
            : { pivot: ev.pivot, sources: [src] };
          return { ...s, pivots: { ...s.pivots, [k]: next } };
        }
        case 'pivot-capped':
          return { ...s, capped: { ...s.capped, [ev.domain]: ev.dropped } };
        case 'done':
          return { ...s, running: false, cancelled: ev.cancelled };
      }
    }
  }
  return s;
}

/** Cards currently skipped for `reason` (e.g. waiting for active mode or the AI data consent). */
export function skippedFor(s: RunState, reason: NonNullable<CardState['skip']>['reason']): CardState[] {
  return Object.values(s.cards).filter((c) => c.status === 'skipped' && c.skip?.reason === reason);
}

/**
 * Text for the polite live region. Changes only when a run starts or ends:
 * a per-card counter would queue one announcement per finished check.
 */
export function liveStatus(s: RunState): string {
  if (!s.root) return '';
  if (s.running) return `Investigating ${s.root.domain}…`;
  const cards = Object.values(s.cards);
  const done = cards.filter((c) => c.status !== 'queued' && c.status !== 'running').length;
  return `${s.cancelled ? 'Cancelled' : 'Finished'} ${s.root.domain}: ${done} of ${cards.length} checks done.`;
}
