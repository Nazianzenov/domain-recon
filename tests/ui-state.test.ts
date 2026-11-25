import { describe, expect, it } from 'vitest';
import type { CardState, Entity, RunEvent } from '@/lib/types';
import { initialRunState, liveStatus, runReducer, skippedFor, type RunState } from '@/ui/state';

const root: Entity = { kind: 'domain', value: 'example.com', depth: 0 };
const ip: Entity = { kind: 'ip', value: '192.0.2.1', depth: 1 };

function card(moduleId: string, e: Entity, over: Partial<CardState> = {}): CardState {
  return { id: `${moduleId}|${e.kind}:${e.value}`, moduleId, label: moduleId, entity: e, status: 'queued', ...over };
}

function run(events: RunEvent[], from: RunState = initialRunState): RunState {
  let s = runReducer(from, { type: 'reset', root: { domain: 'example.com', unicode: 'example.com', isIdn: false }, at: 1 });
  for (const event of events) s = runReducer(s, { type: 'event', event });
  return s;
}

describe('runReducer', () => {
  it('reset clears the previous investigation and starts running', () => {
    const old = run([{ type: 'entity', entity: root }, { type: 'card', card: card('dns', root) }, { type: 'done', cancelled: true }]);
    const s = runReducer(old, { type: 'reset', root: { domain: 'other.example', unicode: 'other.example', isIdn: false }, at: 2 });
    expect(s).toEqual({ ...initialRunState, root: { domain: 'other.example', unicode: 'other.example', isIdn: false }, running: true, startedAt: 2 });
  });

  it('dedupes entities and replaces cards by id', () => {
    const s = run([
      { type: 'entity', entity: root },
      { type: 'entity', entity: root },
      { type: 'card', card: card('dns', root) },
      { type: 'card', card: card('dns', root, { status: 'ok', data: { a: 1 } }) },
    ]);
    expect(s.entities).toEqual([root]);
    expect(Object.values(s.cards)).toHaveLength(1);
    expect(s.cards['dns|domain:example.com']?.status).toBe('ok');
  });

  it('merges pivot sources and keeps the first note', () => {
    const s = run([
      { type: 'pivot', pivot: { kind: 'hash', value: '-1' }, from: { moduleId: 'favicon', entity: root } },
      { type: 'pivot', pivot: { kind: 'hash', value: '-1', note: 'mmh3' }, from: { moduleId: 'shodan', entity: ip } },
      { type: 'pivot', pivot: { kind: 'hash', value: '-1', note: 'other' }, from: { moduleId: 'shodan', entity: ip } },
    ]);
    expect(s.pivots['hash:-1']).toEqual({ pivot: { kind: 'hash', value: '-1', note: 'mmh3' }, sources: ['favicon', 'shodan'] });
  });

  it('running/done toggle the run flags', () => {
    let s = run([{ type: 'done', cancelled: true }]);
    expect(s).toMatchObject({ running: false, cancelled: true });
    s = runReducer(s, { type: 'running' });
    expect(s).toMatchObject({ running: true, cancelled: false });
    s = runReducer(s, { type: 'event', event: { type: 'done', cancelled: false } });
    expect(s).toMatchObject({ running: false, cancelled: false });
  });
});

describe('skippedFor', () => {
  it('returns only cards still skipped for that reason', () => {
    const s = run([
      { type: 'card', card: card('claude', root, { status: 'skipped', skip: { reason: 'consent', message: 'm' } }) },
      { type: 'card', card: card('favicon', root, { status: 'skipped', skip: { reason: 'active', message: 'm' } }) },
      { type: 'card', card: card('vt', root, { status: 'skipped', skip: { reason: 'no-key', message: 'm' } }) },
    ]);
    expect(skippedFor(s, 'consent').map((c) => c.moduleId)).toEqual(['claude']);
    expect(skippedFor(s, 'active').map((c) => c.moduleId)).toEqual(['favicon']);
    // Once a refresh is under way the card no longer counts (no double refresh on a second click).
    const after = runReducer(s, { type: 'event', event: { type: 'card', card: card('claude', root, { status: 'running' }) } });
    expect(skippedFor(after, 'consent')).toEqual([]);
  });
});

describe('liveStatus', () => {
  it('is empty before any investigation', () => {
    expect(liveStatus(initialRunState)).toBe('');
  });

  it('does not change while cards complete (no announcement per card), then summarises', () => {
    const s1 = run([{ type: 'card', card: card('dns', root) }, { type: 'card', card: card('rdap', root) }]);
    const s2 = runReducer(s1, { type: 'event', event: { type: 'card', card: card('dns', root, { status: 'ok' }) } });
    expect(liveStatus(s1)).toBe('Investigating example.com…');
    expect(liveStatus(s2)).toBe(liveStatus(s1));
    const s3 = runReducer(s2, { type: 'event', event: { type: 'done', cancelled: false } });
    expect(liveStatus(s3)).toBe('Finished example.com: 1 of 2 checks done.');
    const s4 = runReducer(s3, { type: 'event', event: { type: 'done', cancelled: true } });
    expect(liveStatus(s4)).toBe('Cancelled example.com: 1 of 2 checks done.');
  });
});
