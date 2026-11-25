import { useId, useState } from 'preact/hooks';
import type { CardState, Fact, Module } from '@/lib/types';
import { formatAgo } from '@/lib/summary';

const STATUS_TEXT: Record<CardState['status'], string> = {
  queued: 'Queued',
  running: 'Running',
  ok: 'OK',
  cached: 'Cached',
  error: 'Error',
  skipped: 'Skipped',
};

/** Only https links built by modules are rendered as anchors. */
export function safeHref(href: string | undefined): string | undefined {
  if (!href) return undefined;
  try {
    const u = new URL(href);
    return u.protocol === 'https:' ? u.href : undefined;
  } catch {
    return undefined;
  }
}

function FactValue({ fact }: { fact: Fact }) {
  const values = Array.isArray(fact.value) ? fact.value : [fact.value];
  const href = safeHref(fact.href);
  if (values.length === 0) return <span class="muted">none</span>;
  return (
    <>
      {values.map((v, i) => (
        <span key={i} class={`fact-v${fact.pivot ? ' pivot' : ''}`}>
          {href && i === 0 ? (
            <a href={href} target="_blank" rel="noreferrer noopener">
              {v}
            </a>
          ) : (
            v
          )}
          {fact.pivot ? <CopyButton text={fact.copy?.[i] ?? v} /> : null}
        </span>
      ))}
    </>
  );
}

export function CopyButton({ text }: { text: string }) {
  const [result, setResult] = useState<'idle' | 'done' | 'failed'>('idle');
  const flash = (r: 'done' | 'failed') => {
    setResult(r);
    setTimeout(() => setResult('idle'), 1200);
  };
  return (
    <button
      type="button"
      class="icon-btn"
      aria-label={`Copy ${text}`}
      title={result === 'failed' ? 'Copy failed' : 'Copy'}
      onClick={() => {
        navigator.clipboard.writeText(text).then(
          () => flash('done'),
          () => flash('failed'),
        );
      }}
    >
      {result === 'done' ? '✓' : result === 'failed' ? '✗' : '⧉'}
    </button>
  );
}

function genericFacts(data: unknown): Fact[] {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return [];
  const out: Fact[] = [];
  for (const [k, v] of Object.entries(data as Record<string, unknown>)) {
    if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') out.push({ label: k, value: String(v) });
    else if (Array.isArray(v) && v.every((x) => typeof x === 'string' || typeof x === 'number')) {
      out.push({ label: k, value: v.map(String) });
    }
    if (out.length >= 12) break;
  }
  return out;
}

export function Card({
  card,
  module,
  now,
  onRefresh,
  onOpenSettings,
}: {
  card: CardState;
  module: Module | undefined;
  now: number;
  onRefresh: () => void;
  onOpenSettings: () => void;
}) {
  const [open, setOpen] = useState(false);
  // Not derived from card.id: "a.b-c.com" and "a-b.c.com" would map to the same sanitised id.
  const bodyId = `card-body-${useId()}`;
  let facts: Fact[] = [];
  if (card.data !== undefined) {
    try {
      facts = module?.facts ? module.facts(card.data, card.entity) : genericFacts(card.data);
    } catch (err) {
      facts = [{ label: 'Render error', value: err instanceof Error ? err.message : String(err), tone: 'bad' }];
    }
  }
  const line =
    card.status === 'error' && !card.data
      ? card.error?.message
      : card.status === 'skipped'
        ? card.skip?.message
        : card.status === 'queued' || card.status === 'running'
          ? card.summary ?? (card.status === 'queued' ? 'Waiting…' : 'Working…')
          : card.summary;
  // A fresh error has no fetchedAt; with one, the error itself came from the cache (kept up to 2 min).
  const cachedBadge = card.fetchedAt !== undefined && (card.status === 'cached' || card.status === 'error' || !!card.stale);

  return (
    <article class="card" data-status={card.status} data-severity={card.severity ?? 'none'}>
      <div class="card-head">
        <button
          type="button"
          class="card-toggle"
          aria-expanded={open}
          aria-controls={bodyId}
          onClick={() => setOpen(!open)}
        >
          <span class={`dot dot-${card.status}${card.revalidating ? ' dot-pulse' : ''}`} aria-hidden="true" />
          <span class="sr-only">{STATUS_TEXT[card.status]}: </span>
          <span class="card-title">{card.label}</span>
          {line ? <span class="card-line">{line}</span> : null}
        </button>
        <div class="card-badges">
          {cachedBadge ? (
            <span class={`badge${card.stale ? ' badge-stale' : ''}`} title={new Date(card.fetchedAt!).toLocaleString()}>
              cached · {formatAgo(now - card.fetchedAt!)}
              {card.revalidating ? ' · refreshing' : card.stale ? ' · stale' : ''}
            </span>
          ) : null}
          {card.severity && card.severity !== 'none' && card.severity !== 'info' ? (
            <span class={`badge sev-${card.severity}`}>{card.severity}</span>
          ) : null}
          <button
            type="button"
            class="icon-btn"
            aria-label={`Refresh ${card.label} for ${card.entity.value}`}
            title="Refresh (bypass cache)"
            disabled={card.status === 'running' || card.status === 'queued'}
            onClick={onRefresh}
          >
            ↻
          </button>
        </div>
      </div>
      {open ? (
        <div class="card-body" id={bodyId}>
          {card.status === 'error' && card.error ? (
            <p class="error-text" role="note">
              {card.error.kind === 'http' && card.error.status ? `[${card.error.status}] ` : ''}
              {card.error.message}
            </p>
          ) : null}
          {card.skip ? (
            <p class="muted">
              {card.skip.message}{' '}
              {card.skip.reason === 'no-key' ? (
                <button type="button" class="link-btn" onClick={onOpenSettings}>
                  Open settings
                </button>
              ) : null}
            </p>
          ) : null}
          {module?.note ? <p class="note">{module.note}</p> : null}
          {facts.length > 0 ? (
            <dl class="facts">
              {facts.map((f, i) => (
                <div key={i} class={`fact${f.tone ? ` tone-${f.tone}` : ''}`}>
                  <dt>{f.label}</dt>
                  <dd>
                    <FactValue fact={f} />
                  </dd>
                </div>
              ))}
            </dl>
          ) : null}
          {card.data !== undefined ? (
            <details class="raw">
              <summary>Raw JSON</summary>
              <pre>{JSON.stringify(card.data, null, 2)}</pre>
            </details>
          ) : null}
        </div>
      ) : null}
    </article>
  );
}
