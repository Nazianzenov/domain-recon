import { defangDeep, defangText } from './defang';
import { entityKey } from './orchestrator';
import type { SummaryView } from './summary';
import type { CardState, Entity, Fact, Module, Pivot } from './types';
import type { Verdict } from './verdict';

export interface ExportInput {
  root: { domain: string; unicode: string; isIdn: boolean };
  generatedAt: number;
  opsec: 'passive' | 'active';
  entities: Entity[];
  cards: CardState[];
  pivots: Array<{ pivot: Pivot; sources: string[] }>;
  capped: Record<string, string[]>;
  summary: SummaryView;
  verdict: Verdict | null;
  modules: readonly Module[];
}

const iso = (ms: number) => new Date(ms).toISOString();

function orderedCards(input: ExportInput, e: Entity): CardState[] {
  const order = new Map(input.modules.map((m, i) => [m.id, i] as const));
  return input.cards
    .filter((c) => entityKey(c.entity) === entityKey(e))
    .sort((a, b) => (order.get(a.moduleId) ?? 999) - (order.get(b.moduleId) ?? 999));
}

/**
 * Whole investigation as JSON, every string value and object key defanged
 * (`ipCapDropped` and some module data are keyed by domains or page strings).
 */
export function toJsonExport(input: ExportInput): string {
  const doc = {
    tool: 'Domain Recon',
    generatedAt: iso(input.generatedAt),
    defanged: true,
    root: input.root,
    opsec: input.opsec,
    summary: {
      ...input.summary.headline,
      ipsInvestigated: input.summary.ipCount,
      worstReputation: input.summary.worst ?? null,
    },
    verdict: input.verdict,
    entities: input.entities.map((e) => ({
      ...e,
      results: orderedCards(input, e).map((c) => ({
        module: c.moduleId,
        label: c.label,
        status: c.status,
        ...(c.summary !== undefined ? { summary: c.summary } : {}),
        ...(c.severity ? { severity: c.severity } : {}),
        ...(c.fetchedAt !== undefined ? { fetchedAt: iso(c.fetchedAt), stale: !!c.stale } : {}),
        ...(c.error ? { error: c.error } : {}),
        ...(c.skip ? { skipped: c.skip } : {}),
        ...(c.data !== undefined ? { data: c.data } : {}),
      })),
    })),
    pivots: input.pivots,
    ipCapDropped: input.capped,
  };
  return JSON.stringify(defangDeep(doc), null, 2);
}

/**
 * Inline code span that survives any content (defanged first). In a GFM table
 * cell a `|` splits the cell even inside a code span, so it is escaped there
 * (GFM renders `\|` in a cell's code span as `|`).
 */
function code(s: string, cell = false): string {
  let v = defangText(String(s)).replace(/\s+/g, ' ');
  if (cell) v = v.replace(/\|/g, '\\|');
  const ticks = (v.match(/`+/g) ?? []).reduce((n, t) => Math.max(n, t.length), 0);
  const fence = '`'.repeat(ticks + 1);
  return `${fence}${ticks ? ' ' : ''}${v}${ticks ? ' ' : ''}${fence}`;
}

/**
 * Escape Markdown in prose (labels, summaries) after defanging. The defang
 * markers "[.]", "[@]" and "[:]" stay readable (every other `[` is escaped), so
 * a `]` is escaped where it could complete a link: before `(` (inline link,
 * e.g. `[.](javascript:...)`) or `:` (a link reference definition such as
 * `[.]: https://...`, which would turn every "[.]" in the report into a link;
 * with no definitions, `[.][.]` stays text). `&` is escaped so entities such as
 * `&#46;` cannot render a live dot, `~` so a `~~~` fence cannot swallow the rest
 * of the report.
 */
function md(s: string): string {
  return defangText(String(s))
    .replace(/\s+/g, ' ')
    .replace(/([\\`*_{}<>#|!~&])/g, '\\$1')
    .replace(/\[(?!\.\]|@\]|:\])/g, '\\[')
    .replace(/\]([(:])/g, ']\\$1');
}

/** Prose that starts its own line: also neutralise list markers and setext/thematic-break lines. */
function mdLine(s: string): string {
  return md(s)
    .replace(/^(\s*)([-+=])/, '$1\\$2')
    .replace(/^(\s*\d+)([.)])/, '$1\\$2');
}

function factLines(f: Fact): string[] {
  const vals = Array.isArray(f.value) ? f.value : [f.value];
  if (vals.length <= 1) return [`- **${md(f.label)}**: ${vals[0] !== undefined ? code(vals[0]) : '_none_'}`];
  return [`- **${md(f.label)}**:`, ...vals.slice(0, 50).map((v) => `  - ${code(v)}`), ...(vals.length > 50 ? [`  - … ${vals.length - 50} more`] : [])];
}

/** Human-readable Markdown report with defanged indicators. */
export function toMarkdown(input: ExportInput): string {
  const h = input.summary.headline;
  const L: string[] = [];
  L.push(`# Domain Recon: ${code(input.root.domain)}`, '');
  L.push(`- Generated: ${iso(input.generatedAt)}`);
  if (input.root.isIdn) L.push(`- Unicode form: ${code(input.root.unicode)}`);
  L.push(`- OPSEC mode: ${input.opsec === 'passive' ? 'passive only' : 'active checks allowed'}`);
  L.push('- Indicators are defanged.', '');

  L.push('## Summary', '');
  L.push('| Field | Value |', '| --- | --- |');
  const row = (k: string, v: string) => L.push(`| ${k} | ${v} |`);
  const parent = h.registrationFor && h.registrationFor !== input.root.domain ? ` of parent ${code(h.registrationFor, true)}` : '';
  row('Domain age', h.domainAgeDays !== undefined ? `${h.domainAgeDays} days${parent} (registered ${md(h.registeredOn ?? '?')})` : '—');
  row('Registrar', h.registrar ? md(h.registrar) : '—');
  row(
    'M365 tenant',
    h.m365
      ? h.m365.tenant
        ? `yes${h.m365.tenantId ? ` (${code(h.m365.tenantId, true)})` : ''}`
        : h.m365.namespaceType === 'Consumer (MSA)'
          ? 'no (consumer Microsoft account domain)'
          : 'no'
      : '—',
  );
  row('Email providers', h.emailProviders?.length ? md(h.emailProviders.join(', ')) : '—');
  row('IPs investigated', String(input.summary.ipCount));
  const w = input.summary.worst;
  row('Worst reputation', w ? `${w.severity}: ${md(w.label)} on ${code(w.entity.value, true)}` : 'no hits');
  row('AI brand', h.brand ? (h.brand.brand ? `${md(h.brand.brand)} (${Math.round(h.brand.confidence * 100)}%)` : 'none') : '—');
  L.push('');

  if (input.verdict) {
    L.push(`## Verdict: ${md(input.verdict.title)}`, '');
    for (const s of input.verdict.signals) L.push(`- [${s.weight}] ${md(s.text)}`);
    L.push('', '_Computed in code from RDAP, M365, page and AI signals; the AI only identifies the brand._', '');
  }

  for (const e of input.entities) {
    L.push(`## ${e.kind === 'domain' ? 'Domain' : 'IP'} ${code(e.value)}`, '');
    for (const c of orderedCards(input, e)) {
      const mod = input.modules.find((m) => m.id === c.moduleId);
      const badge = c.fetchedAt !== undefined && (c.status === 'cached' || c.stale) ? ` (cached ${iso(c.fetchedAt)})` : '';
      L.push(`### ${md(c.label)} [${c.status}${c.severity && c.severity !== 'none' ? `, ${c.severity}` : ''}]${badge}`, '');
      if (c.summary) L.push(mdLine(c.summary), '');
      if (c.error) L.push(`> Error: ${md(c.error.message)}`, '');
      if (c.skip) L.push(`> Skipped: ${md(c.skip.message)}`, '');
      if (c.data !== undefined && mod?.facts) {
        try {
          for (const f of mod.facts(c.data, c.entity)) L.push(...factLines(f));
          L.push('');
        } catch {
          /* facts rendering is best-effort in exports */
        }
      }
    }
  }

  const pivots = input.pivots.filter(
    (p) =>
      !input.entities.some((e) => entityKey(e) === entityKey(p.pivot)) &&
      !(p.pivot.kind === 'domain' && p.pivot.value === input.root.domain),
  );
  if (pivots.length) {
    L.push('## Pivots not investigated', '');
    for (const p of pivots) L.push(`- ${p.pivot.kind} ${code(p.pivot.value)}${p.pivot.note ? ` (${md(p.pivot.note)})` : ''} from ${md(p.sources.join(', '))}`);
    L.push('');
  }
  for (const [domain, dropped] of Object.entries(input.capped)) {
    L.push(`> IP cap (10) reached for ${code(domain)}: ${dropped.length} more not investigated.`, '');
  }
  return `${L.join('\n').replace(/\n{3,}/g, '\n\n').trim()}\n`;
}

export function exportFilename(domain: string, ext: 'json' | 'md', at: number): string {
  const stamp = new Date(at).toISOString().replace(/[:]/g, '').replace(/\..+$/, '');
  return `domain-recon_${domain.replace(/[^a-z0-9.-]/gi, '_')}_${stamp}.${ext}`;
}
