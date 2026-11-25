import { useEffect, useMemo, useReducer, useRef, useState } from 'preact/hooks';
import { browser } from 'wxt/browser';
import { getCache } from '@/lib/cache';
import { exportFilename, toJsonExport, toMarkdown, type ExportInput } from '@/lib/export';
import { shodanSearchUrl } from '@/lib/favhash';
import { ff } from '@/lib/firefox';
import { normalizeInput } from '@/lib/normalize';
import { Investigation, entityKey } from '@/lib/orchestrator';
import {
  hasActiveAccess,
  missingFixedOrigins,
  onPermissionsChanged,
  requestActiveAccess,
  requestFixedOrigins,
} from '@/lib/permissions';
import { RateLimiter } from '@/lib/ratelimit';
import { DEFAULT_SETTINGS, isModuleEnabled, loadSettings, onSettingsChanged } from '@/lib/settings';
import { deriveSummary } from '@/lib/summary';
import type { CardState, Entity, Settings } from '@/lib/types';
import { correlate, type Verdict } from '@/lib/verdict';
import { MODULES } from '@/modules';
import { Card, CopyButton, safeHref } from './Card';
import { Summary } from './Summary';
import { initialRunState, liveStatus, runReducer, skippedFor, type RootInfo } from './state';

type Opsec = 'passive' | 'active';

function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function download(filename: string, content: string, type: string): void {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.append(a);
  a.click();
  a.remove();
  // Generous delay: revoking while Firefox still shows a "save as" dialog fails the download.
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

const VERDICT_CLASS: Record<Verdict['level'], string> = {
  'likely-impersonation': 'banner-bad',
  suspicious: 'banner-warn',
  consistent: 'banner-good',
  inconclusive: 'banner-info',
};

function VerdictBanner({ verdict }: { verdict: Verdict }) {
  return (
    <section class={`banner verdict ${VERDICT_CLASS[verdict.level]}`} role={verdict.level === 'likely-impersonation' ? 'alert' : 'status'}>
      <div>
        <h2>{verdict.title}</h2>
        <ul>
          {verdict.signals.map((s, i) => (
            <li key={i} class={`sig sig-${s.weight}`}>
              <span class="sig-w">{s.weight}</span> {s.text}
            </li>
          ))}
        </ul>
        <p class="note">Verdict computed in code from RDAP, M365, page and AI signals. The AI only identifies the brand.</p>
      </div>
    </section>
  );
}

export function App() {
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  // Until stored settings arrive, a run would see no API keys and skip every keyed module.
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const settingsRef = useRef(settings);
  settingsRef.current = settings;
  const [missing, setMissing] = useState<string[] | null>(null);
  const [activeGranted, setActiveGranted] = useState(false);
  const [opsec, setOpsec] = useState<Opsec>('passive');
  const [input, setInput] = useState('');
  const [inputError, setInputError] = useState<string | null>(null);
  const [state, dispatch] = useReducer(runReducer, initialRunState);
  // Latest state for async callbacks (permission prompts resolve long after the click's render).
  const stateRef = useRef(state);
  stateRef.current = state;
  // Re-renders without a state change: re-syncs the OPSEC radios with `opsec` while/after a prompt.
  const [, setTick] = useState(0);
  const forceRender = () => setTick((n) => n + 1);
  const [notice, setNotice] = useState('');
  const invRef = useRef<Investigation | null>(null);
  /** Investigation runActive() was already started for in the current active-mode session (dedupes double clicks). */
  const activeRunRef = useRef<Investigation | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const limiter = useMemo(() => new RateLimiter(), []);
  const now = useNow();

  useEffect(() => {
    let changed = false;
    const off = onSettingsChanged((s) => {
      changed = true; // newer than a still-pending initial load
      setSettings(s);
      setSettingsLoaded(true);
    });
    void loadSettings().then(
      (s) => {
        if (!changed) setSettings(s);
        setSettingsLoaded(true);
      },
      (err: unknown) => {
        setNotice(`Could not load settings (API keys unavailable): ${errMsg(err)}`);
        setSettingsLoaded(true);
      },
    );
    return off;
  }, []);

  const dropToPassive = () => {
    setOpsec('passive');
    invRef.current?.setAllowActive(false);
    activeRunRef.current = null;
  };

  const refreshAccess = () => {
    missingFixedOrigins().then(setMissing, () => setMissing(null));
    hasActiveAccess().then(
      (granted) => {
        setActiveGranted(granted);
        // All-sites access revoked (about:addons): active mode would only produce failing requests.
        if (!granted) dropToPassive();
      },
      () => setActiveGranted(false),
    );
  };
  useEffect(() => {
    refreshAccess();
    return onPermissionsChanged(refreshAccess);
  }, []);

  // Escape cancels a running investigation from anywhere in the sidebar.
  useEffect(() => {
    if (!state.running) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !e.defaultPrevented) invRef.current?.cancel();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [state.running]);

  /** `root` given: re-run that investigation (Force refresh), whatever is typed in the box now. */
  const startInvestigation = (force: boolean, root?: RootInfo) => {
    if (!settingsLoaded) return;
    let target = root;
    if (!target) {
      const res = normalizeInput(input);
      if (!res.ok) {
        setInputError(res.error);
        return;
      }
      target = { domain: res.domain, unicode: res.unicode, isIdn: res.isIdn };
    }
    setInputError(null);
    setNotice('');
    invRef.current?.cancel();
    const inv = new Investigation(
      { kind: 'domain', value: target.domain },
      {
        modules: MODULES,
        isEnabled: (m) => isModuleEnabled(m, settingsRef.current),
        allowActive: opsec === 'active' && activeGranted,
        force,
        cache: getCache(),
        limiter,
        settings: settingsRef.current,
        getKey: async (p) => settingsRef.current.keys[p],
      },
      (event) => {
        if (invRef.current === inv) dispatch({ type: 'event', event });
      },
    );
    invRef.current = inv;
    dispatch({ type: 'reset', root: target, at: Date.now() });
    void inv.start();
  };

  const runSkippedActive = () => {
    const inv = invRef.current;
    // A second click while the first prompt was open must not start the (paid) AI check twice.
    if (!inv || activeRunRef.current === inv) return;
    activeRunRef.current = inv;
    inv.setAllowActive(true);
    dispatch({ type: 'running' });
    void inv.runActive();
  };

  /** Switch to active mode. permissions.request must be the first call in the click handler. */
  const enableActive = () => {
    void requestActiveAccess().then(
      (granted) => {
        setActiveGranted(granted);
        if (!granted) {
          setNotice('Active checks need access to all sites; the request was declined.');
          forceRender(); // the radio the user clicked may still be checked in the DOM
          return;
        }
        setOpsec('active');
        runSkippedActive();
      },
      (err: unknown) => {
        setNotice(`Could not request access: ${errMsg(err)}`);
        forceRender();
      },
    );
  };

  /**
   * Banner "Run active checks": run the skipped active modules for THIS
   * investigation only. The OPSEC mode stays passive, so the next
   * investigation does not silently contact its target.
   */
  const runActiveOnce = () => {
    void requestActiveAccess().then(
      (granted) => {
        setActiveGranted(granted);
        if (!granted) {
          setNotice('Active checks need access to all sites; the request was declined.');
          return;
        }
        runSkippedActive();
      },
      (err: unknown) => setNotice(`Could not request access: ${errMsg(err)}`),
    );
  };

  const setOpsecMode = (mode: Opsec) => {
    if (mode === 'passive') {
      dropToPassive();
      return;
    }
    enableActive();
    // Mode stays passive until the prompt is answered: put the radios back in sync meanwhile.
    forceRender();
  };

  /** Optional "website content" data-collection consent for the AI check (Firefox built-in consent). */
  const allowAi = () => {
    void ff.permissions.request({ data_collection: ['websiteContent'] }).then(
      (granted) => {
        if (!granted) {
          setNotice('AI page analysis stays off: consent was declined.');
          return;
        }
        const inv = invRef.current;
        if (!inv) return;
        // Read the latest cards, not this render's: while the prompt was open the user may have
        // started another investigation (stale cards) or clicked twice (already refreshing).
        const targets = skippedFor(stateRef.current, 'consent');
        if (targets.length === 0) return;
        dispatch({ type: 'running' });
        // refetch: false reuses the homepage/favicon this run already fetched (no second hit on the target).
        for (const c of targets) void inv.refresh(c.moduleId, c.entity, { refetch: false });
      },
      (err: unknown) => setNotice(`Could not request consent: ${errMsg(err)}`),
    );
  };

  const cards = Object.values(state.cards);
  const view = useMemo(() => deriveSummary(cards, MODULES, state.entities), [state.cards, state.entities]);
  const verdict = useMemo(
    () => (state.root ? correlate({ domain: state.root.domain, isIdn: state.root.isIdn, headline: view.headline }) : null),
    [state.root, view],
  );
  const skippedActive = skippedFor(state, 'active');
  const needsConsent = skippedFor(state, 'consent').length > 0;
  const moduleOrder = useMemo(() => new Map(MODULES.map((m, i) => [m.id, i] as const)), []);
  const cardsFor = (e: Entity): CardState[] =>
    cards
      .filter((c) => entityKey(c.entity) === entityKey(e))
      .sort((a, b) => (moduleOrder.get(a.moduleId) ?? 0) - (moduleOrder.get(b.moduleId) ?? 0));
  const openSettings = () => {
    browser.runtime.openOptionsPage().catch((err: unknown) => setNotice(`Could not open settings: ${errMsg(err)}`));
  };
  const cancel = () => {
    invRef.current?.cancel();
    // The Cancel button disappears when the run ends; keep keyboard focus somewhere useful.
    inputRef.current?.focus();
  };
  // Hide pivots already investigated, and the root domain itself (e.g. PDNS on an IP lists it).
  const pivotRows = Object.values(state.pivots).filter(
    (r) =>
      !state.entities.some((e) => entityKey(e) === entityKey(r.pivot)) &&
      !(r.pivot.kind === 'domain' && r.pivot.value === state.root?.domain),
  );

  const exportInput = (): ExportInput | null =>
    state.root
      ? {
          root: state.root,
          generatedAt: Date.now(),
          opsec,
          entities: state.entities,
          cards,
          pivots: Object.values(state.pivots),
          capped: state.capped,
          summary: view,
          verdict,
          modules: MODULES,
        }
      : null;

  return (
    <main class="app">
      <header class="topbar">
        <h1>Domain Recon</h1>
        <button type="button" class="link-btn" onClick={openSettings}>
          Settings
        </button>
      </header>

      {missing && missing.length > 0 ? (
        <div class="banner banner-warn" role="alert">
          <p>
            Access to {missing.length} API origin{missing.length > 1 ? 's' : ''} is missing or was revoked. Checks using
            them will fail.
          </p>
          <button
            type="button"
            onClick={() =>
              requestFixedOrigins(missing).then(refreshAccess, (err: unknown) =>
                setNotice(`Could not request access: ${errMsg(err)}`),
              )
            }
          >
            Grant access
          </button>
        </div>
      ) : null}

      <form
        class="search"
        onSubmit={(e) => {
          e.preventDefault();
          startInvestigation(false);
        }}
      >
        <label for="q" class="sr-only">
          Domain, URL or defanged indicator
        </label>
        <input
          ref={inputRef}
          id="q"
          type="text"
          inputMode="url"
          autoComplete="off"
          spellcheck={false}
          placeholder="example.com, https://…, evil[.]com"
          value={input}
          aria-invalid={inputError ? true : undefined}
          aria-describedby={inputError ? 'q-err' : undefined}
          onInput={(e) => setInput((e.target as HTMLInputElement).value)}
        />
        <button type="submit" class="primary" disabled={!input.trim() || !settingsLoaded}>
          Investigate
        </button>
        {state.running ? (
          <button type="button" onClick={cancel} aria-keyshortcuts="Escape" title="Cancel (Esc)">
            Cancel
          </button>
        ) : null}
        {inputError ? (
          <p id="q-err" class="error-text" role="alert">
            {inputError}
          </p>
        ) : null}
      </form>

      <div class="controls">
        <fieldset class="opsec">
          <legend>OPSEC</legend>
          <label>
            <input type="radio" name="opsec" checked={opsec === 'passive'} onChange={() => setOpsecMode('passive')} />
            Passive only
          </label>
          <label>
            <input type="radio" name="opsec" checked={opsec === 'active'} onChange={() => setOpsecMode('active')} />
            Allow active checks
          </label>
        </fieldset>
        {state.root ? (
          <div class="toolbar">
            <button
              type="button"
              disabled={state.running}
              onClick={() => state.root && startInvestigation(true, state.root)}
              title="Re-run every module, ignoring the cache"
            >
              Force refresh
            </button>
            <button
              type="button"
              title="Download JSON (indicators defanged)"
              onClick={() => {
                const x = exportInput();
                if (x) download(exportFilename(x.root.domain, 'json', x.generatedAt), toJsonExport(x), 'application/json');
              }}
            >
              JSON
            </button>
            <button
              type="button"
              title="Download Markdown (indicators defanged)"
              onClick={() => {
                const x = exportInput();
                if (x) download(exportFilename(x.root.domain, 'md', x.generatedAt), toMarkdown(x), 'text/markdown');
              }}
            >
              Markdown
            </button>
            <button
              type="button"
              title="Copy the Markdown report to the clipboard"
              onClick={() => {
                const x = exportInput();
                if (x) {
                  navigator.clipboard.writeText(toMarkdown(x)).then(
                    () => setNotice('Markdown report copied.'),
                    (err: unknown) => setNotice(`Could not copy the report: ${errMsg(err)}`),
                  );
                }
              }}
            >
              Copy MD
            </button>
          </div>
        ) : null}
      </div>

      <p class="sr-only" role="status">
        {liveStatus(state)}
      </p>
      {/* Always rendered: a live region inserted together with its text is often not announced. */}
      <p class="note notice" role="status">
        {notice || null}
      </p>

      {verdict && verdict.level !== 'inconclusive' ? <VerdictBanner verdict={verdict} /> : null}

      {state.root ? <Summary root={state.root} view={view} /> : null}

      {verdict && verdict.level === 'inconclusive' ? <VerdictBanner verdict={verdict} /> : null}

      {skippedActive.length > 0 && opsec === 'passive' ? (
        <div class="banner banner-info">
          <p>
            {skippedActive.length} active check{skippedActive.length > 1 ? 's' : ''} skipped. Active checks contact{' '}
            {state.root?.domain ?? 'the target'} directly from your IP address.
          </p>
          <button type="button" onClick={runActiveOnce}>
            {activeGranted ? 'Run active checks' : 'Allow & run active checks'}
          </button>
        </div>
      ) : null}

      {needsConsent ? (
        <div class="banner banner-info">
          <p>
            The AI brand check sends an extracted summary of the homepage (no raw HTML) and its favicon to Anthropic. Firefox
            asks for your consent to share website content.
          </p>
          <button type="button" onClick={allowAi}>
            Allow AI page analysis
          </button>
        </div>
      ) : null}

      {state.entities.map((e) => (
        <section class="entity" key={entityKey(e)} aria-label={`${e.kind} ${e.value}`}>
          <h2 class="entity-h">
            <span class={`kind kind-${e.kind}`}>{e.kind}</span> {e.value}
          </h2>
          {cardsFor(e).map((c) => (
            <Card
              key={c.id}
              card={c}
              module={MODULES.find((m) => m.id === c.moduleId)}
              now={now}
              onOpenSettings={openSettings}
              onRefresh={() => {
                dispatch({ type: 'running' });
                void invRef.current?.refresh(c.moduleId, c.entity);
              }}
            />
          ))}
        </section>
      ))}

      {Object.entries(state.capped).map(([domain, dropped]) => (
        <p class="note" key={domain}>
          IP cap (10) reached for {domain}: {dropped.length} more IP{dropped.length > 1 ? 's' : ''} listed below but not
          investigated.
        </p>
      ))}

      {pivotRows.length > 0 ? (
        <section class="entity" aria-label="Pivots not investigated">
          <h2 class="entity-h">Pivots not investigated</h2>
          <ul class="pivots">
            {pivotRows.map((r) => {
              const shodan = r.pivot.kind === 'hash' && /mmh3/i.test(r.pivot.note ?? '') && /^-?\d+$/.test(r.pivot.value)
                ? safeHref(shodanSearchUrl(Number(r.pivot.value)))
                : undefined;
              return (
                <li key={entityKey(r.pivot)}>
                  <span class={`kind kind-${r.pivot.kind}`}>{r.pivot.kind}</span>
                  <code>{r.pivot.value}</code>
                  <CopyButton text={r.pivot.value} />
                  {shodan ? (
                    <a href={shodan} target="_blank" rel="noreferrer noopener">
                      Shodan
                    </a>
                  ) : null}
                  {r.pivot.note ? <span class="muted"> {r.pivot.note}</span> : null}
                  <span class="muted"> · from {r.sources.join(', ')}</span>
                </li>
              );
            })}
          </ul>
        </section>
      ) : null}

      {!state.root ? (
        <p class="muted intro">
          Enter a domain to investigate. Passive mode only talks to DNS resolvers, registries and threat-intel APIs, never
          to the target itself.
        </p>
      ) : null}
    </main>
  );
}
