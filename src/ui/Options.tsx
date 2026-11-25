import { useEffect, useRef, useState } from 'preact/hooks';
import { getCache } from '@/lib/cache';
import { hasKeyTester, testKey } from '@/lib/keytest';
import {
  CLAUDE_MODEL_PRESETS,
  DEFAULT_CLAUDE_MODEL,
  DEFAULT_SETTINGS,
  PROVIDERS,
  isModuleEnabled,
  isValidModelId,
  loadSettings,
  onSettingsChanged,
  saveKey,
  saveSettings,
} from '@/lib/settings';
import type { Settings } from '@/lib/types';
import { MODULES } from '@/modules';
import '@/modules/keytests';

type TestState = { state: 'idle' } | { state: 'running' } | { state: 'ok' | 'error'; message: string };

const errMsg = (err: unknown) => (err instanceof Error ? err.message : String(err));
const isPreset = (id: string) => CLAUDE_MODEL_PRESETS.some((p) => p.id === id);

function KeyRow({ p, value, onSave }: { p: (typeof PROVIDERS)[number]; value: string; onSave: (v: string) => void }) {
  const [draft, setDraft] = useState(value);
  const [show, setShow] = useState(false);
  const [test, setTest] = useState<TestState>({ state: 'idle' });
  // Bumped on every edit/test: a result for a key that has since been edited is dropped.
  const testSeq = useRef(0);
  useEffect(() => setDraft(value), [value]);
  const id = `key-${p.key}`;
  const helpId = `${id}-help`;
  const resultId = `${id}-result`;
  const dirty = draft.trim() !== value;
  const testable = hasKeyTester(p.key);
  return (
    <div class="key-row">
      <label for={id}>{p.label}</label>
      <input
        id={id}
        {...(show ? { type: 'text' as const } : { type: 'password' as const })}
        autoComplete="off"
        spellcheck={false}
        value={draft}
        aria-describedby={`${helpId} ${resultId}`}
        onInput={(e) => {
          setDraft((e.target as HTMLInputElement).value);
          if (test.state !== 'idle') {
            testSeq.current++;
            setTest({ state: 'idle' });
          }
        }}
        onBlur={() => dirty && onSave(draft.trim())}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && dirty) onSave(draft.trim());
        }}
      />
      <button type="button" aria-label={`${show ? 'Hide' : 'Show'} ${p.label} key`} onClick={() => setShow(!show)}>
        {show ? 'Hide' : 'Show'}
      </button>
      <button
        type="button"
        aria-label={`Test ${p.label} key`}
        disabled={!draft.trim() || !testable || test.state === 'running'}
        title={testable ? 'Make one cheap authenticated request' : 'No test available'}
        onClick={() => {
          if (dirty) onSave(draft.trim());
          const seq = ++testSeq.current;
          setTest({ state: 'running' });
          testKey(p.key, draft).then(
            (message) => seq === testSeq.current && setTest({ state: 'ok', message }),
            (err: unknown) => seq === testSeq.current && setTest({ state: 'error', message: errMsg(err) }),
          );
        }}
      >
        Test
      </button>
      <p class="key-help" id={helpId}>
        {p.help}{' '}
        <a href={p.url} target="_blank" rel="noreferrer noopener">
          Get a key
        </a>
      </p>
      {/* Always rendered so screen readers announce the result when it appears. */}
      <p
        id={resultId}
        class={`test-result ${test.state === 'error' ? 'error-text' : test.state === 'ok' ? 'tone-good' : 'muted'}`}
        role="status"
      >
        {test.state === 'idle' ? '' : test.state === 'running' ? 'Testing…' : test.message}
      </p>
    </div>
  );
}

export function Options() {
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [status, setStatus] = useState('');
  const [cacheMsg, setCacheMsg] = useState('');
  /** "Custom model ID…" picked in the select (or a non-preset model is stored). */
  const [customMode, setCustomMode] = useState(false);
  const [customModel, setCustomModel] = useState('');
  const [modelError, setModelError] = useState<string | null>(null);

  useEffect(() => {
    let lastModel: string | undefined;
    const apply = (s: Settings) => {
      setSettings(s);
      // Only when the stored model itself changed: a module toggle must not wipe a half-typed custom ID.
      if (s.claudeModel !== lastModel && !isPreset(s.claudeModel)) {
        setCustomMode(true);
        setCustomModel(s.claudeModel);
        setModelError(null);
      }
      lastModel = s.claudeModel;
    };
    loadSettings().then(apply, (err: unknown) => setStatus(`Could not load settings: ${errMsg(err)}`));
    // Another settings tab, or a save from this one.
    return onSettingsChanged(apply);
  }, []);

  const report = (err: unknown) => setStatus(`Could not save settings: ${errMsg(err)}`);
  const save = (patch: Partial<Settings>) => {
    saveSettings(patch).then(setSettings, report);
  };
  // Atomic per-key update: never writes back a stale copy of the other keys.
  const storeKey = (p: (typeof PROVIDERS)[number], v: string) => {
    saveKey(p.key, v).then((s) => {
      setSettings(s);
      // Announce the save (it happens on blur, with no other visible cue). Never echo the key.
      setStatus(v ? `${p.label} key saved.` : `${p.label} key removed.`);
    }, report);
  };

  const commitCustomModel = () => {
    const v = customModel.trim();
    if (!v) return; // keep the current model until an ID is entered
    if (!isValidModelId(v)) {
      setModelError('Model IDs are 3–100 characters: letters, digits and . _ : @ - (for example claude-opus-5-5).');
      return;
    }
    setModelError(null);
    if (v !== settings.claudeModel) save({ claudeModel: v });
  };
  const showCustom = customMode || !isPreset(settings.claudeModel);

  return (
    <main class="options">
      <h1>Domain Recon settings</h1>
      <p class="note" role="status">
        {status}
      </p>

      <h2>API keys</h2>
      <p class="banner banner-warn">
        Keys are stored unencrypted in this browser profile (<code>storage.local</code>, never synced) and are sent only
        to the provider that issued them. Anyone with access to this profile can read them.
      </p>
      {PROVIDERS.map((p) => (
        <KeyRow key={p.key} p={p} value={settings.keys[p.key] ?? ''} onSave={(v) => storeKey(p, v)} />
      ))}

      <h2>Modules</h2>
      {MODULES.map((m) => {
        const id = `mod-${m.id}`;
        return (
          <div class="module-row" key={m.id}>
            <input
              id={id}
              type="checkbox"
              checked={isModuleEnabled(m, settings)}
              onChange={(e) => save({ modules: { [m.id]: (e.target as HTMLInputElement).checked } })}
            />
            <label for={id}>
              {m.label}
              {m.active ? <span class="muted"> · active (contacts the target)</span> : null}
              {m.key && !m.keyOptional ? <span class="muted"> · needs {m.key} key</span> : null}
            </label>
          </div>
        );
      })}

      <h2>AI brand check</h2>
      <div class="module-row">
        <label for="model">Claude model</label>
        <select
          id="model"
          value={showCustom ? 'custom' : settings.claudeModel}
          onChange={(e) => {
            const v = (e.target as HTMLSelectElement).value;
            setModelError(null);
            if (v === 'custom') {
              setCustomMode(true);
              setCustomModel(isPreset(settings.claudeModel) ? '' : settings.claudeModel);
              return;
            }
            setCustomMode(false);
            setCustomModel('');
            save({ claudeModel: v });
          }}
        >
          {CLAUDE_MODEL_PRESETS.map((p) => (
            <option key={p.id} value={p.id}>
              {p.label}
            </option>
          ))}
          <option value="custom">Custom model ID…</option>
        </select>
      </div>
      {showCustom ? (
        <div class="module-row module-row-wrap">
          <label for="model-custom">Custom ID</label>
          <input
            id="model-custom"
            type="text"
            spellcheck={false}
            autoComplete="off"
            value={customModel}
            placeholder={DEFAULT_CLAUDE_MODEL}
            aria-invalid={modelError ? true : undefined}
            aria-describedby="model-custom-help"
            onInput={(e) => {
              setCustomModel((e.target as HTMLInputElement).value);
              setModelError(null);
            }}
            onBlur={commitCustomModel}
            onKeyDown={(e) => {
              if (e.key === 'Enter') commitCustomModel();
            }}
          />
          <p id="model-custom-help" class={modelError ? 'error-text' : 'muted'} role={modelError ? 'alert' : undefined}>
            {modelError ?? `In use: ${settings.claudeModel}`}
          </p>
        </div>
      ) : null}

      <h2>Cache</h2>
      <p class="muted">Results are cached in IndexedDB per module and TTL. Errors are kept for at most 2 minutes.</p>
      <button
        type="button"
        onClick={() =>
          void getCache()
            .clear()
            .then(
              () => setCacheMsg('Cache cleared.'),
              (err: unknown) => setCacheMsg(`Failed: ${errMsg(err)}`),
            )
        }
      >
        Clear cache
      </button>{' '}
      <span role="status">{cacheMsg}</span>
    </main>
  );
}
