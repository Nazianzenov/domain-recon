import { browser } from 'wxt/browser';
import { PROVIDER_KEY_NAMES } from './providers';
import type { Module, ProviderKey, Settings } from './types';

/**
 * Default Claude model for brand identification. Opus 5.5 rather than Haiku:
 * brand recognition and "which domain is official" judgements benefit from
 * the larger model; users can pick a cheaper preset in settings.
 */
export const DEFAULT_CLAUDE_MODEL = 'claude-opus-5-5';

export const CLAUDE_MODEL_PRESETS: ReadonlyArray<{ id: string; label: string }> = [
  { id: 'claude-opus-5-5', label: 'Claude Opus 5.5 (best judgement)' },
  { id: 'claude-sonnet-5-5', label: 'Claude Sonnet 5.5 (balanced)' },
  { id: 'claude-haiku-5-5', label: 'Claude Haiku 5.5 (cheapest, fastest)' },
];

export const PROVIDERS: ReadonlyArray<{ key: ProviderKey; label: string; help: string; url: string }> = [
  { key: 'virustotal', label: 'VirusTotal', help: 'Free community key: 4 requests/min, 500/day.', url: 'https://www.virustotal.com/gui/my-apikey' },
  { key: 'otx', label: 'AlienVault OTX', help: 'Free account key.', url: 'https://otx.alienvault.com/settings' },
  { key: 'abuseipdb', label: 'AbuseIPDB', help: 'Free tier: 1,000 checks/day.', url: 'https://www.abuseipdb.com/account/api' },
  { key: 'abusech', label: 'abuse.ch (URLhaus + ThreatFox)', help: 'Free Auth-Key from abuse.ch Authentication Portal.', url: 'https://auth.abuse.ch/' },
  {
    key: 'shodan',
    label: 'Shodan (optional)',
    help: 'InternetDB works without a key; a key adds the host lookup (services, org, ASN), which needs a paid Shodan Membership.',
    url: 'https://account.shodan.io/',
  },
  {
    key: 'mnemonic',
    label: 'Mnemonic Argus (optional)',
    help: 'Passive DNS works without a key (TLP:WHITE data, 1000 records per lookup, 10/min, 1000/day). A key raises the limits. Keys come from argus-support@mnemonic.no.',
    url: 'https://docs.mnemonic.no/',
  },
  { key: 'anthropic', label: 'Anthropic', help: 'Used only for the AI brand check (active).', url: 'https://platform.claude.com/settings/keys' },
];

export const DEFAULT_SETTINGS: Settings = {
  keys: {},
  modules: {},
  claudeModel: DEFAULT_CLAUDE_MODEL,
};

const STORAGE_KEY = 'settings';

const MODEL_ID_RE = /^[\w.:@-]{3,100}$/;

/** Shape check for a (custom) Claude model ID; the settings page validates input with it. */
export function isValidModelId(id: string): boolean {
  return MODEL_ID_RE.test(id.trim());
}

function isProviderKey(k: string): k is ProviderKey {
  return Object.hasOwn(PROVIDER_KEY_NAMES, k);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** Tolerates anything in storage (older versions, manual edits, junk): unknown providers and bad types are dropped. */
export function coerceSettings(v: unknown): Settings {
  const s = isPlainObject(v) ? v : {};
  const keys: Settings['keys'] = {};
  const rawKeys = s['keys'];
  if (isPlainObject(rawKeys)) {
    for (const [k, val] of Object.entries(rawKeys)) {
      if (isProviderKey(k) && typeof val === 'string' && val.trim()) keys[k] = val.trim();
    }
  }
  const modules: Settings['modules'] = {};
  const rawModules = s['modules'];
  if (isPlainObject(rawModules)) {
    for (const [k, val] of Object.entries(rawModules)) {
      if (typeof val === 'boolean' && k !== '__proto__') modules[k] = val;
    }
  }
  const model = s['claudeModel'];
  const claudeModel = typeof model === 'string' && isValidModelId(model) ? model.trim() : DEFAULT_CLAUDE_MODEL;
  return { keys, modules, claudeModel };
}

/** Settings live in storage.local only (never sync): API keys must not leave the device. */
export async function loadSettings(): Promise<Settings> {
  const got = await browser.storage.local.get(STORAGE_KEY);
  return coerceSettings(got[STORAGE_KEY]);
}

/*
 * Every write is a read-modify-write of one storage entry. Writes are queued so
 * two quick edits (a key saved on blur, a module toggled right after) cannot
 * both read the same old value and drop each other's change.
 */
let writeQueue: Promise<unknown> = Promise.resolve();

function serialized<T>(fn: () => Promise<T>): Promise<T> {
  const run = writeQueue.then(fn, fn);
  writeQueue = run.catch(() => undefined);
  return run;
}

async function write(next: Settings): Promise<Settings> {
  await browser.storage.local.set({ [STORAGE_KEY]: next });
  return next;
}

export function saveSettings(patch: Partial<Settings>): Promise<Settings> {
  return serialized(async () => {
    if (patch.claudeModel !== undefined && !isValidModelId(patch.claudeModel)) {
      throw new Error(`Invalid model ID: ${patch.claudeModel}`);
    }
    const current = await loadSettings();
    return write(
      coerceSettings({
        ...current,
        ...patch,
        keys: patch.keys ?? current.keys,
        modules: { ...current.modules, ...patch.modules },
      }),
    );
  });
}

/** Set one provider's key, or remove it when `value` is blank, leaving the other keys untouched. */
export function saveKey(provider: ProviderKey, value: string): Promise<Settings> {
  return serialized(async () => {
    const current = await loadSettings();
    const keys = { ...current.keys };
    const v = value.trim();
    if (v) keys[provider] = v;
    else delete keys[provider];
    return write(coerceSettings({ ...current, keys }));
  });
}

export function onSettingsChanged(cb: (s: Settings) => void): () => void {
  const listener = (changes: Record<string, { newValue?: unknown }>, area: string) => {
    if (area === 'local' && changes[STORAGE_KEY]) cb(coerceSettings(changes[STORAGE_KEY].newValue));
  };
  browser.storage.onChanged.addListener(listener);
  return () => browser.storage.onChanged.removeListener(listener);
}

export function isModuleEnabled(m: Pick<Module, 'id' | 'defaultEnabled'>, s: Settings): boolean {
  return s.modules[m.id] ?? m.defaultEnabled ?? true;
}
