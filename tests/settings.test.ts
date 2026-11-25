import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import {
  DEFAULT_CLAUDE_MODEL,
  coerceSettings,
  isModuleEnabled,
  isValidModelId,
  loadSettings,
  onSettingsChanged,
  saveKey,
  saveSettings,
} from '@/lib/settings';

beforeEach(() => {
  fakeBrowser.reset();
});

describe('settings coercion', () => {
  it('falls back to defaults for junk', () => {
    for (const junk of [undefined, null, 42, 'x', [], [1, 2], true]) {
      expect(coerceSettings(junk)).toEqual({ keys: {}, modules: {}, claudeModel: DEFAULT_CLAUDE_MODEL });
    }
  });

  it('keeps only known providers with non-blank string keys, trimmed', () => {
    const s = coerceSettings({
      keys: { virustotal: '  vt-key \n', otx: '   ', abuseipdb: 123, bogus: 'k', __proto__: 'x', anthropic: 'sk-ant' },
    });
    expect(s.keys).toEqual({ virustotal: 'vt-key', anthropic: 'sk-ant' });
    expect(Object.keys(s.keys)).not.toContain('bogus');
  });

  it('ignores keys/modules stored as arrays', () => {
    const s = coerceSettings({ keys: ['a', 'b'], modules: [true, false] });
    expect(s.keys).toEqual({});
    expect(s.modules).toEqual({});
  });

  it('keeps boolean module toggles only', () => {
    const s = coerceSettings({ modules: { dns: false, claude: true, rdap: 'no', pdns: 0 } });
    expect(s.modules).toEqual({ dns: false, claude: true });
  });

  it('validates the Claude model id', () => {
    expect(coerceSettings({ claudeModel: ' claude-haiku-5-5 ' }).claudeModel).toBe('claude-haiku-5-5');
    expect(coerceSettings({ claudeModel: 'has spaces in it' }).claudeModel).toBe(DEFAULT_CLAUDE_MODEL);
    expect(coerceSettings({ claudeModel: 'x' }).claudeModel).toBe(DEFAULT_CLAUDE_MODEL);
    expect(coerceSettings({ claudeModel: 7 }).claudeModel).toBe(DEFAULT_CLAUDE_MODEL);
    expect(isValidModelId('claude-sonnet-5-5')).toBe(true);
    expect(isValidModelId('anthropic.claude-opus-5-5:0')).toBe(true);
    expect(isValidModelId('')).toBe(false);
    expect(isValidModelId('claude opus')).toBe(false);
    expect(isValidModelId('a'.repeat(101))).toBe(false);
  });

  it('module enablement: override, then module default, then on', () => {
    const s = coerceSettings({ modules: { a: false } });
    expect(isModuleEnabled({ id: 'a', defaultEnabled: true }, s)).toBe(false);
    expect(isModuleEnabled({ id: 'b', defaultEnabled: false }, s)).toBe(false);
    expect(isModuleEnabled({ id: 'c' }, s)).toBe(true);
  });
});

describe('settings storage', () => {
  it('stores in storage.local only (never sync)', async () => {
    const syncSet = vi.spyOn(fakeBrowser.storage.sync, 'set');
    await saveKey('virustotal', 'vt-key');
    expect(syncSet).not.toHaveBeenCalled();
    expect(await fakeBrowser.storage.local.get('settings')).toEqual({
      settings: { keys: { virustotal: 'vt-key' }, modules: {}, claudeModel: DEFAULT_CLAUDE_MODEL },
    });
  });

  it('loads junk from storage without throwing', async () => {
    await fakeBrowser.storage.local.set({ settings: { keys: 'nope', modules: null, claudeModel: '' } });
    expect(await loadSettings()).toEqual({ keys: {}, modules: {}, claudeModel: DEFAULT_CLAUDE_MODEL });
  });

  it('concurrent saves do not drop each other (serialised read-modify-write)', async () => {
    await Promise.all([
      saveSettings({ modules: { dns: false } }),
      saveSettings({ modules: { rdap: false } }),
      saveKey('otx', 'otx-key'),
      saveKey('virustotal', 'vt-key'),
      saveSettings({ claudeModel: 'claude-haiku-5-5' }),
    ]);
    expect(await loadSettings()).toEqual({
      keys: { otx: 'otx-key', virustotal: 'vt-key' },
      modules: { dns: false, rdap: false },
      claudeModel: 'claude-haiku-5-5',
    });
  });

  it('saveKey removes a key when the value is blank and leaves the others', async () => {
    await saveKey('otx', 'otx-key');
    await saveKey('virustotal', 'vt-key');
    const s = await saveKey('otx', '   ');
    expect(s.keys).toEqual({ virustotal: 'vt-key' });
    expect((await loadSettings()).keys).toEqual({ virustotal: 'vt-key' });
  });

  it('rejects an invalid model id instead of silently resetting to the default', async () => {
    await saveSettings({ claudeModel: 'claude-sonnet-5-5' });
    await expect(saveSettings({ claudeModel: 'not a model' })).rejects.toThrow(/Invalid model ID/);
    expect((await loadSettings()).claudeModel).toBe('claude-sonnet-5-5');
    // The queue keeps working after a failed write.
    await saveSettings({ modules: { dns: true } });
    expect((await loadSettings()).modules).toEqual({ dns: true });
  });

  it('notifies listeners with coerced settings from storage.local only', async () => {
    const cb = vi.fn();
    const off = onSettingsChanged(cb);
    await saveKey('shodan', ' sh-key ');
    expect(cb).toHaveBeenLastCalledWith({ keys: { shodan: 'sh-key' }, modules: {}, claudeModel: DEFAULT_CLAUDE_MODEL });
    cb.mockClear();
    await fakeBrowser.storage.sync.set({ settings: { keys: { otx: 'x' } } });
    expect(cb).not.toHaveBeenCalled();
    off();
    await saveKey('otx', 'y');
    expect(cb).not.toHaveBeenCalled();
  });
});
