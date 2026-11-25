import { describe, expect, it } from 'vitest';
import { hasKeyTester, testKey } from '@/lib/keytest';
import { PROVIDERS } from '@/lib/settings';
import '@/modules/keytests';
import { json, mockFetch } from './helpers';

describe('key tests', () => {
  it('registers a tester for every provider on the settings page', () => {
    for (const p of PROVIDERS) expect(hasKeyTester(p.key), p.key).toBe(true);
  });

  it('refuses a blank key or one with spaces/non-ASCII without any request', async () => {
    const { fetch, calls } = mockFetch();
    await expect(testKey('anthropic', '   ', fetch)).rejects.toThrow(/Enter a key/);
    await expect(testKey('anthropic', 'sk-ant one', fetch)).rejects.toThrow(/spaces or characters/);
    await expect(testKey('virustotal', 'abc​def', fetch)).rejects.toThrow(/spaces or characters/);
    expect(calls).toHaveLength(0);
  });

  it('Anthropic: GET /v1/models with the direct-browser-access headers, trimmed key', async () => {
    const { fetch, calls } = mockFetch((u) =>
      u.href === 'https://api.anthropic.com/v1/models?limit=1' ? json({ data: [{ id: 'claude-opus-5-5' }] }) : undefined,
    );
    await expect(testKey('anthropic', '  sk-ant-test \n', fetch)).resolves.toMatch(/Key accepted.*claude-opus-5-5/);
    const h = calls[0]!.init.headers as Record<string, string>;
    expect(h['x-api-key']).toBe('sk-ant-test');
    expect(h['anthropic-version']).toBe('2023-06-01');
    expect(h['anthropic-dangerous-direct-browser-access']).toBe('true');
    expect(calls[0]!.init.credentials).toBe('omit');
  });

  it('Anthropic: 401 becomes a clear message that does not echo the key', async () => {
    const { fetch } = mockFetch(() => json({ type: 'error', error: { type: 'authentication_error', message: 'invalid x-api-key' } }, 401));
    const err = await testKey('anthropic', 'sk-ant-secret', fetch).catch((e: unknown) => e as Error);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toBe('Anthropic rejected this key.');
    expect((err as Error).message).not.toContain('sk-ant-secret');
  });

  it('redacts the key if a provider error body echoes it', async () => {
    const { fetch } = mockFetch(() => json({ error: { message: 'bad request for key sk-ant-echoed' } }, 400));
    const err = await testKey('anthropic', 'sk-ant-echoed', fetch).catch((e: unknown) => e as Error);
    expect((err as Error).message).toContain('[key]');
    expect((err as Error).message).not.toContain('sk-ant-echoed');
  });

  it('Mnemonic: limit above the public cap proves the key is honoured', async () => {
    const ok = mockFetch((u) => (u.pathname === '/pdns/v3/example.com' && u.searchParams.get('limit') === '1001' ? json({ data: [] }) : undefined));
    await expect(testKey('mnemonic', 'argus-key', ok.fetch)).resolves.toMatch(/Key accepted/);
    expect((ok.calls[0]!.init.headers as Record<string, string>)['Argus-API-Key']).toBe('argus-key');

    const pub = mockFetch(() => json({ messages: [{ message: 'Maximum result limit for public usage is 1000' }] }, 412));
    await expect(testKey('mnemonic', 'argus-key', pub.fetch)).rejects.toThrow(/treated as public/);

    const bad = mockFetch(() => json({ messages: [{ message: 'Not authenticated' }] }, 401));
    await expect(testKey('mnemonic', 'argus-key', bad.fetch)).rejects.toThrow('Mnemonic rejected this key.');
  });
});
