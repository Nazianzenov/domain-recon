import { createHttp, type Http } from './http';
import { RateLimiter } from './ratelimit';
import type { ProviderKey } from './types';

/**
 * "Test" buttons on the settings page. Each tester makes one cheap
 * authenticated call and resolves to a short human message, or throws.
 */
export type KeyTester = (key: string, http: Http) => Promise<string>;

const testers: Partial<Record<ProviderKey, KeyTester>> = {};

export function registerKeyTester(p: ProviderKey, t: KeyTester): void {
  testers[p] = t;
}

export function hasKeyTester(p: ProviderKey): boolean {
  return !!testers[p];
}

const limiter = new RateLimiter();

/** Every supported provider issues keys made of printable ASCII without spaces. */
const KEY_CHARS_RE = /^[\x21-\x7e]+$/;

export async function testKey(p: ProviderKey, key: string, fetchImpl: typeof fetch = globalThis.fetch.bind(globalThis)): Promise<string> {
  const t = testers[p];
  if (!t) throw new Error('No test available for this provider yet.');
  const k = key.trim();
  if (!k) throw new Error('Enter a key first.');
  // fetch() rejects such header values with a TypeError that would read as a network/CORS failure.
  if (!KEY_CHARS_RE.test(k)) throw new Error('The key contains spaces or characters API keys never use. Copy it again from the provider.');
  const http = createHttp({ fetch: fetchImpl, limiter, signal: new AbortController().signal });
  // The message is shown on the settings page: never let an API's error body echo the key back.
  const redact = (s: string) => s.split(k).join('[key]');
  try {
    return redact(await t(k, http));
  } catch (err) {
    throw new Error(redact(err instanceof Error ? err.message : String(err)));
  }
}
