import { describe, expect, it } from 'vitest';
import { encodebytes, faviconHashes, md5Hex, sha256Hex, shodanFaviconHash, shodanSearchUrl } from '@/lib/favhash';
import { mmh3 } from '@/lib/mmh3';
import fixtures from './fixtures/favicon-hashes.json';

/**
 * Fixtures generated with Python's `mmh3` and `base64.encodebytes`
 * (scripts/gen_favicon_fixtures.py), i.e. exactly what Shodan computes.
 */

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

describe('mmh3 (MurmurHash3 x86_32, signed)', () => {
  it.each(fixtures.raw.map((r) => [r.hex, r.seed, r.mmh3] as const))('hex=%s seed=%i -> %i', (hex, seed, expected) => {
    expect(mmh3(hexToBytes(hex), seed)).toBe(expected);
  });

  it('returns signed values (negative hashes exist)', () => {
    expect(fixtures.favicon.some((c) => c.mmh3 < 0)).toBe(true);
  });
});

describe('Shodan favicon hash = mmh3(base64.encodebytes(bytes))', () => {
  for (const c of fixtures.favicon) {
    it(c.name, async () => {
      const bytes = hexToBytes(c.hex);
      expect(encodebytes(bytes)).toBe(c.b64);
      expect(shodanFaviconHash(bytes)).toBe(c.mmh3);
      expect(mmh3(bytes)).toBe(c.mmh3_raw);
      expect(md5Hex(bytes)).toBe(c.md5);
      expect(await sha256Hex(bytes)).toBe(c.sha256);
    });
  }

  it('wraps at 76 chars with a newline after every line including the last', () => {
    const b64 = encodebytes(new Uint8Array(200));
    const lines = b64.split('\n');
    expect(lines.at(-1)).toBe('');
    expect(lines.slice(0, -2).every((l) => l.length === 76)).toBe(true);
  });

  it('hashes a sub-array view correctly (no stray buffer bytes)', async () => {
    const big = hexToBytes(fixtures.favicon[2]!.hex.padStart(fixtures.favicon[2]!.hex.length + 8, 'ff'));
    const view = big.subarray(4);
    const h = await faviconHashes(view);
    expect(h).toEqual({ mmh3: fixtures.favicon[2]!.mmh3, md5: fixtures.favicon[2]!.md5, sha256: fixtures.favicon[2]!.sha256 });
  });

  it('builds the Shodan search link', () => {
    expect(shodanSearchUrl(-1253000196)).toBe('https://www.shodan.io/search?query=http.favicon.hash%3A-1253000196');
  });
});
