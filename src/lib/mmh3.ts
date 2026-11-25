/**
 * MurmurHash3 x86_32 (Austin Appleby), returning a SIGNED int32 like
 * Python's `mmh3.hash()` (what Shodan's http.favicon.hash uses).
 */
export function mmh3(bytes: Uint8Array, seed = 0): number {
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  const len = bytes.length;
  const blocks = len & ~3;
  let h = seed | 0;
  for (let i = 0; i < blocks; i += 4) {
    let k = bytes[i]! | (bytes[i + 1]! << 8) | (bytes[i + 2]! << 16) | (bytes[i + 3]! << 24);
    k = Math.imul(k, c1);
    k = (k << 15) | (k >>> 17);
    k = Math.imul(k, c2);
    h ^= k;
    h = (h << 13) | (h >>> 19);
    h = (Math.imul(h, 5) + 0xe6546b64) | 0;
  }
  const rem = len & 3;
  if (rem > 0) {
    let k = 0;
    if (rem === 3) k ^= bytes[blocks + 2]! << 16;
    if (rem >= 2) k ^= bytes[blocks + 1]! << 8;
    k ^= bytes[blocks]!;
    k = Math.imul(k, c1);
    k = (k << 15) | (k >>> 17);
    k = Math.imul(k, c2);
    h ^= k;
  }
  h ^= len;
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h | 0;
}
