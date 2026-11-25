import SparkMD5 from 'spark-md5';
import { mmh3 } from './mmh3';

/** Standard base64 of raw bytes (chunked so large icons don't blow the call stack). */
export function toBase64(bytes: Uint8Array): string {
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

/**
 * Python `base64.encodebytes()`: base64 wrapped at 76 characters with "\n"
 * after EVERY line, including the last. Empty input -> empty string.
 */
export function encodebytes(bytes: Uint8Array): string {
  const b64 = toBase64(bytes);
  let out = '';
  for (let i = 0; i < b64.length; i += 76) out += `${b64.slice(i, i + 76)}\n`;
  return out;
}

/** Shodan `http.favicon.hash`: mmh3 (x86_32, seed 0, signed) of encodebytes(raw). */
export function shodanFaviconHash(bytes: Uint8Array): number {
  return mmh3(new TextEncoder().encode(encodebytes(bytes)), 0);
}

export function md5Hex(bytes: Uint8Array): string {
  // spark-md5 wants an ArrayBuffer of exactly these bytes.
  const copy = bytes.slice();
  return SparkMD5.ArrayBuffer.hash(copy.buffer);
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes.slice());
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export interface FaviconHashes {
  mmh3: number;
  md5: string;
  sha256: string;
}

export async function faviconHashes(bytes: Uint8Array): Promise<FaviconHashes> {
  return { mmh3: shodanFaviconHash(bytes), md5: md5Hex(bytes), sha256: await sha256Hex(bytes) };
}

export function shodanSearchUrl(hash: number): string {
  return `https://www.shodan.io/search?query=${encodeURIComponent(`http.favicon.hash:${hash}`)}`;
}
