/** IP helpers: validation, canonical form, and "is this worth investigating" checks. */

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export function isIPv4(s: string): boolean {
  return IPV4_RE.test(s);
}

/**
 * Only hex digits, colons and dots (IPv4 tail) may reach the URL parser below:
 * anything else (`]`, `@`, `/`) would let the string escape the `[...]` literal
 * and be parsed as a different host, e.g. `::1]@evil.example/[`.
 */
const IPV6_CHARS_RE = /^[0-9a-f:.]{2,45}$/i;

/** Canonical (lowercase, compressed) form of an IPv6 literal, or null. */
function canonicalV6(s: string): string | null {
  if (!s.includes(':') || !IPV6_CHARS_RE.test(s)) return null;
  try {
    // The URL parser validates and canonicalises IPv6 literals.
    const host = new URL(`http://[${s}]/`).hostname;
    return host.startsWith('[') && host.endsWith(']') && host.length > 2 ? host.slice(1, -1).toLowerCase() : null;
  } catch {
    return null;
  }
}

export function isIPv6(s: string): boolean {
  return canonicalV6(s) !== null;
}

/** Canonical form (lowercase, compressed IPv6) or null if not an IP. */
export function normalizeIp(s: string): string | null {
  const v = s.trim().replace(/^\[|\]$/g, '');
  if (isIPv4(v)) return v;
  return canonicalV6(v);
}

function v4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

function inV4(ip: number, cidr: string): boolean {
  const [base, bits] = cidr.split('/') as [string, string];
  const n = Number(bits);
  const mask = n === 0 ? 0 : (~0 << (32 - n)) >>> 0;
  return (ip & mask) === (v4ToInt(base) & mask);
}

const V4_NON_PUBLIC = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.0.2.0/24',
  '192.88.99.0/24',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '198.51.100.0/24',
  '203.0.113.0/24',
  '224.0.0.0/4',
  '240.0.0.0/4',
];

/** Expand a canonical IPv6 string to 8 hextets. */
function expandV6(ip: string): number[] | null {
  const n = normalizeIp(ip);
  if (!n || !n.includes(':')) return null;
  // IPv4-mapped tails (::ffff:1.2.3.4) are already canonicalised to hex by URL.
  const [head, tail] = n.includes('::') ? (n.split('::') as [string, string]) : [n, undefined];
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail !== '' ? tail.split(':') : [];
  const fill = tail !== undefined ? 8 - h.length - t.length : 0;
  const parts = [...h, ...Array<string>(fill).fill('0'), ...t];
  if (parts.length !== 8) return null;
  return parts.map((p) => parseInt(p || '0', 16));
}

/** False for private, loopback, link-local, CGNAT, multicast, documentation and reserved ranges. */
export function isPublicIp(ip: string): boolean {
  const n = normalizeIp(ip);
  if (!n) return false;
  if (isIPv4(n)) {
    const x = v4ToInt(n);
    return !V4_NON_PUBLIC.some((c) => inV4(x, c));
  }
  const h = expandV6(n);
  if (!h) return false;
  const [a = 0, b = 0] = h;
  if (h.every((x) => x === 0)) return false; // ::
  if (h.slice(0, 7).every((x) => x === 0) && h[7] === 1) return false; // ::1
  if ((a & 0xfe00) === 0xfc00) return false; // fc00::/7 ULA
  if ((a & 0xffc0) === 0xfe80) return false; // fe80::/10 link-local
  if ((a & 0xff00) === 0xff00) return false; // multicast
  if (a === 0x2001 && b === 0x0db8) return false; // 2001:db8::/32 documentation
  if (a === 0x3fff && b < 0x1000) return false; // 3fff::/20 documentation (RFC 9637)
  if (h.slice(0, 5).every((x) => x === 0) && h[5] === 0xffff) {
    // IPv4-mapped: judge the embedded IPv4 address
    const v4 = `${h[6]! >> 8}.${h[6]! & 255}.${h[7]! >> 8}.${h[7]! & 255}`;
    return isPublicIp(v4);
  }
  // 64:ff9b::/96 NAT64, ::a.b.c.d, 100::/64 discard, 5f00::/16 SRv6... all fall outside
  // 2000::/3, the only global unicast block.
  if ((a & 0xe000) !== 0x2000) return false;
  if (a === 0x2002) return false; // 2002::/16 6to4: an encapsulated IPv4 address, not a host to look up
  if (a === 0x2001 && b < 0x0200) {
    // 2001::/23 IETF protocol assignments (Teredo 2001::/32, benchmarking 2001:2::/48,
    // ORCHID 2001:10::/28) are not globally reachable, except a few anycast/overlay blocks.
    const c = h[2] ?? 0;
    const anycast = b === 0x0001 && h.slice(2, 7).every((x) => x === 0) && (h[7] ?? 0) >= 1 && (h[7] ?? 0) <= 3; // 2001:1::1-3
    const amt = b === 0x0003; // 2001:3::/32
    const as112 = b === 0x0004 && c === 0x0112; // 2001:4:112::/48
    const orchid2OrDrip = (b & 0xfff0) === 0x0020 || (b & 0xfff0) === 0x0030; // 2001:20::/28, 2001:30::/28
    return anycast || amt || as112 || orchid2OrDrip;
  }
  return true;
}
