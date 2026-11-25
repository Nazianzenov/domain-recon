import { describe, expect, it } from 'vitest';
import { isIPv6, isPublicIp, normalizeIp } from '@/lib/ip';
import { IP_ERROR, normalizeInput, refang } from '@/lib/normalize';
import { decodeLabel, toUnicode } from '@/lib/punycode';

function ok(input: string) {
  const r = normalizeInput(input);
  if (!r.ok) throw new Error(`expected ok for ${input}: ${r.error}`);
  return r;
}

describe('refang', () => {
  it.each([
    ['example[.]com', 'example.com'],
    ['example(.)com', 'example.com'],
    ['example{.}com', 'example.com'],
    ['example[dot]com', 'example.com'],
    ['example\\.com', 'example.com'],
    ['hxxps://evil[.]com/login', 'https://evil.com/login'],
    ['hXXp://evil[.]com', 'http://evil.com'],
    ['hxxps[:]//evil[.]com', 'https://evil.com'],
    ['https[://]evil[.]com', 'https://evil.com'],
    ['user[@]example[.]com', 'user@example.com'],
    ['user[at]example[.]com', 'user@example.com'],
    ['user [at] example [dot] com', 'user@example.com'],
    ['2001[:]db8[:][:]1', '2001:db8::1'],
    ['fxp://files[.]example', 'ftp://files.example'],
  ])('%s -> %s', (input, expected) => {
    expect(refang(input)).toBe(expected);
  });
});

describe('normalizeInput', () => {
  it.each([
    ['example.com', 'example.com'],
    ['  Example.COM  ', 'example.com'],
    ['example.com.', 'example.com'],
    ['https://www.example.com:8443/path?q=1#frag', 'www.example.com'],
    ['http://user:pass@login.example.com/', 'login.example.com'],
    ['www.example.com/some/path', 'www.example.com'],
    ['example.com:8080', 'example.com'],
    ['hxxps://phish[.]example[.]net/secure/login.php', 'phish.example.net'],
    ['ceo@corp-example[.]com', 'corp-example.com'],
    ['mailto:ceo@example.org', 'example.org'],
    ['Please block hxxp://bad[.]example[.]com/x ASAP', 'bad.example.com'],
    ['"example.com",', 'example.com'],
    ['<https://example.com>', 'example.com'],
    ['ftp://files.example.com', 'files.example.com'],
    ['xn--bcher-kva.de', 'xn--bcher-kva.de'],
    // sentences: the first token that yields a valid hostname wins
    ['Mr. Smith reported evil.example today.', 'evil.example'],
    ['e.g. phish.example', 'phish.example'],
    ['Check http://localhost/ and evil.example', 'evil.example'],
    // an @ after the authority is not an email address
    ['evil.example?login=ceo@corp.example', 'evil.example'],
    ['evil.example#ceo@corp.example', 'evil.example'],
    ['evil.example\\@corp.example', 'evil.example'],
    ['user:pass@evil.example/x', 'evil.example'],
    // non-special schemes still get IDNA processing
    ['sftp://BÜCHER.de/x', 'xn--bcher-kva.de'],
    ['ws://Example.COM', 'example.com'],
    // typographic quotes and trailing punctuation from pasted prose
    ['“example.com”', 'example.com'],
    ['(see example.com).', 'example.com'],
    ['example.com…', 'example.com'],
    ['evil。example', 'evil.example'],
  ])('%s -> %s', (input, expected) => {
    expect(ok(input).domain).toBe(expected);
  });

  it('converts IDN to punycode via new URL() and keeps the Unicode form', () => {
    const r = ok('BÜCHER.de');
    expect(r.domain).toBe('xn--bcher-kva.de');
    expect(r.unicode).toBe('bücher.de');
    expect(r.isIdn).toBe(true);
  });

  it('decodes punycode input back to Unicode for display', () => {
    const r = ok('https://xn--80ak6aa92e.com/');
    expect(r.domain).toBe('xn--80ak6aa92e.com');
    expect(r.unicode).toBe('аррӏе.com'); // Cyrillic look-alike of apple.com
    expect(r.isIdn).toBe(true);
  });

  it('handles IDN TLDs', () => {
    const r = ok('пример.рф');
    expect(r.domain).toBe('xn--e1afmkfd.xn--p1ai');
    expect(r.unicode).toBe('пример.рф');
  });

  it('plain ASCII domains are not IDN', () => {
    const r = ok('example.com');
    expect(r.isIdn).toBe(false);
    expect(r.unicode).toBe('example.com');
  });

  it.each([
    '1.2.3.4',
    'http://1.2.3.4/x',
    '8.8.8[.]8',
    '[2001:db8::1]',
    '2001:db8::1',
    'http://[::1]:8080/',
    'http://0x7f.1/',
    // bracketed with a port, bare without the closing bracket being trimmed, prefix, zone, trailing ::
    '[2001:db8::1]:443',
    'http://[2001:db8::1]',
    '(http://[2001:db8::1])',
    '2001:db8::/32',
    'fe80::1%eth0',
    '2001:db8::',
    '::ffff:1.2.3.4',
    '2001[:]db8[:][:]1',
    // every IPv4 form the URL parser accepts
    '2130706433',
    '017700000001',
    '0x7f000001',
    '127.1',
    '１２７.０.０.１',
    'Mr. Smith saw 1.2.3.4',
  ])(
    'rejects IP input %s',
    (input) => {
      const r = normalizeInput(input);
      expect(r).toEqual({ ok: false, error: IP_ERROR });
    },
  );

  it.each([
    ['', /Enter a domain/],
    ['   ', /Enter a domain/],
    ['localhost', /fully qualified/],
    ['example', /fully qualified/],
    ['exa mple', /fully qualified|valid/],
    ['-bad.example.com', /Invalid hostname label/],
    ['bad-.example.com', /Invalid hostname label/],
    ['under_score.example.com', /Invalid hostname label/],
    // WHATWG URL treats a numeric last label as IPv4 and rejects it outright.
    ['example.123', /numeric|valid hostname/],
    ['example.c', /top-level/],
    ['a..b.com', /valid hostname|label/],
    ['http://', /valid hostname/],
    [`${'a'.repeat(64)}.com`, /Invalid hostname label|valid hostname/],
    [`${'abcdefghi.'.repeat(26)}com`, /253/],
    ['*.example.com', /Invalid hostname label|valid hostname/],
  ])('rejects junk %j', (input, re) => {
    const r = normalizeInput(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(re);
  });
});

describe('punycode decoder', () => {
  it.each([
    ['bcher-kva', 'bücher'],
    ['80ak6aa92e', 'аррӏе'],
    ['mnchen-3ya', 'münchen'],
    ['wgv71a119e', '日本語'],
  ])('%s -> %s', (a, u) => {
    expect(decodeLabel(a)).toBe(u);
  });

  it('leaves malformed labels untouched', () => {
    expect(toUnicode('xn--!!!.com')).toBe('xn--!!!.com');
  });

  it('decodes labels with no basic code points and uppercase A-labels', () => {
    expect(decodeLabel('wgv71a119e')).toBe('日本語');
    expect(toUnicode('XN--BCHER-KVA.DE')).toBe('bücher.DE');
  });

  it.each(['bcher-k!a', 'bcher-kv~', 'zzzzzzzzzzzzzzzzzz', '99999999999', '-abc', 'a-b-'])('throws on invalid or overflowing input %s', (s) => {
    let threw = false;
    let out = '';
    try {
      out = decodeLabel(s);
    } catch (e) {
      threw = e instanceof RangeError;
    }
    // "a-b-" is a valid basic-only encoding; everything else must throw.
    if (s === 'a-b-') expect(out).toBe('a-b');
    else expect(threw).toBe(true);
  });

  it('rejects surrogate code points', () => {
    expect(() => decodeLabel(encodeSingle(0xd800))).toThrow(RangeError);
    expect(decodeLabel(encodeSingle(0xe9))).toBe('é');
  });

  it.each([
    ['xn--.com', 'empty label'],
    ['xn--a-.com', 'decodes to plain ASCII "a" (would display as a.com)'],
    ['xn--example-.com', 'decodes to plain ASCII'],
  ])('keeps the A-label when the decoded form is not a plausible U-label: %s (%s)', (host) => {
    expect(toUnicode(host)).toBe(host);
  });

  it('keeps the A-label when the decoded form has invisible or separator characters', () => {
    expect(toUnicode(`xn--${encodeSingle(0x202e)}.com`)).toBe(`xn--${encodeSingle(0x202e)}.com`); // RTL override
    expect(toUnicode(`xn--${encodeSingle(0x3002)}.com`)).toBe(`xn--${encodeSingle(0x3002)}.com`); // ideographic full stop
    expect(toUnicode(`xn--${encodeSingle(0xe9)}.com`)).toBe('é.com');
  });
});

describe('ip helpers', () => {
  it.each([
    ['2001:0DB8:0000::0001', '2001:db8::1'],
    ['[2001:db8::1]', '2001:db8::1'],
    ['::ffff:1.2.3.4', '::ffff:102:304'],
    [' 8.8.8.8 ', '8.8.8.8'],
  ])('normalizeIp(%s) -> %s', (input, expected) => {
    expect(normalizeIp(input)).toBe(expected);
  });

  it.each([
    // strings that escape the [...] literal used for URL-based validation
    '::1]@evil.example/[',
    '2001:db8::1]:80/x#',
    '::1]/x?[',
    '[::1]@evil.example',
    'fe80::1%eth0',
    '01.2.3.4',
    '1.2.3',
    'evil.example',
    '',
  ])('normalizeIp/isIPv6 reject %j', (s) => {
    expect(normalizeIp(s)).toBeNull();
    expect(isIPv6(s)).toBe(false);
  });

  it.each([
    ['8.8.8.8', true],
    ['2606:4700:4700::1111', true],
    ['::ffff:8.8.8.8', true],
    ['2001:3::1', true], // AMT anycast inside 2001::/23
    ['2001:4:112::1', true], // AS112-v6
    ['2001:20::1', true], // ORCHIDv2
    ['10.0.0.1', false],
    ['100.64.0.1', false], // CGNAT
    ['169.254.1.1', false],
    ['192.0.2.1', false],
    ['198.18.0.1', false],
    ['224.0.0.1', false],
    ['255.255.255.255', false],
    ['::', false],
    ['::1', false],
    ['::ffff:10.0.0.1', false], // IPv4-mapped private
    ['::ffff:0:a00:1', false], // IPv4-translated
    ['64:ff9b::808:808', false], // NAT64
    ['fd00::1', false], // ULA
    ['fe80::1', false], // link-local
    ['ff02::1', false], // multicast
    ['2001:db8::1', false], // documentation
    ['3fff::1', false], // documentation (RFC 9637)
    ['3fff:fff::1', false],
    ['2001::1', false], // Teredo
    ['2001:0:4136:e378:8000:63bf:3fff:fdd2', false], // Teredo
    ['2001:2::1', false], // benchmarking
    ['2001:10::1', false], // ORCHID (deprecated)
    ['2002:c000:204::1', false], // 6to4
    ['100::1', false], // discard-only
    ['5f00::1', false], // SRv6 SIDs
    ['not an ip', false],
  ])('isPublicIp(%s) = %s', (ip, expected) => {
    expect(isPublicIp(ip)).toBe(expected);
  });

  it('3fff::/20 is documentation but 3fff:1000:: is not in it', () => {
    expect(isPublicIp('3fff:1000::1')).toBe(true);
  });
});

/** RFC 3492 encoding of a one-code-point label (no basic code points): a single delta. */
function encodeSingle(cp: number): string {
  // First (and only) delta = (cp - 128) * (0 + 1); bias starts at 72.
  let q = cp - 128;
  let out = '';
  const digit = (d: number) => String.fromCharCode(d < 26 ? 97 + d : 22 + d);
  for (let k = 36; ; k += 36) {
    const t = k <= 72 ? 1 : k >= 72 + 26 ? 26 : k - 72;
    if (q < t) break;
    out += digit(t + ((q - t) % (36 - t)));
    q = Math.floor((q - t) / (36 - t));
  }
  return out + digit(q);
}
