import { describe, expect, it } from 'vitest';
import { defangDeep, defangText } from '@/lib/defang';
import { exportFilename, toJsonExport, toMarkdown, type ExportInput } from '@/lib/export';
import type { Module } from '@/lib/types';

describe('defangText', () => {
  it.each([
    ['https://evil.example/login?x=1', 'hxxps://evil[.]example/login?x=1'],
    ['http://evil.example', 'hxxp://evil[.]example'],
    ['HTTPS://Evil.Example/', 'HXXPS://Evil[.]Example/'],
    ['ftp://files.example.org/a', 'fxp://files[.]example[.]org/a'],
    ['visit evil.example now', 'visit evil[.]example now'],
    ['xn--80ak6aa92e.com', 'xn--80ak6aa92e[.]com'],
    ['203.0.113.7', '203[.]0[.]113[.]7'],
    ['2001:db8::1', '2001[:]db8[:][:]1'],
    ['ceo@corp.example', 'ceo[@]corp[.]example'],
    ['https://1.2.3.4:8080/x', 'hxxps://1[.]2[.]3[.]4:8080/x'],
  ])('%s -> %s', (input, expected) => {
    expect(defangText(input)).toBe(expected);
  });

  it.each([
    // IDN / Unicode hostnames (the export's root.unicode) and IDN TLDs
    ['аррӏе.com', 'аррӏе[.]com'],
    ['пример.рф', 'пример[.]рф'],
    ['see bücher.de', 'see bücher[.]de'],
    ['XN--80AK6AA92E.COM', 'XN--80AK6AA92E[.]COM'],
    ['evil.xn--p1ai', 'evil[.]xn--p1ai'],
    // dots that UTS #46 maps to "." (browsers resolve these)
    ['evil。com', 'evil[.]com'],
    ['ｇｏｏｇｌｅ．ｃｏｍ', 'ｇｏｏｇｌｅ[.]ｃｏｍ'],
    // labels the old pattern skipped, leaving an earlier dot live
    ['a_b.com.evil.example', 'a_b[.]com[.]evil[.]example'],
    ['_dmarc.evil.example', '_dmarc[.]evil[.]example'],
    [`${'a'.repeat(70)}.microsoft.com`, `${'a'.repeat(70)}[.]microsoft[.]com`],
    ['a-.evil.example', 'a-[.]evil[.]example'],
    ['login.microsoft[.]com', 'login[.]microsoft[.]com'],
    // punctuation, quotes and Markdown/chat emphasis around hosts
    ['_evil.example_', '_evil[.]example_'],
    ['*evil.example*', '*evil[.]example*'],
    ['`evil.example`', '`evil[.]example`'],
    ['<https://evil.example>', '<hxxps://evil[.]example>'],
    ['(evil.example),', '(evil[.]example),'],
    ['evil.example.', 'evil[.]example.'],
    ['evil.com-foo', 'evil[.]com-foo'],
    // URLs: userinfo/port, scheme glued to punctuation, already-defanged host, nested URL
    ['http://user:pw@evil.example:8080/p', 'hxxp://user:pw@evil[.]example:8080/p'],
    ['_https://evil.example', '_hxxps://evil[.]example'],
    ['https://evil[.]example/', 'hxxps://evil[.]example/'],
    ['hxxp://evil.example', 'hxxp://evil[.]example'],
    ['https://a.example/?u=http://b.example', 'hxxps://a[.]example/?u=hxxp://b[.]example'],
    // IPv4: zero-padded, fullwidth, glued to "_", IPv4-mapped IPv6
    ['192.168.001.001', '192[.]168[.]001[.]001'],
    ['ip_1.2.3.4', 'ip_1[.]2[.]3[.]4'],
    ['１２７．０．０．１', '１２７[.]０[.]０[.]１'],
    ['::ffff:1.2.3.4', '[:][:]ffff[:]1[.]2[.]3[.]4'],
    // IPv6: bracketed, in a URL with userinfo, 8 colons, zone, prefix
    ['[2001:db8::1]:443', '[2001[:]db8[:][:]1]:443'],
    ['https://u@[2001:db8::1]/', 'hxxps://u@[2001[:]db8[:][:]1]/'],
    ['http://[::1]:80/', 'hxxp://[[:][:]1]:80/'],
    ['1:2:3:4:5:6:7::', '1[:]2[:]3[:]4[:]5[:]6[:]7[:][:]'],
    ['::2:3:4:5:6:7:8', '[:][:]2[:]3[:]4[:]5[:]6[:]7[:]8'],
    ['fe80::1%eth0', 'fe80[:][:]1%eth0'],
    ['2001:db8::/32', '2001[:]db8[:][:]/32'],
    // emails with IDN domains
    ['user@bücher.de', 'user[@]bücher[.]de'],
    ['mailto:a@b.example', 'mailto:a[@]b[.]example'],
  ])('leaves no live indicator: %s -> %s', (input, expected) => {
    expect(defangText(input)).toBe(expected);
    expect(defangText(expected)).toBe(expected);
  });

  it('leaves CJK prose ending in an ideographic full stop alone', () => {
    expect(defangText('これは日本語です。次の文')).toBe('これは日本語です。次の文');
  });

  it.each([
    '2026-11-25T10:00:00.000Z',
    '12:30:00',
    'v1.2.3',
    'v1.2.3.4',
    'p=reject; pct=100',
    '3.14',
    '1.5GB',
    '10.0.19041.1',
    '1.3.6.1.4.1.311',
    'e.g. something',
    'U.S.A.',
    '-1253000196',
    'd41d8cd98f00b204e9800998ecf8427e',
    '00:1a:2b:3c:4d:5e',
    'std::vector',
    'Foo :: bar',
    'Mon, 25 Nov 2026 10:00:00 GMT',
    'data:text/html;base64,PHNjcmlwdD4=',
  ])('leaves non-indicators alone: %s', (s) => {
    expect(defangText(s)).toBe(s);
  });

  it('is idempotent', () => {
    const once = defangText('https://a.example/ 1.2.3.4 b.example 2001:db8::1 x@y.example аррӏе.com [::1] evil。com');
    expect(defangText(once)).toBe(once);
  });

  it('stays fast on adversarial input', () => {
    const t = Date.now();
    for (const s of ['a.'.repeat(50_000), '1.'.repeat(50_000), 'a@'.repeat(50_000), ':'.repeat(100_000), 'ab-'.repeat(40_000)]) defangText(s);
    expect(Date.now() - t).toBeLessThan(2000);
  });

  it('defangs nested values and keys', () => {
    expect(defangDeep({ 'evil.example': ['1.2.3.4', { u: 'http://a.example' }], n: 5, 'og:title': 'x' })).toEqual({
      'evil[.]example': ['1[.]2[.]3[.]4', { u: 'hxxp://a[.]example' }],
      n: 5,
      'og:title': 'x',
    });
  });

  it('keeps a JSON "__proto__" key as data and defangs toJSON values', () => {
    const parsed = JSON.parse('{"__proto__": "evil.example", "og:https://evil.example/": 1}') as Record<string, unknown>;
    expect(JSON.stringify(defangDeep(parsed))).toBe('{"__proto__":"evil[.]example","og:hxxps://evil[.]example/":1}');
    expect(JSON.stringify(defangDeep({ u: new URL('https://evil.example/a'), d: new Date(0) }))).toBe(
      '{"u":"hxxps://evil[.]example/a","d":"1970-01-01T00:00:00.000Z"}',
    );
  });
});

const mod: Module<{ a: string[] }> = {
  id: 'dns',
  label: 'DNS (DoH)',
  version: 1,
  accepts: ['domain'],
  ttl: 1,
  run: async () => ({ data: { a: [] } }),
  facts: (d) => [{ label: 'A', value: d.a, pivot: true }],
};

const input: ExportInput = {
  root: { domain: 'xn--80ak6aa92e.com', unicode: 'аррӏе.com', isIdn: true },
  generatedAt: Date.UTC(2026, 10, 25, 12, 0, 0),
  opsec: 'passive',
  entities: [
    { kind: 'domain', value: 'xn--80ak6aa92e.com', depth: 0 },
    { kind: 'ip', value: '203.0.113.7', depth: 1 },
  ],
  cards: [
    {
      id: 'dns|domain:xn--80ak6aa92e.com',
      moduleId: 'dns',
      label: 'DNS (DoH)',
      entity: { kind: 'domain', value: 'xn--80ak6aa92e.com', depth: 0 },
      status: 'cached',
      data: { a: ['203.0.113.7'] },
      summary: '1 A · see https://evil.example/x',
      fetchedAt: Date.UTC(2026, 10, 25, 9, 0, 0),
    },
    {
      id: 'vt|ip:203.0.113.7',
      moduleId: 'vt',
      label: 'VirusTotal',
      entity: { kind: 'ip', value: '203.0.113.7', depth: 1 },
      status: 'skipped',
      skip: { reason: 'no-key', message: 'Add a virustotal API key in settings.' },
    },
  ],
  pivots: [{ pivot: { kind: 'hash', value: '-1253000196', note: 'Shodan favicon mmh3' }, sources: ['favicon'] }],
  capped: {},
  summary: { headline: { domainAgeDays: 6, registeredOn: '2026-11-19', registrar: 'Example Registrar | Inc' }, ipCount: 1 },
  verdict: {
    level: 'likely-impersonation',
    title: 'Likely impersonation of Apple',
    brand: 'Apple',
    officialDomains: ['apple.com'],
    signals: [{ text: 'Registered only 6 days ago', weight: 'strong' }],
  },
  modules: [mod as Module],
};

describe('exports', () => {
  it('JSON export is valid, complete and has no live indicators', () => {
    const out = toJsonExport(input);
    const doc = JSON.parse(out) as { defanged: boolean; entities: Array<{ value: string; results: unknown[] }> };
    expect(doc.defanged).toBe(true);
    expect(doc.entities[0]!.value).toBe('xn--80ak6aa92e[.]com');
    expect(doc.entities[1]!.results).toHaveLength(1);
    expect(out).not.toMatch(/203\.0\.113\.7|https?:\/\/|xn--80ak6aa92e\.com/);
    expect(out).toContain('203[.]0[.]113[.]7');
    expect(out).toContain('"-1253000196"');
  });

  it('Markdown export has summary, verdict, per-entity sections, facts and pivots, all defanged', () => {
    const out = toMarkdown(input);
    expect(out).toMatch(/^# Domain Recon: `xn--80ak6aa92e\[\.\]com`/);
    expect(out).toContain('| Domain age | 6 days (registered 2026-11-19) |');
    expect(out).toContain('Example Registrar \\| Inc');
    expect(out).toContain('## Verdict: Likely impersonation of Apple');
    expect(out).toContain('## IP `203[.]0[.]113[.]7`');
    expect(out).toContain('### DNS (DoH) [cached] (cached 2026-11-25T09:00:00.000Z)');
    expect(out).toContain('- **A**: `203[.]0[.]113[.]7`');
    expect(out).toContain('hxxps://evil\\[.]example'.replace('\\[', '['));
    expect(out).toContain('> Skipped:');
    expect(out).toContain('`-1253000196`');
    expect(out).not.toMatch(/\b203\.0\.113\.7\b|https?:\/\//);
  });

  it('JSON export defangs the Unicode root form and domain-keyed records', () => {
    const out = toJsonExport({ ...input, capped: { 'xn--80ak6aa92e.com': ['198.51.100.1'] } });
    expect(out).not.toContain('аррӏе.com');
    expect(out).toContain('"unicode": "аррӏе[.]com"');
    expect(out).toContain('"xn--80ak6aa92e[.]com": [');
    expect(out).not.toMatch(/xn--80ak6aa92e\.com|198\.51\.100\.1/);
  });

  it('Markdown export defangs the Unicode root form', () => {
    const out = toMarkdown(input);
    expect(out).toContain('- Unicode form: `аррӏе[.]com`');
    expect(out).not.toContain('аррӏе.com');
  });

  const hostile = (summary: string, extra: Partial<ExportInput> = {}): string =>
    toMarkdown({ ...input, ...extra, cards: [{ ...input.cards[0]!, summary }] });

  it.each([
    ['[.]: javascript:alert(1)', '[.]\\: javascript:alert(1)'],
    ['[@]: https://evil.example', '[@]\\: hxxps://evil[.]example'],
    ['click [.](javascript:alert(1))', 'click [.]\\(javascript:alert(1))'],
    ['[x](https://evil.example)', '\\[x]\\(hxxps://evil[.]example)'],
    ['![a](https://evil.example/x.png)', '\\!\\[a]\\(hxxps://evil[.]example/x[.]png)'],
  ])('Markdown summaries cannot create links: %s', (summary, expected) => {
    const out = hostile(summary);
    expect(out).toContain(`\n${expected}\n`);
    expect(out).not.toMatch(/^ {0,3}\[[^\]\n]*\]:/m); // no link reference definition
    expect(out).not.toMatch(/(?<!\\)\]\(/); // no inline link / image
  });

  it.each([
    ['evil&#46;example', 'evil\\&\\#46;example'],
    ['evil&period;example', 'evil\\&period;example'],
    ['~~~', '\\~\\~\\~'],
    ['- not a list', '\\- not a list'],
    ['+ not a list', '\\+ not a list'],
    ['1. not a list', '1\\. not a list'],
    ['=== not a heading', '\\=== not a heading'],
    ['<!-- hidden', '\\<\\!-- hidden'],
    ['```', '\\`\\`\\`'],
    ['| a | b |', '\\| a \\| b \\|'],
  ])('Markdown summaries cannot change document structure: %s', (summary, expected) => {
    expect(hostile(summary)).toContain(`\n${expected}\n`);
  });

  it('escapes pipes in code spans inside table cells', () => {
    const out = hostile('ok', {
      summary: {
        headline: { domainAgeDays: 6, registeredOn: '2026-11-19 | x', registrationFor: 'a|b.example', m365: { tenant: true, tenantId: 'id|x' } },
        ipCount: 1,
        worst: { severity: 'high', label: 'VT', entity: { kind: 'ip', value: '203.0.113.7|z', depth: 1 } },
      },
    });
    const rows = out.split('\n').filter((l) => /^\| (Domain age|M365 tenant|Worst reputation) \|/.test(l));
    expect(rows).toHaveLength(3);
    for (const r of rows) expect(r.match(/(?<!\\)\|/g)).toHaveLength(3);
    expect(out).toContain('`a\\|b[.]example`');
    expect(out).toContain('(registered 2026-11-19 \\| x)');
  });

  it('builds safe filenames', () => {
    expect(exportFilename('xn--80ak6aa92e.com', 'md', Date.UTC(2026, 10, 25, 12, 0, 0))).toBe('domain-recon_xn--80ak6aa92e.com_2026-11-25T120000.md');
  });
});
