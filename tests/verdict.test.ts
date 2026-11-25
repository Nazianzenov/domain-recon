import { describe, expect, it } from 'vitest';
import type { Headline } from '@/lib/types';
import { correlate, domainMatches, findKnownBrand } from '@/lib/verdict';

const brand = (b: Partial<Headline['brand']> = {}): Headline['brand'] => ({
  brand: 'Microsoft',
  confidence: 0.9,
  impersonation: 'low',
  expectedDomain: 'microsoft.com',
  evidence: [],
  ...b,
});

describe('correlate (code-computed verdict)', () => {
  it('spec example: Microsoft brand, non-official domain, no tenant, < 30 days -> likely impersonation', () => {
    const v = correlate({
      domain: 'microsoft-login-secure.com',
      isIdn: false,
      headline: { brand: brand(), domainAgeDays: 6, m365: { tenant: false } },
    })!;
    expect(v.level).toBe('likely-impersonation');
    expect(v.signals.map((s) => s.text)).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/not an official Microsoft domain/),
        'Registered only 6 days ago',
        'No Microsoft 365 / Entra ID tenant for this domain',
      ]),
    );
  });

  it('official domains (incl. subdomains) are consistent regardless of the AI likelihood', () => {
    const v = correlate({ domain: 'login.microsoftonline.com', isIdn: false, headline: { brand: brand({ impersonation: 'high' }) } })!;
    expect(v.level).toBe('consistent');
  });

  it('does not trust the model for known brands: a model-claimed "official" domain is ignored', () => {
    const v = correlate({
      domain: 'paypal-security.net',
      isIdn: false,
      headline: { brand: brand({ brand: 'PayPal', expectedDomain: 'paypal-security.net', impersonation: 'medium' }), domainAgeDays: 400 },
    })!;
    expect(v.level).not.toBe('consistent');
  });

  it('ccTLD families match via patterns', () => {
    const v = correlate({ domain: 'www.amazon.co.uk', isIdn: false, headline: { brand: brand({ brand: 'Amazon', expectedDomain: 'amazon.com' }) } })!;
    expect(v.level).toBe('consistent');
  });

  it('password form posting offsite + high AI likelihood -> likely impersonation even without RDAP', () => {
    const v = correlate({
      domain: 'docs-share.example',
      isIdn: false,
      headline: {
        brand: brand({ brand: 'DocuSign', impersonation: 'high' }),
        page: { finalHost: 'docs-share.example', hasPasswordInput: true, offsiteFormHosts: ['collect.example.net'] },
      },
    })!;
    expect(v.level).toBe('likely-impersonation');
  });

  it('brand mentioned on an old domain with no other signals is inconclusive, not an accusation', () => {
    const v = correlate({
      domain: 'contoso-msp-partner.com',
      isIdn: false,
      headline: { brand: brand({ impersonation: 'low' }), domainAgeDays: 4000, m365: { tenant: true } },
    })!;
    expect(v.level).toBe('inconclusive');
  });

  it('a parent registration (phish.weebly.com) is neither alarming nor reassuring', () => {
    const v = correlate({
      domain: 'microsoft-login.weebly.com',
      isIdn: false,
      headline: { brand: brand({ impersonation: 'low' }), domainAgeDays: 6000, registrationFor: 'weebly.com' },
    })!;
    expect(v.signals.some((s) => s.weight === 'mitigating' && /years ago/.test(s.text))).toBe(false);
    expect(v.signals.some((s) => /parent weebly\.com/.test(s.text))).toBe(true);
  });

  it('IDN alone makes it suspicious', () => {
    const v = correlate({ domain: 'xn--pple-43d.com', isIdn: true, headline: { brand: brand({ brand: 'Apple', expectedDomain: 'apple.com' }), domainAgeDays: 900 } })!;
    expect(v.level).toBe('suspicious');
  });

  it('low confidence or no brand is inconclusive; no AI result -> null', () => {
    expect(correlate({ domain: 'x.com', isIdn: false, headline: { brand: brand({ confidence: 0.3 }) } })!.level).toBe('inconclusive');
    expect(correlate({ domain: 'x.com', isIdn: false, headline: { brand: brand({ brand: null }) } })!.title).toBe('No brand identified');
    expect(correlate({ domain: 'x.com', isIdn: false, headline: {} })).toBeNull();
  });

  it('domainMatches respects label boundaries', () => {
    expect(domainMatches('a.microsoft.com', 'microsoft.com')).toBe(true);
    expect(domainMatches('evilmicrosoft.com', 'microsoft.com')).toBe(false);
  });

  it('label boundaries in the verdict: look-alikes are never official', () => {
    for (const d of ['microsoft.com.evil.net', 'evilmicrosoft.com', 'microsoft-com.net', 'MICROSOFT.COM.attacker.io']) {
      expect(correlate({ domain: d, isIdn: false, headline: { brand: brand() } })!.level).not.toBe('consistent');
    }
    expect(correlate({ domain: 'Login.MicrosoftOnline.com.', isIdn: false, headline: { brand: brand() } })!.level).toBe('consistent');
  });
});

describe('brand table semantics', () => {
  it.each([
    'Big Apple Pizza',
    'Apple Valley Dental',
    'Ups & Downs Cafe',
    'Meta Real Estate',
    'Chase Plumbing',
    'Teams Collaboration Ltd',
    'Outlook India',
    'Azure Spa & Resort',
    'Bing Lee',
    'Adobe Construction Supply',
    'Amazon Rainforest Trust',
    'The Office Fan Club',
    'Startups Inc',
    'Metallica',
  ])('%s is not a built-in brand', (name) => {
    expect(findKnownBrand(name)).toBeUndefined();
  });

  it.each([
    ['Microsoft', 'Microsoft'],
    ['Microsoft Teams', 'Microsoft'],
    ['Office 365 (Microsoft)', 'Microsoft'],
    ['Outlook', 'Microsoft'],
    ['Microsoft Corporation', 'Microsoft'],
    ['Apple Inc.', 'Apple'],
    ['iCloud', 'Apple'],
    ['Amazon.com, Inc.', 'Amazon'],
    ['Amazon Web Services (AWS)', 'Amazon'],
    ['JPMorgan Chase & Co.', 'Chase'],
    ['Chase', 'Chase'],
    ['UPS', 'UPS'],
    ['The UPS Store', 'UPS'],
    ['Meta', 'Meta'],
    ['Facebook', 'Meta'],
    ['DocuSign / Microsoft', 'DocuSign'],
    ['PayPal Holdings, Inc.', 'PayPal'],
  ])('%s -> %s', (name, expected) => {
    expect(findKnownBrand(name)?.name).toBe(expected);
  });

  it('a generic word in a brand name does not import the big brand (no false accusation)', () => {
    // Before: /\boutlook\b/ made this "Microsoft", ignored the AI's domain and flagged the missing M365 tenant.
    const v = correlate({
      domain: 'outlookindia.com',
      isIdn: false,
      headline: { brand: brand({ brand: 'Outlook India', expectedDomain: 'outlookindia.com' }), domainAgeDays: 9000, m365: { tenant: false } },
    })!;
    expect(v.level).toBe('consistent');
    expect(v.officialDomains).toEqual(['outlookindia.com']);
    expect(v.signals.some((s) => /Microsoft 365/.test(s.text))).toBe(false);
  });

  it('ccTLD patterns: real families match, generic/free ccTLDs do not', () => {
    const g = (domain: string) => correlate({ domain, isIdn: false, headline: { brand: brand({ brand: 'Google' }) } })!.level;
    expect(g('www.google.de')).toBe('consistent');
    expect(g('google.co.uk')).toBe('consistent');
    expect(g('google.com.br')).toBe('consistent');
    for (const d of ['google.tk', 'google.co', 'google.io', 'google.ai', 'google.de.evil.com']) expect(g(d)).not.toBe('consistent');
    const a = (domain: string) => correlate({ domain, isIdn: false, headline: { brand: brand({ brand: 'Amazon' }) } })!.level;
    expect(a('amazon.co.jp')).toBe('consistent');
    for (const d of ['amazon.ml', 'amazon.co', 'amazon.co.zw', 'amazon.cm']) expect(a(d)).not.toBe('consistent');
  });

  it('customer-controlled hosting under an official domain is never "official"', () => {
    for (const d of ['evil.blob.core.windows.net', 'phish.z13.web.core.windows.net', 'contoso-share.sharepoint.com', 'vm1.westeurope.cloudapp.azure.com']) {
      const v = correlate({
        domain: d,
        isIdn: false,
        headline: { brand: brand({ impersonation: 'high' }), page: { finalHost: d, hasPasswordInput: true, offsiteFormHosts: ['collect.example.net'] } },
      })!;
      expect(v.level).toBe('likely-impersonation');
      expect(v.signals.some((s) => /customer-controlled hosting/.test(s.text))).toBe(true);
    }
    expect(correlate({ domain: 'bucket.s3.amazonaws.com', isIdn: false, headline: { brand: brand({ brand: 'Amazon' }) } })!.level).not.toBe('consistent');
    expect(correlate({ domain: 'lh3.googleusercontent.com', isIdn: false, headline: { brand: brand({ brand: 'Google' }) } })!.level).not.toBe('consistent');
    // Microsoft's own endpoints under the same parents stay official.
    expect(correlate({ domain: 'login.windows.net', isIdn: false, headline: { brand: brand() } })!.level).toBe('consistent');
    expect(correlate({ domain: 'www.sharepoint.com', isIdn: false, headline: { brand: brand() } })!.level).toBe('consistent');
  });
});

describe('model-claimed official domains (unknown brands)', () => {
  it('a page cannot silence the verdict by getting the AI to name this domain as official', () => {
    const v = correlate({
      domain: 'contoso-bank-secure.com',
      isIdn: false,
      headline: {
        brand: brand({ brand: 'Contoso Bank', expectedDomain: 'contoso-bank-secure.com', impersonation: 'low' }),
        domainAgeDays: 3,
        page: { finalHost: 'contoso-bank-secure.com', hasPasswordInput: true, offsiteFormHosts: ['drop.example.ru'] },
      },
    })!;
    expect(v.level).toBe('suspicious'); // capped: no verified official domain to contrast with
    expect(v.title).toMatch(/not verified/);
    expect(v.signals.map((s) => s.text)).toEqual(
      expect.arrayContaining(['Registered only 3 days ago', 'Password form submits to another host: drop.example.ru']),
    );
  });

  it('AI-claimed official with no risk signals is consistent but labelled unverified', () => {
    const v = correlate({
      domain: 'contoso.com',
      isIdn: false,
      headline: { brand: brand({ brand: 'Contoso', expectedDomain: 'contoso.com' }), domainAgeDays: 5000 },
    })!;
    expect(v.level).toBe('consistent');
    expect(v.title).toMatch(/per the AI \(not verified\)/);
  });

  it('unknown official domain: a new domain is suspicious, never "impersonation" or "non-official"', () => {
    const v = correlate({
      domain: 'joes-pizza.example',
      isIdn: false,
      headline: { brand: brand({ brand: "Joe's Pizza", expectedDomain: null, impersonation: 'high' }), domainAgeDays: 4 },
    })!;
    expect(v.level).toBe('suspicious');
    expect(v.title).not.toMatch(/non-official|impersonation of/i);
    const quiet = correlate({ domain: 'joes-pizza.example', isIdn: false, headline: { brand: brand({ brand: "Joe's Pizza", expectedDomain: null }), domainAgeDays: 800 } })!;
    expect(quiet.level).toBe('inconclusive');
    expect(quiet.title).toMatch(/official domain unknown/);
  });

  it('known brands ignore a model-supplied official domain even when it matches', () => {
    const v = correlate({
      domain: 'apple-id-verify.com',
      isIdn: false,
      headline: { brand: brand({ brand: 'Apple', expectedDomain: 'apple-id-verify.com' }), domainAgeDays: 2 },
    })!;
    expect(v.level).toBe('suspicious');
    expect(v.officialDomains).not.toContain('apple-id-verify.com');
  });
});

describe('registration, tenant and page signals', () => {
  it('a young parent registration is a strong signal (attacker subdomain of a fresh domain)', () => {
    const v = correlate({
      domain: 'login.ms-verify-account.com',
      isIdn: false,
      headline: { brand: brand({ impersonation: 'high' }), domainAgeDays: 4, registrationFor: 'ms-verify-account.com', m365: { tenant: false } },
    })!;
    expect(v.signals).toContainEqual({ text: 'Parent domain ms-verify-account.com registered only 4 days ago', weight: 'strong' });
    expect(v.level).toBe('likely-impersonation');
  });

  it('no M365 tenant on a subdomain is weak (tenants sit on the registered domain)', () => {
    const v = correlate({
      domain: 'portal.contoso-partner.com',
      isIdn: false,
      headline: { brand: brand(), domainAgeDays: 3000, registrationFor: 'contoso-partner.com', m365: { tenant: false } },
    })!;
    expect(v.signals.find((s) => /tenant/.test(s.text))?.weight).toBe('weak');
    expect(v.level).toBe('inconclusive');
    expect(v.title).toMatch(/no strong impersonation signals/);
  });

  it('a redirect to the official site: the page signals are not attributed to this domain', () => {
    const v = correlate({
      domain: 'microsoft-store-deals.com',
      isIdn: false,
      headline: {
        brand: brand(),
        domainAgeDays: 2000,
        m365: { tenant: true },
        page: { finalHost: 'login.microsoftonline.com', hasPasswordInput: true, offsiteFormHosts: ['login.live.com'] },
      },
    })!;
    expect(v.signals.some((s) => /Password/.test(s.text))).toBe(false);
    expect(v.signals.some((s) => /official Microsoft domain \(the page signals/.test(s.text))).toBe(true);
    expect(v.level).toBe('inconclusive');
  });

  it("a password form posting to the brand's own login host is not exfiltration", () => {
    const v = correlate({
      domain: 'contoso-intranet.com',
      isIdn: false,
      headline: {
        brand: brand(),
        domainAgeDays: 2000,
        m365: { tenant: true },
        page: { finalHost: 'contoso-intranet.com', hasPasswordInput: true, offsiteFormHosts: ['login.microsoftonline.com'] },
      },
    })!;
    expect(v.signals.some((s) => /submits to another host/.test(s.text))).toBe(false);
    expect(v.level).toBe('suspicious'); // still: a password field on a non-official domain
  });
});
