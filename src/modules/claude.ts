import { callClaude, type BrandReport } from '@/lib/claude';
import { buildEvidence, domPageView, faviconToPng, isSameSite, renderEvidence, type Evidence, type PageView } from '@/lib/evidence';
import { ff } from '@/lib/firefox';
import { getFavicons, getHomepage, parseHtml } from '@/lib/homepage';
import { toUnicode } from '@/lib/punycode';
import type { Fact, Module } from '@/lib/types';
import { DAY, SkipError } from '@/lib/types';

export interface ClaudeData {
  model: string;
  report: BrandReport;
  evidence: Evidence;
  usage: { input_tokens?: number; output_tokens?: number };
  attempts: string[];
}

export interface ClaudeDeps {
  /** Firefox built-in data consent for the optional "websiteContent" category. */
  hasConsent(): Promise<boolean>;
  pageView(html: string): PageView;
  toPng(bytes: Uint8Array, contentType: string): Promise<{ base64: string; width: number; height: number } | null>;
}

export const CONSENT_MESSAGE =
  'Sending page content to Anthropic needs your consent ("website content" data collection). Use "Allow AI page analysis".';

const defaultDeps: ClaudeDeps = {
  hasConsent: async () => {
    try {
      return await ff.permissions.contains({ data_collection: ['websiteContent'] });
    } catch {
      return false;
    }
  },
  pageView: (html) => domPageView(parseHtml(html)),
  toPng: faviconToPng,
};

export function createClaudeModule(deps: ClaudeDeps = defaultDeps): Module<ClaudeData> {
  return {
    id: 'claude',
    label: 'AI brand check (Claude)',
    // 2: evidence gained passwordFormHosts (+ <base href>/formaction handling); old entries lack it.
    version: 2,
    accepts: ['domain'],
    key: 'anthropic',
    ttl: DAY,
    active: true,
    rateLimit: { perMinute: 20 },
    note: 'Active + AI: fetches the homepage and sends an extracted evidence pack (no raw HTML) and the favicon to Anthropic. The verdict banner is computed in code from these results plus RDAP and M365 data.',
    async run(e, ctx) {
      const key = await ctx.getKey('anthropic');
      if (!key) throw new SkipError('Add an Anthropic API key in settings to enable this check.');
      // Re-checked every run: users can withdraw consent in about:addons at any time.
      if (!(await deps.hasConsent())) throw new SkipError(CONSENT_MESSAGE, 'consent');

      const hp = await getHomepage(ctx, e.value);
      const evidence = buildEvidence(deps.pageView(hp.html), hp.url, hp.status);
      let png: Awaited<ReturnType<ClaudeDeps['toPng']>> = null;
      try {
        const fav = await getFavicons(ctx, e.value);
        const icon = fav.icons[0];
        if (icon) png = await deps.toPng(icon.bytes, icon.contentType);
      } catch (err) {
        if (ctx.signal.aborted) throw err;
        png = null; // the favicon is optional evidence
      }
      if (png) evidence.favicon = { width: png.width, height: png.height };

      const result = await callClaude(ctx, key, {
        model: ctx.settings.claudeModel,
        domain: e.value,
        unicode: toUnicode(e.value),
        evidenceText: renderEvidence(evidence),
        ...(png ? { faviconPng: png.base64 } : {}),
      });
      const r = result.report;
      const data: ClaudeData = { model: result.model, report: r, evidence, usage: result.usage, attempts: result.attempts };
      return {
        data,
        summary: r.brand
          ? `${r.brand} (${Math.round(r.confidence * 100)}%) · impersonation ${r.impersonation_likelihood}${r.expected_official_domain ? ` · official: ${r.expected_official_domain}` : ''}`
          : 'No brand identified',
      };
    },
    headline(d, e) {
      let finalHost: string | null = null;
      try {
        finalHost = new URL(d.evidence.url).hostname;
      } catch {
        finalHost = null;
      }
      // "Offsite" = a password form posting somewhere other than the investigated name or the
      // page actually served (after redirects). Non-credential forms (newsletter, search) are not
      // credential exfiltration and must not trigger the strong verdict signal.
      const local = (h: string) => isSameSite(h, e.value) || (finalHost !== null && isSameSite(h, finalHost));
      return {
        brand: {
          brand: d.report.brand,
          confidence: d.report.confidence,
          impersonation: d.report.impersonation_likelihood,
          expectedDomain: d.report.expected_official_domain,
          evidence: d.report.evidence,
        },
        page: {
          finalHost,
          hasPasswordInput: d.evidence.hasPasswordInput,
          offsiteFormHosts: d.evidence.passwordFormHosts.filter((h) => !local(h)),
        },
      };
    },
    facts(d) {
      const r = d.report;
      const facts: Fact[] = [
        { label: 'Brand', value: r.brand ?? 'none identified' },
        { label: 'Confidence', value: `${Math.round(r.confidence * 100)}%` },
        {
          label: 'Impersonation (AI)',
          value: r.impersonation_likelihood,
          tone: r.impersonation_likelihood === 'high' ? 'bad' : r.impersonation_likelihood === 'medium' ? 'warn' : 'good',
        },
      ];
      if (r.expected_official_domain) facts.push({ label: 'Official domain (AI)', value: r.expected_official_domain, pivot: true });
      if (r.evidence.length) facts.push({ label: 'Evidence', value: r.evidence });
      facts.push({ label: 'Page', value: `${d.evidence.url} (HTTP ${d.evidence.status})` });
      if (d.evidence.title) facts.push({ label: 'Title', value: d.evidence.title });
      if (d.evidence.hasPasswordInput) facts.push({ label: 'Password field', value: 'yes', tone: 'warn' });
      if (d.evidence.formActionHosts.length) facts.push({ label: 'Form targets', value: d.evidence.formActionHosts, pivot: true });
      facts.push({
        label: 'Model',
        value: `${d.model}${d.usage.input_tokens !== undefined ? ` · ${d.usage.input_tokens} in / ${d.usage.output_tokens ?? '?'} out tokens` : ''}`,
      });
      return facts;
    },
  };
}

export const claudeModule = createClaudeModule();
