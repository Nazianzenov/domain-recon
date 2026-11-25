import { defineConfig } from 'wxt';
import { ACTIVE_HOST_PERMISSIONS, FIXED_HOST_PERMISSIONS } from './src/lib/origins';

// See https://wxt.dev/api/config.html
export default defineConfig({
  srcDir: 'src',
  manifestVersion: 3,
  browser: 'firefox',
  // Preact via Oxc's automatic JSX runtime (Vite 8): no extra Vite plugin needed.
  vite: () => ({
    oxc: { jsx: { runtime: 'automatic' as const, importSource: 'preact' } },
  }),
  zip: {
    // The sources zip AMO reviewers rebuild from. Keep build inputs, drop
    // local artefacts (everything .gitignore lists; WXT already skips
    // node_modules, dotfiles such as .env, and *.test.ts files).
    excludeSources: ['.output/**', '.wxt/**', 'coverage/**', 'web-ext-artifacts/**', '**/*.log', '**/*.zip'],
  },
  manifest: {
    name: 'Domain Recon',
    short_name: 'Domain Recon',
    icons: { 48: 'icon.svg', 96: 'icon.svg' },
    // Toolbar button; background.ts toggles the sidebar on click (no popup).
    action: {
      default_title: 'Toggle Domain Recon sidebar',
      default_icon: { 16: 'icon.svg', 32: 'icon.svg' },
      // Firefox defaults to the Extensions menu panel; put the toggle on the toolbar.
      default_area: 'navbar',
    },
    // storage: settings/API keys in storage.local.
    // dns: optional system-resolver comparison module (browser.dns.resolve).
    permissions: ['storage', 'dns'],
    host_permissions: [...FIXED_HOST_PERMISSIONS],
    optional_host_permissions: [...ACTIVE_HOST_PERMISSIONS],
    browser_specific_settings: {
      gecko: {
        // Anonymous, permanent add-on ID (GUID form). Never change it once the
        // add-on has been signed: Firefox treats a new ID as a different add-on.
        id: '{5f588134-5699-4f20-aef2-8334b6d02e66}',
        strict_min_version: '140.0',
        /*
         * Data collection declaration (Mozilla built-in data consent):
         *
         * required: ["browsingActivity"]
         *   Every investigation sends the domain the user typed (frequently a
         *   site they visited or received a link to) and the IPs it resolves
         *   to, to third-party services: Cloudflare/Google DoH, IANA/rdap.org
         *   and registry RDAP servers, Mnemonic, Microsoft login endpoints,
         *   Shodan InternetDB (keyless) and, when the user adds keys,
         *   VirusTotal, OTX, AbuseIPDB, abuse.ch, the Shodan host API and (AI
         *   check) Anthropic. Mozilla defines browsingActivity as information
         *   about the websites/domains a user visits, which is the closest
         *   honest fit.
         *   This is core functionality, so it cannot be optional.
         *
         * optional: ["websiteContent"]
         *   Only when the user enables the AI brand check and runs active
         *   checks, an evidence pack built from the investigated homepage
         *   (title, meta/og tags, visible text, logo alt/src, form hosts and
         *   the favicon) is sent to Anthropic. websiteContent covers text,
         *   images and links visible on a website. Declared optional because
         *   the feature is opt-in.
         *
         * Not declared: API keys are the user's own credentials and are only
         * sent to the provider that issued them; nothing is sent to the
         * developer, and there is no telemetry.
         */
        data_collection_permissions: {
          required: ['browsingActivity'],
          optional: ['websiteContent'],
        },
      },
      // Android has no sidebarAction, so this is effectively desktop-only, but
      // gecko_android inherits strict_min_version 140 from gecko and Android
      // only understands data_collection_permissions from 142. Declaring it
      // keeps `web-ext lint` at zero warnings (KEY_FIREFOX_ANDROID_UNSUPPORTED_BY_MIN_VERSION).
      gecko_android: {
        strict_min_version: '142.0',
      },
    },
  },
});
