# Domain Recon

A lightweight Firefox (Manifest V3) sidebar extension that investigates a single domain and streams results as they arrive. It covers:
- DNS over HTTPS, RDAP registration and passive DNS;
- the Microsoft 365 / Entra ID tenant;
- email-sending providers;
- favicon hashes;
- threat intel (VirusTotal, OTX, AbuseIPDB, abuse.ch, Shodan);
- an optional Claude-based brand-impersonation check.

Built with [WXT](https://wxt.dev), TypeScript (strict) and Preact. No remote code, no `eval`, default CSP.

## Install (temporary, for testing)

Requirements: Firefox 140 or later (desktop), Node.js 24 or later and npm 11.

```sh
npm ci                # installs dependencies and runs `wxt prepare`
npm run build         # -> .output/firefox-mv3/
```

1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on…** and select `.output/firefox-mv3/manifest.json`.
3. Click the **Domain Recon** toolbar button (globe and magnifier) to toggle the sidebar. Settings are under the sidebar's **Settings** link or `about:addons` → Domain Recon → Options.

Firefox removes temporary add-ons when it restarts. For a permanent install, sign the package through AMO; see [Packaging for AMO](#packaging-for-amo).

Firefox grants host permissions at install time, but you can revoke them in `about:addons`. If any API origin is missing, the sidebar shows **Grant access**.

## Using it

1. Type a domain, URL, email address or defanged indicator (`hxxps://evil[.]example/login`) and press **Enter**.
   - The input is refanged and reduced to the hostname.
   - Internationalised names are converted to punycode; both forms are shown when they differ.
   - IP addresses are rejected, because IPs are discovered from the domain.
2. Each module/entity pair gets a collapsible card. Status dots:
   - hollow: queued;
   - pulsing: running;
   - green: OK;
   - faded green: cached;
   - red: error;
   - dashed: skipped.
3. Expand a card for details and raw JSON. **↻** refreshes that card and bypasses the cache. **Force refresh** re-runs everything.
4. Pivots go one hop only: from the domain to its IPs, capped at 10. Private or reserved IPs, extra IPs over the cap, favicon hashes and other values are listed under **Pivots not investigated**.
5. **JSON / Markdown / Copy MD** export the whole investigation. All domains, IPs, URLs and emails in exports are defanged.

**Cancel** (or **Esc** in the input box) aborts every in-flight request.

## OPSEC model

The default mode is **Passive only**, and the sidebar starts in it every time it opens. In passive mode the extension never connects to the investigated domain's own servers. It only talks to:

| Purpose | Contacted |
| --- | --- |
| DNS | `cloudflare-dns.com`, falling back to `dns.google` (DoH JSON) |
| Registration | `data.iana.org` (RDAP bootstrap), the TLD registry's RDAP server, `rdap.org` |
| Passive DNS | `api.mnemonic.no` |
| Microsoft tenant | `login.microsoftonline.com`; the login hint is the fixed fake `probe@<domain>` |
| Threat intel (IPs, no key) | `internetdb.shodan.io` |
| Threat intel (with your keys) | `www.virustotal.com`, `otx.alienvault.com`, `api.abuseipdb.com`, `urlhaus-api.abuse.ch`, `threatfox-api.abuse.ch`, `api.shodan.io` |

The one exception is investigating a domain that belongs to one of these services (for example `dns.google`): the lookup then goes to the target by definition. The RDAP check skips a registry RDAP server that belongs to the investigated domain (for example `rdap.verisign.com` when you investigate `verisign.com`).

Things to keep in mind even in passive mode:
- **DNS lookups still reach the target's nameservers.** They arrive from Cloudflare's or Google's resolvers, not from your IP (Google queries disable EDNS Client Subnet, so your network prefix is not forwarded either), but the domain owner can see that someone resolved those names. That includes DKIM selectors like `s1._domainkey.<domain>`, which the email-provider module queries.
- **Third parties learn what you investigate.** Every service above receives the domain or its IPs. Threat-intel services may record lookups made with your key.
- **The system-resolver module (off by default) uses your OS resolver.** Your local DNS server, ISP or corporate resolver sees the query.

**Active checks** contact the target directly from your IP address:
- **Favicon:** fetches `https://<domain>/` and the favicon.
- **AI brand check:** fetches the homepage, then sends an evidence pack to Anthropic.

Redirects are followed, and a `<link rel="icon">` can point to another host (for example a CDN), so active checks may also reach those servers.

Active checks show as skipped until you click **Run active checks** or switch OPSEC to **Allow active checks**. Either one requests the optional `*://*/*` host permission at that moment.
- **Run active checks** (the banner) runs the skipped active checks for the current investigation only; the toggle stays on **Passive only**, so the next investigation does not contact its target. Switching the toggle to **Allow active checks** enables active checks for every investigation in this sidebar until you switch back.
- Firefox remembers the `*://*/*` grant until you remove it in `about:addons` → Domain Recon → Permissions (removing it switches an open sidebar back to **Passive only**). The OPSEC toggle, not the permission, decides whether active checks run.
- Results cached by an earlier active run are still shown in passive mode (no request is made), but they are not refreshed.

Requests are sent with `credentials: 'omit'` (no cookies), `referrerPolicy: 'no-referrer'` and `cache: 'no-store'`, but your browser's User-Agent is visible to the site. Plain-HTTP sites cannot be fetched, because the default MV3 CSP upgrades insecure requests.

## Modules

Listed in registry order (`src/modules/index.ts`), which is also the card order. The id is the module's key in settings, cache keys and the JSON export.

| Module (id) | Runs on | Mode | Key | Cache TTL | Notes |
| --- | --- | --- | --- | --- | --- |
| DNS (DoH) (`dns`) | domain | passive | none | 5 min | A, AAAA, NS, MX, TXT, CNAME, SOA, CAA and `_dmarc` TXT. A/AAAA become IP pivots. |
| System resolver vs DoH (`sysdns`) | domain | passive (local) | none | 5 min | **Off by default.** Uses `browser.dns.resolve()` (with TRR disabled) and flags split-horizon DNS or local filtering. |
| RDAP (`rdap`) | domain | passive | none | 24 h | IANA bootstrap (cached 24 h), longest-suffix match, `rdap.org` fallback. Shows registration age, registrar, abuse contact, nameservers and statuses. |
| Passive DNS, Mnemonic (`pdns`) | domain, IP | passive | optional | 24 h | Keyless use is limited to TLP:WHITE data, 1000 records and 10 requests/min. |
| Microsoft 365 / Entra ID (`m365`) | domain | passive | none | 7 d | Tenant GUID and region from OpenID metadata, plus Managed/Federated status from `getuserrealm.srf`. Corroborated by MX, `MS=` TXT, autodiscover and DKIM DNS records. |
| Email-sending providers (`email`) | domain | passive | none | 24 h | Data-driven signature table over SPF, MX and DKIM selectors. Extracts SendGrid `u<digits>` account IDs. |
| VirusTotal (`virustotal`) | domain, IP | passive | required | 24 h | Domain, resolutions (become IP pivots) and IP reports. Rate-limited to 4 requests/min. |
| AlienVault OTX (`otx`) | domain, IP | passive | required | 24 h | Pulses and passive DNS. |
| AbuseIPDB (`abuseipdb`) | IP | passive | required | 24 h | IP abuse confidence score (90 days). |
| URLhaus, ThreatFox (`urlhaus`, `threatfox`) | domain, IP | passive | required (abuse.ch) | 24 h | Malware URLs and IOCs. |
| Shodan (`shodan`) | IP | passive | optional | 24 h | InternetDB needs no key. With a key, also full host data (paid plan). |
| Favicon hashes (`favicon`) | domain | **active** | none | 7 d | Shodan `http.favicon.hash` (mmh3 of `base64.encodebytes`), MD5 and SHA-256, plus Shodan search link. |
| AI brand check, Claude (`claude`) | domain | **active** | required (Anthropic) | 24 h | See below. |

Threat-intel modules without a key are skipped with an "add key in settings" hint. Each provider has its own token-bucket rate limiter, and requests queue rather than fail. A 429 pauses that provider's bucket for the `Retry-After` period and retries the request once. A `Retry-After` longer than 5 minutes (a daily quota) fails immediately instead.

## API keys

Keys are entered on the settings page and stored **unencrypted** in `browser.storage.local` in this Firefox profile. They are never synced, and each key is only sent to the provider that issued it. Each key has a **Test** button that makes one cheap authenticated call.

| Provider | Where to get a key | Free tier |
| --- | --- | --- |
| VirusTotal | <https://www.virustotal.com/gui/my-apikey> (sign up, then profile → API key) | 4 requests/min, 500/day |
| AlienVault OTX | <https://otx.alienvault.com/settings> (account settings → OTX Key) | free account |
| AbuseIPDB | <https://www.abuseipdb.com/account/api> | 1,000 checks/day |
| abuse.ch (URLhaus + ThreatFox) | <https://auth.abuse.ch/> (one Auth-Key for both) | free, Auth-Key is mandatory |
| Shodan (optional) | <https://account.shodan.io/> | InternetDB needs no key; host lookups need a paid membership |
| Mnemonic Argus (optional) | `argus-support@mnemonic.no` | keyless access works with lower limits |
| Anthropic | <https://platform.claude.com/settings/keys> | pay as you go |

## AI brand identification

When enabled, the AI check builds a **compact evidence pack** from the fetched homepage. Raw HTML is never sent. The pack contains:
- title, meta description and `og:*` tags;
- the first 4,000 characters of visible text;
- logo image alt/src;
- form action hosts, and whether a password field exists;
- the favicon converted to PNG with `OffscreenCanvas`.

The pack goes to `POST https://api.anthropic.com/v1/messages` with:
- `anthropic-version: 2023-06-01`;
- `anthropic-dangerous-direct-browser-access: true`;
- a single `report_brand` tool with a strict schema.

The page data is wrapped in `<page_content>` tags. The system prompt says that content is untrusted data and never instructions, and the model gets no other tools.

**Model.** The default is **Claude Opus 5.5** (`claude-opus-5-5`). You can change it in settings to Sonnet 5.5, Haiku 5.5 or a custom model ID.
- Opus 5.5 and Sonnet 5.5 reject a forced `tool_choice` (`{type:"tool"}`). For those models the extension sends `tool_choice: auto` with a strict tool and a prompt instruction, and asks once more if the model answered in text.
- Models that accept forcing (for example Haiku 5.5) get the forced call.
- Unknown models are tried forced first and step down automatically if the API rejects it.
- Server-side refusal fallbacks are enabled for Opus and Sonnet.

**Consent.** Sending page content is declared as optional `websiteContent` data collection. Until you consent, the AI card is skipped and the sidebar shows **Allow AI page analysis**, which opens Firefox's consent prompt. You can withdraw consent in `about:addons`; it is checked again before every AI request.

**Verdict.** The model only identifies the brand. The **verdict is computed in code** by correlating:
- the brand against a built-in table of official domains, used in preference to the model's claim;
- the domain age from RDAP;
- the Microsoft 365 tenant;
- password forms that submit to other hosts;
- a homepage that redirects to another host;
- internationalised (IDN) domains;
- the model's own impersonation rating.

For example: the brand is Microsoft, the domain is not an official Microsoft domain, there is no M365 tenant, and it was registered 6 days ago. That shows a red **Likely impersonation** banner listing each signal.

## Data collection declaration

The manifest declares the following in `browser_specific_settings.gecko.data_collection_permissions` (Mozilla's built-in consent, Firefox 140 or later):
- **`required: ["browsingActivity"]`:** every investigation sends the queried domain and its IPs to the third-party services listed above. Mozilla defines *browsing activity* as information about the websites and domains a user visits, which is the closest honest category. This is core functionality, so it cannot be optional.
- **`optional: ["websiteContent"]`:** only when the user grants it is homepage content (text, links, images, favicon) sent to Anthropic for the AI brand check.

Not declared:
- **API keys.** They are the user's own credentials and go only to the service that issued them, to authenticate the user's own requests.
- **Telemetry.** There is none, and nothing is ever sent to the developer.

`gecko_android.strict_min_version` is set to 142 only to keep `web-ext lint` clean. Firefox for Android has no sidebar, so the extension is desktop-only: leave Firefox for Android unticked when uploading to AMO.

## Permissions

| Permission | Why |
| --- | --- |
| `storage` | Settings and API keys (`storage.local`). Results are cached in IndexedDB via `idb-keyval`. |
| `dns` | The optional system-resolver comparison (`browser.dns.resolve`). |
| `host_permissions` (14 fixed API origins, listed in `src/lib/origins.ts`) | Cross-origin API calls. Several providers send no CORS headers. Every origin is used by a module; `tests/origins.test.ts` checks this. |
| `optional_host_permissions: ["*://*/*"]` | Requested only for active checks (homepage and favicon). |

TLD registry RDAP servers are not listed: they are fetched without a host permission and rely on CORS, which most registries send. A registry without CORS headers only answers once you have granted `*://*/*`; the `rdap.org` fallback redirects to the same registry.

## Caching

Results are cached in IndexedDB under the key `${module.id}@${version}:${kind}:${value}`, with stale-while-revalidate:
- Expired data is shown immediately with a **cached · 3h ago** badge and refreshed in the background.
- Errors are cached for at most 2 minutes; cancellations are never cached.
- Bumping a module's `version` invalidates its entries.
- **Clear cache** is on the settings page.

## Development

```sh
npm run dev        # WXT dev mode (launches Firefox with the extension)
npm run typecheck  # tsc --noEmit (strict)
npm test           # vitest; all network calls are mocked
npm run build      # wxt build -b firefox --mv3
npm run lint       # web-ext lint on the build output
npm run check      # typecheck + test + build + lint
npm run zip        # wxt zip -b firefox --mv3: extension zip + sources zip in .output/
```

**Adding a data source.** Create one file in `src/modules/` exporting a `Module`, then add it to the array in `src/modules/index.ts`. A module declares:
- `id`, `label`, `accepts`, `ttl` and `version`;
- optionally a `key` (with `keyOptional`), a `rateLimit`, and the `active` and `defaultEnabled` flags;
- `run()`, which returns `{ data, pivots?, summary?, severity?, ttl? }`;
- optionally `facts()` for the card body and `headline()` for the summary header.

The orchestrator handles caching, rate limiting, OPSEC gating, skipping, errors and pivots. A new API origin also goes in `src/lib/origins.ts` (and so in `host_permissions`); `tests/origins.test.ts` fails if a module is not registered, if a passive module calls an unlisted origin or the investigated domain, or if a listed origin is unused.

**Favicon fixtures.** `tests/fixtures/favicon-hashes.json` is generated with Python's `mmh3` and `base64.encodebytes`:

```sh
pip install mmh3
python -I scripts/gen_favicon_fixtures.py > tests/fixtures/favicon-hashes.json
```

## Packaging for AMO

`npm run zip` produces `.output/domain-recon-<version>-firefox.zip`, the extension to upload. It also produces `.output/domain-recon-<version>-sources.zip`, the source code AMO reviewers rebuild from.

The sources zip contains `package.json`, `package-lock.json`, `wxt.config.ts`, `tsconfig.json`, `src/`, `public/`, `scripts/`, `docs/` and this README. It leaves out `node_modules`, build output (`.output`, `.wxt`), dotfiles such as `.env`, and `*.test.ts` files, which the build does not need.

Reviewer build instructions (also valid for AMO's automatic `build-for-amo` build):
1. Use Node.js 24 and npm 11. Any OS works. The dependencies are pure JS apart from the prebuilt native binaries of Vite's toolchain (Rolldown, Lightning CSS). npm picks the right one per platform; the lockfile includes the Linux arm64 and x64 builds used by AMO's default reviewer environment (Ubuntu 24.04, ARM64).
2. Run `npm ci`. Its `postinstall` step runs `wxt prepare`, which generates `.wxt/`.
3. Run `npm run build-for-amo`. The output is `.output/firefox-mv3/`, which must match the uploaded package. Rebuilding from an extracted sources zip with these steps gave byte-identical files (checked on Windows with Node 24.16 and npm 11.13).

All third-party code comes unmodified from npm and is listed in `package.json` / `package-lock.json`: Preact, idb-keyval and spark-md5. `web-ext lint` reports 0 errors. It reports one `UNSAFE_VAR_ASSIGNMENT` warning inside Preact's runtime, from Preact's generic `dangerouslySetInnerHTML` support. This extension never uses that prop and never renders fetched data as HTML.

The add-on ID in `wxt.config.ts` is a random GUID. Keep it unchanged once the add-on is signed: Firefox treats a different ID as a different add-on (new storage, no updates). Forks that publish their own build should generate their own ID.
