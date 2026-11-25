# Firefox / Mozilla platform rules: verification as of 2026-11-25

**Sources.** I read the source Markdown of these pages directly:
- Extension Workshop (EW): `firefox-builtin-data-consent` (dated 2026-10-18), add-on policies, source-code-submission, the MV3 migration guide and third-party-library-usage.
- MDN content repo: permissions.*, sidebarAction.*, dns.resolve, User_actions, Background_scripts, background, host_permissions, optional_host_permissions, CSP.
- MDN browser-compat-data (BCD).
- Firefox source: schemas/manifest.json, ext-dns.js, ext-browserAction.js, ExtensionCommon/ExtensionChild.
- addons-linter source.
- AMO blog posts.

**Linter checks were run, not inferred.** I ran web-ext 10.8.0 (latest, 2026-10-15, bundles addons-linter 10.14.0) on a scratch manifest built to the spec (in a temporary directory).

## 1. data_collection_permissions

**Schema**
```json
"browser_specific_settings": { "gecko": { "data_collection_permissions": { "required": [ ... ], "optional": [ ... ] } } }
```
- **`required` is mandatory for AMO.** Firefox's own schema makes both arrays optional (default `[]`), but the AMO/linter schema needs `required` with at least 1 item. Leaving it out gives the error `MANIFEST_FIELD_REQUIRED` (verified).
- **Allowed in `required`:** `"none"` or any of `authenticationInfo`, `bookmarksInfo`, `browsingActivity`, `financialAndPaymentInfo`, `healthInfo`, `locationInfo`, `personalCommunications`, `personallyIdentifyingInfo`, `searchTerms`, `websiteActivity`, `websiteContent`.
- **Allowed in `optional`:** the same 11 plus `technicalAndInteraction`.
- **`technicalAndInteraction` may only be optional.** Putting it in `required` gives a JSON_INVALID error (verified). It is the only optional type shown in the install prompt, as an opt-out toggle.
- **`none`:** use it if the extension "doesn't collect or transmit any data". It must be the only entry in `required` (`NONE_DATA_COLLECTION_IS_EXCLUSIVE` error, verified). An extension that collects only optional data must declare `"required": ["none"]`.
- **`has_previous_consent` is reserved.** Setting it to `true` is a linter error.

**Definitions (EW, verbatim)**
- browsingActivity: "Information about the websites users visit, such as specific URLs, domains, or categories of pages users view."
- websiteContent: "Covers anything visible on a website — such as text, images, videos, and links — and anything embedded, such as cookies, audio, page headers, and request and response information."
- websiteActivity: "interactions and mouse and keyboard activity, such as scrolling, clicking, typing, and actions, such as saving and downloading."
- searchTerms: "Search terms entered into search engines or the browser."
- authenticationInfo: "passwords, usernames, personal identification numbers (PINs), security questions, and registration information for extensions that offer account-based services."
- personallyIdentifyingInfo: contact info, ID numbers, recordings, age, demographics, biometrics.
- healthInfo, financialAndPaymentInfo, personalCommunications, locationInfo ("region, GPS coordinates, or information about things near a user's device"), bookmarksInfo.
- technicalAndInteraction: "Device and browser info, extension usage and settings data, crash and error reports."

**Implicit consent**
- Types marked eligible: location, browsing activity, website content, website activity, search terms, bookmarks.
- Implicit consent is policy 6.2.2.2, which is the custom-consent path. On the built-in path (policy 6.2.1, Firefox 140+ only) the extension "must accurately state the data collection practices in the extension manifest". So every type it transmits must be declared.

**Versions and AMO enforcement**
- Supported from Firefox desktop 140 and Android 142 (EW and BCD; the same versions apply to `permissions.Permissions.data_collection`).
- From 2025-11-03, new extensions must declare it. AMO blocks signing if it is missing or wrong (blog, 2025-10-23).
- Mozilla said all extensions would need it in "the first half of 2026". I found no follow-up post. EW (updated 2026-10-18) still says existing extensions "will have to at a later date".
- Once an extension adopts the key, every later version must keep it.
- On updates, only newly added `required` types are shown to the user.

**Recommendation**
- **(a) Queried domain sent to third parties:** `"required": ["browsingActivity"]`, because it covers "domains". This is clearest if the domain is prefilled from the active tab. `searchTerms` does not literally fit, since an extension input box is not a search engine or the browser. Confidence: medium, because the taxonomy has no category for a user-typed lookup target.
- **(b) Homepage content sent to Anthropic:** `"optional": ["websiteContent"]`, covering title, meta, text, favicon, and also any headers you send.
- **(c) User-entered API keys:** the docs say nothing about a user's own third-party key sent only to the provider that issued it. The conservative choice is to add `authenticationInfo` to `optional` (it is not eligible for implicit consent) and request it when the first key is saved. Confidence: low.

**Runtime API (verified in the MDN docs)**
```js
// Click handler: make this the first awaited call (no await before it).
// The type must be listed in data_collection_permissions.optional.
const ok = await browser.permissions.request({ data_collection: ["websiteContent"] });
await browser.permissions.contains({ data_collection: ["websiteContent"] }); // returns a boolean
await browser.permissions.getAll(); // {origins, permissions, data_collection: [...]}; key absent means no built-in consent
await browser.permissions.remove({ data_collection: ["websiteContent"] });
```
- One `request()` can also include `origins`; then "either all are granted, or none are".
- Users can toggle optional types in about:addons → *Permissions and data*, so re-check with `contains()` before every AI call.
- The docs don't say whether `onAdded`/`onRemoved` report `data_collection`.

## 2. sidebarAction.toggle()
- Available in Firefox desktop 73+. There is no sidebarAction on Android.
- MDN: "You can only call this function from inside the handler for a user action." Clicking the action button counts as one. Any `await` before the call loses user-action status.
- **MV3 event page:** the docs don't cover what happens when the event page wakes up. Firefox's source suggests it works:
  - The action's `onClicked` EventManager is created with `inputHandling: true`.
  - The primed listener runs `await fire.wakeup()` and then `fire.sync(...)`.
  - The child process runs the listener inside `withHandlingUserInput`.
  - Confidence: medium-high, based on source code rather than docs.
  - Register the listener synchronously at top level (MDN: "Listeners must be registered synchronously").
- **Gotchas:**
  - `onClicked` "will not fire if the browser action has a popup". Declare an `"action"` key with no `default_popup`.
  - `default_area` defaults to `"menupanel"`, so the button starts in the Extensions panel, not the toolbar.
  - `sidebar_action.open_at_install` defaults to `true`, so the sidebar opens automatically on install. Set it to `false` if you don't want that. Bug 1892667 reports that reload or update still opens it.
  - Don't set `browser_style`; it is unsupported in MV3 from Firefox 118 and the linter warns.

## 3. Permissions from the sidebar; host permissions
- **`permissions.request()` works from the sidebar.** BCD: "Before version 101, permissions cannot be requested from a sidebar document (bug 1493396)." Clicking a button on an extension page counts as a user action.
- **Call it synchronously in the handler.** Don't `await permissions.contains()` first inside the handler. Do the check on load and call `request()` first on click.
- **`optional_host_permissions`:** supported from Firefox 128, MV3 only. `"*://*/*"` lints clean. Requested `origins` can be a subset of the optional pattern.
- **`host_permissions`:** "From Firefox 127, host permissions listed in `host_permissions` … are displayed in the install prompt and granted on installation."
  - Users can revoke them at any time.
  - The extension can re-request them with `permissions.request`.
  - Host permissions added in an update "are not shown to the user" (bug 1893232), so check with `contains()` after updates.
- **CORS:** a host permission gives extension pages fetch "access to those origins without cross-origin restrictions". Without it, a fetch from moz-extension:// is subject to CORS.
- **Plain-HTTP gotcha (not in the spec):** the default MV3 CSP is `"script-src 'self'; upgrade-insecure-requests;"`.
  - Every `http:` fetch is upgraded to `https:`, so homepages of HTTP-only sites will fail to load.
  - Opting out needs a custom CSP without that directive. That is allowed, but policy says user data must be transmitted securely.

## 4. browser.dns.resolve()
- **Signature:** `resolve(hostname: string, flags?: string[]) → Promise<DNSRecord>`.
- **Permission:** `"dns"`. Available from Firefox 60, with no install-prompt string (schema type PermissionNoPrompt).
- **Flags:** `allow_name_collisions`, `bypass_cache`, `canonical_name`, `disable_ipv4`, `disable_ipv6`, `disable_trr`, `offline`, `priority_low`, `priority_medium`, `speculate`.
- **Result:** `{"addresses":["93.184.215.14","2606:2800:21f:cb07:6820:80da:af6b:8b2c"],"canonicalName":"example.com","isTRR":false}`. `canonicalName` appears only when `canonical_name` is passed.
- **From ext-dns.js:**
  - It uses RESOLVE_TYPE_DEFAULT, so you get addresses only (no MX/TXT/NS).
  - Duplicate addresses are removed.
  - Failures reject with `{message: "<nsresult name>"}`, for example `NS_ERROR_UNKNOWN_HOST`.
  - It uses default origin attributes.
- **With Firefox TRR on:** the query goes through Firefox's resolver, so DoH is used unless you pass `disable_trr`. Pass `["disable_trr","bypass_cache"]` for the system-resolver comparison, and treat `isTRR === true` as "not a system result".
- The docs don't say how `disable_trr` behaves in TRR-only mode (mode 3). Handle a rejection.

## 5. Background
- Firefox does not support `background.service_worker` (bug 1573659; BCD: false).
- Use `"background": {"scripts": ["background.js"]}`. In MV3 `persistent` defaults to `false`, which makes it an event page. `persistent: true` in MV3 is an error.
- `type: "module"` is optional (Firefox 112+). It lints clean (verified).
- `service_worker` without `scripts` → **error** `BACKGROUND_SERVICE_WORKER_NOFALLBACK` (verified).

## 6. web-ext lint (verified)
**The spec's manifest gives 0 errors and 1 warning.** The manifest tested had MV3, action, sidebar_action, background.scripts, storage+dns, fixed host_permissions, `*://*/*` optional, the gecko id, strict_min_version 140.0, and `required: [browsingActivity]` with `optional: [websiteContent, authenticationInfo]`.
- **Warning:** `KEY_FIREFOX_ANDROID_UNSUPPORTED_BY_MIN_VERSION` — "strict_min_version requires Firefox for Android 140, which was released before version 142 introduced support for browser_specific_settings.gecko.data_collection_permissions".
- **Cause:** `gecko_android.strict_min_version` defaults to the `gecko` value.
- **Fix:** adding `"gecko_android": {"strict_min_version": "142.0"}` gives 0/0/0. The extension is desktop-only in practice (no sidebarAction on Android), so leave Android unticked on AMO.

**Other verified results**
- Missing `required` → error.
- `none` with another type → error.
- `technicalAndInteraction` in `required` → error.
- Key missing entirely → only a warning (`MISSING_DATA_COLLECTION_PERMISSIONS`), but AMO still blocks signing for new extensions.

**strict_min_version 140** is the minimum that lets the extension rely only on the built-in consent (policy 6.2.1). Below 140 a custom consent UI is required.

**Not linted:** JS rules such as `UNSAFE_VAR_ASSIGNMENT` for innerHTML. These are warnings; render API data with `textContent`.

## 7. AMO source submission (bundler)
**Sources are required** when the build uses minifiers, bundlers ("tools that generate a single file from other files"), template engines, or any pre-processing. Upload a sources file of up to 200 MB with every version.

**The sources package must contain**
- All source, including any private deps.
- A README covering OS/environment, tool versions with install links, and every build command.
- The build script.
- The lockfile (`package-lock.json`).
- "Anything else needed".

**Build rules**
- Tools must be open source and run locally (no web-based tools).
- The reviewer rebuilds and diffs the output: "There must be no differences". Make the build deterministic and output to e.g. `dist/`.
- Obfuscation is banned. Minification is allowed if sources are provided.

**Default reviewer environment:** Ubuntu 24.04.4 LTS, ARM64, Node 24.14.0, npm 11.9.0. Note any differences in the README. My inference: bundlers with native binaries (esbuild/rollup/swc) must resolve linux-arm64 packages from a lockfile created on Windows.

**New (AMO blog, 2026-07-23):** if the sources include `package.json`, AMO tries to build them automatically. Add an npm script named `build-for-amo` and list all devDependencies. The post doesn't document the expected output location.

**Third-party libraries:** put links in "Notes for Reviewers"; with npm, `package.json` counts as the link. Libraries must be release versions and unmodified.

## Other notes
- **Extension ID:** `domain-recon@example.org` matches the ID regex (80 characters or fewer). AMO checks uniqueness, and MV3 requires an ID. The docs don't forbid example.org, but a domain you control is safer.
- **publicSuffix API:** Firefox 153+ has `publicSuffix.getDomain()` for eTLD+1. It doesn't exist at minimum version 140, so feature-detect it or bundle the Public Suffix List.

Key URLs: extensionworkshop.com/documentation/develop/firefox-builtin-data-consent/ · …/publish/add-on-policies/ · …/publish/source-code-submission/ · developer.mozilla.org/…/WebExtensions/User_actions · …/API/permissions/request · …/API/dns/resolve · …/manifest.json/background · …/manifest.json/host_permissions · …/Content_Security_Policy · blog.mozilla.org/addons/2025/10/23/data-collection-consent-changes-for-new-firefox-extensions/ · blog.mozilla.org/addons/2026/07/23/firefox-153-webextensions-api-updates/