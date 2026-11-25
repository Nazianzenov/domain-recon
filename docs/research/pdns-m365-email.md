# Report: Mnemonic PDNS, Microsoft tenant discovery, email-provider DNS signatures (checked 2026-11-25)

Docs were read on 2026-11-25. Where a claim is marked "live", I checked it with curl or DNS-over-HTTPS (DoH). Confidence: H = documented, M = observed or secondary, L = folklore.

## 1. Mnemonic PDNS v3

**Sources:** docs.mnemonic.no/service-integration-guides/passivedns/docs/public/01-public_api.html and 02-private_api.html. Swagger is at portal.mnemonic.no/spa/swagger?module=pdns.

**Endpoints (H)**
- `GET https://api.mnemonic.no/pdns/v3/{query}`. `{query}` can be a domain, an IP or an answer string.
  - Query params: `limit` (default **25**; `0` means unlimited).
  - `offset` (default 0).
  - `rrClass` (default any).
  - `rrType` (default any; can be repeated, e.g. `rrType=a&rrType=mx`).
  - Private-only params: `customerID`, `tlp`, `aggregate` (default true), `includeAnonymous`.
- `GET /pdns/v3/{query}/seen` returns `data.exists` (bool).
- `GET /pdns/v3/cof/...` returns Common Output Format.
- `POST /pdns/v3/search` takes `{"query":"x.com","rrClass":["in"],"rrType":["a"],"limit":0,"offset":0}`.

**Auth and limits (H)**
- Auth header: `Argus-API-Key: 1234/1/abcd1234ef012`. Keys come from argus-support@mnemonic.no.
- Unauthenticated access is allowed but limited to **TLP white**, **10 req/min and 1000 req/day**.
- `limit` maximum is **1000** without a key and 10000 with one. Going over returns **HTTP 412** (live message: "Maximum result limit for public usage is 1000").
- Quota exhaustion returns **HTTP 402** (not 429), with `metaData.millisUntilResourcesAvailable`. A daily block can last up to 24 h.
- Results are sorted by `lastSeenTimestamp` descending.

**Response envelope (H, plus live)**
- Documented fields: `responseCode, count, limit, offset, currentPage, size, data, messages, metaData`. Live responses omit `currentPage`.
- When nothing matches, live returns HTTP 200 with `data:[]` and a message whose `messageTemplate` is `"object.not.found"` and `type` is `"INFO"`.
- Record fields: `query, answer, rrtype, rrclass` (lowercase; the query params are camelCase), `firstSeenTimestamp, lastSeenTimestamp` (epoch ms), `minTtl, maxTtl, times, tlp, customer` (null for public), `createdTimestamp, lastUpdatedTimestamp`.
  - The docs say the two created/updated timestamps are "always 0". Live they are non-zero.
  - Live records also carry an undocumented `flags` array, e.g. `["partialResult"]`.

Example (live, trimmed):
```json
{"responseCode":200,"limit":2,"offset":0,"count":997,"metaData":{},"messages":[],"size":2,
 "data":[{"query":"example.com","answer":"104.20.23.154","rrtype":"a","rrclass":"in",
  "firstSeenTimestamp":1775811478663,"lastSeenTimestamp":1795540944901,"minTtl":1,"maxTtl":300,
  "times":20744,"tlp":"white","customer":null,"flags":["partialResult"],
  "createdTimestamp":1775811501901,"lastUpdatedTimestamp":1795541064939}]}
```

**CORS (live):** responses send `access-control-allow-headers` (including ARGUS-API-Key) but **no `Access-Control-Allow-Origin`** for any Origin. The extension needs the host permission `https://api.mnemonic.no/*`.
- MDN says host_permissions give fetch "without cross-origin restrictions", except from content scripts.
- In Firefox MV3 the user can revoke host permissions. Check with `permissions.contains` and call `permissions.request` if needed.

**Where the spec differs**
- "Unauthenticated results may lack timestamps" is **not in the docs**. Live unauthenticated responses include first and last seen. The real limitations are TLP-white-only data, the 1000-record cap and the 10/min and 1000/day quota. Change the UI note to say that.
- Set `limit` explicitly (default is 25), handle 402 and 412, and run lookups one at a time. A 24 h TTL fits the quota.

## 2. Microsoft tenant discovery

**OIDC discovery** (learn.microsoft.com/entra/identity-platform/v2-protocols-oidc, H)
- v1: `/{tenant}/.well-known/openid-configuration` gives issuer `https://sts.windows.net/{guid}/`.
- v2: `/{tenant}/v2.0/.well-known/openid-configuration` gives issuer `https://login.microsoftonline.com/{guid}/v2.0`.
- **Gotcha (live):** sovereign tenants have a different issuer host. For example, army.mil gives `https://login.microsoftonline.us/{guid}/v2.0`. Extract the GUID with `/\/([0-9a-f-]{36})\//i` and do not hard-code the host.
- Both versions send `Access-Control-Allow-Origin: *` and `Cache-Control: max-age=86400` (live).
- Region fields (live):
  - `tenant_region_scope`: values seen include WW, NA, EU, SA, USGov.
  - `tenant_region_sub_scope`: GCC, DOD (often absent).
  - `cloud_instance_name`: microsoftonline.com or microsoftonline.us.
  - `cloud_graph_host_name`, `msgraph_host` (e.g. dod-graph.microsoft.us).
- Of these, Learn only documents `tenant_region_scope`, as an optional claim ("Region of the resource tenant"), and it does not list the values (M).
- Unknown tenant, live: **HTTP 400** with this body:
```json
{"error":"invalid_tenant","error_description":"AADSTS90002: Tenant 'x.com' not found. ...","error_codes":[90002],"timestamp":"...","trace_id":"...","correlation_id":"...","error_uri":"https://login.microsoftonline.com/error?code=90002"}
```

**getuserrealm.srf**
- `https://login.microsoftonline.com/getuserrealm.srf?login=probe@{d}&json=1` is **undocumented** (no Microsoft docs found).
- Live: no ACAO header, even on OPTIONS, so a host permission is required. Without `json=1` it returns XML `<RealmInfo>`.
- Fields: `State, UserState, Login, NameSpaceType (Managed|Federated|Unknown), DomainName, FederationBrandName, CloudInstanceName, CloudInstanceIssuerUri`. Federated responses also have `AuthURL, FederationGlobalVersion` and sometimes `AuthNForwardType`.
```json
{"State":4,"UserState":1,"Login":"probe@microsoft.com","NameSpaceType":"Managed","DomainName":"microsoft.com","FederationBrandName":"Microsoft","CloudInstanceName":"microsoftonline.com","CloudInstanceIssuerUri":"urn:federation:MicrosoftOnline"}
{"State":3,"UserState":2,"Login":"probe@corp.com","NameSpaceType":"Federated","DomainName":"corp.com","FederationGlobalVersion":-1,"AuthURL":"https://accounts.google.com/o/saml2/idp?idpid=...","FederationBrandName":"Corp","CloudInstanceName":"microsoftonline.com","CloudInstanceIssuerUri":"urn:federation:MicrosoftOnline"}
{"State":4,"UserState":1,"Login":"probe@nx.com","NameSpaceType":"Unknown"}
```
- Alternative (undocumented REST endpoint, also called by ADAL; live, no ACAO): `https://login.microsoftonline.com/common/userrealm/probe@{d}?api-version=2.1`.
  - `api-version=1.0` returns `account_type, domain_name, federation_protocol` (e.g. SAML20/WSTrust), `federation_active_auth_url, cloud_instance_name`.
  - 2.0 and 2.1 return `NameSpaceType, federation_protocol, AuthURL, DomainName, FederationBrandName, TenantBrandingInfo[], cloud_instance_name, is_dsso_enabled`.
  - It is a useful addition because it gives the federation protocol and seamless-SSO status.

**False positives (live)**
- gmail.com, outlook.com and hotmail.com return a **valid OIDC tenant** (Microsoft-owned GUIDs such as `9cd80435-…`, `f8cdef31-…`).
- Their realm comes back `Federated` with `DomainName:"live.com"` and AuthURL host `login.live.com`.
- Fix: treat it as "consumer/MSA, no org tenant" when `DomainName !== d` or the AuthURL host is login.live.com.

**Where the spec differs:** add the issuer-host variance, the HTTP 400 handling, the consumer-domain filter and the CORS/host-permission requirement. "Federated AuthURL host" is correct, but it may be a third-party IdP (Google, Okta, ADFS).

## 3. Microsoft 365 DNS signatures (H unless noted)

- **MX**
  - Legacy: `<MX token>.mail.protection.outlook.com`. The token is usually the domain with dots turned into dashes, but it is not guaranteed.
  - Legacy variants: `mail.eo.outlook.com`, `mail.protection.outlook.de`.
  - New DNSSEC MX: `<MX token>.<sub>.mx.microsoft`, e.g. `contosotest-com.o-v1.mx.microsoft`. Microsoft said new accepted domains move to mx.microsoft provisioning around July 2026 (blog, M).
  - GCC High `mail.protection.office365.us`: L.
- **SPF:** `include:spf.protection.outlook.com`.
- **Autodiscover:** CNAME `autodiscover` → `autodiscover.outlook.com`.
- **Verification TXT:** `MS=msXXXXXXXX`. A live `MS=<40 hex>` variant also exists (M).
- **DKIM**
  - Old format: `selector1-<domain-dashed>._domainkey.<prefix>.onmicrosoft.com`.
  - New format, used for custom domains added since May 2025: `selector1-<domain-dashed>._domainkey.<prefix>.<c>-v1.dkim.mail.microsoft`, where `<c>` is a partition letter such as n or r.
  - In both formats the initial domain is `<prefix>.onmicrosoft.com`.
  - Live: microsoft.com points to `selector1-microsoft-com._domainkey.microsoft.onmicrosoft.com`.
- **Teams:** SRV `_sipfederationtls._tcp` → `sipfed.online.lync.com`.

## 4. Other providers

- **SendGrid** (twilio.com/docs/sendgrid, H)
  - With automated security on: `em####` CNAME → `u<id>.wl<nnn>.sendgrid.net`; `s1._domainkey` → `s1.domainkey.u<id>.wl<nnn>.sendgrid.net` (and s2 the same way). Live: `s1.domainkey.u298828.wl079.sendgrid.net`.
  - With automated security off: TXT `v=spf1 include:sendgrid.net ~all` and MX `mx.sendgrid.net` on **em####**, plus TXT at `m1._domainkey`.
  - So the apex `include:sendgrid.net` is only an optional addition by the domain owner, not the standard setup. The `em####` and `url####` labels can't be guessed.
  - A custom DKIM selector (3 characters) replaces `s`.
  - What `u<digits>` is (M): the API's `user_id` ("ID of the user that this domain is associated with"). It matches in one API example; another example contradicts it. Link-branding `owner_cname` is `<user_id>.domain` → `sendgrid.net`. This may be a **subuser** ID rather than the parent account.
- **Mailgun** (H for SPF, MX and pdk; the rest M or L)
  - SPF `include:mailgun.org`.
  - MX `mxa/mxb.mailgun.org`. EU: `mxa/mxb.eu.mailgun.org` and tracking `eu.mailgun.org`.
  - `include:eu.mailgun.org` resolves to a valid SPF record (live) but is undocumented.
  - Automatic Sender Security: `pdk1/pdk2._domainkey` CNAME → `pdk1._domainkey.<id>.dkim1.mailgun.com`.
  - Legacy TXT selectors (k1, smtp, mx, krs, pic, mailo) are **not documented** (L).
  - Mailgun usually lives on a sending **subdomain** (e.g. mg.example.com), so apex checks miss it.
- **Amazon SES** (H)
  - DKIM: 3 CNAMEs `<token>._domainkey` → `<token>.<SigningHostedZone>`. The hosted zone is e.g. `dkim.amazonses.com`; docs also give `dkim.us-west-2.amazonses.com` as an example. Tokens are random, so they can't be queried blindly; use selectors learned from PDNS or headers.
  - SPF `include:amazonses.com` and MX `10 feedback-smtp.<region>.amazonses.com` are on the custom MAIL FROM **subdomain**, not the apex.
  - Inbound MX `10 inbound-smtp.<region>.amazonaws.com`.
- **Mailchimp / Mandrill**
  - Current Mailchimp docs: 2 CNAMEs plus a DMARC TXT. Records are k2 → `dkim2.mcsv.net` and k3 → `dkim3.mcsv.net`, both seen live; the article itself shows only k2 by name.
  - k1 → `dkim.mcsv.net` is legacy (live on mailchimp.com).
  - `include:servers.mcsv.net` is not in the current Mailchimp article (still shown in a Microsoft example).
  - Mandrill, enforced from 2024-03-15: `mte1/mte2._domainkey` → `dkim1/dkim2.mandrillapp.com`, TXT `mandrill_verify.<key>`, tracking CNAME → `mandrillapp.com`.
  - Legacy Mandrill: `mandrill._domainkey` TXT and `include:spf.mandrillapp.com` (M). **Spec gap:** add mte1/mte2.
- **Google Workspace** (H)
  - MX `smtp.google.com` (priority 1) for new accounts; legacy `aspmx…` values still supported.
  - SPF `include:_spf.google.com`.
  - DKIM default selector `google` (changeable), TXT `v=DKIM1`.
  - `google-site-verification` is not specific to Workspace, so give it low weight.

**DoH gotchas:** a TXT query on a CNAMEd selector returns the CNAME plus the TXT, so filter on `type===5`. Strip trailing dots, lowercase values and join split TXT strings.

## 5. Signature table (TypeScript)

```ts
export type EvidenceType = 'spf'|'mx'|'dkim'|'txt'|'cname';
export interface Signature { provider: string; type: EvidenceType; name: string; // '@'=apex, else label (dkim: selector, CNAME expected unless note says TXT)
  re: RegExp; capture?: string[]; weight: 1|2|3; note?: string }
// values: lowercase, trailing dot stripped, TXT strings joined
const inc = (h: string) => new RegExp(`(?:^|\\s)[+~?]?include:${h.replace(/\./g,'\\.')}(?=\\s|$)`);
export const SIGNATURES: Signature[] = [
  // Microsoft 365
  { provider:'Microsoft 365', type:'spf', name:'@', re:inc('spf.protection.outlook.com'), weight:3 },
  { provider:'Microsoft 365', type:'mx', name:'@', re:/^([a-z0-9-]+)\.mail\.protection\.outlook\.(?:com|de)$|^([a-z0-9-]+)\.mail\.eo\.outlook\.com$/, capture:['mxToken'], weight:3 },
  { provider:'Microsoft 365', type:'mx', name:'@', re:/^([a-z0-9-]+)\.([a-z0-9-]+)\.mx\.microsoft$/, capture:['mxToken','partition'], weight:3, note:'DNSSEC MX' },
  { provider:'Microsoft 365', type:'txt', name:'@', re:/^ms=(?:ms\d{6,10}|[0-9a-f]{40})$/, weight:2 },
  { provider:'Microsoft 365', type:'cname', name:'autodiscover', re:/^autodiscover\.outlook\.com$/, weight:2 },
  { provider:'Microsoft 365', type:'dkim', name:'selector1', re:/^selector1-([a-z0-9-]+)\._domainkey\.([a-z0-9-]+)\.onmicrosoft\.com$/, capture:['domainDashed','initialDomainPrefix'], weight:3 },
  { provider:'Microsoft 365', type:'dkim', name:'selector1', re:/^selector1-([a-z0-9-]+)\._domainkey\.([a-z0-9-]+)\.([a-z0-9])-v1\.dkim\.mail\.microsoft$/, capture:['domainDashed','initialDomainPrefix','partition'], weight:3 },
  { provider:'Microsoft 365', type:'dkim', name:'selector2', re:/^selector2-([a-z0-9-]+)\._domainkey\.([a-z0-9-]+)\.(?:onmicrosoft\.com|[a-z0-9]-v1\.dkim\.mail\.microsoft)$/, capture:['domainDashed','initialDomainPrefix'], weight:3 },
  // SendGrid
  { provider:'SendGrid', type:'dkim', name:'s1', re:/^s1\.domainkey\.u(\d+)\.wl(\d+)\.sendgrid\.net$/, capture:['userId','wl'], weight:3 },
  { provider:'SendGrid', type:'dkim', name:'s2', re:/^s2\.domainkey\.u(\d+)\.wl(\d+)\.sendgrid\.net$/, capture:['userId','wl'], weight:3 },
  { provider:'SendGrid', type:'spf', name:'@', re:inc('sendgrid.net'), weight:2, note:'standard on em#### not apex' },
  // Mailgun
  { provider:'Mailgun', type:'spf', name:'@', re:/(?:^|\s)[+~?]?include:(eu\.)?mailgun\.org(?=\s|$)/, capture:['eu'], weight:3 },
  { provider:'Mailgun', type:'mx', name:'@', re:/^mx[ab]\.(eu\.)?mailgun\.org$/, capture:['eu'], weight:3 },
  { provider:'Mailgun', type:'dkim', name:'pdk1', re:/^pdk1\._domainkey\.([a-z0-9]+)\.dkim\d*\.(?:eu\.)?mailgun\.(?:com|org)$/, capture:['mgId'], weight:3 },
  { provider:'Mailgun', type:'dkim', name:'pdk2', re:/^pdk2\._domainkey\.([a-z0-9]+)\.dkim\d*\.(?:eu\.)?mailgun\.(?:com|org)$/, capture:['mgId'], weight:3 },
  { provider:'Mailgun', type:'cname', name:'email', re:/^(eu\.)?mailgun\.org$/, capture:['eu'], weight:2 },
  // Amazon SES
  { provider:'Amazon SES', type:'spf', name:'@', re:inc('amazonses.com'), weight:2, note:'normally on MAIL FROM subdomain' },
  { provider:'Amazon SES', type:'mx', name:'@', re:/^inbound-smtp\.([a-z0-9-]+)\.amazonaws\.com$/, capture:['region'], weight:3 },
  { provider:'Amazon SES', type:'mx', name:'@', re:/^feedback-smtp\.([a-z0-9-]+)\.amazonses\.com$/, capture:['region'], weight:3, note:'MAIL FROM subdomain' },
  { provider:'Amazon SES', type:'dkim', name:'*', re:/^([a-z0-9]{32})\.dkim(?:\.([a-z0-9-]+))?\.amazonses\.com$/, capture:['token','region'], weight:3, note:'selector=token; only from PDNS/headers' },
  // Mailchimp / Mandrill
  { provider:'Mailchimp', type:'dkim', name:'k1', re:/^dkim\.mcsv\.net$/, weight:3 },
  { provider:'Mailchimp', type:'dkim', name:'k2', re:/^dkim2\.mcsv\.net$/, weight:3 },
  { provider:'Mailchimp', type:'dkim', name:'k3', re:/^dkim3\.mcsv\.net$/, weight:3 },
  { provider:'Mailchimp', type:'spf', name:'@', re:inc('servers.mcsv.net'), weight:2 },
  { provider:'Mandrill', type:'dkim', name:'mte1', re:/^dkim1\.mandrillapp\.com$/, weight:3 },
  { provider:'Mandrill', type:'dkim', name:'mte2', re:/^dkim2\.mandrillapp\.com$/, weight:3 },
  { provider:'Mandrill', type:'dkim', name:'mandrill', re:/(?:^|;)\s*p=[a-z0-9+/=]+/i, weight:2, note:'TXT, legacy' },
  { provider:'Mandrill', type:'spf', name:'@', re:inc('spf.mandrillapp.com'), weight:2 },
  { provider:'Mandrill', type:'txt', name:'@', re:/^mandrill_verify\.[a-z0-9_-]+$/i, weight:2 },
  // Google Workspace
  { provider:'Google Workspace', type:'spf', name:'@', re:inc('_spf.google.com'), weight:3 },
  { provider:'Google Workspace', type:'mx', name:'@', re:/^(?:smtp\.google\.com|(?:alt[1-4]\.)?aspmx\.l\.google\.com|aspmx[2-5]\.googlemail\.com)$/, weight:3 },
  { provider:'Google Workspace', type:'dkim', name:'google', re:/v=dkim1;.*p=/i, weight:2, note:'TXT; selector customizable' },
  { provider:'Google Workspace', type:'txt', name:'@', re:/^google-site-verification=/, weight:1, note:'not Workspace-specific' },
];
```

Unverified (L) and left out: Mailgun legacy TXT selectors, GCC High/21Vianet MX hosts, and the SendGrid custom-selector naming (`<sel>`, `<sel>2`). Use them only to back up evidence that is already strong.
