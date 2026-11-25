# Threat-intel APIs: docs check (2026-11-25)

**Sources.** I read the official docs: docs.virustotal.com, otx.alienvault.com/assets/static/external_api.html, the OTX-Python-SDK, docs.abuseipdb.com, urlhaus-api.abuse.ch, threatfox.abuse.ch/api, developer.shodan.io, help.shodan.io, book.shodan.io and internetdb.shodan.io/openapi.json. Where the docs say nothing, I sent keyless or bogus-key requests to the live APIs to see what they return; those results are marked **[live]**.

---

## 8. VirusTotal v3: the spec is correct, with these additions

**Base and auth**
- Base URL: `https://www.virustotal.com/api/v3`.
- Header: `x-apikey: <key>`, required on every call.

**Endpoints**
- `GET /domains/{d}`
- `GET /domains/{d}/resolutions?limit=&cursor=`
- `GET /ip_addresses/{ip}`

**Resolutions pagination**
- `limit` defaults to 10. The docs don't give a maximum (40 is commonly assumed; low confidence).
- To get the next page, pass `cursor`. The response carries it in `meta.cursor`, and `links.next` is the full next-page URL.

**IPv6:** the docs say "both IPv4 and IPv6 addresses are stored as IP address objects". The path parameter is just "IP address". Colons are legal in a path segment, so there's no need to encode them.

**Quota (public API)**
- 4 requests/min and 500/day. The public-vs-premium page doesn't state a monthly figure.
- Daily quotas reset at 00:00 UTC.
- The public API "must not be used in commercial products or services".
- Every domain or IP you query is added to the VT dataset (privacy).

**Domain fields**
- `last_analysis_stats`: `{harmless, malicious, suspicious, undetected, timeout}`. The spec leaves out `timeout`.
- `reputation` (int; negative means bad), `categories` ({vendor: category}), `registrar`, `creation_date` (unix), `last_dns_records[]` (`{type, value, ttl, …}`), `tags`, `total_votes`, `whois`, `last_https_certificate`, `popularity_ranks`.

**IP fields:** `as_owner`, `asn`, `country`, `network`, `last_analysis_stats`, `reputation`, `tags`. `port_info` is premium only.

**Resolution fields:** `attributes.{ip_address, host_name, date, resolver, ip_address_last_analysis_stats, host_name_last_analysis_stats}`. The `id` is the IP followed directly by the hostname.

**Errors:** the body is always `{"error":{"code","message"}}`.
- 401 `WrongCredentialsError`. [live] A bad key gives `"message":"Wrong API key"`.
- 401 `AuthenticationRequiredError`. [live] No key gives `"X-Apikey header is missing"`.
- 401 `UserNotActiveError`
- 403 `ForbiddenError`
- 404 `NotFoundError`
- 429 `QuotaExceededError` (minute, daily or monthly) and 429 `TooManyRequestsError`
- 400 `InvalidArgumentError`, 503 `TransientError`

**Test key:** use `GET /users/{apikey}/overall_quotas` with the `x-apikey` header. The docs say it uses **no quota**, and the response gives allowed/used for `api_requests_{hourly,daily,monthly}`. Don't test with `/ip_addresses/8.8.8.8`, which uses up one of the 4 calls per minute.

**CORS:** [live] no `Access-Control-Allow-Origin` header. Calls only work because the extension has host permissions.

```json
{"data":{"id":"example.com","type":"domain","attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"harmless":66,"undetected":28,"timeout":0},"reputation":0,"categories":{"Forcepoint ThreatSeeker":"information technology"},"registrar":"RESERVED-Internet Assigned Numbers Authority","creation_date":694224000,"last_dns_records":[{"type":"A","value":"93.184.215.14","ttl":300}]}}}
```
```json
{"meta":{"count":312,"cursor":"CuAB..."},"data":[{"type":"resolution","id":"93.184.215.14example.com","attributes":{"ip_address":"93.184.215.14","host_name":"example.com","date":1716000000,"resolver":"VirusTotal"}}],"links":{"self":"…","next":"https://www.virustotal.com/api/v3/domains/example.com/resolutions?cursor=CuAB...&limit=10"}}
```

---

## 9. AlienVault OTX: the spec works; IPv6 path and anonymous limits noted

**Base and auth**
- Base URL: `https://otx.alienvault.com/api/v1`.
- Header: `X-OTX-API-KEY`, as used by the official SDK.

**Endpoints:** `/indicators/{domain|hostname|IPv4|IPv6}/{value}/{section}`
- Domain sections: `general, geo, malware, url_list, passive_dns` (plus `whois` and `http_scans`).
- IPv4 and IPv6 sections: `general, reputation, geo, malware, url_list, passive_dns`.
- The **IPv6 path is `/indicators/IPv6/{ip}/general`** (capitalised, as in the docs example). [live] Both raw and %3A-encoded colons return 200.

**Test key:** the docs list both `/api/v1/user/me` and `/api/v1/users/me`, and the SDK uses `users`. Both validate the key and return `{username, user_id, pulse_count, …}`.

**Errors**
- [live] A bad or missing key on `users/me` returns **403** `{"detail":"Authentication required"}`. The SDK also maps 403 to InvalidAPIKey.
- [live] An invalid domain (`.invalid` TLD) returns 400.
- 404 means not found.

**Rate limits:** the docs say nothing. The SDK retries on 429 and 5xx.

**Gotchas**
- [live] Indicator lookups work without a key, but `domain/example.com/passive_dns` returned **429** `{"detail":"Anonymous access to this endpoint is limited. Please authenticate."}`.
- [live] `general` for example.com was **428 KB**, because `pulse_info.pulses[]` is not paginated. Cap or truncate it.

**CORS:** [live] `Access-Control-Allow-Origin` is `*` or echoes the Origin.

```json
{"indicator":"example.com","type":"domain","sections":["general","geo","url_list","passive_dns","malware","whois","http_scans"],"validation":[{"source":"whitelist","message":"Whitelisted domain example.com","name":"Whitelisted domain"}],"pulse_info":{"count":50,"pulses":[{"id":"6b06…","name":"…","tags":["TAXII"],"TLP":"green","created":"2026-11-25T03:56:19","malware_families":[]}],"references":[],"related":{}},"base_indicator":{"id":95944,"indicator":"example.com","type":"domain"}}
```

IP `general` also has `reputation`, `asn` (for example `"AS15169 google llc"`), `country_code` and `false_positive`.

```json
{"passive_dns":[{"address":"93.184.215.14","first":"2024-01-02T10:00:00","last":"2026-11-20T08:00:00","hostname":"example.com","record_type":"A","indicator_link":"/indicator/ip/93.184.215.14","flag_title":"United States","asset_type":"IPv4","asn":"AS15133 edgecast"}],"count":1}
```
The `count` key is medium confidence.

---

## 10. AbuseIPDB: the spec is correct

**Request:** `GET https://api.abuseipdb.com/api/v2/check?ipAddress=&maxAgeInDays=` with headers `Key: <key>` and `Accept: application/json`.
- `maxAgeInDays`: 1–365, default 30.
- `verbose` adds `reports[]` and `countryName`.
- **IPv6** is accepted ("v4 or v6"). The docs say to URL-encode it with `encodeURIComponent`.

**Daily check limits:** Standard (free) 1,000; Webmaster 3,000; Supporter 5,000; Basic 10,000; Premium 50,000. The headers `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` (epoch) and `Retry-After` report the limit.

**Errors:** the body is `{"errors":[{"detail","status"}]}`.
- 429: "Daily rate limit of 1000 requests exceeded for this endpoint."
- 422: bad parameters.
- The docs **don't document 401**. [live] It returns 401 `"Authentication failed. Your API key is either missing, incorrect, or revoked. Note: The APIv2 key differs from the APIv1 key."`

**Test key:** the docs say nothing about checking 127.0.0.1; only 127.0.0.2 is mentioned, as a REPORT-endpoint rate-limit test. A check on 127.0.0.1 most likely returns 200 with `isPublic:false` (low confidence). Either way it uses 1 of the daily checks. Treat 401 as a bad key and 200 as valid.

**CORS:** the docs say "CORS headers cannot be set… APIv2 keys… are not intended for client side calls." So host permissions are required. Note the possible terms-of-service issue.

```json
{"data":{"ipAddress":"118.25.6.39","isPublic":true,"ipVersion":4,"isWhitelisted":false,"abuseConfidenceScore":100,"countryCode":"CN","usageType":"Data Center/Web Hosting/Transit","isp":"Tencent Cloud Computing (Beijing) Co. Ltd","domain":"tencent.com","hostnames":[],"isTor":false,"totalReports":1,"numDistinctUsers":1,"lastReportedAt":"2018-12-20T20:55:14+00:00"}}
```

---

## 11. abuse.ch (URLhaus and ThreatFox): Auth-Key is mandatory

**Auth-Key:** required for both. Both API pages say "you must include the HTTP header `Auth-Key`". The required date, **2025-06-30**, comes from the abuse.ch "Community First" blog post as quoted in search results; I didn't open the post itself. Keys are free from auth.abuse.ch.

**Live behaviour with no key or a bad key**

| Case | URLhaus | ThreatFox |
|---|---|---|
| No key | 401 `{"error": "Unauthorized"}`, sent as Content-Type `application/octet-stream`, so parse the text | Same 401 body |
| Bad key | 403 `{"query_status":"unknown_auth_key"}` | Same 403 body |

**URLhaus**
- The spec is correct: `POST https://urlhaus-api.abuse.ch/v1/host/` with form `host=<IPv4|hostname|domain>`.
- `query_status` values: `ok`, `no_results`, `invalid_host`, `http_post_expected`.
- `urls[]` is capped at 100.
- `blacklists` isn't returned for IPv4 hosts.
- Numbers such as `url_count` and `id` come back as strings.
- The docs example has a typo, `"query_staus"`; real responses use `query_status`.
- The docs don't mention IPv6 hosts.

```json
{"query_status":"ok","urlhaus_reference":"https://urlhaus.abuse.ch/host/vektorex.com/","host":"vektorex.com","firstseen":"2019-01-15 07:09:01 UTC","url_count":"120","blacklists":{"spamhaus_dbl":"abused_legit_malware","surbl":"not listed"},"urls":[{"id":"121319","urlhaus_reference":"https://urlhaus.abuse.ch/url/121319/","url":"http://vektorex.com/x.exe","url_status":"online","date_added":"2019-02-11 07:45:05 UTC","threat":"malware_download","reporter":"abuse_ch","larted":"false","takedown_time_seconds":null,"tags":["AZORult","exe"]}]}
```

**ThreatFox**
- The spec is correct: `POST https://threatfox-api.abuse.ch/api/v1/` with a JSON body `{"query":"search_ioc","search_term":"…","exact_match":true}`.
- **Gotcha:** `exact_match` defaults to **false**, which does a wildcard search, so substrings match. Set it to `true`.
- The docs only show `query_status:"ok"`. Community clients report `no_result` with `data` as a *string*, and `illegal_search_term`; both are undocumented. Treat anything other than `ok` as no data.

```json
{"query_status":"ok","data":[{"id":"41","ioc":"139.180.203.104:443","threat_type":"botnet_cc","threat_type_desc":"…","ioc_type":"ip:port","malware":"win.cobalt_strike","malware_printable":"Cobalt Strike","malware_alias":"Agentemis,BEACON","malware_malpedia":"https://malpedia…","confidence_level":75,"first_seen":"2021-03-14 10:00:00 UTC","last_seen":null,"reference":null,"reporter":"abuse_ch","tags":["CobaltStrike"],"malware_samples":[]}]}
```

**Test key**
- `get_iocs` takes `days` from 1 to 7 (default 3). Even `days:1` returns a large payload of every IOC from the last day.
- A cheaper test is `{"query":"types"}` (documented) or a `search_ioc` with `exact_match:true`. A 200 means the key is valid; 403 `unknown_auth_key` means it isn't.
- For URLhaus, POST `host=example.com`: you get `no_results` or `ok`, versus 401/403 for a bad key.

**Rate limits:** the docs only say "fair use".

**CORS:** [live] neither host sends `Access-Control-Allow-Origin`, so host permissions are required. ThreatFox sends `Cross-Origin-Resource-Policy: same-site`, which should only affect no-cors embeds (medium confidence).

**Don't mix up the docs:** abusech-docs.spamhaus.com documents the *commercial* Spamhaus API (`api.spamhaus.com`, JWT login, `/urlhaus/v1/hosts/{host}`, and key-in-URL-path `v2/<api-key>`). It is not the community API. Avoid the key-in-URL option, because its own changelog says the key ends up in logs.

---

## 12. Shodan

**InternetDB:** `GET https://internetdb.shodan.io/{ip}`, no key.
- Fields: `ip` (string), `ports` (int[]), `hostnames`, `cpes`, `tags`, `vulns`.
- It is "free for non-commercial use", data is refreshed weekly, and the rate limit isn't documented.
- **IPv6 works.** [live] `/2001:4860:4860::8888` returns 200 with raw colons.
- [live] An unknown IP *and* malformed input both return **404** `{"detail":"No information available"}`. The OpenAPI spec lists 422 for validation errors.
- [live] `Access-Control-Allow-Origin: *`.
- **Gotcha:** [live] both 200 and 404 responses carry `Cache-Control: public, max-age=432000` (5 days). Use `cache:'no-store'` if you need fresh data.

```json
{"cpes":[],"hostnames":["dns.google"],"ip":"8.8.8.8","ports":[53,443],"tags":["pqc"],"vulns":[]}
```

**Host API:** `GET https://api.shodan.io/shodan/host/{ip}?key=` with optional `history` and `minify`.
- **Use `minify=true`**, because `data[]` banners are very large.
- The key goes only in the query string. There is no header option.
- It requires a **Membership**; help.shodan.io says "at least a Shodan Membership". Free keys likely get 403 "Access denied" (low–medium confidence).
- Host lookups don't use query credits.
- Rate limit is **1 request/second**. Since 2025-11-10, only the requests over that limit get 429; the key is no longer blocked.
- The docs don't mention IPv6 host lookups. I couldn't verify them without a key.
- Not found: [live] **404** `{"error": "No information available for that IP."}`.
- Bad key: [live] **401 with an HTML body**, not JSON. The docs' error example is `{"error":"Invalid IP"}`.
- **Critical gotcha:** [live] host responses are cached by Cloudflare (`cf-cache-status: HIT`). A bogus key got a **200** with full data for 1.1.1.1. So the host endpoint can't validate a key, and a 200 doesn't prove the key works.
- **Test key:** `GET /api-info?key=`. [live] It isn't cached and returns 401 for a bad key. The response is `{plan, query_credits, scan_credits, monitored_ips, unlocked, unlocked_left, https, telnet, usage_limits}`.
- `Access-Control-Allow-Origin: *`.

```json
{"ip":134744072,"ip_str":"8.8.8.8","org":"Google","isp":"Google LLC","asn":"AS15169","os":null,"ports":[53,443],"hostnames":["dns.google"],"domains":["dns.google"],"country_code":"US","last_update":"2026-11-25T07:26:00.000000","tags":["pqc"],"data":[{"port":53,"transport":"udp","timestamp":"…"}]}
```
`ip` is an integer, `ip_str` is a string, and `last_update` has no timezone (it is UTC).

---

## Where the spec differs from the docs
1. VT `last_analysis_stats` also includes `timeout`. Resolutions paginate with `cursor` / `links.next`. Test the key with `/users/{key}/overall_quotas` (no quota used), not an IP lookup.
2. OTX `user/me` is fine (`users/me` is the SDK form). Anonymous `passive_dns` gets 429, and `general` payloads are huge. The IPv6 path is `/indicators/IPv6/`.
3. AbuseIPDB is correct. The docs don't document 401, and they say client-side use isn't intended.
4. abuse.ch Auth-Key is mandatory (401 with no key, 403 `unknown_auth_key` with a bad key). Set ThreatFox `exact_match:true`. Use `{"query":"types"}` rather than `get_iocs` as the test.
5. Shodan host responses are CDN-cached and served even with a bogus key, so test with `/api-info`. Host lookup needs a paid Membership, the limit is 1 req/s, and a bad key returns an HTML 401. InternetDB 404s (and 200s) are cached for 5 days.
