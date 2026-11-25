# DoH JSON and RDAP: docs vs. live behaviour, checked 2026-11-25

Sources are the official docs plus live `curl` probes run today. Confidence is **H** (doc and live agree), **L** (live only, undocumented) or **D** (the doc is silent).

## 1. Cloudflare JSON (developers.cloudflare.com/1.1.1.1/.../dns-json)

- **Request.** `GET https://cloudflare-dns.com/dns-query?name=<n>&type=<t>` with the header `accept: application/dns-json`. The JSON format is GET only. (H)
- **Params.** `name` is required. `type` is optional, defaults to `A`, and takes a number or a text name. `do` and `cd` take empty, `0`, `false`, `1` or `true`. There is no `ct` parameter. (H)
- **The Accept header is mandatory.** Without it you get **HTTP 400 with an empty body**. Passing `ct=application/dns-json` instead also returns 400. (L)
- **Type names.** `type=CAA`, `type=caa` and `type=257` all work, and CAA is supported. A bad type returns 400 `{"error":"Invalid query type \`FOO\`."}`. (L)
- **Names.**
  - U-labels are rejected: `münchen.de` returns 400 "Invalid query name". You must send the A-label (`xn--mnchen-3ya.de`). (L)
  - **Gotcha:** `Question[].name` and `Answer[].name` echo your input without a trailing dot. Google adds one. Target names inside `data` always end in a dot. Normalise by lowercasing and stripping the trailing dot. (L)
- **Response fields** (doc). `Status`, `TC`, `RD`, `RA`, `AD`, `CD`, `Question[{name,type}]`, `Answer|Authority|Additional[{name,type,TTL,data}]`, `Comment`. Unknown types return `data` as hex. Errors are `{"error":"..."}` with 400.
  - **`Comment` is an array of strings**, for example `["EDE(9): DNSKEY Missing ..."]`. (H doc "list of EDE", L shape)
  - Other HTTP codes: 413, 415, 504. (H)
- **CORS.** The docs say nothing. Live, every response, including 400s, carries `Access-Control-Allow-Origin: *`. Content-Type is `application/dns-json`. (D/L)
- **Rate limits.** Not documented. No auth is needed. (D)
- **Caveat from the docs.** There is no RFC for the JSON format, so it "may differ between providers" and may change. Cloudflare says it follows Google's schema.

**Type codes:** A=1, NS=2, CNAME=5, SOA=6, MX=15, TXT=16, AAAA=28, CAA=257 (RRSIG=46 appears when `do=1`).
**rcode (IANA):** 0 NOERROR, 1 FORMERR, 2 SERVFAIL, 3 NXDOMAIN, 4 NOTIMP, 5 REFUSED.

**`data` formats** (live, identical on Cloudflare and Google except for TXT):
- MX: `"10 smtp.google.com."`, meaning preference, a space, then the target with a trailing dot.
- SOA: `"ns1.google.com. dns-admin.google.com. 1028908002 900 900 1800 60"`, meaning mname, rname, serial, refresh, retry, expire, minimum.
- CAA: `"0 issue \"pki.goog\""`, meaning flags, tag, then a quoted value. Tags include `issue`, `issuewild` and `iodef`.
- NS / CNAME: the target FQDN with a trailing dot.

**TXT on Cloudflare** (L). Each character-string is wrapped in literal quotes, and multi-string records are separated by `" "`:
`"data":"\"k=rsa; t=s; p=MIIB...\" \"NHjpVw5...AQAB\""`
Split points can fall mid-token. GitHub's SPF is split as `include:servers." "mcsv.net`. So strip the quotes and **join the chunks with no separator** (RFC 7208 §3.3). Also handle `\"` and `\DDD` escapes.

```json
{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,
 "Question":[{"name":"www.github.com","type":1}],
 "Answer":[{"name":"www.github.com","type":5,"TTL":3570,"data":"github.com."},
           {"name":"github.com","type":1,"TTL":30,"data":"20.208.89.80"}]}
{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,
 "Question":[{"name":"_dmarc.google.com","type":16}],
 "Answer":[{"name":"_dmarc.google.com","type":16,"TTL":168,"data":"\"v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com\""}]}
{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,
 "Question":[{"name":"google.com","type":15}],
 "Answer":[{"name":"google.com","type":15,"TTL":11,"data":"10 smtp.google.com."}]}
```

## 2. Google JSON (developers.google.com/speed/public-dns/docs/doh/json)

- **Endpoint.** `https://dns.google/resolve?` (doc). **No Accept header is needed**, and sending `application/dns-json` is harmless (L).
- **Params** (doc). If a parameter is repeated, only the first value is used.
  - `name` is required: 1–253 chars, labels 1–63, and "non-ASCII names should be punycoded".
  - `type` takes 1–65535 or a case-insensitive mnemonic.
  - `cd` and `do` are booleans. `do=1` adds RRSIG/NSEC records.
  - `ct`: `application/dns-message` returns binary, `application/x-javascript` returns JSON, and any other value returns JSON.
  - `edns_client_subnet`, e.g. `1.2.3.4/24`. `0.0.0.0/0` sends no client subnet; by default Google sends an approximate one.
  - `random_padding` is ignored.
- **Response.** Same fields as Cloudflare. Differences:
  - **`Question` and `Answer` names always end with a dot** (H).
  - There is a top-level `edns_client_subnet` field.
  - **`Comment` is a string**, e.g. `"Response from 216.239.38.10."` or a DNSSEC failure text (doc and live).
  - Live, it also returns `extended_dns_errors:[{info_code,extra_text}]` (L, not in the JSON doc).
- **TXT: the doc differs from live.** The doc's examples show "quoted string" and "multiple quoted strings". **Live, Google returns TXT unquoted, with the chunks already concatenated**: `"data":"v=DMARC1; p=quarantine; ..."`, and the 2-chunk SendGrid DKIM comes back as one string with no quotes. The parser must handle both: if the value starts with `"`, parse it as quoted chunks, otherwise use it raw. (L, high confidence)
- **CAA/MX/SOA** use the same format as Cloudflare (L).
- **HTTP errors** (doc /docs/doh): 400, 413, 414, 415, **429** (honour `Retry-After`), 500, 501, 502.
  - **Gotcha:** a 400 for a bad name returns **an HTML body** (`text/html`), so `res.json()` will throw. Check `res.ok` and the content-type first. (L)
- **CORS** is undocumented. Live, `Access-Control-Allow-Origin: *` and `Content-Type: application/json; charset=UTF-8`. (D/L)
- **Rate limit.** The ISP page says throttling applies above about 1500 QPS per IPv4 address or IPv6 /64, with short bursts allowed. (H)

## 3. CNAME behaviour (live, both resolvers) (L/H)

- **`type=A` on a CNAME.** `Answer` holds the CNAME chain records (type 5) in order, then the A records (type 1) **under the final target name**, not the queried name.
  - `autodiscover.microsoft.com` returned 4 CNAMEs, no A record, and an SOA in `Authority`.
  - **IP pivots must filter by `type===1` or `28`**, not by name or position.
- **Dangling CNAME.** When the chain ends at a name that does not exist, `Status` is **3** and `Answer` still contains the CNAME. Example: `selector1._domainkey.microsoft.com`. Don't treat NXDOMAIN as "no records".
- **`type=CNAME` where no CNAME exists.** You get `Status 0` (NODATA), no `Answer`, and an SOA in `Authority`. Check for a missing `Answer`, not only `Status`.
- **NXDOMAIN.** `Status 3` with the parent zone's SOA in `Authority`.
- **The spec's DKIM check is fragile.** `s1._domainkey.github.com` is a CNAME to SendGrid, and a TXT query returns CNAME plus TXT. A spec that only does CNAME lookups at selectors misses selectors published directly as TXT.

## 4. IANA bootstrap `https://data.iana.org/rdap/dns.json` (RFC 9224 + live)

```json
{"description":"RDAP bootstrap file for Domain Name System registrations",
 "publication":"2026-11-20T23:00:03Z","version":"1.0",
 "services":[
  [["com"],["https://rdap.verisign.com/com/v1/"]],
  [["charity","foundation","org","xn--c1avg","xn--nqv7f"],["https://rdap.publicinterestregistry.org/rdap/"]],
  [["kg"],["http://rdap.cctld.kg/"]]]}
```

**What RFC 9224 says:**
- Base URLs **MUST end with `/`**. Build the query as `base + "domain/" + name`.
- Matching is **per label, right to left, longest match**. Entries may in principle hold multiple labels (e.g. `example.com`).
- IDN entries are **A-labels only** (e.g. `xn--zckzah`).
- Prefer https when several URLs are listed.
- Clients SHOULD cache the file and SHOULD honour HTTP `Expires`.
- If nothing matches, show an error.

**What the live file shows:**
- 592 services and 1203 labels, all lowercase, all single-label TLDs. No service lists more than one URL.
- Every URL ends with `/`.
- Two URLs are `http://` (kg, mg). Both also answer over https, which matters because the **Firefox MV3 default CSP `script-src 'self'; upgrade-insecure-requests;`** auto-upgrades http requests (MDN).
- **Headers:** `Access-Control-Allow-Origin: *` and `Cache-Control: max-age=86400`, so the spec's 24h cache matches.
- **Big gaps:** `de, io, co, eu, jp, cn, ru, me, us` are **absent**.

**Implementation notes:**
- Lowercase the name and convert it to an A-label before matching. In JS, `new URL('http://'+name).hostname` gives the punycode form.
- Iterating labels so a future multi-label entry matches costs nothing.

## 5. rdap.org (about.rdap.org + live)

- **It redirects, it does not proxy.** It answers **302** with `Location: https://rdap.verisign.com/com/v1/domain/google.com` and `access-control-allow-origin: *`. `fetch` follows the redirect, and `res.url` gives the final server.
- **Rate limit:** 10 requests per 10 s through Cloudflare, then 429. A 403 means the client is blocked for abuse. A 400 means a bad request.
- **It only knows IANA-registered servers.** `rdap.org/domain/github.io` and `/denic.de` return **404** with `{"rdapConformance":["rdap_level_0"],"lang":"en","errorCode":404,"title":"No RDAP service is available for this resource"}`.
- **Spec gap:** the fallback adds almost nothing for TLDs missing from the IANA file. Treat "no RDAP for this TLD" as a normal UI state.

## 6. RDAP domain response (RFC 9083 / 7480 / IANA rdap-json-values + live Verisign)

**Transport (RFC 7480):**
- Clients should send `Accept: application/rdap+json`. The spec omits this; add `accept: application/rdap+json, application/json`.
- The response Content-Type is `application/rdap+json`, sometimes with `;charset=UTF-8`.
- 200 is a hit and **404 is an empty result** (not registered, or not served). 400 is a bad query. 429 means honour `Retry-After`. Follow 301/302/303/307 unchanged.
- CORS (§5.6): "RECOMMENDED … Access-Control-Allow-Origin"; `*` suits public data; Allow-Credentials is NOT RECOMMENDED.
- Live, `ACAO: *` was present on Verisign, MarkMonitor, Nominet, Google Registry, Identity Digital, PIR and AFNIC.
- The Verisign 404 had an **empty body**, so don't assume an error JSON (RFC 9083 §6 defines `errorCode`, `title` and `description` as optional extras).

**Event actions (IANA):** registration, reregistration, last changed, expiration, deletion, reinstantiation, transfer, locked, unlocked, last update of RDAP database, registrar expiration, enum validation expiration.
- Don't label "last update of RDAP database" as "last changed".
- Any event can be missing on ccTLDs.

**Status values** are RFC 9083 values plus RFC 8056 EPP-mapped values, as lowercase space-separated strings, e.g. "client transfer prohibited", "server hold", "redemption period", "pending delete".

**Roles:** registrant, technical, administrative, abuse, billing, registrar, reseller, sponsor, proxy, notifications, noc.

**jCard:**
- Format is `["vcard",[[name, params, valueType, value],...]]`. `fn` is required but **may be `""`** (it is empty in Verisign's abuse entity).
- `email` is text. `tel` may be valueType `uri` with value `tel:+1.2086851750`; strip `tel:`.
- `adr` is an array value.
- Find properties by name, not by index.

**Where things live:**
- The abuse contact is **nested in `registrar.entities[]` with `roles:["abuse"]`**. Also check top-level `entities` for `abuse`.
- `ldhName` comes **UPPERCASE** from Verisign, for the domain and the nameservers; RFC 9083 sets no case rule, so lowercase it.
- `unicodeName` appears only for IDNs.
- `.com` and `.net` are thin: no registrant data. A `links[]` entry with `rel:"related"` points to the registrar RDAP, e.g. `https://rdap.markmonitor.com/rdap/domain/GOOGLE.COM`. This is optional follow-up, and its CORS header was `*` live.

**JSContact:** `draft-ietf-regext-rdap-jscontact` is at -27 (Oct 2026) and is **not yet an RFC**. It would add `jscontact_card` as an eventual jCard replacement. Tolerate a missing `vcardArray`. (Medium confidence.)

**Live Verisign response, trimmed:**
```json
{"objectClassName":"domain","handle":"2138514_DOMAIN_COM-VRSN","ldhName":"GOOGLE.COM",
 "links":[{"rel":"related","href":"https://rdap.markmonitor.com/rdap/domain/GOOGLE.COM","type":"application/rdap+json"}],
 "status":["client delete prohibited","client transfer prohibited","server update prohibited"],
 "entities":[{"objectClassName":"entity","handle":"292","roles":["registrar"],
   "publicIds":[{"type":"IANA Registrar ID","identifier":"292"}],
   "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","MarkMonitor Inc."]]],
   "entities":[{"objectClassName":"entity","roles":["abuse"],
     "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text",""],
       ["tel",{"type":"voice"},"uri","tel:+1.2086851750"],
       ["email",{},"text","abusecomplaints@markmonitor.com"]]]}]}],
 "events":[{"eventAction":"registration","eventDate":"1997-09-15T04:00:00Z"},
   {"eventAction":"expiration","eventDate":"2028-09-14T04:00:00Z"},
   {"eventAction":"last changed","eventDate":"2019-09-09T15:39:04Z"},
   {"eventAction":"last update of RDAP database","eventDate":"2026-11-25T11:06:47Z"}],
 "secureDNS":{"delegationSigned":false},
 "nameservers":[{"objectClassName":"nameserver","ldhName":"NS1.GOOGLE.COM"}],
 "rdapConformance":["rdap_level_0","icann_rdap_technical_implementation_guide_1","icann_rdap_response_profile_1"],
 "notices":[{"title":"Terms of Service","description":["..."]}]}
```

## Where the spec differs from the docs or live behaviour
1. Cloudflare: the `accept` header is mandatory. Without it the request fails with 400 and an empty body. Keep it.
2. TXT quoting differs by provider: Cloudflare quotes and splits, Google returns it unquoted and concatenated, which contradicts Google's own docs. The parser needs both paths, and chunks must be joined with no separator.
3. `Comment` is an array on Cloudflare and a string on Google.
4. Cloudflare omits the trailing dot on owner names; Google includes it. Normalise.
5. CNAME chains: filter `Answer` by type. A Status 3 can still carry CNAME answers. NODATA means Status 0 with no `Answer`.
6. Google 400s are HTML, so guard `res.json()`.
7. Both resolvers need A-labels; convert IDNs before querying.
8. RDAP: add `Accept: application/rdap+json`. Lowercase `ldhName`. The abuse contact is nested under the registrar. `fn` may be empty. A 404 body may be empty.
9. The rdap.org fallback does not cover TLDs missing from the IANA file (de, io, co, eu…): it returns 404. Its limit is 10 requests per 10 s.
10. Domain age: use the `registration` event only. It may be absent. Ignore "last update of RDAP database".
11. CORS: every endpoint tested sends `ACAO: *`, and the extension's host permissions bypass CORS anyway. Neither DoH provider documents CORS.

**Sources:**
- [Cloudflare DNS JSON](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/)
- [Cloudflare DoH requests](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/)
- [Google JSON API](https://developers.google.com/speed/public-dns/docs/doh/json)
- [Google DoH](https://developers.google.com/speed/public-dns/docs/doh)
- [Google ISP rate limits](https://developers.google.com/speed/public-dns/docs/isp)
- [IANA dns.json](https://data.iana.org/rdap/dns.json)
- [IANA RDAP JSON values](https://www.iana.org/assignments/rdap-json-values/rdap-json-values.xhtml)
- [RFC 9224](https://www.rfc-editor.org/rfc/rfc9224.html)
- [RFC 7480](https://www.rfc-editor.org/rfc/rfc7480.html)
- [RFC 9083](https://www.rfc-editor.org/rfc/rfc9083.html)
- [about.rdap.org](https://about.rdap.org/)
- [MDN extension CSP](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Content_Security_Policy)
- [RDAP JSContact draft-27](https://datatracker.ietf.org/doc/html/draft-ietf-regext-rdap-jscontact-27)