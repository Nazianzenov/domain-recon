// Fixed API origins the extension talks to. These are the only entries in
// `host_permissions`, and every one is used by a module (tests/origins.test.ts
// checks both directions). The only other hosts a passive module calls are TLD
// registry RDAP servers from the IANA bootstrap: those are fetched without a
// host permission and rely on CORS (RFC 7480 asks registries to send
// Access-Control-Allow-Origin). A registry without CORS only answers once the
// user has granted ACTIVE_HOST_PERMISSIONS: the rdap.org fallback is a 302 to
// that same registry.
// The investigated site itself is only contacted by active modules, through
// that optional all-URLs grant.
//
// Shared by wxt.config.ts (manifest generation) and the sidebar's
// permission check, so the two can never drift apart.
export const FIXED_HOST_PERMISSIONS = [
  // DNS-over-HTTPS
  'https://cloudflare-dns.com/*',
  'https://dns.google/*',
  // RDAP bootstrap + fallback
  'https://data.iana.org/*',
  'https://rdap.org/*',
  // Passive DNS
  'https://api.mnemonic.no/*',
  // Microsoft tenant discovery
  'https://login.microsoftonline.com/*',
  // Threat intel
  'https://www.virustotal.com/*',
  'https://otx.alienvault.com/*',
  'https://api.abuseipdb.com/*',
  'https://urlhaus-api.abuse.ch/*',
  'https://threatfox-api.abuse.ch/*',
  'https://internetdb.shodan.io/*',
  'https://api.shodan.io/*',
  // AI brand identification
  'https://api.anthropic.com/*',
] as const;

/** Requested only when the user runs active checks. */
export const ACTIVE_HOST_PERMISSIONS = ['*://*/*'] as const;
