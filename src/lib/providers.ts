import type { ProviderKey } from './types';

/** Human names for provider keys (hints, settings). Dependency-free so the orchestrator can use it. */
export const PROVIDER_LABELS: Readonly<Record<ProviderKey, string>> = {
  virustotal: 'VirusTotal',
  otx: 'AlienVault OTX',
  abuseipdb: 'AbuseIPDB',
  abusech: 'abuse.ch Auth-Key',
  shodan: 'Shodan',
  mnemonic: 'Mnemonic Argus',
  anthropic: 'Anthropic',
};

/** What each provider calls its credential, for "Add your … in settings" hints. */
export const PROVIDER_KEY_NAMES: Readonly<Record<ProviderKey, string>> = {
  virustotal: 'VirusTotal API key',
  otx: 'OTX API key',
  abuseipdb: 'AbuseIPDB API key',
  abusech: 'abuse.ch Auth-Key',
  shodan: 'Shodan API key',
  mnemonic: 'Mnemonic Argus API key',
  anthropic: 'Anthropic API key',
};

/** Request headers that carry API secrets: never resend them to a redirect target. */
export const SECRET_HEADERS = new Set(['x-apikey', 'x-api-key', 'key', 'auth-key', 'argus-api-key', 'x-otx-api-key', 'authorization']);
