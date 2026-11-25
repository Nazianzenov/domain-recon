import { ANTHROPIC_VERSION } from '@/lib/claude';
import { FetchError } from '@/lib/http';
import { registerKeyTester, type KeyTester } from '@/lib/keytest';
import { abuseipdbKeyTest } from './abuseipdb';
import { abusechKeyTest } from './abusech';
import { otxKeyTest } from './otx';
import { shodanKeyTest } from './shodan';
import { virustotalKeyTest } from './virustotal';

/**
 * Settings-page "Test" buttons. Each makes one cheap authenticated request.
 * Imported for its side effects by the options page.
 */

/** GET /v1/models?limit=1 costs no tokens. */
export const anthropicKeyTest: KeyTester = async (key, http) => {
  try {
    const res = await http.fetchJson<{ data?: Array<{ id?: unknown }> }>('https://api.anthropic.com/v1/models?limit=1', {
      headers: {
        'x-api-key': key,
        'anthropic-version': ANTHROPIC_VERSION,
        'anthropic-dangerous-direct-browser-access': 'true',
      },
    });
    const first = res.data?.data?.[0]?.id;
    return `Key accepted${typeof first === 'string' ? ` (models available, e.g. ${first})` : ''}.`;
  } catch (err) {
    if (err instanceof FetchError && (err.status === 401 || err.status === 403)) throw new Error('Anthropic rejected this key.');
    throw err;
  }
};

/**
 * Public (keyless) Mnemonic PDNS caps `limit` at 1000 and answers 412 above
 * it, so asking for 1001 proves the key is honoured without real cost.
 */
export const mnemonicKeyTest: KeyTester = async (key, http) => {
  try {
    await http.fetchJson('https://api.mnemonic.no/pdns/v3/example.com?limit=1001', { headers: { 'Argus-API-Key': key } });
    return 'Key accepted (authenticated limits active).';
  } catch (err) {
    if (err instanceof FetchError && err.status === 412) throw new Error('Key not recognised: the request was treated as public (unauthenticated).');
    if (err instanceof FetchError && (err.status === 401 || err.status === 403)) throw new Error('Mnemonic rejected this key.');
    throw err;
  }
};

registerKeyTester('anthropic', anthropicKeyTest);
registerKeyTester('mnemonic', mnemonicKeyTest);
registerKeyTester('virustotal', virustotalKeyTest);
registerKeyTester('otx', otxKeyTest);
registerKeyTester('abuseipdb', abuseipdbKeyTest);
registerKeyTester('abusech', abusechKeyTest);
registerKeyTester('shodan', shodanKeyTest);
