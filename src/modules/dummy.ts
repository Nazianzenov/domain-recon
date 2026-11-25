import type { Module } from '@/lib/types';
import { MINUTE } from '@/lib/types';

interface DomainBasics {
  labels: number;
  tld: string;
  idn: boolean;
  length: number;
}

/** Milestone-1 placeholder proving the module -> orchestrator -> cache -> UI path. No network. */
export const dummyModule: Module<DomainBasics> = {
  id: 'dummy',
  label: 'Domain basics (demo)',
  version: 1,
  accepts: ['domain'],
  ttl: 5 * MINUTE,
  async run(e) {
    const parts = e.value.split('.');
    const data: DomainBasics = {
      labels: parts.length,
      tld: parts[parts.length - 1] ?? '',
      idn: parts.some((p) => p.startsWith('xn--')),
      length: e.value.length,
    };
    return { data, summary: `${data.labels} labels · .${data.tld}${data.idn ? ' · IDN' : ''}` };
  },
  facts: (d) => [
    { label: 'Labels', value: String(d.labels) },
    { label: 'TLD', value: d.tld },
    { label: 'IDN', value: d.idn ? 'yes' : 'no', ...(d.idn ? { tone: 'warn' as const } : {}) },
  ],
};
