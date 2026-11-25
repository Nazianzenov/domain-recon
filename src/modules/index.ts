import type { Module } from '@/lib/types';
import { abuseipdbModule } from './abuseipdb';
import { threatfoxModule, urlhausModule } from './abusech';
import { claudeModule } from './claude';
import { dnsModule } from './dns';
import { emailModule } from './email';
import { faviconModule } from './favicon';
import { m365Module } from './m365';
import { otxModule } from './otx';
import { pdnsModule } from './pdns';
import { rdapModule } from './rdap';
import { shodanModule } from './shodan';
import { sysdnsModule } from './sysdns';
import { virustotalModule } from './virustotal';

/**
 * The module registry. Adding a data source = adding one file and one line
 * here. Order is the display order within each entity group.
 */
export const MODULES: readonly Module[] = [
  // keyless, passive
  dnsModule as Module,
  sysdnsModule as Module,
  rdapModule as Module,
  pdnsModule as Module,
  m365Module as Module,
  emailModule as Module,
  // threat intel (BYOK; Shodan InternetDB works keyless)
  virustotalModule as Module,
  otxModule as Module,
  abuseipdbModule as Module,
  urlhausModule as Module,
  threatfoxModule as Module,
  shodanModule as Module,
  // active (OPSEC-gated)
  faviconModule as Module,
  claudeModule as Module,
];

export function getModule(id: string): Module | undefined {
  return MODULES.find((m) => m.id === id);
}
