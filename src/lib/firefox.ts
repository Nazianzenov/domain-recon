import { browser } from 'wxt/browser';

/**
 * WXT types `browser` from Chrome's API surface. These Firefox-only APIs are
 * typed here from MDN so the rest of the code stays strictly typed.
 */

export type DnsResolveFlag =
  | 'allow_name_collisions'
  | 'bypass_cache'
  | 'canonical_name'
  | 'disable_ipv4'
  | 'disable_ipv6'
  | 'disable_trr'
  | 'offline'
  | 'priority_low'
  | 'priority_medium'
  | 'speculate';

export interface DnsRecord {
  addresses: string[];
  canonicalName?: string;
  isTRR: boolean | string;
}

export interface FirefoxPermissions {
  origins?: string[];
  permissions?: string[];
  /** Firefox built-in data consent (optional data_collection_permissions). */
  data_collection?: string[];
}

export interface FirefoxApis {
  sidebarAction: {
    toggle(): Promise<void>;
    open(): Promise<void>;
    close(): Promise<void>;
    isOpen(details?: { windowId?: number }): Promise<boolean>;
  };
  dns: {
    resolve(hostname: string, flags?: DnsResolveFlag[]): Promise<DnsRecord>;
  };
  permissions: {
    contains(p: FirefoxPermissions): Promise<boolean>;
    request(p: FirefoxPermissions): Promise<boolean>;
    remove(p: FirefoxPermissions): Promise<boolean>;
    getAll(): Promise<FirefoxPermissions>;
    onAdded: { addListener(cb: (p: FirefoxPermissions) => void): void; removeListener(cb: (p: FirefoxPermissions) => void): void };
    onRemoved: { addListener(cb: (p: FirefoxPermissions) => void): void; removeListener(cb: (p: FirefoxPermissions) => void): void };
  };
}

export const ff = browser as unknown as FirefoxApis;
