import { describe, expect, it, vi } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import { ACTIVE_HOST_PERMISSIONS, FIXED_HOST_PERMISSIONS } from '@/lib/origins';
import {
  hasActiveAccess,
  missingFixedOrigins,
  onPermissionsChanged,
  requestActiveAccess,
  requestFixedOrigins,
} from '@/lib/permissions';

type Perms = { origins?: string[] };

describe('permissions helpers', () => {
  it('lists the fixed origins that are not granted', async () => {
    const revoked = new Set(['https://api.anthropic.com/*', 'https://dns.google/*']);
    vi.spyOn(fakeBrowser.permissions, 'contains').mockImplementation((async (p: Perms) =>
      !(p.origins ?? []).some((o) => revoked.has(o))) as never);
    expect(await missingFixedOrigins()).toEqual(FIXED_HOST_PERMISSIONS.filter((o) => revoked.has(o)));
  });

  it('request helpers call permissions.request synchronously (user-gesture rule)', () => {
    const request = vi.spyOn(fakeBrowser.permissions, 'request').mockImplementation((async () => true) as never);
    // No await before the call: it must have happened by the time the helper returns.
    void requestActiveAccess();
    expect(request).toHaveBeenCalledTimes(1);
    expect(request).toHaveBeenLastCalledWith({ origins: [...ACTIVE_HOST_PERMISSIONS] });
    void requestFixedOrigins(['https://dns.google/*']);
    expect(request).toHaveBeenCalledTimes(2);
    expect(request).toHaveBeenLastCalledWith({ origins: ['https://dns.google/*'] });
  });

  it('checks the all-sites grant used by active checks', async () => {
    const contains = vi.spyOn(fakeBrowser.permissions, 'contains').mockImplementation((async () => false) as never);
    expect(await hasActiveAccess()).toBe(false);
    expect(contains).toHaveBeenCalledWith({ origins: ['*://*/*'] });
  });

  it('subscribes to both added and removed, and unsubscribes', () => {
    const add = { added: vi.fn(), removed: vi.fn() };
    const rem = { added: vi.fn(), removed: vi.fn() };
    vi.spyOn(fakeBrowser.permissions.onAdded, 'addListener').mockImplementation(add.added as never);
    vi.spyOn(fakeBrowser.permissions.onRemoved, 'addListener').mockImplementation(add.removed as never);
    vi.spyOn(fakeBrowser.permissions.onAdded, 'removeListener').mockImplementation(rem.added as never);
    vi.spyOn(fakeBrowser.permissions.onRemoved, 'removeListener').mockImplementation(rem.removed as never);
    const cb = () => undefined;
    const off = onPermissionsChanged(cb);
    expect(add.added).toHaveBeenCalledWith(cb);
    expect(add.removed).toHaveBeenCalledWith(cb);
    off();
    expect(rem.added).toHaveBeenCalledWith(cb);
    expect(rem.removed).toHaveBeenCalledWith(cb);
  });
});
