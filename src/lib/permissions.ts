import { ff } from './firefox';
import { ACTIVE_HOST_PERMISSIONS, FIXED_HOST_PERMISSIONS } from './origins';

/** Fixed API origins the user has revoked (Firefox MV3 host permissions are user-controllable). */
export async function missingFixedOrigins(): Promise<string[]> {
  const results = await Promise.all(
    FIXED_HOST_PERMISSIONS.map(async (o): Promise<string | null> =>
      (await ff.permissions.contains({ origins: [o] })) ? null : o,
    ),
  );
  return results.filter((o): o is string => o !== null);
}

/**
 * MUST be called synchronously from a click handler (no await before it):
 * Firefox only shows the prompt while handling a user gesture.
 */
export function requestFixedOrigins(origins: string[] = [...FIXED_HOST_PERMISSIONS]): Promise<boolean> {
  return ff.permissions.request({ origins });
}

export function hasActiveAccess(): Promise<boolean> {
  return ff.permissions.contains({ origins: [...ACTIVE_HOST_PERMISSIONS] });
}

/** Same user-gesture rule as requestFixedOrigins. */
export function requestActiveAccess(): Promise<boolean> {
  return ff.permissions.request({ origins: [...ACTIVE_HOST_PERMISSIONS] });
}

export function onPermissionsChanged(cb: () => void): () => void {
  ff.permissions.onAdded.addListener(cb);
  ff.permissions.onRemoved.addListener(cb);
  return () => {
    ff.permissions.onAdded.removeListener(cb);
    ff.permissions.onRemoved.removeListener(cb);
  };
}
