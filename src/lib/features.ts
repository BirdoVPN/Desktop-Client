/**
 * Client-side feature flags: compile-time constants, one place.
 *
 * `anonNumberRotation` (MR-1707, birdo-web #850): the two-phase "replace my
 * account number" screen on Profile. OFF until the server's
 * `ANON_NUMBER_ROTATION` switch is on and the client floor has been raised
 * (rollout order in birdo-web #850). With it off the Profile screen has no
 * entry point and nothing here is reachable; the server answers 403
 * `anon_number_rotation_disabled` to both calls anyway.
 */
export const FEATURES = {
  anonNumberRotation: false,
} as const;

/** A function, not the constant, so a test can swap the answer by mocking this module. */
export function anonNumberRotationEnabled(): boolean {
  return FEATURES.anonNumberRotation;
}
