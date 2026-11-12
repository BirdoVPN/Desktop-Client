/**
 * A-M50: the Linux new-version notice. Linux has no updater endpoint and no apt
 * repository, so Rust (`commands/linux_release.rs`) asks GitHub's public
 * "latest release" API and answers the newer version or nothing. Nothing is
 * installed: the notice opens the release page.
 *
 * Every failure is silence. The dismissal is remembered per version in this
 * browser profile only, so a still-newer release is announced again.
 */
import { invoke } from '@tauri-apps/api/core';
import { isLinuxPlatform } from '@/utils/helpers';

export const LINUX_UPDATE_DISMISSED_KEY = 'birdo-linux-update-dismissed';

/** The newer release's version, or null: up to date, not Linux, or the check failed. */
export async function checkLinuxRelease(): Promise<string | null> {
  if (!isLinuxPlatform()) return null;
  try {
    const version = await invoke<string | null>('check_linux_release');
    return typeof version === 'string' && version.length > 0 && version.length <= 32 ? version : null;
  } catch {
    return null;
  }
}

/** Open the release page in the system browser; a refusal is not an error here. */
export function openLinuxReleasePage(): void {
  invoke('open_linux_release_page').catch(() => {});
}

export function dismissedLinuxVersion(): string | null {
  try {
    return localStorage.getItem(LINUX_UPDATE_DISMISSED_KEY);
  } catch {
    return null;
  }
}

export function dismissLinuxVersion(version: string): void {
  try {
    localStorage.setItem(LINUX_UPDATE_DISMISSED_KEY, version);
  } catch {
    /* storage blocked: the notice returns next start, which is acceptable */
  }
}
