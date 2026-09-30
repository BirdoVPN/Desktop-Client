/**
 * `invoke` with the v2 error contract applied (W2-006, W2-012).
 *
 * Rejects with an `IpcError`, whatever shape Rust rejected with, so no caller
 * ever handles a raw string. And a `session_expired` from ANY command ends the
 * session here, once: before this, every authenticated fetch swallowed its
 * error, so a revoked or expired session left the user in a signed-in shell
 * with an empty server list and "Free plan".
 */
import { invoke } from '@tauri-apps/api/core';
import { toIpcError } from '@/lib/ipc';
import { endSession } from '@/session/session';

export async function command<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await (args === undefined ? invoke<T>(cmd) : invoke<T>(cmd, args));
  } catch (e) {
    const err = toIpcError(e);
    if (err.code === 'session_expired') endSession('expired');
    throw err;
  }
}
