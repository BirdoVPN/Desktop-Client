/**
 * L-9: Shared auto-mock for @tauri-apps/api/core
 *
 * Vitest automatically picks up __mocks__ siblings of node_modules.
 * This module provides a default `invoke` spy that returns `undefined`.
 *
 * Usage in tests:
 *   import { invoke } from '@tauri-apps/api/core';
 *   vi.mocked(invoke).mockResolvedValueOnce({ ... });
 *
 * For manual control, call `vi.mock('@tauri-apps/api/core')` in any test
 * and the mock will be used automatically.
 */
import { vi } from 'vitest';

export const invoke = vi.fn(async () => undefined);
export const convertFileSrc = vi.fn((path: string) => `asset://localhost/${path}`);
export const transformCallback = vi.fn();
