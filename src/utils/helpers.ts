/**
 * Convert a 2-letter ISO country code to a flag emoji.
 * Uses Unicode Regional Indicator symbols.
 * Mirrors the Android FlagUtils.kt implementation.
 */
export function countryCodeToFlag(countryCode: string): string {
  if (!countryCode || countryCode.length !== 2) return '🌐';

  const upper = countryCode.toUpperCase();
  const first = upper.codePointAt(0)! - 0x41 + 0x1f1e6;
  const second = upper.codePointAt(1)! - 0x41 + 0x1f1e6;

  return String.fromCodePoint(first) + String.fromCodePoint(second);
}

/**
 * Format bytes to a human-readable string (B, KB, MB, GB, TB).
 */
export function formatBytes(bytes: number): string {
  if (bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/**
 * Format seconds to HH:MM:SS.
 */
export function formatUptime(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return [h, m, s].map((v) => String(v).padStart(2, '0')).join(':');
}

/**
 * Validate an IPv4 address string.
 * Rejects loopback, link-local, multicast, and wildcard addresses (matching Android InputValidator).
 */
export function isValidDnsAddress(ip: string): { valid: boolean; error?: string } {
  const parts = ip.split('.');
  if (parts.length !== 4) return { valid: false, error: 'Enter a valid IPv4 address (e.g. 1.1.1.1)' };

  // Validate each octet: must be a number 0-255 with no leading zeros
  const nums: number[] = [];
  for (let i = 0; i < 4; i++) {
    const n = Number(parts[i]);
    if (isNaN(n) || n < 0 || n > 255 || String(n) !== parts[i]) {
      return { valid: false, error: 'Enter a valid IPv4 address (e.g. 1.1.1.1)' };
    }
    nums.push(n);
  }

  const [a, b] = nums;

  // Reject loopback (127.x.x.x)
  if (a === 127) return { valid: false, error: 'Loopback addresses are not allowed' };
  // Reject link-local (169.254.x.x)
  if (a === 169 && b === 254) return { valid: false, error: 'Link-local addresses are not allowed' };
  // Reject multicast (224-239.x.x.x)
  if (a >= 224 && a <= 239) return { valid: false, error: 'Multicast addresses are not allowed' };
  // Reject wildcard (0.0.0.0)
  if (nums.every((n) => n === 0)) return { valid: false, error: 'Wildcard address is not allowed' };
  // Reject broadcast (255.255.255.255)
  if (nums.every((n) => n === 255)) return { valid: false, error: 'Broadcast address is not allowed' };

  return { valid: true };
}

/**
 * Validate a WireGuard port number.
 */
export function isValidPort(port: string): boolean {
  const n = Number(port);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}

/**
 * Validate a WireGuard MTU value.
 */
export function isValidMtu(mtu: string): boolean {
  const n = Number(mtu);
  return Number.isInteger(n) && n >= 1280 && n <= 1500;
}
