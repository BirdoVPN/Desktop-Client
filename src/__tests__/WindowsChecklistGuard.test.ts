/**
 * Source guards for the Windows device checklist and the licence notice, in
 * the style of the repo's other guard tests: they read the documents and the
 * app's source, not a render.
 *
 *  - JOURNAL PATH (MR-2097, AUD-DESK-03): since #287 (MR-1721) the route/DNS
 *    journal lives in the admin-only %ProgramData%\BirdoVPN
 *    (vpn/mod.rs `dns_journal::path` → utils/protected_dir.rs). A checklist
 *    that still looks in %APPDATA% passes B4 and B9 without testing anything,
 *    and plants B9's record where the build never reads it.
 *  - B5 (MR-655, AUD-DESK-04): TCP probes to other ports cannot show that the
 *    relay permit is scoped to BirdoVPN.exe. Only the permit's own flow from
 *    another process can: UDP to the relay's WireGuard port.
 *  - W7, W9, W10, W15 (MR-671, AUD-DOC-14): the four Windows checks that had
 *    no step and no Results row. The log lines they wait for and the UI labels
 *    they name must exist in the app, and their checks must be able to fail
 *    (W9 lets the filters settle; W15 checks xray only where one runs).
 *  - LICENCE (MR-1688): the CC BY-NC notice keeps third-party code under its
 *    own licence, naming paths that exist.
 *
 * Run: npx vitest run src/__tests__/WindowsChecklistGuard.test.ts
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

function repoRoot(): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    if (existsSync(resolve(dir, 'src-tauri/Cargo.toml'))) return dir;
    dir = resolve(dir, '..');
  }
  throw new Error('repository root not found');
}

const ROOT = repoRoot();
const read = (path: string) => readFileSync(resolve(ROOT, path), 'utf8').replace(/\r/g, '');

const CHECKLIST = read('docs/WINDOWS-LEAK-VALIDATION.md');
/** The checklist with its prose unwrapped, for phrases a line break may split. */
const CHECKLIST_FLAT = CHECKLIST.replace(/\s+/g, ' ');
const DNS_DOC = read('docs/DEVICE-TEST-WINDOWS-DNS.md');
const LICENSE = read('LICENSE');
const MOD_RS = read('src-tauri/src/vpn/mod.rs');

/** The value of a Rust `const NAME: <type> = <value>;` in `src`. */
function rustConst(src: string, name: string): string {
  const match = src.match(new RegExp(`const ${name}: [^=]+= "?([^";]+)"?;`));
  if (!match) throw new Error(`const ${name} not found`);
  return match[1];
}

const JOURNAL_FILE = rustConst(MOD_RS, 'JOURNAL_FILE');
const STATE_DIR = rustConst(read('src-tauri/src/utils/protected_dir.rs'), 'DIR_NAME');
const WIREGUARD_PORT = rustConst(read('src-tauri/src/commands/vpn.rs'), 'RELAY_WIREGUARD_PORT');

/** `### <id>.` up to the next `##`/`###` heading. */
function section(doc: string, id: string): string {
  const start = doc.indexOf(`\n### ${id}. `);
  if (start < 0) return '';
  const rest = doc.slice(start + 1);
  const end = rest.slice(4).search(/\n#{2,3} /);
  return end < 0 ? rest : rest.slice(0, end + 4);
}

describe('the journal path (MR-2097, AUD-DESK-03)', () => {
  it('the app writes the Windows journal into the admin-only directory', () => {
    const pathFn = MOD_RS.slice(MOD_RS.indexOf('    fn path() -> Option<std::path::PathBuf> {'));
    const windows = pathFn.slice(0, pathFn.indexOf('#[cfg(not(windows))]'));
    expect(windows).toContain('crate::utils::protected_dir::ensure()');
    expect(windows).toContain('dir.join(JOURNAL_FILE)');
    expect(JOURNAL_FILE).toBe('dns-restore.json');
    expect(STATE_DIR).toBe('BirdoVPN');
  });

  it('the checklist reads and plants the journal at $env:ProgramData', () => {
    const jrnl = CHECKLIST.split('\n').find((line) => /^\$Jrnl\s*=/.test(line));
    expect(jrnl).toContain(`"$env:ProgramData\\${STATE_DIR}\\${JOURNAL_FILE}"`);
    // B9 part 1 plants the record through $Jrnl, where the build reads it.
    expect(section(CHECKLIST, 'B9')).toContain('[IO.File]::WriteAllText($Jrnl, $json)');
  });

  it('no paragraph sends the reader to %APPDATA% for the live journal', () => {
    const legacy = /older build|before #287|legacy/i;
    for (const [name, doc] of [
      ['WINDOWS-LEAK-VALIDATION.md', CHECKLIST],
      ['DEVICE-TEST-WINDOWS-DNS.md', DNS_DOC],
    ]) {
      const stale = doc
        .split(/\n\s*\n/)
        .filter((p) => /APPDATA/.test(p.replace(/LOCALAPPDATA/g, '')) && p.includes(JOURNAL_FILE))
        .filter((p) => !legacy.test(p));
      expect(stale, name).toEqual([]);
    }
  });

  it('DEVICE-TEST-WINDOWS-DNS S0.5 names the admin-only journal', () => {
    const s05 = DNS_DOC.slice(DNS_DOC.indexOf('## S0.5'), DNS_DOC.indexOf('## S0.6'));
    expect(s05).toContain(`%ProgramData%\\${STATE_DIR}\\${JOURNAL_FILE}`);
    expect(s05).toContain(`Get-Content "$env:ProgramData\\${STATE_DIR}\\${JOURNAL_FILE}"`);
  });
});

describe('B5: the relay permit is app-scoped (MR-655, AUD-DESK-04)', () => {
  const b5 = section(CHECKLIST, 'B5');

  it('sends UDP to the relay on the WireGuard port from another process', () => {
    expect(WIREGUARD_PORT).toBe('51820');
    expect(b5).toContain('[System.Net.Sockets.UdpClient]::new()');
    expect(b5).toContain(`$u.Send([byte[]](1..32), 32, $Relay, ${WIREGUARD_PORT})`);
  });

  it('decides on the drop audit: the block-all named on the blocked flow', () => {
    expect(b5).toContain('auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable');
    expect(b5).toMatch(/Id = 5157/);
    expect(b5).toContain(`$_.DestPort -eq '${WIREGUARD_PORT}'`);
    expect(b5).toContain('`Birdo: Block all outbound IPv4`');
  });

  it('no longer relies on TCP probes to the relay', () => {
    expect(b5).not.toMatch(/Test-NetConnection \$Relay/);
  });
});

describe('W7, W9, W10 and W15 (MR-671, AUD-DOC-14)', () => {
  it.each(['W7', 'W9', 'W10', 'W15'])('%s has steps, pass criteria, a rollback and a Results row', (id) => {
    const step = section(CHECKLIST, id);
    expect(step, id).toMatch(/```powershell/);
    expect(step, id).toMatch(/\*\*Pass/);
    expect(step, id).toMatch(/\*\*Rollback:\*\*/);
    expect(CHECKLIST).toMatch(new RegExp(`^\\| ${id} \\|`, 'm'));
  });

  it('every Part B step keeps a Results row', () => {
    for (const id of ['A1', ...Array.from({ length: 12 }, (_, i) => `B${i + 1}`)]) {
      expect(CHECKLIST, id).toMatch(new RegExp(`^\\| ${id} \\|`, 'm'));
    }
  });

  it('the log lines the steps wait for are ones the app writes', () => {
    const rust = [
      'src-tauri/src/main.rs',
      'src-tauri/src/vpn/auto_reconnect.rs',
      'src-tauri/src/vpn/xray.rs',
      'src-tauri/src/vpn/wfp.rs',
      'src-tauri/src/vpn/mod.rs',
    ]
      .map(read)
      .join('\n');
    for (const line of [
      'Tunnel declared dead',
      'Auto-reconnect successful',
      'Reconnection successful',
      'Auto-reconnect gave up',
      'Xray exited under the session',
      'Application exit requested',
      'Exit teardown timed out',
      'Exit teardown never ran to its end',
      'Kill switch: no WFP app id',
      'Moved the DNS journal to the admin-only directory',
      'Left the old DNS journal in %APPDATA% in place, unused',
      'Quit BirdoVPN',
    ]) {
      expect(CHECKLIST_FLAT, line).toContain(line);
      expect(rust, line).toContain(line);
    }
  });

  it('the filter names and UI labels the steps use exist in the app', () => {
    const policy = read('src-tauri/src/vpn/wfp_policy.rs');
    for (const name of [
      'Birdo: Permit kill-switch exception (',
      'Birdo: Permit the tunnel interface',
      "Birdo: Permit the app's own HTTPS (control plane)",
    ]) {
      expect(policy, name).toContain(name);
      expect(CHECKLIST_FLAT, name).toContain(name.replace('Birdo: ', ''));
    }
    const ui = ['src/components/Settings.tsx', 'src/screens/VpnSettings.tsx', 'src/screens/SplitTunnel.tsx']
      .map(read)
      .join('\n');
    for (const label of [
      'Privacy & Security',
      'Always-on Kill Switch',
      'VPN Settings',
      'Kill Switch Exceptions',
      'Add by path or name',
      'Stealth Mode',
    ]) {
      expect(ui, label).toContain(label);
      expect(CHECKLIST_FLAT, label).toContain(label);
    }
  });

  it('W9 lets the filters settle after a log line the app writes before changing them', () => {
    // auto_reconnect.rs logs `Reconnection successful` before it releases the
    // block, and `Auto-reconnect gave up` before the teardown: the filter and
    // web checks straight after the wait could catch the old state.
    const lines = section(CHECKLIST, 'W9').split('\n');
    for (const waited of ['Reconnection successful', 'Auto-reconnect gave up']) {
      const at = lines.findIndex((l) => l.startsWith('Birdo-WaitLog') && l.includes(`'${waited}'`));
      expect(at, waited).toBeGreaterThan(-1);
      expect(lines[at + 1], waited).toMatch(/^Start-Sleep \d+/);
    }
  });

  it('W10 says what a stealth relay routed into the tunnel means', () => {
    const w10 = section(CHECKLIST, 'W10').replace(/\s+/g, ' ');
    expect(w10).toMatch(/names `Birdo VPN`, record FAIL and file it against MR-1628/);
  });

  it('W15 checks xray only in a Stealth session, confirming it runs before each exit', () => {
    // Without Stealth Mode there is no xray, and "xray is gone" passes without
    // testing the kill-on-close job (xray.rs, W1-005).
    const parts = section(CHECKLIST, 'W15').split(/\n(?=\*\*Part \d)/);
    const xrayParts = parts.filter((p) => /Get-Process[^\n]*\bxray\b/.test(p));
    expect(xrayParts.length).toBeGreaterThan(0);
    for (const part of xrayParts) {
      expect(part).toContain('Stealth Mode');
      expect(part).toContain('N/A');
      const exits = [...part.matchAll(/\*\*(Quit BirdoVPN|End task)\*\*/g)].map((m) => m.index ?? 0);
      expect(exits.length).toBe(2);
      let from = 0;
      for (const exit of exits) {
        expect(part.slice(from, exit)).toContain('$x = Get-Process xray');
        from = exit;
      }
    }
  });
});

describe('licence carve-out for bundled third-party code (MR-1688)', () => {
  const notices = LICENSE.slice(LICENSE.indexOf('Notices:'), LICENSE.indexOf('For commercial licensing'));
  const flat = notices.replace(/\s+/g, ' ');

  it('the LICENSE notices keep third-party code under its own licence', () => {
    expect(flat).toContain('Third-party code and files in this repository are NOT covered by this licence');
    expect(flat).toContain('stay under their own licences');
    expect(flat).toContain('THIRD-PARTY-NOTICES.txt');
  });

  it('names the bundled third-party paths, which exist', () => {
    for (const path of ['src-tauri/wintun-extract/wintun/', 'third_party/licenses/', 'src/assets/fonts/']) {
      expect(flat, path).toContain(path);
      expect(existsSync(resolve(ROOT, path)), path).toBe(true);
    }
    expect(existsSync(resolve(ROOT, 'src-tauri/wintun-extract/wintun/LICENSE.txt'))).toBe(true);
    expect(read('scripts/generate-third-party-notices.mjs')).toContain('THIRD-PARTY-NOTICES.txt');
  });
});
