/**
 * Licences — pushed from Settings › About (MR-1685).
 *
 * Shows the third-party notices the package ships at
 * resources/THIRD-PARTY-NOTICES.txt: every Rust crate and npm package in this
 * build, Xray-core (with its source pointer and the GPL modules it links) and,
 * on Windows, Wintun, each with its full licence text. The file is generated
 * at build time (scripts/generate-third-party-notices.mjs) and read by the
 * `get_third_party_notices` command; a development build bundles none, and
 * the screen says so instead of showing an empty page.
 */
import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { BirdoTopBar } from '@/components/birdo';
import { useAppStore } from '@/store/app-store';
import { white } from '@/lib/birdo-theme';

export const NOTICES_MISSING_COPY =
  'The licence notices are not included in this build. Release builds include them.';

type Notices = { kind: 'loading' } | { kind: 'ready'; text: string } | { kind: 'missing' };

export function Licences() {
  const popRoute = useAppStore((s) => s.popRoute);
  const [notices, setNotices] = useState<Notices>({ kind: 'loading' });

  useEffect(() => {
    let live = true;
    invoke<string>('get_third_party_notices')
      .then((text) => {
        if (live) setNotices(text ? { kind: 'ready', text } : { kind: 'missing' });
      })
      .catch(() => {
        if (live) setNotices({ kind: 'missing' });
      });
    return () => {
      live = false;
    };
  }, []);

  return (
    <div className="flex h-full flex-col">
      <BirdoTopBar title="Licences" subtitle="Third-party software" onBack={popRoute} />
      <div className="flex-1 overflow-y-auto px-4 pb-8 pt-3">
        {notices.kind === 'loading' && (
          <p className="text-[13px]" style={{ color: white.w60 }}>
            Loading…
          </p>
        )}
        {notices.kind === 'missing' && (
          <p className="text-[13px]" style={{ color: white.w60 }}>
            {NOTICES_MISSING_COPY}
          </p>
        )}
        {notices.kind === 'ready' && (
          <pre
            className="whitespace-pre-wrap break-words font-mono text-[11px] leading-relaxed"
            style={{ color: white.w80 }}
            aria-label="Third-party software notices"
          >
            {notices.text}
          </pre>
        )}
      </div>
    </div>
  );
}
