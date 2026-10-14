// What each release publishes as the corresponding source of the third-party
// programs it bundles, and the module check every reader of xray's Go build
// information shares (owner decisions 2026-10-14, L1: mirror the source per
// release; L2: the AppImage's own components).
//
// Each Desktop release carries one asset, BirdoVPN-<version>-corresponding-
// source.tar.gz (scripts/build-corresponding-source.mjs builds it, release.yml
// uploads it). Under its top-level directory:
//   xray/Xray-core-<XRAY_VERSION>.tar      the Xray-core source at the pinned
//                                          commit (`git archive`)
//   xray/go-modules/<module>@<version>.zip every Go module the four bundled
//                                          xray binaries link, at that version
//   xray/go/go<version>.src.tar.gz         the Go toolchain that built them
//                                          (standard library and runtime)
//   appimage-runtime/...                   the AppImage runtime's source, and
//                                          libfuse's and squashfuse's
//   README.txt
// THIRD-PARTY-NOTICES.txt (scripts/generate-third-party-notices.mjs and
// scripts/generate-appimage-notices.mjs) names that asset as the primary
// source location, so its name, URL and member paths are defined here, once.

/** Licences whose terms require the source to be offered: GPL, LGPL, AGPL, MPL. */
export const COPYLEFT = /GPL|MPL/;

const SHA256 = /^[0-9a-f]{64}$/;

/** The GitHub repository whose releases carry the asset. */
export const RELEASE_REPO = 'BirdoVPN/Desktop-Client';

export const sourceAssetName = (appVersion) => `BirdoVPN-${appVersion}-corresponding-source.tar.gz`;

export const sourceAssetUrl = (appVersion) =>
  `https://github.com/${RELEASE_REPO}/releases/download/v${appVersion}/${sourceAssetName(appVersion)}`;

/** The asset's top-level directory. */
export const sourceAssetRoot = (appVersion) => `BirdoVPN-${appVersion}-corresponding-source`;

/** Where, inside the asset's top-level directory, a Go module's zip is. */
export const moduleZipMember = (modulePath, version) => `xray/go-modules/${modulePath}@${version}.zip`;

/** Where, inside the asset's top-level directory, the Xray-core source is. */
export const xrayTagArchiveMember = (xrayVersion) => `xray/Xray-core-${xrayVersion}.tar`;

/** Where, inside the asset's top-level directory, the Go toolchain's official source archive is. */
export const goSourceMember = (srcArchive) => `xray/go/${srcArchive}`;

/** Where, inside the asset's top-level directory, the AppImage runtime's sources are. */
export const runtimeMember = (file) => `appimage-runtime/${file}`;

/** The type2-runtime source archive's file name. */
export const runtimeSourceFile = (commit) => `type2-runtime-${commit}.tar`;

/**
 * The mismatch gate between xray's Go build information and
 * third_party/licenses/xray-go-modules.json: every linked module must be
 * listed at exactly the linked version, with a reviewed licence, its texts
 * and `zipSha256` (the pin of the module zip the release mirrors); a
 * copyleft one also needs `source` (its upstream).
 * @returns {string[]} one line per problem; empty when the table matches.
 */
export function xrayModuleProblems(modules, table) {
  const problems = [];
  for (const m of modules) {
    const e = (table.modules || {})[m.path];
    if (!e) problems.push(`${m.path} ${m.version} is not listed`);
    else if (!e.license || e.license === 'UNREVIEWED') problems.push(`${m.path}: licence not reviewed`);
    else if (e.version !== m.version) problems.push(`${m.path}: the binary links ${m.version}, the vendored licence is ${e.version || 'none'}`);
    else if (!Array.isArray(e.texts) || e.texts.length === 0) problems.push(`${m.path}: no licence texts`);
    else if (COPYLEFT.test(e.license) && !e.source) problems.push(`${m.path}: ${e.license} needs a \`source\``);
    else if (!SHA256.test(e.zipSha256 || '')) {
      problems.push(`${m.path}: needs \`zipSha256\`, the SHA-256 of ${m.path}@${m.version}.zip (every release mirrors it)`);
    }
  }
  return problems;
}
