// What the release publishes as the corresponding source of the bundled
// Xray-core, and the module check every reader of xray's Go build information
// shares (owner decision 2026-10-14, L1: mirror the source per release).
//
// Each Desktop release carries one asset, BirdoVPN-<version>-xray-
// corresponding-source.tar.gz (scripts/build-xray-source-archive.mjs builds it,
// release.yml uploads it): the Xray-core tag archive at XRAY_VERSION and the
// module zip of every GPL, LGPL and MPL Go module the bundled binaries link, at
// the linked version. THIRD-PARTY-NOTICES.txt (scripts/generate-third-party-
// notices.mjs) names that asset as the primary source location, so the asset
// name, its URL and the member paths are defined here, once.

/** Licences whose terms require the source to be offered: GPL, LGPL, AGPL, MPL. */
export const COPYLEFT = /GPL|MPL/;

const SHA256 = /^[0-9a-f]{64}$/;

/** The GitHub repository whose releases carry the asset. */
export const RELEASE_REPO = 'BirdoVPN/Desktop-Client';

export const sourceAssetName = (appVersion) => `BirdoVPN-${appVersion}-xray-corresponding-source.tar.gz`;

export const sourceAssetUrl = (appVersion) =>
  `https://github.com/${RELEASE_REPO}/releases/download/v${appVersion}/${sourceAssetName(appVersion)}`;

/** The asset's top-level directory. */
export const sourceAssetRoot = (appVersion) => `BirdoVPN-${appVersion}-xray-corresponding-source`;

/** Where, inside the asset's top-level directory, a module's zip is. */
export const moduleZipMember = (modulePath, version) => `go-modules/${modulePath}@${version}.zip`;

/** Where, inside the asset's top-level directory, the Xray-core tag archive is. */
export const xrayTagArchiveMember = (xrayVersion) => `Xray-core-${xrayVersion}.tar.gz`;

/**
 * The mismatch gate between xray's Go build information and
 * third_party/licenses/xray-go-modules.json: every linked module must be
 * listed at exactly the linked version, with a reviewed licence and its
 * texts; a copyleft one also needs `source` (its upstream) and `zipSha256`
 * (the pin of the module zip the release mirrors).
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
    else if (COPYLEFT.test(e.license) && !SHA256.test(e.zipSha256 || '')) {
      problems.push(`${m.path}: ${e.license} needs \`zipSha256\`, the SHA-256 of ${m.path}@${m.version}.zip (the release mirrors it)`);
    }
  }
  return problems;
}
