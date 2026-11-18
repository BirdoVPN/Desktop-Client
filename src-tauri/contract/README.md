# Vendored connect contract (K5)

`vpn-protocol.schema.json` is a **verbatim copy** of birdo-web
`backend/contract/vpn-protocol.schema.json` at the commit it was taken from.
It is generated there from the code that enforces the wire contract
(`ConnectDto`'s class-validator decorators and the `multiHopConnectSchema` zod
twin) by `npm run contract:generate`, and pinned by `protocol-schema.spec.ts`,
so birdo-web CI goes red if the committed schema stops matching the DTOs.

Why desktop keeps a copy: the backend refuses the WHOLE body on one unknown
key (`ValidationPipe(forbidNonWhitelisted)` on `/vpn/connect`, zod `.strict()`
on `/vpn/multi-hop/connect`). A misspelt key or a serde rename slip is a 400
for every user of the next release and no Rust type check can see it, so
`src/api/contract_tests.rs` serialises the real request builders
(`api::client::build_connect_request` / `build_multi_hop_request`) and
validates the resulting JSON against this file.

## Version (MR-197 / MR-1754)

The schema carries `x-contractVersion` (also `_status.contractVersion`), and
`CONTRACT_VERSION` repeats it. The app sends it as `X-Birdo-Contract` on every
control-plane request (`api::client::CONTRACT_VERSION`, `do_request`), and
`contract_tests::the_contract_version_is_the_schemas` fails when the schema, the
file and the constant disagree. When you re-vendor, update the pin
(`CONTRACT.sha256`, `SCHEMA_SHA256`), the version file and the constant in the
same commit. The scheduled drift job that compares against birdo-web needs a
read token the owner has not created yet and is not in place.

## Re-vendoring

1. Copy the file byte-for-byte from birdo-web `main`:
   `git show origin/main:backend/contract/vpn-protocol.schema.json`
   (LF endings, as git stores it). Never hand-edit it here.
2. Update `SCHEMA_SHA256` in `src/api/contract_tests.rs` in the SAME commit —
   `vendored_schema_is_the_birdo_web_blob` compares the sha256 of the file's
   LF-normalised bytes against that constant and fails otherwise.
3. Run `cargo test --lib api::contract_tests`. If the key-set tests now fail,
   the backend gained or lost a property: either start sending it, or add it
   to `CONNECT_KNOWN_UNSENT` / `MULTI_HOP_KNOWN_UNSENT` with the reason.
