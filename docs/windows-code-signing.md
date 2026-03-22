# Windows Code Signing Setup — Birdo VPN

## Why This Is Required

Without code signing, Windows SmartScreen will show scary "Unknown publisher" warnings that will cause most users to abort the install. Microsoft Store requires signed packages.

## Steps

### 1. Purchase a Code Signing Certificate

**Recommended providers:**
- **SignPath** — Free for open source, ~$150/yr for commercial. Fast issuance.
- **Certum** (Asseco) — ~$70/yr for open-source, ~$170/yr commercial. Budget option.
- **DigiCert / Sectigo** — ~$400-700/yr. Most recognized, fastest SmartScreen reputation.
- **SSL.com** — ~$250/yr. Good middle ground.

**EV vs Standard:**
- **EV (Extended Validation)** — instant SmartScreen trust, requires hardware token. ~$350-500/yr.
- **Standard (OV)** — needs reputation building (SmartScreen will warn for first ~50-100 installs). ~$70-250/yr.

**For launch: Standard is fine.** Upgrade to EV once revenue justifies it.

### 2. Export Certificate Thumbprint

After receiving the certificate:

```powershell
# Import the .pfx into your cert store
Import-PfxCertificate -FilePath "birdo-codesign.pfx" -CertStoreLocation Cert:\CurrentUser\My

# Get the thumbprint
Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*Birdo*" } | Select Thumbprint
```

### 3. Update tauri.conf.json

Edit `birdo-client-win/src-tauri/tauri.conf.json`:

```json
"windows": {
  "certificateThumbprint": "YOUR_THUMBPRINT_HERE",
  "digestAlgorithm": "sha256",
  "timestampUrl": "http://timestamp.sectigo.com",
  "allowDowngrades": false,
  ...
}
```

**Timestamp URLs by provider:**
- Sectigo: `http://timestamp.sectigo.com`
- DigiCert: `http://timestamp.digicert.com`
- SSL.com: `http://ts.ssl.com`

### 4. CI/CD Signing (GitHub Actions)

Store as repository secrets:
- `WINDOWS_CERTIFICATE` — base64-encoded .pfx
- `WINDOWS_CERTIFICATE_PASSWORD` — pfx password

In your workflow:

```yaml
- name: Import code signing certificate
  env:
    CERTIFICATE: ${{ secrets.WINDOWS_CERTIFICATE }}
    CERTIFICATE_PASSWORD: ${{ secrets.WINDOWS_CERTIFICATE_PASSWORD }}
  run: |
    $pfx = [Convert]::FromBase64String($env:CERTIFICATE)
    [IO.File]::WriteAllBytes("certificate.pfx", $pfx)
    Import-PfxCertificate -FilePath certificate.pfx -Password (ConvertTo-SecureString $env:CERTIFICATE_PASSWORD -AsPlainText -Force) -CertStoreLocation Cert:\CurrentUser\My
    Remove-Item certificate.pfx
```

### 5. macOS Signing (Future)

Update `birdo-client-win/src-tauri/tauri.conf.json`:

```json
"macOS": {
  "signingIdentity": "Developer ID Application: Your Name (TEAM_ID)",
  ...
}
```

Requires Apple Developer Program ($99/yr) + `codesign` + notarization via `xcrun notarytool`.

## Cost Summary

| Item | Annual Cost | Priority |
|------|------------|----------|
| Standard code signing cert | ~$70-250 | **Required for launch** |
| EV code signing cert | ~$350-500 | Post-launch upgrade |
| Apple Developer Program | $99 | When macOS client ships |
