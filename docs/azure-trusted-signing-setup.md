# Azure Trusted Signing — Setup Guide

Azure Trusted Signing (formerly known as Azure Code Signing) provides
Authenticode signatures for Windows EXE and MSI installers. The CI/CD
pipeline in `build-windows.yml` uses OIDC federation, so **no client
secrets are ever stored in GitHub**.

---

## Architecture

```
Git tag push  →  GitHub Actions (build job)
  → Tauri builds NSIS .exe + MSI
  → Sigstore: cosign sign-blob (provenance layer)
  → artifacts uploaded

  →  GitHub Actions (sign job)
       → azure/login with OIDC JWT (no secrets)
       → azure/trusted-signing-action signs EXE + MSI
       → signed artifacts uploaded

  →  GitHub Actions (release job)
       → prefers signed; falls back to unsigned
       → creates draft GitHub Release
```

---

## Step 1 — Create Azure Trusted Signing Account

```bash
# Variables — fill these in for your environment
RESOURCE_GROUP="birdovpn-rg"
LOCATION="eastus"
ACCOUNT_NAME="BirdoVPN"
CERT_PROFILE="BirdoVPNCertProfile"
SUBSCRIPTION="<your-subscription-id>"

# Create resource group (skip if it already exists)
az group create --name "$RESOURCE_GROUP" --location "$LOCATION"

# Register the provider (one-time per subscription)
az provider register --namespace Microsoft.CodeSigning --wait

# Create the Trusted Signing Account
az codesigning account create \
  --resource-group "$RESOURCE_GROUP" \
  --account-name "$ACCOUNT_NAME" \
  --location "$LOCATION" \
  --sku "Basic"

# Create a certificate profile (PublicTrust = trusted by Windows out of the box)
az codesigning certificate-profile create \
  --resource-group "$RESOURCE_GROUP" \
  --account-name "$ACCOUNT_NAME" \
  --profile-name "$CERT_PROFILE" \
  --profile-type "PublicTrust" \
  --include-street-address false
```

> **PublicTrust** profiles are signed by Microsoft's root CA and are trusted
> by Windows SmartScreen with no user prompts. Identity verification takes
> 1–3 business days.

---

## Step 2 — Register an Azure AD App (Service Principal)

```bash
# Create the app registration
APP_ID=$(az ad app create \
  --display-name "BirdoVPN GitHub Actions CodeSigning" \
  --query appId --output tsv)

# Create a service principal for the app
az ad sp create --id "$APP_ID"

echo "Client ID: $APP_ID"
echo "Tenant ID: $(az account show --query tenantId --output tsv)"
```

---

## Step 3 — Add OIDC Federated Credentials

```bash
# For tag-triggered signing (the sign job runs on tags only)
az ad app federated-credential create \
  --id "$APP_ID" \
  --parameters '{
    "name": "github-tags",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:BirdoVPN/birdo-client-win:ref:refs/tags/*",
    "audiences": ["api://AzureADTokenExchange"]
  }'

# For manual workflow_dispatch runs (optional but recommended for testing)
az ad app federated-credential create \
  --id "$APP_ID" \
  --parameters '{
    "name": "github-workflow-dispatch",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:BirdoVPN/birdo-client-win:environment:production",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

> Replace `BirdoVPN/birdo-client-win` with the actual org/repo slug.

---

## Step 4 — Assign Roles

```bash
# Get the service principal object ID
SP_OBJECT_ID=$(az ad sp show --id "$APP_ID" --query id --output tsv)

# Get the Trusted Signing Account resource ID
ACCOUNT_ID=$(az codesigning account show \
  --resource-group "$RESOURCE_GROUP" \
  --account-name "$ACCOUNT_NAME" \
  --query id --output tsv)

# Grant "Code Signing Certificate Profile Signer" role
az role assignment create \
  --role "Code Signing Certificate Profile Signer" \
  --assignee-object-id "$SP_OBJECT_ID" \
  --assignee-principal-type ServicePrincipal \
  --scope "$ACCOUNT_ID"
```

> This role allows the app to sign binaries using the certificate profile
> but NOT to create, delete, or modify certificates.

---

## Step 5 — Get the Signing Endpoint

```bash
az codesigning account show \
  --resource-group "$RESOURCE_GROUP" \
  --account-name "$ACCOUNT_NAME" \
  --query "accountUri" --output tsv
# Example output: https://eus.codesigning.azure.net/
```

---

## Step 6 — Configure GitHub Repository

### Secrets (Settings → Secrets and variables → Actions → Secrets)

| Secret name | Value |
|---|---|
| `AZURE_TENANT_ID` | Azure AD tenant ID (from Step 2) |
| `AZURE_CLIENT_ID` | App registration client ID (from Step 2) |

### Variables (Settings → Secrets and variables → Actions → Variables)

| Variable name | Example value |
|---|---|
| `AZURE_TRUSTED_SIGNING_ENDPOINT` | `https://eus.codesigning.azure.net/` |
| `AZURE_TRUSTED_SIGNING_ACCOUNT_NAME` | `BirdoVPN` |
| `AZURE_TRUSTED_SIGNING_CERT_PROFILE` | `BirdoVPNCertProfile` |

### Existing secrets that must ALSO be present (Tauri updater)

| Secret name | Purpose |
|---|---|
| `TAURI_SIGNING_PRIVATE_KEY` | Minisign key for Tauri updater |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | Password for the minisign key |

---

## Step 7 — Trigger a Signed Release

Push a tag matching `win-v*`:

```bash
git tag win-v1.0.0
git push origin win-v1.0.0
```

The pipeline will:
1. Build the Tauri NSIS + MSI installers on `windows-latest`
2. Apply Sigstore provenance bundles (free, keyless, tag-tied)
3. Azure-sign both EXE **and** MSI with Authenticode (SHA-256 + RFC 3161 timestamp)
4. Create a draft GitHub Release with all artefacts

---

## Verifying the Authenticode Signature

On any Windows machine after download:

```powershell
Get-AuthenticodeSignature "BirdoVPN-Setup-1.0.0.exe" | Format-List *
```

Look for:
- `Status: Valid`
- `SignerCertificate.Subject` containing `CN=BirdoVPN` (or your registered org name)
- `TimeStamperCertificate` present (proves signing time is locked in)

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `AADSTS700016: Application not found` | Wrong `AZURE_CLIENT_ID` | Double-check the app registration client ID |
| `AADSTS70021: No matching federated identity record` | Subject claim mismatch | Verify the federated credential subject matches the tag format exactly |
| `AuthorizationFailed` | Missing role assignment | Re-run Step 4; allow 5 min for RBAC propagation |
| `CertificateProfileNotFound` | Wrong profile name | Check `AZURE_TRUSTED_SIGNING_CERT_PROFILE` variable value |
| SmartScreen still warns after signing | PublicTrust profile pending verification | Complete identity verification in Azure Portal → Trusted Signing |
