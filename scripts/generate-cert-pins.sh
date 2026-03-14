#!/usr/bin/env bash
# =============================================================================
# generate-cert-pins.sh — Generate SPKI SHA-256 pins for birdo.app
#
# SEC-C1: The Windows Tauri client requires certificate pins in
# src-tauri/src/api/client.rs before release builds can compile.
#
# Usage:
#   ./generate-cert-pins.sh [hostname]
#   ./generate-cert-pins.sh birdo.app
#
# Output: Base64-encoded SHA-256 hashes of each certificate's
#         SubjectPublicKeyInfo (SPKI), suitable for pasting into
#         CERT_PINS_SHA256 in client.rs or CertificatePinner in
#         NetworkModule.kt.
# =============================================================================
set -euo pipefail

HOST="${1:-birdo.app}"
PORT="${2:-443}"

echo "=== Certificate Pin Generator for ${HOST}:${PORT} ==="
echo ""

# Get the full certificate chain
CHAIN=$(openssl s_client -connect "${HOST}:${PORT}" -showcerts </dev/null 2>/dev/null)

if [ -z "$CHAIN" ]; then
    echo "ERROR: Could not connect to ${HOST}:${PORT}"
    exit 1
fi

# Extract and hash each certificate in the chain
INDEX=0
echo "$CHAIN" | awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' | \
while IFS= read -r line; do
    if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
        CERT=""
    fi
    CERT="${CERT}${line}"$'\n'
    if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
        # Get subject and issuer
        SUBJECT=$(echo "$CERT" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//')
        ISSUER=$(echo "$CERT" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//')
        EXPIRY=$(echo "$CERT" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
        
        # Generate SPKI SHA-256 pin (standard format, used by Android/OkHttp)
        SPKI_PIN=$(echo "$CERT" | openssl x509 -pubkey -noout 2>/dev/null | \
              openssl pkey -pubin -outform DER 2>/dev/null | \
              openssl dgst -sha256 -binary | \
              base64)

        # Generate full DER certificate SHA-256 hash (used by Windows/Rust client)
        DER_PIN=$(echo "$CERT" | openssl x509 -outform DER 2>/dev/null | \
              openssl dgst -sha256 -binary | \
              base64)
        
        echo "--- Certificate ${INDEX} ---"
        echo "  Subject: ${SUBJECT}"
        echo "  Issuer:  ${ISSUER}"
        echo "  Expires: ${EXPIRY}"
        echo "  SPKI SHA-256 Pin:     ${SPKI_PIN}"
        echo "  Full DER SHA-256 Pin: ${DER_PIN}"
        echo ""
        
        # Output in Rust format (full DER hash — matches client.rs verify_certificate_pin)
        echo "  // Rust (client.rs CERT_PINS_SHA256 — full DER cert hash):"
        echo "  \"${DER_PIN}\",  // ${SUBJECT}"
        echo ""

        # Output in Rust format for DoH pins (also full DER hash — matches doh.rs)
        echo "  // Rust (doh.rs DoHProvider pins — full DER cert hash):"
        echo "  \"${DER_PIN}\",  // ${SUBJECT}"
        echo ""
        
        # Output in Kotlin format (SPKI hash — OkHttp standard)
        echo "  // Kotlin (NetworkModule.kt CertificatePinner — SPKI hash):"
        echo "  .add(\"${HOST}\", \"sha256/${SPKI_PIN}\")"
        echo ""
        
        INDEX=$((INDEX + 1))
    fi
done

echo "=== Instructions ==="
echo ""
echo "IMPORTANT: The Windows (Rust) client and Android (Kotlin) client use"
echo "different pin formats. The script outputs BOTH:"
echo ""
echo "  - Windows/Rust (client.rs, doh.rs): Full DER certificate SHA-256 hash"
echo "  - Android/Kotlin (NetworkModule.kt): SPKI SHA-256 hash (OkHttp standard)"
echo ""
echo "1. Copy the 'Rust' pins into CERT_PINS_SHA256 in:"
echo "   birdo-client-win/src-tauri/src/api/client.rs"
echo ""
echo "2. Copy the DoH provider pins into the respective DoHProvider structs in:"
echo "   birdo-client-win/src-tauri/src/vpn/doh.rs"
echo "   (Run this script with cloudflare-dns.com, dns.google, dns.quad9.net)"
echo ""
echo "3. Copy the 'Kotlin' pins into CertificatePinner in:"
echo "   birdo-client-android/app/src/main/java/app/birdo/vpn/di/NetworkModule.kt"
echo ""
echo "4. Re-run this script whenever certificates are rotated."
echo "   Set a calendar reminder for 30 days before certificate expiry."
echo ""
echo "5. Always pin at least 2 certificates (leaf + intermediate) to prevent"
echo "   lockouts during certificate renewal."
