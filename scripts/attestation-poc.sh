#!/usr/bin/env bash
#
# Build, sign, attest, and verify the local Secure Enclave POC.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENCLAVE_BIN="$PROJECT_DIR/enclave/.build/release/eigeninference-enclave"
ENTITLEMENTS="$PROJECT_DIR/scripts/entitlements.plist"
ATTESTATION_JSON="/tmp/eigeninference_attestation.json"
CHALLENGE_RESPONSE_JSON="/tmp/eigeninference_challenge_response.json"
SIGN_IDENTITY="${1:--}"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: this POC must run on macOS" >&2
    exit 1
fi

echo "==> Building enclave CLI"
(cd "$PROJECT_DIR/enclave" && swift build -c release)

echo
echo "==> Signing enclave CLI with Hardened Runtime"
codesign --force --options runtime \
    --entitlements "$ENTITLEMENTS" \
    --sign "$SIGN_IDENTITY" \
    "$ENCLAVE_BIN"
codesign --verify --verbose=2 "$ENCLAVE_BIN"

echo
echo "==> Codesign flags"
codesign -dv --verbose=4 "$ENCLAVE_BIN" 2>&1 | grep -E "flags|Runtime" || true

echo
echo "==> Secure Enclave identity"
"$ENCLAVE_BIN" info

echo
echo "==> Creating attestation"
BIN_HASH="$(shasum -a 256 "$ENCLAVE_BIN" | awk '{print $1}')"
"$ENCLAVE_BIN" attest --binary-hash "$BIN_HASH" > "$ATTESTATION_JSON"
echo "wrote $ATTESTATION_JSON"

if command -v jq >/dev/null 2>&1; then
    jq . "$ATTESTATION_JSON"
else
    sed -n '1,40p' "$ATTESTATION_JSON"
fi

echo
echo "==> Verifying attestation in Go"
(cd "$PROJECT_DIR/coordinator" && go run ./cmd/verify-attestation "$ATTESTATION_JSON")

echo
echo "==> Verifying a fresh challenge response"
NONCE="$(openssl rand -base64 32)"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
"$ENCLAVE_BIN" challenge-response \
    --nonce "$NONCE" \
    --timestamp "$TIMESTAMP" \
    --binary-hash "$BIN_HASH" \
    > "$CHALLENGE_RESPONSE_JSON"

if command -v jq >/dev/null 2>&1; then
    jq . "$CHALLENGE_RESPONSE_JSON"
else
    sed -n '1,40p' "$CHALLENGE_RESPONSE_JSON"
fi

(cd "$PROJECT_DIR/coordinator" && go run ./cmd/verify-attestation "$ATTESTATION_JSON" "$CHALLENGE_RESPONSE_JSON")

echo
echo "POC complete."
echo "Attestation JSON: $ATTESTATION_JSON"
echo "Challenge response JSON: $CHALLENGE_RESPONSE_JSON"
echo "Binary hash: $BIN_HASH"
