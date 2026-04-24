# Hardened + Attested macOS Binary - Local POC

This POC is a runnable local walkthrough for the macOS attestation pieces that
exist in this repo today. It demonstrates:

1. Hardened Runtime codesigning on the local enclave CLI.
2. A persistent Secure Enclave P-256 signing identity.
3. A signed JSON attestation blob that binds machine state plus a binary hash.
4. Independent Go verification of the Swift/CryptoKit signature.
5. A fresh nonce challenge signed by the same Secure Enclave identity.

Run it from the repo root:

```bash
./scripts/attestation-poc.sh
```

The script writes the attestation to `/tmp/eigeninference_attestation.json`.

For a Developer ID certificate instead of local ad-hoc signing:

```bash
./scripts/attestation-poc.sh "Developer ID Application: Your Org (TEAMID)"
```

## Prerequisites

- Apple Silicon Mac. `SecureEnclave.isAvailable` is false on Intel Macs.
- SIP enabled: `csrutil status`.
- Xcode Command Line Tools: `xcode-select --install`.
- Go and Swift toolchains available on `PATH`.
- `jq` is optional; the script falls back to printing raw JSON.

## What The Script Runs

The script is intentionally just the manual flow automated:

```bash
cd enclave
swift build -c release
cd ..

codesign --force --options runtime \
  --entitlements scripts/entitlements.plist \
  --sign - \
  enclave/.build/release/eigeninference-enclave

BIN_HASH="$(shasum -a 256 enclave/.build/release/eigeninference-enclave | awk '{print $1}')"
enclave/.build/release/eigeninference-enclave info
enclave/.build/release/eigeninference-enclave attest --binary-hash "$BIN_HASH" \
  > /tmp/eigeninference_attestation.json

(cd coordinator && go run ./cmd/verify-attestation)
```

It then signs a fresh verifier nonce and verifies that signature against the
public key from the attestation:

```bash
NONCE="$(openssl rand -base64 32)"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
CHALLENGE_DATA="${NONCE}${TIMESTAMP}"
CHALLENGE_B64="$(printf "%s" "$CHALLENGE_DATA" | base64 | tr -d '\n')"
SIGNATURE="$(enclave/.build/release/eigeninference-enclave sign --data "$CHALLENGE_B64")"

(cd coordinator && go run ./cmd/verify-attestation \
  /tmp/eigeninference_attestation.json "$CHALLENGE_DATA" "$SIGNATURE")
```

Expected result:

```text
CROSS-LANGUAGE VERIFICATION PASSED
CHALLENGE SIGNATURE PASSED
```

## What Each Layer Proves

| Layer | Local POC proof | Important limit |
| --- | --- | --- |
| Hardened Runtime | `codesign --options runtime` is applied to the enclave CLI without `get-task-allow`. | This protects the signed process while SIP is on. It is not Apple notarization. |
| Secure Enclave identity | `eigeninference-enclave info`, `attest`, and `sign` load the same P-256 key handle from `~/.darkbloom/enclave_key.data`. | The file is an opaque same-device handle, not raw private-key material. |
| Binary integrity | SHA-256 of the built CLI is embedded in the signed blob. | The demo verifier prints the hash but does not compare it to a release allowlist. Production challenge verification can. |
| Machine posture | SIP, Secure Boot placeholder, RDMA status, ARV status, serial, chip, and OS are sealed into the signature. | Several posture fields are software-observed locally. Apple-backed MDM/MDA is the production path for stronger evidence. |
| Freshness | A random nonce plus timestamp is signed and verified against the attested public key. | Freshness only matters if the verifier rejects reused or stale nonces. The production coordinator owns that state. |

## Secure Enclave Key Model

The CLI stores only CryptoKit's opaque Secure Enclave key handle:

```text
~/.darkbloom/enclave_key.data
```

That file is not the raw private key. It lets CryptoKit reload the same key
from the Secure Enclave on this Mac. Delete it to rotate the local identity:

```bash
rm ~/.darkbloom/enclave_key.data
```

The important consequence is that `attest` and `sign` use the same public key.
The Go verifier first verifies the attestation signature, then uses the
attestation's `publicKey` to verify the challenge signature.

Relevant implementation:

- `enclave/Sources/EigenInferenceEnclaveCLI/main.swift`
- `enclave/Sources/EigenInferenceEnclave/SecureEnclaveIdentity.swift`
- `enclave/Sources/EigenInferenceEnclave/Attestation.swift`
- `coordinator/internal/attestation/attestation.go`
- `coordinator/cmd/verify-attestation/main.go`

## JSON Signature Details

The Swift side signs the JSON bytes for the `attestation` object using
CryptoKit P-256 ECDSA. The signature is DER-encoded and base64-encoded in the
top-level `signature` field.

The Go verifier preserves the original raw `attestation` JSON bytes before
parsing. That matters because cross-language JSON re-encoding can differ in
small ways even when the parsed data is identical. The verifier hashes those
exact bytes with SHA-256 and calls Go's `ecdsa.Verify`.

## Tamper Check

After a successful run, mutate one signed field:

```bash
sed -i '' 's/"sipEnabled":true/"sipEnabled":false/' /tmp/eigeninference_attestation.json
(cd coordinator && go run ./cmd/verify-attestation)
```

Expected result:

```text
VERIFICATION FAILED: signature verification failed
```

Regenerate the file with `./scripts/attestation-poc.sh` before continuing.

## What Production Adds

The POC is local and self-contained. The production provider/coordinator path
adds the networked and Apple-backed controls:

- Provider registration sends the attestation blob over the WebSocket.
- The coordinator sends attestation challenges every five minutes.
- Challenge responses include fresh SIP, RDMA, hypervisor, binary, runtime, and
  model hash state.
- Known-good binary/runtime hashes can exclude modified providers from routing.
- ACME `device-attest-01` and Apple Managed Device Attestation can add
  Apple-signed device evidence and bind it back to the provider's SE key.
- Release builds use Developer ID signing, notarization, and stapling for
  distribution.

This POC should be read as the local cryptographic core: Hardened Runtime,
Secure Enclave P-256 signatures, deterministic signed state, and independent
verification.
