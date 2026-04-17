# Hardened + Attested macOS Binary - Local POC

This POC is a runnable local walkthrough for the macOS attestation pieces that
exist in this repo today. It demonstrates:

1. Hardened Runtime codesigning on the local enclave CLI.
2. A Secure Enclave P-256 signing identity created by the current CLI.
3. A signed JSON attestation blob that binds machine state plus a binary hash.
4. Independent Go verification of the Swift/CryptoKit signature.

Run it from the repo root:

```bash
./scripts/attestation-poc.sh
```

The script writes the attestation to `/tmp/eigeninference_attestation.json`,
which is the fixed path read by the existing Go verifier.

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

Expected result:

```text
CROSS-LANGUAGE VERIFICATION PASSED
```

## What Each Layer Proves

| Layer | Local POC proof | Important limit |
| --- | --- | --- |
| Hardened Runtime | `codesign --options runtime` is applied to the enclave CLI without `get-task-allow`. | This protects the signed process while SIP is on. It is not Apple notarization. |
| Secure Enclave identity | `eigeninference-enclave attest` creates a P-256 key and embeds its public key in the signed blob. | The current CLI key is ephemeral. This proves the blob was signed by a SEP key, not a stable provider identity across invocations. |
| Binary integrity | SHA-256 of the built CLI is embedded in the signed blob. | The demo verifier prints the hash but does not compare it to a release allowlist. Production challenge verification can. |
| Machine posture | SIP, Secure Boot placeholder, RDMA status, ARV status, serial, chip, and OS are sealed into the signature. | Several posture fields are software-observed locally. Apple-backed MDM/MDA is the production path for stronger evidence. |
| Freshness | The attestation includes a timestamp. | The source-free local POC does not sign a verifier nonce because the current CLI has no `sign` subcommand. Production challenge-response covers this. |

## Secure Enclave Key Model

The current upstream CLI creates a fresh `SecureEnclaveIdentity` for each
command invocation. The attestation is still useful: it contains the public key
whose private half signed that exact blob, and the Go verifier checks the
signature against that embedded key.

That means this POC is intentionally about local blob integrity and
cross-language verification. Stable provider identity and nonce freshness live
in the provider/coordinator path, not this source-free CLI walkthrough.

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
