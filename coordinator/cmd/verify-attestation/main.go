package main

import (
	"fmt"
	"os"

	"github.com/eigeninference/coordinator/internal/attestation"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		usage()
		return
	}
	if len(args) != 0 && len(args) != 1 && len(args) != 3 {
		usage()
		os.Exit(2)
	}

	path := "/tmp/eigeninference_attestation.json"
	if len(args) >= 1 {
		path = args[0]
	}

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		os.Exit(1)
	}

	result, err := attestation.VerifyJSON(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Attestation from: %s (%s)\n", result.ChipName, result.HardwareModel)
	fmt.Printf("Secure Enclave: %v | SIP: %v | Secure Boot: %v\n",
		result.SecureEnclaveAvailable, result.SIPEnabled, result.SecureBootEnabled)

	if result.Valid {
		fmt.Println("\n✓ CROSS-LANGUAGE VERIFICATION PASSED")
		fmt.Println("  Swift Secure Enclave P-256 signature verified by Go coordinator")
	} else {
		fmt.Printf("\n✗ VERIFICATION FAILED: %s\n", result.Error)
		os.Exit(1)
	}

	if len(args) == 3 {
		challengeData := args[1]
		signature := args[2]
		if err := attestation.VerifyChallengeSignature(result.PublicKey, signature, challengeData); err != nil {
			fmt.Fprintf(os.Stderr, "\n✗ CHALLENGE SIGNATURE FAILED: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("\n✓ CHALLENGE SIGNATURE PASSED")
		fmt.Println("  Same Secure Enclave P-256 identity signed the verifier nonce")
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  verify-attestation [attestation-json]")
	fmt.Fprintln(os.Stderr, "  verify-attestation [attestation-json] [challenge-data] [signature-b64]")
}
