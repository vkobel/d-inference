package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/eigeninference/coordinator/internal/attestation"
)

type localChallengeResponse struct {
	Nonce             string            `json:"nonce"`
	Timestamp         string            `json:"timestamp"`
	Signature         string            `json:"signature"`
	StatusSignature   string            `json:"status_signature"`
	PublicKey         string            `json:"public_key"`
	HypervisorActive  *bool             `json:"hypervisor_active,omitempty"`
	RDMADisabled      *bool             `json:"rdma_disabled,omitempty"`
	SIPEnabled        *bool             `json:"sip_enabled,omitempty"`
	SecureBootEnabled *bool             `json:"secure_boot_enabled,omitempty"`
	BinaryHash        string            `json:"binary_hash,omitempty"`
	ActiveModelHash   string            `json:"active_model_hash,omitempty"`
	PythonHash        string            `json:"python_hash,omitempty"`
	RuntimeHash       string            `json:"runtime_hash,omitempty"`
	TemplateHashes    map[string]string `json:"template_hashes,omitempty"`
	ModelHashes       map[string]string `json:"model_hashes,omitempty"`
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		usage()
		return
	}
	if len(args) != 0 && len(args) != 1 && len(args) != 2 && len(args) != 3 {
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

	if len(args) == 2 {
		if err := verifyLocalChallengeResponse(result, args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "\n✗ CHALLENGE RESPONSE FAILED: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("\n✓ CHALLENGE RESPONSE PASSED")
		fmt.Println("  Same Secure Enclave P-256 identity signed the nonce and canonical status payload")
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  verify-attestation [attestation-json]")
	fmt.Fprintln(os.Stderr, "  verify-attestation [attestation-json] [challenge-response-json]")
	fmt.Fprintln(os.Stderr, "  verify-attestation [attestation-json] [challenge-data] [signature-b64]")
}

func verifyLocalChallengeResponse(result attestation.VerificationResult, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read challenge response: %w", err)
	}

	var resp localChallengeResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("parse challenge response: %w", err)
	}
	if resp.PublicKey != "" && resp.PublicKey != result.PublicKey {
		return fmt.Errorf("public key mismatch")
	}
	if resp.Nonce == "" || resp.Timestamp == "" {
		return fmt.Errorf("nonce and timestamp are required")
	}

	challengeData := resp.Nonce + resp.Timestamp
	if err := attestation.VerifyChallengeSignature(result.PublicKey, resp.Signature, challengeData); err != nil {
		return fmt.Errorf("nonce signature: %w", err)
	}

	statusInput := attestation.StatusCanonicalInput{
		Nonce:             resp.Nonce,
		Timestamp:         resp.Timestamp,
		HypervisorActive:  resp.HypervisorActive,
		RDMADisabled:      resp.RDMADisabled,
		SIPEnabled:        resp.SIPEnabled,
		SecureBootEnabled: resp.SecureBootEnabled,
		BinaryHash:        resp.BinaryHash,
		ActiveModelHash:   resp.ActiveModelHash,
		PythonHash:        resp.PythonHash,
		RuntimeHash:       resp.RuntimeHash,
		TemplateHashes:    resp.TemplateHashes,
		ModelHashes:       resp.ModelHashes,
	}
	if err := attestation.VerifyStatusSignature(result.PublicKey, resp.StatusSignature, statusInput); err != nil {
		return fmt.Errorf("status signature: %w", err)
	}

	return nil
}
