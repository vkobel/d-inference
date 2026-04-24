import CryptoKit
import EigenInferenceEnclave
import Foundation

// MARK: - CLI Entry Point

/// Command-line tool for Secure Enclave attestation and diagnostics.
///
/// Usage:
///   eigeninference-enclave attest [--encryption-key <base64>] [--binary-hash <hex>]
///   eigeninference-enclave info
///   eigeninference-enclave sign --data <base64>
///
/// The CLI persists only CryptoKit's opaque Secure Enclave key handle at
/// ~/.darkbloom/enclave_key.data. The raw private key never leaves the SEP,
/// and the handle only reloads on the same device.

let identityPath: URL = {
    FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".darkbloom", isDirectory: true)
        .appendingPathComponent("enclave_key.data")
}()

func loadOrCreateIdentity() throws -> SecureEnclaveIdentity {
    let fm = FileManager.default

    if fm.fileExists(atPath: identityPath.path) {
        let data = try Data(contentsOf: identityPath)
        return try SecureEnclaveIdentity(dataRepresentation: data)
    }

    let identity = try SecureEnclaveIdentity()
    let dir = identityPath.deletingLastPathComponent()
    try fm.createDirectory(
        at: dir,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    try identity.dataRepresentation.write(to: identityPath, options: [.atomic])
    try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: identityPath.path)
    return identity
}

func printUsage() {
    let usage = """
    Usage: eigeninference-enclave <command> [options]

    Commands:
      attest          Generate a signed attestation blob
      info            Show Secure Enclave availability and public key
      sign            Sign base64-encoded data with the Secure Enclave key

    Options for 'attest':
      --encryption-key <base64>    Bind an X25519 encryption public key to the attestation
      --binary-hash <hex>          Include SHA-256 hash of provider binary for integrity verification

    Options for 'sign':
      --data <base64>              Data to sign
    """
    fputs(usage + "\n", stderr)
}

func cmdAttest(encryptionKey: String?, binaryHash: String?) throws {
    guard SecureEnclave.isAvailable else {
        fputs("error: Secure Enclave is not available on this device\n", stderr)
        exit(1)
    }

    let identity = try loadOrCreateIdentity()
    let service = AttestationService(identity: identity)
    let signed = try service.createAttestation(encryptionPublicKey: encryptionKey, binaryHash: binaryHash)

    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.sortedKeys]
    let jsonData = try encoder.encode(signed)

    guard let jsonStr = String(data: jsonData, encoding: .utf8) else {
        fputs("error: failed to encode attestation as UTF-8\n", stderr)
        exit(1)
    }

    print(jsonStr)
}

func cmdInfo() throws {
    let available = SecureEnclave.isAvailable
    var info: [String: Any] = [
        "secure_enclave_available": available,
        "key_handle_path": identityPath.path,
        "key_persistence": "persistent_opaque_handle",
    ]

    if available {
        let identity = try loadOrCreateIdentity()
        info["public_key"] = identity.publicKeyBase64
    }

    let jsonData = try JSONSerialization.data(
        withJSONObject: info,
        options: [.sortedKeys, .prettyPrinted]
    )
    if let jsonStr = String(data: jsonData, encoding: .utf8) {
        print(jsonStr)
    }
}

func cmdSign(dataBase64: String?) throws {
    guard SecureEnclave.isAvailable else {
        fputs("error: Secure Enclave is not available on this device\n", stderr)
        exit(1)
    }
    guard let dataBase64 else {
        fputs("error: --data <base64> required\n", stderr)
        exit(1)
    }
    guard let data = Data(base64Encoded: dataBase64) else {
        fputs("error: invalid base64 data\n", stderr)
        exit(1)
    }

    let identity = try loadOrCreateIdentity()
    let signature = try identity.sign(data)
    print(signature.base64EncodedString())
}

// MARK: - Argument Parsing

let args = CommandLine.arguments
guard args.count >= 2 else {
    printUsage()
    exit(1)
}

let command = args[1]

do {
    switch command {
    case "attest":
        var encryptionKey: String? = nil
        var binaryHash: String? = nil
        var i = 2
        while i < args.count {
            if args[i] == "--encryption-key" && i + 1 < args.count {
                encryptionKey = args[i + 1]
                i += 2
            } else if args[i] == "--binary-hash" && i + 1 < args.count {
                binaryHash = args[i + 1]
                i += 2
            } else {
                fputs("error: unknown option \(args[i])\n", stderr)
                printUsage()
                exit(1)
            }
        }
        try cmdAttest(encryptionKey: encryptionKey, binaryHash: binaryHash)

    case "info":
        try cmdInfo()

    case "sign":
        var dataBase64: String? = nil
        var i = 2
        while i < args.count {
            if args[i] == "--data" && i + 1 < args.count {
                dataBase64 = args[i + 1]
                i += 2
            } else {
                fputs("error: unknown option \(args[i])\n", stderr)
                printUsage()
                exit(1)
            }
        }
        try cmdSign(dataBase64: dataBase64)

    default:
        fputs("error: unknown command '\(command)'\n", stderr)
        printUsage()
        exit(1)
    }
} catch {
    fputs("error: \(error.localizedDescription)\n", stderr)
    exit(1)
}
