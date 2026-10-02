// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CommonCrypto
import CryptoKit
import Foundation
import Security

// MARK: - Errors

public enum ObscuraCryptoError: Error, Equatable, Sendable, CustomStringConvertible {
    /// The system random number generator reported a failure.
    case randomUnavailable
    case keyDerivationFailed
    /// A key was not the 32 bytes AES-256 needs.
    case invalidKeyLength(Int)
    /// An AES-GCM authentication tag did not verify: wrong key, or the data
    /// was altered.
    case authenticationFailed
    /// The password did not unwrap the key.
    case wrongPassword
    case invalidVaultHeader(String)
    case vaultHeaderChecksumMismatch
    case unsupportedCipherSuite(UInt8)
    /// A header asked for fewer key derivation rounds than the format allows.
    case iterationsBelowMinimum(UInt32)
    case invalidChunkedHeader(String)
    case chunkIndexOutOfRange(Int)
    /// A chunk did not carry the nonce its position requires, meaning chunks
    /// were reordered, or copied in from another file.
    case chunkNonceMismatch(Int)
    /// The file is not the length its header describes.
    case chunkedFileSizeMismatch(expected: Int, actual: Int)
    case invalidFolderProtection(String)
    case invalidExport(String)

    public var description: String {
        switch self {
        case .randomUnavailable: return "The system random number generator failed"
        case .keyDerivationFailed: return "Key derivation failed"
        case .invalidKeyLength(let length): return "Expected a 32-byte key, got \(length) bytes"
        case .authenticationFailed: return "Authentication failed: wrong key, or the data was altered"
        case .wrongPassword: return "Wrong password"
        case .invalidVaultHeader(let reason): return "Not a valid vault header: \(reason)"
        case .vaultHeaderChecksumMismatch: return "Vault header checksum does not match"
        case .unsupportedCipherSuite(let id): return String(format: "Unsupported cipher suite 0x%02x", id)
        case .iterationsBelowMinimum(let rounds): return "Header asks for \(rounds) key derivation rounds, below the minimum"
        case .invalidChunkedHeader(let reason): return "Not a valid chunked media header: \(reason)"
        case .chunkIndexOutOfRange(let index): return "Chunk \(index) is out of range"
        case .chunkNonceMismatch(let index): return "Chunk \(index) carries the wrong nonce: chunks were reordered or replaced"
        case .chunkedFileSizeMismatch(let expected, let actual):
            return "File is \(actual) bytes but its header describes \(expected)"
        case .invalidFolderProtection(let reason): return "Not valid folder protection data: \(reason)"
        case .invalidExport(let reason): return "Not a valid .obscura export: \(reason)"
        }
    }
}

// MARK: - Randomness

enum SecureRandom {
    static func fill(_ buffer: UnsafeMutableRawBufferPointer) throws {
        guard let base = buffer.baseAddress, buffer.count > 0 else { return }
        guard SecRandomCopyBytes(kSecRandomDefault, buffer.count, base) == errSecSuccess else {
            throw ObscuraCryptoError.randomUnavailable
        }
    }

    /// Random bytes that are not secret, such as salts and nonce prefixes.
    static func bytes(_ count: Int) throws -> Data {
        var data = Data(count: count)
        try data.withUnsafeMutableBytes { try fill($0) }
        return data
    }
}

// MARK: - Key derivation

/// PBKDF2-HMAC-SHA256, the only password-based key derivation Obscura uses.
public enum KeyDerivation {
    /// Rounds for vault passwords. The format refuses anything lower.
    public static let vaultIterations: UInt32 = 600_000
    /// Rounds for folder passwords, which sit behind the vault password.
    public static let folderIterations: UInt32 = 100_000
    public static let keyLength = 32
    public static let saltLength = 32

    /// Derives a 32-byte key.
    ///
    /// The password is used as its UTF-8 bytes with no Unicode normalisation,
    /// as the app has always done, so a password typed with a different
    /// composition of the same accented character derives a different key.
    public static func pbkdf2SHA256(password: String, salt: Data, iterations: UInt32) throws -> SecureBytes {
        guard iterations > 0 else { throw ObscuraCryptoError.keyDerivationFailed }
        let key = SecureBytes(count: keyLength)
        var passwordBytes = Array(password.utf8)
        defer { passwordBytes.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) } }

        let status = key.withUnsafeBytes { keyBuffer in
            salt.withUnsafeBytes { saltBuffer in
                passwordBytes.withUnsafeBufferPointer { passwordBuffer in
                    passwordBuffer.withMemoryRebound(to: Int8.self) { password in
                        CCKeyDerivationPBKDF(
                            CCPBKDFAlgorithm(kCCPBKDF2),
                            password.baseAddress,
                            password.count,
                            saltBuffer.bindMemory(to: UInt8.self).baseAddress,
                            saltBuffer.count,
                            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                            iterations,
                            UnsafeMutablePointer(mutating: keyBuffer.bindMemory(to: UInt8.self).baseAddress),
                            keyLength
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else { throw ObscuraCryptoError.keyDerivationFailed }
        return key
    }

    /// A fresh random 32-byte salt.
    public static func makeSalt() throws -> Data {
        try SecureRandom.bytes(saltLength)
    }
}

// MARK: - AES-256-GCM

/// AES-256-GCM in the layout every Obscura format uses: the "combined"
/// representation, `nonce (12) || ciphertext || tag (16)`.
public enum AESGCM {
    public static let nonceSize = 12
    public static let tagSize = 16
    /// Bytes added to every sealed message.
    public static let overhead = nonceSize + tagSize

    /// Seals with a fresh random nonce.
    public static func seal<Plaintext: DataProtocol>(_ plaintext: Plaintext, key: SecureBytes) throws -> Data {
        try checkKey(key)
        return try seal(plaintext, key: key.symmetricKey, nonce: AES.GCM.Nonce())
    }

    public static func open(_ combined: Data, key: SecureBytes) throws -> Data {
        try checkKey(key)
        return try open(combined, key: key.symmetricKey)
    }

    static func seal<Plaintext: DataProtocol>(_ plaintext: Plaintext, key: SymmetricKey, nonce: AES.GCM.Nonce) throws -> Data {
        guard let combined = try AES.GCM.seal(plaintext, using: key, nonce: nonce).combined else {
            // Only happens for a non-standard nonce size, which is never used.
            throw ObscuraCryptoError.authenticationFailed
        }
        return combined
    }

    static func open(_ combined: Data, key: SymmetricKey) throws -> Data {
        do {
            return try AES.GCM.open(AES.GCM.SealedBox(combined: combined), using: key)
        } catch {
            throw ObscuraCryptoError.authenticationFailed
        }
    }

    /// Opens a wrapped key straight into `SecureBytes`.
    ///
    /// CryptoKit returns plaintext as `Data`, which this package does not
    /// control. The copy is overwritten as soon as the key is in its zeroing
    /// buffer, so the unwrapped key does not linger in freed memory. (If the
    /// `Data` storage were shared, which it is not here, the overwrite would
    /// land on a copy and change nothing.)
    static func unwrapKey(_ wrapped: Data, with key: SecureBytes) throws -> SecureBytes {
        var plaintext = try open(wrapped, key: key)
        defer { plaintext.resetBytes(in: 0..<plaintext.count) }
        return SecureBytes(copying: plaintext)
    }

    static func checkKey(_ key: SecureBytes) throws {
        guard key.count == 32 else { throw ObscuraCryptoError.invalidKeyLength(key.count) }
    }
}

// MARK: - CRC32

extension Collection where Element == UInt8 {
    /// CRC-32 (IEEE 802.3), as zlib computes it. Used only to catch a damaged
    /// vault header; it is not a security check, the AES-GCM tags are.
    var crc32: UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in self {
            crc ^= UInt32(byte)
            for _ in 0..<8 {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB8_8320 : crc >> 1
            }
        }
        return crc ^ 0xFFFF_FFFF
    }
}

extension Data {
    func bigEndianUInt32(at offset: Int) -> UInt32 {
        self[startIndex + offset ..< startIndex + offset + 4].reduce(0) { $0 << 8 | UInt32($1) }
    }

    func bigEndianUInt64(at offset: Int) -> UInt64 {
        self[startIndex + offset ..< startIndex + offset + 8].reduce(0) { $0 << 8 | UInt64($1) }
    }

    mutating func appendBigEndian<T: FixedWidthInteger>(_ value: T) {
        Swift.withUnsafeBytes(of: value.bigEndian) { append(contentsOf: $0) }
    }
}
