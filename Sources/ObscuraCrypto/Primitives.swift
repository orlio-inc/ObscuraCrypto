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
    /// A key was used after `SecureBytes.clear()`.
    case keyCleared
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
    /// An `.obscura` export only a newer version can read.
    case exportNewerVersion
    /// A recovery phrase did not have 24 words.
    case recoveryPhraseWrongLength(Int)
    /// The word at this position (1-based) is not on the list.
    case recoveryPhraseUnknownWord(position: Int)
    /// Every word is on the list, but the phrase's checksum does not match:
    /// a word was mistyped as another list word, or words were swapped.
    case recoveryPhraseChecksumMismatch
    /// Not an `.obscurashared` file, or one no app could have written.
    case invalidSharedItems(String)
    /// An `.obscurashared` file whose key opened but whose contents were
    /// altered, cut short or reordered.
    case sharedItemsDamaged(String)
    /// An `.obscurashared` file only a newer version can read.
    case sharedItemsNewerVersion
    /// A password was given for an `.obscurashared` file sent without one.
    case sharedItemsNotLocked
    /// An `.obscurashared` file holds 1 to 1,000 items.
    case tooManySharedItems(Int)

    public var description: String {
        switch self {
        case .randomUnavailable: return "The system random number generator failed"
        case .keyCleared: return "The key has been cleared and cannot be used"
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
        case .exportNewerVersion: return "The .obscura export needs a newer version of Obscura"
        case .recoveryPhraseWrongLength(let count): return "A recovery phrase has 24 words, not \(count)"
        case .recoveryPhraseUnknownWord(let position): return "Word \(position) of the recovery phrase is not on the word list"
        case .recoveryPhraseChecksumMismatch: return "The recovery phrase's checksum does not match: a word is wrong or out of place"
        case .invalidSharedItems(let reason): return "Not a valid .obscurashared file: \(reason)"
        case .sharedItemsDamaged(let reason): return "The .obscurashared file is damaged: \(reason)"
        case .sharedItemsNewerVersion: return "The .obscurashared file needs a newer version of Obscura"
        case .sharedItemsNotLocked:
            return "The .obscurashared file has no password, though one was given: anyone who had the file could have made or changed it"
        case .tooManySharedItems(let count): return "A .obscurashared file holds 1 to 1,000 items, not \(count)"
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
    /// Rounds for folder passwords set from ObscuraCrypto 1.2.0 (Kotlin 1.3.0)
    /// on: the same as a vault's. Someone who has the vault open can copy a
    /// folder's lock and guess at it offline, and that is who a folder
    /// password is for.
    public static let folderIterations: UInt32 = 600_000
    /// Rounds for folder passwords set before: still read, never written.
    public static let legacyFolderIterations: UInt32 = 100_000
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

    /// A 32-byte key for one job, derived from `key` and named by `info`:
    /// HKDF-SHA256 with a salt of 32 zero bytes.
    ///
    /// Version 2 exports and shared items files never use the key a password
    /// or a random draw gives them as it is. The key their records are sealed
    /// with and their key commitment are each derived from it this way, under
    /// different names, so no key is both an AES-GCM key and an HMAC key.
    static func subkey(of key: SecureBytes, info: Data) throws -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: try key.symmetricKey, salt: subkeySalt, info: info, outputByteCount: keyLength)
    }

    /// `subkey` as bytes, for a commitment stored in a file.
    static func subkeyBytes(of key: SecureBytes, info: Data) throws -> Data {
        try subkey(of: key, info: info).withUnsafeBytes { Data($0) }
    }

    static let subkeySalt = Data(count: 32)
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
        return try seal(plaintext, key: try key.symmetricKey, nonce: AES.GCM.Nonce())
    }

    public static func open(_ combined: Data, key: SecureBytes) throws -> Data {
        try checkKey(key)
        return try open(combined, key: try key.symmetricKey)
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

    /// Seals with associated data, which the tag covers but the message does
    /// not carry. `.obscurashared` files and version 2 exports use it.
    static func seal<Plaintext: DataProtocol>(_ plaintext: Plaintext, key: SymmetricKey, nonce: AES.GCM.Nonce,
                                              authenticating associatedData: Data) throws -> Data {
        guard let combined = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: associatedData).combined else {
            throw ObscuraCryptoError.authenticationFailed
        }
        return combined
    }

    static func open(_ combined: Data, key: SymmetricKey, authenticating associatedData: Data) throws -> Data {
        do {
            return try AES.GCM.open(AES.GCM.SealedBox(combined: combined), using: key, authenticating: associatedData)
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
        try key.checkNotCleared()
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
    func bigEndianUInt16(at offset: Int) -> UInt16 {
        UInt16(self[startIndex + offset]) << 8 | UInt16(self[startIndex + offset + 1])
    }

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
