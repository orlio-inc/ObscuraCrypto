// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import Foundation

/// The cipher suite a vault header declares.
public enum CipherSuite: UInt8, Sendable {
    /// PBKDF2-HMAC-SHA256 for the password, AES-256-GCM for everything else.
    case pbkdf2SHA256AES256GCM = 0x01

    public var name: String {
        switch self {
        case .pbkdf2SHA256AES256GCM: return "PBKDF2-HMAC-SHA256 + AES-256-GCM"
        }
    }
}

/// The 145-byte header at the start of every vault file.
///
/// It carries everything needed to go from a password to the vault's master
/// key, and nothing else. The vault's contents follow it: a SQLCipher
/// database encrypted with the master key, then random padding.
///
/// ```
/// offset  size  field
///      0     1  version, 0x03
///      1     7  magic, "OBSCURA"
///      8     1  cipher suite, 0x01
///      9     4  key derivation rounds, big-endian UInt32
///     13    32  salt for the password
///     45    60  master key wrapped with the password key (AES-GCM combined)
///    105    36  database length, encrypted with the master key (AES-GCM combined)
///    141     4  CRC-32 of bytes 0..<141, big-endian
/// ```
///
/// The key hierarchy is password → key encryption key (PBKDF2) → master key
/// (unwrapped with AES-GCM) → data. The master key is random, made once when
/// the vault is created, so changing the password rewraps 32 bytes and
/// leaves every encrypted file as it was.
public struct VaultHeader: Sendable, Equatable {
    public static let size = 145
    public static let version: UInt8 = 0x03
    public static let magic = Data("OBSCURA".utf8)
    public static let wrappedKeySize = AESGCM.overhead + 32
    public static let encryptedDatabaseSizeSize = AESGCM.overhead + 8
    /// Beyond this a header is treated as hostile: about 16 times the
    /// standard count, it already makes an unlock take several seconds.
    public static let maximumIterations: UInt32 = 10_000_000

    public let cipherSuite: CipherSuite
    public let kdfIterations: UInt32
    public let salt: Data
    public let wrappedMasterKey: Data
    public let encryptedDatabaseSize: Data

    public init(
        cipherSuite: CipherSuite = .pbkdf2SHA256AES256GCM,
        kdfIterations: UInt32 = KeyDerivation.vaultIterations,
        salt: Data,
        wrappedMasterKey: Data,
        encryptedDatabaseSize: Data
    ) {
        self.cipherSuite = cipherSuite
        self.kdfIterations = kdfIterations
        self.salt = salt
        self.wrappedMasterKey = wrappedMasterKey
        self.encryptedDatabaseSize = encryptedDatabaseSize
    }

    // MARK: - Reading and writing

    /// Parses the first 145 bytes of `data`, which may be a whole vault file.
    public init(parsing data: Data) throws {
        guard data.count >= Self.size else {
            throw ObscuraCryptoError.invalidVaultHeader("shorter than \(Self.size) bytes")
        }
        let header = Data(data.prefix(Self.size))

        guard header[0] == Self.version else {
            throw ObscuraCryptoError.invalidVaultHeader(String(format: "version 0x%02x, expected 0x03", header[0]))
        }
        guard header[1..<8] == Self.magic else {
            throw ObscuraCryptoError.invalidVaultHeader("missing OBSCURA magic")
        }
        guard header.bigEndianUInt32(at: 141) == header[0..<141].crc32 else {
            throw ObscuraCryptoError.vaultHeaderChecksumMismatch
        }
        guard let suite = CipherSuite(rawValue: header[8]) else {
            throw ObscuraCryptoError.unsupportedCipherSuite(header[8])
        }

        self.init(
            cipherSuite: suite,
            kdfIterations: header.bigEndianUInt32(at: 9),
            salt: Data(header[13..<45]),
            wrappedMasterKey: Data(header[45..<105]),
            encryptedDatabaseSize: Data(header[105..<141])
        )
    }

    /// The 145 header bytes, checksum included.
    public func serialized() -> Data {
        var data = Data(capacity: Self.size)
        data.append(Self.version)
        data.append(Self.magic)
        data.append(cipherSuite.rawValue)
        data.appendBigEndian(kdfIterations)
        data.append(salt)
        data.append(wrappedMasterKey)
        data.append(encryptedDatabaseSize)
        data.appendBigEndian(data.crc32)
        precondition(data.count == Self.size, "vault header fields have the wrong sizes")
        return data
    }

    // MARK: - Keys

    /// Makes a header for a new vault, and the master key it wraps.
    ///
    /// `databaseSize` is what the app stores there: the length of the
    /// SQLCipher database that follows the header. A header made on its own,
    /// as the command-line tool does, records 0.
    public static func create(password: String, databaseSize: UInt64 = 0) throws -> (header: VaultHeader, masterKey: SecureBytes) {
        let masterKey = try SecureBytes.random(count: 32)
        let salt = try KeyDerivation.makeSalt()
        let passwordKey = try KeyDerivation.pbkdf2SHA256(password: password, salt: salt, iterations: KeyDerivation.vaultIterations)
        let header = VaultHeader(
            salt: salt,
            wrappedMasterKey: try masterKey.withUnsafeBytes { try AESGCM.seal($0, key: passwordKey) },
            encryptedDatabaseSize: try encryptDatabaseSize(databaseSize, masterKey: masterKey)
        )
        return (header, masterKey)
    }

    /// Unwraps the master key with `password`.
    ///
    /// Uses the round count the header records, and refuses one below the
    /// format's floor, so a doctored header cannot make a weak password
    /// cheaper to guess.
    public func unlock(password: String) throws -> SecureBytes {
        try checkIterations()
        let passwordKey = try KeyDerivation.pbkdf2SHA256(password: password, salt: salt, iterations: kdfIterations)
        do {
            return try AESGCM.unwrapKey(wrappedMasterKey, with: passwordKey)
        } catch ObscuraCryptoError.authenticationFailed {
            throw ObscuraCryptoError.wrongPassword
        }
    }

    /// The same master key under a new password and a fresh salt.
    ///
    /// Nothing else in the vault changes: the database and every media file
    /// stay encrypted with the master key they already use.
    public func changingPassword(from oldPassword: String, to newPassword: String) throws -> VaultHeader {
        let masterKey = try unlock(password: oldPassword)
        let newSalt = try KeyDerivation.makeSalt()
        let newPasswordKey = try KeyDerivation.pbkdf2SHA256(password: newPassword, salt: newSalt, iterations: KeyDerivation.vaultIterations)
        return VaultHeader(
            cipherSuite: cipherSuite,
            kdfIterations: KeyDerivation.vaultIterations,
            salt: newSalt,
            wrappedMasterKey: try masterKey.withUnsafeBytes { try AESGCM.seal($0, key: newPasswordKey) },
            encryptedDatabaseSize: encryptedDatabaseSize
        )
    }

    /// The length of the database that follows the header.
    public func databaseSize(masterKey: SecureBytes) throws -> UInt64 {
        try Self.decryptDatabaseSize(encryptedDatabaseSize, masterKey: masterKey)
    }

    /// This header with a different database length.
    public func settingDatabaseSize(_ size: UInt64, masterKey: SecureBytes) throws -> VaultHeader {
        VaultHeader(
            cipherSuite: cipherSuite,
            kdfIterations: kdfIterations,
            salt: salt,
            wrappedMasterKey: wrappedMasterKey,
            encryptedDatabaseSize: try Self.encryptDatabaseSize(size, masterKey: masterKey)
        )
    }

    /// A length sealed the way the header stores it: 8 bytes, AES-GCM with the
    /// master key.
    ///
    /// Little-endian, unlike every other number in the header: the app has
    /// always written this one in the device's native byte order, which on
    /// every Apple device it has run on is little-endian.
    public static func encryptDatabaseSize(_ size: UInt64, masterKey: SecureBytes) throws -> Data {
        try withUnsafeBytes(of: size.littleEndian) { try AESGCM.seal($0, key: masterKey) }
    }

    public static func decryptDatabaseSize(_ sealed: Data, masterKey: SecureBytes) throws -> UInt64 {
        let plaintext = try AESGCM.open(sealed, key: masterKey)
        guard plaintext.count == 8 else {
            throw ObscuraCryptoError.invalidVaultHeader("database length is not 8 bytes")
        }
        return plaintext.reversed().reduce(0) { $0 << 8 | UInt64($1) }
    }

    private func checkIterations() throws {
        guard kdfIterations >= KeyDerivation.vaultIterations else {
            throw ObscuraCryptoError.iterationsBelowMinimum(kdfIterations)
        }
        guard kdfIterations <= Self.maximumIterations else {
            throw ObscuraCryptoError.invalidVaultHeader("\(kdfIterations) key derivation rounds is implausibly many")
        }
    }
}
