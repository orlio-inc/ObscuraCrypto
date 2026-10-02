// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CryptoKit
import Foundation

/// A folder password: what the app stores to turn a password into the key
/// for a folder's second encryption layer.
///
/// A protected folder has its own random 32-byte key. Its media is encrypted
/// with the vault's master key first and then again with the folder key, so
/// opening it needs both. The folder key is wrapped with a key derived from
/// the folder password, the same way the vault header wraps the master key,
/// at 100,000 PBKDF2 rounds rather than 600,000 because it only ever sits
/// behind an unlocked vault.
///
/// These three values are stored in the vault's database, base64-encoded.
public struct FolderProtection: Sendable, Equatable {
    /// Salt for the folder password, 32 bytes.
    public let salt: Data
    /// SHA-256 of the password key, checked before unwrapping so a wrong
    /// password is reported as such.
    public let passwordHash: Data
    /// The folder key wrapped with the password key (AES-GCM combined, 60 bytes).
    public let wrappedFolderKey: Data

    public init(salt: Data, passwordHash: Data, wrappedFolderKey: Data) throws {
        guard salt.count == KeyDerivation.saltLength else {
            throw ObscuraCryptoError.invalidFolderProtection("salt is not 32 bytes")
        }
        guard passwordHash.count == SHA256.byteCount else {
            throw ObscuraCryptoError.invalidFolderProtection("password hash is not 32 bytes")
        }
        guard wrappedFolderKey.count == AESGCM.overhead + 32 else {
            throw ObscuraCryptoError.invalidFolderProtection("wrapped key is not 60 bytes")
        }
        self.salt = salt
        self.passwordHash = passwordHash
        self.wrappedFolderKey = wrappedFolderKey
    }

    /// Protection for a new folder, and the folder key it wraps.
    public static func create(password: String) throws -> (protection: FolderProtection, folderKey: SecureBytes) {
        let folderKey = try SecureBytes.random(count: 32)
        let salt = try KeyDerivation.makeSalt()
        let passwordKey = try KeyDerivation.pbkdf2SHA256(password: password, salt: salt, iterations: KeyDerivation.folderIterations)
        let protection = try FolderProtection(
            salt: salt,
            passwordHash: passwordKey.withUnsafeBytes { Data(SHA256.hash(data: $0)) },
            wrappedFolderKey: try folderKey.withUnsafeBytes { try AESGCM.seal($0, key: passwordKey) }
        )
        return (protection, folderKey)
    }

    /// Unwraps the folder key with `password`.
    public func unlock(password: String) throws -> SecureBytes {
        let passwordKey = try KeyDerivation.pbkdf2SHA256(password: password, salt: salt, iterations: KeyDerivation.folderIterations)
        let hash = passwordKey.withUnsafeBytes { Data(SHA256.hash(data: $0)) }
        guard constantTimeEquals(hash, passwordHash) else {
            throw ObscuraCryptoError.wrongPassword
        }
        do {
            return try AESGCM.unwrapKey(wrappedFolderKey, with: passwordKey)
        } catch ObscuraCryptoError.authenticationFailed {
            throw ObscuraCryptoError.wrongPassword
        }
    }
}
