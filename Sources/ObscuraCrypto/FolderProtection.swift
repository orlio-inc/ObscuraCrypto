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
/// at 600,000 PBKDF2 rounds. Folders protected before ObscuraCrypto 1.2.0
/// (Kotlin 1.3.0) used 100,000; the count is not stored, so `unlock` tries
/// both, and such a folder keeps its count until its password is set again.
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

    /// The rounds a folder password may have been set with: 100,000 before
    /// ObscuraCrypto 1.2.0 (Kotlin 1.3.0), 600,000 since. Tried in this
    /// order, so folders from before open as fast as they always did.
    static let readableIterations = [KeyDerivation.legacyFolderIterations, KeyDerivation.folderIterations]

    /// Protection for a new folder, and the folder key it wraps.
    public static func create(password: String) throws -> (protection: FolderProtection, folderKey: SecureBytes) {
        try create(password: password, iterations: KeyDerivation.folderIterations)
    }

    /// `create` with chosen rounds: the old count only for tests and
    /// fixtures that need a folder as earlier releases protected it.
    static func create(password: String, iterations: UInt32) throws -> (protection: FolderProtection, folderKey: SecureBytes) {
        let folderKey = try SecureBytes.random(count: 32)
        let salt = try KeyDerivation.makeSalt()
        let passwordKey = try KeyDerivation.pbkdf2SHA256(password: password, salt: salt, iterations: iterations)
        let protection = try FolderProtection(
            salt: salt,
            passwordHash: try passwordKey.withKeyBytes { Data(SHA256.hash(data: $0)) },
            wrappedFolderKey: try folderKey.withKeyBytes { try AESGCM.seal($0, key: passwordKey) }
        )
        return (protection, folderKey)
    }

    /// Unwraps the folder key with `password`, at whichever of the
    /// `readableIterations` the folder was protected with. A wrong password
    /// costs both derivations.
    public func unlock(password: String) throws -> SecureBytes {
        for iterations in Self.readableIterations {
            let passwordKey = try KeyDerivation.pbkdf2SHA256(password: password, salt: salt, iterations: iterations)
            let hash = try passwordKey.withKeyBytes { Data(SHA256.hash(data: $0)) }
            guard constantTimeEquals(hash, passwordHash) else { continue }
            do {
                return try AESGCM.unwrapKey(wrappedFolderKey, with: passwordKey)
            } catch ObscuraCryptoError.authenticationFailed {
                throw ObscuraCryptoError.wrongPassword
            }
        }
        throw ObscuraCryptoError.wrongPassword
    }
}
