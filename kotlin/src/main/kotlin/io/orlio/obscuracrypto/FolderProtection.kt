// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.security.MessageDigest

/**
 * A folder password: what the app stores to turn a password into the key for
 * a folder's second encryption layer.
 *
 * A protected folder has its own random 32-byte key. Its media is encrypted
 * with the vault's master key first and then again with the folder key, so
 * opening it needs both. The folder key is wrapped with a key derived from the
 * folder password, the same way the vault header wraps the master key, at
 * 100,000 PBKDF2 rounds rather than 600,000 because it only ever sits behind
 * an unlocked vault.
 *
 * These three values are stored in the vault's database, base64-encoded.
 */
class FolderProtection(salt: ByteArray, passwordHash: ByteArray, wrappedFolderKey: ByteArray) {
    /** Salt for the folder password, 32 bytes. */
    val salt: ByteArray = salt.copyOf()

    /**
     * SHA-256 of the password key, checked before unwrapping so a wrong
     * password is reported as such.
     */
    val passwordHash: ByteArray = passwordHash.copyOf()

    /** The folder key wrapped with the password key (AES-GCM combined, 60 bytes). */
    val wrappedFolderKey: ByteArray = wrappedFolderKey.copyOf()

    init {
        if (salt.size != KeyDerivation.SALT_LENGTH) {
            throw ObscuraCryptoException.InvalidFolderProtection("salt is not 32 bytes")
        }
        if (passwordHash.size != 32) {
            throw ObscuraCryptoException.InvalidFolderProtection("password hash is not 32 bytes")
        }
        if (wrappedFolderKey.size != AesGcm.OVERHEAD + 32) {
            throw ObscuraCryptoException.InvalidFolderProtection("wrapped key is not 60 bytes")
        }
    }

    /** Unwraps the folder key with [password]. */
    fun unlock(password: String): SecureBytes {
        val passwordKey = KeyDerivation.pbkdf2SHA256(password, salt, KeyDerivation.FOLDER_ITERATIONS)
        try {
            if (!constantTimeEquals(hash(passwordKey), passwordHash)) throw ObscuraCryptoException.WrongPassword()
            try {
                return AesGcm.unwrapKey(wrappedFolderKey, passwordKey)
            } catch (e: ObscuraCryptoException.AuthenticationFailed) {
                throw ObscuraCryptoException.WrongPassword()
            }
        } finally {
            passwordKey.clear()
        }
    }

    class Created(val protection: FolderProtection, val folderKey: SecureBytes)

    companion object {
        /** Protection for a new folder, and the folder key it wraps. */
        fun create(password: String): Created {
            val folderKey = SecureBytes.random(32)
            val salt = KeyDerivation.makeSalt()
            val passwordKey = KeyDerivation.pbkdf2SHA256(password, salt, KeyDerivation.FOLDER_ITERATIONS)
            try {
                val protection = FolderProtection(
                    salt = salt,
                    passwordHash = hash(passwordKey),
                    wrappedFolderKey = folderKey.withBytes { AesGcm.seal(it, passwordKey) },
                )
                return Created(protection, folderKey)
            } finally {
                passwordKey.clear()
            }
        }

        private fun hash(key: SecureBytes): ByteArray =
            key.withBytes { MessageDigest.getInstance("SHA-256").digest(it) }
    }
}
