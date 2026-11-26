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
 * 600,000 PBKDF2 rounds. Folders protected before ObscuraCrypto 1.3.0 (Swift
 * 1.2.0) used 100,000; the count is not stored, so [unlock] tries both, and
 * such a folder keeps its count until its password is set again.
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

    /**
     * Unwraps the folder key with [password], at whichever of [READABLE_ITERATIONS] the folder was protected with. A wrong password
     * costs both derivations.
     */
    fun unlock(password: String): SecureBytes {
        for (iterations in READABLE_ITERATIONS) {
            val passwordKey = KeyDerivation.pbkdf2SHA256(password, salt, iterations)
            try {
                if (!constantTimeEquals(hash(passwordKey), passwordHash)) continue
                try {
                    return AesGcm.unwrapKey(wrappedFolderKey, passwordKey)
                } catch (e: ObscuraCryptoException.AuthenticationFailed) {
                    throw ObscuraCryptoException.WrongPassword()
                }
            } finally {
                passwordKey.clear()
            }
        }
        throw ObscuraCryptoException.WrongPassword()
    }

    class Created(val protection: FolderProtection, val folderKey: SecureBytes)

    companion object {
        /**
         * The rounds a folder password may have been set with: 100,000 before ObscuraCrypto 1.3.0 (Swift 1.2.0), 600,000 since. Tried in
         * this order, so folders from before open as fast as they always did.
         */
        internal val READABLE_ITERATIONS = listOf(KeyDerivation.LEGACY_FOLDER_ITERATIONS, KeyDerivation.FOLDER_ITERATIONS)

        /** Protection for a new folder, and the folder key it wraps. */
        fun create(password: String): Created = create(password, KeyDerivation.FOLDER_ITERATIONS)

        /** [create] with chosen rounds: the old count only for tests and fixtures that need a folder as earlier releases protected it. */
        internal fun create(password: String, iterations: Int): Created {
            val folderKey = SecureBytes.random(32)
            val salt = KeyDerivation.makeSalt()
            val passwordKey = KeyDerivation.pbkdf2SHA256(password, salt, iterations)
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
