// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.security.GeneralSecurityException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** PBKDF2-HMAC-SHA256, the only password-based key derivation Obscura uses. */
object KeyDerivation {
    /** Rounds for vault passwords. The format refuses anything lower. */
    const val VAULT_ITERATIONS = 600_000

    /** Rounds for folder passwords, which sit behind the vault password. */
    const val FOLDER_ITERATIONS = 100_000

    const val KEY_LENGTH = 32
    const val SALT_LENGTH = 32

    /**
     * Derives a 32-byte key.
     *
     * The password is used as its UTF-8 bytes with no Unicode normalisation,
     * as the iOS app has always done, so a password typed with a different
     * composition of the same accented character derives a different key.
     */
    fun pbkdf2SHA256(password: String, salt: ByteArray, iterations: Int): SecureBytes {
        val passwordBytes = password.toByteArray(Charsets.UTF_8)
        try {
            return pbkdf2SHA256(passwordBytes, salt, iterations)
        } finally {
            passwordBytes.fill(0)
        }
    }

    /**
     * The same, from the password as explicit bytes, so there is no question
     * which text encoding a provider applies to a `CharArray`. The one block
     * of 32 bytes is computed by [Pbkdf2], which does not depend on the
     * platform's HMAC speed. Tests check it against published vectors and
     * against SunJCE's own PBKDF2.
     */
    fun pbkdf2SHA256(passwordBytes: ByteArray, salt: ByteArray, iterations: Int): SecureBytes {
        if (iterations <= 0) throw ObscuraCryptoException.KeyDerivationFailed()
        val derived = implementation.derive(passwordBytes, salt, iterations)
        try {
            if (derived.size != KEY_LENGTH) throw ObscuraCryptoException.KeyDerivationFailed()
            return SecureBytes.copying(derived)
        } finally {
            derived.fill(0)
        }
    }

    /**
     * Computes PBKDF2-HMAC-SHA256 into 32 bytes. The library's own is used
     * unless the app installs another, which Android does at start-up with a
     * native one, because no pure-JVM path is fast enough there (a vault login
     * derives ten keys). Whatever is installed is held to the same published
     * vectors and fixtures; nothing else about the format depends on it.
     */
    fun interface Pbkdf2Function {
        fun derive(passwordBytes: ByteArray, salt: ByteArray, iterations: Int): ByteArray
    }

    /** Set once, before the first derivation. */
    @Volatile
    var implementation: Pbkdf2Function = Pbkdf2Function { password, salt, rounds -> Pbkdf2.derive(password, salt, rounds) }

    /** A fresh random 32-byte salt. */
    fun makeSalt(): ByteArray = Random.bytes(SALT_LENGTH)
}

/**
 * AES-256-GCM in the layout every Obscura format uses: the "combined"
 * representation, `nonce (12) || ciphertext || tag (16)`.
 */
object AesGcm {
    const val NONCE_SIZE = 12
    const val TAG_SIZE = 16

    /** Bytes added to every sealed message. */
    const val OVERHEAD = NONCE_SIZE + TAG_SIZE

    /** Seals with a fresh random nonce. */
    fun seal(plaintext: ByteArray, key: SecureBytes): ByteArray {
        checkKey(key)
        return seal(plaintext, key.secretKey(), Random.bytes(NONCE_SIZE))
    }

    fun open(combined: ByteArray, key: SecureBytes): ByteArray {
        checkKey(key)
        return open(combined, key.secretKey())
    }

    internal fun seal(plaintext: ByteArray, key: SecretKeySpec, nonce: ByteArray): ByteArray {
        require(nonce.size == NONCE_SIZE)
        // A new Cipher every time: the JCA refuses to encrypt twice under one
        // key and nonce on the same instance, which is a safety, not a limit.
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_SIZE * 8, nonce))
        val out = ByteArray(NONCE_SIZE + plaintext.size + TAG_SIZE)
        System.arraycopy(nonce, 0, out, 0, NONCE_SIZE)
        cipher.doFinal(plaintext, 0, plaintext.size, out, NONCE_SIZE)
        return out
    }

    internal fun open(combined: ByteArray, key: SecretKeySpec): ByteArray {
        if (combined.size < OVERHEAD) throw ObscuraCryptoException.AuthenticationFailed()
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_SIZE * 8, combined, 0, NONCE_SIZE))
            cipher.doFinal(combined, NONCE_SIZE, combined.size - NONCE_SIZE)
        } catch (e: AEADBadTagException) {
            throw ObscuraCryptoException.AuthenticationFailed()
        } catch (e: GeneralSecurityException) {
            throw ObscuraCryptoException.AuthenticationFailed()
        }
    }

    /**
     * Opens a wrapped key straight into [SecureBytes], overwriting the
     * plaintext copy the JCA returned as soon as the key is in its own buffer.
     */
    internal fun unwrapKey(wrapped: ByteArray, key: SecureBytes): SecureBytes {
        val plaintext = open(wrapped, key)
        try {
            return SecureBytes.copying(plaintext)
        } finally {
            plaintext.fill(0)
        }
    }

    internal fun checkKey(key: SecureBytes) {
        if (key.count != 32) throw ObscuraCryptoException.InvalidKeyLength(key.count)
    }
}
