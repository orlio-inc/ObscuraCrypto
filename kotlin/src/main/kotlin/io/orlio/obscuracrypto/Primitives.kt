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

    /**
     * Rounds for folder passwords set from ObscuraCrypto 1.3.0 (Swift 1.2.0) on: the same as a vault's. Someone who has the vault open can
     * copy a folder's lock and guess at it offline, and that is who a folder password is for.
     */
    const val FOLDER_ITERATIONS = 600_000

    /** Rounds for folder passwords set before: still read, never written. */
    const val LEGACY_FOLDER_ITERATIONS = 100_000

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
        val derived = active().derive(passwordBytes, salt, iterations)
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

    private val builtIn = Pbkdf2Function { password, salt, rounds -> Pbkdf2.derive(password, salt, rounds) }

    private val lock = Any()
    private var installed: Pbkdf2Function? = null
    private var used = false

    /**
     * Replaces the key derivation, once. Installing the same function again is
     * allowed; a different one, or any install after the first derivation, is
     * refused, so nothing can swap in a weaker derivation while vaults are open.
     *
     * The function is first checked against the library's own on two small
     * inputs, and against a published answer at 65,537 rounds (past any
     * 16-bit round counter), and refused if its answers differ, so a native
     * library that is broken on some device fails at start-up instead of
     * deriving keys that open nothing, or the same key for every password.
     */
    fun install(function: Pbkdf2Function) {
        synchronized(lock) {
            if (installed !== function) checkAgreesWithBuiltIn(function)
            check(installed == null || installed === function) { "A different key derivation is already installed" }
            check(installed != null || !used) { "Key derivation was already used; install before the first vault is opened" }
            installed = function
        }
    }

    private fun checkAgreesWithBuiltIn(function: Pbkdf2Function) {
        val checks = listOf(Triple("password", "NaCl".toByteArray().copyOf(SALT_LENGTH), 1), Triple("Obscura self-test", ByteArray(SALT_LENGTH) { it.toByte() }, 2_048))
        for ((password, salt, rounds) in checks) {
            val bytes = password.toByteArray(Charsets.UTF_8)
            val expected = Pbkdf2.derive(bytes, salt, rounds)
            val actual = try { function.derive(bytes, salt, rounds) } catch (e: Exception) { null }
            val agrees = actual != null && constantTimeEquals(expected, actual)
            expected.fill(0)
            actual?.fill(0)
            check(agrees) { "The key derivation to install does not compute PBKDF2-HMAC-SHA256" }
        }
        // Checked against a fixed answer rather than the library's own, which
        // is slow on a phone at this count.
        val password = "Obscura self-test".toByteArray(Charsets.UTF_8)
        val actual = try { function.derive(password, ByteArray(SALT_LENGTH) { it.toByte() }, 65_537) } catch (e: Exception) { null }
        val agrees = actual != null && constantTimeEquals(MANY_ROUNDS_ANSWER, actual)
        actual?.fill(0)
        check(agrees) { "The key derivation to install does not compute PBKDF2-HMAC-SHA256 at many rounds" }
    }

    /** PBKDF2-HMAC-SHA256("Obscura self-test", bytes 0 to 31, 65,537 rounds), from Python's hashlib. */
    private val MANY_ROUNDS_ANSWER = "b833a0be9869b8205617cdbbd831edb0ccb00e85577aafbcf90457270f87a5fc"
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun active(): Pbkdf2Function = synchronized(lock) {
        used = true
        installed ?: builtIn
    }

    /** Marks the functions that exist only for a project's own tests. */
    @RequiresOptIn("For tests only: replaces the key derivation without the set-once checks.", RequiresOptIn.Level.ERROR)
    annotation class TestingOnly

    /** The derivation in use, for a test that wraps it. */
    @TestingOnly
    fun currentForTesting(): Pbkdf2Function = synchronized(lock) { installed ?: builtIn }

    /** Swaps the derivation with no checks and forgets that one was used; `null` restores the library's own. */
    @TestingOnly
    fun overrideForTesting(function: Pbkdf2Function?) {
        synchronized(lock) {
            installed = function
            used = false
        }
    }

    /** A fresh random 32-byte salt. */
    fun makeSalt(): ByteArray = Random.bytes(SALT_LENGTH)

    /**
     * A 32-byte key for one job, derived from [key] and named by [info]: HKDF-SHA256 with a salt of 32 zero bytes.
     *
     * Version 2 exports and shared items files never use the key a password or a random draw gives them as it is. The key their
     * records are sealed with and their key commitment are each derived from it this way, under different names, so no key is both an
     * AES-GCM key and an HMAC key. The caller zeroes the result.
     */
    internal fun subkey(key: SecureBytes, info: ByteArray): ByteArray =
        key.withBytes { ChunkedMediaCipher.hkdfSha256(it, ByteArray(SALT_LENGTH), info, KEY_LENGTH) }

    /** [subkey] as an AES key for the JCA, which keeps its own copy. */
    internal fun subkeySpec(key: SecureBytes, info: ByteArray): SecretKeySpec {
        val bytes = subkey(key, info)
        return try { SecretKeySpec(bytes, "AES") } finally { bytes.fill(0) }
    }
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

    /**
     * [associatedData] is covered by the tag but not carried in the message.
     * `.obscurashared` files and version 2 exports use it.
     */
    internal fun seal(plaintext: ByteArray, key: SecretKeySpec, nonce: ByteArray, associatedData: ByteArray? = null): ByteArray {
        require(nonce.size == NONCE_SIZE)
        // A new Cipher every time: the JCA refuses to encrypt twice under one
        // key and nonce on the same instance, which is a safety, not a limit.
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_SIZE * 8, nonce))
        if (associatedData != null) cipher.updateAAD(associatedData)
        val out = ByteArray(NONCE_SIZE + plaintext.size + TAG_SIZE)
        System.arraycopy(nonce, 0, out, 0, NONCE_SIZE)
        cipher.doFinal(plaintext, 0, plaintext.size, out, NONCE_SIZE)
        return out
    }

    internal fun open(combined: ByteArray, key: SecretKeySpec, associatedData: ByteArray? = null): ByteArray {
        if (combined.size < OVERHEAD) throw ObscuraCryptoException.AuthenticationFailed()
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_SIZE * 8, combined, 0, NONCE_SIZE))
            if (associatedData != null) cipher.updateAAD(associatedData)
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
