// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec

/**
 * Key material that is zeroed when it is closed.
 *
 * Held in one array this class owns and never copies. Close it as soon as the
 * key is no longer needed; it is also zeroed by [clear].
 *
 * This is weaker than the Swift package's `SecureBytes`, and says so: the JVM
 * gives no promise that the garbage collector has not moved the array before
 * it is zeroed, and the JCA copies a key into its own cipher state, which this
 * class cannot reach. Zeroing limits how long a key sits in memory; it does
 * not prove no other copy exists.
 */
class SecureBytes private constructor(private val buffer: ByteArray) : AutoCloseable {

    val count: Int get() = buffer.size

    /** Zero-filled bytes of the given length. */
    constructor(count: Int) : this(ByteArray(count).also { require(count >= 0) })

    /** Runs [body] with the key bytes. [body] must not keep a reference to the array. */
    fun <R> withBytes(body: (ByteArray) -> R): R = body(buffer)

    /** A copy of the bytes. The caller owns it and should zero it after use. */
    fun toByteArray(): ByteArray = buffer.copyOf()

    /** Overwrites the bytes with zeros. */
    fun clear() {
        buffer.fill(0)
    }

    override fun close() = clear()

    /**
     * The first 8 bytes of SHA-256 over the key, in hex.
     *
     * Safe to show: a truncated one-way hash says nothing useful about the
     * key, but it lets two tools confirm they unwrapped the same one.
     */
    val fingerprint: String
        get() = MessageDigest.getInstance("SHA-256").digest(buffer)
            .take(8).joinToString("") { "%02x".format(it) }

    /** Constant-time comparison, so it does not leak where two keys first differ. */
    fun contentEquals(other: SecureBytes): Boolean = constantTimeEquals(buffer, other.buffer)

    internal fun secretKey(algorithm: String = "AES"): SecretKeySpec = SecretKeySpec(buffer, algorithm)

    companion object {
        /** A copy of `bytes[offset until offset + length]`. The caller keeps its own copy. */
        fun copying(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset): SecureBytes =
            SecureBytes(bytes.copyOfRange(offset, offset + length))

        /** Cryptographically random bytes from the system generator. */
        fun random(count: Int): SecureBytes {
            val bytes = ByteArray(count)
            Random.generator.nextBytes(bytes)
            return SecureBytes(bytes)
        }
    }
}

/** The one source of randomness: the platform's default, never seeded by us. */
internal object Random {
    val generator = SecureRandom()

    /** Random bytes that are not secret, such as salts and nonce prefixes. */
    fun bytes(count: Int): ByteArray = ByteArray(count).also { generator.nextBytes(it) }
}
