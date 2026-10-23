// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * PBKDF2-HMAC-SHA256 with a SHA-256 compression function written out in
 * Kotlin. Not part of the library: it is here only so [Pbkdf2ReferenceTest]
 * can check the shipped loop (a `Mac` in a loop) against a second, independent
 * computation of the same arithmetic.
 */
object Pbkdf2InKotlin {
    private const val BLOCK = 64

    private val K = intArrayOf(
        0x428a2f98, 0x71374491, -0x4a3f0431, -0x164a245b, 0x3956c25b, 0x59f111f1, -0x6dc07d5c, -0x54e3a12b,
        -0x27f85568, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, -0x7f214e02, -0x6423f959, -0x3e640e8c,
        -0x1b64963f, -0x1041b87a, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        -0x67c1aeae, -0x57ce3993, -0x4ffcd838, -0x40a68039, -0x391ff40d, -0x2a586eb9, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, -0x7e3d36d2, -0x6d8dd37b,
        -0x5d40175f, -0x57e599b5, -0x3db47490, -0x3893ae5d, -0x2e6d17e7, -0x2966f9dc, -0x0bf1ca7b, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, -0x7b3787ec, -0x7338fdf8, -0x6f410006, -0x5baf9315, -0x41065c09, -0x398e870e,
    )

    private val INITIAL = intArrayOf(
        0x6a09e667, -0x4498517b, 0x3c6ef372, -0x5ab00ac6, 0x510e527f, -0x64fa9774, 0x1f83d9ab, 0x5be0cd19,
    )

    fun derive(passwordBytes: ByteArray, salt: ByteArray, iterations: Int): ByteArray {
        // The HMAC key is the password, hashed first if it is longer than a
        // block, then padded with zeros to one.
        val key = ByteArray(BLOCK)
        val reduced = if (passwordBytes.size > BLOCK) MessageDigest.getInstance("SHA-256").digest(passwordBytes) else passwordBytes
        System.arraycopy(reduced, 0, key, 0, reduced.size)

        // The first round, U1 = HMAC(password, salt || 00 00 00 01), takes a
        // message of any length, so it goes through the platform once.
        val first = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(if (passwordBytes.isEmpty()) ByteArray(1) else passwordBytes, "HmacSHA256"))
            update(salt)
            update(byteArrayOf(0, 0, 0, 1))
            doFinal()
        }

        // The pad blocks are absorbed once. Every later round is then two
        // compressions: the previous output through the inner state, and that
        // through the outer state.
        val innerState = INITIAL.copyOf()
        val outerState = INITIAL.copyOf()
        val words = IntArray(64)
        for (i in 0 until 16) words[i] = wordAt(key, i * 4) xor 0x36363636
        compress(innerState, words, innerState)
        for (i in 0 until 16) words[i] = wordAt(key, i * 4) xor 0x5c5c5c5c
        compress(outerState, words, outerState)
        key.fill(0)

        val u = IntArray(8) { wordAt(first, it * 4) }
        val t = u.copyOf()
        val scratch = IntArray(8)
        for (round in 1 until iterations) {
            loadPaddedDigest(words, u)
            compress(innerState, words, scratch)
            loadPaddedDigest(words, scratch)
            compress(outerState, words, u)
            for (i in 0 until 8) t[i] = t[i] xor u[i]
        }

        val out = ByteArray(32)
        for (i in 0 until 8) {
            out[i * 4] = (t[i] ushr 24).toByte()
            out[i * 4 + 1] = (t[i] ushr 16).toByte()
            out[i * 4 + 2] = (t[i] ushr 8).toByte()
            out[i * 4 + 3] = t[i].toByte()
        }
        words.fill(0)
        u.fill(0)
        t.fill(0)
        scratch.fill(0)
        first.fill(0)
        return out
    }

    /**
     * A 32-byte digest as the first half of a block that ends the message: the
     * padding for 64 bytes already hashed plus these 32 is a 1 bit, zeros, and
     * the length 96 * 8 = 768.
     */
    private fun loadPaddedDigest(words: IntArray, digest: IntArray) {
        System.arraycopy(digest, 0, words, 0, 8)
        words[8] = Int.MIN_VALUE
        for (i in 9..14) words[i] = 0
        words[15] = 768
    }

    private fun wordAt(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF shl 24) or (bytes[offset + 1].toInt() and 0xFF shl 16) or
            (bytes[offset + 2].toInt() and 0xFF shl 8) or (bytes[offset + 3].toInt() and 0xFF)

    /** One SHA-256 compression of the block in `w[0..15]` into [state], written to [out] (which may be [state]). */
    private fun compress(state: IntArray, w: IntArray, out: IntArray) {
        for (i in 16 until 64) {
            val x = w[i - 15]
            val y = w[i - 2]
            val s0 = x.rotateRight(7) xor x.rotateRight(18) xor (x ushr 3)
            val s1 = y.rotateRight(17) xor y.rotateRight(19) xor (y ushr 10)
            w[i] = w[i - 16] + s0 + w[i - 7] + s1
        }
        var a = state[0]
        var b = state[1]
        var c = state[2]
        var d = state[3]
        var e = state[4]
        var f = state[5]
        var g = state[6]
        var h = state[7]
        for (i in 0 until 64) {
            val t1 = h + (e.rotateRight(6) xor e.rotateRight(11) xor e.rotateRight(25)) +
                ((e and f) xor (e.inv() and g)) + K[i] + w[i]
            val t2 = (a.rotateRight(2) xor a.rotateRight(13) xor a.rotateRight(22)) +
                ((a and b) xor (a and c) xor (b and c))
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2
        }
        out[0] = state[0] + a
        out[1] = state[1] + b
        out[2] = state[2] + c
        out[3] = state[3] + d
        out[4] = state[4] + e
        out[5] = state[5] + f
        out[6] = state[6] + g
        out[7] = state[7] + h
    }
}
