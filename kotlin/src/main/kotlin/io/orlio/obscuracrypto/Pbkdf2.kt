// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * PBKDF2-HMAC-SHA256 for one 32-byte output block: `Mac("HmacSHA256")` in a
 * loop, every primitive from the platform.
 *
 * Under Conscrypt each of the 1.2 million `update`/`doFinal` calls of a vault
 * login crosses into native code, which is why Android installs a native
 * derivation instead (see [KeyDerivation.install]). A hand-written SHA-256 was
 * tried as the alternative and removed: it is only in the test sources now, as
 * an independent check of this loop.
 */
object Pbkdf2 {
    fun derive(passwordBytes: ByteArray, salt: ByteArray, iterations: Int): ByteArray =
        deriveWithMac(passwordBytes, salt, iterations)

    private fun deriveWithMac(passwordBytes: ByteArray, salt: ByteArray, iterations: Int): ByteArray {
        // HMAC pads its key with zeros, so an empty key is the same as one zero
        // byte; `SecretKeySpec` refuses an empty array.
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(if (passwordBytes.isEmpty()) ByteArray(1) else passwordBytes, "HmacSHA256"))
        mac.update(salt)
        mac.update(byteArrayOf(0, 0, 0, 1))
        val u = mac.doFinal()
        val t = u.copyOf()
        for (round in 1 until iterations) {
            mac.update(u)
            mac.doFinal(u, 0)
            for (i in 0 until 32) t[i] = (t[i].toInt() xor u[i].toInt()).toByte()
        }
        u.fill(0)
        return t
    }
}
