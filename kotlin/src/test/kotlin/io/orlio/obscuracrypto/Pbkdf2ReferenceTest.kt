// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * The hand-written SHA-256 inside [Pbkdf2], held against the platform's HMAC:
 * the same PBKDF2 written the obvious way, a `Mac` in a loop. Also published
 * vectors through the Kotlin core, so it does not rest on the other engine.
 */
class Pbkdf2ReferenceTest : CryptoTestCase() {

    /** Password lengths either side of the 64-byte block, where HMAC hashes the key first, and salts of odd lengths. */
    @Test
    fun agreesWithHmacForEveryLengthThatMatters() {
        for (passwordLength in listOf(0, 1, 6, 31, 32, 55, 56, 63, 64, 65, 100, 128)) {
            for (saltLength in listOf(0, 1, 32, 33, 64)) {
                for (iterations in listOf(1, 2, 3, 1_000)) {
                    val password = randomBytes(passwordLength)
                    val salt = randomBytes(saltLength)
                    assertContentEquals(
                        Pbkdf2.derive(password, salt, iterations, Pbkdf2.Engine.MAC),
                        Pbkdf2.derive(password, salt, iterations, Pbkdf2.Engine.KOTLIN),
                        "password $passwordLength bytes, salt $saltLength bytes, $iterations rounds",
                    )
                }
            }
        }
    }

    @Test
    fun kotlinCoreMatchesThePublishedVectors() {
        fun derive(password: String, rounds: Int) = Fixtures.hex(
            Pbkdf2.derive(password.toByteArray(), "salt".toByteArray(), rounds, Pbkdf2.Engine.KOTLIN)
        )
        assertEquals("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", derive("password", 1))
        assertEquals("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43", derive("password", 2))
        assertEquals("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a", derive("password", 4096))
        assertEquals("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc", derive("passwd", 1))
    }

    @Test
    fun agreesWithHmacAtTheVaultRoundCount() {
        val password = "correct horse battery staple".toByteArray()
        val salt = randomBytes(32)
        assertContentEquals(
            Pbkdf2.derive(password, salt, KeyDerivation.VAULT_ITERATIONS, Pbkdf2.Engine.MAC),
            Pbkdf2.derive(password, salt, KeyDerivation.VAULT_ITERATIONS, Pbkdf2.Engine.KOTLIN),
        )
    }
}
