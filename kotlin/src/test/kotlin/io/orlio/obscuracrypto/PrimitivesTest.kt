// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.security.Security
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class PrimitivesTest : CryptoTestCase() {

    private fun hex(key: SecureBytes) = key.withBytes { Fixtures.hex(it) }

    private fun fromHex(text: String) = ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun theSuiteRunsUnderTheProviderItClaims() {
        val expected = if (TestProvider.name == "conscrypt") "Conscrypt" else "SunJCE"
        assertEquals(expected, TestProvider.activeAesProvider())
    }

    /** PBKDF2-HMAC-SHA256 with published inputs and output (RFC 7914, section 11). */
    @Test
    fun pbkdf2MatchesPublishedVector() {
        val key = KeyDerivation.pbkdf2SHA256("passwd", "salt".toByteArray(), 1)
        assertEquals("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc", hex(key))
    }

    /** The widely published PBKDF2-HMAC-SHA256 vectors for "password" and "salt". */
    @Test
    fun pbkdf2MatchesTheCommonSha256Vectors() {
        fun derive(rounds: Int) = hex(KeyDerivation.pbkdf2SHA256("password", "salt".toByteArray(), rounds))
        assertEquals("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", derive(1))
        assertEquals("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43", derive(2))
        assertEquals("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a", derive(4096))
    }

    /** At the real round count, against the JDK's own PBKDF2, with accented and non-Latin text. */
    @Test
    fun pbkdf2AgreesWithTheJdkAtTheVaultRoundCount() {
        val salt = ByteArray(32) { it.toByte() }
        for (password in listOf("correct horse battery staple", "pässwörd-日本語-🔐")) {
            val ours = KeyDerivation.pbkdf2SHA256(password, salt, KeyDerivation.VAULT_ITERATIONS)
            val jdk = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(PBEKeySpec(password.toCharArray(), salt, KeyDerivation.VAULT_ITERATIONS, 256)).encoded
            assertContentEquals(jdk, ours.toByteArray(), password)
        }
    }

    /** Two ways of typing the same accented letter are different bytes, so different keys, as on iOS. */
    @Test
    fun passwordsAreUsedAsUtf8WithoutNormalisation() {
        val precomposed = "café pass"
        val decomposed = "café pass"
        val salt = ByteArray(32) { 7 }
        val a = KeyDerivation.pbkdf2SHA256(precomposed, salt, 10)
        val b = KeyDerivation.pbkdf2SHA256(decomposed, salt, 10)
        assertFalse(a.contentEquals(b))
        assertContentEquals(
            precomposed.toByteArray(Charsets.UTF_8),
            byteArrayOf(*"caf".toByteArray(), 0xC3.toByte(), 0xA9.toByte(), *" pass".toByteArray()),
        )
    }

    @Test
    fun anEmptyPasswordWorksAndEqualsOneZeroByte() {
        val salt = "salt".toByteArray()
        val empty = KeyDerivation.pbkdf2SHA256("", salt, 3)
        val zero = KeyDerivation.pbkdf2SHA256(byteArrayOf(0), salt, 3)
        assertTrue(empty.contentEquals(zero))
    }

    @OptIn(KeyDerivation.TestingOnly::class)
    @Test
    fun anInstalledImplementationIsUsedByEveryDerivation() {
        try {
            var calls = 0
            KeyDerivation.overrideForTesting { password, salt, rounds ->
                calls += 1
                Pbkdf2InKotlin.derive(password, salt, rounds)
            }
            val header = VaultHeader.create("secret password", 1).header
            header.unlock("secret password")
            KeyDerivation.pbkdf2SHA256("x", ByteArray(32), 5)
            assertEquals(3, calls)
            KeyDerivation.overrideForTesting { _, _, _ -> ByteArray(31) }
            assertFailsWith<ObscuraCryptoException.KeyDerivationFailed> { KeyDerivation.pbkdf2SHA256("x", ByteArray(32), 5) }
        } finally {
            KeyDerivation.overrideForTesting(null)
        }
    }

    @OptIn(KeyDerivation.TestingOnly::class)
    @Test
    fun installingIsSetOnceAndRefusedAfterUse() {
        try {
            KeyDerivation.overrideForTesting(null)
            val first = KeyDerivation.Pbkdf2Function { password, salt, rounds -> Pbkdf2.derive(password, salt, rounds) }
            KeyDerivation.install(first)
            KeyDerivation.install(first) // the same function again is fine
            assertFailsWith<IllegalStateException> {
                KeyDerivation.install(KeyDerivation.Pbkdf2Function { password, salt, rounds -> Pbkdf2.derive(password, salt, rounds) })
            }

            KeyDerivation.overrideForTesting(null)
            KeyDerivation.pbkdf2SHA256("x", ByteArray(32), 5)
            assertFailsWith<IllegalStateException> { KeyDerivation.install(first) }
        } finally {
            KeyDerivation.overrideForTesting(null)
        }
    }

    @Test
    fun zeroRoundsIsRefused() {
        assertFailsWith<ObscuraCryptoException.KeyDerivationFailed> {
            KeyDerivation.pbkdf2SHA256("x", ByteArray(32), 0)
        }
    }

    @Test
    fun crc32MatchesTheStandardCheckValue() {
        assertEquals(0xCBF4_3926L, crc32("123456789".toByteArray()))
    }

    /** NIST GCM test cases 13 and 14 (AES-256, zero key, zero nonce). */
    @Test
    fun gcmMatchesTheNistVectors() {
        val key = SecureBytes(32)
        val nonce = ByteArray(12)

        val empty = AesGcm.seal(ByteArray(0), key.secretKey(), nonce)
        assertEquals("530f8afbc74536b9a963b4f1c4cb738b", Fixtures.hex(empty.copyOfRange(12, 28)))

        val sealed = AesGcm.seal(ByteArray(16), key.secretKey(), nonce)
        assertEquals("cea7403d4d606b6e074ec5d3baf39d18", Fixtures.hex(sealed.copyOfRange(12, 28)))
        assertEquals("d0d1c8a799996bf0265b98b5d48ab919", Fixtures.hex(sealed.copyOfRange(28, 44)))
        assertContentEquals(ByteArray(16), AesGcm.open(sealed, key))
        assertContentEquals(fromHex("000000000000000000000000"), sealed.copyOf(12))
    }

    @Test
    fun sealAndOpen() {
        val key = randomKey()
        val sealed = AesGcm.seal("hello".toByteArray(), key)
        assertEquals(5 + AesGcm.OVERHEAD, sealed.size)
        assertContentEquals("hello".toByteArray(), AesGcm.open(sealed, key))
    }

    @Test
    fun everySealUsesAFreshNonce() {
        val key = randomKey()
        val first = AesGcm.seal("same".toByteArray(), key)
        val second = AesGcm.seal("same".toByteArray(), key)
        assertFalse(first.copyOf(12).contentEquals(second.copyOf(12)))
    }

    @Test
    fun alteredCiphertextIsRejected() {
        val key = randomKey()
        val sealed = AesGcm.seal("hello".toByteArray(), key)
        sealed[AesGcm.NONCE_SIZE] = (sealed[AesGcm.NONCE_SIZE].toInt() xor 1).toByte()
        assertRefused<ObscuraCryptoException.AuthenticationFailed> { AesGcm.open(sealed, key) }
    }

    @Test
    fun wrongKeyIsRejected() {
        val sealed = AesGcm.seal("hello".toByteArray(), randomKey())
        assertRefused<ObscuraCryptoException.AuthenticationFailed> { AesGcm.open(sealed, randomKey()) }
    }

    @Test
    fun tooShortAMessageIsRejectedNotACrash() {
        assertRefused<ObscuraCryptoException.AuthenticationFailed> { AesGcm.open(ByteArray(27), randomKey()) }
    }

    @Test
    fun shortKeyIsRejected() {
        val error = assertRefused<ObscuraCryptoException.InvalidKeyLength> { AesGcm.seal(ByteArray(0), SecureBytes(16)) }
        assertEquals(16, error.length)
    }

    @Test
    fun clearZeroesTheBytes() {
        val key = randomKey()
        key.clear()
        assertTrue(key.withBytes { bytes -> bytes.all { it == 0.toByte() } })
    }

    @Test
    fun keysCompareByContent() {
        val key = randomKey()
        val copy = SecureBytes.copying(key.toByteArray())
        assertTrue(key.contentEquals(copy))
        assertFalse(key.contentEquals(randomKey()))
    }

    @Test
    fun randomIsNotConstant() {
        assertNotEquals(SecureBytes.random(32).fingerprint, SecureBytes.random(32).fingerprint)
        assertTrue(Security.getProviders().isNotEmpty())
    }
}
