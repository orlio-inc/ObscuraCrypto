// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** The same checks as the Swift package's `RecoveryPhraseTests`. */
class RecoveryPhraseTest : CryptoTestCase() {

    /**
     * The 256-bit vectors from BIP-39's reference test set (trezor/python-mnemonic
     * vectors.json), entropy to words. The seed half of those vectors does not
     * apply: a recovery phrase is never stretched into a seed.
     */
    private val vectors = listOf(
        "00".repeat(32) to "abandon ".repeat(23) + "art",
        "7f".repeat(32) to "legal winner thank year wave sausage worth useful ".repeat(2) +
            "legal winner thank year wave sausage worth title",
        "80".repeat(32) to "letter advice cage absurd amount doctor acoustic avoid ".repeat(2) +
            "letter advice cage absurd amount doctor acoustic bless",
        "ff".repeat(32) to "zoo ".repeat(23) + "vote",
        "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c" to
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863" to
            "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
        "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad" to
            "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
        "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f" to
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
    )

    private fun hexBytes(hex: String) = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun wordListIsThePublishedOne() {
        val file = RecoveryPhrase.words.joinToString("") { it + "\n" }
        val hash = Fixtures.hex(MessageDigest.getInstance("SHA-256").digest(file.toByteArray(Charsets.UTF_8)))
        assertEquals("2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda", hash)
        assertEquals(2048, RecoveryPhrase.words.size)
        assertEquals(2048, RecoveryPhrase.words.map { it.take(4) }.toSet().size, "every word must be identified by its first four letters")
    }

    @Test
    fun publishedVectorsEncode() {
        for ((entropy, phrase) in vectors) {
            assertEquals(phrase, RecoveryPhrase.words(SecureBytes.copying(hexBytes(entropy))).joinToString(" "))
        }
    }

    @Test
    fun publishedVectorsDecode() {
        for ((entropy, phrase) in vectors) {
            val key = RecoveryPhrase.masterKey(phrase.split(" "))
            assertTrue(key.contentEquals(SecureBytes.copying(hexBytes(entropy))), entropy)
        }
    }

    @Test
    fun randomKeysRoundTrip() {
        repeat(200) {
            val key = SecureBytes.random(32)
            val words = RecoveryPhrase.words(key)
            assertEquals(24, words.size)
            assertTrue(RecoveryPhrase.masterKey(words).contentEquals(key))
        }
    }

    @Test
    fun caseAndSurroundingSpaceAreIgnored() {
        val key = SecureBytes.random(32)
        val typed = RecoveryPhrase.words(key).map { " ${it.uppercase()}\n" }
        assertTrue(RecoveryPhrase.masterKey(typed).contentEquals(key))
    }

    /** Kotlin's lowercase() is locale-independent; a Turkish default locale must not turn I into dotless ı. */
    @Test
    fun aTurkishLocaleDoesNotChangeWords() {
        val saved = java.util.Locale.getDefault()
        try {
            java.util.Locale.setDefault(java.util.Locale.forLanguageTag("tr-TR"))
            assertEquals(RecoveryPhrase.indexOf("inside"), RecoveryPhrase.indexOf("INSIDE"))
        } finally {
            java.util.Locale.setDefault(saved)
        }
    }

    @Test
    fun wrongWordCountIsRefused() {
        val words = RecoveryPhrase.words(SecureBytes.random(32))
        assertEquals(
            ObscuraCryptoException.RecoveryPhraseWrongLength(23),
            assertFailsWith<ObscuraCryptoException.RecoveryPhraseWrongLength> { RecoveryPhrase.masterKey(words.dropLast(1)) },
        )
    }

    @Test
    fun aWordNotOnTheListIsNamedByPosition() {
        val words = RecoveryPhrase.words(SecureBytes.random(32)).toMutableList()
        words[6] = "abandn"
        val error = assertFailsWith<ObscuraCryptoException.RecoveryPhraseUnknownWord> { RecoveryPhrase.masterKey(words) }
        assertEquals(7, error.position)
    }

    @Test
    fun swappedWordsAreCaughtByTheChecksum() {
        val swapped = ("abandon ".repeat(23) + "art").split(" ").toMutableList()
        swapped[0] = swapped[23].also { swapped[23] = swapped[0] }
        assertFailsWith<ObscuraCryptoException.RecoveryPhraseChecksumMismatch> { RecoveryPhrase.masterKey(swapped) }
    }

    @Test
    fun onlyAThirtyTwoByteKeyIsEncoded() {
        val error = assertFailsWith<ObscuraCryptoException.InvalidKeyLength> { RecoveryPhrase.words(SecureBytes(16)) }
        assertEquals(16, error.length)
    }

    @Test
    fun completions() {
        assertEquals(listOf("abandon"), RecoveryPhrase.completions("aba"))
        assertEquals(listOf("zone", "zoo"), RecoveryPhrase.completions("Zo"))
        assertEquals(listOf("abandon", "ability"), RecoveryPhrase.completions("ab", limit = 2))
        assertEquals(emptyList(), RecoveryPhrase.completions(""))
        assertEquals(emptyList(), RecoveryPhrase.completions("qqq"))
    }

    // MARK: With a vault header

    @Test
    fun thePhraseOpensItsOwnVaultOnly() {
        val vault = VaultHeader.create("secret password", databaseSize = 7)
        val other = VaultHeader.create("secret password", databaseSize = 7)
        val recovered = RecoveryPhrase.masterKey(RecoveryPhrase.words(vault.masterKey))
        assertTrue(vault.header.opens(recovered))
        assertFalse(other.header.opens(recovered))
        assertFalse(vault.header.opens(other.masterKey))
    }

    @Test
    fun aNewPasswordFromThePhraseKeepsTheMasterKey() {
        val vault = VaultHeader.create("forgotten password", databaseSize = 9)
        val recovered = RecoveryPhrase.masterKey(RecoveryPhrase.words(vault.masterKey))

        val reset = VaultHeader.parse(vault.header.settingPassword("new password", recovered).serialized())
        assertTrue(reset.unlock("new password").contentEquals(vault.masterKey))
        assertEquals(9L, reset.databaseSize(vault.masterKey))
        assertNotEquals(Fixtures.hex(vault.header.salt), Fixtures.hex(reset.salt))
        assertFailsWith<ObscuraCryptoException.WrongPassword> { reset.unlock("forgotten password") }
        assertTrue(reset.opens(recovered), "a password change leaves the phrase valid")
    }

    @Test
    fun aNewPasswordNeedsTheVaultsOwnKey() {
        val header = VaultHeader.create("secret password").header
        assertFailsWith<ObscuraCryptoException.AuthenticationFailed> {
            header.settingPassword("new password", SecureBytes.random(32))
        }
    }

    /** A closed key is a bug in the caller, not "another vault's key", so it is not answered false. */
    @Test
    fun aClosedKeyIsRefusedRatherThanTried() {
        val vault = VaultHeader.create("secret password")
        vault.masterKey.close()
        assertFailsWith<ObscuraCryptoException.KeyCleared> { vault.header.opens(vault.masterKey) }
    }

    /**
     * The vault the iOS app wrote (Fixtures/vault.header) has these words. The
     * Swift package's `AppCompatibilityTests` checks the same phrase, and it
     * was also worked out by hand with Python's hashlib and the published word
     * list, so all three agree on the encoding of a real vault's key.
     */
    @Test
    fun theAppsVaultHasThePhraseEveryImplementationAgreesOn() {
        val header = VaultHeader.parse(Fixtures.file("vault.header").readBytes())
        val masterKey = header.unlock("correct horse battery staple")
        assertEquals(APP_VAULT_PHRASE, RecoveryPhrase.words(masterKey).joinToString(" "))
        assertTrue(header.opens(RecoveryPhrase.masterKey(APP_VAULT_PHRASE.split(" "))))
    }

    companion object {
        const val APP_VAULT_PHRASE =
            "neglect until scissors settle fit van artefact leave regular fetch open acquire " +
                "mystery pioneer oblige viable pioneer initial apple sunset place rifle people lobster"
    }
}
