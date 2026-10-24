// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

@file:OptIn(KeyDerivation.TestingOnly::class)

package io.orlio.obscuracrypto

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.lang.management.ManagementFactory
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach

/**
 * Behaviour found by a security review: a closed key must not work, an export
 * must not cost memory or stack its contents have not earned, and an installed
 * key derivation must be the real one.
 */
class HardeningTest : CryptoTestCase() {

    @BeforeEach
    fun fastDerivation() {
        // The tests below are about parsing, not about the cost of PBKDF2.
        KeyDerivation.overrideForTesting { password, salt, _ -> Pbkdf2.derive(password, salt, 1) }
    }

    @AfterEach
    fun restoreDerivation() = KeyDerivation.overrideForTesting(null)

    // MARK: Closed keys

    @Test
    fun aClosedKeyCannotSealOpenOrBeRead() {
        val key = randomKey()
        val sealed = AesGcm.seal(byteArrayOf(1, 2, 3), key)
        key.close()
        assertTrue(key.isCleared)
        assertRefused<ObscuraCryptoException.KeyCleared> { AesGcm.seal(byteArrayOf(1), key) }
        assertRefused<ObscuraCryptoException.KeyCleared> { AesGcm.open(sealed, key) }
        assertRefused<ObscuraCryptoException.KeyCleared> { key.toByteArray() }
        assertRefused<ObscuraCryptoException.KeyCleared> { key.withBytes { } }
        assertRefused<ObscuraCryptoException.KeyCleared> { key.fingerprint }
        assertRefused<ObscuraCryptoException.KeyCleared> { key.contentEquals(randomKey()) }
    }

    @Test
    fun nothingCanBeSealedUnderTheZeroKeyByClosingAKey() {
        val key = randomKey()
        key.clear()
        val failure = runCatching { AesGcm.seal("photo".toByteArray(), key) }
        assertTrue(failure.exceptionOrNull() is ObscuraCryptoException.KeyCleared)
    }

    @Test
    fun aKeyThatWasNeverClearedStillWorks() {
        val zeros = SecureBytes(32) // zero-filled on purpose, never cleared
        assertTrue(!zeros.isCleared)
        AesGcm.open(AesGcm.seal(byteArrayOf(9), zeros), zeros)
    }

    @Test
    fun aChunkedCipherStopsWhenItsKeysAreClosed() {
        val master = randomKey()
        val folder = randomKey()
        val header = ChunkedMediaHeader.make(100, 64, hasFolderLayer = true)
        val cipher = ChunkedMediaCipher(header, master, folder)
        val sealed = cipher.seal(randomBytes(64), 0)
        folder.close()
        assertRefused<ObscuraCryptoException.KeyCleared> { cipher.open(sealed, 0) }
        master.close()
        assertRefused<ObscuraCryptoException.KeyCleared> { cipher.seal(randomBytes(64), 0) }
    }

    // MARK: Installed key derivation

    @Test
    fun anInstalledDerivationMustComputePbkdf2() {
        KeyDerivation.overrideForTesting(null)
        assertFailsWith<IllegalStateException> { KeyDerivation.install { _, _, _ -> ByteArray(32) } }
        assertFailsWith<IllegalStateException> { KeyDerivation.install { _, _, _ -> error("native library missing") } }
        assertFailsWith<IllegalStateException> { KeyDerivation.install { p, s, r -> Pbkdf2.derive(p, s, r + 1) } }
        // Refused functions leave nothing installed.
        KeyDerivation.install { p, s, r -> Pbkdf2.derive(p, s, r) }
    }

    // MARK: Hostile exports

    private fun manifest(extra: String = "", media: String = ""): ByteArray {
        val created = VaultHeader.create("pw")
        val b64 = Base64.getEncoder()
        return """{"exportVersion":1,"vaultSalt":"${b64.encodeToString(created.header.salt)}",
            "encryptedMEK":"${b64.encodeToString(created.header.wrappedMasterKey)}","databaseSize":0,
            "mediaFiles":[$media]$extra}""".toByteArray()
    }

    private fun export(manifest: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        ExportWriter.begin(out, "pw").writeManifest(manifest)
        return out.toByteArray()
    }

    @Test
    fun aDeeplyNestedManifestIsRefusedNotAStackOverflow() {
        for (depth in listOf(40, 100_000)) {
            val nested = ",\"x\":" + "[".repeat(depth) + "]".repeat(depth)
            assertRefused<ObscuraCryptoException.InvalidExport> {
                ExportArchive.open(ByteArrayInputStream(export(manifest(nested))), "pw").close()
            }
        }
    }

    @Test
    fun bracketsInsideStringsDoNotCountAsNesting() {
        val text = ",\"note\":\"" + "[".repeat(500) + "\\\"" + "{".repeat(500) + "\""
        ExportArchive.open(ByteArrayInputStream(export(manifest(text))), "pw").close()
    }

    @Test
    fun aRecordLengthIsNotAllocatedBeforeTheBytesArrive() {
        val out = ByteArrayOutputStream()
        ExportWriter.begin(out, "pw")
        out.write(byteArrayOf(0x0F, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())) // claims 256 MiB
        out.write(ByteArray(8))
        val bean = ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
        val thread = Thread.currentThread().threadId()
        val before = bean.getThreadAllocatedBytes(thread)
        assertRefused<ObscuraCryptoException.InvalidExport> { ExportArchive.open(ByteArrayInputStream(out.toByteArray()), "pw") }
        val allocated = bean.getThreadAllocatedBytes(thread) - before
        assertTrue(allocated < 32L shl 20, "allocated $allocated bytes for a 76-byte file")
    }

    @Test
    fun growingReadsStillReturnEveryByte() {
        val data = randomBytes(3 * (1 shl 20) + 17)
        assertBytesEqual(data, ByteArrayInputStream(data).readExactlyGrowing(data.size)!!)
        assertEquals(null, ByteArrayInputStream(data).readExactlyGrowing(data.size + 1))
    }

    @Test
    fun mediaIdsThatDifferOnlyByCaseAreTheSameId() {
        val upper = "A3E42A38-8C9A-483D-BAE4-1AEE61FF133A"
        val entries = """{"mediaId":"$upper","dataSize":0,"thumbSize":0},
            {"mediaId":"${upper.lowercase()}","dataSize":0,"thumbSize":0}"""
        assertRefused<ObscuraCryptoException.InvalidExport> {
            ExportArchive.open(ByteArrayInputStream(export(manifest(media = entries))), "pw").close()
        }
    }
}
