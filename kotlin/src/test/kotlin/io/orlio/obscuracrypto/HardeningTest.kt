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
        // Right at every small count, wrong once the rounds pass 16 bits: a counter overflow no small check would see.
        assertFailsWith<IllegalStateException> { KeyDerivation.install { p, s, r -> Pbkdf2.derive(p, s, r and 0xFFFF) } }
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

    /** The manifest alone, in each version, written without the writer's own check of it, as a hostile file would be. */
    private fun exports(manifest: ByteArray): List<ByteArray> {
        val version1 = ByteArrayOutputStream().also { ExportWriterVersion1.begin(it, "pw").writeManifest(manifest) }.toByteArray()
        val salt = KeyDerivation.makeSalt()
        val prefix = Random.bytes(4)
        val exportKey = KeyDerivation.pbkdf2SHA256("pw", salt, KeyDerivation.VAULT_ITERATIONS)
        val header = ExportHeader.version2(salt, KeyDerivation.VAULT_ITERATIONS.toLong(), prefix, 4_096, ExportHeader.keyCommitment(exportKey))
        val out = ByteArrayOutputStream()
        out.write(header.serialized())
        val records = (SharedItemsFile.padme(4L + manifest.size) + 4_095) / 4_096
        RecordSealer(out, ExportHeader.recordKey(exportKey), prefix, header.serialized(), 4_096, records).run {
            append(bigEndianBytes(manifest.size.toLong(), 4))
            append(manifest)
            finish(0)
        }
        return listOf(version1, out.toByteArray())
    }

    @Test
    fun aDeeplyNestedManifestIsRefusedNotAStackOverflow() {
        for (depth in listOf(40, 100_000)) {
            val nested = ",\"x\":" + "[".repeat(depth) + "]".repeat(depth)
            for (export in exports(manifest(nested))) {
                assertRefused<ObscuraCryptoException.InvalidExport> { ExportArchive.open(ByteArrayInputStream(export), "pw").close() }
            }
        }
    }

    @Test
    fun bracketsInsideStringsDoNotCountAsNesting() {
        val text = ",\"note\":\"" + "[".repeat(500) + "\\\"" + "{".repeat(500) + "\""
        for (export in exports(manifest(text))) ExportArchive.open(ByteArrayInputStream(export), "pw").close()
    }

    /** What the app writes, a date as seconds with a fraction, reads; what no JSON writer would, two of one key or base64 a lenient decoder would take, does not. */
    @Test
    fun aManifestIsReadOneWayOnly() {
        for (export in exports(manifest(",\"exportDate\":785000000.123456,\"scale\":1e-3"))) {
            ExportArchive.open(ByteArrayInputStream(export), "pw").close()
        }
        val created = VaultHeader.create("pw")
        val salt = Base64.getEncoder().encodeToString(created.header.salt)
        val wrapped = Base64.getEncoder().encodeToString(created.header.wrappedMasterKey)
        val hostile = listOf(
            // Two of one key: a reader taking the first and another the last would split the stream differently.
            """{"exportVersion":1,"vaultSalt":"$salt","encryptedMEK":"$wrapped","databaseSize":0,"databaseSize":5,"mediaFiles":[]}""",
            // A size as a string, and a whole number written as a decimal.
            """{"exportVersion":1,"vaultSalt":"$salt","encryptedMEK":"$wrapped","databaseSize":"0","mediaFiles":[]}""",
            """{"exportVersion":1,"vaultSalt":"$salt","encryptedMEK":"$wrapped","databaseSize":0.0,"mediaFiles":[]}""",
            """{"exportVersion":1.0,"vaultSalt":"$salt","encryptedMEK":"$wrapped","databaseSize":0,"mediaFiles":[]}""",
            // Base64 without its padding, and with a line break.
            """{"exportVersion":1,"vaultSalt":"${salt.trimEnd('=')}","encryptedMEK":"$wrapped","databaseSize":0,"mediaFiles":[]}""",
            """{"exportVersion":1,"vaultSalt":"${salt.substring(0, 8)}\n${salt.substring(8)}","encryptedMEK":"$wrapped","databaseSize":0,"mediaFiles":[]}""",
        )
        for (json in hostile) {
            for (export in exports(json.toByteArray())) {
                assertRefused<ObscuraCryptoException.InvalidExport> { ExportArchive.open(ByteArrayInputStream(export), "pw").close() }
            }
        }
    }

    /** Sizes that add up past the largest number are refused, not wrapped round to a small total. */
    @Test
    fun sizesThatOverflowAreRefused() {
        val max = Long.MAX_VALUE
        val id = "A3E42A38-8C9A-483D-BAE4-1AEE61FF133A"
        val hostile = listOf(
            manifest(media = """{"mediaId":"$id","dataSize":$max,"thumbSize":1}"""),
            // Wraps to exactly 0 with plain addition.
            manifest(media = """{"mediaId":"$id","dataSize":$max,"thumbSize":$max},""" +
                """{"mediaId":"B3E42A38-8C9A-483D-BAE4-1AEE61FF133A","dataSize":2,"thumbSize":0}"""),
        )
        for (json in hostile) {
            for (export in exports(json)) {
                assertRefused<ObscuraCryptoException.InvalidExport> { ExportArchive.open(ByteArrayInputStream(export), "pw").close() }
            }
        }
    }

    // MARK: Key block

    private fun exportWithKeyBlock(keyBlock: ByteArray, databaseBytes: ByteArray = ByteArray(0)): ByteArray {
        val created = VaultHeader.create("pw")
        val b64 = Base64.getEncoder()
        val manifest = """{"exportVersion":1,"vaultSalt":"${b64.encodeToString(created.header.salt)}",
            "encryptedMEK":"${b64.encodeToString(created.header.wrappedMasterKey)}","databaseSize":${databaseBytes.size},
            "mediaFiles":[]}""".toByteArray()
        val out = ByteArrayOutputStream()
        ExportWriter.begin(out, "pw", KeyDerivation.VAULT_ITERATIONS, 4_096, keyBlock).run {
            writeManifest(manifest)
            writeFile(ByteArrayInputStream(databaseBytes), databaseBytes.size.toLong())
            finish()
        }
        return out.toByteArray()
    }

    /** A lock of a type no reader knows yet, such as a recovery key added later, is passed over: the file opens with its password. */
    @Test
    fun aLockOfAnUnknownTypeIsPassedOver() {
        val lock = byteArrayOf(0x09, 0x00, 0x05) + "later".toByteArray()
        val export = exportWithKeyBlock(byteArrayOf(1) + lock, byteArrayOf(1, 2, 3))
        ExportArchive.open(ByteArrayInputStream(export), "pw").use { archive ->
            assertEquals(listOf(9), archive.header.lockTypes)
            assertTrue(archive.read(3).contentEquals(byteArrayOf(1, 2, 3)))
            assertTrue(archive.isAtEnd())
        }
    }

    /** The key block is authenticated with the header: a lock changed, taken out or cut short is refused, never read past. */
    @Test
    fun aKeyBlockChangedOrCutShortIsRefused() {
        val lock = byteArrayOf(0x09, 0x00, 0x05) + "later".toByteArray()
        val original = exportWithKeyBlock(byteArrayOf(1) + lock)
        val changed = original.copyOf().also { it[96 + 1 + 3] = (it[96 + 1 + 3].toInt() xor 1).toByte() }
        val removed = original.copyOf().also { it[96] = 0 }
        val cut = original.copyOf(96 + 4).also { it[10] = 0x10 }
        for (bytes in listOf(changed, removed, cut)) {
            assertRefused<ObscuraCryptoException.InvalidExport> { ExportArchive.verify(ByteArrayInputStream(bytes), "pw") }
        }
    }

    @Test
    fun aRecordLengthIsNotAllocatedBeforeTheBytesArrive() {
        val out = ByteArrayOutputStream()
        ExportWriterVersion1.begin(out, "pw")
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
        for (export in exports(manifest(media = entries))) {
            assertRefused<ObscuraCryptoException.InvalidExport> { ExportArchive.open(ByteArrayInputStream(export), "pw").close() }
        }
    }
}
