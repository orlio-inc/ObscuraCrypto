// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MediaTest : CryptoTestCase() {

    // MARK: Single-shot

    @Test
    fun singleShotRoundTrip() {
        val key = randomKey()
        val photo = randomBytes(10_000)
        val sealed = SingleShotMedia.encrypt(photo, key)
        assertEquals(photo.size + 28, sealed.size)
        assertContentEquals(photo, SingleShotMedia.decrypt(sealed, key))
    }

    @Test
    fun singleShotFolderLayerNeedsBothKeys() {
        val master = randomKey()
        val folder = randomKey()
        val photo = randomBytes(1_000)
        val sealed = SingleShotMedia.encrypt(photo, master, folder)
        assertEquals(photo.size + 56, sealed.size)
        assertContentEquals(photo, SingleShotMedia.decrypt(sealed, master, folder))
        assertFailsWith<ObscuraCryptoException> { SingleShotMedia.decrypt(sealed, master) }
        assertFailsWith<ObscuraCryptoException> { SingleShotMedia.decrypt(sealed, master, randomKey()) }
        assertTrue(SingleShotMedia.hasFolderLayer(sealed, folder))
        assertFalse(SingleShotMedia.hasFolderLayer(sealed, randomKey()))
    }

    /** A file an interrupted folder-password run never reached still opens. */
    @Test
    fun folderKeyStillOpensAFileWithoutTheLayer() {
        val master = randomKey()
        val photo = randomBytes(1_000)
        val sealed = SingleShotMedia.encrypt(photo, master)
        assertContentEquals(photo, SingleShotMedia.decrypt(sealed, master, randomKey()))
    }

    // MARK: Chunked

    private fun roundTrip(size: Int, chunkSize: Long, folder: Boolean) {
        val master = randomKey()
        val folderKey = if (folder) randomKey() else null
        val plaintext = randomBytes(size)
        val source = file("in.bin", plaintext)
        val encrypted = File(directory, "out.enc")
        val decrypted = File(directory, "out.bin")

        val header = ChunkedMediaEncryptor.encrypt(source, encrypted, master, folderKey, chunkSize)
        assertEquals(header.fileSize, encrypted.length())

        val reader = ChunkedMediaReader(encrypted)
        assertEquals(header, reader.header)
        reader.decrypt(decrypted, master, folderKey)
        assertContentEquals(plaintext, decrypted.readBytes())

        // The same through streams, which is how an Android content URI is read.
        val sink = ByteArrayOutputStream()
        ChunkedMediaEncryptor.encrypt(ByteArrayInputStream(plaintext), size.toLong(), sink, master, folderKey, chunkSize)
        val second = file("second.enc", sink.toByteArray())
        val viaStream = ByteArrayOutputStream()
        ChunkedMediaReader(second).decrypt(viaStream, master, folderKey)
        assertContentEquals(plaintext, viaStream.toByteArray())
    }

    @Test fun chunkedEndingOnAPartialChunk() = roundTrip(10_000, 4_096, folder = false)

    @Test fun chunkedEndingExactlyOnAChunkBoundary() = roundTrip(8_192, 4_096, folder = false)

    @Test fun chunkedEmptyFile() = roundTrip(0, 4_096, folder = false)

    @Test fun chunkedWithFolderLayer() = roundTrip(10_000, 4_096, folder = true)

    @Test fun chunkedWithTheDefaultChunkSize() = roundTrip(2_500_000, ChunkedMediaHeader.DEFAULT_CHUNK_SIZE, folder = true)

    @Test
    fun nonceIsPrefixThenBigEndianIndex() {
        val header = ChunkedMediaHeader(
            0x01, byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte()), null,
            totalPlaintextSize = 10, chunkPlaintextSize = 4, flags = 1,
        )
        assertEquals(3, header.chunkCount)
        assertContentEquals(
            byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte(), 0, 0, 0, 0, 0, 0, 0, 2),
            header.masterNonce(2),
        )
        // The folder layer numbers on past the last chunk.
        assertContentEquals(
            byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte(), 0, 0, 0, 0, 0, 0, 0, 3),
            header.folderNonce(0),
        )
    }

    @Test
    fun headerLayoutIsTwentyFiveBytes() {
        val header = ChunkedMediaHeader(0x01, byteArrayOf(1, 2, 3, 4), null, 0x0102030405L, 1_048_576, 1)
        val bytes = header.serialized()
        assertEquals(25, bytes.size)
        assertContentEquals("OBCM".toByteArray(), bytes.copyOf(4))
        assertEquals(1.toByte(), bytes[4])
        assertContentEquals(byteArrayOf(1, 2, 3, 4), bytes.copyOfRange(5, 9))
        assertEquals(0x0102030405L, bytes.bigEndianInt64(9))
        assertEquals(1_048_576L, bytes.bigEndianUInt32(17))
        assertEquals(1L, bytes.bigEndianUInt32(21))
        assertEquals(header, ChunkedMediaHeader.parse(bytes))
    }

    /** Every chunk authenticates on its own, so only the nonce check notices two of them trading places. */
    @Test
    fun swappedChunksAreRejected() {
        val master = randomKey()
        val source = file("in.bin", randomBytes(8_192))
        val encrypted = File(directory, "out.enc")
        val header = ChunkedMediaEncryptor.encrypt(source, encrypted, master, chunkSize = 4_096)

        val bytes = encrypted.readBytes()
        val size = header.encryptedSize(0).toInt()
        val first = header.chunkOffset(0).toInt()
        val second = header.chunkOffset(1).toInt()
        val firstBytes = bytes.copyOfRange(first, first + size)
        System.arraycopy(bytes, second, bytes, first, size)
        System.arraycopy(firstBytes, 0, bytes, second, size)
        encrypted.writeBytes(bytes)

        val error = assertRefused<ObscuraCryptoException.ChunkNonceMismatch> {
            ChunkedMediaReader(encrypted).readChunk(0, master)
        }
        assertEquals(0L, error.index)
    }

    @Test
    fun truncatedFileIsRefusedBeforeDecrypting() {
        val master = randomKey()
        val source = file("in.bin", randomBytes(10_000))
        val encrypted = File(directory, "out.enc")
        ChunkedMediaEncryptor.encrypt(source, encrypted, master, chunkSize = 4_096)
        encrypted.writeBytes(encrypted.readBytes().dropLast(10).toByteArray())
        assertRefused<ObscuraCryptoException.ChunkedFileSizeMismatch> { ChunkedMediaReader(encrypted) }
    }

    @Test
    fun failedDecryptLeavesNoPartialPlaintext() {
        val master = randomKey()
        val source = file("in.bin", randomBytes(10_000))
        val encrypted = File(directory, "out.enc")
        val header = ChunkedMediaEncryptor.encrypt(source, encrypted, master, chunkSize = 4_096)
        val bytes = encrypted.readBytes()
        val at = header.chunkOffset(2).toInt() + 20
        bytes[at] = (bytes[at].toInt() xor 1).toByte()
        encrypted.writeBytes(bytes)

        val output = File(directory, "out.bin")
        assertRefused<ObscuraCryptoException.AuthenticationFailed> { ChunkedMediaReader(encrypted).decrypt(output, master) }
        assertFalse(output.exists())
        assertEquals(emptyList(), directory.list()!!.filter { it.endsWith(".partial") })
    }

    // MARK: Per-chunk cipher

    private fun header(size: Long, chunk: Long, folder: Boolean) =
        ChunkedMediaHeader(0x01, byteArrayOf(1, 2, 3, 4), null, size, chunk, if (folder) 1 else 0)

    /** What setting and removing a folder password does to each chunk of a video already in the vault. */
    @Test
    fun addingThenRemovingAFolderLayer() {
        val master = randomKey()
        val folder = randomKey()
        val plain = header(10, 4, folder = false)
        val layered = header(10, 4, folder = true)
        val chunk = randomBytes(4)

        val masterSealed = ChunkedMediaCipher(plain, master).seal(chunk, 1)
        val wrapped = ChunkedMediaCipher(layered, master, folder).addingFolderLayer(masterSealed, 1)
        assertEquals(chunk.size + 56, wrapped.size)
        assertContentEquals(chunk, ChunkedMediaCipher(layered, master, folder).open(wrapped, 1))

        val unwrapped = ChunkedMediaCipher(layered, master, folder).removingFolderLayer(wrapped, 1)
        assertContentEquals(masterSealed, unwrapped)
    }

    @Test
    fun folderLayerIsCheckedAgainstTheRightKey() {
        val master = randomKey()
        val folder = randomKey()
        val layered = header(8, 4, folder = true)
        val stored = ChunkedMediaCipher(layered, master, folder).seal(randomBytes(4), 0)
        assertTrue(ChunkedMediaCipher(layered, master, folder).folderKeyOpens(stored, 0))
        assertFalse(ChunkedMediaCipher(layered, master, randomKey()).folderKeyOpens(stored, 0))
    }

    /** The master layer's nonces come from the prefix and index alone, so they do not change with the length a header records. */
    @Test
    fun masterLayerNoncesDoNotDependOnTheRecordedLength() {
        val master = randomKey()
        val chunks = listOf(randomBytes(4), randomBytes(4), randomBytes(2))
        val sealer = ChunkedMediaCipher(header(0, 4, folder = false), master)
        val stored = chunks.mapIndexed { index, chunk -> sealer.seal(chunk, index.toLong()) }

        val final = ChunkedMediaCipher(header(10, 4, folder = false), master)
        stored.forEachIndexed { index, sealed -> assertContentEquals(chunks[index], final.open(sealed, index.toLong())) }
    }

    @Test
    fun negativeChunkIndexIsRefused() {
        val cipher = ChunkedMediaCipher(header(8, 4, folder = false), randomKey())
        assertRefused<ObscuraCryptoException.ChunkIndexOutOfRange> { cipher.seal(randomBytes(4), -1) }
    }

    // MARK: Version 2: a key per file

    @Test
    fun newFilesAreVersionTwoWithASaltOfTheirOwn() {
        val master = randomKey()
        val source = file("in.bin", randomBytes(10_000))
        val first = ChunkedMediaEncryptor.encrypt(source, File(directory, "a.enc"), master, chunkSize = 4_096)
        val second = ChunkedMediaEncryptor.encrypt(source, File(directory, "b.enc"), master, chunkSize = 4_096)
        assertEquals(0x02.toByte(), first.formatVersion)
        assertEquals(57, first.byteCount)
        assertEquals(32, first.keySalt?.size)
        assertFalse(first.keySalt.contentEquals(second.keySalt))
        assertEquals(first, ChunkedMediaReader(File(directory, "a.enc")).header)
        assertEquals(57L + 10_000 + 3 * 28, first.fileSize)
    }

    /**
     * The weakness version 2 removes: two version 1 files that drew the same
     * prefix seal their chunks under the same key and nonce. Under version 2
     * the same prefix does no harm, as each file has keys of its own.
     */
    @Test
    fun theSamePrefixNoLongerMeansTheSameKeyAndNonce() {
        val master = randomKey()
        val folder = randomKey()
        val chunk = randomBytes(4)
        fun sealed(version: Byte): ByteArray {
            val header = ChunkedMediaHeader(
                version, byteArrayOf(9, 9, 9, 9), if (version.toInt() == 0x01) null else randomBytes(32), 4, 4, 1,
            )
            return ChunkedMediaCipher(header, master, folder).seal(chunk, 0)
        }
        assertContentEquals(sealed(0x01), sealed(0x01))
        assertFalse(sealed(0x02).contentEquals(sealed(0x02)))
    }

    /** The derivation, pinned to vectors computed outside Kotlin (Python's hmac, RFC 5869), the same the Swift package is held to. */
    @Test
    fun layerKeysMatchTheFormatsTestVectors() {
        val key = SecureBytes.copying(ByteArray(32) { it.toByte() })
        val header = ChunkedMediaHeader(
            0x02, byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte()),
            ByteArray(32) { (32 + it).toByte() }, 4, 4, 0,
        )
        val masterVector = "d676bf9cc865de745fe168ae88fc29317550a8226bc3ccffcf6129972991f27b"
        assertEquals(masterVector,
            Fixtures.hex(ChunkedMediaCipher.layerKey(key, header, ChunkedMediaCipher.MASTER_LAYER_INFO).encoded))
        assertEquals("acd57362adb473b5f8a1bdc93b87539be70ca8cf017c719f11e4155ddf38d831",
            Fixtures.hex(ChunkedMediaCipher.layerKey(key, header, ChunkedMediaCipher.FOLDER_LAYER_INFO).encoded))

        // And a chunk sealed by the cipher opens with plain AES-GCM under the
        // vector's key, with the nonce the format gives it: the only chunk is
        // the last, so its counter carries the end mark.
        val stored = ChunkedMediaCipher(header, key).seal(byteArrayOf(1, 2, 3, 4), 0)
        assertContentEquals(
            byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte(), 0x80.toByte(), 0, 0, 0, 0, 0, 0, 0),
            stored.copyOf(12),
        )
        val derived = masterVector.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(derived, "AES"), GCMParameterSpec(128, stored.copyOf(12)))
        assertContentEquals(byteArrayOf(1, 2, 3, 4), cipher.doFinal(stored.copyOfRange(12, stored.size)))
    }

    /** The salt is not authenticated by any tag, but a changed one derives other keys, so nothing opens. */
    @Test
    fun aChangedSaltOpensNothing() {
        val master = randomKey()
        val encrypted = File(directory, "out.enc")
        ChunkedMediaEncryptor.encrypt(file("in.bin", randomBytes(10_000)), encrypted, master, chunkSize = 4_096)
        val bytes = encrypted.readBytes()
        bytes[40] = (bytes[40].toInt() xor 1).toByte()
        encrypted.writeBytes(bytes)
        assertRefused<ObscuraCryptoException.AuthenticationFailed> { ChunkedMediaReader(encrypted).readChunk(0, master) }
    }

    /** A version 2 file's layer keys are derived per chunk from the caller's key, so closing it still stops the cipher. */
    @Test
    fun closingTheKeyStopsAVersionTwoCipher() {
        val master = randomKey()
        val cipher = ChunkedMediaCipher(ChunkedMediaHeader.make(8, 4), master)
        val stored = cipher.seal(randomBytes(4), 0)
        master.close()
        assertRefused<ObscuraCryptoException.KeyCleared> { cipher.open(stored, 0) }
        assertRefused<ObscuraCryptoException.KeyCleared> { cipher.seal(randomBytes(4), 1) }
    }

    /**
     * Version 2 marks its last chunk: cut short at a chunk boundary, with the
     * recorded length lowered to match, a file is refused. Version 1 has no
     * mark, and such a file opens shorter.
     */
    @Test
    fun aFileCutShortIsRefusedInVersionTwo() {
        for (version in listOf<Byte>(0x01, 0x02)) {
            val master = randomKey()
            val encrypted = File(directory, "cut-$version.enc")
            val header = ChunkedMediaEncryptor.encrypt(
                file("in-$version.bin", randomBytes(10_000)), encrypted, master, null, 4_096, version,
            )
            val bytes = encrypted.readBytes().copyOf(header.chunkOffset(2).toInt())
            System.arraycopy(bigEndianBytes(8_192L, 8), 0, bytes, 9, 8)
            encrypted.writeBytes(bytes)
            val output = File(directory, "out-$version.bin")
            if (version.toInt() == 0x01) {
                ChunkedMediaReader(encrypted).decrypt(output, master)
            } else {
                val refused = assertRefused<ObscuraCryptoException.ChunkNonceMismatch> {
                    ChunkedMediaReader(encrypted).decrypt(output, master)
                }
                assertEquals(1L, refused.index)
            }
        }
    }

    /** An empty version 2 file has one empty chunk, carrying the end mark, so a file cut down to its header alone does not pass for empty. */
    @Test
    fun anEmptyFileHasOneMarkedChunk() {
        val master = randomKey()
        val encrypted = File(directory, "empty.enc")
        val header = ChunkedMediaEncryptor.encrypt(file("empty.bin", ByteArray(0)), encrypted, master, chunkSize = 4_096)
        assertEquals(1L, header.chunkCount)
        assertEquals(0L, header.plaintextSize(0))
        assertEquals(57L + 28, encrypted.length())
        val output = File(directory, "empty.out")
        ChunkedMediaReader(encrypted).decrypt(output, master)
        assertContentEquals(ByteArray(0), output.readBytes())

        encrypted.writeBytes(encrypted.readBytes().copyOf(57))
        val refused = assertRefused<ObscuraCryptoException.ChunkedFileSizeMismatch> { ChunkedMediaReader(encrypted) }
        assertEquals(85L, refused.expected)
        assertEquals(57L, refused.actual)
    }

    /** The end mark is the counter's top bit in the master layer only. */
    @Test
    fun theLastChunkIsMarkedInTheMasterNonce() {
        val header = ChunkedMediaHeader(
            0x02, byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte()),
            ByteArray(32) { (32 + it).toByte() }, 10, 4, 1,
        )
        assertContentEquals(
            byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte(), 0, 0, 0, 0, 0, 0, 0, 1),
            header.masterNonce(1),
        )
        assertContentEquals(
            byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte(), 0x80.toByte(), 0, 0, 0, 0, 0, 0, 2),
            header.masterNonce(2),
        )
        assertContentEquals(
            byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte(), 0, 0, 0, 0, 0, 0, 0, 5),
            header.folderNonce(2),
        )
    }

    @Test
    fun versionOneFilesStillRoundTrip() {
        val master = randomKey()
        val folder = randomKey()
        val plaintext = randomBytes(10_000)
        val encrypted = File(directory, "old.enc")
        val header = ChunkedMediaEncryptor.encrypt(file("in.bin", plaintext), encrypted, master, folder, 4_096, 0x01)
        assertEquals(0x01.toByte(), header.formatVersion)
        assertEquals(null, header.keySalt)
        assertEquals(25, header.byteCount)
        assertEquals(25L + 10_000 + 3 * 56, encrypted.length())
        val output = File(directory, "out.bin")
        ChunkedMediaReader(encrypted).decrypt(output, master, folder)
        assertContentEquals(plaintext, output.readBytes())
    }

    /**
     * Setting and removing a folder password rewrites a file's chunks in
     * place; the file keeps its version, prefix and salt, so its master layer
     * is the same bytes before and after.
     */
    @Test
    fun folderLayerComesAndGoesInEitherVersion() {
        for (version in listOf<Byte>(0x01, 0x02)) {
            val master = randomKey()
            val folder = randomKey()
            val plain = ChunkedMediaHeader.make(10, 4, false, version)
            val layered = plain.settingFolderLayer(true)
            assertTrue(layered.hasFolderLayer)
            assertEquals(version, layered.formatVersion)
            assertTrue(layered.keySalt.contentEquals(plain.keySalt))
            assertContentEquals(plain.noncePrefix, layered.noncePrefix)
            assertEquals(plain, layered.settingFolderLayer(false))

            val chunk = randomBytes(4)
            val masterSealed = ChunkedMediaCipher(plain, master).seal(chunk, 1)
            val wrapped = ChunkedMediaCipher(layered, master, folder).addingFolderLayer(masterSealed, 1)
            assertContentEquals(chunk, ChunkedMediaCipher(layered, master, folder).open(wrapped, 1))
            assertContentEquals(masterSealed, ChunkedMediaCipher(layered, master, folder).removingFolderLayer(wrapped, 1))
        }
    }

    @Test
    fun headersOfEitherVersionParseFromAMaximumSizeRead() {
        for (version in listOf<Byte>(0x01, 0x02)) {
            val header = ChunkedMediaHeader.make(10_000, 4_096, true, version)
            val bytes = header.serialized()
            assertEquals(header.byteCount, bytes.size)
            assertEquals(header, ChunkedMediaHeader.parse(bytes + randomBytes(100)))
        }
        val cut = ChunkedMediaHeader.make(10, 4).serialized().copyOf(40)
        assertEquals("shorter than 57 bytes",
            assertRefused<ObscuraCryptoException.InvalidChunkedHeader> { ChunkedMediaHeader.parse(cut) }.reason)
        val future = ChunkedMediaHeader.make(10, 4).serialized().also { it[4] = 0x03 }
        assertEquals("version 0x03, expected 0x01 or 0x02",
            assertRefused<ObscuraCryptoException.InvalidChunkedHeader> { ChunkedMediaHeader.parse(future) }.reason)
        assertEquals("key salt does not match version 1",
            assertRefused<ObscuraCryptoException.InvalidChunkedHeader> {
                ChunkedMediaHeader(0x01, byteArrayOf(1, 2, 3, 4), ByteArray(32), 4, 4, 0)
            }.reason)
    }

    /** A made-up header asking for chunks of gigabytes is refused before anything is allocated for one. */
    @Test
    fun chunksAbove1GiBAreRefused() {
        val bytes = ChunkedMediaHeader.make(10, 4).serialized()
        bytes[17] = 0x80.toByte(); bytes[18] = 0; bytes[19] = 0; bytes[20] = 0
        assertEquals("chunk size above 1 GiB",
            assertRefused<ObscuraCryptoException.InvalidChunkedHeader> { ChunkedMediaHeader.parse(bytes) }.reason)
        ChunkedMediaHeader.make(10, 1L shl 30)
    }

    /**
     * Version 2 defines one flag. The flags are not sealed into the chunks, so
     * any other bit set means the header was changed. Version 1 files read as
     * they always did.
     */
    @Test
    fun versionTwoRefusesFlagsItDoesNotDefine() {
        val bytes = ChunkedMediaHeader.make(10, 4, true).serialized()
        bytes[24] = (bytes[24].toInt() or 0x02).toByte()
        assertEquals("flags 0x00000003, only bit 0 is defined",
            assertRefused<ObscuraCryptoException.InvalidChunkedHeader> { ChunkedMediaHeader.parse(bytes) }.reason)
        val old = ChunkedMediaHeader.make(10, 4, false, 0x01).serialized()
        old[24] = (old[24].toInt() or 0x02).toByte()
        assertEquals(0x02L, ChunkedMediaHeader.parse(old).flags)
    }

    // MARK: Hostile headers

    /** A 25-byte file whose header claims an impossible length: refused, not a crash. */
    @Test
    fun impossibleLengthIsRefusedNotACrash() {
        val bytes = ChunkedMediaHeader.MAGIC + byteArrayOf(0x01) + byteArrayOf(0, 0, 0, 1) +
            bigEndianBytes(-16L, 8) + bigEndianBytes(1, 4) + bigEndianBytes(0, 4)
        assertEquals(25, bytes.size)
        assertRefused<ObscuraCryptoException.InvalidChunkedHeader> { ChunkedMediaHeader.parse(bytes) }
        assertRefused<ObscuraCryptoException.InvalidChunkedHeader> { ChunkedMediaReader(file("hostile.enc", bytes)) }
    }

    @Test
    fun zeroChunkSizeIsRefused() {
        assertRefused<ObscuraCryptoException.InvalidChunkedHeader> { header(10, 0, folder = false) }
    }

    @Test
    fun aLargeRealisticLengthIsStillAccepted() {
        val terabyte = 1L shl 40
        val header = ChunkedMediaHeader(0x01, byteArrayOf(1, 2, 3, 4), null, terabyte, 1_048_576, 1)
        assertEquals(1_048_576L, header.chunkCount)
        assertEquals(25 + terabyte + 1_048_576L * 56, header.fileSize)
    }

    // MARK: Output files

    @Test
    fun failedDecryptLeavesAnExistingFileUntouched() {
        val master = randomKey()
        val encrypted = File(directory, "out.enc")
        ChunkedMediaEncryptor.encrypt(file("in.bin", randomBytes(10_000)), encrypted, master, chunkSize = 4_096)

        val precious = file("precious.txt", "keep me".toByteArray())
        assertFailsWith<ObscuraCryptoException> { ChunkedMediaReader(encrypted).decrypt(precious, randomKey()) }
        assertContentEquals("keep me".toByteArray(), precious.readBytes())
        assertEquals(emptyList(), directory.list()!!.filter { it.endsWith(".partial") })
    }

    @Test
    fun successfulDecryptReplacesAnExistingFile() {
        val master = randomKey()
        val plaintext = randomBytes(10_000)
        val encrypted = File(directory, "out.enc")
        ChunkedMediaEncryptor.encrypt(file("in.bin", plaintext), encrypted, master, chunkSize = 4_096)

        val target = file("target.bin", "old".toByteArray())
        ChunkedMediaReader(encrypted).decrypt(target, master)
        assertContentEquals(plaintext, target.readBytes())
    }

    @Test
    fun streamEndingEarlyIsRefused() {
        val sink = ByteArrayOutputStream()
        assertRefused<ObscuraCryptoException.ChunkedFileSizeMismatch> {
            ChunkedMediaEncryptor.encrypt(ByteArrayInputStream(randomBytes(100)), 200, sink, randomKey(), chunkSize = 64)
        }
    }

    @Test
    fun formatDetection() {
        assertEquals(MediaFormat.CHUNKED, MediaFormat.detect("OBCM".toByteArray() + ByteArray(21)))
        assertEquals(MediaFormat.SINGLE_SHOT, MediaFormat.detect(ByteArray(28) { 0x11 }))
        assertEquals(MediaFormat.SINGLE_SHOT, MediaFormat.detect(ByteArray(2)))
    }
}
