// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
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
            byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte()),
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
        val header = ChunkedMediaHeader(byteArrayOf(1, 2, 3, 4), 0x0102030405L, 1_048_576, 1)
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
        ChunkedMediaHeader(byteArrayOf(1, 2, 3, 4), size, chunk, if (folder) 1 else 0)

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

    // MARK: Hostile headers

    /** A 25-byte file whose header claims an impossible length: refused, not a crash. */
    @Test
    fun impossibleLengthIsRefusedNotACrash() {
        val bytes = ChunkedMediaHeader.MAGIC + byteArrayOf(ChunkedMediaHeader.VERSION) + byteArrayOf(0, 0, 0, 1) +
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
        val header = ChunkedMediaHeader(byteArrayOf(1, 2, 3, 4), terabyte, 1_048_576, 1)
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
