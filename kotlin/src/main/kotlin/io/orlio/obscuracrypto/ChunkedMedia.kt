// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID
import javax.crypto.spec.SecretKeySpec

/**
 * The 25-byte header of a chunked media file.
 *
 * ```
 * offset  size  field
 *      0     4  magic, "OBCM"
 *      4     1  version, 0x01
 *      5     4  nonce prefix, random per file
 *      9     8  total plaintext length, big-endian UInt64
 *     17     4  plaintext bytes per chunk, big-endian UInt32 (1 MiB by default)
 *     21     4  flags, big-endian UInt32; bit 0 set means a folder layer
 * ```
 *
 * Chunks follow at fixed offsets, so chunk `i` starts at
 * `25 + i * (chunkSize + overhead)`. Each chunk is AES-GCM combined,
 * `nonce || ciphertext || tag`; only the last can be shorter.
 *
 * Nonces are derived, not random: `noncePrefix (4) || i (8, big-endian)`. The
 * random prefix keeps files apart and the index keeps chunks apart. A folder
 * layer seals each master-encrypted chunk again with the folder key, numbering
 * its nonces on from `chunkCount` so the two layers never share one; its
 * chunks carry 56 bytes of overhead instead of 28.
 *
 * Sizes are Longs. The two unsigned fields that could exceed a Long's range,
 * the total length and the chunk size, are accepted only when the file they
 * describe fits in one, which is every real file.
 */
class ChunkedMediaHeader(
    noncePrefix: ByteArray,
    val totalPlaintextSize: Long,
    val chunkPlaintextSize: Long,
    val flags: Long,
) {
    val noncePrefix: ByteArray = noncePrefix.copyOf()

    init {
        if (noncePrefix.size != NONCE_PREFIX_SIZE) {
            throw ObscuraCryptoException.InvalidChunkedHeader("nonce prefix is not 4 bytes")
        }
        if (chunkPlaintextSize <= 0 || chunkPlaintextSize > UINT32_MAX) {
            throw ObscuraCryptoException.InvalidChunkedHeader("chunk size is zero")
        }
        // Every size and offset derived from the header has to fit in a Long.
        // Checked here, once, so the plain arithmetic below can never wrap: a
        // header claiming an impossible length is refused as invalid instead of
        // misbehaving for whoever opened the file.
        if (totalPlaintextSize < 0 ||
            checkedFileSize(totalPlaintextSize, chunkPlaintextSize, flags and FOLDER_LAYER_FLAG != 0L) == null
        ) {
            throw ObscuraCryptoException.InvalidChunkedHeader("its length is too large to be a real file")
        }
    }

    fun serialized(): ByteArray {
        val data = ByteArray(SIZE)
        System.arraycopy(MAGIC, 0, data, 0, 4)
        data[4] = VERSION
        System.arraycopy(noncePrefix, 0, data, 5, 4)
        System.arraycopy(bigEndianBytes(totalPlaintextSize, 8), 0, data, 9, 8)
        System.arraycopy(bigEndianBytes(chunkPlaintextSize, 4), 0, data, 17, 4)
        System.arraycopy(bigEndianBytes(flags, 4), 0, data, 21, 4)
        return data
    }

    val hasFolderLayer: Boolean get() = flags and FOLDER_LAYER_FLAG != 0L

    val chunkCount: Long get() = chunkCount(totalPlaintextSize, chunkPlaintextSize)

    /** Bytes each chunk adds: 28 for one layer, 56 for two. */
    val chunkOverhead: Int get() = AesGcm.OVERHEAD * (if (hasFolderLayer) 2 else 1)

    fun chunkOffset(index: Long): Long = SIZE + index * (chunkPlaintextSize + chunkOverhead)

    fun plaintextSize(chunk: Long): Long {
        if (chunk != chunkCount - 1) return chunkPlaintextSize
        val remainder = totalPlaintextSize % chunkPlaintextSize
        return if (remainder == 0L) chunkPlaintextSize else remainder
    }

    fun encryptedSize(chunk: Long): Long = plaintextSize(chunk) + chunkOverhead

    /** How long a file with this header must be. */
    val fileSize: Long
        get() = if (chunkCount == 0L) SIZE.toLong() else chunkOffset(chunkCount - 1) + encryptedSize(chunkCount - 1)

    /** `noncePrefix || counter`, the counter as 8 big-endian bytes. */
    fun nonce(counter: Long): ByteArray = noncePrefix + bigEndianBytes(counter, 8)

    /** The nonce of chunk [index]'s master layer. */
    fun masterNonce(chunk: Long): ByteArray = nonce(chunk)

    /** The nonce of chunk [index]'s folder layer, numbered on past the last chunk. */
    fun folderNonce(chunk: Long): ByteArray = nonce(chunkCount + chunk)

    override fun equals(other: Any?): Boolean =
        other is ChunkedMediaHeader && noncePrefix.contentEquals(other.noncePrefix) &&
            totalPlaintextSize == other.totalPlaintextSize && chunkPlaintextSize == other.chunkPlaintextSize &&
            flags == other.flags

    override fun hashCode(): Int = noncePrefix.contentHashCode()

    companion object {
        const val SIZE = 25
        val MAGIC: ByteArray = "OBCM".toByteArray(Charsets.US_ASCII)
        const val VERSION: Byte = 0x01
        const val DEFAULT_CHUNK_SIZE = 1_048_576L
        const val NONCE_PREFIX_SIZE = 4
        const val FOLDER_LAYER_FLAG = 0x01L
        private const val UINT32_MAX = 0xFFFF_FFFFL

        /**
         * A header for a new file, with a fresh random nonce prefix.
         *
         * The prefix is what keeps two files encrypted under the same master
         * key from ever sharing a nonce, so it is always drawn here, from the
         * system generator, and never supplied by a caller.
         */
        fun make(
            totalPlaintextSize: Long,
            chunkPlaintextSize: Long = DEFAULT_CHUNK_SIZE,
            hasFolderLayer: Boolean = false,
        ): ChunkedMediaHeader = ChunkedMediaHeader(
            noncePrefix = Random.bytes(NONCE_PREFIX_SIZE),
            totalPlaintextSize = totalPlaintextSize,
            chunkPlaintextSize = chunkPlaintextSize,
            flags = if (hasFolderLayer) FOLDER_LAYER_FLAG else 0,
        )

        fun parse(data: ByteArray): ChunkedMediaHeader {
            if (data.size < SIZE) throw ObscuraCryptoException.InvalidChunkedHeader("shorter than $SIZE bytes")
            val header = data.copyOf(SIZE)
            if (!header.startsWith(MAGIC)) throw ObscuraCryptoException.InvalidChunkedHeader("missing OBCM magic")
            if (header[4] != VERSION) {
                throw ObscuraCryptoException.InvalidChunkedHeader(
                    "version 0x%02x, expected 0x01".format(header[4].toInt() and 0xFF)
                )
            }
            return ChunkedMediaHeader(
                noncePrefix = header.range(5, 9),
                totalPlaintextSize = header.bigEndianInt64(9),
                chunkPlaintextSize = header.bigEndianUInt32(17),
                flags = header.bigEndianUInt32(21),
            )
        }

        /** Rounded up without adding first, so it cannot overflow. */
        private fun chunkCount(total: Long, chunk: Long): Long = total / chunk + (if (total % chunk == 0L) 0 else 1)

        /** The file length a header describes, or null if it does not fit in a Long. */
        private fun checkedFileSize(total: Long, chunk: Long, hasFolderLayer: Boolean): Long? = try {
            val overhead = (AesGcm.OVERHEAD * (if (hasFolderLayer) 2 else 1)).toLong()
            val encrypted = Math.multiplyExact(chunkCount(total, chunk), overhead)
            Math.addExact(Math.addExact(encrypted, total), SIZE.toLong())
        } catch (e: ArithmeticException) {
            null
        }
    }
}

// MARK: - Per-chunk cipher

/**
 * Seals and opens the chunks of one chunked file, with no file handling.
 *
 * Everything cryptographic about the chunked format happens here: which key
 * seals which layer, which nonce each layer must carry, and in what order the
 * layers come off. Callers own the file I/O, so the same rules serve a
 * whole-file encryptor, a reader of single chunks, a video data source that
 * reads byte ranges, and a rewrite that adds or removes a folder layer in place.
 */
class ChunkedMediaCipher(
    val header: ChunkedMediaHeader,
    masterKey: SecureBytes,
    folderKey: SecureBytes? = null,
) {
    private val master: SecretKeySpec
    private val folder: SecretKeySpec?

    /**
     * [folderKey] is needed to seal or open a file with a folder layer, and to
     * add or remove one. Given for a file without the layer, it is not used.
     */
    init {
        AesGcm.checkKey(masterKey)
        if (folderKey != null) AesGcm.checkKey(folderKey)
        master = masterKey.secretKey()
        folder = folderKey?.secretKey()
    }

    /**
     * Seals chunk [index]: the master layer, then the folder layer if the
     * header says the file has one.
     *
     * The master layer's nonce comes from the prefix and the index alone; the
     * folder layer's also depends on the chunk count.
     */
    fun seal(plaintext: ByteArray, chunk: Long): ByteArray {
        val inner = sealMaster(plaintext, chunk)
        return if (header.hasFolderLayer) sealFolder(inner, chunk) else inner
    }

    /**
     * Opens chunk [index] as stored, checking that every layer carries the
     * nonce its position requires.
     *
     * The tag proves a chunk is intact, but the nonce travels inside the
     * chunk, so without this check a chunk moved to another position, or
     * copied in from another file under the same key, would still open.
     */
    fun open(stored: ByteArray, chunk: Long): ByteArray =
        openMaster(if (header.hasFolderLayer) openFolder(stored, chunk) else stored, chunk)

    /**
     * Wraps a master-sealed chunk in a folder layer, for a file gaining one.
     * Opens the master layer first, so a damaged chunk is refused rather than
     * sealed in.
     */
    fun addingFolderLayer(masterSealed: ByteArray, chunk: Long): ByteArray {
        openMaster(masterSealed, chunk)
        return sealFolder(masterSealed, chunk)
    }

    /** Takes the folder layer off a chunk, leaving it master-sealed. */
    fun removingFolderLayer(stored: ByteArray, chunk: Long): ByteArray = openFolder(stored, chunk)

    /**
     * Whether the folder key opens the folder layer of this stored chunk. A
     * file whose layer was put there by a key that no longer exists keeps its
     * flag but fails this.
     */
    fun folderKeyOpens(stored: ByteArray, chunk: Long): Boolean =
        try {
            openFolder(stored, chunk)
            true
        } catch (e: ObscuraCryptoException) {
            false
        }

    // MARK: Layers

    private fun sealMaster(plaintext: ByteArray, chunk: Long): ByteArray {
        checkIndex(chunk)
        return AesGcm.seal(plaintext, master, header.masterNonce(chunk))
    }

    private fun sealFolder(inner: ByteArray, chunk: Long): ByteArray {
        checkIndex(chunk)
        val key = folder ?: throw ObscuraCryptoException.AuthenticationFailed()
        return AesGcm.seal(inner, key, header.folderNonce(chunk))
    }

    private fun openMaster(sealed: ByteArray, chunk: Long): ByteArray {
        checkIndex(chunk)
        if (!hasNonce(sealed, header.masterNonce(chunk))) throw ObscuraCryptoException.ChunkNonceMismatch(chunk)
        return AesGcm.open(sealed, master)
    }

    private fun openFolder(stored: ByteArray, chunk: Long): ByteArray {
        checkIndex(chunk)
        val key = folder ?: throw ObscuraCryptoException.AuthenticationFailed()
        if (!hasNonce(stored, header.folderNonce(chunk))) throw ObscuraCryptoException.ChunkNonceMismatch(chunk)
        return AesGcm.open(stored, key)
    }

    private fun hasNonce(sealed: ByteArray, nonce: ByteArray): Boolean =
        sealed.size >= AesGcm.NONCE_SIZE && constantTimeEquals(sealed.copyOf(AesGcm.NONCE_SIZE), nonce)

    /** Refuses a negative index. Readers check the upper bound against the header first. */
    private fun checkIndex(index: Long) {
        if (index < 0) throw ObscuraCryptoException.ChunkIndexOutOfRange(index)
    }
}

// MARK: - Encrypting

object ChunkedMediaEncryptor {

    /**
     * Encrypts [source] into a new chunked file at [destination], one chunk in
     * memory at a time. Returns the header written.
     *
     * Writes to a temporary file beside [destination] and moves it into place
     * only when complete, so a failure never leaves a partial file.
     */
    fun encrypt(
        source: File,
        destination: File,
        masterKey: SecureBytes,
        folderKey: SecureBytes? = null,
        chunkSize: Long = ChunkedMediaHeader.DEFAULT_CHUNK_SIZE,
    ): ChunkedMediaHeader {
        val temporary = temporaryFile(destination)
        try {
            val header = source.inputStream().use { input ->
                temporary.outputStream().use { output ->
                    encrypt(input, source.length(), output, masterKey, folderKey, chunkSize)
                        .also { output.flush(); output.fd.sync() }
                }
            }
            moveIntoPlace(temporary, destination)
            return header
        } catch (e: Throwable) {
            temporary.delete()
            throw e
        }
    }

    /**
     * Encrypts exactly [totalSize] bytes read from [input] into [output], one
     * chunk in memory at a time, and returns the header written. For sources
     * that are not files, such as an Android content URI. Fails with
     * [ObscuraCryptoException.ChunkedFileSizeMismatch] if the stream ends early.
     */
    fun encrypt(
        input: InputStream,
        totalSize: Long,
        output: OutputStream,
        masterKey: SecureBytes,
        folderKey: SecureBytes? = null,
        chunkSize: Long = ChunkedMediaHeader.DEFAULT_CHUNK_SIZE,
    ): ChunkedMediaHeader {
        val header = ChunkedMediaHeader.make(totalSize, chunkSize, hasFolderLayer = folderKey != null)
        output.write(header.serialized())
        val cipher = ChunkedMediaCipher(header, masterKey, folderKey)
        val buffer = ByteArray(Math.toIntExact(minOf(chunkSize, totalSize.coerceAtLeast(1))))

        for (index in 0 until header.chunkCount) {
            val size = Math.toIntExact(header.plaintextSize(index))
            if (input.readFully(buffer, size) != size) {
                throw ObscuraCryptoException.ChunkedFileSizeMismatch(totalSize, -1)
            }
            output.write(cipher.seal(if (size == buffer.size) buffer else buffer.copyOf(size), index))
        }
        return header
    }
}

// MARK: - Decrypting

/** Reads and decrypts a chunked media file a chunk at a time. */
class ChunkedMediaReader(val file: File) {
    val header: ChunkedMediaHeader

    /**
     * Opens [file] and checks that its length matches its header, so a
     * truncated or padded file is refused before any key is used.
     */
    init {
        RandomAccessFile(file, "r").use { handle ->
            val head = ByteArray(ChunkedMediaHeader.SIZE)
            val read = handle.readAtMost(head)
            header = ChunkedMediaHeader.parse(head.copyOf(read))
            val actual = handle.length()
            if (actual != header.fileSize) {
                throw ObscuraCryptoException.ChunkedFileSizeMismatch(header.fileSize, actual)
            }
        }
    }

    /**
     * Decrypts chunk [index].
     *
     * Checks that each layer carries the nonce its position requires before
     * trusting it (see [ChunkedMediaCipher.open]). A file with a folder layer
     * needs [folderKey]. Given a folder key, a file without the layer is read
     * with the master key alone.
     */
    fun readChunk(index: Long, masterKey: SecureBytes, folderKey: SecureBytes? = null): ByteArray =
        RandomAccessFile(file, "r").use { handle ->
            readChunk(index, handle, ChunkedMediaCipher(header, masterKey, folderKey))
        }

    /**
     * Decrypts the whole file into [destination], one chunk in memory at a
     * time.
     *
     * Writes to a temporary file beside [destination] and moves it into place
     * only once every chunk has decrypted, so a failure leaves no partial
     * plaintext and never touches a file already at [destination].
     */
    fun decrypt(
        destination: File,
        masterKey: SecureBytes,
        folderKey: SecureBytes? = null,
        progress: ((chunksDone: Long, chunkCount: Long) -> Unit)? = null,
    ) {
        val temporary = privateTemporaryFile(destination)
        try {
            temporary.outputStream().use { output ->
                decrypt(output, masterKey, folderKey, progress)
                output.flush()
                output.fd.sync()
            }
            moveIntoPlace(temporary, destination)
        } catch (e: Throwable) {
            temporary.delete()
            throw e
        }
    }

    /** Decrypts the whole file into [output], one chunk in memory at a time. */
    fun decrypt(
        output: OutputStream,
        masterKey: SecureBytes,
        folderKey: SecureBytes? = null,
        progress: ((chunksDone: Long, chunkCount: Long) -> Unit)? = null,
    ) {
        val cipher = ChunkedMediaCipher(header, masterKey, folderKey)
        RandomAccessFile(file, "r").use { input ->
            for (index in 0 until header.chunkCount) {
                output.write(readChunk(index, input, cipher))
                progress?.invoke(index + 1, header.chunkCount)
            }
        }
    }

    /** Reads and opens one chunk through a handle the caller keeps open. */
    fun readChunk(index: Long, handle: RandomAccessFile, cipher: ChunkedMediaCipher): ByteArray {
        if (index < 0 || index >= header.chunkCount) throw ObscuraCryptoException.ChunkIndexOutOfRange(index)
        handle.seek(header.chunkOffset(index))
        val size = Math.toIntExact(header.encryptedSize(index))
        val stored = ByteArray(size)
        if (handle.readAtMost(stored) != size) {
            throw ObscuraCryptoException.ChunkedFileSizeMismatch(header.fileSize, -1)
        }
        return cipher.open(stored, index)
    }
}

private fun RandomAccessFile.readAtMost(buffer: ByteArray): Int {
    var total = 0
    while (total < buffer.size) {
        val read = read(buffer, total, buffer.size - total)
        if (read < 0) break
        total += read
    }
    return total
}

internal fun temporaryFile(destination: File): File =
    File(destination.absoluteFile.parentFile, ".${destination.name}.${UUID.randomUUID()}.partial")

/**
 * A temporary file for decrypted bytes, made readable by its owner only before
 * anything is written to it. Where the file system has no owner permissions the
 * file is still created.
 */
internal fun privateTemporaryFile(destination: File): File {
    val file = temporaryFile(destination)
    try {
        Files.createFile(file.toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
    } catch (e: UnsupportedOperationException) {
        file.createNewFile()
    }
    return file
}

/**
 * Moves a finished temporary file to [destination], replacing a file already
 * there in one step rather than deleting it first.
 */
internal fun moveIntoPlace(temporary: File, destination: File) {
    Files.move(
        temporary.toPath(), destination.toPath(),
        StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE,
    )
}
