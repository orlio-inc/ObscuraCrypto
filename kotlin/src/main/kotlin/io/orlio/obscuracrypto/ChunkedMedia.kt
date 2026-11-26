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
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The header of a chunked media file: 57 bytes in version 2, which new files
 * are written in, and 25 in version 1.
 *
 * ```
 * offset  size  field
 *      0     4  magic, "OBCM"
 *      4     1  version, 0x02 (0x01 for files written before ObscuraCrypto 1.2.0 / Kotlin 1.3.0)
 *      5     4  nonce prefix, random per file
 *      9     8  total plaintext length, big-endian UInt64
 *     17     4  plaintext bytes per chunk, big-endian UInt32 (1 MiB by default)
 *     21     4  flags, big-endian UInt32; bit 0 set means a folder layer
 *     25    32  key salt, random per file (version 2 only)
 * ```
 *
 * Chunks follow at fixed offsets, so chunk `i` starts at
 * `byteCount + i * (chunkSize + overhead)`. Each chunk is AES-GCM combined,
 * `nonce || ciphertext || tag`; only the last can be shorter.
 *
 * Nonces are derived, not random: `noncePrefix (4) || i (8, big-endian)`. The
 * index keeps chunks apart. A folder layer seals each master-encrypted chunk
 * again with the folder key, numbering its nonces on from `chunkCount` so the
 * two layers never share one; its chunks carry 56 bytes of overhead instead
 * of 28.
 *
 * Version 2 also marks the end. The master layer of a file's last chunk sets
 * the counter's top bit ([LAST_CHUNK_FLAG]), and a file always has at least
 * one chunk (an empty file one empty chunk). A file cut short at a chunk
 * boundary, with its recorded length changed to match, ends on an unmarked
 * chunk and is refused; in version 1 it opened, shorter.
 *
 * What keeps files apart differs by version. Version 1 seals every file under
 * the vault's keys themselves, so two files are kept apart only by their
 * 4-byte prefixes, and two that draw the same one (about 1 in 90 for 10,000
 * files under one key) reuse each other's nonces. Version 2 seals each file
 * under keys of its own, derived from the vault's keys and the file's random
 * salt ([ChunkedMediaCipher]), so files never share a key and the prefix no
 * longer carries that weight.
 *
 * Sizes are Longs. The two unsigned fields that could exceed a Long's range,
 * the total length and the chunk size, are accepted only when the file they
 * describe fits in one, which is every real file.
 */
class ChunkedMediaHeader internal constructor(
    val formatVersion: Byte,
    noncePrefix: ByteArray,
    keySalt: ByteArray?,
    val totalPlaintextSize: Long,
    val chunkPlaintextSize: Long,
    val flags: Long,
) {
    val noncePrefix: ByteArray = noncePrefix.copyOf()

    /** The salt each layer's key is derived with; null in version 1, which uses the vault's keys as they are. */
    val keySalt: ByteArray? = keySalt?.copyOf()

    /**
     * A version 1 header, as files written before version 2 have. New files get a version 2 header from [make], and a
     * rewrite that adds or removes a folder layer keeps its file's header with [settingFolderLayer]: building the
     * rewritten header with this instead would drop a version 2 file's salt and leave it unopenable, so it no longer
     * compiles.
     */
    @Deprecated(
        "Makes a version 1 header. Use settingFolderLayer() to change a file's folder layer, make() for a new file, " +
            "or parse() for a file's own header.",
        level = DeprecationLevel.ERROR,
    )
    constructor(noncePrefix: ByteArray, totalPlaintextSize: Long, chunkPlaintextSize: Long, flags: Long) :
        this(0x01, noncePrefix, null, totalPlaintextSize, chunkPlaintextSize, flags)

    init {
        when {
            formatVersion.toInt() == 0x01 && keySalt == null -> {}
            formatVersion.toInt() == 0x02 && keySalt != null && keySalt.size == KEY_SALT_SIZE -> {}
            formatVersion.toInt() == 0x01 || formatVersion.toInt() == 0x02 ->
                throw ObscuraCryptoException.InvalidChunkedHeader("key salt does not match version $formatVersion")
            else -> throw ObscuraCryptoException.InvalidChunkedHeader(
                "version 0x%02x, expected 0x01 or 0x02".format(formatVersion.toInt() and 0xFF)
            )
        }
        if (noncePrefix.size != NONCE_PREFIX_SIZE) {
            throw ObscuraCryptoException.InvalidChunkedHeader("nonce prefix is not 4 bytes")
        }
        if (chunkPlaintextSize <= 0) {
            throw ObscuraCryptoException.InvalidChunkedHeader("chunk size is zero")
        }
        if (chunkPlaintextSize > MAXIMUM_CHUNK_SIZE) {
            throw ObscuraCryptoException.InvalidChunkedHeader("chunk size above 1 GiB")
        }
        // Version 2 defines bit 0 only. The flags are not sealed into the
        // chunks, so a reader that let the others pass would open a file whose
        // header had been changed.
        if (formatVersion.toInt() != 0x01 && flags and FOLDER_LAYER_FLAG.inv() != 0L) {
            throw ObscuraCryptoException.InvalidChunkedHeader("flags 0x%08x, only bit 0 is defined".format(flags))
        }
        // Every size and offset derived from the header has to fit in a Long.
        // Checked here, once, so the plain arithmetic below can never wrap: a
        // header claiming an impossible length is refused as invalid instead of
        // misbehaving for whoever opened the file.
        if (totalPlaintextSize < 0 || checkedFileSize(
                formatVersion, totalPlaintextSize, chunkPlaintextSize, flags and FOLDER_LAYER_FLAG != 0L,
            ) == null
        ) {
            throw ObscuraCryptoException.InvalidChunkedHeader("its length is too large to be a real file")
        }
    }

    fun serialized(): ByteArray {
        val data = ByteArray(byteCount)
        System.arraycopy(MAGIC, 0, data, 0, 4)
        data[4] = formatVersion
        System.arraycopy(noncePrefix, 0, data, 5, 4)
        System.arraycopy(bigEndianBytes(totalPlaintextSize, 8), 0, data, 9, 8)
        System.arraycopy(bigEndianBytes(chunkPlaintextSize, 4), 0, data, 17, 4)
        System.arraycopy(bigEndianBytes(flags, 4), 0, data, 21, 4)
        keySalt?.let { System.arraycopy(it, 0, data, 25, KEY_SALT_SIZE) }
        return data
    }

    /** This header's length, where its first chunk starts. */
    val byteCount: Int get() = byteCount(formatVersion)

    /**
     * The same file with its folder layer flag set or cleared, for a rewrite
     * that adds or removes the layer in place. Everything else, the version,
     * prefix and salt included, stays: the master layer is not touched.
     */
    fun settingFolderLayer(hasFolderLayer: Boolean): ChunkedMediaHeader = ChunkedMediaHeader(
        formatVersion, noncePrefix, keySalt, totalPlaintextSize, chunkPlaintextSize,
        if (hasFolderLayer) flags or FOLDER_LAYER_FLAG else flags and FOLDER_LAYER_FLAG.inv(),
    )

    val hasFolderLayer: Boolean get() = flags and FOLDER_LAYER_FLAG != 0L

    /** Version 2 files have one chunk at least: an empty file's is empty and carries the end mark. */
    val chunkCount: Long get() = chunkCount(formatVersion, totalPlaintextSize, chunkPlaintextSize)

    /** Bytes each chunk adds: 28 for one layer, 56 for two. */
    val chunkOverhead: Int get() = AesGcm.OVERHEAD * (if (hasFolderLayer) 2 else 1)

    fun chunkOffset(index: Long): Long = byteCount + index * (chunkPlaintextSize + chunkOverhead)

    fun plaintextSize(chunk: Long): Long {
        if (chunk != chunkCount - 1) return chunkPlaintextSize
        if (totalPlaintextSize == 0L) return 0
        val remainder = totalPlaintextSize % chunkPlaintextSize
        return if (remainder == 0L) chunkPlaintextSize else remainder
    }

    fun encryptedSize(chunk: Long): Long = plaintextSize(chunk) + chunkOverhead

    /** How long a file with this header must be. */
    val fileSize: Long
        get() = if (chunkCount == 0L) byteCount.toLong() else chunkOffset(chunkCount - 1) + encryptedSize(chunkCount - 1)

    /** `noncePrefix || counter`, the counter as 8 big-endian bytes. */
    fun nonce(counter: Long): ByteArray = noncePrefix + bigEndianBytes(counter, 8)

    /** The nonce of chunk [index]'s master layer. */
    fun masterNonce(chunk: Long): ByteArray = masterNonce(chunk, isLast = chunk == chunkCount - 1)

    /** Version 2 marks the last chunk, so a file cut short is refused; the index alone never reaches the top bit. */
    internal fun masterNonce(chunk: Long, isLast: Boolean): ByteArray =
        nonce(chunk or (if (formatVersion.toInt() >= 0x02 && isLast) LAST_CHUNK_FLAG else 0L))

    /** The nonce of chunk [index]'s folder layer, numbered on past the last chunk. */
    fun folderNonce(chunk: Long): ByteArray = nonce(chunkCount + chunk)

    override fun equals(other: Any?): Boolean =
        other is ChunkedMediaHeader && formatVersion == other.formatVersion &&
            noncePrefix.contentEquals(other.noncePrefix) && keySalt.contentEquals(other.keySalt) &&
            totalPlaintextSize == other.totalPlaintextSize && chunkPlaintextSize == other.chunkPlaintextSize &&
            flags == other.flags

    override fun hashCode(): Int = noncePrefix.contentHashCode()

    companion object {
        /** What a reader needs to have read to parse a header of any version. */
        const val MAXIMUM_SIZE = 57
        val MAGIC: ByteArray = "OBCM".toByteArray(Charsets.US_ASCII)
        /** The version new files are written in. */
        const val CURRENT_VERSION: Byte = 0x02
        const val DEFAULT_CHUNK_SIZE = 1_048_576L

        /**
         * The largest chunk a reader takes, so a made-up header cannot ask for gigabytes of memory per chunk (the JVM cannot hold a chunk
         * over 2 GB at all). Writers use 1 MB.
         */
        const val MAXIMUM_CHUNK_SIZE = 1L shl 30
        const val NONCE_PREFIX_SIZE = 4
        const val KEY_SALT_SIZE = 32
        const val FOLDER_LAYER_FLAG = 0x01L

        /** The size of a version 1 header, the only version before version 2. */
        @Deprecated("a version 1 header's size: read MAXIMUM_SIZE bytes to parse any header, and use byteCount for where its chunks start")
        const val SIZE = 25

        /** The version files were written in before version 2. */
        @Deprecated("the version Kotlin 1.2.0 and earlier wrote; a header's own is formatVersion", ReplaceWith("CURRENT_VERSION"))
        const val VERSION: Byte = 0x01

        /**
         * A header for a new file: the current version, with a fresh random
         * nonce prefix and key salt.
         *
         * The salt is what keeps two files encrypted under the same master key
         * from ever sharing a key, and so a nonce, so it is always drawn here,
         * from the system generator, and never supplied by a caller.
         */
        fun make(
            totalPlaintextSize: Long,
            chunkPlaintextSize: Long = DEFAULT_CHUNK_SIZE,
            hasFolderLayer: Boolean = false,
        ): ChunkedMediaHeader = make(totalPlaintextSize, chunkPlaintextSize, hasFolderLayer, CURRENT_VERSION)

        /** [make] in a chosen version: version 1 only for tests and fixtures that need a file as older releases wrote it. */
        internal fun make(
            totalPlaintextSize: Long, chunkPlaintextSize: Long, hasFolderLayer: Boolean, formatVersion: Byte,
        ): ChunkedMediaHeader = ChunkedMediaHeader(
            formatVersion = formatVersion,
            noncePrefix = Random.bytes(NONCE_PREFIX_SIZE),
            keySalt = if (formatVersion.toInt() == 0x01) null else Random.bytes(KEY_SALT_SIZE),
            totalPlaintextSize = totalPlaintextSize,
            chunkPlaintextSize = chunkPlaintextSize,
            flags = if (hasFolderLayer) FOLDER_LAYER_FLAG else 0,
        )

        /** Parses the header at the start of [data], which should hold [MAXIMUM_SIZE] bytes or the whole file if it is shorter. */
        fun parse(data: ByteArray): ChunkedMediaHeader {
            val shortest = byteCount(0x01)
            if (data.size < shortest) throw ObscuraCryptoException.InvalidChunkedHeader("shorter than $shortest bytes")
            val bytes = data.copyOf(minOf(data.size, MAXIMUM_SIZE))
            if (!bytes.startsWith(MAGIC)) throw ObscuraCryptoException.InvalidChunkedHeader("missing OBCM magic")
            val version = bytes[4]
            if (version.toInt() != 0x01 && version.toInt() != 0x02) {
                throw ObscuraCryptoException.InvalidChunkedHeader(
                    "version 0x%02x, expected 0x01 or 0x02".format(version.toInt() and 0xFF)
                )
            }
            val size = byteCount(version)
            if (bytes.size < size) throw ObscuraCryptoException.InvalidChunkedHeader("shorter than $size bytes")
            return ChunkedMediaHeader(
                formatVersion = version,
                noncePrefix = bytes.range(5, 9),
                keySalt = if (version.toInt() == 0x01) null else bytes.range(25, 57),
                totalPlaintextSize = bytes.bigEndianInt64(9),
                chunkPlaintextSize = bytes.bigEndianUInt32(17),
                flags = bytes.bigEndianUInt32(21),
            )
        }

        private fun byteCount(version: Byte): Int = if (version.toInt() == 0x01) 25 else 57

        /** Set in the master-layer counter of a version 2 file's last chunk. */
        internal const val LAST_CHUNK_FLAG: Long = 1L shl 63

        /** Rounded up without adding first, so it cannot overflow. */
        private fun chunkCount(version: Byte, total: Long, chunk: Long): Long {
            val count = total / chunk + (if (total % chunk == 0L) 0 else 1)
            return if (version.toInt() == 0x01) count else maxOf(count, 1L)
        }

        /** The file length a header describes, or null if it does not fit in a Long. */
        private fun checkedFileSize(version: Byte, total: Long, chunk: Long, hasFolderLayer: Boolean): Long? = try {
            val overhead = (AesGcm.OVERHEAD * (if (hasFolderLayer) 2 else 1)).toLong()
            val encrypted = Math.multiplyExact(chunkCount(version, total, chunk), overhead)
            Math.addExact(Math.addExact(encrypted, total), byteCount(version).toLong())
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
    private val master: SecureBytes
    private val folder: SecureBytes?

    /**
     * [folderKey] is needed to seal or open a file with a folder layer, and to
     * add or remove one. Given for a file without the layer, it is not used.
     */
    init {
        AesGcm.checkKey(masterKey)
        if (folderKey != null) AesGcm.checkKey(folderKey)
        // Kept as the caller's keys, not copied into key specs: closing a key
        // then stops this cipher too, and no copy outlives it. A version 2
        // file's layer keys are derived from them for each chunk, for the same
        // reason.
        master = masterKey
        folder = folderKey
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
        return AesGcm.seal(plaintext, layerKey(master, header, MASTER_LAYER_INFO), header.masterNonce(chunk))
    }

    private fun sealFolder(inner: ByteArray, chunk: Long): ByteArray {
        checkIndex(chunk)
        val key = folder ?: throw ObscuraCryptoException.AuthenticationFailed()
        return AesGcm.seal(inner, layerKey(key, header, FOLDER_LAYER_INFO), header.folderNonce(chunk))
    }

    private fun openMaster(sealed: ByteArray, chunk: Long): ByteArray {
        checkIndex(chunk)
        if (!hasNonce(sealed, header.masterNonce(chunk))) throw ObscuraCryptoException.ChunkNonceMismatch(chunk)
        return AesGcm.open(sealed, layerKey(master, header, MASTER_LAYER_INFO))
    }

    private fun openFolder(stored: ByteArray, chunk: Long): ByteArray {
        checkIndex(chunk)
        val key = folder ?: throw ObscuraCryptoException.AuthenticationFailed()
        if (!hasNonce(stored, header.folderNonce(chunk))) throw ObscuraCryptoException.ChunkNonceMismatch(chunk)
        return AesGcm.open(stored, layerKey(key, header, FOLDER_LAYER_INFO))
    }

    private fun hasNonce(sealed: ByteArray, nonce: ByteArray): Boolean =
        sealed.size >= AesGcm.NONCE_SIZE && constantTimeEquals(sealed.copyOf(AesGcm.NONCE_SIZE), nonce)

    /** Refuses a negative index. Readers check the upper bound against the header first. */
    private fun checkIndex(index: Long) {
        if (index < 0) throw ObscuraCryptoException.ChunkIndexOutOfRange(index)
    }

    internal companion object {
        val MASTER_LAYER_INFO: ByteArray = "OBCM v2 master layer".toByteArray(Charsets.US_ASCII)
        val FOLDER_LAYER_INFO: ByteArray = "OBCM v2 folder layer".toByteArray(Charsets.US_ASCII)

        /**
         * The key that seals one layer of this file. Version 1 uses the vault's
         * key as it is. Version 2 derives one for the file: HKDF-SHA256 with the
         * header's random salt, and an info string naming the layer, so the two
         * layers' keys differ too.
         */
        fun layerKey(key: SecureBytes, header: ChunkedMediaHeader, info: ByteArray): SecretKeySpec {
            val salt = header.keySalt ?: return key.secretKey()
            val derived = key.withBytes { hkdfSha256(it, salt, info, 32) }
            // The spec keeps its own copy.
            return try { SecretKeySpec(derived, "AES") } finally { derived.fill(0) }
        }

        /** HKDF-SHA256 (RFC 5869): extract with [salt], expand with [info]. The caller zeroes the result. */
        fun hkdfSha256(inputKey: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(salt, "HmacSHA256"))
            val pseudorandomKey = mac.doFinal(inputKey)
            val output = ByteArray(length)
            var block = ByteArray(0)
            try {
                mac.init(SecretKeySpec(pseudorandomKey, "HmacSHA256"))
                var written = 0
                var counter = 1
                while (written < length) {
                    mac.update(block)
                    mac.update(info)
                    mac.update(counter.toByte())
                    val next = mac.doFinal()
                    block.fill(0)
                    block = next
                    val take = minOf(block.size, length - written)
                    System.arraycopy(block, 0, output, written, take)
                    written += take
                    counter += 1
                }
                return output
            } finally {
                pseudorandomKey.fill(0)
                block.fill(0)
            }
        }
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
    ): ChunkedMediaHeader = encrypt(source, destination, masterKey, folderKey, chunkSize, ChunkedMediaHeader.CURRENT_VERSION)

    /** [encrypt] in a chosen version: version 1 only for tests and fixtures. */
    internal fun encrypt(
        source: File, destination: File, masterKey: SecureBytes, folderKey: SecureBytes?, chunkSize: Long,
        formatVersion: Byte,
    ): ChunkedMediaHeader {
        val temporary = temporaryFile(destination)
        try {
            val header = source.inputStream().use { input ->
                temporary.outputStream().use { output ->
                    encrypt(input, source.length(), output, masterKey, folderKey, chunkSize, formatVersion)
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
    ): ChunkedMediaHeader =
        encrypt(input, totalSize, output, masterKey, folderKey, chunkSize, ChunkedMediaHeader.CURRENT_VERSION)

    /** [encrypt] in a chosen version: version 1 only for tests and fixtures. */
    internal fun encrypt(
        input: InputStream, totalSize: Long, output: OutputStream, masterKey: SecureBytes, folderKey: SecureBytes?,
        chunkSize: Long, formatVersion: Byte,
    ): ChunkedMediaHeader {
        val header = ChunkedMediaHeader.make(totalSize, chunkSize, folderKey != null, formatVersion)
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
            val head = ByteArray(ChunkedMediaHeader.MAXIMUM_SIZE)
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
