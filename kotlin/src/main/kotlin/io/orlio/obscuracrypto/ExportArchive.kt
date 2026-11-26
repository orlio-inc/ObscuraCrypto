// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.util.Base64
import javax.crypto.spec.SecretKeySpec

/**
 * The unencrypted header of an `.obscura` export: 64 bytes in version 1, 96 in version 2, which this library writes. The Swift
 * package's `ExportHeader`.
 *
 * Version 1:
 * ```
 * offset  size  field
 *      0     4  magic, "OBSV"
 *      4     2  version, big-endian UInt16, 1
 *      6     2  flags, reserved
 *      8    32  salt for the export password
 *     40     4  PBKDF2-HMAC-SHA256 rounds, big-endian UInt32
 *     44    16  password check: the AES-GCM tag of "OBSCURA_EXPORT_V1"
 *     60     4  nonce prefix, random per file
 * ```
 *
 * Version 2:
 * ```
 * offset  size  field
 *      0     4  magic, "OBSV"
 *      4     2  version, 2
 *      6     2  readable by: the oldest reader version that opens the file, 2
 *      8     2  flags: bits 0-7 must be understood, bits 8-15 may be ignored; none defined
 *     10     2  key block length: bytes of the key block after the header (1 to 4,096)
 *     12     4  record size: plaintext bytes in every record (1,048,576)
 *     16    32  salt for the export password
 *     48     4  PBKDF2-HMAC-SHA256 rounds
 *     52     4  nonce prefix, random per file
 *     56    32  key commitment, derived from the export key (below)
 *     88     8  reserved, zero
 *     96     n  key block: a lock count (1 byte), then each lock as type (1) || body length (2, big-endian) || body
 * ```
 *
 * The key block is room for more ways to open the file beside its password, such as a recovery key, added later without a new
 * version: a reader skips a lock of a type it does not know and opens the file with its password as before. No type is defined yet,
 * and writers write none (a count of 0). The password, its salt, rounds and the key commitment stay in the fixed header. The key block
 * is part of the header's bytes, so every record authenticates it too.
 *
 * A version 2 export key, `PBKDF2-HMAC-SHA256(password, salt, rounds)`, is never used as it is. HKDF-SHA256 over it, with a salt of
 * 32 zero bytes, gives the record key (info "OBSV v2 records") and the key commitment (info "OBSV v2 key commitment"), each 32 bytes.
 */
class ExportHeader private constructor(
    val version: Int,
    /** The oldest reader version that opens the file: 1 for version 1. */
    val readableBy: Int,
    val flags: Int,
    salt: ByteArray,
    val kdfIterations: Long,
    verificationTag: ByteArray,
    noncePrefix: ByteArray,
    /** Version 2: plaintext bytes in every record. 0 in version 1, whose records vary in length. */
    val recordSize: Int,
    keyCommitment: ByteArray,
    bytes: ByteArray,
) {
    val salt: ByteArray = salt.copyOf()

    /** Version 1's password check; empty in version 2. */
    val verificationTag: ByteArray = verificationTag.copyOf()
    val noncePrefix: ByteArray = noncePrefix.copyOf()

    /** Version 2's password check, which also commits the file to one key; empty in version 1. */
    val keyCommitment: ByteArray = keyCommitment.copyOf()

    /** The header as stored, a version 2 key block included. Every version 2 record authenticates it. */
    internal val bytes: ByteArray = bytes.copyOf()

    /** Version 2: lock types in the key block, in file order. This library knows none yet and reads past them all; empty in version 1. */
    val lockTypes: List<Int> = if (version >= 2) lockTypes(this.bytes.copyOfRange(VERSION_2_SIZE, this.bytes.size)) else emptyList()

    val byteCount: Int get() = bytes.size

    /** Version 1: `noncePrefix || counter`. Records count from 0; the password check uses the largest counter, which is -1 here. */
    internal fun nonce(counter: Long): ByteArray = noncePrefix + bigEndianBytes(counter, 8)

    fun serialized(): ByteArray = bytes.copyOf()

    companion object {
        /** Version 1's size, and what every reader reads first. */
        const val SIZE = 64
        const val VERSION_2_SIZE = 96

        /** The most a version 2 key block may take. */
        const val MAXIMUM_KEY_BLOCK = 4_096

        /** Enough to hold the header of any version this library reads, its key block included. */
        const val MAXIMUM_SIZE = VERSION_2_SIZE + MAXIMUM_KEY_BLOCK
        val MAGIC: ByteArray = "OBSV".toByteArray(Charsets.US_ASCII)

        /** The version this library writes, and the newest it reads. */
        const val VERSION = 2
        internal val VERIFICATION_PLAINTEXT: ByteArray = "OBSCURA_EXPORT_V1".toByteArray(Charsets.US_ASCII)
        private val KEY_COMMITMENT_INFO = "OBSV v2 key commitment".toByteArray(Charsets.US_ASCII)
        private val RECORD_KEY_INFO = "OBSV v2 records".toByteArray(Charsets.US_ASCII)
        private const val REQUIRED_FLAGS = 0x00FF

        /** The record sizes a version 2 reader accepts. */
        internal val RECORD_SIZES = 4_096..1_048_576

        private fun u16(data: ByteArray, at: Int) = ((data[at].toInt() and 0xFF) shl 8) or (data[at + 1].toInt() and 0xFF)

        /** The types of a key block's locks, every byte accounted for. */
        internal fun lockTypes(keyBlock: ByteArray): List<Int> {
            val types = ArrayList<Int>()
            var offset = 1
            repeat(keyBlock[0].toInt() and 0xFF) {
                if (offset + 3 > keyBlock.size) throw ObscuraCryptoException.InvalidExport("the key block is cut short")
                val length = u16(keyBlock, offset + 1)
                if (offset + 3 + length > keyBlock.size) throw ObscuraCryptoException.InvalidExport("the key block is cut short")
                types += keyBlock[offset].toInt() and 0xFF
                offset += 3 + length
            }
            if (offset != keyBlock.size) throw ObscuraCryptoException.InvalidExport("the key block has bytes left over")
            return types
        }

        /** A version 2 header's key block length, from its first 96 bytes. */
        internal fun keyBlockLengthOf(data: ByteArray): Int = u16(data, 10)

        /** The version a header says it is, from its first 64 bytes. */
        internal fun versionOf(data: ByteArray): Int = if (data.size >= 6) u16(data, 4) else 0

        /** Parses the header at the start of [data], which must hold all of it: 64 bytes for version 1, 96 and the key block for version 2. */
        fun parse(data: ByteArray): ExportHeader {
            if (data.size < SIZE) throw ObscuraCryptoException.InvalidExport("shorter than $SIZE bytes")
            if (!data.startsWith(MAGIC)) throw ObscuraCryptoException.InvalidExport("missing OBSV magic")
            val version = u16(data, 4)
            return when {
                version == 1 -> ExportHeader(
                    version = 1, readableBy = 1, flags = u16(data, 6), salt = data.range(8, 40), kdfIterations = data.bigEndianUInt32(40),
                    verificationTag = data.range(44, 60), noncePrefix = data.range(60, 64), recordSize = 0, keyCommitment = ByteArray(0),
                    bytes = data.copyOf(SIZE),
                )
                version >= 2 -> {
                    // Later versions keep this layout and say what they need.
                    val readableBy = u16(data, 6)
                    if (readableBy < 2 || readableBy > version) {
                        throw ObscuraCryptoException.InvalidExport("version $version, readable by $readableBy")
                    }
                    if (readableBy > VERSION) throw ObscuraCryptoException.ExportNewerVersion()
                    if (data.size < VERSION_2_SIZE) throw ObscuraCryptoException.InvalidExport("shorter than $VERSION_2_SIZE bytes")
                    val flags = u16(data, 8)
                    if (flags and REQUIRED_FLAGS != 0) throw ObscuraCryptoException.ExportNewerVersion()
                    val recordSize = data.bigEndianUInt32(12)
                    if (recordSize !in RECORD_SIZES.first.toLong()..RECORD_SIZES.last.toLong()) {
                        throw ObscuraCryptoException.InvalidExport("records of an impossible size")
                    }
                    val keyBlockLength = u16(data, 10)
                    if (keyBlockLength !in 1..MAXIMUM_KEY_BLOCK) throw ObscuraCryptoException.InvalidExport("a key block of an impossible length")
                    if (data.size < VERSION_2_SIZE + keyBlockLength) {
                        throw ObscuraCryptoException.InvalidExport("the file ends inside its key block")
                    }
                    ExportHeader(
                        version = version, readableBy = readableBy, flags = flags, salt = data.range(16, 48),
                        kdfIterations = data.bigEndianUInt32(48), verificationTag = ByteArray(0), noncePrefix = data.range(52, 56),
                        recordSize = recordSize.toInt(), keyCommitment = data.range(56, 88),
                        bytes = data.copyOf(VERSION_2_SIZE + keyBlockLength),
                    )
                }
                else -> throw ObscuraCryptoException.InvalidExport("version $version")
            }
        }

        /** A version 1 header, as earlier releases wrote them: for tests and fixtures. */
        internal fun version1(salt: ByteArray, rounds: Long, verificationTag: ByteArray, noncePrefix: ByteArray): ExportHeader {
            val data = ByteArray(SIZE)
            System.arraycopy(MAGIC, 0, data, 0, 4)
            System.arraycopy(bigEndianBytes(1, 2), 0, data, 4, 2)
            System.arraycopy(salt, 0, data, 8, 32)
            System.arraycopy(bigEndianBytes(rounds, 4), 0, data, 40, 4)
            System.arraycopy(verificationTag, 0, data, 44, 16)
            System.arraycopy(noncePrefix, 0, data, 60, 4)
            return parse(data)
        }

        /** A version 2 header for a new export, with an empty key block unless a test gives another. */
        internal fun version2(
            salt: ByteArray, rounds: Long, noncePrefix: ByteArray, recordSize: Int, keyCommitment: ByteArray,
            keyBlock: ByteArray = byteArrayOf(0),
        ): ExportHeader {
            val data = ByteArray(VERSION_2_SIZE + keyBlock.size)
            System.arraycopy(bigEndianBytes(keyBlock.size.toLong(), 2), 0, data, 10, 2)
            System.arraycopy(keyBlock, 0, data, VERSION_2_SIZE, keyBlock.size)
            System.arraycopy(MAGIC, 0, data, 0, 4)
            System.arraycopy(bigEndianBytes(VERSION.toLong(), 2), 0, data, 4, 2)
            System.arraycopy(bigEndianBytes(2, 2), 0, data, 6, 2)
            System.arraycopy(bigEndianBytes(recordSize.toLong(), 4), 0, data, 12, 4)
            System.arraycopy(salt, 0, data, 16, 32)
            System.arraycopy(bigEndianBytes(rounds, 4), 0, data, 48, 4)
            System.arraycopy(noncePrefix, 0, data, 52, 4)
            System.arraycopy(keyCommitment, 0, data, 56, 32)
            return parse(data)
        }

        /**
         * What a version 2 header holds to check a password, and what ties the file to one key, since AES-GCM does not: 32 bytes HKDF
         * derives from the export key.
         */
        internal fun keyCommitment(exportKey: SecureBytes): ByteArray = KeyDerivation.subkey(exportKey, KEY_COMMITMENT_INFO)

        /** The key a version 2 export's records are sealed under, derived from the export key, which the commitment is made from. */
        internal fun recordKey(exportKey: SecureBytes): SecretKeySpec = KeyDerivation.subkeySpec(exportKey, RECORD_KEY_INFO)
    }
}

/**
 * What an export's manifest says about its layout and keys, and nothing else.
 *
 * The manifest is the app's JSON description of the exported vault. Only these fields are read, the ones needed to split the encrypted
 * stream into files and to find the master key; everything else in it, the app's own description of folders and photos, is ignored by
 * this library and left to the app.
 *
 * It is read by this library's strict JSON reader ([SharedItemsJson], here taking numbers with fractions, as the app writes dates that
 * way), the same as the Swift package's: a key twice, a number where a string belongs, or base64 in any but its standard padded form is
 * refused, so one export never reads two ways.
 */
class ExportIndex private constructor(
    vaultSalt: ByteArray,
    wrappedMasterKey: ByteArray,
    /** Length of the vault file that follows the manifest in the stream. */
    val databaseSize: Long,
    /** Media files in the order they follow the vault file. */
    val mediaFiles: List<MediaFile>,
) {
    class MediaFile(
        /** The file's ID in the vault's media pool, always a UUID. */
        val id: String,
        val dataSize: Long,
        val thumbnailSize: Long,
    )

    /** Salt and wrapped master key, as in the vault header. */
    val vaultSalt: ByteArray = vaultSalt.copyOf()
    val wrappedMasterKey: ByteArray = wrappedMasterKey.copyOf()

    /**
     * Every byte the stream holds after the manifest: the vault file and each media file's data and thumbnail. Added up once, with
     * overflow checked (an `ArithmeticException`, which [parse] turns into a refusal): the sizes are the file's word, and a plain `+`
     * would wrap sizes near `Long.MAX_VALUE` round to a small total.
     */
    val contentSize: Long = mediaFiles.fold(databaseSize) { total, media ->
        Math.addExact(Math.addExact(total, media.dataSize), media.thumbnailSize)
    }

    /** Unwraps the exported vault's master key. The app exports with the vault's own password, so this is normally the export password too. */
    fun unlockMasterKey(password: String): SecureBytes {
        val passwordKey = KeyDerivation.pbkdf2SHA256(password, vaultSalt, KeyDerivation.VAULT_ITERATIONS)
        try {
            return AesGcm.unwrapKey(wrappedMasterKey, passwordKey)
        } catch (e: ObscuraCryptoException.AuthenticationFailed) {
            throw ObscuraCryptoException.WrongPassword()
        } finally {
            passwordKey.clear()
        }
    }

    companion object {
        internal const val MAXIMUM_MANIFEST_DEPTH = 32

        /**
         * Parses the index out of the manifest JSON, refusing anything that could not have come from the app: a media ID that is not a
         * UUID would otherwise become a path component when files are written out.
         */
        fun parse(manifest: ByteArray): ExportIndex {
            val unreadable = ObscuraCryptoException.InvalidExport("manifest is not readable")
            val root = try {
                SharedItemsJson.parse(manifest, allowingDecimals = true, maximumDepth = MAXIMUM_MANIFEST_DEPTH)
            } catch (e: SharedItemsJson.Malformed) {
                throw unreadable
            } as? SharedItemsJson.Value.Object ?: throw unreadable
            fun integer(value: SharedItemsJson.Value?): Long = (value as? SharedItemsJson.Value.Integer)?.value ?: throw unreadable

            // Standard base64 with padding, as Swift's `JSONEncoder` writes `Data`, and nothing a lenient decoder would also take.
            fun base64(value: SharedItemsJson.Value?): ByteArray {
                val text = (value as? SharedItemsJson.Value.Text)?.value ?: throw unreadable
                val bytes = try {
                    Base64.getDecoder().decode(text)
                } catch (e: IllegalArgumentException) {
                    throw unreadable
                }
                if (Base64.getEncoder().encodeToString(bytes) != text) throw unreadable
                return bytes
            }

            val exportVersion = integer(root["exportVersion"])
            if (exportVersion != 1L) throw ObscuraCryptoException.InvalidExport("manifest version $exportVersion, expected 1")
            val salt = base64(root["vaultSalt"])
            val wrapped = base64(root["encryptedMEK"])
            val databaseSize = integer(root["databaseSize"])
            if (salt.size != KeyDerivation.SALT_LENGTH || wrapped.size != VaultHeader.WRAPPED_KEY_SIZE || databaseSize < 0) {
                throw ObscuraCryptoException.InvalidExport("manifest key fields have the wrong sizes")
            }
            val entries = root["mediaFiles"] as? SharedItemsJson.Value.Array ?: throw unreadable
            // IDs differing only by case name one file on a file system that ignores case, so they count as the same ID.
            val seen = HashSet<String>()
            val files = entries.elements.map { entry ->
                val media = entry as? SharedItemsJson.Value.Object ?: throw unreadable
                val id = (media["mediaId"] as? SharedItemsJson.Value.Text)?.value ?: throw unreadable
                val dataSize = integer(media["dataSize"])
                val thumbnailSize = integer(media["thumbSize"])
                if (!isCanonicalUuid(id) || dataSize < 0 || thumbnailSize < 0 || !seen.add(id.lowercase())) {
                    throw ObscuraCryptoException.InvalidExport("manifest lists a media file that is not a unique UUID with valid sizes")
                }
                MediaFile(id, dataSize, thumbnailSize)
            }
            return try {
                ExportIndex(salt, wrapped, databaseSize, files)
            } catch (e: ArithmeticException) {
                throw ObscuraCryptoException.InvalidExport("manifest sizes add up to too much")
            }
        }
    }
}

/**
 * Reads an `.obscura` export, version 1 or 2. The Swift package's `ExportArchive`.
 *
 * Both carry one plaintext stream, sealed with AES-256-GCM under the export key, `PBKDF2-HMAC-SHA256(password, salt, rounds)`: the
 * manifest (JSON), then the vault file (header and encrypted database, `databaseSize` bytes), then for each media file in the
 * manifest's order its `.data.enc` bytes and its `.thumb.enc` bytes. Media files are carried exactly as the vault stores them, so each
 * is still encrypted with the vault's master key inside.
 *
 * - Version 1: records of a 4-byte length and one AES-GCM message, record `i` with nonce `noncePrefix || i`. Record 0 is the manifest
 *   alone, and every file starts a new record, so the records show how many files there are and the size of each.
 * - Version 2: records all of one size after a 96-byte header, nonce `noncePrefix || i` with the top bit set on the last, the header as
 *   every record's associated data. The stream opens with the manifest's length (4 bytes) and ends in zeros to the Padmé length, rounded
 *   up to whole records, so the file shows only roughly how much it holds.
 *
 * This reader checks every nonce against its position, so records moved, copied, dropped or cut off are refused. Reads from any
 * [InputStream], which on Android is what a document the user picked opens as. Close it when done.
 */
class ExportArchive private constructor(
    private val input: PushbackInputStream,
    val header: ExportHeader,
    val index: ExportIndex,
    manifest: ByteArray,
    private val key: SecretKeySpec,
    /** Version 2: the records as one stream. */
    private val stream: SharedItemsRecordStream?,
) : Closeable {

    /** The manifest JSON exactly as it was written, for the parts this library does not read: the app's description of folders and photos. */
    val manifestBytes: ByteArray = manifest.copyOf()

    /** Version 1: the next record's counter. */
    private var counter = 1L

    /** Reads the vault file's bytes, still encrypted with the master key, into [output]. */
    fun copyDatabase(output: OutputStream) = pass(index.databaseSize, output)

    /** Reads past the vault file without keeping it. */
    fun skipDatabase() = pass(index.databaseSize, null)

    /**
     * Writes one stored media file, still encrypted with the master key, to [output], or reads past it when [output] is null. Call in
     * the manifest's order, once for its data and once for its thumbnail; a size of zero writes nothing.
     */
    fun copyStoredFile(size: Long, output: OutputStream?) = pass(size, output)

    fun copyStoredFile(size: Long, to: File?) {
        if (to == null) return pass(size, null)
        to.outputStream().use {
            pass(size, it)
            it.flush()
            it.fd.sync()
        }
    }

    /**
     * The next [count] bytes of the stream after the manifest: the vault file and the media files, end to end, read in the manifest's
     * order. In a version 1 export a read may not run past the end of a file, as a record there never holds the end of one file and the
     * start of the next.
     */
    fun read(count: Int): ByteArray {
        val out = ByteArrayOutputStream(count)
        pass(count.toLong(), out)
        return out.toByteArray()
    }

    /**
     * Whether everything has been read: in version 1, no record follows; in version 2, only padding follows, to the last record and its
     * end mark (anything else throws). Checked after the last media file, so an export with records appended or altered at its end is
     * noticed.
     */
    fun isAtEnd(): Boolean {
        stream?.let {
            it.finish()
            return true
        }
        val next = input.read()
        if (next < 0) return true
        input.unread(next)
        return false
    }

    override fun close() = input.close()

    // MARK: Records

    private fun pass(size: Long, output: OutputStream?) {
        stream?.let { return it.read(size) { piece -> output?.write(piece) } }
        var remaining = size
        while (remaining > 0) {
            val record = nextRecord()
            if (record.size.toLong() > remaining) throw ObscuraCryptoException.InvalidExport("a record runs past the end of its file")
            output?.write(record)
            remaining -= record.size
        }
    }

    /** Version 1: a file's bytes always start a new record, and a record never holds the end of one file and the start of the next. */
    private fun nextRecord(): ByteArray {
        val record = readRecord(input, key, header.nonce(counter), MAXIMUM_RECORD_SIZE)
            ?: throw ObscuraCryptoException.InvalidExport("the export ends early")
        counter += 1
        return record
    }

    companion object {
        /** A manifest larger than this is not one the app wrote. */
        const val MAXIMUM_MANIFEST_SIZE = 256L shl 20
        const val MAXIMUM_RECORD_SIZE = 1_048_576L + AesGcm.OVERHEAD

        /** Opens [file]. See [open]. */
        fun open(file: File, password: String): ExportArchive = open(file.inputStream(), password)

        /** Opens [stream], checks [password] against the header, and reads the index. The archive owns the stream from here and closes it on failure. */
        fun open(stream: InputStream, password: String): ExportArchive {
            val input = PushbackInputStream(BufferedInputStream(stream, 64 * 1024), 1)
            try {
                val first = input.readExactly(ExportHeader.SIZE) ?: ByteArray(0)
                val bytes = if (first.size == ExportHeader.SIZE && first.startsWith(ExportHeader.MAGIC) && ExportHeader.versionOf(first) >= 2) {
                    val fixed = first + (input.readExactly(ExportHeader.VERSION_2_SIZE - ExportHeader.SIZE) ?: ByteArray(0))
                    // The key block, when its length is one a reader takes; parse refuses any other.
                    val keyBlockLength = if (fixed.size == ExportHeader.VERSION_2_SIZE) ExportHeader.keyBlockLengthOf(fixed) else 0
                    if (keyBlockLength in 1..ExportHeader.MAXIMUM_KEY_BLOCK) fixed + (input.readExactly(keyBlockLength) ?: ByteArray(0)) else fixed
                } else {
                    first
                }
                val header = ExportHeader.parse(bytes)
                if (header.kdfIterations < KeyDerivation.VAULT_ITERATIONS) {
                    throw ObscuraCryptoException.IterationsBelowMinimum(header.kdfIterations)
                }
                if (header.kdfIterations > VaultHeader.MAXIMUM_ITERATIONS) {
                    throw ObscuraCryptoException.InvalidExport("${header.kdfIterations} key derivation rounds is implausibly many")
                }

                val exportKey = KeyDerivation.pbkdf2SHA256(password, header.salt, header.kdfIterations.toInt())
                // Version 1 seals under the export key itself; version 2 under a key derived from it.
                val key = if (header.version == 1) exportKey.secretKey() else ExportHeader.recordKey(exportKey)
                val manifest: ByteArray
                val records: SharedItemsRecordStream?
                try {
                    if (header.version == 1) {
                        val check = AesGcm.seal(ExportHeader.VERIFICATION_PLAINTEXT, key, header.nonce(-1))
                        val tag = check.copyOfRange(check.size - AesGcm.TAG_SIZE, check.size)
                        if (!constantTimeEquals(tag, header.verificationTag)) throw ObscuraCryptoException.WrongPassword()
                        manifest = readRecord(input, key, header.nonce(0), MAXIMUM_MANIFEST_SIZE)
                            ?: throw ObscuraCryptoException.InvalidExport("no manifest")
                        records = null
                    } else {
                        if (!constantTimeEquals(ExportHeader.keyCommitment(exportKey), header.keyCommitment)) {
                            throw ObscuraCryptoException.WrongPassword()
                        }
                        records = SharedItemsRecordStream(input, key, header.noncePrefix, header.bytes, header.recordSize) {
                            ObscuraCryptoException.InvalidExport(it)
                        }
                        val length = records.read(4).bigEndianUInt32(0)
                        if (length <= 0 || length > MAXIMUM_MANIFEST_SIZE) {
                            throw ObscuraCryptoException.InvalidExport("a manifest of an impossible length")
                        }
                        manifest = records.read(length.toInt())
                    }
                } finally {
                    exportKey.clear()
                }
                return ExportArchive(input, header, ExportIndex.parse(manifest), manifest, key, records)
            } catch (e: Throwable) {
                input.close()
                throw e
            }
        }

        /**
         * Reads [file] to its end with [password]: every record authenticated and in its place, every file the manifest lists present,
         * nothing after the last. What an app runs on an export it has just written, before telling anyone it is done.
         */
        fun verify(file: File, password: String, progress: ((bytesRead: Long, total: Long) -> Unit)? = null) =
            verify(file.inputStream(), password, progress)

        fun verify(stream: InputStream, password: String, progress: ((bytesRead: Long, total: Long) -> Unit)? = null) {
            open(stream, password).use { archive ->
                val total = archive.index.contentSize
                var done = 0L
                archive.skipDatabase()
                done += archive.index.databaseSize
                progress?.invoke(done, total)
                for (media in archive.index.mediaFiles) {
                    archive.copyStoredFile(media.dataSize, null as OutputStream?)
                    archive.copyStoredFile(media.thumbnailSize, null as OutputStream?)
                    done += media.dataSize + media.thumbnailSize
                    progress?.invoke(done, total)
                }
                if (!archive.isAtEnd()) throw ObscuraCryptoException.InvalidExport("there is data after the last file")
            }
        }

        /** One version 1 record, or null at the end of the file. */
        internal fun readRecord(input: InputStream, key: SecretKeySpec, nonce: ByteArray, maximumSize: Long): ByteArray? {
            val first = input.read()
            if (first < 0) return null
            val rest = input.readExactly(3) ?: throw ObscuraCryptoException.InvalidExport("the export ends early")
            val prefix = byteArrayOf(first.toByte()) + rest
            val length = prefix.bigEndianUInt32(0)
            if (length <= AesGcm.OVERHEAD || length > maximumSize) {
                throw ObscuraCryptoException.InvalidExport("a record has an impossible length")
            }
            val sealed = input.readExactlyGrowing(length.toInt()) ?: throw ObscuraCryptoException.InvalidExport("the export ends early")
            if (!constantTimeEquals(sealed.copyOf(AesGcm.NONCE_SIZE), nonce)) {
                throw ObscuraCryptoException.InvalidExport("a record carries the wrong nonce: records were reordered or replaced")
            }
            return AesGcm.open(sealed, key)
        }
    }
}

/**
 * Writes an `.obscura` export, version 2: the layout [ExportArchive] reads, and the Swift package's `ExportWriter` writes.
 *
 * Usage: [begin], then [writeManifest], then the vault file with [writeFile], then each media file's data and thumbnail with
 * [writeFile] in the manifest's order, then [finish]. The manifest says how much follows it, and the writer checks that exactly that
 * much is written. [ExportArchive.verify] should be run on the result before it is offered as a backup.
 */
class ExportWriter private constructor(
    private val output: OutputStream,
    val header: ExportHeader,
    private val key: SecretKeySpec,
) {
    private var sealer: RecordSealer? = null

    /** Bytes the manifest says follow it, and how many have been written. */
    private var expected = 0L
    private var written = 0L

    /** Writes the manifest, which comes first and says how much follows it. */
    fun writeManifest(manifest: ByteArray) {
        check(sealer == null) { "the manifest is written once, first" }
        require(manifest.size <= ExportArchive.MAXIMUM_MANIFEST_SIZE)
        val index = ExportIndex.parse(manifest)
        expected = index.contentSize
        // Far beyond any phone, and low enough that the padding below cannot overflow.
        if (expected >= 1L shl 60) throw ObscuraCryptoException.InvalidExport("the manifest lists too much")
        val content = 4L + manifest.size + expected
        val recordSize = header.recordSize
        val recordCount = (SharedItemsFile.padme(content) + recordSize - 1) / recordSize
        val records = RecordSealer(output, key, header.noncePrefix, header.bytes, recordSize, recordCount) {
            ObscuraCryptoException.InvalidExport("more written than the manifest lists")
        }
        records.append(bigEndianBytes(manifest.size.toLong(), 4))
        records.append(manifest)
        sealer = records
    }

    /** Writes exactly [size] bytes read from [input]: the vault file, then each media file's data and thumbnail, in the manifest's order. */
    fun writeFile(input: InputStream, size: Long) {
        val records = checkNotNull(sealer) { "write the manifest first" }
        val buffer = ByteArray(RECORD_SIZE)
        var remaining = size
        while (remaining > 0) {
            val want = minOf(remaining, RECORD_SIZE.toLong()).toInt()
            if (input.readFully(buffer, want) != want) {
                throw ObscuraCryptoException.InvalidExport("a file is shorter than the size recorded for it")
            }
            written += want
            if (written > expected) throw ObscuraCryptoException.InvalidExport("more written than the manifest lists")
            records.append(buffer, want)
            remaining -= want
        }
    }

    fun writeFile(file: File) {
        file.inputStream().use { writeFile(it, file.length()) }
    }

    /** Pads the stream, seals the last record with its end mark, and flushes. Refuses if less was written than the manifest lists. */
    fun finish() {
        val records = checkNotNull(sealer) { "write the manifest first" }
        if (written != expected) throw ObscuraCryptoException.InvalidExport("less written than the manifest lists")
        records.finish(0)
        output.flush()
    }

    companion object {
        const val RECORD_SIZE = 1_048_576

        /** Derives the export key from [password], writes the 96-byte header and its empty key block to [output], and returns the writer. */
        fun begin(output: OutputStream, password: String, iterations: Int = KeyDerivation.VAULT_ITERATIONS): ExportWriter =
            begin(output, password, iterations, RECORD_SIZE)

        /** With a chosen record size and key block: other values only for tests. */
        internal fun begin(
            output: OutputStream, password: String, iterations: Int, recordSize: Int, keyBlock: ByteArray = byteArrayOf(0),
        ): ExportWriter {
            require(iterations >= KeyDerivation.VAULT_ITERATIONS) { "an export must use at least 600,000 rounds" }
            val salt = KeyDerivation.makeSalt()
            val noncePrefix = Random.bytes(4)
            val exportKey = KeyDerivation.pbkdf2SHA256(password, salt, iterations)
            try {
                val header = ExportHeader.version2(
                    salt, iterations.toLong(), noncePrefix, recordSize, ExportHeader.keyCommitment(exportKey), keyBlock,
                )
                output.write(header.serialized())
                return ExportWriter(output, header, ExportHeader.recordKey(exportKey))
            } finally {
                exportKey.clear()
            }
        }
    }
}

/**
 * Writes an `.obscura` export in version 1's layout, as releases before ObscuraCrypto 1.3.0 (Kotlin) and the iPhone app before it
 * wrote them: for tests and fixtures that need an export from then. Every file starts a new record, which is what version 2 hides.
 */
internal class ExportWriterVersion1 private constructor(
    private val output: OutputStream,
    private val header: ExportHeader,
    private val key: SecretKeySpec,
) {
    private var counter = 0L

    /** Writes the manifest JSON as record 0. */
    fun writeManifest(manifest: ByteArray) {
        check(counter == 0L) { "the manifest is the first record" }
        require(manifest.size <= ExportArchive.MAXIMUM_MANIFEST_SIZE)
        writeRecord(manifest, 0, manifest.size)
    }

    /** Writes exactly [size] bytes read from [input] as records of up to 1 MiB. A file's bytes start a new record; a size of zero writes nothing. */
    fun writeFile(input: InputStream, size: Long) {
        check(counter > 0) { "write the manifest first" }
        val buffer = ByteArray(ExportWriter.RECORD_SIZE)
        var remaining = size
        while (remaining > 0) {
            val want = minOf(remaining, ExportWriter.RECORD_SIZE.toLong()).toInt()
            if (input.readFully(buffer, want) != want) {
                throw ObscuraCryptoException.InvalidExport("a file is shorter than the size recorded for it")
            }
            writeRecord(buffer, 0, want)
            remaining -= want
        }
    }

    fun writeFile(file: File) {
        file.inputStream().use { writeFile(it, file.length()) }
    }

    fun finish() = output.flush()

    private fun writeRecord(bytes: ByteArray, offset: Int, length: Int) {
        val plaintext = if (offset == 0 && length == bytes.size) bytes else bytes.copyOfRange(offset, offset + length)
        val sealed = AesGcm.seal(plaintext, key, header.nonce(counter))
        output.write(bigEndianBytes(sealed.size.toLong(), 4))
        output.write(sealed)
        counter += 1
    }

    companion object {
        fun begin(output: OutputStream, password: String, iterations: Int = KeyDerivation.VAULT_ITERATIONS): ExportWriterVersion1 {
            val salt = KeyDerivation.makeSalt()
            val noncePrefix = Random.bytes(4)
            val exportKey = KeyDerivation.pbkdf2SHA256(password, salt, iterations)
            val key = exportKey.secretKey()
            exportKey.clear()
            val unsigned = ExportHeader.version1(salt, iterations.toLong(), ByteArray(16), noncePrefix)
            val check = AesGcm.seal(ExportHeader.VERIFICATION_PLAINTEXT, key, unsigned.nonce(-1))
            val header = ExportHeader.version1(salt, iterations.toLong(), check.copyOfRange(check.size - AesGcm.TAG_SIZE, check.size), noncePrefix)
            output.write(header.serialized())
            return ExportWriterVersion1(output, header, key)
        }
    }
}
