// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.io.BufferedInputStream
import java.io.Closeable
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.util.Base64
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.int
import kotlinx.serialization.json.longOrNull

/**
 * The 64-byte header of an `.obscura` export, the only unencrypted part.
 *
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
 */
class ExportHeader(
    val version: Int,
    val flags: Int,
    salt: ByteArray,
    val kdfIterations: Long,
    verificationTag: ByteArray,
    noncePrefix: ByteArray,
) {
    val salt: ByteArray = salt.copyOf()
    val verificationTag: ByteArray = verificationTag.copyOf()
    val noncePrefix: ByteArray = noncePrefix.copyOf()

    /** `noncePrefix || counter`, as in the chunked media format. Chunks count from 0; the password check uses the largest counter, `UInt64.max`, which is -1 here. */
    internal fun nonce(counter: Long): ByteArray = noncePrefix + bigEndianBytes(counter, 8)

    fun serialized(): ByteArray {
        val data = ByteArray(SIZE)
        System.arraycopy(MAGIC, 0, data, 0, 4)
        System.arraycopy(bigEndianBytes(version.toLong(), 2), 0, data, 4, 2)
        System.arraycopy(bigEndianBytes(flags.toLong(), 2), 0, data, 6, 2)
        System.arraycopy(salt, 0, data, 8, 32)
        System.arraycopy(bigEndianBytes(kdfIterations, 4), 0, data, 40, 4)
        System.arraycopy(verificationTag, 0, data, 44, 16)
        System.arraycopy(noncePrefix, 0, data, 60, 4)
        return data
    }

    companion object {
        const val SIZE = 64
        val MAGIC: ByteArray = "OBSV".toByteArray(Charsets.US_ASCII)
        const val VERSION = 1
        internal val VERIFICATION_PLAINTEXT: ByteArray = "OBSCURA_EXPORT_V1".toByteArray(Charsets.US_ASCII)

        fun parse(data: ByteArray): ExportHeader {
            if (data.size < SIZE) throw ObscuraCryptoException.InvalidExport("shorter than $SIZE bytes")
            val header = data.copyOf(SIZE)
            if (!header.startsWith(MAGIC)) throw ObscuraCryptoException.InvalidExport("missing OBSV magic")
            val version = (header[4].toInt() and 0xFF shl 8) or (header[5].toInt() and 0xFF)
            if (version != VERSION) throw ObscuraCryptoException.InvalidExport("version $version, expected 1")
            return ExportHeader(
                version = version,
                flags = (header[6].toInt() and 0xFF shl 8) or (header[7].toInt() and 0xFF),
                salt = header.range(8, 40),
                kdfIterations = header.bigEndianUInt32(40),
                verificationTag = header.range(44, 60),
                noncePrefix = header.range(60, 64),
            )
        }
    }
}

/**
 * What an export's manifest says about its layout and keys, and nothing else.
 *
 * The manifest is the app's JSON description of the exported vault. Only these
 * fields are read, the ones needed to split the encrypted stream into files and
 * to find the master key; everything else in it, the app's own description of
 * folders and photos, is ignored by this library and left to the app.
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
     * Unwraps the exported vault's master key. The app exports with the
     * vault's own password, so this is normally the export password too.
     */
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
        /**
         * Parses the index out of the manifest JSON, refusing anything that
         * could not have come from the app: a media ID that is not a UUID
         * would otherwise become a path component when files are written out.
         *
         * Binary fields are standard base64, as Swift's `JSONEncoder` writes
         * `Data`.
         */
        fun parse(manifest: ByteArray): ExportIndex {
            val unreadable = ObscuraCryptoException.InvalidExport("manifest is not readable")
            val root: JsonObject
            val exportVersion: Int
            val vaultSalt: ByteArray
            val encryptedMEK: ByteArray
            val databaseSize: Long
            val media: List<Triple<String, Long, Long>>
            try {
                root = Json.parseToJsonElement(manifest.toString(Charsets.UTF_8)) as? JsonObject ?: throw unreadable
                exportVersion = root.primitive("exportVersion").int
                vaultSalt = Base64.getDecoder().decode(root.primitive("vaultSalt").content)
                encryptedMEK = Base64.getDecoder().decode(root.primitive("encryptedMEK").content)
                databaseSize = root.primitive("databaseSize").long()
                media = (root["mediaFiles"] as? JsonArray ?: throw unreadable).map {
                    val entry = it as? JsonObject ?: throw unreadable
                    Triple(
                        entry.primitive("mediaId").also { id -> if (!id.isString) throw unreadable }.content,
                        entry.primitive("dataSize").long(),
                        entry.primitive("thumbSize").long(),
                    )
                }
            } catch (e: ObscuraCryptoException) {
                throw e
            } catch (e: Exception) {
                throw unreadable
            }

            if (exportVersion != 1) {
                throw ObscuraCryptoException.InvalidExport("manifest version $exportVersion, expected 1")
            }
            if (vaultSalt.size != KeyDerivation.SALT_LENGTH || encryptedMEK.size != VaultHeader.WRAPPED_KEY_SIZE ||
                databaseSize < 0
            ) {
                throw ObscuraCryptoException.InvalidExport("manifest key fields have the wrong sizes")
            }
            val seen = HashSet<String>()
            val files = media.map { (id, dataSize, thumbSize) ->
                if (!isCanonicalUuid(id) || dataSize < 0 || thumbSize < 0 || !seen.add(id)) {
                    throw ObscuraCryptoException.InvalidExport(
                        "manifest lists a media file that is not a unique UUID with valid sizes"
                    )
                }
                MediaFile(id, dataSize, thumbSize)
            }
            return ExportIndex(vaultSalt, encryptedMEK, databaseSize, files)
        }

        private fun JsonObject.primitive(key: String): JsonPrimitive =
            this[key] as? JsonPrimitive ?: throw ObscuraCryptoException.InvalidExport("manifest is not readable")

        private fun JsonPrimitive.long(): Long =
            longOrNull ?: throw ObscuraCryptoException.InvalidExport("manifest is not readable")
    }
}

/**
 * Reads an `.obscura` export.
 *
 * After the header, the file is a sequence of records, each a 4-byte
 * big-endian length and then one AES-256-GCM message (combined layout) sealed
 * with the export key, `PBKDF2-HMAC-SHA256(password, salt, rounds)`. Record
 * `i` carries nonce `noncePrefix || i`; this reader checks it, so records moved
 * or copied between exports are refused.
 *
 * The decrypted records, read in order, are one stream:
 * 1. record 0 on its own: the manifest, JSON;
 * 2. the vault file, header and encrypted database, `databaseSize` bytes;
 * 3. for each media file in the manifest's order, its `.data.enc` bytes and
 *    then its `.thumb.enc` bytes, each starting a new record.
 *
 * Media files are carried exactly as the vault stores them, so each is still
 * encrypted with the vault's master key inside the export's own encryption.
 *
 * Reads from any [InputStream], which on Android is what a document the user
 * picked opens as. Close it when done.
 */
class ExportArchive private constructor(
    private val input: PushbackInputStream,
    val header: ExportHeader,
    val index: ExportIndex,
    manifest: ByteArray,
    private val key: SecretKeySpec,
) : Closeable {

    /**
     * The manifest JSON exactly as it was written, for the parts this library does
     * not read: the app's description of folders and photos.
     */
    val manifestBytes: ByteArray = manifest.copyOf()

    private var counter = 1L

    /** Reads the vault file's bytes, still encrypted with the master key, into [output]. */
    fun copyDatabase(output: OutputStream) = copyRecords(index.databaseSize, output)

    /** Reads past the vault file without keeping it. */
    fun skipDatabase() = copyRecords(index.databaseSize, null)

    /**
     * Writes one stored media file, still encrypted with the master key, to
     * [output], or reads past it when [output] is null. Call in the manifest's
     * order, once for its data and once for its thumbnail; a size of zero
     * writes nothing.
     */
    fun copyStoredFile(size: Long, output: OutputStream?) = copyRecords(size, output)

    fun copyStoredFile(size: Long, to: File?) {
        if (to == null) return copyRecords(size, null)
        to.outputStream().use {
            copyRecords(size, it)
            it.flush()
            it.fd.sync()
        }
    }

    /**
     * Whether every record has been read. Checked after the last media file
     * so an export with records appended is noticed.
     */
    fun isAtEnd(): Boolean {
        val next = input.read()
        if (next < 0) return true
        input.unread(next)
        return false
    }

    override fun close() = input.close()

    // MARK: Records

    /**
     * A file's bytes always start a new record, and a record never holds the
     * end of one file and the start of the next: the app writes each file in
     * 1 MB reads of its own.
     */
    private fun copyRecords(size: Long, output: OutputStream?) {
        var remaining = size
        while (remaining > 0) {
            val record = nextRecord()
            if (record.size.toLong() > remaining) {
                throw ObscuraCryptoException.InvalidExport("a record runs past the end of its file")
            }
            output?.write(record)
            remaining -= record.size
        }
    }

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

        /**
         * Opens [stream], checks [password] against the header, and reads the
         * index. The archive owns the stream from here and closes it on
         * failure.
         */
        fun open(stream: InputStream, password: String): ExportArchive {
            val input = PushbackInputStream(BufferedInputStream(stream, 64 * 1024), 1)
            try {
                val header = ExportHeader.parse(input.readExactly(ExportHeader.SIZE) ?: ByteArray(0))
                if (header.kdfIterations < KeyDerivation.VAULT_ITERATIONS) {
                    throw ObscuraCryptoException.IterationsBelowMinimum(header.kdfIterations)
                }
                if (header.kdfIterations > VaultHeader.MAXIMUM_ITERATIONS) {
                    throw ObscuraCryptoException.InvalidExport(
                        "${header.kdfIterations} key derivation rounds is implausibly many"
                    )
                }

                val exportKey = KeyDerivation.pbkdf2SHA256(password, header.salt, header.kdfIterations.toInt())
                val key = exportKey.secretKey()
                exportKey.clear()
                val check = AesGcm.seal(ExportHeader.VERIFICATION_PLAINTEXT, key, header.nonce(-1))
                val tag = check.copyOfRange(check.size - AesGcm.TAG_SIZE, check.size)
                if (!constantTimeEquals(tag, header.verificationTag)) throw ObscuraCryptoException.WrongPassword()

                val manifest = readRecord(input, key, header.nonce(0), MAXIMUM_MANIFEST_SIZE)
                    ?: throw ObscuraCryptoException.InvalidExport("no manifest")
                return ExportArchive(input, header, ExportIndex.parse(manifest), manifest, key)
            } catch (e: Throwable) {
                input.close()
                throw e
            }
        }

        /** One record, or null at the end of the file. */
        internal fun readRecord(input: InputStream, key: SecretKeySpec, nonce: ByteArray, maximumSize: Long): ByteArray? {
            val first = input.read()
            if (first < 0) return null
            val rest = input.readExactly(3) ?: throw ObscuraCryptoException.InvalidExport("the export ends early")
            val prefix = byteArrayOf(first.toByte()) + rest
            val length = prefix.bigEndianUInt32(0)
            if (length <= AesGcm.OVERHEAD || length > maximumSize) {
                throw ObscuraCryptoException.InvalidExport("a record has an impossible length")
            }
            val sealed = input.readExactly(length.toInt()) ?: throw ObscuraCryptoException.InvalidExport("the export ends early")
            if (!constantTimeEquals(sealed.copyOf(AesGcm.NONCE_SIZE), nonce)) {
                throw ObscuraCryptoException.InvalidExport(
                    "a record carries the wrong nonce: records were reordered or replaced"
                )
            }
            return AesGcm.open(sealed, key)
        }
    }
}

/**
 * Writes an `.obscura` export in the layout [ExportArchive] reads, which is
 * the layout the iOS app writes and reads.
 *
 * This is the one thing the Kotlin library does that the Swift package does
 * not: the iPhone app has its own writer. It exists so that an Android export
 * is produced by code that is tested against the Swift reader, instead of by
 * format knowledge scattered through an app.
 *
 * Usage: [begin], then [writeManifest], then the vault file with [writeFile],
 * then each media file's data and thumbnail with [writeFile] in the manifest's
 * order, then [finish].
 */
class ExportWriter private constructor(
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

    /**
     * Writes exactly [size] bytes read from [input] as records of up to 1 MiB.
     * A file's bytes start a new record; a size of zero writes nothing.
     */
    fun writeFile(input: InputStream, size: Long) {
        check(counter > 0) { "write the manifest first" }
        val buffer = ByteArray(RECORD_SIZE)
        var remaining = size
        while (remaining > 0) {
            val want = minOf(remaining, RECORD_SIZE.toLong()).toInt()
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
        const val RECORD_SIZE = 1_048_576

        /** Derives the export key from [password], writes the 64-byte header to [output], and returns the writer. */
        fun begin(output: OutputStream, password: String, iterations: Int = KeyDerivation.VAULT_ITERATIONS): ExportWriter {
            require(iterations >= KeyDerivation.VAULT_ITERATIONS) { "an export must use at least 600,000 rounds" }
            val salt = KeyDerivation.makeSalt()
            val noncePrefix = Random.bytes(4)
            val exportKey = KeyDerivation.pbkdf2SHA256(password, salt, iterations)
            val key = exportKey.secretKey()
            exportKey.clear()
            val unsignedHeader = ExportHeader(
                ExportHeader.VERSION, 0, salt, iterations.toLong(), ByteArray(16), noncePrefix,
            )
            val check = AesGcm.seal(ExportHeader.VERIFICATION_PLAINTEXT, key, unsignedHeader.nonce(-1))
            val header = ExportHeader(
                ExportHeader.VERSION, 0, salt, iterations.toLong(),
                check.copyOfRange(check.size - AesGcm.TAG_SIZE, check.size), noncePrefix,
            )
            output.write(header.serialized())
            return ExportWriter(output, header, key)
        }
    }
}
