// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.LinkOption

/** Turns stored media files back into ordinary photos and videos. */
object MediaExtraction {

    sealed class Outcome {
        /** Decrypted to this file. */
        class Extracted(val file: File) : Outcome()

        /**
         * The master key does not open it. For a file the vault references,
         * that means a protected folder's second layer.
         */
        object NotOpenedByMasterKey : Outcome()
    }

    /**
     * Decrypts a stored `.data.enc` file, single-shot or chunked, into
     * [directory] as `<id>.<extension>`, the extension chosen from what the
     * decrypted bytes actually are.
     *
     * [id] becomes a file name, so it must be a UUID; anything else is
     * refused. Never overwrites: a name already taken in [directory] is an
     * error. Writes through a temporary file, so a failure leaves nothing.
     */
    fun extract(
        storedFile: File,
        id: String,
        masterKey: SecureBytes,
        folderKey: SecureBytes? = null,
        directory: File,
    ): Outcome {
        if (!isCanonicalUuid(id)) throw ObscuraCryptoException.InvalidExport("$id is not a media ID")
        val temporary = privateTemporaryFile(File(directory, id))
        try {
            val prefix = readPrefix(storedFile, 4)
            try {
                when (MediaFormat.detect(prefix)) {
                    MediaFormat.CHUNKED ->
                        ChunkedMediaReader(storedFile).decrypt(temporary, masterKey, folderKey)
                    MediaFormat.SINGLE_SHOT ->
                        temporary.writeBytes(SingleShotMedia.decrypt(storedFile.readBytes(), masterKey, folderKey))
                }
            } catch (e: ObscuraCryptoException.AuthenticationFailed) {
                return Outcome.NotOpenedByMasterKey
            }

            val destination = File(directory, "$id.${fileExtension(readPrefix(temporary, 16))}")
            // A link at this name, even a dangling one, counts as taken.
            if (Files.exists(destination.toPath(), LinkOption.NOFOLLOW_LINKS)) {
                throw ObscuraCryptoException.InvalidExport("${destination.name} already exists")
            }
            Files.move(temporary.toPath(), destination.toPath())
            return Outcome.Extracted(destination)
        } finally {
            temporary.delete()
        }
    }

    /**
     * Whether the master key opens a stored file, checked as cheaply as the
     * format allows: a single-shot file whole, a chunked file by its first
     * chunk.
     */
    fun masterKeyOpens(storedFile: File, masterKey: SecureBytes): Boolean {
        val prefix = try {
            readPrefix(storedFile, 4)
        } catch (e: Exception) {
            return false
        }
        return try {
            when (MediaFormat.detect(prefix)) {
                MediaFormat.CHUNKED -> {
                    val reader = ChunkedMediaReader(storedFile)
                    if (reader.header.chunkCount == 0L) {
                        !reader.header.hasFolderLayer
                    } else {
                        !reader.header.hasFolderLayer && reader.readChunk(0, masterKey).let { true }
                    }
                }
                MediaFormat.SINGLE_SHOT -> SingleShotMedia.decrypt(storedFile.readBytes(), masterKey).let { true }
            }
        } catch (e: Exception) {
            false
        }
    }

    /** A file extension from a file's first bytes. */
    fun fileExtension(head: ByteArray): String {
        val bytes = head.copyOf(minOf(head.size, 16))
        fun starts(signature: ByteArray, at: Int = 0): Boolean =
            bytes.size >= at + signature.size && bytes.copyOfRange(at, at + signature.size).contentEquals(signature)
        fun ascii(text: String) = text.toByteArray(Charsets.US_ASCII)

        if (starts(byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte()))) return "jpg"
        if (starts(byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47))) return "png"
        if (starts(ascii("GIF8"))) return "gif"
        if (starts(ascii("RIFF")) && starts(ascii("WEBP"), 8)) return "webp"
        if (starts(byteArrayOf(0x49, 0x49, 0x2A, 0x00)) || starts(byteArrayOf(0x4D, 0x4D, 0x00, 0x2A))) return "tiff"
        if (starts(ascii("ftyp"), 4) && bytes.size >= 12) {
            return when (String(bytes, 8, 4, Charsets.UTF_8)) {
                "heic", "heix", "hevc", "heim", "heis", "hevm", "hevs", "mif1", "msf1" -> "heic"
                "avif", "avis" -> "avif"
                "qt  " -> "mov"
                else -> "mp4"
            }
        }
        return "bin"
    }

    private fun readPrefix(file: File, count: Int): ByteArray = RandomAccessFile(file, "r").use { handle ->
        val buffer = ByteArray(count)
        var total = 0
        while (total < count) {
            val read = handle.read(buffer, total, count - total)
            if (read < 0) break
            total += read
        }
        buffer.copyOf(total)
    }
}
