// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto.cli

import io.orlio.obscuracrypto.MediaExtraction
import io.orlio.obscuracrypto.SharedItemsFile
import io.orlio.obscuracrypto.SharedItemsFile.Kind
import io.orlio.obscuracrypto.SharedItemsPreamble
import io.orlio.obscuracrypto.SharedPassword
import java.io.File

/**
 * What `obscura shared encrypt | verify | decrypt` share with the Swift tool's
 * `SharedCommands`, word for word, so the two print the same.
 */
internal object SharedCommands {

    /** What the app can add, by file extension: the kind and MIME type a file is sent as. */
    val types: Map<String, Pair<Kind, String>> = mapOf(
        "jpg" to (Kind.PHOTO to "image/jpeg"), "jpeg" to (Kind.PHOTO to "image/jpeg"), "png" to (Kind.PHOTO to "image/png"),
        "heic" to (Kind.PHOTO to "image/heic"), "heif" to (Kind.PHOTO to "image/heif"), "tif" to (Kind.PHOTO to "image/tiff"),
        "tiff" to (Kind.PHOTO to "image/tiff"), "webp" to (Kind.PHOTO to "image/webp"), "avif" to (Kind.PHOTO to "image/avif"),
        "jxl" to (Kind.PHOTO to "image/jxl"), "bmp" to (Kind.PHOTO to "image/bmp"), "dng" to (Kind.PHOTO to "image/x-adobe-dng"),
        "gif" to (Kind.GIF to "image/gif"),
        "mov" to (Kind.VIDEO to "video/quicktime"), "mp4" to (Kind.VIDEO to "video/mp4"), "m4v" to (Kind.VIDEO to "video/x-m4v"),
        "3gp" to (Kind.VIDEO to "video/3gpp"), "3g2" to (Kind.VIDEO to "video/3gpp2"),
        "pdf" to (Kind.PDF to "application/pdf"),
    )

    /** The extension for each MIME type in [types]. */
    private val extensions: Map<String, String> = mapOf(
        "image/jpeg" to "jpg", "image/png" to "png", "image/heic" to "heic", "image/heif" to "heif", "image/tiff" to "tiff",
        "image/webp" to "webp", "image/avif" to "avif", "image/jxl" to "jxl", "image/bmp" to "bmp", "image/x-adobe-dng" to "dng",
        "image/gif" to "gif", "video/quicktime" to "mov", "video/mp4" to "mp4", "video/x-m4v" to "m4v", "video/3gpp" to "3gp",
        "video/3gpp2" to "3g2", "application/pdf" to "pdf",
    )

    /** The app asks the same of a password for Send Encrypted. */
    const val MINIMUM_PASSWORD_LENGTH = 6

    /** Why a password the file was sealed under is easy to guess. Said, not refused: the choice is the sender's. */
    fun explanation(problem: SharedPassword.Problem): String {
        val reason = when (problem) {
            SharedPassword.Problem.TOO_SHORT -> "it is under ${SharedPassword.RECOMMENDED_LENGTH} characters"
            SharedPassword.Problem.TOO_SIMPLE -> "it is simple (few different characters, digits alone, or a run like abcdefghij)"
            SharedPassword.Problem.TOO_COMMON -> "it is a well-known password with a few characters added"
        }
        return "this password is easy to guess, as $reason; anyone who keeps a copy of the file can try as long as they like. --generate-password makes one that is not"
    }

    const val OPEN_LOCK = "open, no password: the key is in the file, so anyone who has the file can open it, or change it"

    const val OPEN_NOTE = "sent without a password: anyone who had the file on the way could have read it, " +
        "or made or changed it, so it does not show who sent it"

    fun passwordLock(rounds: Long) = "password: PBKDF2-HMAC-SHA256, $rounds rounds, then AES-256-GCM"

    fun lockSummary(preamble: SharedItemsPreamble): String {
        var text = if (preamble.isOpen) OPEN_LOCK else preamble.locks.firstNotNullOfOrNull { it.rounds }?.let(::passwordLock) ?: "password"
        if (preamble.unknownLockCount > 0) text += "; and ${preamble.unknownLockCount} of a kind this version does not know"
        return text
    }

    /** "4: 1 photo, 1 video, 1 Live Photo, 1 document", in a fixed order. */
    fun itemSummary(kinds: List<String>): String {
        val names = listOf(
            Triple(Kind.PHOTO, "photo", "photos"), Triple(Kind.GIF, "GIF", "GIFs"), Triple(Kind.VIDEO, "video", "videos"),
            Triple(Kind.LIVE_PHOTO, "Live Photo", "Live Photos"), Triple(Kind.PDF, "document", "documents"),
        )
        val parts = names.mapNotNull { (kind, one, many) ->
            val count = kinds.count { it == kind.id }
            if (count == 0) null else "$count ${if (count == 1) one else many}"
        }.toMutableList()
        val unknown = kinds.count { Kind.of(it) == null }
        if (unknown > 0) parts += "$unknown of a kind this version does not know"
        return "${kinds.size}: " + parts.joinToString(", ")
    }

    fun label(kind: Kind): String = when (kind) {
        Kind.PHOTO -> "photo"
        Kind.GIF -> "gif"
        Kind.VIDEO -> "video"
        Kind.LIVE_PHOTO -> "live-photo"
        Kind.PDF -> "document"
    }

    /**
     * From what the bytes are, as `export extract` names files; failing that,
     * from the MIME type the sender gave (looked up, never used as it is), and
     * a Live Photo's motion as a movie.
     */
    fun fileExtension(head: ByteArray, type: String?, isMotion: Boolean): String {
        val sniffed = MediaExtraction.fileExtension(head)
        if (sniffed != "bin") return sniffed
        if (isMotion) return "mov"
        return type?.let { extensions[it] } ?: "bin"
    }

    /** A title as the sender wrote it, safe to print: no control or direction characters that could rewrite the terminal. */
    fun printable(text: String): String {
        val out = StringBuilder()
        var index = 0
        var count = 0
        while (index < text.length && count < SharedItemsFile.MAXIMUM_NAME_LENGTH) {
            val point = text.codePointAt(index)
            val hidden = point < 0x20 || point in 0x7F..0x9F || point == 0x200E || point == 0x200F ||
                point in 0x202A..0x202E || point in 0x2066..0x2069
            if (hidden) out.append('?') else out.appendCodePoint(point)
            index += Character.charCount(point)
            count += 1
        }
        return out.toString()
    }

    /** One source per file, a Live Photo for each still and video sharing a name when asked to pair them, in the order given. */
    fun sources(inputs: List<File>, pairingLivePhotos: Boolean): List<SharedItemsFile.Source> {
        val sources = inputs.map { file ->
            val (kind, type) = types[file.extension.lowercase()]
                ?: throw CliError("${file.name}: not a photo, video or PDF the app can add")
            if (!file.isFile) throw CliError("${file.absolutePath} is not a file")
            SharedItemsFile.Source(file, kind, name = if (kind == Kind.PDF) file.nameWithoutExtension else null, mimeType = type)
        }
        if (!pairingLivePhotos) return sources

        fun stem(file: File) = File(file.absoluteFile.parentFile, file.nameWithoutExtension).path.lowercase()
        val paired = ArrayList<SharedItemsFile.Source>()
        val used = HashSet<Int>()
        for ((index, source) in sources.withIndex()) {
            if (index in used) continue
            val group = listOf(index) + sources.indices.filter { it != index && it !in used && stem(sources[it].file) == stem(source.file) }
            val stills = group.filter { sources[it].kind == Kind.PHOTO }
            val videos = group.filter { sources[it].kind == Kind.VIDEO }
            if (stills.size == 1 && videos.size == 1) {
                val still = sources[stills[0]]
                paired += SharedItemsFile.Source(still.file, Kind.LIVE_PHOTO, sources[videos[0]].file, mimeType = still.mimeType)
                used += stills[0]
                used += videos[0]
            } else {
                paired += source
                used += index
            }
        }
        return paired
    }
}
