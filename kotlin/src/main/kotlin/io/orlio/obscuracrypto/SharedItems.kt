// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.io.BufferedInputStream
import java.io.Closeable
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.security.MessageDigest
import javax.crypto.spec.SecretKeySpec

/**
 * The `.obscurashared` file the app's Send Encrypted makes: photos, videos and
 * documents chosen in one vault, for another person to add to theirs. The
 * Swift package's `SharedItemsFile`, byte for byte: a file written by either
 * opens with the other. The layout is in FORMATS.md.
 *
 * It is sealed under a password the sender picks and tells the receiver
 * separately, or under none. Without a password the key travels in the file
 * itself (an open lock): the file still does not show what it holds to a photo
 * library or a preview, but anyone who has it can open it, and change it and
 * seal it again. Only a password protects the items.
 *
 * Without the password the file shows only that it is one, how it is locked,
 * and its length, padded so that it tells little more than how much the items
 * come to: how many items there are and how large each is are inside the
 * encryption.
 *
 * Built to be read by apps newer and older than the one that wrote it: a file
 * whose "readable by" this version meets opens; flags, locks, kinds of item,
 * parts and JSON members it does not know are passed over; only a file that
 * needs a newer reader says so ([ObscuraCryptoException.SharedItemsNewerVersion]),
 * never that it is damaged.
 */
object SharedItemsFile {
    const val FILE_EXTENSION = "obscurashared"
    val MAGIC: ByteArray = "OBSI".toByteArray(Charsets.US_ASCII)

    /** The format this library writes, and the newest it reads. */
    const val VERSION = 3

    /** What a file this library writes asks of its reader. */
    const val READABLE_BY = 3
    const val HEADER_SIZE = 64

    /** Plaintext bytes in each record, as this library writes them. */
    const val RECORD_SIZE = 65_536

    /** The record sizes a reader accepts. */
    val RECORD_SIZES = 4_096..1_048_576

    /** The share sheet's own cap on a selection. */
    const val MAXIMUM_ITEMS = 1_000
    const val MAXIMUM_PARTS_PER_ITEM = 16

    /** Bounds a reader holds a file to, so a made-up one cannot ask for unbounded memory or work. */
    const val MAXIMUM_KEY_BLOCK = 4_096
    const val MAXIMUM_MANIFEST = 2 * 1_048_576
    const val MAXIMUM_ROUNDS = 10_000_000L

    /** The most key derivation rounds a reader spends on one file, all its password locks together. */
    const val ROUNDS_BUDGET = 10_000_000L

    /** A document's title, at most, in code points (Swift's Unicode scalars). */
    const val MAXIMUM_NAME_LENGTH = 200
    internal const val MAXIMUM_PASSWORD_LOCKS_TRIED = 4
    internal const val REQUIRED_FLAGS = 0x00FF
    internal const val CONTENT_KEY_SIZE = 32

    /**
     * The key block opens with a commitment to the content key: 32 bytes HKDF derives from it. AES-GCM does not commit to its key, so
     * a password lock can be made that opens under several passwords, each to a different key; a reader takes only the key the file
     * commits to, so every file has one key and one meaning.
     */
    internal const val KEY_COMMITMENT_SIZE = 32
    private val KEY_COMMITMENT_INFO = "OBSI v3 key commitment".toByteArray(Charsets.US_ASCII)

    /** The records are sealed under a key HKDF derives from the content key, not under the content key itself. */
    private val RECORD_KEY_INFO = "OBSI v3 records".toByteArray(Charsets.US_ASCII)

    internal fun keyCommitment(contentKey: SecureBytes): ByteArray = KeyDerivation.subkey(contentKey, KEY_COMMITMENT_INFO)

    internal fun recordKey(contentKey: SecureBytes): SecretKeySpec = KeyDerivation.subkeySpec(contentKey, RECORD_KEY_INFO)

    /** Rounds, salt and the sealed content key. */
    internal const val PASSWORD_LOCK_SIZE = 4 + KeyDerivation.SALT_LENGTH + CONTENT_KEY_SIZE + AesGcm.OVERHEAD

    /** Set in the last record's nonce, so a file cut short at a record boundary ends on a record without it. */
    internal const val LAST_RECORD_FLAG = Long.MIN_VALUE

    enum class LockType(val id: Int) {
        PASSWORD(1),
        OPEN(2),
        ;

        companion object {
            fun of(id: Int): LockType? = entries.firstOrNull { it.id == id }
        }
    }

    enum class Kind(val id: String) {
        PHOTO("photo"),
        GIF("gif"),
        VIDEO("video"),
        LIVE_PHOTO("livePhoto"),

        /** A document, as one PDF. */
        PDF("pdf"),
        ;

        companion object {
            fun of(id: String): Kind? = entries.firstOrNull { it.id == id }
        }
    }

    enum class Role(val id: String) {
        /** The item's file; a Live Photo's still. */
        FILE("file"),

        /** A Live Photo's motion video. */
        MOTION("motion"),
        ;

        companion object {
            fun of(id: String): Role? = entries.firstOrNull { it.id == id }
        }
    }

    data class Part(
        val role: String,
        val size: Long,
        /** Lowercase hex SHA-256 of the plaintext. */
        val sha256: String,
    )

    data class Item(
        /** Kept as written: a kind this library does not know is read past. */
        val kind: String,
        /** MIME type of the file part, when the sender knew it. */
        val type: String? = null,
        /** A document's title, so it arrives under its own name. */
        val name: String? = null,
        val parts: List<Part>,
    ) {
        /** The kind, when this library knows it. */
        val knownKind: Kind? get() = Kind.of(kind)

        fun part(role: Role): Part? = parts.firstOrNull { it.role == role.id }

        /**
         * Everything a reader holds an item to, the same in Swift and Kotlin: kinds and roles of 1 to 64 printable ASCII characters, a
         * type of 1 to 100, 1 to 16 parts each with a size above 0 and a 64-digit lowercase hash, no role twice, a title of at most 200
         * code points with no control or direction characters, and the parts a known kind needs: a file, and a motion video exactly when
         * it is a Live Photo.
         */
        val isWellFormed: Boolean
            get() {
                if (!isToken(kind, 64) || type?.let { isToken(it, 100) } == false || name?.let(::isAcceptableName) == false) return false
                if (parts.size !in 1..MAXIMUM_PARTS_PER_ITEM) return false
                if (!parts.all { it.size > 0 && isToken(it.role, 64) && isHash(it.sha256) }) return false
                if (parts.map { it.role }.toSet().size != parts.size) return false
                val known = knownKind ?: return true
                if (part(Role.FILE) == null) return false
                return (known == Kind.LIVE_PHOTO) == (part(Role.MOTION) != null)
            }
    }

    data class Manifest(val items: List<Item>)

    /** One item to send: a plaintext file, and a Live Photo's motion video. */
    class Source(
        val file: File,
        val kind: Kind,
        val pairedVideo: File? = null,
        /** A document's title. */
        val name: String? = null,
        /** The file's MIME type, when known. */
        val mimeType: String? = null,
    )

    // MARK: Writing

    /**
     * Seals [sources] (plaintext files, read a record at a time) into [destination], under [password], or in an open lock when it is
     * null. Any password is taken: [SharedPassword.problem] is for saying, before, what makes one easy to guess.
     *
     * Every file is read twice, as the manifest needs each part's size and hash before any part is written; nothing is held in memory.
     * Writes to a temporary file beside [destination] and moves it into place only when complete, so a failure leaves nothing.
     */
    fun write(sources: List<Source>, password: String?, destination: File) {
        write(sources, password, destination, KeyDerivation.VAULT_ITERATIONS, RECORD_SIZE)
    }

    /**
     * [write] with chosen rounds, record size, manifest and padding: other values only for tests and fixtures
     * (fewer rounds than a reader accepts, small records that keep fixtures small, manifests and padding no writer makes).
     */
    internal fun write(
        sources: List<Source>, password: String?, destination: File, rounds: Int, recordSize: Int,
        manifestOverride: ByteArray? = null, padding: Byte = 0,
    ) {
        if (sources.isEmpty() || sources.size > MAXIMUM_ITEMS) throw ObscuraCryptoException.TooManySharedItems(sources.size)
        if (recordSize !in RECORD_SIZES) throw ObscuraCryptoException.InvalidSharedItems("a record size outside $RECORD_SIZES")
        val items = sources.map { source ->
            if ((source.kind == Kind.LIVE_PHOTO) != (source.pairedVideo != null)) {
                throw ObscuraCryptoException.InvalidSharedItems(
                    if (source.kind == Kind.LIVE_PHOTO) "a Live Photo needs its motion video" else "only a Live Photo has a motion video",
                )
            }
            val parts = arrayListOf(part(Role.FILE, source.file, recordSize))
            source.pairedVideo?.let { parts += part(Role.MOTION, it, recordSize) }
            Item(source.kind.id, source.mimeType?.takeIf { isToken(it, 100) }, source.name?.let(::cleanedName), parts)
        }
        val manifest = manifestOverride ?: SharedItemsJson.encode(Manifest(items))
        if (manifest.size > MAXIMUM_MANIFEST) throw ObscuraCryptoException.TooManySharedItems(sources.size)

        val content = 4L + manifest.size + items.flatMap { it.parts }.sumOf { it.size }
        val recordCount = (padme(content) + recordSize - 1) / recordSize

        val contentKey = SecureBytes.random(CONTENT_KEY_SIZE)
        try {
            val prefix = Random.bytes(4)
            // A password lock is sealed with the header as associated data, and the header gives the key block's length: the lock's
            // size is fixed, so the header is final before the lock is made.
            val header = makeHeader(
                KEY_COMMITMENT_SIZE + 1 + 3 + if (password == null) CONTENT_KEY_SIZE else PASSWORD_LOCK_SIZE,
                recordSize, Random.bytes(16), prefix,
            )
            val keyBlock = keyCommitment(contentKey) + if (password != null) {
                val salt = KeyDerivation.makeSalt()
                val passwordKey = KeyDerivation.pbkdf2SHA256(password, salt, rounds)
                val sealed = try {
                    contentKey.withBytes { AesGcm.seal(it, passwordKey.secretKey(), Random.bytes(AesGcm.NONCE_SIZE), header) }
                } finally {
                    passwordKey.clear()
                }
                byteArrayOf(1) + lock(LockType.PASSWORD, bigEndianBytes(rounds.toLong(), 4) + salt + sealed)
            } else {
                byteArrayOf(1) + lock(LockType.OPEN, contentKey.toByteArray())
            }
            val preamble = header + keyBlock

            val temporary = temporaryFile(destination)
            var finished = false
            try {
                FileOutputStream(temporary).use { out ->
                    out.write(preamble)
                    val sealer = RecordSealer(out, recordKey(contentKey), prefix, preamble, recordSize, recordCount)
                    sealer.append(bigEndianBytes(manifest.size.toLong(), 4))
                    sealer.append(manifest)
                    for ((source, item) in sources.zip(items)) {
                        for ((file, part) in listOfNotNull(source.file, source.pairedVideo).zip(item.parts)) {
                            sealPart(file, part, sealer, recordSize)
                        }
                    }
                    sealer.finish(padding)
                    out.flush()
                    out.fd.sync()
                }
                moveIntoPlace(temporary, destination)
                finished = true
            } finally {
                if (!finished) temporary.delete()
            }
        } finally {
            contentKey.clear()
        }
    }

    /**
     * One part's file into the stream, checked against the size and hash the manifest already gives, so a file that changes meanwhile
     * is never sent as one the reader would call damaged.
     */
    private fun sealPart(file: File, part: Part, sealer: RecordSealer, recordSize: Int) {
        val digest = MessageDigest.getInstance("SHA-256")
        var written = 0L
        FileInputStream(file).use { input ->
            val buffer = ByteArray(recordSize)
            while (true) {
                val read = input.readFully(buffer)
                if (read <= 0) break
                written += read
                if (written > part.size) break
                digest.update(buffer, 0, read)
                sealer.append(buffer, read)
                if (read < buffer.size) break
            }
        }
        if (written != part.size || hex(digest.digest()) != part.sha256) {
            throw ObscuraCryptoException.InvalidSharedItems("${file.name} changed while it was being sealed")
        }
    }

    /** Whether [file] needs a password to open, from its header and key block alone. */
    fun needsPassword(file: File): Boolean = !SharedItemsPreamble.read(file).isOpen

    fun needsPassword(stream: InputStream): Boolean = !SharedItemsPreamble.read(stream).isOpen

    // MARK: Helpers

    /** `noncePrefix || index`, the index's top bit set on the last record. */
    internal fun recordNonce(prefix: ByteArray, index: Long, isLast: Boolean): ByteArray =
        prefix + bigEndianBytes(if (isLast) index or LAST_RECORD_FLAG else index, 8)

    /**
     * Padmé (Nikitin et al., 2019): [length] rounded up so that only its top bits remain, at most 12% more, which leaves a file's
     * length saying little more than its order of magnitude.
     */
    internal fun padme(length: Long): Long {
        if (length <= 1) return length
        val exponent = 63 - java.lang.Long.numberOfLeadingZeros(length)
        val exponentBits = 64 - java.lang.Long.numberOfLeadingZeros(exponent.toLong())
        val mask = (1L shl (exponent - exponentBits)) - 1
        return (length + mask) and mask.inv()
    }

    private fun makeHeader(keyBlockLength: Int, recordSize: Int, fileId: ByteArray, prefix: ByteArray): ByteArray {
        val header = ByteArray(HEADER_SIZE)
        System.arraycopy(MAGIC, 0, header, 0, 4)
        System.arraycopy(bigEndianBytes(VERSION.toLong(), 2), 0, header, 4, 2)
        System.arraycopy(bigEndianBytes(READABLE_BY.toLong(), 2), 0, header, 6, 2)
        // [8:10] flags: none defined.
        System.arraycopy(bigEndianBytes(keyBlockLength.toLong(), 2), 0, header, 10, 2)
        System.arraycopy(bigEndianBytes(recordSize.toLong(), 4), 0, header, 12, 4)
        System.arraycopy(fileId, 0, header, 16, 16)
        System.arraycopy(prefix, 0, header, 32, 4)
        return header
    }

    private fun lock(type: LockType, body: ByteArray): ByteArray =
        byteArrayOf(type.id.toByte()) + bigEndianBytes(body.size.toLong(), 2) + body

    /** A part's size and hash, read a record at a time. */
    private fun part(role: Role, file: File, recordSize: Int): Part {
        val digest = MessageDigest.getInstance("SHA-256")
        var size = 0L
        FileInputStream(file).use { input ->
            val buffer = ByteArray(recordSize)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
                size += read
            }
        }
        if (size <= 0) throw ObscuraCryptoException.InvalidSharedItems("${file.name} is empty")
        return Part(role.id, size, hex(digest.digest()))
    }

    internal fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(java.util.Locale.ROOT, it) }

    /** 1 to [maximum] characters, each printable ASCII other than space. */
    internal fun isToken(text: String, maximum: Int): Boolean =
        text.length in 1..maximum && text.all { it.code in 0x21..0x7E }

    internal fun isHash(text: String): Boolean = text.length == 64 && text.all { it in '0'..'9' || it in 'a'..'f' }

    /** Characters a title may not hold: those [isBreakingCharacter] and [isInvisibleCharacter] name. */
    internal fun isHiddenCharacter(point: Int): Boolean = isBreakingCharacter(point) || isInvisibleCharacter(point)

    /** Control characters, and those that change the direction of the text around them or break the line. Writers make them spaces. */
    internal fun isBreakingCharacter(point: Int): Boolean =
        point in 0x00..0x1F || point in 0x7F..0x9F || point == 0x061C || point == 0x200E || point == 0x200F ||
            point == 0x2028 || point == 0x2029 || point in 0x202A..0x202E || point in 0x2066..0x2069

    /**
     * Characters that show nothing at all, so a title could look blank, or like another, while it carries more: Unicode's
     * Default_Ignorable_Code_Point set (zero-width spaces, the byte order mark, Hangul fillers, variation selectors, tag characters and
     * the rest), written out here so Swift and Kotlin decide alike whatever their own Unicode tables say. Writers leave them out.
     * Allowed after all: the joiners U+200C and U+200D, which Persian, Indic scripts and emoji need, and the text and emoji presentation
     * selectors U+FE0E and U+FE0F, but only right after a visible character ([isPresentationSelector]).
     */
    internal fun isInvisibleCharacter(point: Int): Boolean =
        point == 0x00AD || point == 0x034F || point == 0x115F || point == 0x1160 || point == 0x17B4 || point == 0x17B5 ||
            point in 0x180B..0x180F || point == 0x200B || point in 0x2060..0x206F || point == 0x3164 || point in 0xFE00..0xFE0D ||
            point == 0xFEFF || point == 0xFFA0 || point in 0xFFF0..0xFFFB || point in 0x1BCA0..0x1BCA3 || point in 0x1D173..0x1D17A ||
            point in 0xE0000..0xE0FFF

    internal fun isPresentationSelector(point: Int): Boolean = point == 0xFE0E || point == 0xFE0F

    /** Spaces of every kind, listed for the same reason. */
    internal fun isSpace(point: Int): Boolean =
        point == 0x20 || point == 0xA0 || point == 0x1680 || point in 0x2000..0x200A || point == 0x202F || point == 0x205F || point == 0x3000

    /** Shows something: not a space, not the blank braille pattern, not a joiner or presentation selector, nor anything hidden. */
    internal fun isVisible(point: Int): Boolean =
        !(isSpace(point) || point == 0x2800 || point == 0x200C || point == 0x200D || isPresentationSelector(point) || isHiddenCharacter(point))

    internal fun isAcceptableName(name: String): Boolean {
        val points = name.codePoints().toArray()
        if (points.size > MAXIMUM_NAME_LENGTH || points.none(::isVisible)) return false
        for ((index, point) in points.withIndex()) {
            if (isHiddenCharacter(point)) return false
            if (isPresentationSelector(point) && (index == 0 || !isVisible(points[index - 1]))) return false
        }
        return true
    }

    /**
     * A title as writers put it in: breaking characters made spaces, invisible ones and presentation selectors not after a visible
     * character left out, spaces at either end taken off, at most 200 code points; null when nothing visible is left.
     */
    internal fun cleanedName(name: String): String? {
        val kept = ArrayList<Int>()
        for (point in name.codePoints().toArray()) {
            if (isInvisibleCharacter(point)) continue
            if (isPresentationSelector(point) && !(kept.lastOrNull()?.let(::isVisible) ?: false)) continue
            kept += if (isBreakingCharacter(point)) ' '.code else point
        }
        fun trimmed(list: List<Int>) = list.dropWhile(::isSpace).dropLastWhile(::isSpace)
        val points = trimmed(trimmed(kept).take(MAXIMUM_NAME_LENGTH))
        return if (points.any(::isVisible)) String(points.toIntArray(), 0, points.size) else null
    }
}

/** Fills records of the plaintext stream and seals each as it fills. */
internal class RecordSealer(
    private val output: OutputStream,
    private val key: SecretKeySpec,
    private val prefix: ByteArray,
    private val associatedData: ByteArray,
    private val recordSize: Int,
    private val recordCount: Long,
    /** Thrown when more is written than the records were counted for. */
    private val overflow: () -> Exception = { ObscuraCryptoException.InvalidSharedItems("more to write than the records hold") },
) {
    private val buffer = ByteArray(recordSize)
    private var filled = 0
    private var sealed = 0L

    fun append(data: ByteArray, length: Int = data.size) {
        var offset = 0
        while (offset < length) {
            val take = minOf(recordSize - filled, length - offset)
            System.arraycopy(data, offset, buffer, filled, take)
            filled += take
            offset += take
            if (filled == recordSize) seal()
        }
    }

    /** [padding] to the end of the stream, which may be whole records more. */
    fun finish(padding: Byte) {
        while (sealed < recordCount) {
            buffer.fill(padding, filled, recordSize)
            filled = recordSize
            seal()
        }
        if (filled != 0) throw overflow()
    }

    private fun seal() {
        if (sealed >= recordCount) throw overflow()
        val nonce = SharedItemsFile.recordNonce(prefix, sealed, sealed == recordCount - 1)
        output.write(AesGcm.seal(buffer, key, nonce, associatedData))
        sealed += 1
        filled = 0
    }
}

/** The header and key block of an `.obscurashared` file: everything that can be known without a password. */
class SharedItemsPreamble private constructor(
    val formatVersion: Int,
    val readableBy: Int,
    val flags: Int,
    val recordSize: Int,
    fileId: ByteArray,
    noncePrefix: ByteArray,
    /** Locks of the types this library knows, in file order. */
    val locks: List<Lock>,
    /** Locks of types this library does not know, passed over. */
    val unknownLockCount: Int,
    internal val header: ByteArray,
    internal val keyBlock: ByteArray,
) {
    /** What the content key must give under [SharedItemsFile.keyCommitment]. */
    private val keyCommitment = keyBlock.copyOf(SharedItemsFile.KEY_COMMITMENT_SIZE)

    private fun isCommitted(key: SecureBytes): Boolean = constantTimeEquals(SharedItemsFile.keyCommitment(key), keyCommitment)

    class Lock internal constructor(val type: SharedItemsFile.LockType, internal val body: ByteArray) {
        /** A password lock's PBKDF2 rounds, as the file states them. */
        val rounds: Long?
            get() = if (type == SharedItemsFile.LockType.PASSWORD && body.size == SharedItemsFile.PASSWORD_LOCK_SIZE) {
                body.bigEndianUInt32(0)
            } else {
                null
            }
    }

    val fileId: ByteArray = fileId.copyOf()
    val noncePrefix: ByteArray = noncePrefix.copyOf()

    /** The header and key block, the associated data of every record. */
    internal val bytes: ByteArray get() = header + keyBlock

    /** Sent without a password: the file holds its own key. */
    val isOpen: Boolean get() = locks.any { it.type == SharedItemsFile.LockType.OPEN }

    /**
     * The content key: from an open lock when no password is given, else from the first password lock [password] opens, spending at most
     * [roundsBudget] rounds on them all. Either way only the key the file commits to. No lock this library knows is a newer version.
     *
     * A file with an open lock is refused when a password is given ([ObscuraCryptoException.SharedItemsNotLocked]): anyone who had it
     * could have made it or changed it, so it must not pass for one sealed with the password.
     */
    internal fun contentKey(password: String?, roundsBudget: Long = SharedItemsFile.ROUNDS_BUDGET): SecureBytes {
        locks.firstOrNull { it.type == SharedItemsFile.LockType.OPEN }?.let { open ->
            if (open.body.size != SharedItemsFile.CONTENT_KEY_SIZE) {
                throw ObscuraCryptoException.InvalidSharedItems("an open lock that holds no key")
            }
            if (password != null) throw ObscuraCryptoException.SharedItemsNotLocked()
            val key = SecureBytes.copying(open.body)
            if (!isCommitted(key)) {
                key.clear()
                throw ObscuraCryptoException.SharedItemsDamaged("its key is not the one it commits to")
            }
            return key
        }
        val passwordLocks = locks.filter { it.type == SharedItemsFile.LockType.PASSWORD }
        if (passwordLocks.isEmpty()) throw ObscuraCryptoException.SharedItemsNewerVersion()
        if (password == null) throw ObscuraCryptoException.WrongPassword()
        var usable = false
        var spent = 0L
        for (lock in passwordLocks.take(SharedItemsFile.MAXIMUM_PASSWORD_LOCKS_TRIED)) {
            // Never fewer rounds than a vault's own; a ceiling, per lock and for the file, so a made-up one cannot hold the reader long.
            val rounds = lock.rounds ?: continue
            if (rounds < KeyDerivation.VAULT_ITERATIONS || rounds > SharedItemsFile.MAXIMUM_ROUNDS) continue
            usable = true
            if (rounds > roundsBudget - spent) break
            spent += rounds
            val salt = lock.body.copyOfRange(4, 4 + KeyDerivation.SALT_LENGTH)
            val sealed = lock.body.copyOfRange(4 + KeyDerivation.SALT_LENGTH, lock.body.size)
            val passwordKey = KeyDerivation.pbkdf2SHA256(password, salt, rounds.toInt())
            val key = try {
                AesGcm.open(sealed, passwordKey.secretKey(), header)
            } catch (e: ObscuraCryptoException.AuthenticationFailed) {
                continue
            } finally {
                passwordKey.clear()
            }
            try {
                if (key.size != SharedItemsFile.CONTENT_KEY_SIZE) continue
                // A lock can be made to open under more than one password, each to a different key; only the committed one is the file's.
                val candidate = SecureBytes.copying(key)
                if (!isCommitted(candidate)) {
                    candidate.clear()
                    continue
                }
                return candidate
            } finally {
                key.fill(0)
            }
        }
        if (usable) throw ObscuraCryptoException.WrongPassword()
        throw ObscuraCryptoException.InvalidSharedItems("no password lock with rounds between 600,000 and 10,000,000")
    }

    companion object {
        fun read(file: File): SharedItemsPreamble = file.inputStream().use { read(it) }

        /** Reads and checks the preamble; [input] is left just after it. */
        fun read(input: InputStream): SharedItemsPreamble {
            val header = input.readExactly(SharedItemsFile.HEADER_SIZE)
                ?: throw ObscuraCryptoException.InvalidSharedItems("shorter than ${SharedItemsFile.HEADER_SIZE} bytes")
            if (!header.startsWith(SharedItemsFile.MAGIC)) throw ObscuraCryptoException.InvalidSharedItems("missing OBSI magic")
            val format = u16(header, 4)
            val readable = u16(header, 6)
            // 1 and 2 were layouts that never shipped; "readable by" above the format that wrote the file is not one any app made.
            if (format < 3 || readable < 3 || readable > format) {
                throw ObscuraCryptoException.InvalidSharedItems("format $format, readable by $readable")
            }
            if (readable > SharedItemsFile.VERSION) throw ObscuraCryptoException.SharedItemsNewerVersion()
            val flags = u16(header, 8)
            if (flags and SharedItemsFile.REQUIRED_FLAGS != 0) throw ObscuraCryptoException.SharedItemsNewerVersion()
            val keyBlockLength = u16(header, 10)
            val recordSize = header.bigEndianUInt32(12)
            if (keyBlockLength <= SharedItemsFile.KEY_COMMITMENT_SIZE + 1 || keyBlockLength > SharedItemsFile.MAXIMUM_KEY_BLOCK) {
                throw ObscuraCryptoException.InvalidSharedItems("a key block of an impossible length")
            }
            if (recordSize !in SharedItemsFile.RECORD_SIZES.first.toLong()..SharedItemsFile.RECORD_SIZES.last.toLong()) {
                throw ObscuraCryptoException.InvalidSharedItems("records of an impossible size")
            }
            val keyBlock = input.readExactly(keyBlockLength)
                ?: throw ObscuraCryptoException.InvalidSharedItems("the file ends inside its key block")
            val locks = ArrayList<Lock>()
            var unknown = 0
            var offset = SharedItemsFile.KEY_COMMITMENT_SIZE + 1
            repeat(keyBlock[SharedItemsFile.KEY_COMMITMENT_SIZE].toInt() and 0xFF) {
                if (offset + 3 > keyBlock.size) throw ObscuraCryptoException.InvalidSharedItems("the key block is cut short")
                val type = keyBlock[offset].toInt() and 0xFF
                val length = u16(keyBlock, offset + 1)
                if (offset + 3 + length > keyBlock.size) throw ObscuraCryptoException.InvalidSharedItems("the key block is cut short")
                val known = SharedItemsFile.LockType.of(type)
                if (known != null) locks += Lock(known, keyBlock.copyOfRange(offset + 3, offset + 3 + length)) else unknown += 1
                offset += 3 + length
            }
            if (offset != keyBlock.size) throw ObscuraCryptoException.InvalidSharedItems("the key block has bytes left over")
            return SharedItemsPreamble(
                formatVersion = format, readableBy = readable, flags = flags, recordSize = recordSize.toInt(),
                fileId = header.copyOfRange(16, 32), noncePrefix = header.copyOfRange(32, 36),
                locks = locks, unknownLockCount = unknown, header = header, keyBlock = keyBlock,
            )
        }

        private fun u16(bytes: ByteArray, offset: Int): Int =
            ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
    }
}

/**
 * The records of an `.obscurashared` file as one plaintext stream, a record in memory at a time. A record is the last when the input
 * ends right after it, which it learns by looking one byte ahead, so it works on any stream.
 */
internal class SharedItemsRecordStream(
    private val input: PushbackInputStream,
    private val key: SecretKeySpec,
    private val prefix: ByteArray,
    private val associatedData: ByteArray,
    recordSize: Int,
    /** The format's own error for a damaged file: a version 2 export uses this stream too. */
    private val damaged: (String) -> Exception,
) {
    constructor(input: PushbackInputStream, key: SecretKeySpec, preamble: SharedItemsPreamble) :
        this(input, key, preamble.noncePrefix, preamble.bytes, preamble.recordSize, { ObscuraCryptoException.SharedItemsDamaged(it) })

    private val recordBytes = recordSize + AesGcm.OVERHEAD
    private var index = 0L
    private var buffer = ByteArray(0)
    private var offset = 0

    /** The last record, the one with the end mark, has been read. */
    var reachedEnd = false
        private set

    /** Hands over the next [count] bytes of the stream, a piece at a time. */
    fun read(count: Long, sink: (ByteArray) -> Unit) {
        var remaining = count
        while (remaining > 0) {
            if (offset == buffer.size) nextRecord()
            val take = minOf((buffer.size - offset).toLong(), remaining).toInt()
            sink(buffer.copyOfRange(offset, offset + take))
            offset += take
            remaining -= take
        }
    }

    fun read(count: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream(count)
        read(count.toLong()) { out.write(it) }
        return out.toByteArray()
    }

    /** Reads the rest of the stream, which must be padding: zeros, to the end of the last record. */
    fun finish() {
        while (true) {
            for (i in offset until buffer.size) {
                if (buffer[i] != 0.toByte()) throw damaged("there is data after the last item")
            }
            offset = buffer.size
            if (reachedEnd) return
            nextRecord()
        }
    }

    private fun nextRecord() {
        if (reachedEnd) throw damaged("the file ends inside an item")
        val sealed = input.readExactly(recordBytes) ?: throw damaged("the file ends inside a record")
        // The last record is the one the input ends with; any bytes after it make it not the last, and its end mark then fails the check.
        val next = input.read()
        val isLast = next < 0
        if (!isLast) input.unread(next)
        val nonce = SharedItemsFile.recordNonce(prefix, index, isLast)
        if (!sealed.copyOf(AesGcm.NONCE_SIZE).contentEquals(nonce)) {
            throw damaged("a record carries the wrong nonce: records were reordered, dropped, replaced or cut off")
        }
        buffer = try {
            AesGcm.open(sealed, key, associatedData)
        } catch (e: ObscuraCryptoException.AuthenticationFailed) {
            throw damaged("a record does not authenticate: the file was altered")
        }
        offset = 0
        index += 1
        reachedEnd = isLast
    }
}

/**
 * An opened `.obscurashared` file: the password checked and the manifest read. Every part is then read in the manifest's order with
 * [read] or [skip], those of kinds this library does not know included, and [finish] checks that only padding follows the last. Reads
 * from any [InputStream], which on Android is what a received file opens as. Close it when done.
 */
class SharedItemsReader private constructor(
    private val input: PushbackInputStream,
    val preamble: SharedItemsPreamble,
    val manifest: SharedItemsFile.Manifest,
    private val stream: SharedItemsRecordStream,
) : Closeable {
    /** Every part of every item, in file order, and the next one to read. */
    private val parts = manifest.items.flatMap { it.parts }
    private var nextPart = 0

    /** Set when a read stopped part way: the stream is out of step. */
    private var broken = false

    /** Items of kinds this library knows. */
    val supportedCount: Int get() = manifest.items.count { it.knownKind != null }

    /**
     * Reads [part], which must be the next in the file, handing its plaintext to [sink] a piece at a time, then checks its SHA-256. When
     * this throws, what was handed over is not the part: discard it.
     */
    fun read(part: SharedItemsFile.Part, sink: (ByteArray) -> Unit) = readPart(part, sink)

    /** Reads past [part], which must be the next in the file. It is still decrypted and checked, so the stream stays in order and authentic. */
    fun skip(part: SharedItemsFile.Part) = readPart(part) { }

    /** Checks that every part was read and that only zeros follow the last, to the end of the file's last record. */
    fun finish() {
        if (broken || nextPart != parts.size) throw ObscuraCryptoException.InvalidSharedItems("finished before every part was read")
        stream.finish()
    }

    override fun close() = input.close()

    private fun readPart(part: SharedItemsFile.Part, sink: (ByteArray) -> Unit) {
        if (broken) throw ObscuraCryptoException.SharedItemsDamaged("an earlier part did not read")
        if (nextPart >= parts.size || parts[nextPart] != part) {
            throw ObscuraCryptoException.InvalidSharedItems("parts are read in the order the manifest lists them")
        }
        broken = true
        val digest = MessageDigest.getInstance("SHA-256")
        stream.read(part.size) { piece ->
            digest.update(piece)
            sink(piece)
        }
        if (SharedItemsFile.hex(digest.digest()) != part.sha256) {
            throw ObscuraCryptoException.SharedItemsDamaged("an item does not match its SHA-256")
        }
        broken = false
        nextPart += 1
    }

    companion object {
        /** Opens [file]. See [open]. */
        fun open(file: File, password: String?): SharedItemsReader = open(file.inputStream(), password)

        /**
         * Opens [stream] with [password], null for a file sent without one (ask [SharedItemsFile.needsPassword] first). Throws
         * [ObscuraCryptoException.WrongPassword] without reading further when it does not open the file,
         * [ObscuraCryptoException.SharedItemsNotLocked] when a password is given for a file that has none, and
         * [ObscuraCryptoException.SharedItemsNewerVersion] when nothing in it is for this version. The reader owns the stream from here
         * and closes it on failure.
         */
        fun open(stream: InputStream, password: String?): SharedItemsReader = open(stream, password, SharedItemsFile.ROUNDS_BUDGET)

        internal fun open(stream: InputStream, password: String?, roundsBudget: Long): SharedItemsReader {
            val input = PushbackInputStream(BufferedInputStream(stream, 64 * 1024), 1)
            try {
                val preamble = SharedItemsPreamble.read(input)
                val contentKey = preamble.contentKey(password, roundsBudget)
                val key = SharedItemsFile.recordKey(contentKey)
                contentKey.clear()
                val records = SharedItemsRecordStream(input, key, preamble)

                val manifestLength = records.read(4).bigEndianUInt32(0)
                if (manifestLength !in 1L..SharedItemsFile.MAXIMUM_MANIFEST.toLong()) {
                    throw ObscuraCryptoException.SharedItemsDamaged("a manifest of an impossible length")
                }
                val manifest = try {
                    SharedItemsJson.manifest(records.read(manifestLength.toInt()))
                } catch (e: SharedItemsJson.Malformed) {
                    throw ObscuraCryptoException.SharedItemsDamaged("the manifest is not readable: ${e.reason}")
                }
                if (manifest.items.isEmpty() || manifest.items.size > SharedItemsFile.MAXIMUM_ITEMS ||
                    !manifest.items.all { it.isWellFormed }
                ) {
                    throw ObscuraCryptoException.SharedItemsDamaged("the manifest lists an item that cannot be")
                }
                if (manifest.items.none { it.knownKind != null }) throw ObscuraCryptoException.SharedItemsNewerVersion()
                return SharedItemsReader(input, preamble, manifest, records)
            } catch (e: Throwable) {
                input.close()
                throw e
            }
        }
    }
}
