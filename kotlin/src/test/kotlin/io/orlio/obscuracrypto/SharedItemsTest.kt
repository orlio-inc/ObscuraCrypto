// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import io.orlio.obscuracrypto.SharedItemsFile.Kind
import io.orlio.obscuracrypto.SharedItemsFile.Source
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The `.obscurashared` file, as the Swift package's `SharedItemsTests` checks it: round trips, the password check and rules, what the
 * file shows without the password, every way of altering a file, the strict manifest, and the rules for files from later versions. The
 * layout is also checked both ways against [SpecFile], a writer and reader built from the documented layout alone.
 */
class SharedItemsTest : CryptoTestCase() {

    private val password = "correct horse battery"

    private fun bytes(count: Int, seed: Int) = ByteArray(count) { (((it * 31) and 0xFF) xor seed).toByte() }

    private fun source(data: ByteArray): File = file(UUID.randomUUID().toString(), data)

    /** A photo, a video over two records, a Live Photo, and a document. */
    private fun makeFile(password: String?): Pair<File, List<ByteArray>> {
        val parts = listOf(
            bytes(5_000, 1), bytes(SharedItemsFile.RECORD_SIZE * 2 + 123, 2), bytes(7_000, 3),
            bytes(SharedItemsFile.RECORD_SIZE + 77, 4), bytes(1_500, 5),
        )
        val files = parts.map(::source)
        val out = File(directory, "sent.obscurashared")
        SharedItemsFile.write(
            listOf(
                Source(files[0], Kind.PHOTO, mimeType = "image/jpeg"),
                Source(files[1], Kind.VIDEO, mimeType = "video/quicktime"),
                Source(files[2], Kind.LIVE_PHOTO, pairedVideo = files[3], mimeType = "image/heic"),
                Source(files[4], Kind.PDF, name = "Lease", mimeType = "application/pdf"),
            ),
            password, out,
        )
        return out to parts
    }

    /** Every part of every item this library knows, in order; parts and kinds it does not know are read past. */
    private fun readAll(file: File, password: String?, roundsBudget: Long = SharedItemsFile.ROUNDS_BUDGET): List<ByteArray> {
        val parts = ArrayList<ByteArray>()
        SharedItemsReader.open(file.inputStream(), password, roundsBudget).use { reader ->
            for (item in reader.manifest.items) {
                for (part in item.parts) {
                    val role = SharedItemsFile.Role.of(part.role)
                    val known = item.knownKind != null && role != null &&
                        !(role == SharedItemsFile.Role.MOTION && item.knownKind != Kind.LIVE_PHOTO)
                    if (!known) {
                        reader.skip(part)
                        continue
                    }
                    val out = ByteArrayOutputStream()
                    reader.read(part) { out.write(it) }
                    parts += out.toByteArray()
                }
            }
            reader.finish()
        }
        return parts
    }

    private fun assertParts(expected: List<ByteArray>, actual: List<ByteArray>) {
        assertEquals(expected.size, actual.size, "parts")
        expected.indices.forEach { assertBytesEqual(expected[it], actual[it], "part $it") }
    }

    private fun refusedAs(expected: String, message: String = "", block: () -> Unit) {
        val error = assertFailsWith<Throwable>(message) { block() }
        assertEquals(expected, Compat.errorName(error), "$message: $error")
    }

    private fun spec(password: String? = null, configure: SpecFile.() -> Unit = {}): File {
        val spec = SpecFile(password)
        spec.items += SpecFile.Item("photo", listOf("file" to bytes(2_000, 1)))
        spec.configure()
        return spec.write(directory)
    }

    // MARK: Round trips

    @Test
    fun roundTripWithPassword() {
        val (file, parts) = makeFile(password)
        assertTrue(SharedItemsFile.needsPassword(file))
        assertParts(parts, readAll(file, password))
    }

    @Test
    fun roundTripWithoutPassword() {
        val (file, parts) = makeFile(null)
        assertFalse(SharedItemsFile.needsPassword(file))
        assertParts(parts, readAll(file, null))
    }

    /**
     * A file sent with a password can be swapped on the way for one sent without: a reader given the password refuses it rather than
     * open it as though it were the sender's.
     */
    @Test
    fun anOpenFileIsRefusedWhenAPasswordIsGiven() {
        val (file, _) = makeFile(null)
        refusedAs("sharedItemsNotLocked") { readAll(file, password) }
    }

    /**
     * AES-GCM does not commit to its key, so a lock can be made to open under several passwords, each to a different key. Only the key
     * the file commits to opens it: any other is a wrong password, and an open lock holding another key is damage.
     */
    @Test
    fun onlyTheCommittedKeyOpensAFile() {
        refusedAs("wrongPassword") { readAll(spec(password) { commitsToKey = false }, password) }
        refusedAs("sharedItemsDamaged") { readAll(spec(null) { commitsToKey = false }, null) }
    }

    @Test
    fun theManifestCarriesKindsTypesAndATitle() {
        val (file, _) = makeFile(null)
        SharedItemsReader.open(file, null).use { reader ->
            assertEquals(listOf("photo", "video", "livePhoto", "pdf"), reader.manifest.items.map { it.kind })
            assertEquals(listOf("image/jpeg", "video/quicktime", "image/heic", "application/pdf"), reader.manifest.items.map { it.type })
            assertEquals("Lease", reader.manifest.items.last().name)
            assertEquals(4, reader.supportedCount)
            assertEquals(listOf(SharedItemsFile.LockType.OPEN), reader.preamble.locks.map { it.type })
            assertEquals(SharedItemsFile.RECORD_SIZE, reader.preamble.recordSize)
        }
    }

    @Test
    fun aPasswordLockUsesTheVaultsRounds() {
        val (file, _) = makeFile(password)
        val preamble = SharedItemsPreamble.read(file)
        assertEquals(listOf(KeyDerivation.VAULT_ITERATIONS.toLong()), preamble.locks.map { it.rounds })
        assertEquals(3, preamble.formatVersion)
        assertEquals(3, preamble.readableBy)
    }

    @Test
    fun wrongOrMissingPasswordIsRefused() {
        val (file, _) = makeFile(password)
        refusedAs("wrongPassword") { readAll(file, "wrong horse battery") }
        refusedAs("wrongPassword") { readAll(file, null) }
    }

    @Test
    fun noPlaintextIsInTheFile() {
        val marker = "A VERY RECOGNISABLE PLAINTEXT MARKER".toByteArray()
        val out = File(directory, "f.obscurashared")
        SharedItemsFile.write(listOf(Source(source(marker), Kind.PDF, name = "Lease")), password, out)
        val written = String(out.readBytes(), Charsets.ISO_8859_1)
        assertFalse(written.contains(String(marker, Charsets.ISO_8859_1)))
        assertFalse(written.contains("Lease"), "the manifest is sealed too")
    }

    // MARK: What the file shows without the password

    /** Items run on inside equal records, so neither how many there are nor how large each is shows. */
    @Test
    fun itemCountAndSizesDoNotShow() {
        fun write(sizes: List<Int>): File {
            val out = File(directory, "${sizes.joinToString("-")}.obscurashared")
            SharedItemsFile.write(sizes.mapIndexed { i, size -> Source(source(bytes(size, i)), Kind.PHOTO) }, null, out,
                KeyDerivation.VAULT_ITERATIONS, 4_096)
            return out
        }
        val one = write(listOf(5_000, 2_000))
        val other = write(listOf(1_000, 3_000, 2_500))
        assertEquals(one.length(), other.length())
        val read = SpecFile.read(one, null)
        assertTrue(read.recordLengths.all { it == 4_096 + 28 }, "every record is the same size")
        assertTrue(read.paddingIsZero)
    }

    @Test
    fun padmeRoundsUpByAtMostAnEighth() {
        for (length in listOf(2L, 3L, 9L, 100L, 1_000L, 65_537L, 1_048_577L, 10_000_000L, 3_000_000_000L)) {
            val padded = SharedItemsFile.padme(length)
            assertTrue(padded >= length)
            assertTrue((padded - length).toDouble() <= length * 0.125, "$length")
            assertEquals(padded, SharedItemsFile.padme(padded), "$length pads to a length that pads to itself")
        }
        assertEquals(1_006_632_960L, SharedItemsFile.padme(1_000_000_000L))
    }

    // MARK: Passwords

    @Test
    fun passwordRules() {
        val cases = listOf(
            "short pw" to SharedPassword.Problem.TOO_SHORT, "aaaaaaaaaaaa" to SharedPassword.Problem.TOO_SIMPLE,
            "1212121212" to SharedPassword.Problem.TOO_SIMPLE, "0123456789012" to SharedPassword.Problem.TOO_SIMPLE,
            "qwertyuiop" to SharedPassword.Problem.TOO_SIMPLE, "ZYXWVUTSRQ" to SharedPassword.Problem.TOO_SIMPLE,
            "Password123!" to SharedPassword.Problem.TOO_COMMON, "P@ssw0rd2024" to SharedPassword.Problem.TOO_COMMON,
            "iloveyou2024" to SharedPassword.Problem.TOO_COMMON, "monkeymonkey1" to SharedPassword.Problem.TOO_COMMON,
            "!!obscura12345" to SharedPassword.Problem.TOO_COMMON, "Summer2025!!" to SharedPassword.Problem.TOO_COMMON,
        )
        for ((candidate, problem) in cases) assertEquals(problem, SharedPassword.problem(candidate), candidate)
        for (candidate in listOf("correct horse battery", "Tr0ub4dor&3x", "lunch-orbit-gravity", "Ünïcödé pässwörd", "пароль-для-файла")) {
            assertNull(SharedPassword.problem(candidate), candidate)
        }
    }

    /** The checks are advice: the writer takes any password. */
    @Test
    fun aWeakPasswordIsTakenAllTheSame() {
        val out = File(directory, "weak.obscurashared")
        SharedItemsFile.write(listOf(Source(source(bytes(10, 1)), Kind.PHOTO)), "abc123", out)
        assertTrue(SharedPassword.problem("abc123") != null)
        assertParts(listOf(bytes(10, 1)), readAll(out, "abc123"))
    }

    @Test
    fun suggestedPasswordsAreSixDifferentListWords() {
        val first = SharedPassword.suggested()
        val words = first.split("-")
        assertEquals(6, words.size)
        assertEquals(6, words.toSet().size)
        assertTrue(words.all { it in RecoveryPhrase.words })
        assertNull(SharedPassword.problem(first))
        assertNotEquals(first, SharedPassword.suggested())
    }

    /** A made-up file with many expensive locks costs the reader at most the budget: with a budget of one lock, the second is never tried. */
    @Test
    fun passwordLocksStopAtTheRoundsBudget() {
        val file = spec("between us both") { extraPasswordLocks += "another password" to 600_000L }
        assertEquals(1, readAll(file, "between us both").size)
        refusedAs("wrongPassword") { readAll(file, "between us both", roundsBudget = 1_000_000) }
    }

    // MARK: Writing

    @Test
    fun whatCannotBeSentIsRefused() {
        val out = File(directory, "never.obscurashared")
        refusedAs("invalidSharedItems") { SharedItemsFile.write(listOf(Source(source(bytes(100, 1)), Kind.LIVE_PHOTO)), null, out) }
        refusedAs("invalidSharedItems") {
            SharedItemsFile.write(listOf(Source(source(bytes(100, 1)), Kind.PHOTO, pairedVideo = source(bytes(100, 2)))), null, out)
        }
        refusedAs("invalidSharedItems") { SharedItemsFile.write(listOf(Source(source(ByteArray(0)), Kind.PHOTO)), null, out) }
        refusedAs("tooManySharedItems") { SharedItemsFile.write(emptyList(), null, out) }
        assertFalse(out.exists())
    }

    @Test
    fun aFailedWriteLeavesNothingBehind() {
        val out = File(directory, "never.obscurashared")
        assertFailsWith<Exception> { SharedItemsFile.write(listOf(Source(File(directory, "does-not-exist"), Kind.PHOTO)), null, out) }
        assertFalse(out.exists())
        assertEquals(emptyList(), directory.list().orEmpty().filter { it.endsWith(".partial") })
    }

    /**
     * Titles go in cleaned: control and direction characters as spaces, invisible ones left out, ends trimmed, at most 200 code points.
     * The joiners emoji and some scripts need stay.
     */
    @Test
    fun aTitleIsCleanedAndCut() {
        val joined = File(directory, "joined.obscurashared")
        SharedItemsFile.write(
            listOf(Source(source(bytes(10, 1)), Kind.PDF, name = "\u200BMi\uFEFFet\u2060vertrag\uDB40\uDC41 \uD83D\uDC68\u200D\uD83D\uDC69")),
            null, joined,
        )
        assertEquals("Mietvertrag \uD83D\uDC68\u200D\uD83D\uDC69", SharedItemsReader.open(joined, null).use { it.manifest.items[0].name })
        val out = File(directory, "title.obscurashared")
        val name = "‮Lease\nfor 2027\u0007 " + "a".repeat(500)
        SharedItemsFile.write(listOf(Source(source(bytes(10, 1)), Kind.PDF, name = name)), null, out)
        val title = SharedItemsReader.open(out, null).use { it.manifest.items[0].name!! }
        assertTrue(title.startsWith("Lease for 2027  aaa"), title)
        assertEquals(200, title.codePointCount(0, title.length))
    }

    /**
     * A title may not hide anything, nor show nothing: Unicode's ignorable characters (variation selectors, Hangul fillers, the soft hyphen
     * and the rest) are refused, presentation selectors only after a visible character, and a title of spaces and blanks is no title.
     */
    @Test
    fun titlesThatHideOrShowNothingAreRefused() {
        for (name in listOf("Passport\uFE01", "a\uDB40\uDD00", "\uFE0FLease", "Lease \uFE0F", "\u3164", "a\u115Fb", "pa\u00ADss",
            "a\u034Fb", "\u3000\u2800", " ", "\u200D")) {
            assertFalse(SharedItemsFile.isAcceptableName(name), name)
        }
        for (name in listOf("\u2764\uFE0F Lease", "Pass\u200Cport", "\uD83D\uDC68\u200D\uD83D\uDC69", "日本\u3000語", " Lease ")) {
            assertTrue(SharedItemsFile.isAcceptableName(name), name)
        }
        assertEquals("\u2764\uFE0F Lease", SharedItemsFile.cleanedName("\uFE0F\u2764\uFE0F\uFE0F Lease\u3000\uFE01"))
        assertNull(SharedItemsFile.cleanedName("\u3164\u2800\u3000"))
    }

    // MARK: Tampering

    @Test
    fun alteredBytesAreRefused() {
        val (file, _) = makeFile(null)
        val original = file.readBytes()
        for (offset in listOf(original.size - 40, original.size / 2, 200)) {
            file.writeBytes(original.copyOf().also { it[offset] = (it[offset].toInt() xor 1).toByte() })
            refusedAs("sharedItemsDamaged", "byte $offset") { readAll(file, null) }
        }
    }

    /** The header and key block are associated data of every record, and the header of the password lock. */
    @Test
    fun alteredHeaderOrKeyBlockIsRefused() {
        for ((pw, offset, expected) in listOf(
            Triple(null, 40, "sharedItemsDamaged"), Triple(null, 20, "sharedItemsDamaged"),
            Triple(null, SharedItemsFile.HEADER_SIZE + 5, "sharedItemsDamaged"),
            Triple(password, 40, "wrongPassword"), Triple(password, 33, "wrongPassword"),
        )) {
            val (file, _) = makeFile(pw)
            file.writeBytes(file.readBytes().also { it[offset] = (it[offset].toInt() xor 1).toByte() })
            refusedAs(expected, "byte $offset") { readAll(file, pw) }
        }
    }

    /** Swapping two whole records keeps each one authentic on its own; the nonce check is what catches it. */
    @Test
    fun reorderedRecordsAreRefused() {
        val (file, _) = makeFile(password)
        file.writeBytes(Compat.swappingRecords(file.readBytes(), 1, 2))
        refusedAs("sharedItemsDamaged") { readAll(file, password) }
    }

    @Test
    fun cutShortOrAddedToIsRefused() {
        val (file, _) = makeFile(null)
        val bytes = file.readBytes()
        val record = SharedItemsFile.RECORD_SIZE + 28
        for ((name, altered) in listOf(
            "a byte off" to bytes.copyOf(bytes.size - 1), "half a record off" to bytes.copyOf(bytes.size - record / 2),
            "the last record off" to bytes.copyOf(bytes.size - record), "bytes added" to bytes + ByteArray(8),
            "a record added" to bytes + bytes.copyOfRange(bytes.size - record, bytes.size),
        )) {
            file.writeBytes(altered)
            refusedAs("sharedItemsDamaged", name) { readAll(file, null) }
        }
        file.writeBytes(bytes.copyOf(10))
        refusedAs("invalidSharedItems") { SharedItemsFile.needsPassword(file) }
    }

    @Test
    fun theLastRecordMustCarryTheEndMark() = refusedAs("sharedItemsDamaged") { readAll(spec { marksLastRecord = false }, null) }

    @Test
    fun paddingMustBeZeros() {
        refusedAs("sharedItemsDamaged") { readAll(spec { trailing = byteArrayOf(0, 0, 1) }, null) }
        assertEquals(1, readAll(spec { extraZeroRecords = 2 }, null).size, "whole records of zeros after the items are padding")
    }

    @Test
    fun aFileThatIsNotOneIsSaidSo() {
        refusedAs("invalidSharedItems") { readAll(file("other", ByteArray(500) { it.toByte() }), null) }
        refusedAs("invalidSharedItems", "a layout that never shipped") { readAll(spec { format = 2; readableBy = 2 }, null) }
        refusedAs("invalidSharedItems", "records too small") { readAll(spec { recordSize = 1_000 }, null) }
    }

    @Test
    fun partsAreReadInTheirOrderOnly() {
        val (file, _) = makeFile(null)
        SharedItemsReader.open(file, null).use { reader ->
            val items = reader.manifest.items
            refusedAs("invalidSharedItems") { reader.skip(items[1].parts[0]) }
            reader.skip(items[0].parts[0])
            refusedAs("invalidSharedItems") { reader.finish() }
        }
    }

    // MARK: The strict manifest

    /** Each of these reads one way in one JSON library and another way, or not at all, in the next. Both of this repository's readers refuse them. */
    @Test
    fun aManifestOutsideTheStrictFormIsDamaged() {
        val hash = "0".repeat(64)
        val part = """{"role":"file","size":2000,"sha256":"$hash"}"""
        val parts17 = (0 until 17).joinToString(",") { """{"role":"r$it","size":1,"sha256":"$hash"}""" }
        val cases: List<Pair<String, ByteArray>> = listOf(
            "a name twice" to """{"items":[{"kind":"photo","kind":"pdf","parts":[$part]}]}""".toByteArray(),
            "items twice" to """{"items":[],"items":[{"kind":"photo","parts":[$part]}]}""".toByteArray(),
            "a fraction" to """{"items":[{"kind":"photo","parts":[{"role":"file","size":2000.0,"sha256":"$hash"}]}]}""".toByteArray(),
            "an exponent" to """{"items":[{"kind":"photo","parts":[{"role":"file","size":2e3,"sha256":"$hash"}]}]}""".toByteArray(),
            "a leading zero" to """{"items":[{"kind":"photo","parts":[{"role":"file","size":02000,"sha256":"$hash"}]}]}""".toByteArray(),
            "a size as text" to """{"items":[{"kind":"photo","parts":[{"role":"file","size":"2000","sha256":"$hash"}]}]}""".toByteArray(),
            "a byte-order mark" to byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte()) +
                """{"items":[{"kind":"photo","parts":[$part]}]}""".toByteArray(),
            "UTF-16" to """{"items":[{"kind":"photo","parts":[$part]}]}""".toByteArray(Charsets.UTF_16BE),
            "a lone surrogate" to """{"items":[{"kind":"photo","x":"\uD800","parts":[$part]}]}""".toByteArray(),
            "malformed UTF-8" to """{"items":[{"kind":"photo","x":"""".toByteArray() + byteArrayOf(0xC0.toByte(), 0xAF.toByte()) +
                """","parts":[$part]}]}""".toByteArray(),
            "nested too deeply" to ("""{"items":[{"kind":"photo","x":""" + "[".repeat(20) + "]".repeat(20) + ""","parts":[$part]}]}""").toByteArray(),
            "data after the JSON" to """{"items":[{"kind":"photo","parts":[$part]}]} {}""".toByteArray(),
            "a kind outside ASCII" to """{"items":[{"kind":"phötö","parts":[$part]}]}""".toByteArray(),
            "roles that differ only in composition" to
                """{"items":[{"kind":"x","parts":[{"role":"é","size":1,"sha256":"$hash"},{"role":"é","size":1,"sha256":"$hash"}]}]}""".toByteArray(),
            "an uppercase hash" to """{"items":[{"kind":"photo","parts":[{"role":"file","size":2000,"sha256":"${"A".repeat(64)}"}]}]}""".toByteArray(),
            "a title with a line break" to """{"items":[{"kind":"pdf","name":"a\nb","parts":[$part]}]}""".toByteArray(),
            "a title too long" to """{"items":[{"kind":"pdf","name":"${"a".repeat(201)}","parts":[$part]}]}""".toByteArray(),
            "seventeen parts" to """{"items":[{"kind":"x","parts":[$parts17]}]}""".toByteArray(),
        )
        for ((name, manifest) in cases) refusedAs("sharedItemsDamaged", name) { readAll(spec { manifestOverride = manifest }, null) }
    }

    // MARK: The documented layout

    @Test
    fun writtenFilesMatchTheDocumentedLayout() {
        for (pw in listOf(password, null)) {
            val (file, parts) = makeFile(pw)
            val read = SpecFile.read(file, pw)
            assertEquals(3, read.format)
            assertEquals(3, read.readableBy)
            assertEquals(0, read.flags)
            assertTrue(read.reservedAreZero)
            assertTrue(read.paddingIsZero)
            assertParts(parts, read.parts)
            assertEquals(if (pw == null) null else 600_000L, read.rounds)
        }
    }

    @Test
    fun aFileWrittenFromTheDocumentationOpens() {
        for (pw in listOf("between us both", null)) assertParts(listOf(bytes(2_000, 1)), readAll(spec(pw), pw))
    }

    // MARK: Files from later versions

    /**
     * Everything a later version may add without raising "readable by" is passed over: a higher format number, an optional flag, a lock
     * type beside the password, more rounds, unknown JSON members, an item kind and a part this library does not know.
     */
    @Test
    fun aLaterFileThisVersionCanReadOpens() {
        val photo = bytes(4_000, 5)
        val still = bytes(2_000, 6)
        val motion = bytes(10_000, 7)
        val file = spec("between us both") {
            format = 7
            flags = 0x0100
            rounds = 700_000
            unknownLocks += 42 to ByteArray(80) { 1 }
            extraManifest = ""","sender":"someone","expires":"2027-01-01""""
            items.clear()
            items += SpecFile.Item("audio", listOf("file" to bytes(1_500, 8)))
            items += SpecFile.Item("photo", listOf("thumbnail" to bytes(300, 9), "file" to photo), ""","caption":"at the lake"""")
            items += SpecFile.Item("livePhoto", listOf("file" to still, "motion" to motion))
        }
        SharedItemsReader.open(file, "between us both").use { reader ->
            assertEquals(3, reader.manifest.items.size)
            assertEquals(2, reader.supportedCount)
            assertEquals(1, reader.preamble.unknownLockCount)
        }
        assertParts(listOf(photo, still, motion), readAll(file, "between us both"))
        refusedAs("wrongPassword") { readAll(file, "not it at all") }
    }

    /** What only a newer reader can open says so, never "damaged". */
    @Test
    fun aFileForANewerReaderAsksForAnUpdate() {
        val specs = listOf<SpecFile.() -> Unit>(
            { format = 4; readableBy = 4 },
            { flags = 0x0001 },
            { knownLock = false; unknownLocks += 3 to ByteArray(64) { 2 } },
            { items.clear(); items += SpecFile.Item("audio", listOf("file" to bytes(100, 2))) },
        )
        for (configure in specs) refusedAs("sharedItemsNewerVersion") { SharedItemsReader.open(spec(null, configure), null).close() }
    }

    /** Fewer rounds than a vault's own are not a file Obscura made; a count past the ceiling would hold the reader for minutes. */
    @Test
    fun roundsOutsideTheLimitsAreRefused() {
        for (rounds in listOf(100_000L, 599_999L, SharedItemsFile.MAXIMUM_ROUNDS + 1)) {
            // The reader refuses on the count alone, so the lock need not open.
            val file = spec("between us both") { this.rounds = rounds; sealsLock = false }
            refusedAs("invalidSharedItems", "$rounds") { readAll(file, "between us both") }
        }
    }

    /** A known kind missing a part it needs is damaged, not newer. */
    @Test
    fun aKnownKindWithoutItsPartsIsDamaged() {
        for (item in listOf(
            SpecFile.Item("livePhoto", listOf("file" to bytes(100, 1))),
            SpecFile.Item("photo", listOf("file" to bytes(100, 1), "motion" to bytes(100, 2))),
            SpecFile.Item("video", listOf("thumbnail" to bytes(100, 1))),
        )) {
            refusedAs("sharedItemsDamaged", item.kind) { readAll(spec { items.clear(); items += item }, null) }
        }
    }
}

/**
 * The documented layout (FORMATS.md), written and read here from the JDK's AES-GCM, hand-built JSON and the library's PBKDF2 alone,
 * sharing no code with the library's reader and writer.
 */
class SpecFile(var password: String?) {
    class Item(val kind: String, val parts: List<Pair<String, ByteArray>>, val extraJson: String = "")

    var format = 3
    var readableBy = 3
    var flags = 0
    var rounds = 600_000L
    var recordSize = 4_096

    /** A password or open lock, after any unknown ones. */
    var knownLock = true
    val unknownLocks = ArrayList<Pair<Int, ByteArray>>()

    /** Password locks before the known one, each under its own password. */
    val extraPasswordLocks = ArrayList<Pair<String, Long>>()
    var extraManifest = ""
    val items = ArrayList<Item>()

    /** The manifest's bytes as they are, in place of one made from [items]. */
    var manifestOverride: ByteArray? = null

    /** Bytes after the last part, before the zeros. */
    var trailing = ByteArray(0)
    var extraZeroRecords = 0
    var marksLastRecord = true

    /** False writes a password lock of random bytes, skipping the derivation. */
    var sealsLock = true

    /** False writes a key commitment to some other key. */
    var commitsToKey = true

    private fun be(value: Long, size: Int) = ByteArray(size) { ((value shr (8 * (size - 1 - it))) and 0xFF).toByte() }

    private fun random(count: Int) = ByteArray(count).also { java.security.SecureRandom().nextBytes(it) }

    private fun gcm(key: ByteArray, nonce: ByteArray, aad: ByteArray, plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return nonce + cipher.doFinal(plain)
    }

    fun write(directory: File): File {
        val manifest = manifestOverride ?: run {
            val manifestItems = items.joinToString(",") { item ->
                val parts = item.parts.joinToString(",") { (role, data) ->
                    """{"role":"$role","size":${data.size},"sha256":"${sha256(data)}"}"""
                }
                """{"kind":"${item.kind}","parts":[$parts]${item.extraJson}}"""
            }
            """{"items":[$manifestItems]$extraManifest}""".toByteArray()
        }
        val contentKey = random(32)
        val prefix = random(4)
        val locks = ArrayList<Pair<Int, ByteArray>>(unknownLocks)
        extraPasswordLocks.forEach { locks += 1 to ByteArray(96) }
        if (knownLock) locks += (if (password == null) 2 else 1) to ByteArray(if (password == null) 32 else 96)
        val keyBlockLength = 32 + 1 + locks.sumOf { 3 + it.second.size }

        val header = ByteArray(64)
        System.arraycopy("OBSI".toByteArray(), 0, header, 0, 4)
        System.arraycopy(be(format.toLong(), 2), 0, header, 4, 2)
        System.arraycopy(be(readableBy.toLong(), 2), 0, header, 6, 2)
        System.arraycopy(be(flags.toLong(), 2), 0, header, 8, 2)
        System.arraycopy(be(keyBlockLength.toLong(), 2), 0, header, 10, 2)
        System.arraycopy(be(recordSize.toLong(), 4), 0, header, 12, 4)
        System.arraycopy(random(16), 0, header, 16, 16)
        System.arraycopy(prefix, 0, header, 32, 4)

        fun passwordLock(password: String, rounds: Long): ByteArray {
            val salt = random(32)
            val kek = KeyDerivation.pbkdf2SHA256(password, salt, rounds.toInt()).toByteArray()
            return be(rounds, 4) + salt + gcm(kek, random(12), header, contentKey)
        }
        extraPasswordLocks.forEachIndexed { index, (extra, extraRounds) ->
            locks[unknownLocks.size + index] = 1 to passwordLock(extra, extraRounds)
        }
        val password = password
        if (knownLock) {
            locks[locks.lastIndex] = locks.last().first to when {
                password == null -> contentKey
                !sealsLock -> be(rounds, 4) + random(92)
                else -> passwordLock(password, rounds)
            }
        }
        val keyBlock = ByteArrayOutputStream().apply {
            // HKDF-SHA256 over the content key, salt 32 zero bytes, info "OBSI v3 key commitment".
            write(commitment(if (commitsToKey) contentKey else random(32)))
            write(locks.size)
            for ((type, body) in locks) {
                write(type)
                write(be(body.size.toLong(), 2))
                write(body)
            }
        }.toByteArray()
        val preamble = header + keyBlock

        val stream = ByteArrayOutputStream()
        stream.write(be(manifest.size.toLong(), 4))
        stream.write(manifest)
        for (item in items) for ((_, data) in item.parts) stream.write(data)
        stream.write(trailing)
        val records = maxOf(1, (stream.size() + recordSize - 1) / recordSize) + extraZeroRecords
        stream.write(ByteArray(records * recordSize - stream.size()))
        val plain = stream.toByteArray()

        val out = ByteArrayOutputStream()
        out.write(preamble)
        for (index in 0 until records) {
            val counter = if (index == records - 1 && marksLastRecord) index.toLong() or Long.MIN_VALUE else index.toLong()
            out.write(gcm(recordKey(contentKey), prefix + be(counter, 8), preamble,
                plain.copyOfRange(index * recordSize, (index + 1) * recordSize)))
        }
        return File(directory, "${UUID.randomUUID()}.obscurashared").also { it.writeBytes(out.toByteArray()) }
    }

    class Read(
        val format: Int,
        val readableBy: Int,
        val flags: Int,
        val reservedAreZero: Boolean,
        val rounds: Long?,
        val recordLengths: List<Int>,
        val paddingIsZero: Boolean,
        val parts: List<ByteArray>,
    )

    companion object {
        fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

        /**
         * HKDF-SHA256 as the formats describe it, written out here rather than taken from the library: salt 32 zero bytes, and the
         * 32 bytes of the first block.
         */
        fun subkey(key: ByteArray, info: String): ByteArray {
            val pseudorandomKey = Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
                doFinal(key)
            }
            return Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(pseudorandomKey, "HmacSHA256"))
                update(info.toByteArray())
                doFinal(byteArrayOf(1))
            }
        }

        fun commitment(key: ByteArray): ByteArray = subkey(key, "OBSI v3 key commitment")

        fun recordKey(key: ByteArray): ByteArray = subkey(key, "OBSI v3 records")

        fun read(file: File, password: String?): Read {
            val data = file.readBytes()
            fun u16(at: Int) = ((data[at].toInt() and 0xFF) shl 8) or (data[at + 1].toInt() and 0xFF)
            fun u32(at: Int) = (u16(at).toLong() shl 16) or u16(at + 2).toLong()
            fun open(key: ByteArray, combined: ByteArray, aad: ByteArray): ByteArray {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, combined, 0, 12))
                cipher.updateAAD(aad)
                return cipher.doFinal(combined, 12, combined.size - 12)
            }
            check(String(data, 0, 4, Charsets.US_ASCII) == "OBSI")
            val header = data.copyOfRange(0, 64)
            val keyBlockLength = u16(10)
            val recordSize = u32(12).toInt()
            val prefix = header.copyOfRange(32, 36)
            val preamble = data.copyOfRange(0, 64 + keyBlockLength)

            var key: ByteArray? = null
            var rounds: Long? = null
            val committed = data.copyOfRange(64, 96)
            var at = 97
            repeat(data[96].toInt()) {
                val type = data[at].toInt()
                val length = u16(at + 1)
                val body = data.copyOfRange(at + 3, at + 3 + length)
                if (type == 2) key = body
                if (type == 1 && password != null) {
                    val r = u32(at + 3)
                    val kek = KeyDerivation.pbkdf2SHA256(password, body.copyOfRange(4, 36), r.toInt()).toByteArray()
                    key = open(kek, body.copyOfRange(36, body.size), header)
                    rounds = r
                }
                at += 3 + length
            }
            val contentKey = checkNotNull(key)
            check(commitment(contentKey).contentEquals(committed)) { "the key is the one the file commits to" }

            val recordBytes = recordSize + 28
            check((data.size - at) % recordBytes == 0)
            val count = (data.size - at) / recordBytes
            val stream = ByteArrayOutputStream()
            val lengths = ArrayList<Int>()
            for (index in 0 until count) {
                val combined = data.copyOfRange(at + index * recordBytes, at + (index + 1) * recordBytes)
                val counter = if (index == count - 1) index.toLong() or Long.MIN_VALUE else index.toLong()
                val nonce = prefix + ByteArray(8) { ((counter shr (8 * (7 - it))) and 0xFF).toByte() }
                check(nonce.contentEquals(combined.copyOfRange(0, 12))) { "record $index's nonce is its position" }
                stream.write(open(recordKey(contentKey), combined, preamble))
                lengths += recordBytes
            }
            val all = stream.toByteArray()
            val manifestLength = ((all[0].toInt() and 0xFF) shl 24) or ((all[1].toInt() and 0xFF) shl 16) or
                ((all[2].toInt() and 0xFF) shl 8) or (all[3].toInt() and 0xFF)
            val text = String(all, 4, manifestLength, Charsets.UTF_8)
            val sizes = Regex(""""size":(\d+)""").findAll(text).map { it.groupValues[1].toInt() }.toList()
            var position = 4 + manifestLength
            val parts = sizes.map { size -> all.copyOfRange(position, position + size).also { position += size } }
            return Read(
                format = u16(4), readableBy = u16(6), flags = u16(8), reservedAreZero = header.copyOfRange(36, 64).all { it == 0.toByte() },
                rounds = rounds, recordLengths = lengths, paddingIsZero = (position until all.size).all { all[it] == 0.toByte() },
                parts = parts,
            )
        }
    }
}
