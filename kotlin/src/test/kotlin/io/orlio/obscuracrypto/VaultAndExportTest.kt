// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.io.ByteArrayOutputStream
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/**
 * A real vault and a real export, made end to end by the Obscura iOS app's own
 * code: the vault file, its media pool with a file from a second vault in it,
 * and an export made by the app's exporter. Only the vault file's random
 * padding was cut off, to keep the fixture small. The Swift package reads the
 * same files in its `VaultAndExportTests`.
 */
class VaultAndExportTest : CryptoTestCase() {

    private val manifest = Json.parseToJsonElement(Fixtures.file("vault-manifest.json").readText()).jsonObject

    private fun string(key: String) = manifest.getValue(key).jsonPrimitive.content

    private val vaultPassword get() = string("vaultPassword")
    private val photo get() = string("photo")
    private val video get() = string("video")
    private val protectedPhoto get() = string("protectedPhoto")
    private val otherVaultPhoto get() = string("otherVaultPhoto")

    private fun masterKey(): SecureBytes =
        VaultHeader.parse(Fixtures.file(string("vaultFile")).readBytes()).unlock(vaultPassword)

    private fun stored(id: String, kind: String = "data") = Fixtures.file("vault/media/$id.$kind.enc")

    /** The app's movie generator, so the fixture need not carry the plaintext. */
    private fun movie(): ByteArray =
        byteArrayOf(0, 0, 0, 20) + "ftypqt  ".toByteArray() + ByteArray(8) +
            ByteArray(1_100_000) { ((it * 7 + 3) % 251).toByte() }

    // MARK: Media in the pool

    @Test
    fun masterKeyOpensThisVaultsFilesOnly() {
        val key = masterKey()
        assertTrue(MediaExtraction.masterKeyOpens(stored(photo), key))
        assertTrue(MediaExtraction.masterKeyOpens(stored(video), key))
        assertFalse(MediaExtraction.masterKeyOpens(stored(protectedPhoto), key))
        assertFalse(MediaExtraction.masterKeyOpens(stored(otherVaultPhoto), key))
    }

    /** The pool is shared by every vault and file names say nothing about ownership; trying the key picks out this vault's files. */
    @Test
    fun tryingTheKeyFindsThisVaultsFilesInTheSharedPool() {
        val key = masterKey()
        val pool = Fixtures.file("vault/media")
        val ids = pool.list()!!.filter { it.endsWith(".data.enc") }.map { it.removeSuffix(".data.enc") }
        val opened = ids.filter { MediaExtraction.masterKeyOpens(File(pool, "$it.data.enc"), key) }
        assertEquals(setOf(photo, video), opened.toSet())
    }

    @Test
    fun extractionNamesFilesByWhatTheyAre() {
        val key = masterKey()

        val photoOutcome = MediaExtraction.extract(stored(photo), photo, key, directory = directory)
        assertEquals("jpg", assertIs<MediaExtraction.Outcome.Extracted>(photoOutcome).file.extension)

        val videoOutcome = MediaExtraction.extract(stored(video), video, key, directory = directory)
        val movieFile = assertIs<MediaExtraction.Outcome.Extracted>(videoOutcome).file
        assertEquals("mov", movieFile.extension)
        assertContentEquals(movie(), movieFile.readBytes())

        assertIs<MediaExtraction.Outcome.NotOpenedByMasterKey>(
            MediaExtraction.extract(stored(protectedPhoto), protectedPhoto, key, directory = directory)
        )
        assertEquals(emptyList(), directory.list()!!.filter { it.endsWith(".partial") })
    }

    @Test
    fun extractionRefusesANameThatIsNotAMediaId() {
        for (id in listOf("../escape", "x", "A3E42A38-8C9A-483D-BAE4-1AEE61FF133", "A3E42A38-8C9A-483D-BAE4-1AEE61FF133AA")) {
            assertRefused<ObscuraCryptoException.InvalidExport> {
                MediaExtraction.extract(stored(photo), id, masterKey(), directory = directory)
            }
        }
    }

    @Test
    fun extractionNeverOverwrites() {
        val key = masterKey()
        MediaExtraction.extract(stored(photo), photo, key, directory = directory)
        assertRefused<ObscuraCryptoException.InvalidExport> {
            MediaExtraction.extract(stored(photo), photo, key, directory = directory)
        }
    }

    @Test
    fun extractionRefusesALinkAtTheName() {
        val target = File(directory, "elsewhere")
        java.nio.file.Files.createSymbolicLink(File(directory, "$photo.jpg").toPath(), target.toPath())
        assertRefused<ObscuraCryptoException.InvalidExport> {
            MediaExtraction.extract(stored(photo), photo, masterKey(), directory = directory)
        }
        assertFalse(target.exists())
    }

    @Test
    fun extractedFilesAreReadableByTheirOwnerOnly() {
        val outcome = MediaExtraction.extract(stored(video), video, masterKey(), directory = directory)
        val file = assertIs<MediaExtraction.Outcome.Extracted>(outcome).file
        assertEquals(
            "rw-------",
            java.nio.file.attribute.PosixFilePermissions.toString(java.nio.file.Files.getPosixFilePermissions(file.toPath())),
        )
    }

    @Test
    fun fileTypesComeFromTheBytesNotTheName() {
        fun ext(vararg bytes: Int) = MediaExtraction.fileExtension(ByteArray(bytes.size) { bytes[it].toByte() })
        assertEquals("jpg", ext(0xFF, 0xD8, 0xFF, 0xE0))
        assertEquals("png", ext(0x89, 0x50, 0x4E, 0x47))
        assertEquals("heic", MediaExtraction.fileExtension(byteArrayOf(0, 0, 0, 24) + "ftypheic".toByteArray()))
        assertEquals("mov", MediaExtraction.fileExtension(byteArrayOf(0, 0, 0, 20) + "ftypqt  ".toByteArray()))
        assertEquals("mp4", MediaExtraction.fileExtension(byteArrayOf(0, 0, 0, 24) + "ftypisom".toByteArray()))
        assertEquals("bin", ext(1, 2, 3))
    }

    // MARK: Export

    @Test
    fun exportUnpacksToTheSameFilesAndKey() {
        ExportArchive.open(Fixtures.file("vault.obscura"), vaultPassword).use { archive ->
            assertTrue(archive.index.unlockMasterKey(vaultPassword).contentEquals(masterKey()))
            assertEquals(setOf(photo, video, protectedPhoto), archive.index.mediaFiles.map { it.id }.toSet())

            // The vault file comes out whole.
            val vaultFile = Fixtures.file(string("vaultFile")).readBytes()
            assertEquals(vaultFile.size.toLong(), archive.index.databaseSize)
            val database = ByteArrayOutputStream()
            archive.copyDatabase(database)
            assertContentEquals(vaultFile, database.toByteArray())

            // Every stored media file comes out byte for byte.
            for (media in archive.index.mediaFiles) {
                val data = File(directory, "${media.id}.data")
                archive.copyStoredFile(media.dataSize, data)
                assertContentEquals(stored(media.id).readBytes(), data.readBytes())
                if (media.thumbnailSize > 0) {
                    val thumb = File(directory, "${media.id}.thumb")
                    archive.copyStoredFile(media.thumbnailSize, thumb)
                    assertContentEquals(stored(media.id, "thumb").readBytes(), thumb.readBytes())
                }
            }
            assertTrue(archive.isAtEnd())
        }
    }

    @Test
    fun exportRefusesTheWrongPassword() {
        assertRefused<ObscuraCryptoException.WrongPassword> {
            ExportArchive.open(Fixtures.file("vault.obscura"), "not it")
        }
    }

    @Test
    fun alteredExportIsRefused() {
        val bytes = Fixtures.file("vault.obscura").readBytes()
        bytes[bytes.size - 30] = (bytes[bytes.size - 30].toInt() xor 1).toByte()
        val altered = file("altered.obscura", bytes)

        ExportArchive.open(altered, vaultPassword).use { archive ->
            archive.skipDatabase()
            assertFailsWith<ObscuraCryptoException> {
                for (media in archive.index.mediaFiles) {
                    archive.copyStoredFile(media.dataSize, null as File?)
                    archive.copyStoredFile(media.thumbnailSize, null as File?)
                }
            }
        }
    }

    @Test
    fun exportHeaderLayout() {
        val header = ExportHeader.parse(Fixtures.file("vault.obscura").readBytes())
        assertEquals(1, header.version)
        assertEquals(600_000L, header.kdfIterations)
        assertEquals(32, header.salt.size)
        assertEquals(4, header.noncePrefix.size)
        assertContentEquals(Fixtures.file("vault.obscura").readBytes().copyOf(64), header.serialized())
    }

    @Test
    fun version2HeaderLayout() {
        val out = ByteArrayOutputStream()
        val writer = ExportWriter.begin(out, "pw")
        val bytes = out.toByteArray()
        assertEquals(97, bytes.size, "the header and a key block of one byte")
        assertContentEquals("OBSV".toByteArray(), bytes.copyOf(4))
        assertContentEquals(byteArrayOf(0, 2, 0, 2, 0, 0, 0, 1, 0, 0x10, 0, 0), bytes.copyOfRange(4, 16))
        assertContentEquals(writer.header.salt, bytes.copyOfRange(16, 48))
        assertEquals(600_000L, bytes.bigEndianUInt32(48))
        assertContentEquals(writer.header.noncePrefix, bytes.copyOfRange(52, 56))
        val exportKey = KeyDerivation.pbkdf2SHA256("pw", writer.header.salt, 600_000)
        // HKDF-SHA256 over the export key, salt 32 zero bytes, info "OBSV v2 key commitment".
        assertContentEquals(SpecFile.subkey(exportKey.toByteArray(), "OBSV v2 key commitment"), bytes.copyOfRange(56, 88))
        assertContentEquals(ByteArray(8), bytes.copyOfRange(88, 96))
        assertEquals(0, bytes[96].toInt(), "no locks beside the password")
        val header = ExportHeader.parse(bytes)
        assertEquals(emptyList(), header.lockTypes)
        assertEquals(2, header.version)
        assertEquals(2, header.readableBy)
        assertEquals(1_048_576, header.recordSize)
    }

    // MARK: Writing an export

    /** What the writer produces, the reader (which reads the iOS app's exports) takes back. */
    @Test
    fun anExportWrittenHereReadsBackHere() {
        val created = VaultHeader.create("export password")
        val vaultFile = created.header.serialized() + randomBytes(5_000)
        val media = listOf(randomBytes(3_000_000), randomBytes(10), ByteArray(0))
        val ids = listOf("A3E42A38-8C9A-483D-BAE4-1AEE61FF133A", "B73D3715-51FA-4CFD-81F8-863C3D37D73F")
        val thumbs = listOf(randomBytes(500), randomBytes(77))

        val manifestJson = """
            {"exportVersion":1,
             "vaultSalt":"${java.util.Base64.getEncoder().encodeToString(created.header.salt)}",
             "encryptedMEK":"${java.util.Base64.getEncoder().encodeToString(created.header.wrappedMasterKey)}",
             "databaseSize":${vaultFile.size},
             "mediaFiles":[
               {"mediaId":"${ids[0]}","dataSize":${media[0].size},"thumbSize":${thumbs[0].size}},
               {"mediaId":"${ids[1]}","dataSize":${media[1].size},"thumbSize":${thumbs[1].size}}]}
        """.trimIndent()

        val out = ByteArrayOutputStream()
        val writer = ExportWriter.begin(out, "export password")
        writer.writeManifest(manifestJson.toByteArray())
        writer.writeFile(vaultFile.inputStream(), vaultFile.size.toLong())
        writer.writeFile(media[0].inputStream(), media[0].size.toLong())
        writer.writeFile(thumbs[0].inputStream(), thumbs[0].size.toLong())
        writer.writeFile(media[1].inputStream(), media[1].size.toLong())
        writer.writeFile(thumbs[1].inputStream(), thumbs[1].size.toLong())
        writer.finish()

        ExportArchive.open(out.toByteArray().inputStream(), "export password").use { archive ->
            assertTrue(archive.index.unlockMasterKey("export password").contentEquals(created.masterKey))
            val database = ByteArrayOutputStream()
            archive.copyDatabase(database)
            assertContentEquals(vaultFile, database.toByteArray())
            val first = ByteArrayOutputStream()
            archive.copyStoredFile(media[0].size.toLong(), first)
            assertContentEquals(media[0], first.toByteArray())
            val firstThumb = ByteArrayOutputStream()
            archive.copyStoredFile(thumbs[0].size.toLong(), firstThumb)
            assertContentEquals(thumbs[0], firstThumb.toByteArray())
            archive.copyStoredFile(media[1].size.toLong(), null as java.io.OutputStream?)
            archive.copyStoredFile(thumbs[1].size.toLong(), null as java.io.OutputStream?)
            assertTrue(archive.isAtEnd())
        }
        assertRefused<ObscuraCryptoException.WrongPassword> { ExportArchive.open(out.toByteArray().inputStream(), "other") }

        // Version 2: whole records of one size after the header, the content padded to its Padmé length.
        val written = out.toByteArray()
        val writtenHeader = ExportHeader.parse(written)
        assertEquals(2, writtenHeader.version)
        val headerSize = writtenHeader.byteCount
        val recordBytes = ExportWriter.RECORD_SIZE + AesGcm.OVERHEAD
        assertEquals(0, (written.size - headerSize) % recordBytes)
        val content = 4L + manifestJson.toByteArray().size + vaultFile.size + media.sumOf { it.size } + thumbs.sumOf { it.size }
        val records = (SharedItemsFile.padme(content) + ExportWriter.RECORD_SIZE - 1) / ExportWriter.RECORD_SIZE
        assertEquals(records, ((written.size - headerSize) / recordBytes).toLong())
        var reported = 0L
        ExportArchive.verify(written.inputStream(), "export password") { done, total ->
            assertTrue(done in reported..total)
            reported = done
        }
        assertEquals(content - 4 - manifestJson.toByteArray().size, reported)
    }

    private fun manifestFor(created: VaultHeader.Created, databaseSize: Int, media: String = ""): ByteArray {
        val b64 = java.util.Base64.getEncoder()
        return ("{\"exportVersion\":1,\"vaultSalt\":\"${b64.encodeToString(created.header.salt)}\"," +
            "\"encryptedMEK\":\"${b64.encodeToString(created.header.wrappedMasterKey)}\"," +
            "\"databaseSize\":$databaseSize,\"mediaFiles\":[$media]}").toByteArray()
    }

    @Test
    fun theWriterRefusesToWriteOtherThanWhatTheManifestLists() {
        val json = manifestFor(VaultHeader.create("pw"), 10)
        val short = ExportWriter.begin(ByteArrayOutputStream(), "pw").apply { writeManifest(json) }
        short.writeFile(ByteArray(9).inputStream(), 9)
        assertRefused<ObscuraCryptoException.InvalidExport> { short.finish() }
        val long = ExportWriter.begin(ByteArrayOutputStream(), "pw").apply { writeManifest(json) }
        assertRefused<ObscuraCryptoException.InvalidExport> { long.writeFile(ByteArray(11).inputStream(), 11) }
    }

    /** Files share version 2 records: each still reads back as its own bytes, an empty one included. */
    @Test
    fun smallRecordsAcrossFilesReadBackWhole() {
        val files = listOf(randomBytes(10), randomBytes(9_000), ByteArray(0), randomBytes(1), randomBytes(4_096))
        val entries = "{\"mediaId\":\"A3E42A38-8C9A-483D-BAE4-1AEE61FF133A\",\"dataSize\":${files[1].size},\"thumbSize\":0}," +
            "{\"mediaId\":\"B73D3715-51FA-4CFD-81F8-863C3D37D73F\",\"dataSize\":${files[3].size},\"thumbSize\":${files[4].size}}"
        val out = ByteArrayOutputStream()
        val writer = ExportWriter.begin(out, "pw", KeyDerivation.VAULT_ITERATIONS, 4_096)
        writer.writeManifest(manifestFor(VaultHeader.create("pw"), files[0].size, entries))
        for (file in files) writer.writeFile(file.inputStream(), file.size.toLong())
        writer.finish()
        ExportArchive.open(out.toByteArray().inputStream(), "pw").use { archive ->
            assertEquals(4_096, archive.header.recordSize)
            for (file in files) {
                val copy = ByteArrayOutputStream()
                archive.copyStoredFile(file.size.toLong(), copy)
                assertContentEquals(file, copy.toByteArray())
            }
            assertTrue(archive.isAtEnd())
        }
    }

    @Test
    fun theWriterRefusesToStartWithTooFewRounds() {
        assertFailsWith<IllegalArgumentException> { ExportWriter.begin(ByteArrayOutputStream(), "x", iterations = 1_000) }
    }

    @Test
    fun theReaderRefusesAManifestWithABadMediaId() {
        val created = VaultHeader.create("pw")
        fun archiveWith(mediaId: String): ByteArray {
            val json = """{"exportVersion":1,"vaultSalt":"${java.util.Base64.getEncoder().encodeToString(created.header.salt)}",
                "encryptedMEK":"${java.util.Base64.getEncoder().encodeToString(created.header.wrappedMasterKey)}","databaseSize":0,
                "mediaFiles":[{"mediaId":"$mediaId","dataSize":0,"thumbSize":0}]}"""
            val out = ByteArrayOutputStream()
            ExportWriterVersion1.begin(out, "pw").writeManifest(json.toByteArray())
            return out.toByteArray()
        }
        assertRefused<ObscuraCryptoException.InvalidExport> { ExportArchive.open(archiveWith("../../etc").inputStream(), "pw") }
        ExportArchive.open(archiveWith("A3E42A38-8C9A-483D-BAE4-1AEE61FF133A").inputStream(), "pw").close()
        // The writer refuses such a manifest before writing a record.
        val hostile = manifestFor(created, 0, "{\"mediaId\":\"../../etc\",\"dataSize\":0,\"thumbSize\":0}")
        assertRefused<ObscuraCryptoException.InvalidExport> { ExportWriter.begin(ByteArrayOutputStream(), "pw").writeManifest(hostile) }
    }
}
