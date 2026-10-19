// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/**
 * The cross-language fixtures: a folder of files, written by one language of
 * this library, with a `compat.json` that says what each file is, and what a
 * reader must do with it: open it and get the stated contents, or refuse it
 * with a named error. Each language writes a set and reads both, so Kotlin
 * opens every file Swift wrote, Swift opens every file Kotlin wrote, and both
 * refuse the same tampered files for the same reason.
 *
 * The Swift package has the same schema and the same checks in
 * `CompatFixtureTests.swift`. Change one, change both.
 *
 * `compat.json`:
 * ```
 * { "format": 1, "generatedBy": "...",
 *   "vaultPassword": "...", "folderPassword": "...",
 *   "masterKeyFingerprint": "...", "folderKeyFingerprint": "...", "databaseSize": N,
 *   "folder": { "passwordSalt": b64, "passwordHash": b64, "folderKeyEncrypted": b64 },
 *   "cases": [ { "file": "...", "kind": "vaultHeader" | "singleShot" | "chunked" | "export",
 *                "expect": "opens" | "<error name>", ... } ] }
 * ```
 * Plaintext is never stored: a case carries `count` and `seed`, and the bytes
 * are `(i * 31 + seed) % 251`.
 */
object Compat {
    val json = Json { prettyPrint = true }

    class Outcome(val case: String, val ok: Boolean, val detail: String)

    /** "AuthenticationFailed" is named "authenticationFailed", as in the Swift enum. */
    fun errorName(e: Throwable): String =
        if (e is ObscuraCryptoException) e::class.simpleName!!.replaceFirstChar { it.lowercase() } else "other: $e"

    fun sha256(bytes: ByteArray): String = Fixtures.hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    // MARK: Verifying

    /** Checks every case in [directory]'s `compat.json`. */
    fun verify(directory: File): List<Outcome> {
        val manifest = Json.parseToJsonElement(File(directory, "compat.json").readText()).jsonObject
        fun text(key: String) = manifest.getValue(key).jsonPrimitive.content
        val vaultPassword = text("vaultPassword")
        val folderPassword = text("folderPassword")
        val folderObject = manifest.getValue("folder").jsonObject
        fun b64(key: String) = Base64.getDecoder().decode(folderObject.getValue(key).jsonPrimitive.content)
        val protection = FolderProtection(b64("passwordSalt"), b64("passwordHash"), b64("folderKeyEncrypted"))

        val results = ArrayList<Outcome>()
        for (element in manifest.getValue("cases").jsonArray) {
            val case = element.jsonObject
            val file = case.getValue("file").jsonPrimitive.content
            val expect = case.getValue("expect").jsonPrimitive.content
            val actual = try {
                check(File(directory, file), case, manifest, vaultPassword, folderPassword, protection)
                "opens"
            } catch (e: Throwable) {
                errorName(e)
            }
            results += Outcome(file, actual == expect, "expected $expect, got $actual")
        }
        return results
    }

    private fun check(
        file: File, case: JsonObject, manifest: JsonObject,
        vaultPassword: String, folderPassword: String, protection: FolderProtection,
    ) {
        val bytes = file.readBytes()
        val withFolder = case["folder"]?.jsonPrimitive?.boolean ?: false
        fun masterKey() = VaultHeader.parse(
            File(file.parentFile.let { if (it.name == "tampered") it.parentFile else it }, "vault.header").readBytes()
        ).unlock(vaultPassword)

        when (val kind = case.getValue("kind").jsonPrimitive.content) {
            "vaultHeader" -> {
                val header = VaultHeader.parse(bytes)
                val key = header.unlock(vaultPassword)
                require(key.fingerprint == manifest.getValue("masterKeyFingerprint").jsonPrimitive.content) { "master key" }
                require(header.databaseSize(key) == manifest.getValue("databaseSize").jsonPrimitive.long) { "database size" }
                require(header.serialized().contentEquals(bytes)) { "header does not rewrite identically" }
            }
            "singleShot" -> {
                val folderKey = if (withFolder) protection.unlock(folderPassword) else null
                val plaintext = SingleShotMedia.decrypt(bytes, masterKey(), folderKey)
                require(plaintext.contentEquals(plaintextOf(case))) { "plaintext differs" }
            }
            "chunked" -> {
                val folderKey = if (withFolder) protection.unlock(folderPassword) else null
                val reader = ChunkedMediaReader(file)
                val out = ByteArrayOutputStream()
                reader.decrypt(out, masterKey(), folderKey)
                require(out.toByteArray().contentEquals(plaintextOf(case))) { "plaintext differs" }
                require(reader.header.chunkPlaintextSize == case.getValue("chunkSize").jsonPrimitive.long) { "chunk size" }
                require(reader.header.hasFolderLayer == withFolder) { "folder flag" }
            }
            "export" -> {
                val password = case["password"]?.jsonPrimitive?.content ?: vaultPassword
                ExportArchive.open(file, password).use { archive ->
                    val key = archive.index.unlockMasterKey(vaultPassword)
                    require(key.fingerprint == manifest.getValue("masterKeyFingerprint").jsonPrimitive.content) { "master key" }
                    val database = ByteArrayOutputStream().also { archive.copyDatabase(it) }.toByteArray()
                    require(sha256(database) == case.getValue("databaseSha256").jsonPrimitive.content) { "database" }
                    val media = case.getValue("media").jsonArray
                    require(media.size == archive.index.mediaFiles.size) { "media count" }
                    for ((entry, listed) in media.zip(archive.index.mediaFiles)) {
                        val expected = entry.jsonObject
                        require(listed.id == expected.getValue("id").jsonPrimitive.content) { "media id" }
                        val data = ByteArrayOutputStream().also { archive.copyStoredFile(listed.dataSize, it) }.toByteArray()
                        val thumb = ByteArrayOutputStream().also { archive.copyStoredFile(listed.thumbnailSize, it) }.toByteArray()
                        require(sha256(data) == expected.getValue("dataSha256").jsonPrimitive.content) { "data of ${listed.id}" }
                        require(sha256(thumb) == expected.getValue("thumbSha256").jsonPrimitive.content) { "thumbnail of ${listed.id}" }
                    }
                    require(archive.isAtEnd()) { "records left over" }
                }
            }
            else -> error("unknown case kind $kind")
        }
    }

    private fun plaintextOf(case: JsonObject): ByteArray =
        Fixtures.plaintext(case.getValue("count").jsonPrimitive.int, case.getValue("seed").jsonPrimitive.int)

    // MARK: Writing

    /** Writes this language's fixture set into [directory], which is created. */
    fun write(directory: File, generatedBy: String) {
        directory.deleteRecursively()
        File(directory, "tampered").mkdirs()
        val vaultPassword = "kotlin pässword 日本語" // a decomposed accent, and Japanese
        val folderPassword = "kotlin folder pass 1"
        val databaseSize = 1_234_567L

        val created = VaultHeader.create(vaultPassword, databaseSize)
        val master = created.masterKey
        val folder = FolderProtection.create(folderPassword)
        val folderKey = folder.folderKey

        val cases = ArrayList<JsonObject>()
        fun case(vararg fields: Pair<String, Any>) = cases.add(JsonObject(fields.associate { (k, v) ->
            k to when (v) {
                is Boolean -> JsonPrimitive(v)
                is Number -> JsonPrimitive(v)
                else -> JsonPrimitive(v.toString())
            }
        }))
        fun put(path: String, bytes: ByteArray) = File(directory, path).writeBytes(bytes)

        // Vault headers
        val header = created.header.serialized()
        put("vault.header", header)
        case("file" to "vault.header", "kind" to "vaultHeader", "expect" to "opens")

        val damaged = header.copyOf().also { it[20] = (it[20].toInt() xor 0xFF).toByte() }
        put("tampered/vault-checksum.header", damaged)
        case("file" to "tampered/vault-checksum.header", "kind" to "vaultHeader", "expect" to "vaultHeaderChecksumMismatch")

        val wrongVersion = header.copyOf().also { it[0] = 0x02 }
        put("tampered/vault-version.header", wrongVersion)
        case("file" to "tampered/vault-version.header", "kind" to "vaultHeader", "expect" to "invalidVaultHeader")

        val unknownSuite = header.copyOf().also { it[8] = 0x02; refreshChecksum(it) }
        put("tampered/vault-suite.header", unknownSuite)
        case("file" to "tampered/vault-suite.header", "kind" to "vaultHeader", "expect" to "unsupportedCipherSuite")

        val weakened = VaultHeader(
            kdfIterations = 1_000, salt = created.header.salt,
            wrappedMasterKey = created.header.wrappedMasterKey, encryptedDatabaseSize = created.header.encryptedDatabaseSize,
        ).serialized()
        put("tampered/vault-rounds.header", weakened)
        case("file" to "tampered/vault-rounds.header", "kind" to "vaultHeader", "expect" to "iterationsBelowMinimum")

        // Single-shot media
        val photoPlain = Fixtures.plaintext(20_000, 1)
        put("photo.data.enc", SingleShotMedia.encrypt(photoPlain, master))
        case("file" to "photo.data.enc", "kind" to "singleShot", "folder" to false, "count" to 20_000, "seed" to 1, "expect" to "opens")
        put("photo-folder.data.enc", SingleShotMedia.encrypt(photoPlain, master, folderKey))
        case("file" to "photo-folder.data.enc", "kind" to "singleShot", "folder" to true, "count" to 20_000, "seed" to 1, "expect" to "opens")
        val tamperedPhoto = SingleShotMedia.encrypt(photoPlain, master).also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        put("tampered/photo-tag.data.enc", tamperedPhoto)
        case("file" to "tampered/photo-tag.data.enc", "kind" to "singleShot", "folder" to false, "count" to 20_000, "seed" to 1, "expect" to "authenticationFailed")

        // Chunked media
        fun chunked(name: String, count: Int, seed: Int, chunkSize: Long, withFolder: Boolean): File {
            val source = File(directory, ".source.bin").also { it.writeBytes(Fixtures.plaintext(count, seed)) }
            val destination = File(directory, name)
            ChunkedMediaEncryptor.encrypt(source, destination, master, if (withFolder) folderKey else null, chunkSize)
            source.delete()
            case("file" to name, "kind" to "chunked", "folder" to withFolder, "count" to count, "seed" to seed,
                "chunkSize" to chunkSize, "expect" to "opens")
            return destination
        }
        chunked("video.data.enc", 200_000, 2, 65_536, false)
        chunked("video-folder.data.enc", 200_000, 2, 65_536, true)
        chunked("video-boundary.data.enc", 131_072, 3, 65_536, false)
        chunked("video-empty.data.enc", 0, 4, 65_536, false)
        chunked("video-small-chunks.data.enc", 10_000, 5, 4_096, true)

        val video = File(directory, "video.data.enc").readBytes()
        val videoHeader = ChunkedMediaHeader.parse(video)
        val swapped = video.copyOf()
        val size = videoHeader.encryptedSize(0).toInt()
        val first = videoHeader.chunkOffset(0).toInt()
        val second = videoHeader.chunkOffset(1).toInt()
        System.arraycopy(video, second, swapped, first, size)
        System.arraycopy(video, first, swapped, second, size)
        fun tamperedVideo(name: String, bytes: ByteArray, expect: String) {
            put("tampered/$name", bytes)
            case("file" to "tampered/$name", "kind" to "chunked", "folder" to false, "count" to 200_000, "seed" to 2,
                "chunkSize" to 65_536, "expect" to expect)
        }
        tamperedVideo("video-swapped.data.enc", swapped, "chunkNonceMismatch")
        tamperedVideo("video-truncated.data.enc", video.copyOf(video.size - 10), "chunkedFileSizeMismatch")
        tamperedVideo(
            "video-flipped.data.enc",
            video.copyOf().also { val at = videoHeader.chunkOffset(2).toInt() + 20; it[at] = (it[at].toInt() xor 1).toByte() },
            "authenticationFailed",
        )
        val hostile = video.copyOf(25)
        System.arraycopy(bigEndianBytes(-16L, 8), 0, hostile, 9, 8)
        tamperedVideo("video-hostile-length.data.enc", hostile, "invalidChunkedHeader")

        // Export
        val exportCases = writeExport(directory, created, vaultPassword, master, folderKey)
        cases += exportCases

        val manifest = JsonObject(mapOf(
            "format" to JsonPrimitive(1),
            "generatedBy" to JsonPrimitive(generatedBy),
            "vaultPassword" to JsonPrimitive(vaultPassword),
            "folderPassword" to JsonPrimitive(folderPassword),
            "masterKeyFingerprint" to JsonPrimitive(master.fingerprint),
            "folderKeyFingerprint" to JsonPrimitive(folderKey.fingerprint),
            "databaseSize" to JsonPrimitive(databaseSize),
            "folder" to JsonObject(mapOf(
                "passwordSalt" to JsonPrimitive(Base64.getEncoder().encodeToString(folder.protection.salt)),
                "passwordHash" to JsonPrimitive(Base64.getEncoder().encodeToString(folder.protection.passwordHash)),
                "folderKeyEncrypted" to JsonPrimitive(Base64.getEncoder().encodeToString(folder.protection.wrappedFolderKey)),
            )),
            "cases" to JsonArray(cases),
        ))
        File(directory, "compat.json").writeText(asciiJson(json.encodeToString(JsonObject.serializer(), manifest)) + "\n")
    }

    private fun writeExport(
        directory: File, created: VaultHeader.Created, vaultPassword: String,
        master: SecureBytes, folderKey: SecureBytes,
    ): List<JsonObject> {
        val vaultFile = created.header.serialized() + Fixtures.plaintext(90_000, 9)
        class Media(val id: String, val data: ByteArray, val thumb: ByteArray)
        val chunkedSource = File(directory, ".media.bin").also { it.writeBytes(Fixtures.plaintext(150_000, 6)) }
        val chunkedFile = File(directory, ".media.enc")
        ChunkedMediaEncryptor.encrypt(chunkedSource, chunkedFile, master, null, 65_536)
        val media = listOf(
            Media("A3E42A38-8C9A-483D-BAE4-1AEE61FF133A", SingleShotMedia.encrypt(Fixtures.plaintext(3_000, 7), master),
                SingleShotMedia.encrypt(Fixtures.plaintext(400, 8), master)),
            Media("B73D3715-51FA-4CFD-81F8-863C3D37D73F", chunkedFile.readBytes(),
                SingleShotMedia.encrypt(Fixtures.plaintext(300, 10), master)),
            Media("919120EA-50E6-417C-8F1A-714F5A286E56", SingleShotMedia.encrypt(Fixtures.plaintext(2_000, 11), master, folderKey),
                ByteArray(0)),
        )
        chunkedSource.delete()
        chunkedFile.delete()

        val b64 = Base64.getEncoder()
        val manifestJson = buildString {
            append("{\"exportVersion\":1,\"vaultSalt\":\"").append(b64.encodeToString(created.header.salt))
            append("\",\"encryptedMEK\":\"").append(b64.encodeToString(created.header.wrappedMasterKey))
            append("\",\"databaseSize\":").append(vaultFile.size).append(",\"mediaFiles\":[")
            append(media.joinToString(",") {
                "{\"mediaId\":\"${it.id}\",\"dataSize\":${it.data.size},\"thumbSize\":${it.thumb.size}}"
            })
            append("]}")
        }

        fun export(name: String, password: String = vaultPassword): File {
            val out = ByteArrayOutputStream()
            val writer = ExportWriter.begin(out, password)
            writer.writeManifest(manifestJson.toByteArray())
            writer.writeFile(vaultFile.inputStream(), vaultFile.size.toLong())
            for (m in media) {
                writer.writeFile(m.data.inputStream(), m.data.size.toLong())
                writer.writeFile(m.thumb.inputStream(), m.thumb.size.toLong())
            }
            writer.finish()
            return File(directory, name).also { it.writeBytes(out.toByteArray()) }
        }

        val good = export("export.obscura")
        val mediaCase = JsonArray(media.map {
            JsonObject(mapOf(
                "id" to JsonPrimitive(it.id),
                "dataSha256" to JsonPrimitive(sha256(it.data)),
                "thumbSha256" to JsonPrimitive(sha256(it.thumb)),
            ))
        })
        fun exportCase(file: String, expect: String, password: String? = null) = JsonObject(buildMap {
            put("file", JsonPrimitive(file))
            put("kind", JsonPrimitive("export"))
            put("expect", JsonPrimitive(expect))
            put("databaseSha256", JsonPrimitive(sha256(vaultFile)))
            put("media", mediaCase)
            if (password != null) put("password", JsonPrimitive(password))
        })

        val bytes = good.readBytes()
        File(directory, "tampered/export-flipped.obscura").writeBytes(
            bytes.copyOf().also { it[it.size - 30] = (it[it.size - 30].toInt() xor 1).toByte() }
        )
        File(directory, "tampered/export-truncated.obscura").writeBytes(bytes.copyOf(bytes.size - 100))
        return listOf(
            exportCase("export.obscura", "opens"),
            exportCase("export.obscura", "wrongPassword", password = "not the password"),
            exportCase("tampered/export-flipped.obscura", "authenticationFailed"),
            exportCase("tampered/export-truncated.obscura", "invalidExport"),
        )
    }

    private fun refreshChecksum(header: ByteArray) {
        System.arraycopy(bigEndianBytes(crc32(header, 141), 4), 0, header, 141, 4)
    }

    /** Escapes everything outside ASCII, so no tool between the writer and the reader can normalise a password. */
    fun asciiJson(text: String): String = buildString {
        for (c in text) if (c.code < 128) append(c) else append("\\u%04x".format(c.code))
    }
}
