// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.io.File
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/**
 * Reads files the Obscura iOS app itself wrote, through the same calls it makes
 * to create a vault, save media and set a folder password. These are the
 * fixtures the Swift package's own `AppCompatibilityTests` reads: this is the
 * Kotlin library opening what the iPhone writes. See `Fixtures/manifest.json`.
 */
class AppCompatibilityTest : CryptoTestCase() {

    private val manifest: JsonObject =
        Json.parseToJsonElement(Fixtures.file("manifest.json").readText()).jsonObject

    private fun string(key: String) = manifest.getValue(key).jsonPrimitive.content

    private val vaultPassword get() = string("vaultPassword")
    private val folderPassword get() = string("folderPassword")
    private val photoCount get() = manifest.getValue("photo").jsonObject.getValue("count").jsonPrimitive.int
    private val photoSeed get() = manifest.getValue("photo").jsonObject.getValue("seed").jsonPrimitive.int
    private val video get() = manifest.getValue("video").jsonObject

    private fun masterKey(): SecureBytes =
        VaultHeader.parse(Fixtures.file("vault.header").readBytes()).unlock(vaultPassword)

    private fun folderKey(): SecureBytes {
        val folder = manifest.getValue("folder").jsonObject
        fun b64(key: String) = Base64.getDecoder().decode(folder.getValue(key).jsonPrimitive.content)
        return FolderProtection(b64("passwordSalt"), b64("passwordHash"), b64("folderKeyEncrypted")).unlock(folderPassword)
    }

    @Test
    fun unlocksTheAppsVaultHeader() {
        val key = masterKey()
        assertEquals(string("masterKeyFingerprint"), key.fingerprint)
        val header = VaultHeader.parse(Fixtures.file("vault.header").readBytes())
        assertEquals(manifest.getValue("databaseSize").jsonPrimitive.long, header.databaseSize(key))
    }

    /** Byte for byte, so nothing the app puts in a header is lost or reordered. */
    @Test
    fun rewritesTheAppsHeaderIdentically() {
        val original = Fixtures.file("vault.header").readBytes()
        assertContentEquals(original, VaultHeader.parse(original).serialized())
    }

    @Test
    fun unlocksTheAppsFolderKey() {
        assertEquals(string("folderKeyFingerprint"), folderKey().fingerprint)
    }

    @Test
    fun decryptsTheAppsSingleShotPhoto() {
        val sealed = Fixtures.file("photo.data.enc").readBytes()
        assertContentEquals(Fixtures.plaintext(photoCount, photoSeed), SingleShotMedia.decrypt(sealed, masterKey()))
    }

    @Test
    fun decryptsTheAppsFolderProtectedPhoto() {
        val sealed = Fixtures.file("photo-folder.data.enc").readBytes()
        assertContentEquals(
            Fixtures.plaintext(photoCount, photoSeed),
            SingleShotMedia.decrypt(sealed, masterKey(), folderKey()),
        )
    }

    @Test
    fun decryptsTheAppsChunkedVideo() = assertChunked("video.data.enc", withFolder = false)

    /** Also shows the app writes the nonces the format specifies, since the reader checks every one. */
    @Test
    fun decryptsTheAppsFolderProtectedChunkedVideo() = assertChunked("video-folder.data.enc", withFolder = true)

    private fun assertChunked(name: String, withFolder: Boolean) {
        val reader = ChunkedMediaReader(Fixtures.file(name))
        assertEquals(video.getValue("chunkSize").jsonPrimitive.long, reader.header.chunkPlaintextSize)
        assertEquals(withFolder, reader.header.hasFolderLayer)

        val output = File(directory, "out.bin")
        reader.decrypt(output, masterKey(), if (withFolder) folderKey() else null)
        val expected = Fixtures.plaintext(
            video.getValue("count").jsonPrimitive.int, video.getValue("seed").jsonPrimitive.int,
        )
        assertContentEquals(expected, output.readBytes())
    }
}
