// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto.cli

import io.orlio.obscuracrypto.FolderProtection
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Folder protection as JSON with the same three base64 fields the app keeps
 * in its database for a protected folder, and the same file the Swift tool writes.
 */
internal object FolderFile {
    private val pretty = Json { prettyPrint = true }

    fun encode(protection: FolderProtection): String {
        val encoder = Base64.getEncoder()
        // Keys sorted, as the Swift tool writes them.
        return pretty.encodeToString(
            JsonObject.serializer(),
            JsonObject(
                sortedMapOf(
                    "folderKeyEncrypted" to JsonPrimitive(encoder.encodeToString(protection.wrappedFolderKey)),
                    "passwordHash" to JsonPrimitive(encoder.encodeToString(protection.passwordHash)),
                    "passwordSalt" to JsonPrimitive(encoder.encodeToString(protection.salt)),
                ),
            ),
        ) + "\n"
    }

    fun decode(text: String): FolderProtection {
        val root = try {
            Json.parseToJsonElement(text).jsonObject
        } catch (e: Exception) {
            throw CliError("not a folder file: ${e.message}")
        }
        fun field(name: String): ByteArray {
            val value = root[name]?.jsonPrimitive?.contentOrNull ?: throw CliError("folder file has no $name")
            return try {
                Base64.getDecoder().decode(value)
            } catch (e: IllegalArgumentException) {
                throw CliError("folder file fields are not valid base64")
            }
        }
        return FolderProtection(field("passwordSalt"), field("passwordHash"), field("folderKeyEncrypted"))
    }
}
