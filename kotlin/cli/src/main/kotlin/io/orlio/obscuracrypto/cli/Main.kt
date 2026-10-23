// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto.cli

import io.orlio.obscuracrypto.ChunkedMediaEncryptor
import io.orlio.obscuracrypto.ChunkedMediaHeader
import io.orlio.obscuracrypto.ChunkedMediaReader
import io.orlio.obscuracrypto.ExportArchive
import io.orlio.obscuracrypto.ExportHeader
import io.orlio.obscuracrypto.KeyDerivation
import io.orlio.obscuracrypto.MediaExtraction
import io.orlio.obscuracrypto.MediaFormat
import io.orlio.obscuracrypto.ObscuraCryptoException
import io.orlio.obscuracrypto.SecureBytes
import io.orlio.obscuracrypto.SingleShotMedia
import io.orlio.obscuracrypto.VaultHeader
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.util.UUID
import kotlin.system.exitProcess

internal val usage = """
obscura: create, inspect and decrypt Obscura vault and media files.

VAULT
  obscura vault create <file>         Write a new vault header, prompting for a password
  obscura vault inspect <file>        Show a vault header. Needs no password
  obscura vault unlock <file>         Check a password by unwrapping the master key
  obscura vault passwd <file>         Change the password; nothing else is re-encrypted
  obscura vault extract <file> <out-dir> [--media <dir>]
                                      Decrypt this vault's photos and videos to <out-dir>

MEDIA
  obscura media encrypt <in> <out> --vault <file> [--chunked] [--chunk-size <bytes>] [--folder <file>] [--force]
  obscura media decrypt <in> <out> --vault <file> [--folder <file>] [--force]
  obscura media inspect <file>        Show a media file's format. Needs no password

FOLDER
  obscura folder create <file>        Write folder protection, prompting for a folder password

EXPORT
  obscura export inspect <file.obscura>
                                      Show an export's header. Needs no password
  obscura export extract <file.obscura> <out-dir>
                                      Decrypt an export's photos and videos to <out-dir>

`vault extract` and `export extract` write only photos and videos, never the
vault's database or the export's manifest. Media in a password-protected folder
is not extracted: its second key lives in the vault's database.

OPTIONS
  --password-stdin    Read passwords from standard input, one per line, in the
                      order they are asked for. For scripts and tests.
  --force             Let media encrypt and decrypt replace an existing <out>.
                      Without it they refuse, so a mistyped path cannot
                      overwrite one of your files.

Passwords are never taken as arguments, so they stay out of shell history.
Keys are never printed. `unlock` shows a fingerprint: the first 8 bytes of
SHA-256 over the key, enough to confirm two tools agree and nothing more.
""".trimIndent()

private val valuedOptions = setOf("vault", "folder", "chunk-size", "media")

fun main(args: Array<String>) {
    try {
        Cli(args.toList(), System.`in`.bufferedReader(), System.out).run()
    } catch (e: CliError) {
        System.err.println("obscura: ${e.message}")
        exitProcess(1)
    } catch (e: ObscuraCryptoException) {
        System.err.println("obscura: ${e.message}")
        exitProcess(1)
    } catch (e: java.io.IOException) {
        System.err.println("obscura: ${e.message}")
        exitProcess(1)
    }
}

internal class CliError(message: String) : Exception(message)

/** The parsed command line: positional arguments, `--name value` options and bare `--switch`es. */
internal class Arguments(raw: List<String>, valued: Set<String>) {
    val positionals = mutableListOf<String>()
    private val options = mutableMapOf<String, String>()
    private val switches = mutableSetOf<String>()

    init {
        val iterator = raw.iterator()
        while (iterator.hasNext()) {
            val argument = iterator.next()
            if (!argument.startsWith("--")) {
                positionals.add(argument)
                continue
            }
            val name = argument.removePrefix("--")
            if (name in valued) {
                if (!iterator.hasNext()) throw CliError("--$name needs a value")
                options[name] = iterator.next()
            } else {
                switches.add(name)
            }
        }
    }

    fun positional(index: Int, name: String): String =
        positionals.getOrNull(index) ?: throw CliError("missing <$name>")

    fun option(name: String): String? = options[name]
    fun has(name: String): Boolean = name in switches
}

internal class Cli(private val raw: List<String>, private val stdin: java.io.BufferedReader, private val out: java.io.PrintStream) {

    fun run() {
        if (raw.size < 2) {
            out.println(usage)
            return
        }
        val arguments = Arguments(raw.drop(2), valuedOptions)
        val fromStdin = arguments.has("password-stdin")

        when (raw[0] to raw[1]) {
            "vault" to "create" -> {
                val path = arguments.positional(0, "file")
                if (File(path).exists()) throw CliError("$path already exists")
                val password = readPassword("New vault password: ", fromStdin, confirm = !fromStdin)
                val created = VaultHeader.create(password)
                writeNew(File(path), created.header.serialized())
                fields(
                    "Created" to path,
                    "Master key" to "random, 32 bytes, fingerprint ${created.masterKey.fingerprint}",
                    "Wrapped with" to "PBKDF2-HMAC-SHA256, ${created.header.kdfIterations} rounds, then AES-256-GCM",
                )
            }

            "vault" to "inspect" -> {
                val data = File(arguments.positional(0, "file")).readBytes()
                val header = VaultHeader.parse(data)
                fields(
                    "Format" to "Obscura vault, version 3",
                    "Cipher suite" to "0x%02x, ".format(header.cipherSuite.id) + header.cipherSuite.displayName,
                    "KDF rounds" to "${header.kdfIterations}",
                    "Salt" to hex(header.salt),
                    "Master key" to "wrapped, ${header.wrappedMasterKey.size} bytes (12 nonce + 32 key + 16 tag)",
                    "Checksum" to "CRC-32 matches",
                    "After header" to byteCount((data.size - VaultHeader.SIZE).toLong()) + ", the encrypted database and padding",
                )
            }

            "vault" to "unlock" -> {
                val path = arguments.positional(0, "file")
                val header = VaultHeader.parse(File(path).readBytes())
                val masterKey = header.unlock(readPassword("Vault password: ", fromStdin))
                fields(
                    "Unlocked" to path,
                    "Master key" to "fingerprint ${masterKey.fingerprint}",
                    "Database size" to byteCount(header.databaseSize(masterKey)),
                )
            }

            "vault" to "passwd" -> {
                val file = File(arguments.positional(0, "file"))
                val data = file.readBytes()
                val header = VaultHeader.parse(data)
                val current = readPassword("Current password: ", fromStdin)
                val masterKey = header.unlock(current)
                val replacement = readPassword("New password: ", fromStdin, confirm = !fromStdin)
                val updated = header.changingPassword(current, replacement)
                updated.serialized().copyInto(data)
                replaceAtomically(file, data)
                fields(
                    "Changed" to file.path,
                    "Master key" to "unchanged, fingerprint ${masterKey.fingerprint}",
                    "Rewritten" to "the ${VaultHeader.SIZE}-byte header only, with a new salt",
                )
            }

            "media" to "encrypt" -> {
                val input = File(arguments.positional(0, "in"))
                val output = outputFile(arguments)
                val masterKey = unlockVault(arguments, fromStdin)
                val folderKey = unlockFolder(arguments, fromStdin)
                val folderNote = if (folderKey == null) "" else ", with a folder layer"
                if (arguments.has("chunked")) {
                    val chunkSize = arguments.option("chunk-size")?.let {
                        it.toLongOrNull()?.takeIf { size -> size > 0 }
                            ?: throw CliError("--chunk-size must be a positive number of bytes")
                    } ?: ChunkedMediaHeader.DEFAULT_CHUNK_SIZE
                    val header = ChunkedMediaEncryptor.encrypt(input, output, masterKey, folderKey, chunkSize)
                    out.println("Encrypted ${header.chunkCount} chunks to ${output.path}$folderNote")
                } else {
                    val sealed = SingleShotMedia.encrypt(input.readBytes(), masterKey, folderKey)
                    replaceAtomically(output, sealed)
                    out.println("Encrypted to ${output.path}$folderNote")
                }
            }

            "media" to "decrypt" -> {
                val input = File(arguments.positional(0, "in"))
                val output = outputFile(arguments)
                val masterKey = unlockVault(arguments, fromStdin)
                val folderKey = unlockFolder(arguments, fromStdin)
                when (MediaFormat.detect(readPrefix(input, 4))) {
                    MediaFormat.CHUNKED -> {
                        val reader = ChunkedMediaReader(input)
                        reader.decrypt(output, masterKey, folderKey)
                        out.println("Decrypted ${reader.header.chunkCount} chunks to ${output.path}")
                    }
                    MediaFormat.SINGLE_SHOT -> {
                        replaceAtomically(output, SingleShotMedia.decrypt(input.readBytes(), masterKey, folderKey))
                        out.println("Decrypted to ${output.path}")
                    }
                }
            }

            "media" to "inspect" -> {
                val file = File(arguments.positional(0, "file"))
                val prefix = readPrefix(file, ChunkedMediaHeader.SIZE)
                val size = file.length()
                when (MediaFormat.detect(prefix)) {
                    MediaFormat.CHUNKED -> {
                        val header = ChunkedMediaReader(file).header
                        fields(
                            "Format" to "chunked (OBCM, version 1)",
                            "Plaintext" to byteCount(header.totalPlaintextSize),
                            "Chunks" to "${header.chunkCount} of up to ${header.chunkPlaintextSize} bytes",
                            "Folder layer" to if (header.hasFolderLayer) "yes, 56 bytes of overhead per chunk" else "no, 28 bytes of overhead per chunk",
                            "Nonce prefix" to hex(header.noncePrefix),
                            "File length" to "$size bytes, matches the header",
                        )
                    }
                    MediaFormat.SINGLE_SHOT -> fields(
                        "Format" to "single-shot AES-256-GCM",
                        "Nonce" to hex(prefix.copyOf(minOf(prefix.size, 12))),
                        "Ciphertext" to "${maxOf(size - 28, 0)} bytes, plus a 16-byte tag",
                        "Folder layer" to "cannot be told without the folder key",
                    )
                }
            }

            "folder" to "create" -> {
                val path = arguments.positional(0, "file")
                if (File(path).exists()) throw CliError("$path already exists")
                val password = readPassword("New folder password: ", fromStdin, confirm = !fromStdin)
                val created = io.orlio.obscuracrypto.FolderProtection.create(password)
                writeNew(File(path), FolderFile.encode(created.protection).toByteArray())
                fields(
                    "Created" to path,
                    "Folder key" to "random, 32 bytes, fingerprint ${created.folderKey.fingerprint}",
                    "Wrapped with" to "PBKDF2-HMAC-SHA256, ${KeyDerivation.FOLDER_ITERATIONS} rounds, then AES-256-GCM",
                )
            }

            "vault" to "extract" -> {
                val vault = File(arguments.positional(0, "file"))
                val outDir = outputDirectory(arguments)
                val pool = mediaPool(arguments, vault) ?: throw CliError("no media folder found; give one with --media <dir>")
                val header = VaultHeader.parse(readPrefix(vault, VaultHeader.SIZE))
                val masterKey = header.unlock(readPassword("Vault password: ", fromStdin))
                // The media pool is shared by every vault, and nothing in a file's name
                // says which vault it belongs to. The key does. Thumbnails are tried
                // first, being small.
                val ids = mediaIds(pool).sorted()
                var extracted = 0
                for (id in ids) {
                    if (!opens(id, pool, masterKey)) continue
                    val outcome = MediaExtraction.extract(File(pool, "$id.data.enc"), id, masterKey, directory = outDir)
                    if (outcome is MediaExtraction.Outcome.Extracted) extracted += 1
                }
                fields(
                    "Extracted" to "$extracted photos and videos to ${outDir.path}",
                    "Not extracted" to "${ids.size - extracted} files that this vault's key does not open: " +
                        "other vaults' files, and this vault's files in password-protected folders",
                )
            }

            "export" to "inspect" -> {
                val file = File(arguments.positional(0, "file"))
                val header = ExportHeader.parse(readPrefix(file, ExportHeader.SIZE))
                fields(
                    "Format" to "Obscura export, version ${header.version}",
                    "Key" to "PBKDF2-HMAC-SHA256, ${header.kdfIterations} rounds, then AES-256-GCM",
                    "Salt" to hex(header.salt),
                    "Nonce prefix" to hex(header.noncePrefix),
                    "Encrypted" to byteCount(file.length() - ExportHeader.SIZE) + " after the 64-byte header",
                )
            }

            "export" to "extract" -> exportExtract(arguments, fromStdin)

            else -> throw CliError("unknown command \"${raw[0]} ${raw[1]}\"; run obscura with no arguments for help")
        }
    }

    private fun exportExtract(arguments: Arguments, fromStdin: Boolean) {
        val file = File(arguments.positional(0, "file.obscura"))
        val outDir = outputDirectory(arguments)
        val password = readPassword("Export password: ", fromStdin)
        ExportArchive.open(file, password).use { archive ->
            // The app exports with the vault's own password, which also unwraps the
            // master key; ask separately only if it does not.
            val masterKey = try {
                archive.index.unlockMasterKey(password)
            } catch (e: ObscuraCryptoException.WrongPassword) {
                archive.index.unlockMasterKey(readPassword("Vault password: ", fromStdin))
            }

            archive.skipDatabase()
            var extracted = 0
            var layered = 0
            // Each stored file is staged in a folder made fresh for this run, owner-only,
            // so a name someone planted in out-dir (a link, say) is never written through.
            val staging = Files.createTempDirectory(
                outDir.toPath(), ".obscura-staging-",
                java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                    java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"),
                ),
            ).toFile()
            try {
                for (media in archive.index.mediaFiles) {
                    val stored = File(staging, "${media.id}.stored")
                    try {
                        archive.copyStoredFile(media.dataSize, stored)
                        archive.copyStoredFile(media.thumbnailSize, null as File?)
                        if (media.dataSize <= 0) continue
                        when (MediaExtraction.extract(stored, media.id, masterKey, directory = outDir)) {
                            is MediaExtraction.Outcome.Extracted -> extracted += 1
                            MediaExtraction.Outcome.NotOpenedByMasterKey -> layered += 1
                        }
                    } finally {
                        stored.delete()
                    }
                }
            } finally {
                staging.deleteRecursively()
            }
            if (!archive.isAtEnd()) {
                throw CliError("the export has data after its last media file; it may have been altered")
            }
            fields(
                "Extracted" to "$extracted photos and videos to ${outDir.path}",
                "Not extracted" to "$layered in password-protected folders",
            )
        }
    }

    // MARK: Helpers

    private fun fields(vararg rows: Pair<String, String>) {
        val width = rows.maxOf { it.first.length }
        for ((label, value) in rows) out.println(label.padEnd(width) + "  " + value)
    }

    /**
     * Passwords come from `--password-stdin` when scripting, and otherwise from
     * the terminal with echo off. Never from an argument, which would leave
     * them in shell history and in the process list.
     */
    private fun readPassword(prompt: String, fromStdin: Boolean, confirm: Boolean = false): String {
        if (fromStdin) {
            val line = stdin.readLine()
            if (line.isNullOrEmpty()) throw CliError("expected a password on standard input")
            return line
        }
        val console = System.console() ?: throw CliError("could not read a password from the terminal; use --password-stdin")
        fun prompted(text: String): String {
            val chars = console.readPassword(text) ?: throw CliError("could not read a password from the terminal; use --password-stdin")
            try {
                if (chars.isEmpty()) throw CliError("empty password")
                return String(chars)
            } finally {
                chars.fill('\u0000')
            }
        }
        val password = prompted(prompt)
        if (confirm && prompted("Repeat to confirm: ") != password) throw CliError("the passwords do not match")
        return password
    }

    private fun unlockVault(arguments: Arguments, fromStdin: Boolean): SecureBytes {
        val path = arguments.option("vault") ?: throw CliError("--vault <file> is required")
        val header = VaultHeader.parse(File(path).readBytes())
        return header.unlock(readPassword("Vault password: ", fromStdin))
    }

    private fun unlockFolder(arguments: Arguments, fromStdin: Boolean): SecureBytes? {
        val path = arguments.option("folder") ?: return null
        val protection = FolderFile.decode(File(path).readText())
        return protection.unlock(readPassword("Folder password: ", fromStdin))
    }

    /** `<out>`, refused if something is already there unless `--force` was given. Checked before any password is asked for. */
    private fun outputFile(arguments: Arguments): File {
        val path = arguments.positional(1, "out")
        if (File(path).exists() && !arguments.has("force")) throw CliError("$path already exists; use --force to replace it")
        return File(path)
    }

    private fun outputDirectory(arguments: Arguments): File {
        val dir = File(arguments.positional(1, "out-dir"))
        Files.createDirectories(dir.toPath())
        return dir
    }

    /** `--media`, or the `media` folder beside the vault's `data` folder, as the app lays them out. */
    private fun mediaPool(arguments: Arguments, vault: File): File? {
        val candidate = arguments.option("media")?.let(::File)
            ?: File(vault.absoluteFile.parentFile.parentFile, "media")
        return candidate.takeIf { it.isDirectory }
    }

    private fun mediaIds(pool: File): List<String> = pool.list().orEmpty().mapNotNull { name ->
        if (!name.endsWith(".data.enc")) return@mapNotNull null
        val id = name.removeSuffix(".data.enc")
        id.takeIf { it.length == 36 && runCatching { UUID.fromString(it) }.isSuccess }
    }

    /** Whether [masterKey] opens a stored file, trying its thumbnail first. */
    private fun opens(id: String, pool: File, masterKey: SecureBytes): Boolean {
        val thumb = File(pool, "$id.thumb.enc")
        return MediaExtraction.masterKeyOpens(if (thumb.exists()) thumb else File(pool, "$id.data.enc"), masterKey)
    }

    private fun readPrefix(file: File, count: Int): ByteArray = RandomAccessFile(file, "r").use {
        val buffer = ByteArray(count)
        var total = 0
        while (total < count) {
            val read = it.read(buffer, total, count - total)
            if (read < 0) break
            total += read
        }
        buffer.copyOf(total)
    }

    private fun writeNew(file: File, bytes: ByteArray) {
        Files.write(file.toPath(), bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
    }

    private fun replaceAtomically(file: File, bytes: ByteArray) {
        val temporary = File(file.absoluteFile.parentFile, ".${file.name}.${UUID.randomUUID()}.partial")
        try {
            Files.write(temporary.toPath(), bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
            Files.move(temporary.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } finally {
            temporary.delete()
        }
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    /** Like Apple's file style: powers of 1000, one decimal from 10 up, none below. */
    private fun byteCount(bytes: Long): String {
        if (bytes < 1_000) return "$bytes bytes"
        val units = listOf("KB", "MB", "GB", "TB")
        var value = bytes / 1000.0
        var unit = 0
        while (value >= 1000 && unit < units.lastIndex) {
            value /= 1000
            unit += 1
        }
        val text = if (value < 10 && unit > 0) "%.1f".format(java.util.Locale.ROOT, value) else "%.0f".format(java.util.Locale.ROOT, value)
        return "$text ${units[unit]} ($bytes bytes)"
    }
}
