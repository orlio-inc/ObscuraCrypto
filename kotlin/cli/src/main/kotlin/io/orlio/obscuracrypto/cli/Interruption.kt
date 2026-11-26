// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto.cli

import java.io.File
import java.io.IOException
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions

/**
 * What a command leaves while it works, removed if it is stopped part way with Control-C or a kill: the JVM runs no `finally` when a
 * signal ends it, only shutdown hooks, so without this a decrypted file could stay behind in a hidden staging folder or `.partial` file.
 *
 * Only what this run made is removed: the staging folders it created, by their exact paths and without following any link inside them,
 * and new `.partial` files that are plain files, never a folder or a link someone else put in the output folder. Once a signal has come,
 * the run makes no new file ([checkpoint]), and the folder is swept more than once, for a file that was being created as the signal came.
 */
internal object Interruption {
    private val lock = Any()

    @Volatile
    private var stopping = false
    private val staging = HashSet<Path>()
    private val folders = HashMap<File, Set<String>>()

    init {
        Runtime.getRuntime().addShutdownHook(Thread(::stop))
    }

    /**
     * Runs [body], which writes into [folder]. If the process is stopped before it returns, `.partial` files that appeared there meanwhile
     * are removed; ones that were there before are left alone.
     */
    fun <R> cleaningUp(folder: File, body: () -> R): R {
        val before = partials(folder).toSet()
        synchronized(lock) { folders[folder] = before }
        try {
            return body()
        } finally {
            synchronized(lock) { folders.remove(folder) }
        }
    }

    /** A new staging folder in [folder], owner only, removed if the run is stopped before [removeStaging]. */
    fun makeStaging(folder: File): File {
        val path = Files.createTempDirectory(
            folder.toPath(), ".obscura-staging-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
        )
        synchronized(lock) { staging.add(path) }
        return path.toFile()
    }

    fun removeStaging(dir: File) {
        deleteTree(dir.toPath())
        synchronized(lock) { staging.remove(dir.toPath()) }
    }

    /** Called before each file a run creates: once a signal has come, the run waits here to be ended rather than make another. */
    fun checkpoint() {
        while (stopping) Thread.sleep(1_000)
    }

    private fun stop() {
        stopping = true
        repeat(3) {
            removeLeftovers()
            Thread.sleep(100)
        }
        removeLeftovers()
    }

    private fun partials(folder: File): List<String> =
        (folder.list() ?: emptyArray()).filter { it.startsWith(".") && it.endsWith(".partial") }

    private fun removeLeftovers() {
        val (made, watched) = synchronized(lock) { staging.toList() to HashMap(folders) }
        made.forEach(::deleteTree)
        for ((folder, before) in watched) {
            for (name in partials(folder)) {
                if (name in before) continue
                val path = File(folder, name).toPath()
                if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) runCatching { Files.deleteIfExists(path) }
            }
        }
    }

    /** Deletes [root] and what is in it, a link as the link itself, never what it points to. */
    fun deleteTree(root: Path) {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
        runCatching {
            Files.walkFileTree(root, object : SimpleFileVisitor<Path>() {
                override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                    runCatching { Files.deleteIfExists(file) }
                    return FileVisitResult.CONTINUE
                }

                override fun visitFileFailed(file: Path, exc: IOException): FileVisitResult = FileVisitResult.CONTINUE

                override fun postVisitDirectory(dir: Path, exc: IOException?): FileVisitResult {
                    runCatching { Files.deleteIfExists(dir) }
                    return FileVisitResult.CONTINUE
                }
            })
        }
    }

    /**
     * Refuses a folder others can change: decrypted files are staged and moved there, and whoever can rename or replace its entries could
     * send them elsewhere or have the cleanup remove what they put there. A folder only its owner can write to is fine, and so is one with
     * the sticky bit (such as /tmp) owned by its user or by root. Skipped where the file system does not report Unix modes.
     */
    fun requirePrivateFolder(folder: File) {
        val path = folder.toPath()
        val mode = runCatching { Files.getAttribute(path, "unix:mode") as Int }.getOrNull() ?: return
        val owner = Files.getOwner(path).name
        val sticky = mode and 0x200 != 0
        val othersWrite = mode and (0x10 or 0x2) != 0
        val mine = owner == System.getProperty("user.name")
        if (!((!othersWrite || sticky) && (mine || (owner == "root" && sticky)))) {
            throw CliError("${folder.path} can be changed by other users; use a folder only you can write to")
        }
    }
}
