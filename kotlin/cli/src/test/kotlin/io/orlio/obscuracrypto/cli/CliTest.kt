// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto.cli

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CliTest {
    private val fixtures = File(System.getProperty("obscura.fixtures"))
    private val vault = File(fixtures, "vault/data/068E6368-A18E-45FD-96EB-95E9251F848A.db.enc")
    private val password = "correct horse battery staple"

    private fun run(stdin: String, vararg args: String): String {
        val out = ByteArrayOutputStream()
        Cli(args.toList(), stdin.reader().buffered(), PrintStream(out)).run()
        return out.toString()
    }

    @Test
    fun noArgumentsPrintTheUsage() {
        assertContains(run(""), "obscura: create, inspect and decrypt")
    }

    @Test
    fun unlockShowsAFingerprintAndNeverTheKey() {
        val output = run("$password\n", "vault", "unlock", vault.path, "--password-stdin")
        assertContains(output, "fingerprint 255909a13b5c6082")
    }

    @Test
    fun aWrongPasswordIsRefused() {
        assertFailsWith<io.orlio.obscuracrypto.ObscuraCryptoException.WrongPassword> {
            run("not it\n", "vault", "unlock", vault.path, "--password-stdin")
        }
    }

    @Test
    fun anUnknownCommandIsRefused() {
        assertFailsWith<CliError> { run("", "vault", "explode") }
    }

    @Test
    fun mediaDecryptRefusesToOverwriteWithoutForce() {
        val target = File.createTempFile("obscura", ".out")
        try {
            assertFailsWith<CliError> {
                run("$password\n", "media", "decrypt", File(fixtures, "photo.data.enc").path, target.path, "--vault", vault.path, "--password-stdin")
            }
            assertTrue(target.length() == 0L)
        } finally {
            target.delete()
        }
    }

    private fun scratch(body: (File) -> Unit) {
        val directory = java.nio.file.Files.createTempDirectory("obscura-cli").toFile()
        try {
            body(directory)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun sharedItemsGoThroughEncryptVerifyAndDecrypt() = scratch { directory ->
        val still = File(directory, "IMG_0001.HEIC").also { it.writeBytes(ByteArray(3_000) { n -> (n * 7).toByte() }) }
        val motion = File(directory, "IMG_0001.MOV").also { it.writeBytes(ByteArray(5_000) { n -> (n * 3).toByte() }) }
        val photo = File(directory, "beach.jpg").also { it.writeBytes(byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte()) + ByteArray(900) { 4 }) }
        val pdf = File(directory, "Lease.pdf").also { it.writeBytes("%PDF-1.4 a lease".toByteArray()) }
        val sealed = File(directory, "out.obscurashared")
        val created = run("shared pass\n", "shared", "encrypt", sealed.path, still.path, motion.path, photo.path, pdf.path,
            "--live-photos", "--password-stdin")
        assertContains(created, "3: 1 photo, 1 Live Photo, 1 document")
        assertContains(created, "600000 rounds")

        val verified = run("shared pass\n", "shared", "verify", sealed.path, "--password-stdin")
        assertContains(verified, "every record intact and in order")
        assertFailsWith<io.orlio.obscuracrypto.ObscuraCryptoException.WrongPassword> {
            run("not it at all\n", "shared", "verify", sealed.path, "--password-stdin")
        }

        val out = File(directory, "out")
        val decrypted = run("shared pass\n", "shared", "decrypt", sealed.path, out.path, "--password-stdin")
        assertContains(decrypted, "3-document.pdf is \"Lease\"")
        assertTrue(File(out, "1-live-photo.heic").readBytes().contentEquals(still.readBytes()))
        assertTrue(File(out, "1-live-photo.mov").readBytes().contentEquals(motion.readBytes()))
        assertTrue(File(out, "2-photo.jpg").readBytes().contentEquals(photo.readBytes()))
        assertTrue(File(out, "3-document.pdf").readBytes().contentEquals(pdf.readBytes()))
        assertTrue(
            java.nio.file.Files.getPosixFilePermissions(File(out, "2-photo.jpg").toPath()) ==
                java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"),
        )
        assertTrue(out.list().orEmpty().none { it.startsWith(".") }, "no staging folder is left")

        // Decrypting again into the same folder takes no name that is there.
        assertFailsWith<CliError> { run("shared pass\n", "shared", "decrypt", sealed.path, out.path, "--password-stdin") }
        assertTrue(out.list().orEmpty().none { it.startsWith(".") })
    }

    @Test
    fun anOpenSharedFileAsksForNoPassword() = scratch { directory ->
        val photo = File(directory, "a.png").also { it.writeBytes(ByteArray(100) { 1 }) }
        val sealed = File(directory, "open.obscurashared")
        assertContains(run("", "shared", "encrypt", sealed.path, photo.path, "--open"), "anyone who has the file can open it")
        val verified = run("", "shared", "verify", sealed.path)
        assertContains(verified, "1: 1 photo")
        assertContains(verified, "sent without a password")
    }

    /** A script that gives a password is refused a file sent without one: someone may have swapped it on the way. */
    @Test
    fun anOpenSharedFileIsRefusedWhenAPasswordIsGiven() = scratch { directory ->
        val photo = File(directory, "a.png").also { it.writeBytes(ByteArray(100) { 1 }) }
        val sealed = File(directory, "open.obscurashared")
        run("", "shared", "encrypt", sealed.path, photo.path, "--open")
        assertFailsWith<io.orlio.obscuracrypto.ObscuraCryptoException.SharedItemsNotLocked> {
            run("the password\n", "shared", "verify", sealed.path, "--password-stdin")
        }
    }

    @Test
    fun sharedEncryptRefusesWhatTheAppCannotAddAndShortPasswords() = scratch { directory ->
        val text = File(directory, "notes.txt").also { it.writeText("hello") }
        val photo = File(directory, "a.jpg").also { it.writeBytes(ByteArray(100) { 1 }) }
        val sealed = File(directory, "out.obscurashared")
        assertFailsWith<CliError> { run("long enough\n", "shared", "encrypt", sealed.path, text.path, "--password-stdin") }
        assertFailsWith<CliError> { run("short\n", "shared", "encrypt", sealed.path, photo.path, "--password-stdin") }
        assertTrue(!sealed.exists())
    }

    @Test
    fun verifiesASharedFileTheSwiftLibraryWrote() {
        val output = run("swift shared pass\n", "shared", "verify", File(fixtures, "FromSwift/shared-password.obscurashared").path, "--password-stdin")
        assertContains(output, "5: 1 photo, 1 GIF, 1 video, 1 Live Photo, 1 document")
    }

    @Test
    fun sharedEncryptCanMakeThePassword() = scratch { directory ->
        val photo = File(directory, "a.jpg").also { it.writeBytes(ByteArray(100) { 1 }) }
        val sealed = File(directory, "out.obscurashared")
        val output = run("", "shared", "encrypt", sealed.path, photo.path, "--generate-password")
        val password = Regex("Password +([a-z]+(-[a-z]+){5})(?![a-z-])").find(output)!!.groupValues[1]
        assertContains(run("$password\n", "shared", "verify", sealed.path, "--password-stdin"), "1: 1 photo")
        assertFailsWith<CliError> { run("", "shared", "encrypt", File(directory, "x.obscurashared").path, photo.path, "--generate-password", "--open") }
    }

    /** Said, not refused: the file is made under the password chosen. */
    @Test
    fun sharedEncryptWarnsAboutAnEasyPassword() = scratch { directory ->
        val photo = File(directory, "a.jpg").also { it.writeBytes(ByteArray(100) { 1 }) }
        val sealed = File(directory, "out.obscurashared")
        val output = run("Password123!\n", "shared", "encrypt", sealed.path, photo.path, "--password-stdin")
        assertContains(output, "this password is easy to guess")
        assertContains(run("Password123!\n", "shared", "verify", sealed.path, "--password-stdin"), "1: 1 photo")
    }

    @Test
    fun decryptedSingleShotMediaIsReadableByItsOwnerOnly() {
        val directory = java.nio.file.Files.createTempDirectory("obscura-cli").toFile()
        try {
            val newVault = File(directory, "v.vault")
            val plain = File(directory, "photo.bin").also { it.writeBytes(ByteArray(300) { n -> n.toByte() }) }
            val sealed = File(directory, "photo.enc")
            val target = File(directory, "photo.out")
            run("$password\n", "vault", "create", newVault.path, "--password-stdin")
            run("$password\n", "media", "encrypt", plain.path, sealed.path, "--vault", newVault.path, "--password-stdin")
            run("$password\n", "media", "decrypt", sealed.path, target.path, "--vault", newVault.path, "--password-stdin")
            assertTrue(target.readBytes().contentEquals(plain.readBytes()))
            assertTrue(
                java.nio.file.Files.getPosixFilePermissions(target.toPath()) ==
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"),
            )
        } finally {
            directory.deleteRecursively()
        }
    }
}
