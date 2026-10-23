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
}
