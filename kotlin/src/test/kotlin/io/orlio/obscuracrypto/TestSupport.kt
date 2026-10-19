// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.io.File
import java.nio.file.Files
import java.security.Security
import java.util.Comparator
import javax.crypto.Cipher
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.conscrypt.Conscrypt
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach

/**
 * The suite runs once under the JDK's own crypto providers and once with
 * Conscrypt, the BoringSSL-based provider Android ships, ahead of them. The
 * provider is chosen by the Gradle task through a system property.
 */
object TestProvider {
    val name: String = System.getProperty("obscura.provider", "jdk")

    init {
        if (name == "conscrypt") Security.insertProviderAt(Conscrypt.newProvider(), 1)
    }

    /** The provider JCA actually hands out for AES-GCM, so a mis-wired run cannot pass quietly. */
    fun activeAesProvider(): String = Cipher.getInstance("AES/GCM/NoPadding").provider.name
}

abstract class CryptoTestCase {
    protected lateinit var directory: File

    @BeforeEach
    fun setUpDirectory() {
        TestProvider.name
        directory = Files.createTempDirectory("obscura-test").toFile()
    }

    @AfterEach
    fun tearDownDirectory() {
        directory.walkBottomUp().forEach { it.delete() }
    }

    protected fun file(name: String, data: ByteArray): File = File(directory, name).also { it.writeBytes(data) }

    protected fun randomBytes(count: Int): ByteArray = ByteArray(count).also { Random.generator.nextBytes(it) }

    protected fun randomKey(): SecureBytes = SecureBytes.random(32)

    protected inline fun <reified E : ObscuraCryptoException> assertRefused(block: () -> Unit): E =
        assertFailsWith<E> { block() }
}

object Fixtures {
    val directory: File = File(
        System.getProperty("obscura.fixtures") ?: error("obscura.fixtures is not set; run the tests through Gradle")
    )

    fun file(path: String): File = File(directory, path).also {
        require(it.exists()) { "missing fixture $path" }
    }

    /** The app's plaintext generator, so the fixtures need not carry plaintext. */
    fun plaintext(count: Int, seed: Int): ByteArray = ByteArray(count) { ((it * 31 + seed) % 251).toByte() }

    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}

fun assertBytesEqual(expected: ByteArray, actual: ByteArray, message: String? = null) {
    assertEquals(expected.size, actual.size, message ?: "length")
    assertEquals(Fixtures.hex(expected), Fixtures.hex(actual), message ?: "content")
}
