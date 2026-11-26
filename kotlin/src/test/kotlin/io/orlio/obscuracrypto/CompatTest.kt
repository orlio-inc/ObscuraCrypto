// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

/**
 * Reads the cross-language fixture sets, `FromSwift` and `FromKotlin`, and
 * checks every case in each: files that must open open, files that must be
 * refused are refused for the stated reason. See [Compat].
 */
class CompatTest {

    private fun verify(set: String) {
        val directory = File(Fixtures.directory, set)
        assertTrue(File(directory, "compat.json").exists(), "missing $set/compat.json: generate it with the writer")
        val results = Compat.verify(directory)
        assertTrue(results.size >= 20, "only ${results.size} cases in $set")
        val failures = results.filter { !it.ok }
        assertEquals(emptyList(), failures.map { "${it.case}: ${it.detail}" }, "$set: cases that did not behave")
    }

    @Test fun opensEveryFileSwiftWroteAndRefusesItsTamperedOnes() = verify("FromSwift")

    @Test fun opensItsOwnFilesAndRefusesItsOwnTamperedOnes() = verify("FromKotlin")

    /** Rewrites `Fixtures/FromKotlin`. Skipped unless OBSCURA_WRITE_KOTLIN_FIXTURES is set, as the fixtures are committed. */
    @Test
    fun writeKotlinFixtures() {
        assumeTrue(System.getenv("OBSCURA_WRITE_KOTLIN_FIXTURES") != null)
        Compat.write(File(Fixtures.directory, "FromKotlin"), "ObscuraCrypto Kotlin 1.3.0")
    }
}
