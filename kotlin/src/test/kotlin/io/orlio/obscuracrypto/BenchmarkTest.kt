// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.util.concurrent.Executors
import kotlin.test.Test
import org.junit.jupiter.api.Assumptions.assumeTrue

/**
 * How long a vault login takes: ten 600,000-round derivations, one per slot.
 * Skipped unless OBSCURA_BENCH is set. Printed, not asserted: the pass mark is
 * judged on a real phone, with the same code run from an instrumented test.
 */
class BenchmarkTest : CryptoTestCase() {

    @Test
    fun timeAVaultLogin() {
        assumeTrue(System.getenv("OBSCURA_BENCH") != null)
        val salt = ByteArray(32) { it.toByte() }
        val provider = TestProvider.activeAesProvider()

        val password = "correct horse battery staple".toByteArray()
        for (engine in listOf("MAC", "KOTLIN")) {
            fun oneDerivation() = if (engine == "MAC") Pbkdf2.derive(password, salt, KeyDerivation.VAULT_ITERATIONS)
                else Pbkdf2InKotlin.derive(password, salt, KeyDerivation.VAULT_ITERATIONS)
            oneDerivation() // warm up the JIT
            val single = (1..5).map { time { oneDerivation() } }.sorted()
            println("BENCH provider=$provider engine=$engine one derivation: median ${single[2]} ms, best ${single[0]} ms")

            for (workers in listOf(1, 4)) {
                val pool = Executors.newFixedThreadPool(workers)
                val runs = (1..3).map {
                    time { (1..10).map { pool.submit { oneDerivation() } }.forEach { it.get() } }
                }.sorted()
                pool.shutdown()
                println("BENCH provider=$provider engine=$engine ten slots, $workers worker(s): median ${runs[1]} ms")
            }
        }
    }

    private fun time(block: () -> Unit): Long {
        val start = System.nanoTime()
        block()
        return (System.nanoTime() - start) / 1_000_000
    }
}
