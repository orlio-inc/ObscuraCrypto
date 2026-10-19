// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class VaultTest : CryptoTestCase() {

    @Test
    fun createThenUnlock() {
        val (header, masterKey) = VaultHeader.create("secret password", databaseSize = 42).let { it.header to it.masterKey }
        val reread = VaultHeader.parse(header.serialized())
        assertEquals(header, reread)
        assertTrue(reread.unlock("secret password").contentEquals(masterKey))
        assertEquals(42L, reread.databaseSize(masterKey))
    }

    @Test
    fun layoutIsExactly145BytesWithFieldsWhereTheSpecSays() {
        val header = VaultHeader.create("secret password").header
        val bytes = header.serialized()
        assertEquals(145, bytes.size)
        assertEquals(0x03.toByte(), bytes[0])
        assertContentEquals("OBSCURA".toByteArray(), bytes.copyOfRange(1, 8))
        assertEquals(0x01.toByte(), bytes[8])
        assertEquals(600_000L, bytes.bigEndianUInt32(9))
        assertContentEquals(header.salt, bytes.copyOfRange(13, 45))
        assertContentEquals(header.wrappedMasterKey, bytes.copyOfRange(45, 105))
        assertContentEquals(header.encryptedDatabaseSize, bytes.copyOfRange(105, 141))
    }

    /** The one little-endian number in the header; every other is big-endian. */
    @Test
    fun theDatabaseLengthIsSealedLittleEndian() {
        val key = randomKey()
        val sealed = VaultHeader.encryptDatabaseSize(0x0102030405060708L, key)
        val plaintext = AesGcm.open(sealed, key)
        assertContentEquals(byteArrayOf(8, 7, 6, 5, 4, 3, 2, 1), plaintext)
        assertEquals(0x0102030405060708L, VaultHeader.decryptDatabaseSize(sealed, key))
    }

    @Test
    fun wrongPasswordIsRejected() {
        val header = VaultHeader.create("secret password").header
        assertRefused<ObscuraCryptoException.WrongPassword> { header.unlock("secret passworD") }
    }

    @Test
    fun damagedHeaderFailsItsChecksum() {
        val bytes = VaultHeader.create("secret password").header.serialized()
        bytes[20] = (bytes[20].toInt() xor 0xFF).toByte()
        assertRefused<ObscuraCryptoException.VaultHeaderChecksumMismatch> { VaultHeader.parse(bytes) }
    }

    @Test
    fun shortOrForeignDataIsRefused() {
        assertRefused<ObscuraCryptoException.InvalidVaultHeader> { VaultHeader.parse(ByteArray(144)) }
        val bytes = VaultHeader.create("secret password").header.serialized()
        bytes[0] = 0x02
        assertRefused<ObscuraCryptoException.InvalidVaultHeader> { VaultHeader.parse(bytes) }
    }

    /** A header rewritten to ask for fewer rounds, checksum and all, must not make a password cheaper to try. */
    @Test
    fun loweredIterationCountIsRefused() {
        val header = VaultHeader.create("secret password").header
        val weakened = VaultHeader(
            kdfIterations = 1_000, salt = header.salt,
            wrappedMasterKey = header.wrappedMasterKey, encryptedDatabaseSize = header.encryptedDatabaseSize,
        )
        val reread = VaultHeader.parse(weakened.serialized())
        val error = assertRefused<ObscuraCryptoException.IterationsBelowMinimum> { reread.unlock("secret password") }
        assertEquals(1_000L, error.rounds)
    }

    @Test
    fun implausiblyManyRoundsAreRefused() {
        val header = VaultHeader.create("secret password").header
        val hostile = VaultHeader(
            kdfIterations = 4_000_000_000L, salt = header.salt,
            wrappedMasterKey = header.wrappedMasterKey, encryptedDatabaseSize = header.encryptedDatabaseSize,
        )
        assertRefused<ObscuraCryptoException.InvalidVaultHeader> { VaultHeader.parse(hostile.serialized()).unlock("x") }
    }

    @Test
    fun unknownCipherSuiteIsRefused() {
        val bytes = VaultHeader.create("secret password").header.serialized()
        bytes[8] = 0x02
        val crc = bigEndianBytes(crc32(bytes, 141), 4)
        System.arraycopy(crc, 0, bytes, 141, 4)
        val error = assertRefused<ObscuraCryptoException.UnsupportedCipherSuite> { VaultHeader.parse(bytes) }
        assertEquals(2, error.id)
    }

    /** The point of the key hierarchy: a new password, a new salt, the same master key, so nothing encrypted needs touching. */
    @Test
    fun changingPasswordKeepsTheMasterKey() {
        val created = VaultHeader.create("old password")
        val changed = created.header.changingPassword("old password", "new password")
        assertTrue(!changed.salt.contentEquals(created.header.salt))
        assertTrue(changed.unlock("new password").contentEquals(created.masterKey))
        assertFailsWith<ObscuraCryptoException.WrongPassword> { changed.unlock("old password") }
    }

    @Test
    fun settingTheDatabaseSizeKeepsTheRestOfTheHeader() {
        val created = VaultHeader.create("secret password", databaseSize = 1)
        val resized = created.header.settingDatabaseSize(99, created.masterKey)
        assertEquals(99L, resized.databaseSize(created.masterKey))
        assertContentEquals(created.header.salt, resized.salt)
        assertNotEquals(created.header, resized)
    }

    @Test
    fun folderProtection() {
        val created = FolderProtection.create("folder pass")
        assertTrue(created.protection.unlock("folder pass").contentEquals(created.folderKey))
        assertRefused<ObscuraCryptoException.WrongPassword> { created.protection.unlock("folder pasS") }
    }

    @Test
    fun folderProtectionRefusesWronglySizedFields() {
        assertRefused<ObscuraCryptoException.InvalidFolderProtection> {
            FolderProtection(ByteArray(31), ByteArray(32), ByteArray(60))
        }
        assertRefused<ObscuraCryptoException.InvalidFolderProtection> {
            FolderProtection(ByteArray(32), ByteArray(31), ByteArray(60))
        }
        assertRefused<ObscuraCryptoException.InvalidFolderProtection> {
            FolderProtection(ByteArray(32), ByteArray(32), ByteArray(59))
        }
    }
}
