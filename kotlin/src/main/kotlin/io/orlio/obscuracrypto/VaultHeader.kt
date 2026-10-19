// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

/** The cipher suite a vault header declares. */
enum class CipherSuite(val id: Int) {
    /** PBKDF2-HMAC-SHA256 for the password, AES-256-GCM for everything else. */
    PBKDF2_SHA256_AES256GCM(0x01);

    val displayName: String
        get() = when (this) {
            PBKDF2_SHA256_AES256GCM -> "PBKDF2-HMAC-SHA256 + AES-256-GCM"
        }

    companion object {
        fun fromId(id: Int): CipherSuite? = entries.firstOrNull { it.id == id }
    }
}

/**
 * The 145-byte header at the start of every vault file.
 *
 * It carries everything needed to go from a password to the vault's master
 * key, and nothing else. The vault's contents follow it: a SQLCipher
 * database encrypted with the master key, then random padding.
 *
 * ```
 * offset  size  field
 *      0     1  version, 0x03
 *      1     7  magic, "OBSCURA"
 *      8     1  cipher suite, 0x01
 *      9     4  key derivation rounds, big-endian UInt32
 *     13    32  salt for the password
 *     45    60  master key wrapped with the password key (AES-GCM combined)
 *    105    36  database length, encrypted with the master key (AES-GCM combined)
 *    141     4  CRC-32 of bytes 0..<141, big-endian
 * ```
 *
 * The key hierarchy is password, then key encryption key (PBKDF2), then master
 * key (unwrapped with AES-GCM), then data. The master key is random, made once
 * when the vault is created, so changing the password rewraps 32 bytes and
 * leaves every encrypted file as it was.
 */
class VaultHeader(
    val cipherSuite: CipherSuite = CipherSuite.PBKDF2_SHA256_AES256GCM,
    /** Key derivation rounds as the file records them: an unsigned 32-bit number. */
    val kdfIterations: Long = KeyDerivation.VAULT_ITERATIONS.toLong(),
    salt: ByteArray,
    wrappedMasterKey: ByteArray,
    encryptedDatabaseSize: ByteArray,
) {
    val salt: ByteArray = salt.copyOf()
    val wrappedMasterKey: ByteArray = wrappedMasterKey.copyOf()
    val encryptedDatabaseSize: ByteArray = encryptedDatabaseSize.copyOf()

    /** The 145 header bytes, checksum included. */
    fun serialized(): ByteArray {
        val data = ByteArray(SIZE)
        var at = 0
        fun put(bytes: ByteArray) {
            System.arraycopy(bytes, 0, data, at, bytes.size)
            at += bytes.size
        }
        put(byteArrayOf(VERSION))
        put(MAGIC)
        put(byteArrayOf(cipherSuite.id.toByte()))
        put(bigEndianBytes(kdfIterations, 4))
        put(salt)
        put(wrappedMasterKey)
        put(encryptedDatabaseSize)
        check(at == SIZE - 4) { "vault header fields have the wrong sizes" }
        put(bigEndianBytes(crc32(data, SIZE - 4), 4))
        return data
    }

    // MARK: Keys

    /**
     * Unwraps the master key with [password].
     *
     * Uses the round count the header records, and refuses one below the
     * format's floor, so a doctored header cannot make a weak password
     * cheaper to guess.
     */
    fun unlock(password: String): SecureBytes {
        checkIterations()
        val passwordKey = KeyDerivation.pbkdf2SHA256(password, salt, kdfIterations.toInt())
        try {
            return AesGcm.unwrapKey(wrappedMasterKey, passwordKey)
        } catch (e: ObscuraCryptoException.AuthenticationFailed) {
            throw ObscuraCryptoException.WrongPassword()
        } finally {
            passwordKey.clear()
        }
    }

    /**
     * The same master key under a new password and a fresh salt.
     *
     * Nothing else in the vault changes: the database and every media file
     * stay encrypted with the master key they already use.
     */
    fun changingPassword(oldPassword: String, newPassword: String): VaultHeader {
        unlock(oldPassword).use { masterKey ->
            val newSalt = KeyDerivation.makeSalt()
            val newPasswordKey = KeyDerivation.pbkdf2SHA256(newPassword, newSalt, KeyDerivation.VAULT_ITERATIONS)
            try {
                return VaultHeader(
                    cipherSuite = cipherSuite,
                    kdfIterations = KeyDerivation.VAULT_ITERATIONS.toLong(),
                    salt = newSalt,
                    wrappedMasterKey = masterKey.withBytes { AesGcm.seal(it, newPasswordKey) },
                    encryptedDatabaseSize = encryptedDatabaseSize,
                )
            } finally {
                newPasswordKey.clear()
            }
        }
    }

    /** The length of the database that follows the header. */
    fun databaseSize(masterKey: SecureBytes): Long = decryptDatabaseSize(encryptedDatabaseSize, masterKey)

    /** This header with a different database length. */
    fun settingDatabaseSize(size: Long, masterKey: SecureBytes): VaultHeader = VaultHeader(
        cipherSuite = cipherSuite,
        kdfIterations = kdfIterations,
        salt = salt,
        wrappedMasterKey = wrappedMasterKey,
        encryptedDatabaseSize = encryptDatabaseSize(size, masterKey),
    )

    private fun checkIterations() {
        if (kdfIterations < KeyDerivation.VAULT_ITERATIONS) {
            throw ObscuraCryptoException.IterationsBelowMinimum(kdfIterations)
        }
        if (kdfIterations > MAXIMUM_ITERATIONS) {
            throw ObscuraCryptoException.InvalidVaultHeader("$kdfIterations key derivation rounds is implausibly many")
        }
    }

    override fun equals(other: Any?): Boolean =
        other is VaultHeader && cipherSuite == other.cipherSuite && kdfIterations == other.kdfIterations &&
            salt.contentEquals(other.salt) && wrappedMasterKey.contentEquals(other.wrappedMasterKey) &&
            encryptedDatabaseSize.contentEquals(other.encryptedDatabaseSize)

    override fun hashCode(): Int = salt.contentHashCode()

    class Created(val header: VaultHeader, val masterKey: SecureBytes)

    companion object {
        const val SIZE = 145
        const val VERSION: Byte = 0x03
        val MAGIC: ByteArray = "OBSCURA".toByteArray(Charsets.US_ASCII)
        const val WRAPPED_KEY_SIZE = AesGcm.OVERHEAD + 32
        const val ENCRYPTED_DATABASE_SIZE_SIZE = AesGcm.OVERHEAD + 8

        /**
         * Beyond this a header is treated as hostile: about 16 times the
         * standard count, it already makes an unlock take several seconds.
         */
        const val MAXIMUM_ITERATIONS = 10_000_000L

        /** Parses the first 145 bytes of [data], which may be a whole vault file. */
        fun parse(data: ByteArray): VaultHeader {
            if (data.size < SIZE) throw ObscuraCryptoException.InvalidVaultHeader("shorter than $SIZE bytes")
            val header = data.copyOf(SIZE)

            if (header[0] != VERSION) {
                throw ObscuraCryptoException.InvalidVaultHeader(
                    "version 0x%02x, expected 0x03".format(header[0].toInt() and 0xFF)
                )
            }
            if (!header.range(1, 8).contentEquals(MAGIC)) {
                throw ObscuraCryptoException.InvalidVaultHeader("missing OBSCURA magic")
            }
            if (header.bigEndianUInt32(141) != crc32(header, 141)) {
                throw ObscuraCryptoException.VaultHeaderChecksumMismatch()
            }
            val suiteId = header[8].toInt() and 0xFF
            val suite = CipherSuite.fromId(suiteId) ?: throw ObscuraCryptoException.UnsupportedCipherSuite(suiteId)

            return VaultHeader(
                cipherSuite = suite,
                kdfIterations = header.bigEndianUInt32(9),
                salt = header.range(13, 45),
                wrappedMasterKey = header.range(45, 105),
                encryptedDatabaseSize = header.range(105, 141),
            )
        }

        /**
         * Makes a header for a new vault, and the master key it wraps.
         *
         * [databaseSize] is what the app stores there: the length of the
         * SQLCipher database that follows the header.
         */
        fun create(password: String, databaseSize: Long = 0): Created {
            val masterKey = SecureBytes.random(32)
            val salt = KeyDerivation.makeSalt()
            val passwordKey = KeyDerivation.pbkdf2SHA256(password, salt, KeyDerivation.VAULT_ITERATIONS)
            try {
                val header = VaultHeader(
                    salt = salt,
                    wrappedMasterKey = masterKey.withBytes { AesGcm.seal(it, passwordKey) },
                    encryptedDatabaseSize = encryptDatabaseSize(databaseSize, masterKey),
                )
                return Created(header, masterKey)
            } finally {
                passwordKey.clear()
            }
        }

        /**
         * A length sealed the way the header stores it: 8 bytes, AES-GCM with
         * the master key.
         *
         * Little-endian, unlike every other number in the header: the iOS app
         * has always written this one in the device's native byte order, which
         * on every Apple device it has run on is little-endian.
         */
        fun encryptDatabaseSize(size: Long, masterKey: SecureBytes): ByteArray =
            AesGcm.seal(littleEndianBytes(size), masterKey)

        fun decryptDatabaseSize(sealed: ByteArray, masterKey: SecureBytes): Long {
            val plaintext = AesGcm.open(sealed, masterKey)
            if (plaintext.size != 8) throw ObscuraCryptoException.InvalidVaultHeader("database length is not 8 bytes")
            var value = 0L
            for (i in 7 downTo 0) value = value shl 8 or (plaintext[i].toLong() and 0xFF)
            if (value < 0) throw ObscuraCryptoException.InvalidVaultHeader("database length is implausibly large")
            return value
        }
    }
}
