// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

/**
 * Everything this library refuses, one class per reason, matching the Swift
 * package's `ObscuraCryptoError`. Two errors are equal when they are the same
 * kind with the same message, which carries their parameters.
 */
sealed class ObscuraCryptoException(message: String) : Exception(message) {

    class KeyDerivationFailed : ObscuraCryptoException("Key derivation failed")

    /** A key was used after it was cleared, which would otherwise mean using zeros. */
    class KeyCleared : ObscuraCryptoException("The key has been cleared and cannot be used")

    /** A key was not the 32 bytes AES-256 needs. */
    class InvalidKeyLength(val length: Int) :
        ObscuraCryptoException("Expected a 32-byte key, got $length bytes")

    /** An AES-GCM authentication tag did not verify: wrong key, or the data was altered. */
    class AuthenticationFailed :
        ObscuraCryptoException("Authentication failed: wrong key, or the data was altered")

    /** The password did not unwrap the key. */
    class WrongPassword : ObscuraCryptoException("Wrong password")

    class InvalidVaultHeader(val reason: String) :
        ObscuraCryptoException("Not a valid vault header: $reason")

    class VaultHeaderChecksumMismatch :
        ObscuraCryptoException("Vault header checksum does not match")

    class UnsupportedCipherSuite(val id: Int) :
        ObscuraCryptoException("Unsupported cipher suite 0x%02x".format(id))

    /** A header asked for fewer key derivation rounds than the format allows. */
    class IterationsBelowMinimum(val rounds: Long) :
        ObscuraCryptoException("Header asks for $rounds key derivation rounds, below the minimum")

    class InvalidChunkedHeader(val reason: String) :
        ObscuraCryptoException("Not a valid chunked media header: $reason")

    class ChunkIndexOutOfRange(val index: Long) :
        ObscuraCryptoException("Chunk $index is out of range")

    /**
     * A chunk did not carry the nonce its position requires, meaning chunks
     * were reordered, or copied in from another file.
     */
    class ChunkNonceMismatch(val index: Long) :
        ObscuraCryptoException("Chunk $index carries the wrong nonce: chunks were reordered or replaced")

    /** The file is not the length its header describes. */
    class ChunkedFileSizeMismatch(val expected: Long, val actual: Long) :
        ObscuraCryptoException("File is $actual bytes but its header describes $expected")

    class InvalidFolderProtection(val reason: String) :
        ObscuraCryptoException("Not valid folder protection data: $reason")

    class InvalidExport(val reason: String) :
        ObscuraCryptoException("Not a valid .obscura export: $reason")

    override fun equals(other: Any?): Boolean =
        other is ObscuraCryptoException && other::class == this::class && other.message == message

    override fun hashCode(): Int = message.hashCode()
}
