// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.security.MessageDigest

/**
 * A vault's master key written out as 24 words, so it can be kept on paper or
 * in a password manager and typed back if the password is forgotten. The same
 * encoding as the Swift package's `RecoveryPhrase`, so words shown on an
 * iPhone open the vault on Android, and the reverse.
 *
 * The words are the master key itself, not something derived from it: the 32
 * bytes, followed by the first byte of their SHA-256, read as 24 numbers of 11
 * bits, each standing for a word of the BIP-39 English list. That is BIP-39's
 * encoding of 256 bits of entropy, so its published test vectors apply, but
 * nothing else of BIP-39 is used: the words are never stretched into a seed,
 * and they are not a cryptocurrency wallet.
 *
 * Because the words are the key, they open everything the key does, for as
 * long as the vault exists. A password change leaves them valid, and they
 * cannot be revoked short of re-encrypting the vault under a new key.
 *
 * The checksum byte catches a mistyped phrase before any vault is tried. It is
 * public arithmetic on the key, so it costs an attacker nothing to compute;
 * 248 bits remain to be guessed.
 *
 * As with [SecureBytes], the JVM cannot promise that no copy of the words or
 * the key outlives this object; the working arrays are zeroed after use.
 */
object RecoveryPhrase {
    const val WORD_COUNT = 24
    private const val KEY_SIZE = 32
    private const val BITS_PER_WORD = 11

    /** The BIP-39 English list, 2,048 words, in order. */
    val words: List<String> get() = RECOVERY_PHRASE_WORDS

    private val indexByWord: Map<String, Int> by lazy {
        RECOVERY_PHRASE_WORDS.withIndex().associate { (index, word) -> word to index }
    }

    /** The 24 words for a 32-byte master key. */
    fun words(masterKey: SecureBytes): List<String> {
        if (masterKey.count != KEY_SIZE) throw ObscuraCryptoException.InvalidKeyLength(masterKey.count)
        // Key and checksum together, 33 bytes = 264 bits = 24 words.
        val bits = ByteArray(KEY_SIZE + 1)
        try {
            masterKey.withBytes { key ->
                System.arraycopy(key, 0, bits, 0, KEY_SIZE)
                bits[KEY_SIZE] = checksum(key)
            }
            return List(WORD_COUNT) { RECOVERY_PHRASE_WORDS[readBits(bits, it * BITS_PER_WORD)] }
        } finally {
            bits.fill(0)
        }
    }

    /**
     * The master key the words stand for.
     *
     * Words are matched after [normalized]. Throws
     * [ObscuraCryptoException.RecoveryPhraseWrongLength],
     * [ObscuraCryptoException.RecoveryPhraseUnknownWord] with the 1-based
     * position of the first word not on the list, or
     * [ObscuraCryptoException.RecoveryPhraseChecksumMismatch] when every word
     * is on the list but the phrase is not one this encoding produces (a word
     * mistyped as another list word, or two words swapped).
     */
    fun masterKey(phrase: List<String>): SecureBytes {
        if (phrase.size != WORD_COUNT) throw ObscuraCryptoException.RecoveryPhraseWrongLength(phrase.size)
        val indices = IntArray(WORD_COUNT)
        val bits = ByteArray(KEY_SIZE + 1)
        try {
            phrase.forEachIndexed { position, word ->
                indices[position] = indexOf(word)
                    ?: throw ObscuraCryptoException.RecoveryPhraseUnknownWord(position + 1)
            }
            indices.forEachIndexed { position, index -> writeBits(index, bits, position * BITS_PER_WORD) }

            val key = bits.copyOf(KEY_SIZE)
            try {
                if (checksum(key) != bits[KEY_SIZE]) throw ObscuraCryptoException.RecoveryPhraseChecksumMismatch()
                return SecureBytes.copying(key)
            } finally {
                key.fill(0)
            }
        } finally {
            // The word numbers too: together they are the key.
            indices.fill(0)
            bits.fill(0)
        }
    }

    /**
     * A word as it is compared with the list: trimmed and lowercased. The
     * lowercasing is locale-independent, so a Turkish phone's dotted and
     * dotless i do not change a word.
     */
    fun normalized(word: String): String = word.trim().lowercase()

    /** The word's number, 0 to 2047, or null when it is not on the list. */
    fun indexOf(word: String): Int? = indexByWord[normalized(word)]

    /**
     * List words starting with [prefix], in list order, for autocompletion.
     *
     * The list is public, so suggesting from it says nothing about any key.
     * Every word is identified by its first four letters.
     */
    fun completions(prefix: String, limit: Int = 4): List<String> {
        val start = normalized(prefix)
        if (start.isEmpty()) return emptyList()
        return RECOVERY_PHRASE_WORDS.asSequence().filter { it.startsWith(start) }.take(limit).toList()
    }

    /** The first byte of the key's SHA-256: the last 8 bits of the phrase. */
    private fun checksum(key: ByteArray): Byte {
        val digest = MessageDigest.getInstance("SHA-256").digest(key)
        return digest[0].also { digest.fill(0) }
    }

    /** The 11 bits starting at bit [offset], most significant first. */
    private fun readBits(buffer: ByteArray, offset: Int): Int {
        var value = 0
        for (bit in offset until offset + BITS_PER_WORD) {
            val byte = buffer[bit / 8].toInt() and 0xFF
            value = (value shl 1) or ((byte shr (7 - bit % 8)) and 1)
        }
        return value
    }

    private fun writeBits(value: Int, buffer: ByteArray, offset: Int) {
        for (i in 0 until BITS_PER_WORD) {
            if ((value shr (BITS_PER_WORD - 1 - i)) and 1 == 1) {
                val bit = offset + i
                buffer[bit / 8] = (buffer[bit / 8].toInt() or (1 shl (7 - bit % 8))).toByte()
            }
        }
    }
}
