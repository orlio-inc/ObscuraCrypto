// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CryptoKit
import Foundation

/// A vault's master key written out as 24 words, so it can be kept on paper
/// or in a password manager and typed back if the password is forgotten.
///
/// The words are the master key itself, not something derived from it: the
/// 32 bytes, followed by the first byte of their SHA-256, read as 24 numbers
/// of 11 bits, each standing for a word of the BIP-39 English list. That is
/// BIP-39's encoding of 256 bits of entropy, so its published test vectors
/// apply, but nothing else of BIP-39 is used: the words are never stretched
/// into a seed, and they are not a cryptocurrency wallet.
///
/// Because the words are the key, they open everything the key does, for as
/// long as the vault exists. A password change leaves them valid, and they
/// cannot be revoked short of re-encrypting the vault under a new key.
///
/// The checksum byte catches a mistyped phrase before any vault is tried. It
/// is public arithmetic on the key, so it costs an attacker nothing to
/// compute; 248 bits remain to be guessed.
public enum RecoveryPhrase {
    public static let wordCount = 24
    static let keySize = 32
    static let bitsPerWord = 11

    /// The 24 words for a 32-byte master key.
    public static func words(for masterKey: SecureBytes) throws -> [String] {
        guard masterKey.count == keySize else {
            throw ObscuraCryptoError.invalidKeyLength(masterKey.count)
        }
        // Key and checksum together, 33 bytes = 264 bits = 24 words.
        let bits = SecureBytes(count: keySize + 1)
        bits.withUnsafeMutableBytes { buffer in
            masterKey.withUnsafeBytes { key in
                buffer.baseAddress!.copyMemory(from: key.baseAddress!, byteCount: keySize)
                buffer[keySize] = checksum(of: key)
            }
        }
        return bits.withUnsafeBytes { buffer in
            (0..<wordCount).map { words[readBits(buffer, from: $0 * bitsPerWord)] }
        }
    }

    /// The master key the words stand for.
    ///
    /// Words are matched after `normalized(_:)`. Throws
    /// `recoveryPhraseWrongLength`, `recoveryPhraseUnknownWord` with the
    /// 1-based position of the first word not on the list, or
    /// `recoveryPhraseChecksumMismatch` when every word is on the list but
    /// the phrase is not one this encoding produces (a word mistyped as
    /// another list word, or two words swapped).
    public static func masterKey(from phrase: [String]) throws -> SecureBytes {
        guard phrase.count == wordCount else {
            throw ObscuraCryptoError.recoveryPhraseWrongLength(phrase.count)
        }
        var indices: [Int] = []
        indices.reserveCapacity(wordCount)
        for (position, word) in phrase.enumerated() {
            guard let index = index(of: word) else {
                throw ObscuraCryptoError.recoveryPhraseUnknownWord(position: position + 1)
            }
            indices.append(index)
        }

        let bits = SecureBytes(count: keySize + 1)
        bits.withUnsafeMutableBytes { buffer in
            for (position, index) in indices.enumerated() {
                writeBits(index, to: buffer, at: position * bitsPerWord)
            }
        }
        // Clear the word numbers too: together they are the key.
        for position in indices.indices { indices[position] = 0 }

        let checksumMatches = bits.withUnsafeBytes { buffer in
            checksum(of: UnsafeRawBufferPointer(rebasing: buffer[0..<keySize])) == buffer[keySize]
        }
        guard checksumMatches else {
            throw ObscuraCryptoError.recoveryPhraseChecksumMismatch
        }
        return bits.withUnsafeBytes { SecureBytes(copying: UnsafeRawBufferPointer(rebasing: $0[0..<keySize])) }
    }

    /// A word as it is compared with the list: trimmed and lowercased.
    public static func normalized(_ word: String) -> String {
        word.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// The word's number, 0 to 2047, or nil when it is not on the list.
    public static func index(of word: String) -> Int? {
        indexByWord[normalized(word)]
    }

    /// List words starting with `prefix`, in list order, for autocompletion.
    ///
    /// The list is public, so suggesting from it says nothing about any key.
    /// Every word is identified by its first four letters.
    public static func completions(for prefix: String, limit: Int = 4) -> [String] {
        let prefix = normalized(prefix)
        guard !prefix.isEmpty else { return [] }
        return Array(words.lazy.filter { $0.hasPrefix(prefix) }.prefix(limit))
    }

    private static let indexByWord: [String: Int] = Dictionary(
        uniqueKeysWithValues: words.enumerated().map { ($1, $0) })

    /// The first byte of the key's SHA-256: the last 8 bits of the phrase.
    private static func checksum(of key: UnsafeRawBufferPointer) -> UInt8 {
        SHA256.hash(data: key).withUnsafeBytes { $0[0] }
    }

    /// The 11 bits starting at bit `offset`, most significant first.
    private static func readBits(_ buffer: UnsafeRawBufferPointer, from offset: Int) -> Int {
        var value = 0
        for bit in offset..<(offset + bitsPerWord) {
            let byte = buffer[bit / 8]
            value = value << 1 | Int((byte >> (7 - UInt8(bit % 8))) & 1)
        }
        return value
    }

    private static func writeBits(_ value: Int, to buffer: UnsafeMutableRawBufferPointer, at offset: Int) {
        for i in 0..<bitsPerWord where (value >> (bitsPerWord - 1 - i)) & 1 == 1 {
            let bit = offset + i
            buffer[bit / 8] |= 1 << (7 - UInt8(bit % 8))
        }
    }
}
