// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CryptoKit
import Foundation
import os

/// Key material that is zeroed when it is released.
///
/// Held in a buffer this type allocates itself rather than in `Data` or an
/// array, because both of those copy on write: a key passed around as `Data`
/// can leave copies behind that nothing ever clears. Here there is one buffer,
/// it is never copied by this type, and it is overwritten with `memset_s`,
/// which the compiler may not optimise away, before it is freed.
///
/// Keys are handed to CryptoKit as a `SymmetricKey`, which keeps and clears
/// its own copy.
///
/// A cleared key refuses to be used: every seal, open, wrap or derivation in
/// this package throws `keyCleared` for it. Zeroed bytes are a perfectly good
/// AES key, so without that refusal a seal made after the key was cleared
/// would succeed, under a key anyone can guess.
public final class SecureBytes: @unchecked Sendable {
    // Safe to share across threads: the buffer is only written during init
    // and by `clear()`, which callers use when they are done with the key.
    private let buffer: UnsafeMutableRawBufferPointer
    private let cleared = OSAllocatedUnfairLock(initialState: false)

    public var count: Int { buffer.count }

    /// Whether `clear()` has run. A cleared key cannot be used again.
    public var isCleared: Bool { cleared.withLock { $0 } }

    /// Zero-filled bytes of the given length.
    public init(count: Int) {
        precondition(count >= 0, "SecureBytes count must not be negative")
        buffer = .allocate(byteCount: count, alignment: 16)
        buffer.initializeMemory(as: UInt8.self, repeating: 0)
    }

    /// A copy of `bytes`. The caller remains responsible for its own copy.
    public convenience init<Bytes: ContiguousBytes>(copying bytes: Bytes) {
        let length = bytes.withUnsafeBytes { $0.count }
        self.init(count: length)
        bytes.withUnsafeBytes { source in
            if let base = source.baseAddress, length > 0 {
                buffer.baseAddress!.copyMemory(from: base, byteCount: length)
            }
        }
    }

    /// Cryptographically random bytes from the system generator.
    public static func random(count: Int) throws -> SecureBytes {
        let bytes = SecureBytes(count: count)
        try SecureRandom.fill(bytes.buffer)
        return bytes
    }

    /// The bytes as they are, zeros once `clear()` has run. For using them as
    /// a key (sealing, wrapping, deriving another key), use `withKeyBytes`,
    /// which refuses a cleared key.
    public func withUnsafeBytes<Result>(_ body: (UnsafeRawBufferPointer) throws -> Result) rethrows -> Result {
        try body(UnsafeRawBufferPointer(buffer))
    }

    /// The bytes, for use as a key: throws `keyCleared` once `clear()` has run.
    /// Everything in this package that encrypts, decrypts, wraps or derives
    /// with a key reads it through here, and so should any caller that does.
    public func withKeyBytes<Result>(_ body: (UnsafeRawBufferPointer) throws -> Result) throws -> Result {
        try checkNotCleared()
        return try body(UnsafeRawBufferPointer(buffer))
    }

    func checkNotCleared() throws {
        if isCleared { throw ObscuraCryptoError.keyCleared }
    }

    /// Writes into the buffer in place. Internal: keys are built here only
    /// by this package, as `RecoveryPhrase` does when decoding words.
    func withUnsafeMutableBytes<Result>(_ body: (UnsafeMutableRawBufferPointer) throws -> Result) rethrows -> Result {
        try body(buffer)
    }

    /// Overwrites the bytes with zeros, and refuses any later use as a key.
    /// Also done automatically on release.
    public func clear() {
        cleared.withLock { $0 = true }
        guard let base = buffer.baseAddress, buffer.count > 0 else { return }
        _ = memset_s(base, buffer.count, 0, buffer.count)
    }

    /// The first 8 bytes of SHA-256 over the key, in hex.
    ///
    /// Safe to show: a truncated one-way hash says nothing useful about the
    /// key, but it lets two tools confirm they unwrapped the same one. A
    /// cleared key shows "cleared", never the fingerprint of its zeros.
    public var fingerprint: String {
        guard !isCleared else { return "cleared" }
        let digest = withUnsafeBytes { SHA256.hash(data: $0) }
        return digest.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    /// The key for CryptoKit: throws `keyCleared` once `clear()` has run.
    var symmetricKey: SymmetricKey {
        get throws { try withKeyBytes { SymmetricKey(data: $0) } }
    }

    deinit {
        clear()
        buffer.deallocate()
    }
}

extension SecureBytes: Equatable {
    /// Constant-time comparison, so equality checks on keys do not leak where
    /// two keys first differ. A cleared key equals no key, not even another
    /// cleared one: their zeros are not keys.
    public static func == (lhs: SecureBytes, rhs: SecureBytes) -> Bool {
        guard !lhs.isCleared, !rhs.isCleared else { return false }
        return lhs.withUnsafeBytes { a in
            rhs.withUnsafeBytes { b in
                constantTimeEquals(a, b)
            }
        }
    }
}

/// Compares two byte sequences in time that depends only on their length.
func constantTimeEquals<A: Collection, B: Collection>(_ a: A, _ b: B) -> Bool
where A.Element == UInt8, B.Element == UInt8 {
    guard a.count == b.count else { return false }
    var difference: UInt8 = 0
    for (x, y) in zip(a, b) {
        difference |= x ^ y
    }
    return difference == 0
}
