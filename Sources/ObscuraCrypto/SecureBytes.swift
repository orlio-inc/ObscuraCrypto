// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CryptoKit
import Foundation

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
public final class SecureBytes: @unchecked Sendable {
    // Safe to share across threads: the buffer is only written during init
    // and by `clear()`, which callers use when they are done with the key.
    private let buffer: UnsafeMutableRawBufferPointer

    public var count: Int { buffer.count }

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

    public func withUnsafeBytes<Result>(_ body: (UnsafeRawBufferPointer) throws -> Result) rethrows -> Result {
        try body(UnsafeRawBufferPointer(buffer))
    }

    /// Overwrites the bytes with zeros. Also done automatically on release.
    public func clear() {
        guard let base = buffer.baseAddress, buffer.count > 0 else { return }
        _ = memset_s(base, buffer.count, 0, buffer.count)
    }

    /// The first 8 bytes of SHA-256 over the key, in hex.
    ///
    /// Safe to show: a truncated one-way hash says nothing useful about the
    /// key, but it lets two tools confirm they unwrapped the same one.
    public var fingerprint: String {
        let digest = withUnsafeBytes { SHA256.hash(data: $0) }
        return digest.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    var symmetricKey: SymmetricKey {
        withUnsafeBytes { SymmetricKey(data: $0) }
    }

    deinit {
        clear()
        buffer.deallocate()
    }
}

extension SecureBytes: Equatable {
    /// Constant-time comparison, so equality checks on keys do not leak where
    /// two keys first differ.
    public static func == (lhs: SecureBytes, rhs: SecureBytes) -> Bool {
        lhs.withUnsafeBytes { a in
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
