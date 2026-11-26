// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import XCTest
@testable import ObscuraCrypto

final class PrimitivesTests: XCTestCase {

    /// PBKDF2-HMAC-SHA256 with published inputs and output (RFC 7914, §11).
    func testPBKDF2MatchesPublishedVector() throws {
        let key = try KeyDerivation.pbkdf2SHA256(password: "passwd", salt: Data("salt".utf8), iterations: 1)
        let expected = "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        XCTAssertEqual(key.withUnsafeBytes { $0.map { String(format: "%02x", $0) }.joined() }, expected)
    }

    func testCRC32MatchesTheStandardCheckValue() {
        XCTAssertEqual(Array("123456789".utf8).crc32, 0xCBF4_3926)
    }

    func testSealAndOpen() throws {
        let key = try SecureBytes.random(count: 32)
        let sealed = try AESGCM.seal(Data("hello".utf8), key: key)
        XCTAssertEqual(sealed.count, 5 + AESGCM.overhead)
        XCTAssertEqual(try AESGCM.open(sealed, key: key), Data("hello".utf8))
    }

    func testEverySealUsesAFreshNonce() throws {
        let key = try SecureBytes.random(count: 32)
        let first = try AESGCM.seal(Data("same".utf8), key: key)
        let second = try AESGCM.seal(Data("same".utf8), key: key)
        XCTAssertNotEqual(first.prefix(AESGCM.nonceSize), second.prefix(AESGCM.nonceSize))
    }

    func testAlteredCiphertextIsRejected() throws {
        let key = try SecureBytes.random(count: 32)
        var sealed = try AESGCM.seal(Data("hello".utf8), key: key)
        sealed[AESGCM.nonceSize] ^= 0x01
        XCTAssertThrowsError(try AESGCM.open(sealed, key: key)) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .authenticationFailed)
        }
    }

    func testWrongKeyIsRejected() throws {
        let sealed = try AESGCM.seal(Data("hello".utf8), key: try SecureBytes.random(count: 32))
        XCTAssertThrowsError(try AESGCM.open(sealed, key: try SecureBytes.random(count: 32)))
    }

    func testShortKeyIsRejected() throws {
        XCTAssertThrowsError(try AESGCM.seal(Data(), key: SecureBytes(count: 16))) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .invalidKeyLength(16))
        }
    }

    func testClearZeroesTheBytes() throws {
        let key = try SecureBytes.random(count: 32)
        key.clear()
        XCTAssertTrue(key.withUnsafeBytes { $0.allSatisfy { $0 == 0 } })
    }

    /// Zeroed bytes are a working AES key, so a cleared key must refuse to
    /// be used, or a seal after a lock would succeed under a key anyone can
    /// guess.
    func testAClearedKeyCannotSealOpenWrapOrBecomeWords() throws {
        let key = try SecureBytes.random(count: 32)
        let sealed = try AESGCM.seal(Data("photo".utf8), key: key)
        let (header, _) = try VaultHeader.create(password: "correct horse")
        key.clear()
        XCTAssertTrue(key.isCleared)
        func assertCleared(_ body: () throws -> Any, line: UInt = #line) {
            XCTAssertThrowsError(try body(), line: line) {
                XCTAssertEqual($0 as? ObscuraCryptoError, .keyCleared, line: line)
            }
        }
        assertCleared { try AESGCM.seal(Data("photo".utf8), key: key) }
        assertCleared { try AESGCM.open(sealed, key: key) }
        assertCleared { try SingleShotMedia.encrypt(Data("photo".utf8), masterKey: key) }
        assertCleared { try ChunkedMediaCipher(header: try ChunkedMediaHeader.make(totalPlaintextSize: 10), masterKey: key) }
        assertCleared { try VaultHeader.encryptDatabaseSize(10, masterKey: key) }
        assertCleared { try header.settingPassword("new password", masterKey: key) }
        assertCleared { try RecoveryPhrase.words(for: key) }
        assertCleared { try key.withKeyBytes { Data($0) } }
        XCTAssertFalse(header.opens(masterKey: key))
        // Its zeros are no key: not shown as one, and equal to nothing.
        XCTAssertEqual(key.fingerprint, "cleared")
        let other = try SecureBytes.random(count: 32)
        other.clear()
        XCTAssertNotEqual(key, other)
        XCTAssertNotEqual(key, key)
    }

    func testAKeyThatWasNeverClearedStillWorks() throws {
        let key = try SecureBytes.random(count: 32)
        XCTAssertFalse(key.isCleared)
        XCTAssertEqual(try AESGCM.open(try AESGCM.seal(Data("photo".utf8), key: key), key: key), Data("photo".utf8))
    }

    func testKeysCompareByContent() throws {
        let key = try SecureBytes.random(count: 32)
        let copy = key.withUnsafeBytes { SecureBytes(copying: Data($0)) }
        XCTAssertEqual(key, copy)
        XCTAssertNotEqual(key, try SecureBytes.random(count: 32))
    }
}
