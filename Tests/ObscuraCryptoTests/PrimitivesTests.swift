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

    func testKeysCompareByContent() throws {
        let key = try SecureBytes.random(count: 32)
        let copy = key.withUnsafeBytes { SecureBytes(copying: Data($0)) }
        XCTAssertEqual(key, copy)
        XCTAssertNotEqual(key, try SecureBytes.random(count: 32))
    }
}
