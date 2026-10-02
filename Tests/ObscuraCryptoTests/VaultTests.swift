// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import XCTest
@testable import ObscuraCrypto

final class VaultTests: XCTestCase {

    func testCreateThenUnlock() throws {
        let (header, masterKey) = try VaultHeader.create(password: "secret password", databaseSize: 42)
        let reread = try VaultHeader(parsing: header.serialized())
        XCTAssertEqual(reread, header)
        XCTAssertEqual(try reread.unlock(password: "secret password"), masterKey)
        XCTAssertEqual(try reread.databaseSize(masterKey: masterKey), 42)
    }

    func testLayoutIsExactly145BytesWithFieldsWhereTheSpecSays() throws {
        let (header, _) = try VaultHeader.create(password: "secret password")
        let bytes = header.serialized()
        XCTAssertEqual(bytes.count, 145)
        XCTAssertEqual(bytes[0], 0x03)
        XCTAssertEqual(bytes[1..<8], Data("OBSCURA".utf8))
        XCTAssertEqual(bytes[8], 0x01)
        XCTAssertEqual(bytes.bigEndianUInt32(at: 9), 600_000)
        XCTAssertEqual(bytes[13..<45], header.salt)
        XCTAssertEqual(bytes[45..<105], header.wrappedMasterKey)
        XCTAssertEqual(bytes[105..<141], header.encryptedDatabaseSize)
    }

    func testWrongPasswordIsRejected() throws {
        let (header, _) = try VaultHeader.create(password: "secret password")
        XCTAssertThrowsError(try header.unlock(password: "secret passworD")) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .wrongPassword)
        }
    }

    func testDamagedHeaderFailsItsChecksum() throws {
        var bytes = try VaultHeader.create(password: "secret password").header.serialized()
        bytes[20] ^= 0xFF
        XCTAssertThrowsError(try VaultHeader(parsing: bytes)) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .vaultHeaderChecksumMismatch)
        }
    }

    /// A header rewritten to ask for fewer rounds, checksum and all, must not
    /// make a password cheaper to try.
    func testLoweredIterationCountIsRefused() throws {
        let (header, _) = try VaultHeader.create(password: "secret password")
        let weakened = VaultHeader(
            kdfIterations: 1_000, salt: header.salt,
            wrappedMasterKey: header.wrappedMasterKey, encryptedDatabaseSize: header.encryptedDatabaseSize)
        let reread = try VaultHeader(parsing: weakened.serialized())
        XCTAssertThrowsError(try reread.unlock(password: "secret password")) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .iterationsBelowMinimum(1_000))
        }
    }

    func testUnknownCipherSuiteIsRefused() throws {
        var bytes = try VaultHeader.create(password: "secret password").header.serialized()
        bytes[8] = 0x02
        bytes.replaceSubrange(141..<145, with: Data())
        bytes.appendBigEndian(bytes.crc32)
        XCTAssertThrowsError(try VaultHeader(parsing: bytes)) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .unsupportedCipherSuite(0x02))
        }
    }

    /// The point of the key hierarchy: a new password, a new salt, the same
    /// master key, so nothing encrypted needs touching.
    func testChangingPasswordKeepsTheMasterKey() throws {
        let (header, masterKey) = try VaultHeader.create(password: "old password")
        let changed = try header.changingPassword(from: "old password", to: "new password")
        XCTAssertNotEqual(changed.salt, header.salt)
        XCTAssertEqual(try changed.unlock(password: "new password"), masterKey)
        XCTAssertThrowsError(try changed.unlock(password: "old password"))
    }

    func testFolderProtection() throws {
        let (protection, folderKey) = try FolderProtection.create(password: "folder pass")
        XCTAssertEqual(try protection.unlock(password: "folder pass"), folderKey)
        XCTAssertThrowsError(try protection.unlock(password: "folder pasS")) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .wrongPassword)
        }
    }
}
