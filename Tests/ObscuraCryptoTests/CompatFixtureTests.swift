// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CryptoKit
import XCTest
@testable import ObscuraCrypto

/// The cross-language fixtures: a folder of files written by one language of
/// this library, with a `compat.json` saying what each file is and what a
/// reader must do with it: open it and get the stated contents, or refuse it
/// with a named error. Each language writes a set and reads both, so this
/// package opens every file the Kotlin library wrote, the Kotlin library
/// opens every file written here, and both refuse the same tampered files for
/// the same reason.
///
/// The Kotlin library has the same schema and the same checks in
/// `kotlin/src/test/.../CompatFixtures.kt`. Change one, change both.
///
/// Plaintext is never stored: a case carries `count` and `seed`, and the bytes
/// are `(i * 31 + seed) % 251`.
final class CompatFixtureTests: XCTestCase {

    private var fixtures: URL {
        get throws { try XCTUnwrap(Bundle.module.url(forResource: "Fixtures", withExtension: nil)) }
    }

    func testOpensEveryFileKotlinWroteAndRefusesItsTamperedOnes() throws {
        try verify(set: "FromKotlin")
    }

    func testOpensItsOwnFilesAndRefusesItsOwnTamperedOnes() throws {
        try verify(set: "FromSwift")
    }

    /// Rewrites `Fixtures/FromSwift` in the source tree. Skipped unless
    /// `OBSCURA_WRITE_SWIFT_FIXTURES` names the destination directory, as the
    /// fixtures are committed.
    func testWriteSwiftFixtures() throws {
        guard let path = ProcessInfo.processInfo.environment["OBSCURA_WRITE_SWIFT_FIXTURES"] else {
            throw XCTSkip("set OBSCURA_WRITE_SWIFT_FIXTURES to the FromSwift directory to rewrite it")
        }
        try CompatWriter.write(to: URL(fileURLWithPath: path), generatedBy: "ObscuraCrypto Swift 1.1.0")
    }

    // MARK: Verifying

    private func verify(set: String) throws {
        let directory = try fixtures.appendingPathComponent(set)
        let manifestURL = directory.appendingPathComponent("compat.json")
        XCTAssertTrue(FileManager.default.fileExists(atPath: manifestURL.path), "missing \(set)/compat.json")
        let manifest = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: manifestURL)) as? [String: Any])
        let vaultPassword = try XCTUnwrap(manifest["vaultPassword"] as? String)
        let folderPassword = try XCTUnwrap(manifest["folderPassword"] as? String)
        let folder = try XCTUnwrap(manifest["folder"] as? [String: String])
        let protection = try FolderProtection(
            salt: XCTUnwrap(Data(base64Encoded: XCTUnwrap(folder["passwordSalt"]))),
            passwordHash: XCTUnwrap(Data(base64Encoded: XCTUnwrap(folder["passwordHash"]))),
            wrappedFolderKey: XCTUnwrap(Data(base64Encoded: XCTUnwrap(folder["folderKeyEncrypted"]))))
        let cases = try XCTUnwrap(manifest["cases"] as? [[String: Any]])
        XCTAssertGreaterThanOrEqual(cases.count, 20, "only \(cases.count) cases in \(set)")

        var failures: [String] = []
        for entry in cases {
            let file = try XCTUnwrap(entry["file"] as? String)
            let expect = try XCTUnwrap(entry["expect"] as? String)
            let actual: String
            do {
                try check(directory.appendingPathComponent(file), entry, manifest: manifest,
                          vaultPassword: vaultPassword, folderPassword: folderPassword, protection: protection)
                actual = "opens"
            } catch let error as ObscuraCryptoError {
                actual = CompatWriter.name(of: error)
            } catch {
                actual = "other: \(error)"
            }
            if actual != expect { failures.append("\(file): expected \(expect), got \(actual)") }
        }
        XCTAssertEqual(failures, [], "\(set): cases that did not behave")
    }

    private struct Mismatch: Error { let what: String }

    private func check(_ file: URL, _ entry: [String: Any], manifest: [String: Any],
                       vaultPassword: String, folderPassword: String, protection: FolderProtection) throws {
        let bytes = try Data(contentsOf: file)
        let withFolder = entry["folder"] as? Bool ?? false
        func require(_ condition: Bool, _ what: String) throws { if !condition { throw Mismatch(what: what) } }
        func masterKey() throws -> SecureBytes {
            var directory = file.deletingLastPathComponent()
            if directory.lastPathComponent == "tampered" { directory.deleteLastPathComponent() }
            return try VaultHeader(parsing: Data(contentsOf: directory.appendingPathComponent("vault.header")))
                .unlock(password: vaultPassword)
        }
        func plaintext() -> Data {
            let count = entry["count"] as! Int, seed = entry["seed"] as! Int
            return Data((0..<count).map { UInt8((($0 * 31) + seed) % 251) })
        }

        switch entry["kind"] as? String {
        case "vaultHeader":
            let header = try VaultHeader(parsing: bytes)
            let key = try header.unlock(password: vaultPassword)
            try require(key.fingerprint == manifest["masterKeyFingerprint"] as? String, "master key")
            try require(try header.databaseSize(masterKey: key) == (manifest["databaseSize"] as! NSNumber).uint64Value, "database size")
            try require(header.serialized() == bytes, "header does not rewrite identically")
        case "singleShot":
            let folderKey = withFolder ? try protection.unlock(password: folderPassword) : nil
            let decrypted = try SingleShotMedia.decrypt(bytes, masterKey: masterKey(), folderKey: folderKey)
            try require(decrypted == plaintext(), "plaintext differs")
        case "chunked":
            let folderKey = withFolder ? try protection.unlock(password: folderPassword) : nil
            let reader = try ChunkedMediaReader(url: file)
            let output = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            defer { try? FileManager.default.removeItem(at: output) }
            try reader.decrypt(to: output, masterKey: masterKey(), folderKey: folderKey)
            try require(try Data(contentsOf: output) == plaintext(), "plaintext differs")
            try require(UInt32(entry["chunkSize"] as! Int) == reader.header.chunkPlaintextSize, "chunk size")
            try require(reader.header.hasFolderLayer == withFolder, "folder flag")
        case "export":
            let password = entry["password"] as? String ?? vaultPassword
            let archive = try ExportArchive(url: file, password: password)
            let key = try archive.index.unlockMasterKey(password: vaultPassword)
            try require(key.fingerprint == manifest["masterKeyFingerprint"] as? String, "master key")

            let scratch = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: scratch) }
            // The Swift reader skips the vault file rather than writing it out, so
            // hash it by reading the same records through the archive's own stream.
            try archive.skipDatabase()
            let media = entry["media"] as! [[String: String]]
            try require(media.count == archive.index.mediaFiles.count, "media count")
            for (expected, listed) in zip(media, archive.index.mediaFiles) {
                try require(listed.id == expected["id"], "media id")
                let data = scratch.appendingPathComponent("\(listed.id).data")
                let thumb = scratch.appendingPathComponent("\(listed.id).thumb")
                try archive.copyStoredFile(size: listed.dataSize, to: data)
                try archive.copyStoredFile(size: listed.thumbnailSize, to: thumb)
                try require(CompatWriter.sha256(Data(contentsOf: data)) == expected["dataSha256"], "data of \(listed.id)")
                try require(CompatWriter.sha256(Data(contentsOf: thumb)) == expected["thumbSha256"], "thumbnail of \(listed.id)")
            }
            try require(try archive.isAtEnd(), "records left over")
        default:
            throw Mismatch(what: "unknown case kind")
        }
    }
}
