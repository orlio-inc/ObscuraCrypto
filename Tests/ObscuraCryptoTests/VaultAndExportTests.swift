// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import XCTest
@testable import ObscuraCrypto

/// A real vault and a real export, made end to end by the Obscura app's own
/// code: the vault file, its
/// media pool with a file from a second vault in it, and an export made by the
/// app's exporter. Only the vault file's random padding was
/// cut off, to keep the fixture small.
final class VaultAndExportTests: XCTestCase {

    private struct Manifest: Decodable {
        let vaultPassword: String
        let vaultFile: String
        let databaseSize: UInt64
        let photo: String
        let video: String
        let protectedPhoto: String
        let otherVaultPhoto: String
    }

    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func fixture(_ path: String) throws -> URL {
        try XCTUnwrap(Bundle.module.url(forResource: "Fixtures/\(path)", withExtension: nil), "missing fixture \(path)")
    }

    private func manifest() throws -> Manifest {
        try JSONDecoder().decode(Manifest.self, from: Data(contentsOf: fixture("vault-manifest.json")))
    }

    private func masterKey(_ manifest: Manifest) throws -> SecureBytes {
        try VaultHeader(parsing: Data(contentsOf: fixture(manifest.vaultFile))).unlock(password: manifest.vaultPassword)
    }

    private func stored(_ id: String, _ kind: String = "data") throws -> URL {
        try fixture("vault/media/\(id).\(kind).enc")
    }

    /// The app's movie generator, so the fixture need not carry the plaintext.
    private func movie() -> Data {
        var data = Data([0, 0, 0, 20]) + Data("ftypqt  ".utf8) + Data(count: 8)
        data += Data((0..<1_100_000).map { UInt8(($0 * 7 + 3) % 251) })
        return data
    }

    // MARK: - Media in the pool

    func testMasterKeyOpensThisVaultsFilesOnly() throws {
        let manifest = try manifest()
        let key = try masterKey(manifest)
        XCTAssertTrue(MediaExtraction.masterKeyOpens(storedFile: try stored(manifest.photo), masterKey: key))
        XCTAssertTrue(MediaExtraction.masterKeyOpens(storedFile: try stored(manifest.video), masterKey: key))
        XCTAssertFalse(MediaExtraction.masterKeyOpens(storedFile: try stored(manifest.protectedPhoto), masterKey: key))
        XCTAssertFalse(MediaExtraction.masterKeyOpens(storedFile: try stored(manifest.otherVaultPhoto), masterKey: key))
    }

    /// The pool is shared by every vault and file names say nothing about
    /// ownership; trying the key picks out exactly this vault's files outside
    /// protected folders.
    func testTryingTheKeyFindsThisVaultsFilesInTheSharedPool() throws {
        let manifest = try manifest()
        let key = try masterKey(manifest)
        let pool = try fixture("vault/media")
        let ids = try FileManager.default.contentsOfDirectory(atPath: pool.path)
            .filter { $0.hasSuffix(".data.enc") }
            .map { String($0.dropLast(".data.enc".count)) }
        let opened = ids.filter { MediaExtraction.masterKeyOpens(storedFile: pool.appendingPathComponent("\($0).data.enc"), masterKey: key) }
        XCTAssertEqual(Set(opened), [manifest.photo, manifest.video])
    }

    func testExtractionNamesFilesByWhatTheyAre() throws {
        let manifest = try manifest()
        let key = try masterKey(manifest)

        guard case .extracted(let photo) = try MediaExtraction.extract(
            storedFile: stored(manifest.photo), id: manifest.photo, masterKey: key, into: directory) else {
            return XCTFail("photo not extracted")
        }
        XCTAssertEqual(photo.pathExtension, "jpg")

        guard case .extracted(let video) = try MediaExtraction.extract(
            storedFile: stored(manifest.video), id: manifest.video, masterKey: key, into: directory) else {
            return XCTFail("video not extracted")
        }
        XCTAssertEqual(video.pathExtension, "mov")
        XCTAssertEqual(try Data(contentsOf: video), movie())

        XCTAssertEqual(try MediaExtraction.extract(
            storedFile: stored(manifest.protectedPhoto), id: manifest.protectedPhoto, masterKey: key, into: directory),
            .notOpenedByMasterKey)
    }

    func testExtractionRefusesANameThatIsNotAMediaID() throws {
        let manifest = try manifest()
        XCTAssertThrowsError(try MediaExtraction.extract(
            storedFile: stored(manifest.photo), id: "../escape", masterKey: masterKey(manifest), into: directory))
    }

    // MARK: - Export

    func testExportUnpacksToTheSameFilesAndKey() throws {
        let manifest = try manifest()
        let archive = try ExportArchive(url: fixture("vault.obscura"), password: manifest.vaultPassword)
        XCTAssertEqual(try archive.index.unlockMasterKey(password: manifest.vaultPassword).fingerprint,
                       try masterKey(manifest).fingerprint)
        XCTAssertEqual(Set(archive.index.mediaFiles.map(\.id)), [manifest.photo, manifest.video, manifest.protectedPhoto])

        // The vault file is read past, never written out.
        XCTAssertEqual(archive.index.databaseSize, Int64(try Data(contentsOf: fixture(manifest.vaultFile)).count))
        try archive.skipDatabase()

        // Every stored media file comes out byte for byte.
        for media in archive.index.mediaFiles {
            let data = directory.appendingPathComponent("\(media.id).data")
            let thumb = directory.appendingPathComponent("\(media.id).thumb")
            try archive.copyStoredFile(size: media.dataSize, to: data)
            XCTAssertEqual(try Data(contentsOf: data), try Data(contentsOf: stored(media.id)))
            if media.thumbnailSize > 0 {
                try archive.copyStoredFile(size: media.thumbnailSize, to: thumb)
                XCTAssertEqual(try Data(contentsOf: thumb), try Data(contentsOf: stored(media.id, "thumb")))
            }
        }
        XCTAssertTrue(try archive.isAtEnd())
    }

    func testExportRefusesTheWrongPassword() throws {
        XCTAssertThrowsError(try ExportArchive(url: fixture("vault.obscura"), password: "not it")) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .wrongPassword)
        }
    }

    func testAlteredExportIsRefused() throws {
        let manifest = try manifest()
        var bytes = try Data(contentsOf: fixture("vault.obscura"))
        bytes[bytes.count - 30] ^= 0x01
        let altered = directory.appendingPathComponent("altered.obscura")
        try bytes.write(to: altered)

        let archive = try ExportArchive(url: altered, password: manifest.vaultPassword)
        try archive.skipDatabase()
        XCTAssertThrowsError(try {
            for media in archive.index.mediaFiles {
                try archive.copyStoredFile(size: media.dataSize, to: nil)
                try archive.copyStoredFile(size: media.thumbnailSize, to: nil)
            }
        }())
    }

    func testExportHeaderLayout() throws {
        let header = try ExportHeader(parsing: Data(contentsOf: fixture("vault.obscura")))
        XCTAssertEqual(header.version, 1)
        XCTAssertEqual(header.kdfIterations, 600_000)
        XCTAssertEqual(header.salt.count, 32)
        XCTAssertEqual(header.noncePrefix.count, 4)
    }
}
