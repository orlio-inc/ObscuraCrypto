// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import XCTest
@testable import ObscuraCrypto

/// Reads files the Obscura app itself wrote, which is what shows this package
/// reads exactly what the app writes rather than only what it writes itself.
///
/// The fixtures come from the app's own code, through the same calls it makes
/// to create a vault, save media and set a folder password. See
/// `Fixtures/manifest.json`.
final class AppCompatibilityTests: XCTestCase {

    private struct Manifest: Decodable {
        struct Folder: Decodable {
            let passwordSalt: String
            let passwordHash: String
            let folderKeyEncrypted: String
        }
        struct Sample: Decodable {
            let count: Int
            let seed: Int
            let chunkSize: UInt32?
        }
        let vaultPassword: String
        let folderPassword: String
        let databaseSize: UInt64
        let masterKeyFingerprint: String
        let folderKeyFingerprint: String
        let folder: Folder
        let photo: Sample
        let video: Sample
    }

    private func fixture(_ name: String) throws -> URL {
        try XCTUnwrap(Bundle.module.url(forResource: "Fixtures/\(name)", withExtension: nil), "missing fixture \(name)")
    }

    private func manifest() throws -> Manifest {
        try JSONDecoder().decode(Manifest.self, from: Data(contentsOf: fixture("manifest.json")))
    }

    /// The app's plaintext generator, so the fixtures need not carry it.
    private func plaintext(_ sample: Manifest.Sample) -> Data {
        Data((0..<sample.count).map { UInt8((($0 * 31) + sample.seed) % 251) })
    }

    private func masterKey(_ manifest: Manifest) throws -> SecureBytes {
        try VaultHeader(parsing: Data(contentsOf: fixture("vault.header"))).unlock(password: manifest.vaultPassword)
    }

    private func folderKey(_ manifest: Manifest) throws -> SecureBytes {
        try FolderProtection(
            salt: XCTUnwrap(Data(base64Encoded: manifest.folder.passwordSalt)),
            passwordHash: XCTUnwrap(Data(base64Encoded: manifest.folder.passwordHash)),
            wrappedFolderKey: XCTUnwrap(Data(base64Encoded: manifest.folder.folderKeyEncrypted))
        ).unlock(password: manifest.folderPassword)
    }

    func testUnlocksTheAppsVaultHeader() throws {
        let manifest = try manifest()
        let key = try masterKey(manifest)
        XCTAssertEqual(key.fingerprint, manifest.masterKeyFingerprint)
        let header = try VaultHeader(parsing: Data(contentsOf: fixture("vault.header")))
        XCTAssertEqual(try header.databaseSize(masterKey: key), manifest.databaseSize)
    }

    /// Byte for byte, so nothing the app puts in a header is lost or reordered.
    func testRewritesTheAppsHeaderIdentically() throws {
        let original = try Data(contentsOf: fixture("vault.header"))
        XCTAssertEqual(try VaultHeader(parsing: original).serialized(), original)
    }

    func testUnlocksTheAppsFolderKey() throws {
        let manifest = try manifest()
        XCTAssertEqual(try folderKey(manifest).fingerprint, manifest.folderKeyFingerprint)
    }

    func testDecryptsTheAppsSingleShotPhoto() throws {
        let manifest = try manifest()
        let sealed = try Data(contentsOf: fixture("photo.data.enc"))
        XCTAssertEqual(try SingleShotMedia.decrypt(sealed, masterKey: masterKey(manifest)), plaintext(manifest.photo))
    }

    func testDecryptsTheAppsFolderProtectedPhoto() throws {
        let manifest = try manifest()
        let sealed = try Data(contentsOf: fixture("photo-folder.data.enc"))
        XCTAssertEqual(
            try SingleShotMedia.decrypt(sealed, masterKey: masterKey(manifest), folderKey: folderKey(manifest)),
            plaintext(manifest.photo))
    }

    func testDecryptsTheAppsChunkedVideo() throws {
        let manifest = try manifest()
        try assertChunked("video.data.enc", manifest: manifest, folderKey: nil)
    }

    /// Also shows the app writes the nonces the format specifies, since the
    /// reader checks every one.
    func testDecryptsTheAppsFolderProtectedChunkedVideo() throws {
        let manifest = try manifest()
        try assertChunked("video-folder.data.enc", manifest: manifest, folderKey: folderKey(manifest))
    }

    private func assertChunked(_ name: String, manifest: Manifest, folderKey: SecureBytes?) throws {
        let reader = try ChunkedMediaReader(url: fixture(name))
        XCTAssertEqual(reader.header.chunkPlaintextSize, manifest.video.chunkSize)
        XCTAssertEqual(reader.header.hasFolderLayer, folderKey != nil)

        let output = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: output) }
        try reader.decrypt(to: output, masterKey: masterKey(manifest), folderKey: folderKey)
        XCTAssertEqual(try Data(contentsOf: output), plaintext(manifest.video))
    }
}
