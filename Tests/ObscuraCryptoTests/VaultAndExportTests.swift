// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CryptoKit
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

    /// `UUID(uuidString:)` stops at a NUL byte, so it passes a UUID with a
    /// path after it; a media ID is the 36 characters and nothing else.
    func testAMediaIDIsExactlyAUUID() {
        let id = "A3E42A38-8C9A-483D-BAE4-1AEE61FF133A"
        XCTAssertTrue(MediaExtraction.isMediaID(id))
        XCTAssertTrue(MediaExtraction.isMediaID(id.lowercased()))
        for bad in [id + "\u{0}/../../escape", id + " ", "{\(id)}", String(id.dropLast()), id.replacingOccurrences(of: "-", with: "")] {
            XCTAssertFalse(MediaExtraction.isMediaID(bad), bad)
        }
    }

    /// A link planted at the file's name, even one pointing nowhere, counts as taken.
    func testExtractionRefusesALinkAtTheName() throws {
        let manifest = try manifest()
        let target = directory.appendingPathComponent("elsewhere")
        try FileManager.default.createSymbolicLink(
            at: directory.appendingPathComponent("\(manifest.photo).jpg"), withDestinationURL: target)
        XCTAssertThrowsError(try MediaExtraction.extract(
            storedFile: stored(manifest.photo), id: manifest.photo, masterKey: masterKey(manifest), into: directory))
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
    }

    func testExtractedFilesAreReadableByTheirOwnerOnly() throws {
        let manifest = try manifest()
        guard case .extracted(let file) = try MediaExtraction.extract(
            storedFile: stored(manifest.video), id: manifest.video, masterKey: masterKey(manifest), into: directory) else {
            return XCTFail("video not extracted")
        }
        let mode = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? Int
        XCTAssertEqual(mode, 0o600)
    }

    // MARK: - Export

    func testExportUnpacksToTheSameFilesAndKey() throws {
        let manifest = try manifest()
        let archive = try ExportArchive(url: fixture("vault.obscura"), password: manifest.vaultPassword)
        XCTAssertEqual(try archive.index.unlockMasterKey(password: manifest.vaultPassword).fingerprint,
                       try masterKey(manifest).fingerprint)
        XCTAssertEqual(Set(archive.index.mediaFiles.map(\.id)), [manifest.photo, manifest.video, manifest.protectedPhoto])

        // The vault file comes out whole.
        let vaultFile = try Data(contentsOf: fixture(manifest.vaultFile))
        XCTAssertEqual(archive.index.databaseSize, Int64(vaultFile.count))
        XCTAssertEqual(try archive.read(vaultFile.count), vaultFile)

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

    // MARK: - Export, version 2

    /// The app's own export, written again by this package as version 2, reads back the same.
    func testARealExportRewrittenAsVersion2ReadsBackTheSame() throws {
        let manifest = try manifest()
        let source = try ExportArchive(url: fixture("vault.obscura"), password: manifest.vaultPassword)
        var files = [try source.read(Int(source.index.databaseSize))]
        for media in source.index.mediaFiles {
            files.append(try source.read(Int(media.dataSize)))
            files.append(try source.read(Int(media.thumbnailSize)))
        }
        XCTAssertTrue(try source.isAtEnd())

        let url = directory.appendingPathComponent("version2.obscura")
        let writer = try ExportWriter(url: url, password: "another password", manifest: source.manifestData)
        for file in files { try writer.write(file) }
        try writer.finish()

        var progress: [Int64] = []
        try ExportArchive.verify(url: url, password: "another password") { done, total in
            XCTAssertEqual(total, source.index.contentSize)
            progress.append(done)
        }
        XCTAssertEqual(progress, progress.sorted())
        XCTAssertEqual(progress.last, source.index.contentSize)

        let archive = try ExportArchive(url: url, password: "another password")
        XCTAssertEqual(archive.header.version, 2)
        XCTAssertEqual(archive.manifestData, source.manifestData)
        XCTAssertEqual(archive.index, source.index)
        XCTAssertEqual(try archive.index.unlockMasterKey(password: manifest.vaultPassword).fingerprint, try masterKey(manifest).fingerprint)
        for file in files { XCTAssertEqual(try archive.read(file.count), file) }
        XCTAssertTrue(try archive.isAtEnd())

        // Whole records, all one size, as many as the Padmé length needs: nothing in the file's length says how many files it holds.
        let size = try Data(contentsOf: url).count
        let recordBytes = ExportWriter.recordSize + AESGCM.overhead
        let content = 4 + source.manifestData.count + Int(source.index.contentSize)
        XCTAssertEqual((size - archive.header.byteCount) % recordBytes, 0)
        XCTAssertEqual((size - archive.header.byteCount) / recordBytes,
                       (SharedItemsFile.padme(content) + ExportWriter.recordSize - 1) / ExportWriter.recordSize)
        XCTAssertThrowsError(try ExportArchive(url: url, password: manifest.vaultPassword)) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .wrongPassword)
        }
    }

    func testVersion2HeaderLayout() throws {
        let url = directory.appendingPathComponent("layout.obscura")
        let writer = try ExportWriter(url: url, password: "pw", manifest: try vaultManifest(databaseSize: 0))
        try writer.finish()
        let bytes = try Data(contentsOf: url)
        XCTAssertEqual(bytes.prefix(4), Data("OBSV".utf8))
        XCTAssertEqual(Array(bytes[4..<16]), [0, 2, 0, 2, 0, 0, 0, 1, 0, 0x10, 0, 0], "a key block of one byte")
        XCTAssertEqual(bytes.subdata(in: 16..<48), writer.header.salt)
        XCTAssertEqual(bytes.bigEndianUInt32(at: 48), 600_000)
        XCTAssertEqual(bytes.subdata(in: 52..<56), writer.header.noncePrefix)
        let exportKey = try KeyDerivation.pbkdf2SHA256(password: "pw", salt: writer.header.salt, iterations: 600_000)
        // HKDF-SHA256 over the export key, salt 32 zero bytes, info "OBSV v2 key commitment".
        XCTAssertEqual(bytes.subdata(in: 56..<88),
                       HKDF<SHA256>.deriveKey(inputKeyMaterial: try exportKey.symmetricKey, salt: Data(count: 32),
                                              info: Data("OBSV v2 key commitment".utf8), outputByteCount: 32)
                           .withUnsafeBytes { Data($0) })
        XCTAssertEqual(bytes.subdata(in: 88..<96), Data(count: 8))
        XCTAssertEqual(bytes[96], 0, "no locks beside the password")
        let header = try ExportHeader(parsing: bytes)
        XCTAssertEqual(header.readableBy, 2)
        XCTAssertEqual(header.recordSize, 1_048_576)
        XCTAssertEqual(header.byteCount, 97)
        XCTAssertEqual(header.lockTypes, [])
    }

    /// Files share version 2 records: each still reads back as its own bytes, an empty one included.
    func testSmallRecordsAcrossFilesReadBackWhole() throws {
        let files = [Data(repeating: 1, count: 10), Data((0..<9_000).map { UInt8(truncatingIfNeeded: $0) }), Data(),
                     Data([7]), Data(repeating: 9, count: 4_096)]
        let media = """
            {"mediaId":"A3E42A38-8C9A-483D-BAE4-1AEE61FF133A","dataSize":\(files[1].count),"thumbSize":0},\
            {"mediaId":"B73D3715-51FA-4CFD-81F8-863C3D37D73F","dataSize":\(files[3].count),"thumbSize":\(files[4].count)}
            """
        let url = directory.appendingPathComponent("small.obscura")
        let writer = try ExportWriter(url: url, password: "pw", manifest: try vaultManifest(databaseSize: files[0].count, media: media),
                                      attributes: nil, rounds: KeyDerivation.vaultIterations, recordSize: 4_096)
        for file in files { try writer.write(file) }
        try writer.finish()

        let archive = try ExportArchive(url: url, password: "pw")
        XCTAssertEqual(archive.header.recordSize, 4_096)
        for (index, file) in files.enumerated() {
            let out = directory.appendingPathComponent("file\(index)")
            try archive.copyStoredFile(size: Int64(file.count), to: out)
            XCTAssertEqual(try Data(contentsOf: out), file)
        }
        XCTAssertTrue(try archive.isAtEnd())
    }

    func testTheWriterWritesExactlyWhatTheManifestLists() throws {
        let manifest = try vaultManifest(databaseSize: 10)
        let short = try ExportWriter(url: directory.appendingPathComponent("short.obscura"), password: "pw", manifest: manifest)
        try short.write(Data(count: 9))
        XCTAssertThrowsError(try short.finish())
        let long = try ExportWriter(url: directory.appendingPathComponent("long.obscura"), password: "pw", manifest: manifest)
        XCTAssertThrowsError(try long.write(Data(count: 11)))
        let hostile = try vaultManifest(databaseSize: 0, media: #"{"mediaId":"../../etc","dataSize":0,"thumbSize":0}"#)
        XCTAssertThrowsError(try ExportWriter(url: directory.appendingPathComponent("bad.obscura"), password: "pw", manifest: hostile))
    }

    func testANewerExportIsReportedAsSuch() throws {
        let url = directory.appendingPathComponent("newer.obscura")
        try ExportWriter(url: url, password: "pw", manifest: try vaultManifest(databaseSize: 0)).finish()
        var newer = try Data(contentsOf: url)
        newer[5] = 3
        newer[7] = 3
        XCTAssertThrowsError(try ExportHeader(parsing: newer)) { XCTAssertEqual($0 as? ObscuraCryptoError, .exportNewerVersion) }
        // A later version that a version 2 reader can still read opens.
        var compatible = try Data(contentsOf: url)
        compatible[5] = 3
        XCTAssertEqual(try ExportHeader(parsing: compatible).version, 3)
        var flagged = try Data(contentsOf: url)
        flagged[9] = 0x80
        XCTAssertThrowsError(try ExportHeader(parsing: flagged)) { XCTAssertEqual($0 as? ObscuraCryptoError, .exportNewerVersion) }
        var optional = try Data(contentsOf: url)
        optional[8] = 0x01
        XCTAssertEqual(try ExportHeader(parsing: optional).flags, 0x0100)
    }

    // MARK: - Hostile manifests, both versions

    private func vaultManifest(databaseSize: Int, media: String = "", extra: String = "") throws -> Data {
        let (header, _) = try VaultHeader.create(password: "pw")
        return Data(("{\"exportVersion\":1,\"vaultSalt\":\"\(header.salt.base64EncodedString())\"," +
            "\"encryptedMEK\":\"\(header.wrappedMasterKey.base64EncodedString())\",\"databaseSize\":\(databaseSize)," +
            "\"mediaFiles\":[\(media)]\(extra)}").utf8)
    }

    /// The manifest alone, in each version, written without the writer's own check of it, as a hostile file would be.
    private func exports(_ manifest: Data) throws -> [URL] {
        let salt = try KeyDerivation.makeSalt()
        let prefix = try SecureRandom.bytes(4)
        let exportKey = try KeyDerivation.pbkdf2SHA256(password: "pw", salt: salt, iterations: KeyDerivation.vaultIterations)
        let key = try exportKey.symmetricKey

        var check = prefix
        check.appendBigEndian(UInt64.max)
        var first = ExportHeader.magic
        first.appendBigEndian(UInt16(1))
        first.appendBigEndian(UInt16(0))
        first.append(salt)
        first.appendBigEndian(KeyDerivation.vaultIterations)
        first.append(try AES.GCM.seal(ExportHeader.verificationPlaintext, using: key, nonce: AES.GCM.Nonce(data: check)).tag)
        first.append(prefix)
        var nonce = prefix
        nonce.appendBigEndian(UInt64(0))
        let record = try AES.GCM.seal(manifest, using: key, nonce: AES.GCM.Nonce(data: nonce)).combined!
        first.appendBigEndian(UInt32(record.count))
        first.append(record)
        let version1 = directory.appendingPathComponent("hostile-1.obscura")
        try first.write(to: version1)

        let header = try ExportHeader.version2(salt: salt, rounds: KeyDerivation.vaultIterations, noncePrefix: prefix, recordSize: 4_096,
                                               keyCommitment: try ExportHeader.keyCommitment(exportKey))
        let version2 = directory.appendingPathComponent("hostile-2.obscura")
        FileManager.default.createFile(atPath: version2.path, contents: header.bytes)
        let handle = try FileHandle(forWritingTo: version2)
        try handle.seekToEnd()
        let sealer = RecordSealer(output: handle, key: try ExportHeader.recordKey(exportKey), prefix: prefix,
                                  associatedData: header.bytes, recordSize: 4_096,
                                  recordCount: (SharedItemsFile.padme(4 + manifest.count) + 4_095) / 4_096)
        var length = Data()
        length.appendBigEndian(UInt32(manifest.count))
        try sealer.append(length)
        try sealer.append(manifest)
        try sealer.finish(padding: 0)
        try handle.close()
        return [version1, version2]
    }

    private func assertRefused(_ manifest: Data, line: UInt = #line) throws {
        for url in try exports(manifest) {
            XCTAssertThrowsError(try ExportArchive(url: url, password: "pw"), line: line) {
                guard case .invalidExport? = $0 as? ObscuraCryptoError else { return XCTFail("\($0)", line: line) }
            }
        }
    }

    /// What the app writes, a date as seconds with a fraction, reads, as do brackets inside a string.
    func testAManifestAsTheAppWritesItOpens() throws {
        let extra = #","exportDate":785000000.123456,"scale":1e-3,"note":"[[[{{{\"]]]""#
        for url in try exports(try vaultManifest(databaseSize: 0, extra: extra)) {
            XCTAssertNoThrow(try ExportArchive(url: url, password: "pw"))
        }
    }

    /// What no JSON writer would write is refused, so one export never reads two ways.
    func testAManifestIsReadOneWayOnly() throws {
        let (header, _) = try VaultHeader.create(password: "pw")
        let salt = header.salt.base64EncodedString()
        let wrapped = header.wrappedMasterKey.base64EncodedString()
        let hostile = [
            // Two of one key: a reader taking the first and another the last would split the stream differently.
            #"{"exportVersion":1,"vaultSalt":"\#(salt)","encryptedMEK":"\#(wrapped)","databaseSize":0,"databaseSize":5,"mediaFiles":[]}"#,
            // A size as a string, and whole numbers written as decimals.
            #"{"exportVersion":1,"vaultSalt":"\#(salt)","encryptedMEK":"\#(wrapped)","databaseSize":"0","mediaFiles":[]}"#,
            #"{"exportVersion":1,"vaultSalt":"\#(salt)","encryptedMEK":"\#(wrapped)","databaseSize":0.0,"mediaFiles":[]}"#,
            #"{"exportVersion":1.0,"vaultSalt":"\#(salt)","encryptedMEK":"\#(wrapped)","databaseSize":0,"mediaFiles":[]}"#,
            // Base64 without its padding, and with a line break.
            #"{"exportVersion":1,"vaultSalt":"\#(salt.replacingOccurrences(of: "=", with: ""))","encryptedMEK":"\#(wrapped)","databaseSize":0,"mediaFiles":[]}"#,
            #"{"exportVersion":1,"vaultSalt":"\#(salt.prefix(8))\n\#(salt.dropFirst(8))","encryptedMEK":"\#(wrapped)","databaseSize":0,"mediaFiles":[]}"#,
            // Media IDs that differ only by case, which name one file where case is ignored.
            #"{"exportVersion":1,"vaultSalt":"\#(salt)","encryptedMEK":"\#(wrapped)","databaseSize":0,"mediaFiles":[{"mediaId":"A3E42A38-8C9A-483D-BAE4-1AEE61FF133A","dataSize":0,"thumbSize":0},{"mediaId":"a3e42a38-8c9a-483d-bae4-1aee61ff133a","dataSize":0,"thumbSize":0}]}"#,
        ]
        for json in hostile { try assertRefused(Data(json.utf8)) }
        for depth in [40, 100_000] {
            try assertRefused(try vaultManifest(databaseSize: 0, extra: #","x":"# + String(repeating: "[", count: depth) + String(repeating: "]", count: depth)))
        }
    }

    /// Sizes that add up past the largest number are refused, not added with a
    /// plain `+`, which would stop the app instead.
    func testSizesThatOverflowAreRefused() throws {
        let max = Int64.max
        try assertRefused(try vaultManifest(databaseSize: Int(max), media:
            #"{"mediaId":"A3E42A38-8C9A-483D-BAE4-1AEE61FF133A","dataSize":1,"thumbSize":0}"#))
        try assertRefused(try vaultManifest(databaseSize: 0, media:
            #"{"mediaId":"A3E42A38-8C9A-483D-BAE4-1AEE61FF133A","dataSize":\#(max),"thumbSize":\#(max)}"#))
    }

    // MARK: Key block

    /// A lock of a type no reader knows yet, such as a recovery key added in
    /// a later release, is passed over: the file opens with its password and
    /// reads whole, with no new version.
    func testALockOfAnUnknownTypeIsPassedOver() throws {
        let url = directory.appendingPathComponent("later.obscura")
        let lock = Data([0x09, 0x00, 0x05]) + Data("later".utf8)
        let writer = try ExportWriter(url: url, password: "pw", manifest: try vaultManifest(databaseSize: 3), attributes: nil,
                                      rounds: KeyDerivation.vaultIterations, recordSize: 4_096, keyBlock: Data([1]) + lock)
        try writer.write(Data([1, 2, 3]))
        try writer.finish()

        let archive = try ExportArchive(url: url, password: "pw")
        XCTAssertEqual(archive.header.lockTypes, [9])
        XCTAssertEqual(try archive.read(3), Data([1, 2, 3]))
        XCTAssertTrue(try archive.isAtEnd())
    }

    /// The key block is authenticated with the header: a lock changed, taken
    /// out or cut short is refused, never read past.
    func testAKeyBlockChangedOrCutShortIsRefused() throws {
        let url = directory.appendingPathComponent("locked.obscura")
        let lock = Data([0x09, 0x00, 0x05]) + Data("later".utf8)
        let writer = try ExportWriter(url: url, password: "pw", manifest: try vaultManifest(databaseSize: 0), attributes: nil,
                                      rounds: KeyDerivation.vaultIterations, recordSize: 4_096, keyBlock: Data([1]) + lock)
        try writer.finish()
        let original = try Data(contentsOf: url)

        var changed = original
        changed[96 + 1 + 3] ^= 0x01
        // Taken out: the count says none, the lock's bytes are left over.
        var removed = original
        removed[96] = 0
        // The length says more than the file holds.
        var cut = original.prefix(96 + 4)
        cut[10] = 0x10
        for (name, bytes) in [("changed", changed), ("removed", removed), ("cut", Data(cut))] {
            let tampered = directory.appendingPathComponent("\(name).obscura")
            try bytes.write(to: tampered)
            XCTAssertThrowsError(try ExportArchive.verify(url: tampered, password: "pw"), name) {
                guard case .invalidExport? = $0 as? ObscuraCryptoError else { return XCTFail("\(name): \($0)") }
            }
        }
    }
}
