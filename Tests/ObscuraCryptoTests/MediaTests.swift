// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CryptoKit
import XCTest
@testable import ObscuraCrypto

final class MediaTests: XCTestCase {

    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func file(_ name: String, _ data: Data) throws -> URL {
        let url = directory.appendingPathComponent(name)
        try data.write(to: url)
        return url
    }

    private func randomData(_ count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: 0...255) })
    }

    // MARK: - Single-shot

    func testSingleShotRoundTrip() throws {
        let key = try SecureBytes.random(count: 32)
        let photo = randomData(10_000)
        let sealed = try SingleShotMedia.encrypt(photo, masterKey: key)
        XCTAssertEqual(sealed.count, photo.count + 28)
        XCTAssertEqual(try SingleShotMedia.decrypt(sealed, masterKey: key), photo)
    }

    func testSingleShotFolderLayerNeedsBothKeys() throws {
        let master = try SecureBytes.random(count: 32)
        let folder = try SecureBytes.random(count: 32)
        let photo = randomData(1_000)
        let sealed = try SingleShotMedia.encrypt(photo, masterKey: master, folderKey: folder)
        XCTAssertEqual(sealed.count, photo.count + 56)
        XCTAssertEqual(try SingleShotMedia.decrypt(sealed, masterKey: master, folderKey: folder), photo)
        XCTAssertThrowsError(try SingleShotMedia.decrypt(sealed, masterKey: master))
        XCTAssertThrowsError(try SingleShotMedia.decrypt(sealed, masterKey: master, folderKey: try SecureBytes.random(count: 32)))
    }

    /// A file an interrupted folder-password run never reached still opens.
    func testFolderKeyStillOpensAFileWithoutTheLayer() throws {
        let master = try SecureBytes.random(count: 32)
        let photo = randomData(1_000)
        let sealed = try SingleShotMedia.encrypt(photo, masterKey: master)
        XCTAssertEqual(try SingleShotMedia.decrypt(sealed, masterKey: master, folderKey: try SecureBytes.random(count: 32)), photo)
    }

    // MARK: - Chunked

    private func roundTrip(size: Int, chunkSize: UInt32, folder: Bool) throws {
        let master = try SecureBytes.random(count: 32)
        let folderKey = folder ? try SecureBytes.random(count: 32) : nil
        let plaintext = randomData(size)
        let source = try file("in.bin", plaintext)
        let encrypted = directory.appendingPathComponent("out.enc")
        let decrypted = directory.appendingPathComponent("out.bin")

        let header = try ChunkedMediaEncryptor.encrypt(
            from: source, to: encrypted, masterKey: master, folderKey: folderKey, chunkSize: chunkSize)
        XCTAssertEqual(try Data(contentsOf: encrypted).count, header.fileSize)

        let reader = try ChunkedMediaReader(url: encrypted)
        XCTAssertEqual(reader.header, header)
        try reader.decrypt(to: decrypted, masterKey: master, folderKey: folderKey)
        XCTAssertEqual(try Data(contentsOf: decrypted), plaintext)
    }

    func testChunkedEndingOnAPartialChunk() throws {
        try roundTrip(size: 10_000, chunkSize: 4_096, folder: false)
    }

    func testChunkedEndingExactlyOnAChunkBoundary() throws {
        try roundTrip(size: 8_192, chunkSize: 4_096, folder: false)
    }

    func testChunkedEmptyFile() throws {
        try roundTrip(size: 0, chunkSize: 4_096, folder: false)
    }

    func testChunkedWithFolderLayer() throws {
        try roundTrip(size: 10_000, chunkSize: 4_096, folder: true)
    }

    func testNonceIsPrefixThenBigEndianIndex() throws {
        let header = try ChunkedMediaHeader(
            formatVersion: 0x01, noncePrefix: Data([0xAA, 0xBB, 0xCC, 0xDD]), keySalt: nil,
            totalPlaintextSize: 10, chunkPlaintextSize: 4, flags: 1)
        XCTAssertEqual(header.chunkCount, 3)
        XCTAssertEqual(header.masterNonce(forChunk: 2), Data([0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0, 0, 0, 0, 2]))
        // The folder layer numbers on past the last chunk.
        XCTAssertEqual(header.folderNonce(forChunk: 0), Data([0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0, 0, 0, 0, 3]))
    }

    /// Every chunk authenticates on its own, so only the nonce check notices
    /// two of them trading places.
    func testSwappedChunksAreRejected() throws {
        let master = try SecureBytes.random(count: 32)
        let source = try file("in.bin", randomData(8_192))
        let encrypted = directory.appendingPathComponent("out.enc")
        let header = try ChunkedMediaEncryptor.encrypt(from: source, to: encrypted, masterKey: master, chunkSize: 4_096)

        var bytes = try Data(contentsOf: encrypted)
        let size = header.encryptedSize(ofChunk: 0)
        let first = bytes.subdata(in: header.chunkOffset(0) ..< header.chunkOffset(0) + size)
        let second = bytes.subdata(in: header.chunkOffset(1) ..< header.chunkOffset(1) + size)
        bytes.replaceSubrange(header.chunkOffset(0) ..< header.chunkOffset(0) + size, with: second)
        bytes.replaceSubrange(header.chunkOffset(1) ..< header.chunkOffset(1) + size, with: first)
        try bytes.write(to: encrypted)

        XCTAssertThrowsError(try ChunkedMediaReader(url: encrypted).readChunk(0, masterKey: master)) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .chunkNonceMismatch(0))
        }
    }

    func testTruncatedFileIsRefusedBeforeDecrypting() throws {
        let master = try SecureBytes.random(count: 32)
        let source = try file("in.bin", randomData(10_000))
        let encrypted = directory.appendingPathComponent("out.enc")
        try ChunkedMediaEncryptor.encrypt(from: source, to: encrypted, masterKey: master, chunkSize: 4_096)
        try Data(contentsOf: encrypted).dropLast(10).write(to: encrypted)
        XCTAssertThrowsError(try ChunkedMediaReader(url: encrypted))
    }

    func testFailedDecryptLeavesNoPartialPlaintext() throws {
        let master = try SecureBytes.random(count: 32)
        let source = try file("in.bin", randomData(10_000))
        let encrypted = directory.appendingPathComponent("out.enc")
        let header = try ChunkedMediaEncryptor.encrypt(from: source, to: encrypted, masterKey: master, chunkSize: 4_096)
        var bytes = try Data(contentsOf: encrypted)
        bytes[header.chunkOffset(2) + 20] ^= 0x01
        try bytes.write(to: encrypted)

        let output = directory.appendingPathComponent("out.bin")
        XCTAssertThrowsError(try ChunkedMediaReader(url: encrypted).decrypt(to: output, masterKey: master))
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
    }

    // MARK: - Per-chunk cipher

    private func header(size: UInt64, chunk: UInt32, folder: Bool) throws -> ChunkedMediaHeader {
        try ChunkedMediaHeader(
            formatVersion: 0x01, noncePrefix: Data([1, 2, 3, 4]), keySalt: nil,
            totalPlaintextSize: size, chunkPlaintextSize: chunk, flags: folder ? 1 : 0)
    }

    /// What setting and removing a folder password does to each chunk of a
    /// video already in the vault.
    func testAddingThenRemovingAFolderLayer() throws {
        let master = try SecureBytes.random(count: 32)
        let folder = try SecureBytes.random(count: 32)
        let plain = try header(size: 10, chunk: 4, folder: false)
        let layered = try header(size: 10, chunk: 4, folder: true)
        let chunk = randomData(4)

        let masterSealed = try ChunkedMediaCipher(header: plain, masterKey: master).seal(chunk, chunk: 1)
        let wrapped = try ChunkedMediaCipher(header: layered, masterKey: master, folderKey: folder)
            .addingFolderLayer(to: masterSealed, chunk: 1)
        XCTAssertEqual(wrapped.count, chunk.count + 56)
        XCTAssertEqual(try ChunkedMediaCipher(header: layered, masterKey: master, folderKey: folder).open(wrapped, chunk: 1), chunk)

        let unwrapped = try ChunkedMediaCipher(header: layered, masterKey: master, folderKey: folder)
            .removingFolderLayer(from: wrapped, chunk: 1)
        XCTAssertEqual(unwrapped, masterSealed)
    }

    func testFolderLayerIsCheckedAgainstTheRightKey() throws {
        let master = try SecureBytes.random(count: 32)
        let folder = try SecureBytes.random(count: 32)
        let layered = try header(size: 8, chunk: 4, folder: true)
        let stored = try ChunkedMediaCipher(header: layered, masterKey: master, folderKey: folder).seal(randomData(4), chunk: 0)
        XCTAssertTrue(try ChunkedMediaCipher(header: layered, masterKey: master, folderKey: folder).folderKeyOpens(stored, chunk: 0))
        XCTAssertFalse(try ChunkedMediaCipher(header: layered, masterKey: master, folderKey: try SecureBytes.random(count: 32))
            .folderKeyOpens(stored, chunk: 0))
    }

    /// The master layer's nonces come from the prefix and index alone, so they
    /// do not change with the length a header records.
    func testMasterLayerNoncesDoNotDependOnTheRecordedLength() throws {
        let master = try SecureBytes.random(count: 32)
        let chunks = [randomData(4), randomData(4), randomData(2)]
        let provisional = try header(size: 0, chunk: 4, folder: false)
        let sealer = try ChunkedMediaCipher(header: provisional, masterKey: master)
        let stored = try chunks.enumerated().map { try sealer.seal($0.element, chunk: $0.offset) }

        let final = try ChunkedMediaCipher(header: header(size: 10, chunk: 4, folder: false), masterKey: master)
        for (index, sealed) in stored.enumerated() {
            XCTAssertEqual(try final.open(sealed, chunk: index), chunks[index])
        }
    }

    // MARK: - Version 2: a key per file

    func testNewFilesAreVersionTwoWithASaltOfTheirOwn() throws {
        let master = try SecureBytes.random(count: 32)
        let source = try file("in.bin", randomData(10_000))
        let first = try ChunkedMediaEncryptor.encrypt(
            from: source, to: directory.appendingPathComponent("a.enc"), masterKey: master, chunkSize: 4_096)
        let second = try ChunkedMediaEncryptor.encrypt(
            from: source, to: directory.appendingPathComponent("b.enc"), masterKey: master, chunkSize: 4_096)
        XCTAssertEqual(first.formatVersion, 0x02)
        XCTAssertEqual(first.byteCount, 57)
        XCTAssertEqual(first.keySalt?.count, 32)
        XCTAssertNotEqual(first.keySalt, second.keySalt)
        XCTAssertEqual(try ChunkedMediaReader(url: directory.appendingPathComponent("a.enc")).header, first)
        XCTAssertEqual(first.fileSize, 57 + 10_000 + 3 * 28)
    }

    /// The weakness version 2 removes: two version 1 files that drew the same
    /// prefix seal their chunks under the same key and nonce. Under version 2
    /// the same prefix does no harm, as each file has keys of its own.
    func testTheSamePrefixNoLongerMeansTheSameKeyAndNonce() throws {
        let master = try SecureBytes.random(count: 32)
        let folder = try SecureBytes.random(count: 32)
        let chunk = randomData(4)
        func sealed(_ version: UInt8) throws -> Data {
            let header = try ChunkedMediaHeader(
                formatVersion: version, noncePrefix: Data([9, 9, 9, 9]),
                keySalt: version == 0x01 ? nil : try SecureBytes.random(count: 32).withUnsafeBytes { Data($0) },
                totalPlaintextSize: 4, chunkPlaintextSize: 4, flags: 1)
            return try ChunkedMediaCipher(header: header, masterKey: master, folderKey: folder).seal(chunk, chunk: 0)
        }
        XCTAssertEqual(try sealed(0x01), try sealed(0x01))
        XCTAssertNotEqual(try sealed(0x02), try sealed(0x02))
    }

    /// The derivation, pinned to vectors computed outside Swift (Python's
    /// hmac, RFC 5869), so the Kotlin library can be held to the same values.
    func testLayerKeysMatchTheFormatsTestVectors() throws {
        let key = SecureBytes(copying: Data(0..<32))
        let header = try ChunkedMediaHeader(
            formatVersion: 0x02, noncePrefix: Data([0xAA, 0xBB, 0xCC, 0xDD]), keySalt: Data(32..<64),
            totalPlaintextSize: 4, chunkPlaintextSize: 4, flags: 0)
        func hex(_ key: SymmetricKey) -> String { key.withUnsafeBytes { $0.map { String(format: "%02x", $0) }.joined() } }
        XCTAssertEqual(hex(try ChunkedMediaCipher.layerKey(key, header: header, info: ChunkedMediaCipher.masterLayerInfo)),
                       "d676bf9cc865de745fe168ae88fc29317550a8226bc3ccffcf6129972991f27b")
        XCTAssertEqual(hex(try ChunkedMediaCipher.layerKey(key, header: header, info: ChunkedMediaCipher.folderLayerInfo)),
                       "acd57362adb473b5f8a1bdc93b87539be70ca8cf017c719f11e4155ddf38d831")

        // And a chunk sealed by the cipher opens with plain AES-GCM under the
        // vector's key, with the nonce the format gives it: the only chunk is
        // the last, so its counter carries the end mark.
        let stored = try ChunkedMediaCipher(header: header, masterKey: key).seal(Data([1, 2, 3, 4]), chunk: 0)
        let derived = SymmetricKey(data: Data(hexString: "d676bf9cc865de745fe168ae88fc29317550a8226bc3ccffcf6129972991f27b"))
        let box = try AES.GCM.SealedBox(combined: stored)
        XCTAssertEqual(Data(box.nonce), Data([0xAA, 0xBB, 0xCC, 0xDD, 0x80, 0, 0, 0, 0, 0, 0, 0]))
        XCTAssertEqual(try AES.GCM.open(box, using: derived), Data([1, 2, 3, 4]))
    }

    /// The salt is not authenticated by any tag, but a changed one derives
    /// other keys, so nothing opens.
    func testAChangedSaltOpensNothing() throws {
        let master = try SecureBytes.random(count: 32)
        let encrypted = directory.appendingPathComponent("out.enc")
        try ChunkedMediaEncryptor.encrypt(from: file("in.bin", randomData(10_000)), to: encrypted, masterKey: master, chunkSize: 4_096)
        var bytes = try Data(contentsOf: encrypted)
        bytes[40] ^= 0x01
        try bytes.write(to: encrypted)
        XCTAssertThrowsError(try ChunkedMediaReader(url: encrypted).readChunk(0, masterKey: master)) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .authenticationFailed)
        }
    }

    /// Version 2 marks its last chunk: cut short at a chunk boundary, with
    /// the recorded length lowered to match, a file is refused. Version 1
    /// has no mark, and such a file opens shorter.
    func testAFileCutShortIsRefusedInVersionTwo() throws {
        for version: UInt8 in [0x01, 0x02] {
            let master = try SecureBytes.random(count: 32)
            let encrypted = directory.appendingPathComponent("cut-\(version).enc")
            let header = try ChunkedMediaEncryptor.encrypt(
                from: file("in.bin", randomData(10_000)), to: encrypted, masterKey: master, folderKey: nil,
                chunkSize: 4_096, formatVersion: version)
            var bytes = try Data(contentsOf: encrypted)
            bytes = bytes.prefix(header.chunkOffset(2))
            bytes.replaceSubrange(9..<17, with: withUnsafeBytes(of: UInt64(8_192).bigEndian) { Data($0) })
            try bytes.write(to: encrypted)
            let output = directory.appendingPathComponent("out-\(version).bin")
            if version == 0x01 {
                XCTAssertNoThrow(try ChunkedMediaReader(url: encrypted).decrypt(to: output, masterKey: master))
            } else {
                XCTAssertThrowsError(try ChunkedMediaReader(url: encrypted).decrypt(to: output, masterKey: master)) {
                    XCTAssertEqual($0 as? ObscuraCryptoError, .chunkNonceMismatch(1))
                }
            }
        }
    }

    /// An empty version 2 file has one empty chunk, carrying the end mark,
    /// so a file cut down to its header alone does not pass for empty.
    func testAnEmptyFileHasOneMarkedChunk() throws {
        let master = try SecureBytes.random(count: 32)
        let encrypted = directory.appendingPathComponent("empty.enc")
        let header = try ChunkedMediaEncryptor.encrypt(
            from: file("empty.bin", Data()), to: encrypted, masterKey: master, chunkSize: 4_096)
        XCTAssertEqual(header.chunkCount, 1)
        XCTAssertEqual(header.plaintextSize(ofChunk: 0), 0)
        XCTAssertEqual(try Data(contentsOf: encrypted).count, 57 + 28)
        let output = directory.appendingPathComponent("empty.out")
        try ChunkedMediaReader(url: encrypted).decrypt(to: output, masterKey: master)
        XCTAssertEqual(try Data(contentsOf: output), Data())

        try Data(contentsOf: encrypted).prefix(57).write(to: encrypted)
        XCTAssertThrowsError(try ChunkedMediaReader(url: encrypted)) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .chunkedFileSizeMismatch(expected: 85, actual: 57))
        }
    }

    /// The end mark is the counter's top bit in the master layer only.
    func testTheLastChunkIsMarkedInTheMasterNonce() throws {
        let header = try ChunkedMediaHeader(
            formatVersion: 0x02, noncePrefix: Data([0xAA, 0xBB, 0xCC, 0xDD]), keySalt: Data(32..<64),
            totalPlaintextSize: 10, chunkPlaintextSize: 4, flags: 1)
        XCTAssertEqual(header.masterNonce(forChunk: 1), Data([0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0, 0, 0, 0, 1]))
        XCTAssertEqual(header.masterNonce(forChunk: 2), Data([0xAA, 0xBB, 0xCC, 0xDD, 0x80, 0, 0, 0, 0, 0, 0, 2]))
        XCTAssertEqual(header.folderNonce(forChunk: 2), Data([0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0, 0, 0, 0, 5]))
    }

    func testVersionOneFilesStillRoundTrip() throws {
        let master = try SecureBytes.random(count: 32)
        let folder = try SecureBytes.random(count: 32)
        let plaintext = randomData(10_000)
        let encrypted = directory.appendingPathComponent("old.enc")
        let header = try ChunkedMediaEncryptor.encrypt(
            from: file("in.bin", plaintext), to: encrypted, masterKey: master, folderKey: folder, chunkSize: 4_096,
            formatVersion: 0x01)
        XCTAssertEqual(header.formatVersion, 0x01)
        XCTAssertNil(header.keySalt)
        XCTAssertEqual(header.byteCount, 25)
        XCTAssertEqual(try Data(contentsOf: encrypted).count, 25 + 10_000 + 3 * 56)
        let output = directory.appendingPathComponent("out.bin")
        try ChunkedMediaReader(url: encrypted).decrypt(to: output, masterKey: master, folderKey: folder)
        XCTAssertEqual(try Data(contentsOf: output), plaintext)
    }

    /// Setting and removing a folder password rewrites a file's chunks in
    /// place; the file keeps its version, prefix and salt, so its master
    /// layer is the same bytes before and after.
    func testFolderLayerComesAndGoesInEitherVersion() throws {
        for version: UInt8 in [0x01, 0x02] {
            let master = try SecureBytes.random(count: 32)
            let folder = try SecureBytes.random(count: 32)
            let plain = try ChunkedMediaHeader.make(
                totalPlaintextSize: 10, chunkPlaintextSize: 4, hasFolderLayer: false, formatVersion: version)
            let layered = try plain.settingFolderLayer(true)
            XCTAssertTrue(layered.hasFolderLayer)
            XCTAssertEqual(layered.formatVersion, version)
            XCTAssertEqual(layered.keySalt, plain.keySalt)
            XCTAssertEqual(layered.noncePrefix, plain.noncePrefix)
            XCTAssertEqual(try layered.settingFolderLayer(false), plain)

            let chunk = randomData(4)
            let masterSealed = try ChunkedMediaCipher(header: plain, masterKey: master).seal(chunk, chunk: 1)
            let wrapped = try ChunkedMediaCipher(header: layered, masterKey: master, folderKey: folder)
                .addingFolderLayer(to: masterSealed, chunk: 1)
            XCTAssertEqual(try ChunkedMediaCipher(header: layered, masterKey: master, folderKey: folder).open(wrapped, chunk: 1), chunk)
            XCTAssertEqual(try ChunkedMediaCipher(header: layered, masterKey: master, folderKey: folder)
                .removingFolderLayer(from: wrapped, chunk: 1), masterSealed)
        }
    }

    func testHeadersOfEitherVersionParseFromAMaximumSizeRead() throws {
        for version: UInt8 in [0x01, 0x02] {
            let header = try ChunkedMediaHeader.make(
                totalPlaintextSize: 10_000, chunkPlaintextSize: 4_096, hasFolderLayer: true, formatVersion: version)
            let bytes = header.serialized()
            XCTAssertEqual(bytes.count, header.byteCount)
            XCTAssertEqual(try ChunkedMediaHeader(parsing: bytes + randomData(100)), header)
        }
        let cut = try ChunkedMediaHeader.make(totalPlaintextSize: 10, chunkPlaintextSize: 4).serialized().prefix(40)
        XCTAssertThrowsError(try ChunkedMediaHeader(parsing: cut)) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .invalidChunkedHeader("shorter than 57 bytes"))
        }
        var future = try ChunkedMediaHeader.make(totalPlaintextSize: 10, chunkPlaintextSize: 4).serialized()
        future[4] = 0x03
        XCTAssertThrowsError(try ChunkedMediaHeader(parsing: future)) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .invalidChunkedHeader("version 0x03, expected 0x01 or 0x02"))
        }
    }

    /// A made-up header asking for chunks of gigabytes is refused before
    /// anything is allocated for one.
    func testChunksAbove1GiBAreRefused() throws {
        var bytes = try ChunkedMediaHeader.make(totalPlaintextSize: 10, chunkPlaintextSize: 4).serialized()
        bytes.replaceSubrange(17..<21, with: [0x80, 0, 0, 0])
        XCTAssertThrowsError(try ChunkedMediaHeader(parsing: bytes)) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .invalidChunkedHeader("chunk size above 1 GiB"))
        }
        XCTAssertNoThrow(try ChunkedMediaHeader.make(totalPlaintextSize: 10, chunkPlaintextSize: 1 << 30))
    }

    /// Version 2 defines one flag. The flags are not sealed into the chunks,
    /// so any other bit set means the header was changed. Version 1 files
    /// read as they always did.
    func testVersionTwoRefusesFlagsItDoesNotDefine() throws {
        var bytes = try ChunkedMediaHeader.make(totalPlaintextSize: 10, chunkPlaintextSize: 4, hasFolderLayer: true).serialized()
        bytes[24] |= 0x02
        XCTAssertThrowsError(try ChunkedMediaHeader(parsing: bytes)) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .invalidChunkedHeader("flags 0x00000003, only bit 0 is defined"))
        }
        var old = try ChunkedMediaHeader.make(
            totalPlaintextSize: 10, chunkPlaintextSize: 4, hasFolderLayer: false, formatVersion: 0x01).serialized()
        old[24] |= 0x02
        XCTAssertEqual(try ChunkedMediaHeader(parsing: old).flags, 0x02)
    }

    // MARK: - Hostile headers

    /// A 25-byte file whose header claims an impossible length. This crashed
    /// the reader with an arithmetic overflow; it must be refused instead.
    func testImpossibleLengthIsRefusedNotACrash() throws {
        var bytes = ChunkedMediaHeader.magic
        bytes.append(0x01)
        bytes.append(contentsOf: [0, 0, 0, 1])
        bytes.appendBigEndian(UInt64(0xFFFF_FFFF_FFFF_FFF0))
        bytes.appendBigEndian(UInt32(1))
        bytes.appendBigEndian(UInt32(0))

        XCTAssertThrowsError(try ChunkedMediaHeader(parsing: bytes)) {
            guard case .invalidChunkedHeader = $0 as? ObscuraCryptoError else {
                return XCTFail("expected invalidChunkedHeader, got \($0)")
            }
        }
        XCTAssertThrowsError(try ChunkedMediaReader(url: file("hostile.enc", bytes)))
    }

    func testLargeRealisticLengthIsStillAccepted() throws {
        let terabyte = UInt64(1) << 40
        let header = try ChunkedMediaHeader(
            formatVersion: 0x01, noncePrefix: Data([1, 2, 3, 4]), keySalt: nil,
            totalPlaintextSize: terabyte, chunkPlaintextSize: 1_048_576, flags: 1)
        XCTAssertEqual(header.chunkCount, 1_048_576)
        XCTAssertEqual(header.fileSize, 25 + Int(terabyte) + 1_048_576 * 56)
    }

    // MARK: - Output files

    func testFailedDecryptLeavesAnExistingFileUntouched() throws {
        let master = try SecureBytes.random(count: 32)
        let encrypted = directory.appendingPathComponent("out.enc")
        try ChunkedMediaEncryptor.encrypt(from: file("in.bin", randomData(10_000)), to: encrypted, masterKey: master, chunkSize: 4_096)

        let precious = try file("precious.txt", Data("keep me".utf8))
        XCTAssertThrowsError(try ChunkedMediaReader(url: encrypted).decrypt(to: precious, masterKey: try SecureBytes.random(count: 32)))
        XCTAssertEqual(try Data(contentsOf: precious), Data("keep me".utf8))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).filter { $0.hasSuffix(".partial") }, [])
    }

    func testSuccessfulDecryptReplacesAnExistingFile() throws {
        let master = try SecureBytes.random(count: 32)
        let plaintext = randomData(10_000)
        let encrypted = directory.appendingPathComponent("out.enc")
        try ChunkedMediaEncryptor.encrypt(from: file("in.bin", plaintext), to: encrypted, masterKey: master, chunkSize: 4_096)

        let target = try file("target.bin", Data("old".utf8))
        try ChunkedMediaReader(url: encrypted).decrypt(to: target, masterKey: master)
        XCTAssertEqual(try Data(contentsOf: target), plaintext)
    }

    func testFormatDetection() throws {
        XCTAssertEqual(MediaFormat.detect(Data("OBCM".utf8) + Data(count: 21)), .chunked)
        XCTAssertEqual(MediaFormat.detect(randomData(28)), .singleShot)
    }
}

private extension Data {
    init(hexString: String) {
        var bytes = [UInt8]()
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            bytes.append(UInt8(hexString[index..<next], radix: 16)!)
            index = next
        }
        self.init(bytes)
    }
}
