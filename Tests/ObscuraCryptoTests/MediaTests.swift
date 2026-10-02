// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

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
            noncePrefix: Data([0xAA, 0xBB, 0xCC, 0xDD]), totalPlaintextSize: 10, chunkPlaintextSize: 4, flags: 1)
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
            noncePrefix: Data([1, 2, 3, 4]), totalPlaintextSize: size, chunkPlaintextSize: chunk, flags: folder ? 1 : 0)
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

    // MARK: - Hostile headers

    /// A 25-byte file whose header claims an impossible length. This crashed
    /// the reader with an arithmetic overflow; it must be refused instead.
    func testImpossibleLengthIsRefusedNotACrash() throws {
        var bytes = ChunkedMediaHeader.magic
        bytes.append(ChunkedMediaHeader.version)
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
            noncePrefix: Data([1, 2, 3, 4]), totalPlaintextSize: terabyte, chunkPlaintextSize: 1_048_576, flags: 1)
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
