// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CryptoKit
import Foundation

/// The 25-byte header of a chunked media file.
///
/// ```
/// offset  size  field
///      0     4  magic, "OBCM"
///      4     1  version, 0x01
///      5     4  nonce prefix, random per file
///      9     8  total plaintext length, big-endian UInt64
///     17     4  plaintext bytes per chunk, big-endian UInt32 (1 MiB by default)
///     21     4  flags, big-endian UInt32; bit 0 set means a folder layer
/// ```
///
/// Chunks follow at fixed offsets, so chunk `i` starts at
/// `25 + i × (chunkSize + overhead)`. Each chunk is AES-GCM combined,
/// `nonce || ciphertext || tag`; only the last can be shorter.
///
/// Nonces are derived, not random: `noncePrefix (4) || i (8, big-endian)`.
/// The random prefix keeps files apart and the index keeps chunks apart.
/// A folder layer seals each master-encrypted chunk again with the folder key,
/// numbering its nonces on from `chunkCount` so the two layers never share
/// one; its chunks carry 56 bytes of overhead instead of 28.
public struct ChunkedMediaHeader: Sendable, Equatable {
    public static let size = 25
    public static let magic = Data("OBCM".utf8)
    public static let version: UInt8 = 0x01
    public static let defaultChunkSize: UInt32 = 1_048_576
    public static let noncePrefixSize = 4
    static let folderLayerFlag: UInt32 = 0x01

    public let noncePrefix: Data
    public let totalPlaintextSize: UInt64
    public let chunkPlaintextSize: UInt32
    public let flags: UInt32

    public init(noncePrefix: Data, totalPlaintextSize: UInt64, chunkPlaintextSize: UInt32, flags: UInt32) throws {
        guard noncePrefix.count == Self.noncePrefixSize else {
            throw ObscuraCryptoError.invalidChunkedHeader("nonce prefix is not 4 bytes")
        }
        guard chunkPlaintextSize > 0 else {
            throw ObscuraCryptoError.invalidChunkedHeader("chunk size is zero")
        }
        // Every size and offset derived from the header has to fit in an Int.
        // Checked here, once, with overflow-reporting arithmetic, so that the
        // plain arithmetic in the properties below can never trap: a header
        // claiming an impossible length is refused as invalid instead of
        // crashing whoever opened the file.
        guard Self.checkedFileSize(totalPlaintextSize: totalPlaintextSize, chunkPlaintextSize: chunkPlaintextSize,
                                   hasFolderLayer: flags & Self.folderLayerFlag != 0) != nil else {
            throw ObscuraCryptoError.invalidChunkedHeader("its length is too large to be a real file")
        }
        self.noncePrefix = noncePrefix
        self.totalPlaintextSize = totalPlaintextSize
        self.chunkPlaintextSize = chunkPlaintextSize
        self.flags = flags
    }

    /// A header for a new file, with a fresh random nonce prefix.
    ///
    /// The prefix is what keeps two files encrypted under the same master key
    /// from ever sharing a nonce, so it is always drawn here, from the system
    /// generator, and never supplied by a caller.
    public static func make(
        totalPlaintextSize: UInt64,
        chunkPlaintextSize: UInt32 = defaultChunkSize,
        hasFolderLayer: Bool = false
    ) throws -> ChunkedMediaHeader {
        try ChunkedMediaHeader(
            noncePrefix: try SecureRandom.bytes(ChunkedMediaHeader.noncePrefixSize),
            totalPlaintextSize: totalPlaintextSize,
            chunkPlaintextSize: chunkPlaintextSize,
            flags: hasFolderLayer ? folderLayerFlag : 0
        )
    }

    public init(parsing data: Data) throws {
        guard data.count >= Self.size else {
            throw ObscuraCryptoError.invalidChunkedHeader("shorter than \(Self.size) bytes")
        }
        let header = Data(data.prefix(Self.size))
        guard header.prefix(4) == Self.magic else {
            throw ObscuraCryptoError.invalidChunkedHeader("missing OBCM magic")
        }
        guard header[4] == Self.version else {
            throw ObscuraCryptoError.invalidChunkedHeader(String(format: "version 0x%02x, expected 0x01", header[4]))
        }
        try self.init(
            noncePrefix: Data(header[5..<9]),
            totalPlaintextSize: header.bigEndianUInt64(at: 9),
            chunkPlaintextSize: header.bigEndianUInt32(at: 17),
            flags: header.bigEndianUInt32(at: 21)
        )
    }

    public func serialized() -> Data {
        var data = Data(capacity: Self.size)
        data.append(Self.magic)
        data.append(Self.version)
        data.append(noncePrefix)
        data.appendBigEndian(totalPlaintextSize)
        data.appendBigEndian(chunkPlaintextSize)
        data.appendBigEndian(flags)
        return data
    }

    public var hasFolderLayer: Bool { flags & Self.folderLayerFlag != 0 }

    public var chunkCount: Int {
        Int(Self.chunkCount(totalPlaintextSize: totalPlaintextSize, chunkPlaintextSize: chunkPlaintextSize))
    }

    /// Rounded up without adding first, so it cannot overflow.
    private static func chunkCount(totalPlaintextSize: UInt64, chunkPlaintextSize: UInt32) -> UInt64 {
        let chunk = UInt64(chunkPlaintextSize)
        return totalPlaintextSize / chunk + (totalPlaintextSize % chunk == 0 ? 0 : 1)
    }

    /// The file length a header describes, or nil if it does not fit in an Int.
    private static func checkedFileSize(totalPlaintextSize: UInt64, chunkPlaintextSize: UInt32, hasFolderLayer: Bool) -> Int? {
        let overhead = UInt64(AESGCM.overhead * (hasFolderLayer ? 2 : 1))
        let count = chunkCount(totalPlaintextSize: totalPlaintextSize, chunkPlaintextSize: chunkPlaintextSize)
        let (encrypted, overflowA) = count.multipliedReportingOverflow(by: overhead)
        let (withData, overflowB) = encrypted.addingReportingOverflow(totalPlaintextSize)
        let (total, overflowC) = withData.addingReportingOverflow(UInt64(size))
        guard !overflowA, !overflowB, !overflowC else { return nil }
        return Int(exactly: total)
    }

    /// Bytes each chunk adds: 28 for one layer, 56 for two.
    public var chunkOverhead: Int { AESGCM.overhead * (hasFolderLayer ? 2 : 1) }

    public func chunkOffset(_ index: Int) -> Int {
        Self.size + index * (Int(chunkPlaintextSize) + chunkOverhead)
    }

    public func plaintextSize(ofChunk index: Int) -> Int {
        guard index == chunkCount - 1 else { return Int(chunkPlaintextSize) }
        let remainder = Int(totalPlaintextSize % UInt64(chunkPlaintextSize))
        return remainder == 0 ? Int(chunkPlaintextSize) : remainder
    }

    public func encryptedSize(ofChunk index: Int) -> Int {
        plaintextSize(ofChunk: index) + chunkOverhead
    }

    /// How long a file with this header must be.
    public var fileSize: Int {
        chunkCount == 0 ? Self.size : chunkOffset(chunkCount - 1) + encryptedSize(ofChunk: chunkCount - 1)
    }

    /// `noncePrefix || counter`, the counter as 8 big-endian bytes.
    public func nonce(counter: UInt64) -> Data {
        var nonce = noncePrefix
        nonce.appendBigEndian(counter)
        return nonce
    }

    /// The nonce of chunk `index`'s master layer.
    public func masterNonce(forChunk index: Int) -> Data { nonce(counter: UInt64(index)) }

    /// The nonce of chunk `index`'s folder layer, numbered on past the last chunk.
    public func folderNonce(forChunk index: Int) -> Data { nonce(counter: UInt64(chunkCount + index)) }
}

// MARK: - Per-chunk cipher

/// Seals and opens the chunks of one chunked file, with no file handling.
///
/// Everything cryptographic about the chunked format happens here: which key
/// seals which layer, which nonce each layer must carry, and in what order the
/// layers come off. Callers own the file I/O, so the same rules serve a
/// whole-file encryptor, a reader of single chunks, and a
/// rewrite that adds or removes a folder layer in place.
public struct ChunkedMediaCipher: Sendable {
    public let header: ChunkedMediaHeader
    private let master: SymmetricKey
    private let folder: SymmetricKey?

    /// `folderKey` is needed to seal or open a file with a folder layer, and to
    /// add or remove one. Given for a file without the layer, it is not used.
    public init(header: ChunkedMediaHeader, masterKey: SecureBytes, folderKey: SecureBytes? = nil) throws {
        try AESGCM.checkKey(masterKey)
        if let folderKey { try AESGCM.checkKey(folderKey) }
        self.header = header
        self.master = masterKey.symmetricKey
        self.folder = folderKey?.symmetricKey
    }

    /// Seals chunk `index`: the master layer, then the folder layer if the
    /// header says the file has one.
    ///
    /// The master layer's nonce comes from the prefix and the index alone; the
    /// folder layer's also depends on the chunk count.
    public func seal(_ plaintext: Data, chunk index: Int) throws -> Data {
        let inner = try sealMaster(plaintext, chunk: index)
        return header.hasFolderLayer ? try sealFolder(inner, chunk: index) : inner
    }

    /// Opens chunk `index` as stored, checking that every layer carries the
    /// nonce its position requires.
    ///
    /// The tag proves a chunk is intact, but the nonce travels inside the
    /// chunk, so without this check a chunk moved to another position, or
    /// copied in from another file under the same key, would still open.
    public func open(_ stored: Data, chunk index: Int) throws -> Data {
        try openMaster(header.hasFolderLayer ? try openFolder(stored, chunk: index) : stored, chunk: index)
    }

    /// Wraps a master-sealed chunk in a folder layer, for a file gaining one.
    /// Opens the master layer first, so a damaged chunk is refused rather
    /// than sealed in.
    public func addingFolderLayer(to masterSealed: Data, chunk index: Int) throws -> Data {
        _ = try openMaster(masterSealed, chunk: index)
        return try sealFolder(masterSealed, chunk: index)
    }

    /// Takes the folder layer off a chunk, leaving it master-sealed.
    public func removingFolderLayer(from stored: Data, chunk index: Int) throws -> Data {
        try openFolder(stored, chunk: index)
    }

    /// Whether `folderKey` opens the folder layer of this stored chunk. A file
    /// whose layer was put there by a key that no longer exists keeps its flag
    /// but fails this.
    public func folderKeyOpens(_ stored: Data, chunk index: Int) -> Bool {
        (try? openFolder(stored, chunk: index)) != nil
    }

    // MARK: Layers

    private func sealMaster(_ plaintext: Data, chunk index: Int) throws -> Data {
        try checkIndex(index)
        return try AESGCM.seal(plaintext, key: master, nonce: try AES.GCM.Nonce(data: header.masterNonce(forChunk: index)))
    }

    private func sealFolder(_ inner: Data, chunk index: Int) throws -> Data {
        try checkIndex(index)
        guard let folder else { throw ObscuraCryptoError.authenticationFailed }
        return try AESGCM.seal(inner, key: folder, nonce: try AES.GCM.Nonce(data: header.folderNonce(forChunk: index)))
    }

    private func openMaster(_ sealed: Data, chunk index: Int) throws -> Data {
        try checkIndex(index)
        guard sealed.prefix(AESGCM.nonceSize) == header.masterNonce(forChunk: index) else {
            throw ObscuraCryptoError.chunkNonceMismatch(index)
        }
        return try AESGCM.open(sealed, key: master)
    }

    private func openFolder(_ stored: Data, chunk index: Int) throws -> Data {
        try checkIndex(index)
        guard let folder else { throw ObscuraCryptoError.authenticationFailed }
        guard stored.prefix(AESGCM.nonceSize) == header.folderNonce(forChunk: index) else {
            throw ObscuraCryptoError.chunkNonceMismatch(index)
        }
        return try AESGCM.open(stored, key: folder)
    }

    /// Refuses a negative index. Readers check the upper bound against the
    /// header before they get here.
    private func checkIndex(_ index: Int) throws {
        guard index >= 0 else { throw ObscuraCryptoError.chunkIndexOutOfRange(index) }
    }
}

// MARK: - Encrypting

public enum ChunkedMediaEncryptor {
    /// Encrypts `source` into a new chunked file at `destination`, one chunk
    /// in memory at a time. Returns the header written.
    ///
    /// Writes to a temporary file beside `destination` and moves it into
    /// place only when complete, so a failure never leaves a partial file.
    @discardableResult
    public static func encrypt(
        from source: URL,
        to destination: URL,
        masterKey: SecureBytes,
        folderKey: SecureBytes? = nil,
        chunkSize: UInt32 = ChunkedMediaHeader.defaultChunkSize
    ) throws -> ChunkedMediaHeader {
        let totalSize = try FileManager.default.attributesOfItem(atPath: source.path)[.size] as? UInt64 ?? 0
        let header = try ChunkedMediaHeader.make(
            totalPlaintextSize: totalSize, chunkPlaintextSize: chunkSize, hasFolderLayer: folderKey != nil)

        let temporary = destination.deletingLastPathComponent()
            .appendingPathComponent(".\(destination.lastPathComponent).\(UUID().uuidString).partial")
        FileManager.default.createFile(atPath: temporary.path, contents: nil)
        do {
            let input = try FileHandle(forReadingFrom: source)
            let output = try FileHandle(forWritingTo: temporary)
            defer {
                try? input.close()
                try? output.close()
            }
            try output.write(contentsOf: header.serialized())
            let cipher = try ChunkedMediaCipher(header: header, masterKey: masterKey, folderKey: folderKey)

            for index in 0..<header.chunkCount {
                guard let plaintext = try input.read(upToCount: header.plaintextSize(ofChunk: index)),
                      plaintext.count == header.plaintextSize(ofChunk: index) else {
                    throw ObscuraCryptoError.chunkedFileSizeMismatch(expected: Int(totalSize), actual: -1)
                }
                try output.write(contentsOf: try cipher.seal(plaintext, chunk: index))
            }
            try output.synchronize()
            try moveIntoPlace(temporary, at: destination)
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
        return header
    }
}

// MARK: - Decrypting

/// Reads and decrypts a chunked media file a chunk at a time.
public struct ChunkedMediaReader: Sendable {
    public let url: URL
    public let header: ChunkedMediaHeader

    /// Opens `url` and checks that its length matches its header, so a
    /// truncated or padded file is refused before any key is used.
    public init(url: URL) throws {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let header = try ChunkedMediaHeader(parsing: try handle.read(upToCount: ChunkedMediaHeader.size) ?? Data())
        let actual = Int(try handle.seekToEnd())
        guard actual == header.fileSize else {
            throw ObscuraCryptoError.chunkedFileSizeMismatch(expected: header.fileSize, actual: actual)
        }
        self.url = url
        self.header = header
    }

    /// Decrypts chunk `index`.
    ///
    /// Checks that each layer carries the nonce its position requires before
    /// trusting it. The authentication tag proves a chunk is intact, but the
    /// nonce is stored inside the chunk, so without this a chunk moved to a
    /// different position, or copied in from another file under the same key,
    /// would still decrypt.
    ///
    /// A file with a folder layer needs `folderKey`. Given a folder key, a
    /// file without the layer is read with the master key alone.
    public func readChunk(_ index: Int, masterKey: SecureBytes, folderKey: SecureBytes? = nil) throws -> Data {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        return try readChunk(index, from: handle, cipher: ChunkedMediaCipher(header: header, masterKey: masterKey, folderKey: folderKey))
    }

    /// Decrypts the whole file into `destination`, one chunk in memory at a time.
    ///
    /// Writes to a temporary file beside `destination` and moves it into place
    /// only once every chunk has decrypted, so a failure leaves no partial
    /// plaintext and never touches a file already at `destination`.
    public func decrypt(
        to destination: URL,
        masterKey: SecureBytes,
        folderKey: SecureBytes? = nil,
        progress: ((_ chunksDone: Int, _ chunkCount: Int) -> Void)? = nil
    ) throws {
        let cipher = try ChunkedMediaCipher(header: header, masterKey: masterKey, folderKey: folderKey)
        let temporary = destination.deletingLastPathComponent()
            .appendingPathComponent(".\(destination.lastPathComponent).\(UUID().uuidString).partial")
        FileManager.default.createFile(atPath: temporary.path, contents: nil)
        do {
            let input = try FileHandle(forReadingFrom: url)
            let output = try FileHandle(forWritingTo: temporary)
            defer {
                try? input.close()
                try? output.close()
            }
            for index in 0..<header.chunkCount {
                try output.write(contentsOf: try readChunk(index, from: input, cipher: cipher))
                progress?(index + 1, header.chunkCount)
            }
            try output.synchronize()
            try moveIntoPlace(temporary, at: destination)
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
    }

    private func readChunk(_ index: Int, from handle: FileHandle, cipher: ChunkedMediaCipher) throws -> Data {
        guard index >= 0, index < header.chunkCount else {
            throw ObscuraCryptoError.chunkIndexOutOfRange(index)
        }
        try handle.seek(toOffset: UInt64(header.chunkOffset(index)))
        let size = header.encryptedSize(ofChunk: index)
        guard let stored = try handle.read(upToCount: size), stored.count == size else {
            throw ObscuraCryptoError.chunkedFileSizeMismatch(expected: header.fileSize, actual: -1)
        }
        return try cipher.open(stored, chunk: index)
    }
}

/// Moves a finished temporary file to `destination`, replacing a file already
/// there in one step rather than deleting it first.
private func moveIntoPlace(_ temporary: URL, at destination: URL) throws {
    if FileManager.default.fileExists(atPath: destination.path) {
        _ = try FileManager.default.replaceItemAt(destination, withItemAt: temporary)
    } else {
        try FileManager.default.moveItem(at: temporary, to: destination)
    }
}
