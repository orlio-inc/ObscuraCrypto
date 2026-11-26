// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CryptoKit
import Foundation

/// The header of a chunked media file: 57 bytes in version 2, which new
/// files are written in, and 25 in version 1.
///
/// ```
/// offset  size  field
///      0     4  magic, "OBCM"
///      4     1  version, 0x02 (0x01 for files written before ObscuraCrypto 1.2.0)
///      5     4  nonce prefix, random per file
///      9     8  total plaintext length, big-endian UInt64
///     17     4  plaintext bytes per chunk, big-endian UInt32 (1 MiB by default)
///     21     4  flags, big-endian UInt32; bit 0 set means a folder layer
///     25    32  key salt, random per file (version 2 only)
/// ```
///
/// Chunks follow at fixed offsets, so chunk `i` starts at
/// `byteCount + i × (chunkSize + overhead)`. Each chunk is AES-GCM combined,
/// `nonce || ciphertext || tag`; only the last can be shorter.
///
/// Nonces are derived, not random: `noncePrefix (4) || i (8, big-endian)`.
/// The index keeps chunks apart. A folder layer seals each master-encrypted
/// chunk again with the folder key, numbering its nonces on from `chunkCount`
/// so the two layers never share one; its chunks carry 56 bytes of overhead
/// instead of 28.
///
/// Version 2 also marks the end. The master layer of a file's last chunk
/// sets the counter's top bit (`lastChunkFlag`), and a file always has at
/// least one chunk (an empty file one empty chunk). A file cut short at a
/// chunk boundary, with its recorded length changed to match, ends on an
/// unmarked chunk and is refused; in version 1 it opened, shorter.
///
/// What keeps files apart differs by version. Version 1 seals every file
/// under the vault's keys themselves, so two files are kept apart only by
/// their 4-byte prefixes, and two that draw the same one (about 1 in 90 for
/// 10,000 files under one key) reuse each other's nonces. Version 2 seals
/// each file under keys of its own, derived from the vault's keys and the
/// file's random salt (`ChunkedMediaCipher`), so files never share a key and
/// the prefix no longer carries that weight.
public struct ChunkedMediaHeader: Sendable, Equatable {
    /// What a reader needs to have read to parse a header of any version.
    public static let maximumSize = 57
    public static let magic = Data("OBCM".utf8)
    /// The version new files are written in.
    public static let currentVersion: UInt8 = 0x02
    public static let defaultChunkSize: UInt32 = 1_048_576
    /// The largest chunk a reader takes, so a made-up header cannot ask for
    /// gigabytes of memory per chunk (the JVM cannot hold a chunk over 2 GB
    /// at all). Writers use 1 MB.
    public static let maximumChunkSize: UInt32 = 1 << 30
    public static let noncePrefixSize = 4
    public static let keySaltSize = 32
    static let folderLayerFlag: UInt32 = 0x01

    /// The size of a version 1 header, the only version before 1.2.0.
    @available(*, deprecated, message: "a version 1 header's size: read maximumSize bytes to parse any header, and use byteCount for where its chunks start")
    public static let size = 25
    /// The version files were written in before 1.2.0.
    @available(*, deprecated, renamed: "currentVersion", message: "the version 1.1.0 and earlier wrote; a header's own is formatVersion")
    public static let version: UInt8 = 0x01

    public let formatVersion: UInt8
    public let noncePrefix: Data
    /// The salt each layer's key is derived with; nil in version 1, which
    /// uses the vault's keys as they are.
    public let keySalt: Data?
    public let totalPlaintextSize: UInt64
    public let chunkPlaintextSize: UInt32
    public let flags: UInt32

    /// A version 1 header, as files written before 1.2.0 have. New files
    /// get a version 2 header from `make`, and a rewrite that adds or removes
    /// a folder layer keeps its file's header with `settingFolderLayer`:
    /// building the rewritten header with this instead would drop a version
    /// 2 file's salt and leave it unopenable.
    @available(*, deprecated, message: "makes a version 1 header: use settingFolderLayer(_:) to change a file's folder layer, make(...) for a new file, or init(parsing:)")
    public init(noncePrefix: Data, totalPlaintextSize: UInt64, chunkPlaintextSize: UInt32, flags: UInt32) throws {
        try self.init(formatVersion: 0x01, noncePrefix: noncePrefix, keySalt: nil,
                      totalPlaintextSize: totalPlaintextSize, chunkPlaintextSize: chunkPlaintextSize, flags: flags)
    }

    init(formatVersion: UInt8, noncePrefix: Data, keySalt: Data?,
         totalPlaintextSize: UInt64, chunkPlaintextSize: UInt32, flags: UInt32) throws {
        switch (formatVersion, keySalt) {
        case (0x01, nil): break
        case (0x02, let salt?) where salt.count == Self.keySaltSize: break
        case (0x01, _), (0x02, _):
            throw ObscuraCryptoError.invalidChunkedHeader("key salt does not match version \(formatVersion)")
        default:
            throw ObscuraCryptoError.invalidChunkedHeader(String(format: "version 0x%02x, expected 0x01 or 0x02", formatVersion))
        }
        guard noncePrefix.count == Self.noncePrefixSize else {
            throw ObscuraCryptoError.invalidChunkedHeader("nonce prefix is not 4 bytes")
        }
        guard chunkPlaintextSize > 0 else {
            throw ObscuraCryptoError.invalidChunkedHeader("chunk size is zero")
        }
        guard chunkPlaintextSize <= Self.maximumChunkSize else {
            throw ObscuraCryptoError.invalidChunkedHeader("chunk size above 1 GiB")
        }
        // Version 2 defines bit 0 only. The flags are not sealed into the
        // chunks, so a reader that let the others pass would open a file
        // whose header had been changed.
        guard formatVersion == 0x01 || flags & ~Self.folderLayerFlag == 0 else {
            throw ObscuraCryptoError.invalidChunkedHeader(String(format: "flags 0x%08x, only bit 0 is defined", flags))
        }
        // Every size and offset derived from the header has to fit in an Int.
        // Checked here, once, with overflow-reporting arithmetic, so that the
        // plain arithmetic in the properties below can never trap: a header
        // claiming an impossible length is refused as invalid instead of
        // crashing whoever opened the file.
        guard Self.checkedFileSize(formatVersion: formatVersion,
                                   totalPlaintextSize: totalPlaintextSize, chunkPlaintextSize: chunkPlaintextSize,
                                   hasFolderLayer: flags & Self.folderLayerFlag != 0) != nil else {
            throw ObscuraCryptoError.invalidChunkedHeader("its length is too large to be a real file")
        }
        self.formatVersion = formatVersion
        self.noncePrefix = noncePrefix
        self.keySalt = keySalt
        self.totalPlaintextSize = totalPlaintextSize
        self.chunkPlaintextSize = chunkPlaintextSize
        self.flags = flags
    }

    /// A header for a new file: the current version, with a fresh random
    /// nonce prefix and key salt.
    ///
    /// The salt is what keeps two files encrypted under the same master key
    /// from ever sharing a key, and so a nonce, so it is always drawn here,
    /// from the system generator, and never supplied by a caller.
    public static func make(
        totalPlaintextSize: UInt64,
        chunkPlaintextSize: UInt32 = defaultChunkSize,
        hasFolderLayer: Bool = false
    ) throws -> ChunkedMediaHeader {
        try make(totalPlaintextSize: totalPlaintextSize, chunkPlaintextSize: chunkPlaintextSize,
                 hasFolderLayer: hasFolderLayer, formatVersion: currentVersion)
    }

    /// `make` in a chosen version: version 1 only for tests and fixtures that
    /// need a file as older releases wrote it.
    static func make(
        totalPlaintextSize: UInt64, chunkPlaintextSize: UInt32, hasFolderLayer: Bool, formatVersion: UInt8
    ) throws -> ChunkedMediaHeader {
        try ChunkedMediaHeader(
            formatVersion: formatVersion,
            noncePrefix: try SecureRandom.bytes(ChunkedMediaHeader.noncePrefixSize),
            keySalt: formatVersion == 0x01 ? nil : try SecureRandom.bytes(ChunkedMediaHeader.keySaltSize),
            totalPlaintextSize: totalPlaintextSize,
            chunkPlaintextSize: chunkPlaintextSize,
            flags: hasFolderLayer ? folderLayerFlag : 0
        )
    }

    /// The same file with its folder layer flag set or cleared, for a rewrite
    /// that adds or removes the layer in place. Everything else, the version,
    /// prefix and salt included, stays: the master layer is not touched.
    public func settingFolderLayer(_ hasFolderLayer: Bool) throws -> ChunkedMediaHeader {
        try ChunkedMediaHeader(
            formatVersion: formatVersion, noncePrefix: noncePrefix, keySalt: keySalt,
            totalPlaintextSize: totalPlaintextSize, chunkPlaintextSize: chunkPlaintextSize,
            flags: hasFolderLayer ? flags | Self.folderLayerFlag : flags & ~Self.folderLayerFlag)
    }

    /// Parses the header at the start of `data`, which should hold
    /// `maximumSize` bytes or the whole file if it is shorter.
    public init(parsing data: Data) throws {
        guard data.count >= Self.byteCount(of: 0x01) else {
            throw ObscuraCryptoError.invalidChunkedHeader("shorter than \(Self.byteCount(of: 0x01)) bytes")
        }
        let bytes = Data(data.prefix(Self.maximumSize))
        guard bytes.prefix(4) == Self.magic else {
            throw ObscuraCryptoError.invalidChunkedHeader("missing OBCM magic")
        }
        let version = bytes[4]
        guard version == 0x01 || version == 0x02 else {
            throw ObscuraCryptoError.invalidChunkedHeader(String(format: "version 0x%02x, expected 0x01 or 0x02", version))
        }
        let size = Self.byteCount(of: version)
        guard bytes.count >= size else {
            throw ObscuraCryptoError.invalidChunkedHeader("shorter than \(size) bytes")
        }
        try self.init(
            formatVersion: version,
            noncePrefix: Data(bytes[5..<9]),
            keySalt: version == 0x01 ? nil : Data(bytes[25..<57]),
            totalPlaintextSize: bytes.bigEndianUInt64(at: 9),
            chunkPlaintextSize: bytes.bigEndianUInt32(at: 17),
            flags: bytes.bigEndianUInt32(at: 21)
        )
    }

    public func serialized() -> Data {
        var data = Data(capacity: byteCount)
        data.append(Self.magic)
        data.append(formatVersion)
        data.append(noncePrefix)
        data.appendBigEndian(totalPlaintextSize)
        data.appendBigEndian(chunkPlaintextSize)
        data.appendBigEndian(flags)
        if let keySalt { data.append(keySalt) }
        return data
    }

    /// This header's length, where its first chunk starts.
    public var byteCount: Int { Self.byteCount(of: formatVersion) }

    private static func byteCount(of version: UInt8) -> Int { version == 0x01 ? 25 : 57 }

    public var hasFolderLayer: Bool { flags & Self.folderLayerFlag != 0 }

    /// Version 2 files have one chunk at least: an empty file's is empty and
    /// carries the end mark.
    public var chunkCount: Int {
        Int(Self.chunkCount(formatVersion: formatVersion, totalPlaintextSize: totalPlaintextSize,
                            chunkPlaintextSize: chunkPlaintextSize))
    }

    /// Rounded up without adding first, so it cannot overflow.
    private static func chunkCount(formatVersion: UInt8, totalPlaintextSize: UInt64, chunkPlaintextSize: UInt32) -> UInt64 {
        let chunk = UInt64(chunkPlaintextSize)
        let count = totalPlaintextSize / chunk + (totalPlaintextSize % chunk == 0 ? 0 : 1)
        return formatVersion == 0x01 ? count : max(count, 1)
    }

    /// The file length a header describes, or nil if it does not fit in an Int.
    private static func checkedFileSize(formatVersion: UInt8, totalPlaintextSize: UInt64, chunkPlaintextSize: UInt32,
                                        hasFolderLayer: Bool) -> Int? {
        let overhead = UInt64(AESGCM.overhead * (hasFolderLayer ? 2 : 1))
        let count = chunkCount(formatVersion: formatVersion, totalPlaintextSize: totalPlaintextSize,
                               chunkPlaintextSize: chunkPlaintextSize)
        let (encrypted, overflowA) = count.multipliedReportingOverflow(by: overhead)
        let (withData, overflowB) = encrypted.addingReportingOverflow(totalPlaintextSize)
        let (total, overflowC) = withData.addingReportingOverflow(UInt64(byteCount(of: formatVersion)))
        guard !overflowA, !overflowB, !overflowC else { return nil }
        return Int(exactly: total)
    }

    /// Bytes each chunk adds: 28 for one layer, 56 for two.
    public var chunkOverhead: Int { AESGCM.overhead * (hasFolderLayer ? 2 : 1) }

    public func chunkOffset(_ index: Int) -> Int {
        byteCount + index * (Int(chunkPlaintextSize) + chunkOverhead)
    }

    public func plaintextSize(ofChunk index: Int) -> Int {
        guard index == chunkCount - 1 else { return Int(chunkPlaintextSize) }
        if totalPlaintextSize == 0 { return 0 }
        let remainder = Int(totalPlaintextSize % UInt64(chunkPlaintextSize))
        return remainder == 0 ? Int(chunkPlaintextSize) : remainder
    }

    public func encryptedSize(ofChunk index: Int) -> Int {
        plaintextSize(ofChunk: index) + chunkOverhead
    }

    /// How long a file with this header must be.
    public var fileSize: Int {
        chunkCount == 0 ? byteCount : chunkOffset(chunkCount - 1) + encryptedSize(ofChunk: chunkCount - 1)
    }

    /// `noncePrefix || counter`, the counter as 8 big-endian bytes.
    public func nonce(counter: UInt64) -> Data {
        var nonce = noncePrefix
        nonce.appendBigEndian(counter)
        return nonce
    }

    /// Set in the master-layer counter of a version 2 file's last chunk.
    static let lastChunkFlag: UInt64 = 1 << 63

    /// The nonce of chunk `index`'s master layer.
    public func masterNonce(forChunk index: Int) -> Data {
        masterNonce(forChunk: index, isLast: index == chunkCount - 1)
    }

    /// Version 2 marks the last chunk, so a file cut short is refused; the
    /// index alone never reaches the top bit.
    func masterNonce(forChunk index: Int, isLast: Bool) -> Data {
        nonce(counter: UInt64(index) | (formatVersion >= 0x02 && isLast ? Self.lastChunkFlag : 0))
    }

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
        self.master = try Self.layerKey(masterKey, header: header, info: Self.masterLayerInfo)
        self.folder = try folderKey.map { try Self.layerKey($0, header: header, info: Self.folderLayerInfo) }
    }

    static let masterLayerInfo = Data("OBCM v2 master layer".utf8)
    static let folderLayerInfo = Data("OBCM v2 folder layer".utf8)

    /// The key that seals one layer of this file. Version 1 uses the vault's
    /// key as it is. Version 2 derives one for the file: HKDF-SHA256 with the
    /// header's random salt, and an info string naming the layer, so the two
    /// layers' keys differ too.
    static func layerKey(_ key: SecureBytes, header: ChunkedMediaHeader, info: Data) throws -> SymmetricKey {
        guard let salt = header.keySalt else { return try key.symmetricKey }
        return HKDF<SHA256>.deriveKey(inputKeyMaterial: try key.symmetricKey, salt: salt, info: info, outputByteCount: 32)
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
        try encrypt(from: source, to: destination, masterKey: masterKey, folderKey: folderKey, chunkSize: chunkSize,
                    formatVersion: ChunkedMediaHeader.currentVersion)
    }

    /// `encrypt` in a chosen version: version 1 only for tests and fixtures.
    @discardableResult
    static func encrypt(
        from source: URL, to destination: URL, masterKey: SecureBytes, folderKey: SecureBytes?, chunkSize: UInt32,
        formatVersion: UInt8
    ) throws -> ChunkedMediaHeader {
        let totalSize = try FileManager.default.attributesOfItem(atPath: source.path)[.size] as? UInt64 ?? 0
        let header = try ChunkedMediaHeader.make(
            totalPlaintextSize: totalSize, chunkPlaintextSize: chunkSize, hasFolderLayer: folderKey != nil,
            formatVersion: formatVersion)

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
                // A pool per chunk, so each chunk's buffers are freed before
                // the next is read rather than when the whole file is done.
                try autoreleasepool {
                    // A version 2 empty file's one chunk reads nothing.
                    let size = header.plaintextSize(ofChunk: index)
                    guard let plaintext = size == 0 ? Data() : try input.read(upToCount: size),
                          plaintext.count == size else {
                        throw ObscuraCryptoError.chunkedFileSizeMismatch(expected: Int(totalSize), actual: -1)
                    }
                    try output.write(contentsOf: try cipher.seal(plaintext, chunk: index))
                }
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
        let header = try ChunkedMediaHeader(parsing: try handle.read(upToCount: ChunkedMediaHeader.maximumSize) ?? Data())
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
        FileManager.default.createFile(
            atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600])
        do {
            let input = try FileHandle(forReadingFrom: url)
            let output = try FileHandle(forWritingTo: temporary)
            defer {
                try? input.close()
                try? output.close()
            }
            for index in 0..<header.chunkCount {
                // See `ChunkedMediaEncryptor.encrypt`: freed chunk by chunk.
                try autoreleasepool {
                    try output.write(contentsOf: try readChunk(index, from: input, cipher: cipher))
                }
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
/// there in one step rather than deleting it first. The result keeps the
/// temporary file's permissions and protection, never the replaced file's:
/// a decrypted file stays owner-only even over one others could read.
func moveIntoPlace(_ temporary: URL, at destination: URL) throws {
    if FileManager.default.fileExists(atPath: destination.path) {
        _ = try FileManager.default.replaceItemAt(destination, withItemAt: temporary, options: .usingNewMetadataOnly)
    } else {
        try FileManager.default.moveItem(at: temporary, to: destination)
    }
}
