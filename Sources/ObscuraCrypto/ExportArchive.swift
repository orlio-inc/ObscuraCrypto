// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CryptoKit
import Foundation

/// The unencrypted header of an `.obscura` export: 64 bytes in version 1, 96
/// in version 2, which this package writes.
///
/// Version 1:
/// ```
/// offset  size  field
///      0     4  magic, "OBSV"
///      4     2  version, big-endian UInt16, 1
///      6     2  flags, reserved
///      8    32  salt for the export password
///     40     4  PBKDF2-HMAC-SHA256 rounds, big-endian UInt32
///     44    16  password check: the AES-GCM tag of "OBSCURA_EXPORT_V1"
///     60     4  nonce prefix, random per file
/// ```
///
/// Version 2:
/// ```
/// offset  size  field
///      0     4  magic, "OBSV"
///      4     2  version, 2
///      6     2  readable by: the oldest reader version that opens the file, 2
///      8     2  flags: bits 0-7 must be understood, bits 8-15 may be ignored; none defined
///     10     2  key block length: bytes of the key block after the header (1 to 4,096)
///     12     4  record size: plaintext bytes in every record (1,048,576)
///     16    32  salt for the export password
///     48     4  PBKDF2-HMAC-SHA256 rounds
///     52     4  nonce prefix, random per file
///     56    32  key commitment, derived from the export key (below)
///     88     8  reserved, zero
///     96     n  key block: a lock count (1 byte), then each lock as
///               type (1) || body length (2, big-endian) || body
/// ```
///
/// The key block is room for more ways to open the file beside its
/// password, such as a vault's recovery key, added later without a new
/// version: a reader skips a lock of a type it does not know and opens the
/// file with its password as before. No type is defined yet, and writers
/// write none (a count of 0). The password, its salt, rounds and the key
/// commitment stay in the fixed header. The key block is part of the
/// header's `bytes`, so every record authenticates it too: a lock cannot be
/// added, removed or changed without every record failing.
///
/// A version 2 export key, `PBKDF2-HMAC-SHA256(password, salt, rounds)`, is
/// never used as it is. HKDF-SHA256 over it, with a salt of 32 zero bytes,
/// gives the record key (info "OBSV v2 records") and the key commitment
/// (info "OBSV v2 key commitment"), each 32 bytes.
public struct ExportHeader: Sendable, Equatable {
    /// Version 1's size, and what every reader reads first.
    public static let size = 64
    public static let version2Size = 96
    /// The most a version 2 key block may take.
    public static let maximumKeyBlock = 4_096
    /// Enough to hold the header of any version this package reads, its
    /// key block included.
    public static let maximumSize = version2Size + maximumKeyBlock
    public static let magic = Data("OBSV".utf8)
    /// The version this package writes, and the newest it reads.
    public static let version: UInt16 = 2
    static let verificationPlaintext = Data("OBSCURA_EXPORT_V1".utf8)
    static let keyCommitmentInfo = Data("OBSV v2 key commitment".utf8)
    static let recordKeyInfo = Data("OBSV v2 records".utf8)
    static let requiredFlags: UInt16 = 0x00FF
    /// The record sizes a version 2 reader accepts.
    static let recordSizes = 4_096...1_048_576

    public let version: UInt16
    /// The oldest reader version that opens the file: 1 for version 1.
    public let readableBy: UInt16
    public let flags: UInt16
    public let salt: Data
    public let kdfIterations: UInt32
    /// Version 1's password check; empty in version 2.
    public let verificationTag: Data
    public let noncePrefix: Data
    /// Version 2: plaintext bytes in every record. 0 in version 1, whose
    /// records vary in length.
    public let recordSize: Int
    /// Version 2's password check, which also commits the file to one key;
    /// empty in version 1.
    public let keyCommitment: Data
    /// Version 2: lock types in the key block, in file order. This package
    /// knows none yet and reads past them all; empty in version 1.
    public let lockTypes: [UInt8]
    /// The header as stored, a version 2 key block included. Every version 2
    /// record authenticates it.
    public let bytes: Data

    public var byteCount: Int { bytes.count }

    /// Parses the header at the start of `data`, which must hold all of it:
    /// 64 bytes for version 1, 96 and the key block for version 2.
    public init(parsing data: Data) throws {
        let data = Data(data)
        guard data.count >= Self.size else {
            throw ObscuraCryptoError.invalidExport("shorter than \(Self.size) bytes")
        }
        guard data.prefix(4) == Self.magic else {
            throw ObscuraCryptoError.invalidExport("missing OBSV magic")
        }
        version = data.bigEndianUInt16(at: 4)
        switch version {
        case 1:
            readableBy = 1
            flags = data.bigEndianUInt16(at: 6)
            salt = data.subdata(in: 8..<40)
            kdfIterations = data.bigEndianUInt32(at: 40)
            verificationTag = data.subdata(in: 44..<60)
            noncePrefix = data.subdata(in: 60..<64)
            recordSize = 0
            keyCommitment = Data()
            lockTypes = []
            bytes = data.prefix(Self.size)
        case 2...:
            // Later versions keep this layout and say what they need.
            readableBy = data.bigEndianUInt16(at: 6)
            guard readableBy >= 2, readableBy <= version else {
                throw ObscuraCryptoError.invalidExport("version \(version), readable by \(readableBy)")
            }
            guard readableBy <= Self.version else { throw ObscuraCryptoError.exportNewerVersion }
            guard data.count >= Self.version2Size else {
                throw ObscuraCryptoError.invalidExport("shorter than \(Self.version2Size) bytes")
            }
            flags = data.bigEndianUInt16(at: 8)
            guard flags & Self.requiredFlags == 0 else { throw ObscuraCryptoError.exportNewerVersion }
            recordSize = Int(data.bigEndianUInt32(at: 12))
            guard Self.recordSizes.contains(recordSize) else {
                throw ObscuraCryptoError.invalidExport("records of an impossible size")
            }
            salt = data.subdata(in: 16..<48)
            kdfIterations = data.bigEndianUInt32(at: 48)
            noncePrefix = data.subdata(in: 52..<56)
            keyCommitment = data.subdata(in: 56..<88)
            verificationTag = Data()
            let keyBlockLength = Int(data.bigEndianUInt16(at: 10))
            guard (1...Self.maximumKeyBlock).contains(keyBlockLength) else {
                throw ObscuraCryptoError.invalidExport("a key block of an impossible length")
            }
            guard data.count >= Self.version2Size + keyBlockLength else {
                throw ObscuraCryptoError.invalidExport("the file ends inside its key block")
            }
            lockTypes = try Self.lockTypes(in: data.subdata(in: Self.version2Size..<(Self.version2Size + keyBlockLength)))
            bytes = data.prefix(Self.version2Size + keyBlockLength)
        default:
            throw ObscuraCryptoError.invalidExport("version \(version)")
        }
    }

    /// The types of a key block's locks, every byte accounted for.
    static func lockTypes(in keyBlock: Data) throws -> [UInt8] {
        let cutShort = ObscuraCryptoError.invalidExport("the key block is cut short")
        var types: [UInt8] = []
        var offset = 1
        for _ in 0..<Int(keyBlock[keyBlock.startIndex]) {
            guard offset + 3 <= keyBlock.count else { throw cutShort }
            let length = Int(keyBlock.bigEndianUInt16(at: offset + 1))
            guard offset + 3 + length <= keyBlock.count else { throw cutShort }
            types.append(keyBlock[keyBlock.startIndex + offset])
            offset += 3 + length
        }
        guard offset == keyBlock.count else {
            throw ObscuraCryptoError.invalidExport("the key block has bytes left over")
        }
        return types
    }

    /// A version 2 header for a new export, with an empty key block.
    static func version2(salt: Data, rounds: UInt32, noncePrefix: Data, recordSize: Int, keyCommitment: Data,
                         keyBlock: Data = Data([0])) throws -> ExportHeader {
        var data = Self.magic
        data.appendBigEndian(Self.version)
        data.appendBigEndian(UInt16(2))
        data.appendBigEndian(UInt16(0))
        data.appendBigEndian(UInt16(keyBlock.count))
        data.appendBigEndian(UInt32(recordSize))
        data.append(salt)
        data.appendBigEndian(rounds)
        data.append(noncePrefix)
        data.append(keyCommitment)
        data.append(Data(count: Self.version2Size - data.count))
        data.append(keyBlock)
        return try ExportHeader(parsing: data)
    }

    /// What a version 2 header holds to check a password, and what ties the
    /// file to one key, since AES-GCM does not: 32 bytes HKDF derives from
    /// the export key.
    static func keyCommitment(_ exportKey: SecureBytes) throws -> Data {
        try KeyDerivation.subkeyBytes(of: exportKey, info: keyCommitmentInfo)
    }

    /// The key a version 2 export's records are sealed under, derived from
    /// the export key, which the commitment is made from.
    static func recordKey(_ exportKey: SecureBytes) throws -> SymmetricKey {
        try KeyDerivation.subkey(of: exportKey, info: recordKeyInfo)
    }

    /// Version 1: `noncePrefix || counter`, as in the chunked media format.
    /// Records count from 0; the password check uses the largest counter,
    /// `UInt64.max`.
    func nonce(counter: UInt64) -> Data {
        var nonce = noncePrefix
        nonce.appendBigEndian(counter)
        return nonce
    }
}

/// What an export's manifest says about its layout and keys, and nothing else.
///
/// The manifest is the app's JSON description of the exported vault. Only
/// these fields are read, the ones needed to split the encrypted stream into
/// files and to find the master key; everything else in it, the app's own
/// description of folders and photos, is ignored and never written out.
///
/// It is read by this package's strict JSON reader (`SharedItemsJSON`, here
/// taking numbers with fractions, as the app writes dates that way), the same
/// in Swift and Kotlin: a key twice, a number where a string belongs, or
/// base64 in any but its standard padded form is refused, so one export never
/// reads two ways.
public struct ExportIndex: Sendable, Equatable {
    public struct MediaFile: Sendable, Equatable {
        /// The file's ID in the vault's media pool, always a UUID.
        public let id: String
        public let dataSize: Int64
        public let thumbnailSize: Int64
    }

    /// Salt and wrapped master key, as in the vault header.
    public let vaultSalt: Data
    public let wrappedMasterKey: Data
    /// Length of the vault file that follows the manifest in the stream.
    public let databaseSize: Int64
    /// Media files in the order they follow the vault file.
    public let mediaFiles: [MediaFile]

    /// Every byte the stream holds after the manifest: the vault file and
    /// each media file's data and thumbnail. Added up once, with overflow
    /// checked: the sizes are the file's word, and sizes near `Int64.max`
    /// would otherwise stop the app at a plain `+` rather than be refused.
    public let contentSize: Int64

    static let maximumManifestDepth = 32

    /// Parses the index out of the manifest JSON, refusing anything that could
    /// not have come from the app: a media ID that is not a UUID would
    /// otherwise become a path component when files are written out.
    init(manifest: Data) throws {
        let unreadable = ObscuraCryptoError.invalidExport("manifest is not readable")
        let root: SharedItemsJSON.Value
        do {
            root = try SharedItemsJSON.parse(manifest, allowingDecimals: true, maximumDepth: Self.maximumManifestDepth)
        } catch {
            throw unreadable
        }
        guard case .object = root else { throw unreadable }
        func integer(_ value: SharedItemsJSON.Value?) throws -> Int64 {
            guard case .integer(let number)? = value else { throw unreadable }
            return number
        }
        /// Standard base64 with padding, as Swift's `JSONEncoder` writes
        /// `Data`, and nothing a lenient decoder would also take.
        func base64(_ value: SharedItemsJSON.Value?) throws -> Data {
            guard case .string(let text)? = value, let data = Data(base64Encoded: text),
                  data.base64EncodedString() == text else { throw unreadable }
            return data
        }

        let exportVersion = try integer(root["exportVersion"])
        guard exportVersion == 1 else {
            throw ObscuraCryptoError.invalidExport("manifest version \(exportVersion), expected 1")
        }
        let salt = try base64(root["vaultSalt"])
        let wrapped = try base64(root["encryptedMEK"])
        let databaseSize = try integer(root["databaseSize"])
        guard salt.count == KeyDerivation.saltLength, wrapped.count == VaultHeader.wrappedKeySize, databaseSize >= 0 else {
            throw ObscuraCryptoError.invalidExport("manifest key fields have the wrong sizes")
        }
        guard case .array(let entries)? = root["mediaFiles"] else { throw unreadable }
        // IDs differing only by case name one file on a file system that
        // ignores case, so they count as the same ID.
        var seen = Set<String>()
        mediaFiles = try entries.map { entry in
            guard case .object = entry, case .string(let id)? = entry["mediaId"] else { throw unreadable }
            let dataSize = try integer(entry["dataSize"])
            let thumbnailSize = try integer(entry["thumbSize"])
            guard MediaExtraction.isMediaID(id), dataSize >= 0, thumbnailSize >= 0, seen.insert(id.lowercased()).inserted else {
                throw ObscuraCryptoError.invalidExport("manifest lists a media file that is not a unique UUID with valid sizes")
            }
            return MediaFile(id: id, dataSize: dataSize, thumbnailSize: thumbnailSize)
        }
        var total = databaseSize
        for media in mediaFiles {
            for size in [media.dataSize, media.thumbnailSize] {
                let (sum, overflow) = total.addingReportingOverflow(size)
                guard !overflow else { throw ObscuraCryptoError.invalidExport("manifest sizes add up to too much") }
                total = sum
            }
        }
        contentSize = total
        vaultSalt = salt
        wrappedMasterKey = wrapped
        self.databaseSize = databaseSize
    }

    /// Unwraps the exported vault's master key. The app exports with the
    /// vault's own password, so this is normally the export password too.
    public func unlockMasterKey(password: String) throws -> SecureBytes {
        let passwordKey = try KeyDerivation.pbkdf2SHA256(password: password, salt: vaultSalt, iterations: KeyDerivation.vaultIterations)
        do {
            return try AESGCM.unwrapKey(wrappedMasterKey, with: passwordKey)
        } catch ObscuraCryptoError.authenticationFailed {
            throw ObscuraCryptoError.wrongPassword
        }
    }
}

/// Reads an `.obscura` export, version 1 or 2.
///
/// Both carry one plaintext stream, sealed with AES-256-GCM under the export
/// key, `PBKDF2-HMAC-SHA256(password, salt, rounds)` (in version 2, under the
/// record key derived from it, see `ExportHeader`): the manifest (JSON),
/// then the vault file (header and encrypted database, `databaseSize` bytes),
/// then for each media file in the manifest's order its `.data.enc` bytes and
/// its `.thumb.enc` bytes. Media files are carried exactly as the vault stores
/// them, so each is still encrypted with the vault's master key inside.
///
/// - Version 1: records of a 4-byte length and one AES-GCM message, record
///   `i` with nonce `noncePrefix || i`. Record 0 is the manifest alone, and
///   every file starts a new record, so the records show how many files there
///   are and the size of each.
/// - Version 2: records all of one size after a 96-byte header and its key block, nonce
///   `noncePrefix || i` with the top bit set on the last, the header as every
///   record's associated data. The stream opens with the manifest's length
///   (4 bytes) and ends in zeros to the Padmé length, rounded up to whole
///   records, so the file shows only roughly how much it holds.
///
/// This reader checks every nonce against its position, so records moved,
/// copied, dropped or cut off are refused.
public final class ExportArchive {
    public let header: ExportHeader
    public let index: ExportIndex
    /// The manifest JSON exactly as it was written, for the parts this package
    /// does not read: the app's description of folders and photos.
    public let manifestData: Data

    private let handle: FileHandle
    private let key: SymmetricKey
    /// Version 1: the next record's counter.
    private var counter: UInt64 = 1
    /// Version 2: the records as one stream.
    private let stream: SharedItemsRecordStream?

    /// A manifest larger than this is not one the app wrote.
    static let maximumManifestSize: UInt32 = 256 << 20
    static let maximumRecordSize = UInt32(1_048_576 + AESGCM.overhead)

    /// Opens `url`, checks `password` against the header, and reads the index.
    public init(url: URL, password: String) throws {
        handle = try FileHandle(forReadingFrom: url)
        do {
            header = try ExportHeader(parsing: try handle.read(upToCount: ExportHeader.maximumSize) ?? Data())
            try handle.seek(toOffset: UInt64(header.byteCount))
            guard header.kdfIterations >= KeyDerivation.vaultIterations else {
                throw ObscuraCryptoError.iterationsBelowMinimum(header.kdfIterations)
            }
            guard header.kdfIterations <= VaultHeader.maximumIterations else {
                throw ObscuraCryptoError.invalidExport("\(header.kdfIterations) key derivation rounds is implausibly many")
            }

            let exportKey = try KeyDerivation.pbkdf2SHA256(password: password, salt: header.salt, iterations: header.kdfIterations)
            // Version 1 seals under the export key itself; version 2 under a
            // key derived from it.
            key = header.version == 1 ? try exportKey.symmetricKey : try ExportHeader.recordKey(exportKey)
            let manifest: Data
            if header.version == 1 {
                let check = try AES.GCM.seal(
                    ExportHeader.verificationPlaintext, using: key,
                    nonce: try AES.GCM.Nonce(data: header.nonce(counter: .max)))
                guard constantTimeEquals(check.tag, header.verificationTag) else {
                    throw ObscuraCryptoError.wrongPassword
                }
                guard let record = try Self.readRecord(from: handle, key: key, nonce: header.nonce(counter: 0),
                                                       maximumSize: Self.maximumManifestSize) else {
                    throw ObscuraCryptoError.invalidExport("no manifest")
                }
                manifest = record
                stream = nil
            } else {
                guard constantTimeEquals(try ExportHeader.keyCommitment(exportKey), header.keyCommitment) else {
                    throw ObscuraCryptoError.wrongPassword
                }
                let fileSize = try handle.seekToEnd()
                try handle.seek(toOffset: UInt64(header.byteCount))
                let records = SharedItemsRecordStream(
                    handle: handle, key: key, prefix: header.noncePrefix, associatedData: header.bytes,
                    recordSize: header.recordSize, bodySize: fileSize - UInt64(header.byteCount)
                ) { ObscuraCryptoError.invalidExport($0) }
                let length = try records.read(4).bigEndianUInt32(at: 0)
                guard length > 0, length <= Self.maximumManifestSize else {
                    throw ObscuraCryptoError.invalidExport("a manifest of an impossible length")
                }
                manifest = try records.read(Int(length))
                stream = records
            }
            manifestData = manifest
            index = try ExportIndex(manifest: manifest)
        } catch {
            try? handle.close()
            throw error
        }
    }

    deinit {
        try? handle.close()
    }

    /// Reads past the vault file. Its database is encrypted with the master
    /// key, is not needed to recover media, and is never written out.
    public func skipDatabase() throws {
        try pass(index.databaseSize, to: nil)
    }

    /// Writes one stored media file, still encrypted with the master key, to
    /// `url`. Call in the manifest's order, once for its data and once for its
    /// thumbnail; a size of zero writes nothing.
    public func copyStoredFile(size: Int64, to url: URL?) throws {
        guard let url else { return try pass(size, to: nil) }
        FileManager.default.createFile(atPath: url.path, contents: nil)
        let output = try FileHandle(forWritingTo: url)
        defer { try? output.close() }
        try pass(size, to: output)
        try output.synchronize()
    }

    /// The next `count` bytes of the stream after the manifest: the vault
    /// file and the media files, end to end, read in the manifest's order. In
    /// a version 1 export a read may not run past the end of a file, as a
    /// record there never holds the end of one file and the start of the next.
    public func read(_ count: Int) throws -> Data {
        var data = Data(capacity: count)
        try pass(Int64(count)) { data.append($0) }
        return data
    }

    /// Whether everything has been read: in version 1, no record follows; in
    /// version 2, only padding follows, to the last record and its end mark
    /// (anything else throws). Checked after the last media file, so an
    /// export with records appended or altered at its end is noticed.
    public func isAtEnd() throws -> Bool {
        if let stream {
            try stream.finish()
            return true
        }
        let position = try handle.offset()
        let end = try handle.seekToEnd()
        try handle.seek(toOffset: position)
        return position == end
    }

    /// Reads `url` to its end with `password`: every record authenticated and
    /// in its place, every file the manifest lists present, nothing after the
    /// last. What an app runs on an export it has just written, before telling
    /// anyone it is done.
    public static func verify(url: URL, password: String,
                              progress: ((_ bytesRead: Int64, _ total: Int64) -> Void)? = nil) throws {
        let archive = try ExportArchive(url: url, password: password)
        let total = archive.index.contentSize
        var done: Int64 = 0
        try archive.skipDatabase()
        done += archive.index.databaseSize
        progress?(done, total)
        for media in archive.index.mediaFiles {
            try archive.copyStoredFile(size: media.dataSize, to: nil)
            try archive.copyStoredFile(size: media.thumbnailSize, to: nil)
            done += media.dataSize + media.thumbnailSize
            progress?(done, total)
        }
        guard try archive.isAtEnd() else {
            throw ObscuraCryptoError.invalidExport("there is data after the last file")
        }
    }

    // MARK: Records

    private func pass(_ size: Int64, to output: FileHandle?) throws {
        try pass(size) { try output?.write(contentsOf: $0) }
    }

    /// Hands over the next `size` bytes of the stream, a piece at a time.
    private func pass(_ size: Int64, into body: (Data) throws -> Void) throws {
        if let stream {
            return try stream.read(size) { piece in try autoreleasepool { try body(piece) } }
        }
        var remaining = size
        while remaining > 0 {
            try autoreleasepool {
                let record = try nextRecord()
                guard Int64(record.count) <= remaining else {
                    throw ObscuraCryptoError.invalidExport("a record runs past the end of its file")
                }
                try body(record)
                remaining -= Int64(record.count)
            }
        }
    }

    /// Version 1: a file's bytes always start a new record, and a record never
    /// holds the end of one file and the start of the next.
    private func nextRecord() throws -> Data {
        guard let record = try Self.readRecord(from: handle, key: key, nonce: header.nonce(counter: counter),
                                               maximumSize: Self.maximumRecordSize) else {
            throw ObscuraCryptoError.invalidExport("the export ends early")
        }
        counter += 1
        return record
    }

    /// One version 1 record, or nil at the end of the file.
    private static func readRecord(from handle: FileHandle, key: SymmetricKey, nonce: Data, maximumSize: UInt32) throws -> Data? {
        guard let prefix = try handle.read(upToCount: 4), !prefix.isEmpty else { return nil }
        guard prefix.count == 4 else { throw ObscuraCryptoError.invalidExport("the export ends early") }
        let length = prefix.bigEndianUInt32(at: 0)
        guard length > UInt32(AESGCM.overhead), length <= maximumSize else {
            throw ObscuraCryptoError.invalidExport("a record has an impossible length")
        }
        guard let sealed = try handle.read(upToCount: Int(length)), sealed.count == Int(length) else {
            throw ObscuraCryptoError.invalidExport("the export ends early")
        }
        guard sealed.prefix(AESGCM.nonceSize) == nonce else {
            throw ObscuraCryptoError.invalidExport("a record carries the wrong nonce: records were reordered or replaced")
        }
        return try AESGCM.open(sealed, key: key)
    }
}

/// Writes an `.obscura` export, version 2.
///
/// The manifest comes first and says how much follows; the writer checks that
/// exactly that much is written. Then write the vault file, then each media
/// file's data and thumbnail in the manifest's order, and `finish`.
/// `ExportArchive.verify` should be run on the result before it is offered as
/// a backup.
public final class ExportWriter {
    public static let recordSize = 1_048_576

    public let header: ExportHeader
    private let output: FileHandle
    private let sealer: RecordSealer
    /// Bytes the manifest says follow it, and how many have been written.
    private let expected: Int64
    private var written: Int64 = 0

    /// Creates `url` with `attributes` (such as its data protection), derives
    /// the export key from `password`, and writes the header and manifest.
    public convenience init(url: URL, password: String, manifest: Data,
                            attributes: [FileAttributeKey: Any]? = nil) throws {
        try self.init(url: url, password: password, manifest: manifest, attributes: attributes,
                      rounds: KeyDerivation.vaultIterations, recordSize: Self.recordSize)
    }

    /// With chosen rounds, record size and key block: other values only for
    /// tests (a lock of a type no reader knows yet).
    init(url: URL, password: String, manifest: Data, attributes: [FileAttributeKey: Any]?,
         rounds: UInt32, recordSize: Int, keyBlock: Data = Data([0])) throws {
        guard manifest.count <= Int(ExportArchive.maximumManifestSize) else {
            throw ObscuraCryptoError.invalidExport("the manifest is too large")
        }
        let index = try ExportIndex(manifest: manifest)
        expected = index.contentSize
        // Far beyond any phone, and low enough that the padding below cannot overflow.
        guard expected < 1 << 60 else { throw ObscuraCryptoError.invalidExport("the manifest lists too much") }
        let content = 4 + manifest.count + Int(expected)
        let recordCount = (SharedItemsFile.padme(content) + recordSize - 1) / recordSize

        let salt = try KeyDerivation.makeSalt()
        let prefix = try SecureRandom.bytes(4)
        let exportKey = try KeyDerivation.pbkdf2SHA256(password: password, salt: salt, iterations: rounds)
        header = try ExportHeader.version2(salt: salt, rounds: rounds, noncePrefix: prefix, recordSize: recordSize,
                                           keyCommitment: try ExportHeader.keyCommitment(exportKey), keyBlock: keyBlock)
        guard FileManager.default.createFile(atPath: url.path, contents: nil, attributes: attributes) else {
            throw ObscuraCryptoError.invalidExport("the export file could not be created")
        }
        output = try FileHandle(forWritingTo: url)
        _ = fcntl(output.fileDescriptor, F_NOCACHE, 1)
        sealer = RecordSealer(output: output, key: try ExportHeader.recordKey(exportKey), prefix: prefix, associatedData: header.bytes,
                              recordSize: recordSize, recordCount: recordCount,
                              overflow: ObscuraCryptoError.invalidExport("more written than the manifest lists"))
        try output.write(contentsOf: header.bytes)
        var length = Data()
        length.appendBigEndian(UInt32(manifest.count))
        try sealer.append(length)
        try sealer.append(manifest)
    }

    deinit {
        try? output.close()
    }

    /// The next bytes of the stream: the vault file, then each media file's
    /// data and thumbnail, in the manifest's order.
    public func write(_ data: Data) throws {
        written += Int64(data.count)
        guard written <= expected else { throw ObscuraCryptoError.invalidExport("more written than the manifest lists") }
        try autoreleasepool { try sealer.append(data) }
    }

    /// Pads the stream, seals the last record with its end mark, and closes
    /// the file. Refuses if less was written than the manifest lists.
    public func finish() throws {
        guard written == expected else { throw ObscuraCryptoError.invalidExport("less written than the manifest lists") }
        try sealer.finish(padding: 0)
        try output.synchronize()
        try output.close()
    }
}
