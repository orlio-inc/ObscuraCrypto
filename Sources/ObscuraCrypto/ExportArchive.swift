// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CryptoKit
import Foundation

/// The 64-byte header of an `.obscura` export, the only unencrypted part.
///
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
public struct ExportHeader: Sendable, Equatable {
    public static let size = 64
    public static let magic = Data("OBSV".utf8)
    public static let version: UInt16 = 1
    static let verificationPlaintext = Data("OBSCURA_EXPORT_V1".utf8)

    public let version: UInt16
    public let flags: UInt16
    public let salt: Data
    public let kdfIterations: UInt32
    public let verificationTag: Data
    public let noncePrefix: Data

    public init(parsing data: Data) throws {
        guard data.count >= Self.size else {
            throw ObscuraCryptoError.invalidExport("shorter than \(Self.size) bytes")
        }
        let header = Data(data.prefix(Self.size))
        guard header.prefix(4) == Self.magic else {
            throw ObscuraCryptoError.invalidExport("missing OBSV magic")
        }
        version = UInt16(header[4]) << 8 | UInt16(header[5])
        guard version == Self.version else {
            throw ObscuraCryptoError.invalidExport("version \(version), expected 1")
        }
        flags = UInt16(header[6]) << 8 | UInt16(header[7])
        salt = Data(header[8..<40])
        kdfIterations = header.bigEndianUInt32(at: 40)
        verificationTag = Data(header[44..<60])
        noncePrefix = Data(header[60..<64])
    }

    /// `noncePrefix || counter`, as in the chunked media format. Chunks count
    /// from 0; the password check uses the largest counter, `UInt64.max`.
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

    /// Parses the index out of the manifest JSON, refusing anything that could
    /// not have come from the app: a media ID that is not a UUID would
    /// otherwise become a path component when files are written out.
    init(manifest: Data) throws {
        struct Manifest: Decodable {
            struct Media: Decodable {
                let mediaId: String
                let dataSize: Int64
                let thumbSize: Int64
            }
            let exportVersion: Int
            let vaultSalt: Data
            let encryptedMEK: Data
            let databaseSize: Int64
            let mediaFiles: [Media]
        }
        let decoded: Manifest
        do {
            decoded = try JSONDecoder().decode(Manifest.self, from: manifest)
        } catch {
            throw ObscuraCryptoError.invalidExport("manifest is not readable")
        }
        guard decoded.exportVersion == 1 else {
            throw ObscuraCryptoError.invalidExport("manifest version \(decoded.exportVersion), expected 1")
        }
        guard decoded.vaultSalt.count == KeyDerivation.saltLength,
              decoded.encryptedMEK.count == VaultHeader.wrappedKeySize,
              decoded.databaseSize >= 0 else {
            throw ObscuraCryptoError.invalidExport("manifest key fields have the wrong sizes")
        }
        var seen = Set<String>()
        mediaFiles = try decoded.mediaFiles.map { media in
            guard UUID(uuidString: media.mediaId) != nil,
                  media.dataSize >= 0, media.thumbSize >= 0, seen.insert(media.mediaId).inserted else {
                throw ObscuraCryptoError.invalidExport("manifest lists a media file that is not a unique UUID with valid sizes")
            }
            return MediaFile(id: media.mediaId, dataSize: media.dataSize, thumbnailSize: media.thumbSize)
        }
        vaultSalt = decoded.vaultSalt
        wrappedMasterKey = decoded.encryptedMEK
        databaseSize = decoded.databaseSize
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

/// Reads an `.obscura` export.
///
/// After the header, the file is a sequence of records, each a 4-byte
/// big-endian length and then one AES-256-GCM message (combined layout) sealed
/// with the export key, `PBKDF2-HMAC-SHA256(password, salt, rounds)`. Record
/// `i` carries nonce `noncePrefix || i`; this reader checks it, so records
/// moved or copied between exports are refused.
///
/// The decrypted records, read in order, are one stream:
/// 1. record 0 on its own: the manifest, JSON;
/// 2. the vault file, header and encrypted database, `databaseSize` bytes,
///    which this reader skips;
/// 3. for each media file in the manifest's order, its `.data.enc` bytes and
///    then its `.thumb.enc` bytes, each starting a new record.
///
/// Media files are carried exactly as the vault stores them, so each is still
/// encrypted with the vault's master key inside the export's own encryption.
public final class ExportArchive {
    public let header: ExportHeader
    public let index: ExportIndex

    private let handle: FileHandle
    private let key: SymmetricKey
    private var counter: UInt64 = 1

    /// A manifest larger than this is not one the app wrote.
    static let maximumManifestSize: UInt32 = 256 << 20
    static let maximumRecordSize = UInt32(1_048_576 + AESGCM.overhead)

    /// Opens `url`, checks `password` against the header, and reads the index.
    public init(url: URL, password: String) throws {
        handle = try FileHandle(forReadingFrom: url)
        do {
            header = try ExportHeader(parsing: try handle.read(upToCount: ExportHeader.size) ?? Data())
            guard header.kdfIterations >= KeyDerivation.vaultIterations else {
                throw ObscuraCryptoError.iterationsBelowMinimum(header.kdfIterations)
            }
            guard header.kdfIterations <= VaultHeader.maximumIterations else {
                throw ObscuraCryptoError.invalidExport("\(header.kdfIterations) key derivation rounds is implausibly many")
            }

            let exportKey = try KeyDerivation.pbkdf2SHA256(password: password, salt: header.salt, iterations: header.kdfIterations)
            key = exportKey.symmetricKey
            let check = try AES.GCM.seal(
                ExportHeader.verificationPlaintext, using: key,
                nonce: try AES.GCM.Nonce(data: header.nonce(counter: .max)))
            guard constantTimeEquals(check.tag, header.verificationTag) else {
                throw ObscuraCryptoError.wrongPassword
            }

            guard let manifest = try Self.readRecord(from: handle, key: key, nonce: header.nonce(counter: 0),
                                                     maximumSize: Self.maximumManifestSize) else {
                throw ObscuraCryptoError.invalidExport("no manifest")
            }
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
        try skipRecords(covering: index.databaseSize)
    }

    /// Writes one stored media file, still encrypted with the master key, to
    /// `url`. Call in the manifest's order, once for its data and once for its
    /// thumbnail; a size of zero writes nothing.
    public func copyStoredFile(size: Int64, to url: URL?) throws {
        if let url {
            try copyRecords(covering: size, to: url)
        } else {
            try skipRecords(covering: size)
        }
    }

    /// Whether every record has been read. Checked after the last media file
    /// so an export with records appended is noticed.
    public func isAtEnd() throws -> Bool {
        let position = try handle.offset()
        let end = try handle.seekToEnd()
        try handle.seek(toOffset: position)
        return position == end
    }

    // MARK: Records

    /// A file's bytes always start a new record, and a record never holds the
    /// end of one file and the start of the next: the app writes each file in
    /// 1 MB reads of its own.
    private func copyRecords(covering size: Int64, to url: URL) throws {
        FileManager.default.createFile(atPath: url.path, contents: nil)
        let output = try FileHandle(forWritingTo: url)
        defer { try? output.close() }
        var remaining = size
        while remaining > 0 {
            let record = try nextRecord()
            guard Int64(record.count) <= remaining else {
                throw ObscuraCryptoError.invalidExport("a record runs past the end of its file")
            }
            try output.write(contentsOf: record)
            remaining -= Int64(record.count)
        }
        try output.synchronize()
    }

    private func skipRecords(covering size: Int64) throws {
        var remaining = size
        while remaining > 0 {
            let record = try nextRecord()
            guard Int64(record.count) <= remaining else {
                throw ObscuraCryptoError.invalidExport("a record runs past the end of its file")
            }
            remaining -= Int64(record.count)
        }
    }

    private func nextRecord() throws -> Data {
        guard let record = try Self.readRecord(from: handle, key: key, nonce: header.nonce(counter: counter),
                                               maximumSize: Self.maximumRecordSize) else {
            throw ObscuraCryptoError.invalidExport("the export ends early")
        }
        counter += 1
        return record
    }

    /// One record, or nil at the end of the file.
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
