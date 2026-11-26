// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CryptoKit
import Foundation

/// The `.obscurashared` file the app's Send Encrypted makes: photos, videos and
/// documents chosen in one vault, for another person to add to theirs.
///
/// It is sealed under a password the sender picks and tells the receiver
/// separately, or under none. Without a password the key travels in the file
/// itself (an open lock): the file still does not show what it holds to a
/// photo library or a preview, but anyone who has it can open it, and change
/// it and seal it again. Only a password protects the items, and only a
/// password-sealed file shows that it is the one its sender made.
///
/// It carries no vault: no database, no master key, nothing that opens
/// anything but the items inside.
///
/// What it shows without the password: that it is such a file, how it is
/// locked (password and rounds, or open), and its length, which is padded
/// so that it tells only roughly how much the items come to. How many items
/// there are and how large each is are inside the encryption.
///
/// Built to be read by apps newer and older than the one that wrote it:
///
/// - Two version numbers: the format the writer used, and the oldest reader
///   that can open the file. A reader opens any file whose "readable by" it
///   meets, so additions an older reader can pass over never shut it out; only
///   a real break raises "readable by", and then the reader says to update
///   (`sharedItemsNewerVersion`), never that the file is damaged.
/// - The items are under a random content key, held in one or more locks: a
///   password (PBKDF2), or open. A reader uses the first lock it knows; new
///   kinds of lock can sit beside the old ones.
/// - The manifest lists every item's parts with a role. Unknown kinds of item
///   and unknown parts are read past, and the rest are taken. Unknown JSON
///   members are ignored.
///
/// ```
/// Header (64 bytes, unencrypted):
///   [0:4]    "OBSI"
///   [4:6]    format version (3; 1 and 2 were layouts that never shipped)
///   [6:8]    readable by: the oldest reader version that can open it (3)
///   [8:10]   flags: bits 0-7 must be understood (a reader that does not know
///            a set one refuses as newer), bits 8-15 may be ignored. None are
///            defined yet.
///   [10:12]  key block length
///   [12:16]  record size: plaintext bytes in every record (65,536)
///   [16:32]  file id, random
///   [32:36]  nonce prefix, random
///   [36:64]  reserved, written as zeros, ignored
///
/// Key block (unencrypted): [key commitment, 32 bytes], [lock count, 1 byte],
///   then each lock as [type, 1 byte][body length, 2 bytes][body]
///   type 1, password: [rounds, 4 bytes][salt, 32][sealed key, 60]: the content
///     key sealed with AES-256-GCM (random nonce, the 64-byte header as
///     associated data) under PBKDF2-HMAC-SHA256(password, salt, rounds);
///     rounds at least 600,000.
///   type 2, open: [content key, 32]
///   other types are skipped.
///
/// The content key is never used as it is. HKDF-SHA256 over it, with a salt
///   of 32 zero bytes, gives the record key (info "OBSI v3 records") and the
///   key commitment (info "OBSI v3 key commitment"), each 32 bytes.
///
/// Records: back to back, each `record size` bytes of plaintext sealed with
///   AES-256-GCM under the record key, stored combined (nonce | ciphertext |
///   tag), with the header and key block as associated data. Nonce = prefix ||
///   record index (8 bytes), the index's top bit set on the last record; a
///   reader checks it, so records cannot be reordered, dropped or repeated, nor
///   the file cut short at a record boundary, unnoticed.
///
/// The records' plaintext is one stream: the manifest's length (4 bytes), the
///   manifest, every part of every item in manifest order, end to end, then
///   zeros to the end of the last record. Writers pad further, to the Padmé
///   length of the stream (at most 12% more), rounded up to whole records.
///
/// Manifest: JSON in the strict form `SharedItemsJSON` reads: {"items":
///   [{"kind": "photo", "type": "image/jpeg", "name": "...", "parts": [{"role":
///   "file", "size": n, "sha256": hex}, ...]}]}. Kinds: photo, gif, video,
///   livePhoto (parts file and motion), pdf (name is the document's title).
///   "type" is a MIME type.
/// ```
public enum SharedItemsFile {
    public static let fileExtension = "obscurashared"
    public static let magic = Data("OBSI".utf8)
    /// The format this package writes, and the newest it reads.
    public static let version: UInt16 = 3
    /// What a file this package writes asks of its reader.
    public static let readableBy: UInt16 = 3
    public static let headerSize = 64
    /// Plaintext bytes in each record, as this package writes them.
    public static let recordSize = 65_536
    /// The record sizes a reader accepts.
    public static let recordSizes = 4_096...1_048_576
    /// The share sheet's own cap on a selection.
    public static let maximumItems = 1_000
    public static let maximumPartsPerItem = 16
    /// Bounds a reader holds a file to, so a made-up one cannot ask for
    /// unbounded memory or work. A real manifest of 1,000 items with long
    /// titles stays under a megabyte.
    public static let maximumKeyBlock = 4_096
    public static let maximumManifest = 2 * 1_048_576
    public static let maximumRounds: UInt32 = 10_000_000
    /// The most key derivation rounds a reader spends on one file, all its
    /// password locks together: about five seconds on a phone.
    public static let roundsBudget: UInt32 = 10_000_000
    /// A document's title, at most, in Unicode scalars (Kotlin's code points).
    public static let maximumNameLength = 200
    static let maximumPasswordLocksTried = 4
    static let requiredFlags: UInt16 = 0x00FF
    static let contentKeySize = 32
    /// The key block opens with a commitment to the content key: 32 bytes
    /// HKDF derives from it. AES-GCM does not commit to its key, so a
    /// password lock can be made that opens under several passwords, each to
    /// a different key; a reader takes only the key the file commits to, so
    /// every file has one key and one meaning.
    static let keyCommitmentSize = 32
    static let keyCommitmentInfo = Data("OBSI v3 key commitment".utf8)
    /// The records are sealed under a key HKDF derives from the content key,
    /// not under the content key itself, which the commitment is made from.
    static let recordKeyInfo = Data("OBSI v3 records".utf8)
    /// Rounds, salt and the sealed content key.
    static let passwordLockSize = 4 + KeyDerivation.saltLength + contentKeySize + AESGCM.overhead
    /// Set in the last record's nonce, so a file cut short at a record
    /// boundary ends on a record without it.
    static let lastRecordFlag: UInt64 = 1 << 63
    /// Bytes read from a file at a time, sending and receiving. Files are
    /// read with `F_NOCACHE`, which stops the system reading ahead, so one
    /// read per 64 KB record took three times as long.
    static let readSize = 1_048_576

    public enum LockType: UInt8, Sendable {
        case password = 1
        case open = 2
    }

    public enum Kind: String, Sendable, CaseIterable {
        case photo, gif, video, livePhoto
        /// A document, as one PDF.
        case pdf
    }

    public enum Role: String, Sendable {
        /// The item's file; a Live Photo's still.
        case file
        /// A Live Photo's motion video.
        case motion
    }

    public struct Part: Sendable, Equatable {
        public let role: String
        public let size: Int64
        /// Lowercase hex SHA-256 of the plaintext.
        public let sha256: String

        public init(role: String, size: Int64, sha256: String) {
            self.role = role
            self.size = size
            self.sha256 = sha256
        }
    }

    public struct Item: Sendable, Equatable {
        /// Kept as written: a kind this package does not know is read past.
        public let kind: String
        /// MIME type of the file part, when the sender knew it.
        public var type: String?
        /// A document's title, so it arrives under its own name.
        public var name: String?
        public let parts: [Part]

        public init(kind: String, type: String? = nil, name: String? = nil, parts: [Part]) {
            self.kind = kind
            self.type = type
            self.name = name
            self.parts = parts
        }

        /// The kind, when this package knows it.
        public var knownKind: Kind? { Kind(rawValue: kind) }

        public func part(_ role: Role) -> Part? { parts.first { $0.role == role.rawValue } }

        /// Everything a reader holds an item to, the same in Swift and
        /// Kotlin: kinds and roles of 1 to 64 printable ASCII characters, a
        /// type of 1 to 100, 1 to 16 parts each with a size above 0 and a
        /// 64-digit lowercase hash, no role twice, a title of at most 200
        /// scalars with no control or direction characters, and the parts a
        /// known kind needs: a file, and a motion video exactly when it is a
        /// Live Photo.
        public var isWellFormed: Bool {
            guard SharedItemsFile.isToken(kind, maximum: 64),
                  type.map({ SharedItemsFile.isToken($0, maximum: 100) }) ?? true,
                  name.map(SharedItemsFile.isAcceptableName) ?? true,
                  (1...SharedItemsFile.maximumPartsPerItem).contains(parts.count),
                  parts.allSatisfy({ $0.size > 0 && SharedItemsFile.isToken($0.role, maximum: 64)
                                     && SharedItemsFile.isHash($0.sha256) }),
                  Set(parts.map(\.role)).count == parts.count else { return false }
            guard let kind = knownKind else { return true }
            guard part(.file) != nil else { return false }
            return (kind == .livePhoto) == (part(.motion) != nil)
        }
    }

    public struct Manifest: Sendable, Equatable {
        public let items: [Item]

        public init(items: [Item]) { self.items = items }
    }

    /// One item to send: a plaintext file, and a Live Photo's motion video.
    public struct Source: Sendable {
        public var url: URL
        public var kind: Kind
        public var pairedVideo: URL?
        /// A document's title.
        public var name: String?
        /// The file's MIME type, when known.
        public var mimeType: String?

        public init(url: URL, kind: Kind, pairedVideo: URL? = nil, name: String? = nil, mimeType: String? = nil) {
            self.url = url
            self.kind = kind
            self.pairedVideo = pairedVideo
            self.name = name
            self.mimeType = mimeType
        }
    }

    // MARK: Writing

    /// Seals `sources` (plaintext files, read a record at a time) into
    /// `destination`, under `password`, or in an open lock when it is nil.
    /// Any password is taken: `passwordProblem` is for saying, before, what
    /// makes one easy to guess.
    ///
    /// Every file is read twice, as the manifest needs each part's size and
    /// hash before any part is written; nothing is held in memory. Writes to a
    /// temporary file beside `destination`, created with `attributes`, and
    /// moves it into place only when complete, so a failure leaves nothing.
    public static func write(_ sources: [Source], password: String?, to destination: URL,
                             attributes: [FileAttributeKey: Any]? = nil) throws {
        try write(sources, password: password, to: destination, attributes: attributes,
                  rounds: KeyDerivation.vaultIterations, recordSize: recordSize)
    }

    /// `write` with chosen rounds, record size, manifest and padding: other
    /// values only for tests and fixtures (fewer rounds
    /// than a reader accepts, small records that keep fixtures small,
    /// manifests and padding no writer makes).
    static func write(_ sources: [Source], password: String?, to destination: URL,
                      attributes: [FileAttributeKey: Any]?, rounds: UInt32, recordSize: Int,
                      manifestOverride: Data? = nil, padding: UInt8 = 0) throws {
        guard !sources.isEmpty, sources.count <= maximumItems else {
            throw ObscuraCryptoError.tooManySharedItems(sources.count)
        }
        guard recordSizes.contains(recordSize) else {
            throw ObscuraCryptoError.invalidSharedItems("a record size outside \(recordSizes)")
        }
        var items: [Item] = []
        for source in sources {
            guard (source.kind == .livePhoto) == (source.pairedVideo != nil) else {
                throw ObscuraCryptoError.invalidSharedItems(
                    source.kind == .livePhoto ? "a Live Photo needs its motion video" : "only a Live Photo has a motion video")
            }
            var parts = [try part(.file, of: source.url)]
            if let video = source.pairedVideo { parts.append(try part(.motion, of: video)) }
            items.append(Item(kind: source.kind.rawValue, type: source.mimeType.flatMap { isToken($0, maximum: 100) ? $0 : nil },
                              name: source.name.flatMap(cleanedName), parts: parts))
        }
        let manifest = manifestOverride ?? SharedItemsJSON.encode(Manifest(items: items))
        guard manifest.count <= maximumManifest else { throw ObscuraCryptoError.tooManySharedItems(sources.count) }

        let content = 4 + manifest.count + items.flatMap(\.parts).reduce(0) { $0 + Int($1.size) }
        let recordCount = (padme(content) + recordSize - 1) / recordSize

        let contentKey = try SecureBytes.random(count: contentKeySize)
        let prefix = try SecureRandom.bytes(4)
        // A password lock is sealed with the header as associated data, and
        // the header gives the key block's length: the lock's size is fixed,
        // so the header is final before the lock is made.
        let header = makeHeader(keyBlockLength: keyCommitmentSize + 1 + 3 + (password == nil ? contentKeySize : passwordLockSize),
                                recordSize: recordSize, fileId: try SecureRandom.bytes(16), prefix: prefix)
        var keyBlock = try keyCommitment(contentKey)
        keyBlock.append(1)
        if let password {
            let salt = try KeyDerivation.makeSalt()
            let passwordKey = try KeyDerivation.pbkdf2SHA256(password: password, salt: salt, iterations: rounds)
            let sealed = try contentKey.withKeyBytes {
                try AESGCM.seal($0, key: try passwordKey.symmetricKey, nonce: AES.GCM.Nonce(), authenticating: header)
            }
            var body = Data()
            body.appendBigEndian(rounds)
            body.append(salt)
            body.append(sealed)
            keyBlock.append(lock(.password, body))
        } else {
            keyBlock.append(lock(.open, try contentKey.withKeyBytes { Data($0) }))
        }
        let preamble = header + keyBlock

        let temporary = destination.deletingLastPathComponent()
            .appendingPathComponent(".\(destination.lastPathComponent).\(UUID().uuidString).partial")
        FileManager.default.createFile(atPath: temporary.path, contents: nil, attributes: attributes)
        do {
            let output = try FileHandle(forWritingTo: temporary)
            defer { try? output.close() }
            _ = fcntl(output.fileDescriptor, F_NOCACHE, 1)
            try output.write(contentsOf: preamble)
            let sealer = RecordSealer(output: output, key: try recordKey(contentKey), prefix: prefix,
                                      associatedData: preamble, recordSize: recordSize, recordCount: recordCount)
            var length = Data()
            length.appendBigEndian(UInt32(manifest.count))
            try sealer.append(length)
            try sealer.append(manifest)
            for (source, item) in zip(sources, items) {
                for (url, part) in zip([source.url] + (source.pairedVideo.map { [$0] } ?? []), item.parts) {
                    try sealPart(url, part: part, into: sealer)
                }
            }
            try sealer.finish(padding: padding)
            try output.synchronize()
            try moveIntoPlace(temporary, at: destination)
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
    }

    /// One part's file into the stream, checked against the size and hash
    /// the manifest already gives, so a file that changes meanwhile is never
    /// sent as one the reader would call damaged.
    private static func sealPart(_ url: URL, part: Part, into sealer: RecordSealer) throws {
        let input = try FileHandle(forReadingFrom: url)
        defer { try? input.close() }
        _ = fcntl(input.fileDescriptor, F_NOCACHE, 1)
        var hasher = SHA256()
        var written: Int64 = 0
        while true {
            // A pool per record, so each record's buffers are freed before
            // the next is read.
            let done: Bool = try autoreleasepool {
                guard let chunk = try input.read(upToCount: readSize), !chunk.isEmpty else { return true }
                written += Int64(chunk.count)
                guard written <= part.size else { return true }
                hasher.update(data: chunk)
                try sealer.append(chunk)
                return false
            }
            if done { break }
        }
        guard written == part.size, hex(hasher.finalize()) == part.sha256 else {
            throw ObscuraCryptoError.invalidSharedItems("\(url.lastPathComponent) changed while it was being sealed")
        }
    }

    /// Whether `url` needs a password to open, from its header and key block
    /// alone.
    public static func needsPassword(_ url: URL) throws -> Bool {
        try !SharedItemsPreamble(url: url).isOpen
    }

    // MARK: Helpers

    /// `noncePrefix || index`, the index's top bit set on the last record.
    static func recordNonce(prefix: Data, index: UInt64, isLast: Bool) -> Data {
        var nonce = prefix
        nonce.appendBigEndian(index | (isLast ? lastRecordFlag : 0))
        return nonce
    }

    /// Padmé (Nikitin et al., 2019): `length` rounded up so that only its
    /// top bits remain, at most 12% more, which leaves a file's length
    /// saying little more than its order of magnitude.
    static func padme(_ length: Int) -> Int {
        guard length > 1 else { return length }
        let exponent = Int.bitWidth - 1 - length.leadingZeroBitCount
        let exponentBits = Int.bitWidth - exponent.leadingZeroBitCount
        let mask = (1 << (exponent - exponentBits)) - 1
        return (length + mask) & ~mask
    }

    static func makeHeader(keyBlockLength: Int, recordSize: Int, fileId: Data, prefix: Data) -> Data {
        var header = magic
        header.appendBigEndian(version)
        header.appendBigEndian(readableBy)
        header.appendBigEndian(UInt16(0))
        header.appendBigEndian(UInt16(keyBlockLength))
        header.appendBigEndian(UInt32(recordSize))
        header.append(fileId)
        header.append(prefix)
        header.append(Data(count: headerSize - header.count))
        return header
    }

    static func lock(_ type: LockType, _ body: Data) -> Data {
        var data = Data([type.rawValue])
        data.appendBigEndian(UInt16(body.count))
        data.append(body)
        return data
    }

    /// A part's size and hash, read a record at a time.
    private static func part(_ role: Role, of url: URL) throws -> Part {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        _ = fcntl(handle.fileDescriptor, F_NOCACHE, 1)
        var hasher = SHA256()
        var size: Int64 = 0
        while true {
            let done: Bool = try autoreleasepool {
                guard let chunk = try handle.read(upToCount: readSize), !chunk.isEmpty else { return true }
                hasher.update(data: chunk)
                size += Int64(chunk.count)
                return false
            }
            if done { break }
        }
        guard size > 0 else { throw ObscuraCryptoError.invalidSharedItems("\(url.lastPathComponent) is empty") }
        return Part(role: role.rawValue, size: size, sha256: hex(hasher.finalize()))
    }

    static func hex<Bytes: Sequence>(_ bytes: Bytes) -> String where Bytes.Element == UInt8 {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    static func keyCommitment(_ contentKey: SecureBytes) throws -> Data {
        try KeyDerivation.subkeyBytes(of: contentKey, info: keyCommitmentInfo)
    }

    static func recordKey(_ contentKey: SecureBytes) throws -> SymmetricKey {
        try KeyDerivation.subkey(of: contentKey, info: recordKeyInfo)
    }

    /// 1 to `maximum` characters, each printable ASCII other than space.
    static func isToken(_ text: String, maximum: Int) -> Bool {
        let scalars = text.unicodeScalars
        return (1...maximum).contains(scalars.count) && scalars.allSatisfy { (0x21...0x7E).contains($0.value) }
    }

    static func isHash(_ text: String) -> Bool {
        text.unicodeScalars.count == 64
            && text.unicodeScalars.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
    }

    /// Characters a title may not hold: those `isBreakingCharacter` and
    /// `isInvisibleCharacter` name.
    static func isHiddenCharacter(_ scalar: Unicode.Scalar) -> Bool {
        isBreakingCharacter(scalar) || isInvisibleCharacter(scalar)
    }

    /// Control characters, and those that change the direction of the text
    /// around them or break the line. Writers make them spaces.
    static func isBreakingCharacter(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x00...0x1F, 0x7F...0x9F, 0x061C, 0x200E, 0x200F, 0x2028, 0x2029, 0x202A...0x202E, 0x2066...0x2069:
            return true
        default:
            return false
        }
    }

    /// Characters that show nothing at all, so a title could look blank, or
    /// like another, while it carries more: Unicode's Default_Ignorable_Code_Point
    /// set (zero-width spaces, the byte order mark, Hangul fillers, variation
    /// selectors, tag characters and the rest), written out here so Swift and
    /// Kotlin decide alike whatever their own Unicode tables say. Writers
    /// leave them out. Allowed after all: the joiners U+200C and U+200D, which
    /// Persian, Indic scripts and emoji need, and the text and emoji
    /// presentation selectors U+FE0E and U+FE0F, but only right after a
    /// visible character (`isPresentationSelector`).
    static func isInvisibleCharacter(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x00AD, 0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B...0x180F, 0x200B, 0x2060...0x206F, 0x3164,
             0xFE00...0xFE0D, 0xFEFF, 0xFFA0, 0xFFF0...0xFFFB, 0x1BCA0...0x1BCA3, 0x1D173...0x1D17A, 0xE0000...0xE0FFF:
            return true
        default:
            return false
        }
    }

    static func isPresentationSelector(_ scalar: Unicode.Scalar) -> Bool {
        scalar.value == 0xFE0E || scalar.value == 0xFE0F
    }

    /// Spaces of every kind, listed for the same reason.
    static func isSpace(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x20, 0xA0, 0x1680, 0x2000...0x200A, 0x202F, 0x205F, 0x3000: return true
        default: return false
        }
    }

    /// Shows something: not a space, not the blank braille pattern, not a
    /// joiner or presentation selector, nor anything hidden.
    static func isVisible(_ scalar: Unicode.Scalar) -> Bool {
        !(isSpace(scalar) || scalar.value == 0x2800 || scalar.value == 0x200C || scalar.value == 0x200D
            || isPresentationSelector(scalar) || isHiddenCharacter(scalar))
    }

    static func isAcceptableName(_ name: String) -> Bool {
        let scalars = Array(name.unicodeScalars)
        guard scalars.count <= maximumNameLength, scalars.contains(where: isVisible) else { return false }
        for (index, scalar) in scalars.enumerated() {
            if isHiddenCharacter(scalar) { return false }
            if isPresentationSelector(scalar), index == 0 || !isVisible(scalars[index - 1]) { return false }
        }
        return true
    }

    /// A title as writers put it in: breaking characters made spaces,
    /// invisible ones and presentation selectors not after a visible
    /// character left out, spaces at either end taken off, at most 200
    /// scalars; nil when nothing visible is left.
    static func cleanedName(_ name: String) -> String? {
        var kept: [Unicode.Scalar] = []
        for scalar in name.unicodeScalars {
            if isInvisibleCharacter(scalar) { continue }
            if isPresentationSelector(scalar), !(kept.last.map(isVisible) ?? false) { continue }
            kept.append(isBreakingCharacter(scalar) ? " " : scalar)
        }
        var scalars = kept[...]
        func trim() {
            while let first = scalars.first, isSpace(first) { scalars = scalars.dropFirst() }
            while let last = scalars.last, isSpace(last) { scalars = scalars.dropLast() }
        }
        trim()
        scalars = scalars.prefix(maximumNameLength)
        trim()
        return scalars.contains(where: isVisible) ? String(String.UnicodeScalarView(scalars)) : nil
    }
}

/// Fills records of the plaintext stream and seals each as it fills: equal
/// records, nonce `prefix || index` with the end mark on the last, the
/// preamble as associated data. Shared items files and version 2 exports.
final class RecordSealer {
    private let output: FileHandle
    private let key: SymmetricKey
    private let prefix: Data
    private let associatedData: Data
    private let recordSize: Int
    private let recordCount: Int
    /// Thrown when more is written than the records were counted for.
    private let overflow: Error
    private var buffer: Data
    private var sealed = 0

    init(output: FileHandle, key: SymmetricKey, prefix: Data, associatedData: Data, recordSize: Int, recordCount: Int,
         overflow: Error = ObscuraCryptoError.invalidSharedItems("more to write than the records hold")) {
        self.output = output
        self.key = key
        self.prefix = prefix
        self.associatedData = associatedData
        self.recordSize = recordSize
        self.recordCount = recordCount
        self.overflow = overflow
        buffer = Data(capacity: recordSize)
    }

    func append(_ data: Data) throws {
        var offset = data.startIndex
        while offset < data.endIndex {
            let take = min(recordSize - buffer.count, data.endIndex - offset)
            buffer.append(data[offset..<offset + take])
            offset += take
            if buffer.count == recordSize { try seal() }
        }
    }

    /// `padding` to the end of the stream, which may be whole records more.
    func finish(padding: UInt8) throws {
        while sealed < recordCount {
            buffer.append(Data(repeating: padding, count: recordSize - buffer.count))
            try autoreleasepool { try seal() }
        }
        guard buffer.isEmpty else { throw overflow }
    }

    private func seal() throws {
        guard sealed < recordCount else { throw overflow }
        let nonce = SharedItemsFile.recordNonce(prefix: prefix, index: UInt64(sealed), isLast: sealed == recordCount - 1)
        try output.write(contentsOf: try AESGCM.seal(buffer, key: key, nonce: AES.GCM.Nonce(data: nonce),
                                                     authenticating: associatedData))
        sealed += 1
        buffer.removeAll(keepingCapacity: true)
    }
}

/// The header and key block of an `.obscurashared` file: everything that can
/// be known without a password.
public struct SharedItemsPreamble: Sendable {
    public struct Lock: Sendable {
        public let type: SharedItemsFile.LockType
        let body: Data

        /// A password lock's PBKDF2 rounds, as the file states them.
        public var rounds: UInt32? {
            type == .password && body.count == SharedItemsFile.passwordLockSize ? body.bigEndianUInt32(at: 0) : nil
        }
    }

    public let formatVersion: UInt16
    public let readableBy: UInt16
    public let flags: UInt16
    public let recordSize: Int
    public let fileId: Data
    public let noncePrefix: Data
    /// Locks of the types this package knows, in file order.
    public let locks: [Lock]
    /// Locks of types this package does not know, passed over.
    public let unknownLockCount: Int
    /// What the content key must give under `SharedItemsFile.keyCommitment`.
    let keyCommitment: Data
    let header: Data
    let keyBlock: Data

    /// The header and key block, the associated data of every record.
    var bytes: Data { header + keyBlock }

    /// Sent without a password: the file holds its own key.
    public var isOpen: Bool { locks.contains { $0.type == .open } }

    public init(url: URL) throws {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        try self.init(handle: handle)
    }

    /// Reads and checks the preamble; the handle is left just after it.
    public init(handle: FileHandle) throws {
        typealias File = SharedItemsFile
        guard let header = try handle.read(upToCount: File.headerSize), header.count == File.headerSize else {
            throw ObscuraCryptoError.invalidSharedItems("shorter than \(File.headerSize) bytes")
        }
        guard header.prefix(4) == File.magic else { throw ObscuraCryptoError.invalidSharedItems("missing OBSI magic") }
        let format = header.bigEndianUInt16(at: 4)
        let readable = header.bigEndianUInt16(at: 6)
        // 1 and 2 were layouts that never shipped; "readable by" above the
        // format that wrote the file is not one any app made.
        guard format >= 3, readable >= 3, readable <= format else {
            throw ObscuraCryptoError.invalidSharedItems("format \(format), readable by \(readable)")
        }
        guard readable <= File.version else { throw ObscuraCryptoError.sharedItemsNewerVersion }
        let flags = header.bigEndianUInt16(at: 8)
        guard flags & File.requiredFlags == 0 else { throw ObscuraCryptoError.sharedItemsNewerVersion }
        let keyBlockLength = Int(header.bigEndianUInt16(at: 10))
        let recordSize = Int(header.bigEndianUInt32(at: 12))
        guard keyBlockLength > File.keyCommitmentSize + 1, keyBlockLength <= File.maximumKeyBlock else {
            throw ObscuraCryptoError.invalidSharedItems("a key block of an impossible length")
        }
        guard File.recordSizes.contains(recordSize) else {
            throw ObscuraCryptoError.invalidSharedItems("records of an impossible size")
        }
        guard let keyBlock = try handle.read(upToCount: keyBlockLength), keyBlock.count == keyBlockLength else {
            throw ObscuraCryptoError.invalidSharedItems("the file ends inside its key block")
        }
        var locks: [Lock] = []
        var unknown = 0
        var offset = File.keyCommitmentSize + 1
        for _ in 0..<Int(keyBlock[keyBlock.startIndex + File.keyCommitmentSize]) {
            guard offset + 3 <= keyBlock.count else { throw ObscuraCryptoError.invalidSharedItems("the key block is cut short") }
            let type = keyBlock[keyBlock.startIndex + offset]
            let length = Int(keyBlock.bigEndianUInt16(at: offset + 1))
            guard offset + 3 + length <= keyBlock.count else {
                throw ObscuraCryptoError.invalidSharedItems("the key block is cut short")
            }
            let start = keyBlock.startIndex + offset + 3
            if let known = SharedItemsFile.LockType(rawValue: type) {
                locks.append(Lock(type: known, body: keyBlock.subdata(in: start..<start + length)))
            } else {
                unknown += 1
            }
            offset += 3 + length
        }
        guard offset == keyBlock.count else { throw ObscuraCryptoError.invalidSharedItems("the key block has bytes left over") }

        self.formatVersion = format
        self.readableBy = readable
        self.flags = flags
        self.recordSize = recordSize
        self.fileId = header.subdata(in: 16..<32)
        self.noncePrefix = header.subdata(in: 32..<36)
        self.locks = locks
        self.unknownLockCount = unknown
        self.keyCommitment = keyBlock.prefix(File.keyCommitmentSize)
        self.header = header
        self.keyBlock = keyBlock
    }

    /// The content key: from an open lock when no password is given, else
    /// from the first password lock `password` opens, spending at most
    /// `roundsBudget` rounds on them all. Either way only the key the file
    /// commits to. No lock this package knows is a newer version.
    ///
    /// A file with an open lock is refused when a password is given
    /// (`sharedItemsNotLocked`): anyone who had it could have made it or
    /// changed it, so it must not pass for one sealed with the password.
    func contentKey(password: String?, roundsBudget: UInt32 = SharedItemsFile.roundsBudget) throws -> SecureBytes {
        if let open = locks.first(where: { $0.type == .open }) {
            guard open.body.count == SharedItemsFile.contentKeySize else {
                throw ObscuraCryptoError.invalidSharedItems("an open lock that holds no key")
            }
            guard password == nil else { throw ObscuraCryptoError.sharedItemsNotLocked }
            let key = SecureBytes(copying: open.body)
            guard try isCommitted(key) else {
                throw ObscuraCryptoError.sharedItemsDamaged("its key is not the one it commits to")
            }
            return key
        }
        let passwordLocks = locks.filter { $0.type == .password }
        guard !passwordLocks.isEmpty else { throw ObscuraCryptoError.sharedItemsNewerVersion }
        guard let password else { throw ObscuraCryptoError.wrongPassword }
        var usable = false
        var spent: UInt32 = 0
        for lock in passwordLocks.prefix(SharedItemsFile.maximumPasswordLocksTried) {
            // Never fewer rounds than a vault's own; a ceiling, per lock and
            // for the file, so a made-up one cannot hold the reader long.
            guard let rounds = lock.rounds, rounds >= KeyDerivation.vaultIterations,
                  rounds <= SharedItemsFile.maximumRounds else { continue }
            usable = true
            guard rounds <= roundsBudget - spent else { break }
            spent += rounds
            let body = lock.body
            let salt = body.subdata(in: (body.startIndex + 4)..<(body.startIndex + 4 + KeyDerivation.saltLength))
            let sealed = body.subdata(in: (body.startIndex + 4 + KeyDerivation.saltLength)..<body.endIndex)
            let passwordKey = try KeyDerivation.pbkdf2SHA256(password: password, salt: salt, iterations: rounds)
            guard var key = try? AESGCM.open(sealed, key: try passwordKey.symmetricKey, authenticating: header) else { continue }
            defer { key.resetBytes(in: 0..<key.count) }
            guard key.count == SharedItemsFile.contentKeySize else { continue }
            // A lock can be made to open under more than one password, each
            // to a different key; only the committed one is the file's.
            let candidate = SecureBytes(copying: key)
            guard try isCommitted(candidate) else { continue }
            return candidate
        }
        if usable { throw ObscuraCryptoError.wrongPassword }
        throw ObscuraCryptoError.invalidSharedItems("no password lock with rounds between 600,000 and 10,000,000")
    }
}

extension SharedItemsPreamble {
    func isCommitted(_ key: SecureBytes) throws -> Bool {
        constantTimeEquals(try SharedItemsFile.keyCommitment(key), keyCommitment)
    }
}

/// The records of an `.obscurashared` file as one plaintext stream, a record
/// in memory at a time.
final class SharedItemsRecordStream {
    private let handle: FileHandle
    private let key: SymmetricKey
    private let prefix: Data
    private let associatedData: Data
    private let recordBytes: Int
    /// The format's own error for a damaged file.
    private let damaged: (String) -> Error
    /// Whole records in the file, and the bytes after them: none in a file
    /// that is whole.
    private let fullRecords: UInt64
    private let leftover: UInt64
    private var index: UInt64 = 0
    private var buffer = Data()
    private var offset = 0
    /// Sealed records read from the file ahead of use, `readSize` at a
    /// time, and how far they have been opened.
    private var sealedAhead = Data()
    private var sealedOffset = 0
    /// The last record, the one with the end mark, has been read.
    private(set) var reachedEnd = false

    convenience init(handle: FileHandle, key: SymmetricKey, preamble: SharedItemsPreamble, bodySize: UInt64) {
        self.init(handle: handle, key: key, prefix: preamble.noncePrefix, associatedData: preamble.bytes,
                  recordSize: preamble.recordSize, bodySize: bodySize) { ObscuraCryptoError.sharedItemsDamaged($0) }
    }

    /// The records that follow a preamble of any format that uses them, a
    /// version 2 export too: `bodySize` bytes from the handle's position.
    init(handle: FileHandle, key: SymmetricKey, prefix: Data, associatedData: Data, recordSize: Int, bodySize: UInt64,
         damaged: @escaping (String) -> Error) {
        self.handle = handle
        self.key = key
        self.prefix = prefix
        self.associatedData = associatedData
        self.recordBytes = recordSize + AESGCM.overhead
        self.fullRecords = bodySize / UInt64(recordBytes)
        self.leftover = bodySize % UInt64(recordBytes)
        self.damaged = damaged
    }

    /// Hands over the next `count` bytes of the stream, a piece at a time.
    func read(_ count: Int64, into body: (Data) throws -> Void) throws {
        var remaining = count
        while remaining > 0 {
            if offset == buffer.count { try nextRecord() }
            let take = Int(min(Int64(buffer.count - offset), remaining))
            let start = buffer.startIndex + offset
            try body(buffer.subdata(in: start..<start + take))
            offset += take
            remaining -= Int64(take)
        }
    }

    func read(_ count: Int) throws -> Data {
        var data = Data(capacity: count)
        try read(Int64(count)) { data.append($0) }
        return data
    }

    /// Reads the rest of the stream, which must be padding: zeros, to the end
    /// of the last record.
    func finish() throws {
        while true {
            guard buffer[(buffer.startIndex + offset)...].allSatisfy({ $0 == 0 }) else {
                throw damaged("there is data after the last item")
            }
            offset = buffer.count
            if reachedEnd { return }
            try nextRecord()
        }
    }

    private func nextRecord() throws {
        guard !reachedEnd else { throw damaged("the file ends inside an item") }
        guard index < fullRecords else { throw damaged("the file ends inside a record") }
        // The last record is the one the file ends with; any bytes after it
        // make it not the last, and its end mark then fails the check.
        let isLast = index == fullRecords - 1 && leftover == 0
        try autoreleasepool {
            if sealedOffset == sealedAhead.count {
                // Whole records, and none past the last whole one.
                let records = max(1, min(SharedItemsFile.readSize / recordBytes, Int(fullRecords - index)))
                sealedAhead = try handle.read(upToCount: records * recordBytes) ?? Data()
                sealedOffset = 0
            }
            guard sealedAhead.count - sealedOffset >= recordBytes else {
                throw damaged("the file ends inside a record")
            }
            let start = sealedAhead.startIndex + sealedOffset
            let sealed = sealedAhead.subdata(in: start..<start + recordBytes)
            sealedOffset += recordBytes
            let nonce = SharedItemsFile.recordNonce(prefix: prefix, index: index, isLast: isLast)
            guard sealed.prefix(AESGCM.nonceSize) == nonce else {
                throw damaged("a record carries the wrong nonce: records were reordered, dropped, replaced or cut off")
            }
            do {
                buffer = try AESGCM.open(sealed, key: key, authenticating: associatedData)
            } catch {
                throw damaged("a record does not authenticate: the file was altered")
            }
        }
        offset = 0
        index += 1
        reachedEnd = isLast
    }
}

/// An opened `.obscurashared` file: the password checked and the manifest
/// read. Every part is then read in the manifest's order with `read` or
/// `skip`, those of kinds this package does not know included, and `finish`
/// checks that only padding follows the last.
public final class SharedItemsReader {
    public let preamble: SharedItemsPreamble
    public let manifest: SharedItemsFile.Manifest

    private let handle: FileHandle
    private let stream: SharedItemsRecordStream
    /// Every part of every item, in file order, and the next one to read.
    private let parts: [SharedItemsFile.Part]
    private var nextPart = 0
    /// Set when a read stopped part way: the stream is out of step.
    private var broken = false

    /// Items of kinds this package knows.
    public var supportedCount: Int { manifest.items.filter { $0.knownKind != nil }.count }

    /// Opens `url` with `password`, nil for a file sent without one (ask
    /// `SharedItemsFile.needsPassword` first). Throws `wrongPassword` without
    /// reading further when it does not open the file,
    /// `sharedItemsNotLocked` when a password is given for a file that has
    /// none, and `sharedItemsNewerVersion` when nothing in it is for this
    /// version.
    public convenience init(url: URL, password: String?) throws {
        try self.init(url: url, password: password, roundsBudget: SharedItemsFile.roundsBudget)
    }

    init(url: URL, password: String?, roundsBudget: UInt32) throws {
        let handle = try FileHandle(forReadingFrom: url)
        _ = fcntl(handle.fileDescriptor, F_NOCACHE, 1)
        self.handle = handle
        do {
            let preamble = try SharedItemsPreamble(handle: handle)
            let fileSize = try handle.seekToEnd()
            let bodyStart = UInt64(preamble.header.count + preamble.keyBlock.count)
            try handle.seek(toOffset: bodyStart)
            let key = try SharedItemsFile.recordKey(try preamble.contentKey(password: password, roundsBudget: roundsBudget))
            let stream = SharedItemsRecordStream(handle: handle, key: key, preamble: preamble, bodySize: fileSize - bodyStart)
            self.preamble = preamble
            self.stream = stream

            let manifestLength = Int(try stream.read(4).bigEndianUInt32(at: 0))
            guard (1...SharedItemsFile.maximumManifest).contains(manifestLength) else {
                throw ObscuraCryptoError.sharedItemsDamaged("a manifest of an impossible length")
            }
            let manifest: SharedItemsFile.Manifest
            do {
                manifest = try SharedItemsFile.Manifest(json: try stream.read(manifestLength))
            } catch let error as SharedItemsJSON.Malformed {
                throw ObscuraCryptoError.sharedItemsDamaged("the manifest is not readable: \(error.reason)")
            }
            guard !manifest.items.isEmpty, manifest.items.count <= SharedItemsFile.maximumItems,
                  manifest.items.allSatisfy(\.isWellFormed) else {
                throw ObscuraCryptoError.sharedItemsDamaged("the manifest lists an item that cannot be")
            }
            guard manifest.items.contains(where: { $0.knownKind != nil }) else {
                throw ObscuraCryptoError.sharedItemsNewerVersion
            }
            self.manifest = manifest
            self.parts = manifest.items.flatMap(\.parts)
        } catch {
            try? handle.close()
            throw error
        }
    }

    deinit { try? handle.close() }

    /// Reads `part`, which must be the next in the file, handing over its
    /// plaintext a piece at a time, then checks its SHA-256. When this throws,
    /// what was handed over is not the part: discard it.
    public func read(_ part: SharedItemsFile.Part, into body: (Data) throws -> Void) throws {
        try readPart(part, body)
    }

    /// Reads past `part`, which must be the next in the file. It is still
    /// decrypted and checked, so the stream stays in order and authentic.
    public func skip(_ part: SharedItemsFile.Part) throws {
        try readPart(part) { _ in }
    }

    /// Checks that every part was read and that only zeros follow the last,
    /// to the end of the file's last record.
    public func finish() throws {
        guard !broken, nextPart == parts.count else {
            throw ObscuraCryptoError.invalidSharedItems("finished before every part was read")
        }
        try stream.finish()
    }

    private func readPart(_ part: SharedItemsFile.Part, _ body: (Data) throws -> Void) throws {
        guard !broken else { throw ObscuraCryptoError.sharedItemsDamaged("an earlier part did not read") }
        guard nextPart < parts.count, parts[nextPart] == part else {
            throw ObscuraCryptoError.invalidSharedItems("parts are read in the order the manifest lists them")
        }
        broken = true
        var hasher = SHA256()
        try stream.read(part.size) { piece in
            hasher.update(data: piece)
            try body(piece)
        }
        guard SharedItemsFile.hex(hasher.finalize()) == part.sha256 else {
            throw ObscuraCryptoError.sharedItemsDamaged("an item does not match its SHA-256")
        }
        broken = false
        nextPart += 1
    }
}
