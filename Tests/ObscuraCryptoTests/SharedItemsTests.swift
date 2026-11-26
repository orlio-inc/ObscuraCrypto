// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CryptoKit
import XCTest
@testable import ObscuraCrypto

/// The `.obscurashared` file: round trips with and without a password, the
/// password check and rules, what the file shows without the password, every
/// way of altering a file, the strict manifest, and the rules for files from
/// later versions. The layout is also checked both ways against `SpecFile`, a
/// writer and reader built from the documented layout alone, so a mistake
/// this package's writer and reader shared would still show.
final class SharedItemsTests: XCTestCase {

    private var scratch: URL!

    override func setUpWithError() throws {
        scratch = FileManager.default.temporaryDirectory.appendingPathComponent("SharedItemsTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: scratch)
    }

    private static let password = "correct horse battery"

    private static func bytes(_ count: Int, seed: UInt8) -> Data {
        Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31) ^ seed })
    }

    private func source(_ data: Data) throws -> URL {
        let url = scratch.appendingPathComponent(UUID().uuidString)
        try data.write(to: url)
        return url
    }

    /// A photo, a video over two records, a Live Photo, and a document.
    private func makeFile(password: String?) throws -> (URL, [Data]) {
        let parts = [Self.bytes(5_000, seed: 1), Self.bytes(SharedItemsFile.recordSize * 2 + 123, seed: 2),
                     Self.bytes(7_000, seed: 3), Self.bytes(SharedItemsFile.recordSize + 77, seed: 4),
                     Self.bytes(1_500, seed: 5)]
        let urls = try parts.map(source)
        let file = scratch.appendingPathComponent("sent.obscurashared")
        try SharedItemsFile.write([
            .init(url: urls[0], kind: .photo, mimeType: "image/jpeg"),
            .init(url: urls[1], kind: .video, mimeType: "video/quicktime"),
            .init(url: urls[2], kind: .livePhoto, pairedVideo: urls[3], mimeType: "image/heic"),
            .init(url: urls[4], kind: .pdf, name: "Lease", mimeType: "application/pdf"),
        ], password: password, to: file)
        return (file, parts)
    }

    /// Every part of every item this package knows, in order; parts and kinds
    /// it does not know are read past.
    private func readAll(_ file: URL, password: String?) throws -> [Data] {
        let reader = try SharedItemsReader(url: file, password: password)
        var parts: [Data] = []
        for item in reader.manifest.items {
            for part in item.parts {
                let known = item.knownKind != nil && SharedItemsFile.Role(rawValue: part.role) != nil
                    && !(part.role == "motion" && item.knownKind != .livePhoto)
                guard known else {
                    try reader.skip(part)
                    continue
                }
                var data = Data()
                try reader.read(part) { data.append($0) }
                parts.append(data)
            }
        }
        try reader.finish()
        return parts
    }

    private func assertRefused(_ expected: String, _ file: URL, password: String?, _ message: String = "",
                               file sourceFile: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try readAll(file, password: password), message, file: sourceFile, line: line) {
            XCTAssertEqual(($0 as? ObscuraCryptoError).map(CompatWriter.name(of:)) ?? "\($0)", expected,
                           "\(message): \($0)", file: sourceFile, line: line)
        }
    }

    private func spec(_ password: String? = nil, _ configure: (inout SpecFile) -> Void = { _ in }) throws -> URL {
        var spec = SpecFile(password: password)
        spec.items = [.init(kind: "photo", parts: [("file", Self.bytes(2_000, seed: 1))])]
        configure(&spec)
        return try spec.write(in: scratch)
    }

    // MARK: Round trips

    func testRoundTripWithPassword() throws {
        let (file, parts) = try makeFile(password: Self.password)
        XCTAssertTrue(try SharedItemsFile.needsPassword(file))
        XCTAssertEqual(try readAll(file, password: Self.password), parts)
    }

    func testRoundTripWithoutPassword() throws {
        let (file, parts) = try makeFile(password: nil)
        XCTAssertFalse(try SharedItemsFile.needsPassword(file))
        XCTAssertEqual(try readAll(file, password: nil), parts)
    }

    /// A file sent with a password can be swapped on the way for one sent
    /// without: a reader given the password refuses it rather than open it
    /// as though it were the sender's.
    func testAnOpenFileIsRefusedWhenAPasswordIsGiven() throws {
        let (file, _) = try makeFile(password: nil)
        assertRefused("sharedItemsNotLocked", file, password: Self.password)
    }

    /// AES-GCM does not commit to its key, so a lock can be made to open
    /// under several passwords, each to a different key. Only the key the
    /// file commits to opens it: any other is a wrong password, and an open
    /// lock holding another key is damage.
    func testOnlyTheCommittedKeyOpensAFile() throws {
        assertRefused("wrongPassword", try spec(Self.password) { $0.commitsToKey = false }, password: Self.password)
        assertRefused("sharedItemsDamaged", try spec(nil) { $0.commitsToKey = false }, password: nil)
    }

    func testTheManifestCarriesKindsTypesAndATitle() throws {
        let (file, _) = try makeFile(password: nil)
        let reader = try SharedItemsReader(url: file, password: nil)
        XCTAssertEqual(reader.manifest.items.map(\.kind), ["photo", "video", "livePhoto", "pdf"])
        XCTAssertEqual(reader.manifest.items.map(\.type), ["image/jpeg", "video/quicktime", "image/heic", "application/pdf"])
        XCTAssertEqual(reader.manifest.items.last?.name, "Lease")
        XCTAssertEqual(reader.supportedCount, 4)
        XCTAssertEqual(reader.preamble.locks.map(\.type), [.open])
        XCTAssertEqual(reader.preamble.recordSize, SharedItemsFile.recordSize)
    }

    func testAPasswordLockUsesTheVaultsRounds() throws {
        let (file, _) = try makeFile(password: Self.password)
        let preamble = try SharedItemsPreamble(url: file)
        XCTAssertEqual(preamble.locks.map(\.rounds), [KeyDerivation.vaultIterations])
        XCTAssertEqual(preamble.formatVersion, 3)
        XCTAssertEqual(preamble.readableBy, 3)
    }

    func testWrongOrMissingPasswordIsRefused() throws {
        let (file, _) = try makeFile(password: Self.password)
        assertRefused("wrongPassword", file, password: "wrong horse battery")
        assertRefused("wrongPassword", file, password: nil)
    }

    func testNoPlaintextInTheFile() throws {
        let marker = Data("A VERY RECOGNISABLE PLAINTEXT MARKER".utf8)
        let file = scratch.appendingPathComponent("f.obscurashared")
        try SharedItemsFile.write([.init(url: try source(marker), kind: .pdf, name: "Lease")], password: Self.password, to: file)
        let written = try Data(contentsOf: file)
        XCTAssertNil(written.range(of: marker))
        XCTAssertNil(written.range(of: Data("Lease".utf8)), "the manifest is sealed too")
    }

    // MARK: What the file shows without the password

    /// The items run on from one to the next inside equal records, so
    /// neither how many there are nor how large each is shows: two files
    /// whose items come to the same total are the same length, every record
    /// the same size.
    func testItemCountAndSizesDoNotShow() throws {
        func write(_ sizes: [Int]) throws -> URL {
            let file = scratch.appendingPathComponent("\(sizes).obscurashared")
            let sources = try sizes.enumerated().map {
                SharedItemsFile.Source(url: try source(Self.bytes($0.element, seed: UInt8($0.offset))), kind: .photo)
            }
            try SharedItemsFile.write(sources, password: nil, to: file, attributes: nil,
                                      rounds: KeyDerivation.vaultIterations, recordSize: 4_096)
            return file
        }
        let one = try write([5_000, 2_000])
        let other = try write([1_000, 3_000, 2_500])
        let size = { (url: URL) in try FileManager.default.attributesOfItem(atPath: url.path)[.size] as! Int }
        // Different counts and sizes, and manifests of different lengths,
        // padded to the same two records.
        XCTAssertEqual(try size(one), try size(other))
        let read = try SpecFile.read(one, password: nil)
        XCTAssertTrue(read.recordLengths.allSatisfy { $0 == 4_096 + 28 }, "every record is the same size")
        XCTAssertTrue(read.paddingIsZero)
    }

    func testPadmeRoundsUpByAtMostAnEighth() {
        for length in [2, 3, 9, 100, 1_000, 65_537, 1_048_577, 10_000_000, 3_000_000_000] {
            let padded = SharedItemsFile.padme(length)
            XCTAssertGreaterThanOrEqual(padded, length)
            XCTAssertLessThanOrEqual(Double(padded - length), Double(length) * 0.125, "\(length)")
            XCTAssertEqual(SharedItemsFile.padme(padded), padded, "\(length) pads to a length that pads to itself")
        }
        // Worked from the definition: E = 29 for 1e9, S = 5, so the low 24 bits go.
        XCTAssertEqual(SharedItemsFile.padme(1_000_000_000), 1_006_632_960)
    }

    // MARK: Passwords

    func testPasswordRules() {
        for (password, problem) in [
            ("short pw", SharedItemsFile.PasswordProblem.tooShort), ("aaaaaaaaaaaa", .tooSimple), ("1212121212", .tooSimple),
            ("0123456789012", .tooSimple), ("qwertyuiop", .tooSimple), ("ZYXWVUTSRQ", .tooSimple),
            ("Password123!", .tooCommon), ("P@ssw0rd2024", .tooCommon), ("iloveyou2024", .tooCommon),
            ("monkeymonkey1", .tooCommon), ("!!obscura12345", .tooCommon), ("Summer2025!!", .tooCommon),
        ] {
            XCTAssertEqual(SharedItemsFile.passwordProblem(password), problem, password)
        }
        for password in ["correct horse battery", "Tr0ub4dor&3x", "lunch-orbit-gravity", "Ünïcödé pässwörd", "пароль-для-файла"] {
            XCTAssertNil(SharedItemsFile.passwordProblem(password), password)
        }
    }

    /// The rules are advice: the writer takes any password.
    func testAWeakPasswordIsTakenAllTheSame() throws {
        let file = scratch.appendingPathComponent("weak.obscurashared")
        try SharedItemsFile.write([.init(url: try source(Self.bytes(10, seed: 1)), kind: .photo)],
                                  password: "abc123", to: file)
        XCTAssertNotNil(SharedItemsFile.passwordProblem("abc123"))
        XCTAssertEqual(try readAll(file, password: "abc123"), [Self.bytes(10, seed: 1)])
    }

    func testSuggestedPasswordsAreSixDifferentListWords() throws {
        let first = try SharedItemsFile.suggestedPassword()
        let words = first.split(separator: "-").map(String.init)
        XCTAssertEqual(words.count, 6)
        XCTAssertEqual(Set(words).count, 6)
        XCTAssertTrue(words.allSatisfy(RecoveryPhrase.words.contains))
        XCTAssertNil(SharedItemsFile.passwordProblem(first))
        XCTAssertNotEqual(first, try SharedItemsFile.suggestedPassword())
    }

    /// A made-up file with many expensive locks costs the reader at most the
    /// budget: here, with a budget of one lock, the second is never tried.
    func testPasswordLocksStopAtTheRoundsBudget() throws {
        let file = try spec("between us both") { $0.extraPasswordLocks = [("another password", 600_000)] }
        XCTAssertEqual(try readAll(file, password: "between us both").count, 1)
        XCTAssertThrowsError(try SharedItemsReader(url: file, password: "between us both", roundsBudget: 1_000_000)) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .wrongPassword)
        }
    }

    // MARK: Writing

    func testWhatCannotBeSentIsRefused() throws {
        let still = try source(Self.bytes(100, seed: 1))
        let video = try source(Self.bytes(100, seed: 2))
        let file = scratch.appendingPathComponent("never.obscurashared")
        for (name, sources) in [
            ("a Live Photo without its motion", [SharedItemsFile.Source(url: still, kind: .livePhoto)]),
            ("a photo with a motion", [SharedItemsFile.Source(url: still, kind: .photo, pairedVideo: video)]),
            ("an empty file", [SharedItemsFile.Source(url: try source(Data()), kind: .photo)]),
        ] {
            XCTAssertThrowsError(try SharedItemsFile.write(sources, password: nil, to: file), name) {
                guard case ObscuraCryptoError.invalidSharedItems = $0 else { return XCTFail("\(name): \($0)") }
            }
        }
        XCTAssertThrowsError(try SharedItemsFile.write([], password: nil, to: file)) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .tooManySharedItems(0))
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }

    func testAFailedWriteLeavesNothingBehind() throws {
        let destination = scratch.appendingPathComponent("never.obscurashared")
        let missing = scratch.appendingPathComponent("does-not-exist")
        XCTAssertThrowsError(try SharedItemsFile.write([.init(url: missing, kind: .photo)], password: nil, to: destination))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: scratch.path).filter { $0.hasSuffix(".partial") }, [])
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
    }

    /// Titles go in cleaned: control and direction characters as spaces,
    /// invisible ones left out, ends trimmed, at most 200 scalars. The
    /// joiners emoji and some scripts need stay.
    func testATitleIsCleanedAndCut() throws {
        let joined = scratch.appendingPathComponent("joined.obscurashared")
        try SharedItemsFile.write([.init(url: try source(Self.bytes(10, seed: 1)), kind: .pdf,
                                         name: "\u{200B}Mi\u{FEFF}et\u{2060}vertrag\u{E0041} \u{1F468}\u{200D}\u{1F469}")],
                                  password: nil, to: joined)
        XCTAssertEqual(try SharedItemsReader(url: joined, password: nil).manifest.items[0].name,
                       "Mietvertrag \u{1F468}\u{200D}\u{1F469}")
        let file = scratch.appendingPathComponent("title.obscurashared")
        let name = "\u{202E}Lease\nfor 2027\u{0007} " + String(repeating: "a", count: 500)
        try SharedItemsFile.write([.init(url: try source(Self.bytes(10, seed: 1)), kind: .pdf, name: name)],
                                  password: nil, to: file)
        let title = try XCTUnwrap(try SharedItemsReader(url: file, password: nil).manifest.items[0].name)
        XCTAssertTrue(title.hasPrefix("Lease for 2027  aaa"))
        XCTAssertEqual(title.unicodeScalars.count, 200)
    }

    /// A title may not hide anything, nor show nothing: Unicode's ignorable
    /// characters (variation selectors, Hangul fillers, the soft hyphen and
    /// the rest) are refused, presentation selectors only after a visible
    /// character, and a title of spaces and blanks is no title.
    func testTitlesThatHideOrShowNothingAreRefused() {
        for name in ["Passport\u{FE01}", "a\u{E0100}", "\u{FE0F}Lease", "Lease \u{FE0F}", "\u{3164}", "a\u{115F}b",
                     "pa\u{00AD}ss", "a\u{034F}b", "\u{3000}\u{2800}", " ", "\u{200D}"] {
            XCTAssertFalse(SharedItemsFile.isAcceptableName(name), name.unicodeScalars.map { String($0.value, radix: 16) }.joined(separator: " "))
        }
        for name in ["\u{2764}\u{FE0F} Lease", "Pass\u{200C}port", "\u{1F468}\u{200D}\u{1F469}", "日本\u{3000}語", " Lease "] {
            XCTAssertTrue(SharedItemsFile.isAcceptableName(name), name)
        }
        XCTAssertEqual(SharedItemsFile.cleanedName("\u{FE0F}\u{2764}\u{FE0F}\u{FE0F} Lease\u{3000}\u{FE01}"), "\u{2764}\u{FE0F} Lease")
        XCTAssertNil(SharedItemsFile.cleanedName("\u{3164}\u{2800}\u{3000}"))
    }

    // MARK: Tampering

    func testAlteredBytesAreRefused() throws {
        let (file, _) = try makeFile(password: nil)
        let original = try Data(contentsOf: file)
        for offset in [original.count - 40, original.count / 2, 200] {
            var bytes = original
            bytes[offset] ^= 0x01
            try bytes.write(to: file)
            assertRefused("sharedItemsDamaged", file, password: nil, "byte \(offset)")
        }
    }

    /// The header and key block are associated data of every record, and the
    /// header of the password lock: even a reserved byte or the file id
    /// cannot be changed.
    func testAlteredHeaderOrKeyBlockIsRefused() throws {
        for (password, offset, expected) in [
            (nil, 40, "sharedItemsDamaged"), (nil, 20, "sharedItemsDamaged"),
            (nil, SharedItemsFile.headerSize + 5, "sharedItemsDamaged"),
            (Self.password, 40, "wrongPassword"), (Self.password, 33, "wrongPassword"),
        ] as [(String?, Int, String)] {
            let (file, _) = try makeFile(password: password)
            var bytes = try Data(contentsOf: file)
            bytes[offset] ^= 0x01
            try bytes.write(to: file)
            assertRefused(expected, file, password: password, "byte \(offset)")
        }
    }

    /// Swapping two whole records keeps each one authentic on its own; the
    /// nonce check is what catches it.
    func testReorderedRecordsAreRefused() throws {
        let (file, _) = try makeFile(password: Self.password)
        try CompatWriter.swappingRecords(try Data(contentsOf: file), 1, 2).write(to: file)
        assertRefused("sharedItemsDamaged", file, password: Self.password)
    }

    func testCutShortOrAddedToIsRefused() throws {
        let (file, _) = try makeFile(password: nil)
        let bytes = try Data(contentsOf: file)
        let record = SharedItemsFile.recordSize + 28
        for (name, altered) in [
            ("a byte off", bytes.dropLast(1)), ("half a record off", bytes.dropLast(record / 2)),
            ("the last record off", bytes.dropLast(record)), ("bytes added", bytes + Data(count: 8)),
            ("a record added", bytes + bytes.suffix(record)),
        ] {
            try Data(altered).write(to: file)
            assertRefused("sharedItemsDamaged", file, password: nil, name)
        }
        try bytes.prefix(10).write(to: file)
        XCTAssertThrowsError(try SharedItemsFile.needsPassword(file)) {
            guard case ObscuraCryptoError.invalidSharedItems = $0 else { return XCTFail("\($0)") }
        }
    }

    func testTheLastRecordMustCarryTheEndMark() throws {
        assertRefused("sharedItemsDamaged", try spec { $0.marksLastRecord = false }, password: nil)
    }

    func testPaddingMustBeZeros() throws {
        assertRefused("sharedItemsDamaged", try spec { $0.trailing = Data([0, 0, 1]) }, password: nil)
        XCTAssertEqual(try readAll(try spec { $0.extraZeroRecords = 2 }, password: nil).count, 1,
                       "whole records of zeros after the items are padding")
    }

    func testAFileThatIsNotOneIsSaidSo() throws {
        let other = scratch.appendingPathComponent("other")
        try Data((0..<500).map { UInt8($0 % 256) }).write(to: other)
        assertRefused("invalidSharedItems", other, password: nil)
        assertRefused("invalidSharedItems", try spec { $0.format = 2; $0.readableBy = 2 }, password: nil,
                      "a layout that never shipped")
        assertRefused("invalidSharedItems", try spec { $0.recordSize = 1_000 }, password: nil, "records too small")
    }

    func testPartsAreReadInTheirOrderOnly() throws {
        let (file, _) = try makeFile(password: nil)
        let reader = try SharedItemsReader(url: file, password: nil)
        let items = reader.manifest.items
        XCTAssertThrowsError(try reader.skip(items[1].parts[0])) {
            guard case ObscuraCryptoError.invalidSharedItems = $0 else { return XCTFail("\($0)") }
        }
        try reader.skip(items[0].parts[0])
        XCTAssertThrowsError(try reader.finish(), "parts are left")
    }

    // MARK: The strict manifest

    /// Each of these reads one way in one JSON library and another way, or
    /// not at all, in the next. Both of this package's readers refuse them.
    func testAManifestOutsideTheStrictFormIsDamaged() throws {
        let hash = String(repeating: "0", count: 64)
        let part = #"{"role":"file","size":2000,"sha256":"\#(hash)"}"#
        let cases: [(String, Data)] = [
            ("a name twice", Data(#"{"items":[{"kind":"photo","kind":"pdf","parts":[\#(part)]}]}"#.utf8)),
            ("items twice", Data(#"{"items":[],"items":[{"kind":"photo","parts":[\#(part)]}]}"#.utf8)),
            ("a fraction", Data(#"{"items":[{"kind":"photo","parts":[{"role":"file","size":2000.0,"sha256":"\#(hash)"}]}]}"#.utf8)),
            ("an exponent", Data(#"{"items":[{"kind":"photo","parts":[{"role":"file","size":2e3,"sha256":"\#(hash)"}]}]}"#.utf8)),
            ("a leading zero", Data(#"{"items":[{"kind":"photo","parts":[{"role":"file","size":02000,"sha256":"\#(hash)"}]}]}"#.utf8)),
            ("a size as text", Data(#"{"items":[{"kind":"photo","parts":[{"role":"file","size":"2000","sha256":"\#(hash)"}]}]}"#.utf8)),
            ("a byte-order mark", Data([0xEF, 0xBB, 0xBF]) + Data(#"{"items":[{"kind":"photo","parts":[\#(part)]}]}"#.utf8)),
            ("UTF-16", #"{"items":[{"kind":"photo","parts":[\#(part)]}]}"#.data(using: .utf16BigEndian)!),
            ("a lone surrogate", Data(#"{"items":[{"kind":"photo","x":"\uD800","parts":[\#(part)]}]}"#.utf8)),
            ("malformed UTF-8", Data(#"{"items":[{"kind":"photo","x":""#.utf8) + Data([0xC0, 0xAF])
                + Data(#"","parts":[\#(part)]}]}"#.utf8)),
            ("nested too deeply", Data((#"{"items":[{"kind":"photo","x":"# + String(repeating: "[", count: 20)
                + String(repeating: "]", count: 20) + #","parts":[\#(part)]}]}"#).utf8)),
            ("data after the JSON", Data(#"{"items":[{"kind":"photo","parts":[\#(part)]}]} {}"#.utf8)),
            ("a kind outside ASCII", Data(#"{"items":[{"kind":"phötö","parts":[\#(part)]}]}"#.utf8)),
            ("roles that differ only in composition", Data(#"{"items":[{"kind":"x","parts":[{"role":"é","size":1,"sha256":"\#(hash)"},{"role":"é","size":1,"sha256":"\#(hash)"}]}]}"#.utf8)),
            ("an uppercase hash", Data(#"{"items":[{"kind":"photo","parts":[{"role":"file","size":2000,"sha256":"\#(String(repeating: "A", count: 64))"}]}]}"#.utf8)),
            ("a title with a line break", Data(#"{"items":[{"kind":"pdf","name":"a\nb","parts":[\#(part)]}]}"#.utf8)),
            ("a title too long", Data(#"{"items":[{"kind":"pdf","name":"\#(String(repeating: "a", count: 201))","parts":[\#(part)]}]}"#.utf8)),
            ("seventeen parts", Data(#"{"items":[{"kind":"x","parts":[\#((0..<17).map { #"{"role":"r\#($0)","size":1,"sha256":"\#(hash)"}"# }.joined(separator: ","))]}]}"#.utf8)),
        ]
        for (name, manifest) in cases {
            assertRefused("sharedItemsDamaged", try spec { $0.manifestOverride = manifest }, password: nil, name)
        }
    }

    // MARK: The documented layout

    func testWrittenFilesMatchTheDocumentedLayout() throws {
        for password in [Self.password, nil] as [String?] {
            let (file, parts) = try makeFile(password: password)
            let read = try SpecFile.read(file, password: password)
            XCTAssertEqual(read.format, 3)
            XCTAssertEqual(read.readableBy, 3)
            XCTAssertEqual(read.flags, 0)
            XCTAssertTrue(read.reservedAreZero)
            XCTAssertTrue(read.paddingIsZero)
            XCTAssertEqual(read.parts, parts)
            XCTAssertEqual(read.rounds, password == nil ? nil : 600_000)
        }
    }

    func testAFileWrittenFromTheDocumentationOpens() throws {
        for password in ["between us both", nil] as [String?] {
            XCTAssertEqual(try readAll(try spec(password), password: password), [Self.bytes(2_000, seed: 1)])
        }
    }

    // MARK: Files from later versions

    /// Everything a later version may add without raising "readable by" is
    /// passed over: a higher format number, an optional flag, a lock type
    /// beside the password, more rounds, unknown JSON members, an item kind
    /// and a part this package does not know.
    func testALaterFileThisVersionCanReadOpens() throws {
        let photo = Self.bytes(4_000, seed: 5)
        let still = Self.bytes(2_000, seed: 6)
        let motion = Self.bytes(10_000, seed: 7)
        let file = try spec("between us both") {
            $0.format = 7
            $0.flags = 0x0100
            $0.rounds = 700_000
            $0.unknownLocks = [(42, Data(repeating: 1, count: 80))]
            $0.extraManifest = ["sender": "someone", "expires": "2027-01-01"]
            $0.items = [
                .init(kind: "audio", parts: [("file", Self.bytes(1_500, seed: 8))]),
                .init(kind: "photo", parts: [("thumbnail", Self.bytes(300, seed: 9)), ("file", photo)],
                      extra: ["caption": "at the lake"]),
                .init(kind: "livePhoto", parts: [("file", still), ("motion", motion)]),
            ]
        }
        let reader = try SharedItemsReader(url: file, password: "between us both")
        XCTAssertEqual(reader.manifest.items.count, 3)
        XCTAssertEqual(reader.supportedCount, 2)
        XCTAssertEqual(reader.preamble.unknownLockCount, 1)
        XCTAssertEqual(try readAll(file, password: "between us both"), [photo, still, motion])
        assertRefused("wrongPassword", file, password: "not it at all")
    }

    /// What only a newer reader can open says so, never "damaged".
    func testAFileForANewerReaderAsksForAnUpdate() throws {
        let item = SpecFile.Item(kind: "audio", parts: [("file", Self.bytes(100, seed: 2))])
        for (name, configure) in [
            ("readable by 4", { (spec: inout SpecFile) in spec.format = 4; spec.readableBy = 4 }),
            ("a required flag", { (spec: inout SpecFile) in spec.flags = 0x0001 }),
            ("only an unknown lock", { (spec: inout SpecFile) in
                spec.knownLock = false
                spec.unknownLocks = [(3, Data(repeating: 2, count: 64))]
            }),
            ("only unknown kinds", { (spec: inout SpecFile) in spec.items = [item] }),
        ] as [(String, (inout SpecFile) -> Void)] {
            XCTAssertThrowsError(try SharedItemsReader(url: try spec(nil, configure), password: nil), name) {
                XCTAssertEqual($0 as? ObscuraCryptoError, .sharedItemsNewerVersion, name)
            }
        }
    }

    /// Fewer rounds than a vault's own are not a file Obscura made; a count
    /// past the ceiling would hold the reader for minutes.
    func testRoundsOutsideTheLimitsAreRefused() throws {
        for rounds: UInt32 in [100_000, 599_999, SharedItemsFile.maximumRounds + 1] {
            // The reader refuses on the count alone, so the lock need not open.
            let file = try spec("between us both") { $0.rounds = rounds; $0.sealsLock = false }
            assertRefused("invalidSharedItems", file, password: "between us both", "\(rounds)")
        }
    }

    /// A known kind missing a part it needs is damaged, not newer.
    func testAKnownKindWithoutItsPartsIsDamaged() throws {
        for item in [
            SpecFile.Item(kind: "livePhoto", parts: [("file", Self.bytes(100, seed: 1))]),
            SpecFile.Item(kind: "photo", parts: [("file", Self.bytes(100, seed: 1)), ("motion", Self.bytes(100, seed: 2))]),
            SpecFile.Item(kind: "video", parts: [("thumbnail", Self.bytes(100, seed: 1))]),
        ] {
            assertRefused("sharedItemsDamaged", try spec { $0.items = [item] }, password: nil, item.kind)
        }
    }
}

/// The documented layout (FORMATS.md), written and read here from CryptoKit,
/// Foundation's JSON and the package's PBKDF2 alone, sharing no code with
/// the package's reader and writer.
struct SpecFile {
    struct Item {
        var kind: String
        var parts: [(role: String, data: Data)]
        var extra: [String: String] = [:]
    }

    var password: String?
    var format: UInt16 = 3
    var readableBy: UInt16 = 3
    var flags: UInt16 = 0
    var rounds: UInt32 = 600_000
    var recordSize = 4_096
    /// A password or open lock, after any unknown ones.
    var knownLock = true
    var unknownLocks: [(type: UInt8, body: Data)] = []
    /// Password locks before the known one, each under its own password.
    var extraPasswordLocks: [(password: String, rounds: UInt32)] = []
    var extraManifest: [String: String] = [:]
    var items: [Item] = []
    /// The manifest's bytes as they are, in place of one made from `items`.
    var manifestOverride: Data?
    /// Bytes after the last part, before the zeros.
    var trailing = Data()
    var extraZeroRecords = 0
    var marksLastRecord = true
    /// False writes a password lock of random bytes, skipping the derivation.
    var sealsLock = true
    /// False writes a key commitment to some other key.
    var commitsToKey = true

    init(password: String?) { self.password = password }

    private static func random(_ count: Int) -> Data { Data((0..<count).map { _ in UInt8.random(in: 0...255) }) }

    func write(in directory: URL) throws -> URL {
        let manifest: Data
        if let manifestOverride {
            manifest = manifestOverride
        } else {
            var manifestItems: [[String: Any]] = []
            for item in items {
                var entry: [String: Any] = item.extra
                entry["kind"] = item.kind
                entry["parts"] = item.parts.map { part -> [String: Any] in
                    ["role": part.role, "size": part.data.count,
                     "sha256": SHA256.hash(data: part.data).map { String(format: "%02x", $0) }.joined()]
                }
                manifestItems.append(entry)
            }
            var manifestObject: [String: Any] = extraManifest
            manifestObject["items"] = manifestItems
            manifest = try JSONSerialization.data(withJSONObject: manifestObject)
        }

        let contentKey = SymmetricKey(size: .bits256)
        let keyData = contentKey.withUnsafeBytes { Data($0) }
        let prefix = Self.random(4)
        var locks: [(UInt8, Data)] = unknownLocks.map { ($0.type, $0.body) }
            + extraPasswordLocks.map { _ in (UInt8(1), Data(count: 96)) }
        if knownLock { locks.append((password == nil ? 2 : 1, Data(count: password == nil ? 32 : 96))) }
        let keyBlockLength = 32 + 1 + locks.reduce(0) { $0 + 3 + $1.1.count }

        var header = Data("OBSI".utf8)
        header.append(be(format)); header.append(be(readableBy)); header.append(be(flags))
        header.append(be(UInt16(keyBlockLength))); header.append(be(UInt32(recordSize)))
        header.append(Self.random(16))
        header.append(prefix)
        header.append(Data(count: 64 - header.count))

        func passwordLock(_ password: String, rounds: UInt32) throws -> Data {
            let salt = Self.random(32)
            let kek = try KeyDerivation.pbkdf2SHA256(password: password, salt: salt, iterations: rounds)
                .withUnsafeBytes { SymmetricKey(data: Data($0)) }
            return be(rounds) + salt + (try AES.GCM.seal(keyData, using: kek, authenticating: header).combined!)
        }
        for (index, extra) in extraPasswordLocks.enumerated() {
            locks[unknownLocks.count + index].1 = try passwordLock(extra.password, rounds: extra.rounds)
        }
        if knownLock {
            if password != nil, !sealsLock {
                locks[locks.count - 1].1 = be(rounds) + Self.random(92)
            } else if let password {
                locks[locks.count - 1].1 = try passwordLock(password, rounds: rounds)
            } else {
                locks[locks.count - 1].1 = keyData
            }
        }
        // HKDF-SHA256 over the content key, salt 32 zero bytes, info "OBSI v3 key commitment".
        let committed = commitsToKey ? contentKey : SymmetricKey(size: .bits256)
        var keyBlock = subkey(committed, "OBSI v3 key commitment").withUnsafeBytes { Data($0) }
        keyBlock.append(UInt8(locks.count))
        for (type, body) in locks { keyBlock.append(type); keyBlock.append(be(UInt16(body.count))); keyBlock.append(body) }
        let preamble = header + keyBlock

        var stream = be(UInt32(manifest.count)) + manifest
        for item in items { for part in item.parts { stream.append(part.data) } }
        stream.append(trailing)
        let records = max(1, (stream.count + recordSize - 1) / recordSize) + extraZeroRecords
        stream.append(Data(count: records * recordSize - stream.count))

        var out = preamble
        for index in 0..<records {
            var counter = UInt64(index)
            if index == records - 1, marksLastRecord { counter |= 1 << 63 }
            let nonce = try AES.GCM.Nonce(data: prefix + be(counter))
            let plaintext = stream.subdata(in: (index * recordSize)..<((index + 1) * recordSize))
            out.append(try AES.GCM.seal(plaintext, using: subkey(contentKey, "OBSI v3 records"), nonce: nonce,
                                        authenticating: preamble).combined!)
        }
        let url = directory.appendingPathComponent("\(UUID().uuidString).obscurashared")
        try out.write(to: url)
        return url
    }

    struct Read {
        let format: UInt16
        let readableBy: UInt16
        let flags: UInt16
        let reservedAreZero: Bool
        let rounds: UInt32?
        let recordLengths: [Int]
        let paddingIsZero: Bool
        let parts: [Data]
    }

    static func read(_ url: URL, password: String?) throws -> Read {
        let bytes = try Data(contentsOf: url)
        func u16(_ at: Int) -> UInt16 { UInt16(bytes[at]) << 8 | UInt16(bytes[at + 1]) }
        func u32(_ at: Int) -> UInt32 { (0..<4).reduce(UInt32(0)) { $0 << 8 | UInt32(bytes[at + $1]) } }
        guard bytes.prefix(4) == Data("OBSI".utf8) else { throw CocoaError(.fileReadCorruptFile) }
        let header = bytes.prefix(64)
        let keyBlockLength = Int(u16(10))
        let recordSize = Int(u32(12))
        let prefix = bytes.subdata(in: 32..<36)
        let preamble = bytes.prefix(64 + keyBlockLength)

        var key: SymmetricKey?
        var rounds: UInt32?
        let commitment = bytes.subdata(in: 64..<96)
        var offset = 97
        for _ in 0..<Int(bytes[96]) {
            let type = bytes[offset]
            let length = Int(u16(offset + 1))
            let body = bytes.subdata(in: (offset + 3)..<(offset + 3 + length))
            if type == 2 { key = SymmetricKey(data: body) }
            if type == 1, let password {
                let r = (0..<4).reduce(UInt32(0)) { $0 << 8 | UInt32(body[body.startIndex + $1]) }
                let salt = body.subdata(in: (body.startIndex + 4)..<(body.startIndex + 36))
                let kek = try KeyDerivation.pbkdf2SHA256(password: password, salt: salt, iterations: r)
                    .withUnsafeBytes { SymmetricKey(data: Data($0)) }
                let box = try AES.GCM.SealedBox(combined: body.subdata(in: (body.startIndex + 36)..<body.endIndex))
                key = SymmetricKey(data: try AES.GCM.open(box, using: kek, authenticating: header))
                rounds = r
            }
            offset += 3 + length
        }
        guard let key else { throw CocoaError(.fileReadNoPermission) }
        guard subkey(key, "OBSI v3 key commitment").withUnsafeBytes({ Data($0) }) == commitment else {
            throw CocoaError(.fileReadCorruptFile)
        }

        var stream = Data()
        var lengths: [Int] = []
        let recordBytes = recordSize + 28
        let count = (bytes.count - offset) / recordBytes
        guard (bytes.count - offset) % recordBytes == 0 else { throw CocoaError(.fileReadCorruptFile) }
        for index in 0..<count {
            let start = offset + index * recordBytes
            let box = try AES.GCM.SealedBox(combined: bytes.subdata(in: start..<(start + recordBytes)))
            let counter = UInt64(index) | (index == count - 1 ? 1 << 63 : 0)
            guard Data(box.nonce) == prefix + be(counter) else { throw CocoaError(.fileReadCorruptFile) }
            stream.append(try AES.GCM.open(box, using: subkey(key, "OBSI v3 records"), authenticating: preamble))
            lengths.append(recordBytes)
        }
        let manifestLength = Int((0..<4).reduce(UInt32(0)) { $0 << 8 | UInt32(stream[$1]) })
        let manifest = try JSONSerialization.jsonObject(with: stream.subdata(in: 4..<(4 + manifestLength))) as! [String: Any]
        var parts: [Data] = []
        var position = 4 + manifestLength
        for item in manifest["items"] as! [[String: Any]] {
            for part in item["parts"] as! [[String: Any]] {
                let size = part["size"] as! Int
                parts.append(stream.subdata(in: position..<(position + size)))
                position += size
            }
        }
        return Read(format: u16(4), readableBy: u16(6), flags: u16(8), reservedAreZero: bytes[36..<64].allSatisfy { $0 == 0 },
                    rounds: rounds, recordLengths: lengths, paddingIsZero: stream[position...].allSatisfy { $0 == 0 },
                    parts: parts)
    }
}

/// A key derived as the format describes: HKDF-SHA256, salt 32 zero bytes.
private func subkey(_ key: SymmetricKey, _ info: String) -> SymmetricKey {
    HKDF<SHA256>.deriveKey(inputKeyMaterial: key, salt: Data(count: 32), info: Data(info.utf8), outputByteCount: 32)
}

private func be<T: FixedWidthInteger>(_ value: T) -> Data {
    var big = value.bigEndian
    return Data(bytes: &big, count: MemoryLayout<T>.size)
}
