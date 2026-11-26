// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CryptoKit
import Foundation
@testable import ObscuraCrypto

/// Writes this language's cross-language fixture set. See `CompatFixtureTests`.
///
/// Exports are written here twice: by the package's own writer (version 2,
/// what the app ships), and by small independent writers built from the
/// format description (versions 1 and 2), not by the iOS app and not by the
/// Kotlin library, so that the Kotlin reader is tested against a third
/// implementation too.
enum CompatWriter {

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// The Swift case name, as the Kotlin side spells the same error.
    static func name(of error: ObscuraCryptoError) -> String {
        switch error {
        case .randomUnavailable: return "randomUnavailable"
        case .keyCleared: return "keyCleared"
        case .keyDerivationFailed: return "keyDerivationFailed"
        case .invalidKeyLength: return "invalidKeyLength"
        case .authenticationFailed: return "authenticationFailed"
        case .wrongPassword: return "wrongPassword"
        case .invalidVaultHeader: return "invalidVaultHeader"
        case .vaultHeaderChecksumMismatch: return "vaultHeaderChecksumMismatch"
        case .unsupportedCipherSuite: return "unsupportedCipherSuite"
        case .iterationsBelowMinimum: return "iterationsBelowMinimum"
        case .invalidChunkedHeader: return "invalidChunkedHeader"
        case .chunkIndexOutOfRange: return "chunkIndexOutOfRange"
        case .chunkNonceMismatch: return "chunkNonceMismatch"
        case .chunkedFileSizeMismatch: return "chunkedFileSizeMismatch"
        case .invalidFolderProtection: return "invalidFolderProtection"
        case .invalidExport: return "invalidExport"
        case .exportNewerVersion: return "exportNewerVersion"
        case .recoveryPhraseWrongLength: return "recoveryPhraseWrongLength"
        case .recoveryPhraseUnknownWord: return "recoveryPhraseUnknownWord"
        case .recoveryPhraseChecksumMismatch: return "recoveryPhraseChecksumMismatch"
        case .invalidSharedItems: return "invalidSharedItems"
        case .sharedItemsDamaged: return "sharedItemsDamaged"
        case .sharedItemsNewerVersion: return "sharedItemsNewerVersion"
        case .sharedItemsNotLocked: return "sharedItemsNotLocked"
        case .tooManySharedItems: return "tooManySharedItems"
        }
    }

    static func plaintext(_ count: Int, _ seed: Int) -> Data {
        Data((0..<count).map { UInt8((($0 * 31) + seed) % 251) })
    }

    static func write(to directory: URL, generatedBy: String) throws {
        let fm = FileManager.default
        try? fm.removeItem(at: directory)
        try fm.createDirectory(at: directory.appendingPathComponent("tampered"), withIntermediateDirectories: true)

        let vaultPassword = "swift p\u{00E4}ssword \u{1F510}" // a precomposed accent, and a character outside the BMP
        let folderPassword = "swift folder pass 1"
        let databaseSize: UInt64 = 7_654_321

        let (vaultHeader, master) = try VaultHeader.create(password: vaultPassword, databaseSize: databaseSize)
        let (protection, folderKey) = try FolderProtection.create(password: folderPassword)

        var cases: [[String: Any]] = []
        func put(_ path: String, _ data: Data) throws { try data.write(to: directory.appendingPathComponent(path)) }
        func flipped(_ data: Data, at index: Int) -> Data {
            var copy = data
            copy[index] ^= 0x01
            return copy
        }

        // Vault headers
        let header = vaultHeader.serialized()
        try put("vault.header", header)
        cases.append(["file": "vault.header", "kind": "vaultHeader", "expect": "opens"])

        var damaged = header
        damaged[20] ^= 0xFF
        try put("tampered/vault-checksum.header", damaged)
        cases.append(["file": "tampered/vault-checksum.header", "kind": "vaultHeader", "expect": "vaultHeaderChecksumMismatch"])

        var wrongVersion = header
        wrongVersion[0] = 0x02
        try put("tampered/vault-version.header", wrongVersion)
        cases.append(["file": "tampered/vault-version.header", "kind": "vaultHeader", "expect": "invalidVaultHeader"])

        var unknownSuite = header
        unknownSuite[8] = 0x02
        unknownSuite.replaceSubrange(141..<145, with: Data())
        unknownSuite.appendBigEndian(unknownSuite.crc32)
        try put("tampered/vault-suite.header", unknownSuite)
        cases.append(["file": "tampered/vault-suite.header", "kind": "vaultHeader", "expect": "unsupportedCipherSuite"])

        let weakened = VaultHeader(
            kdfIterations: 1_000, salt: vaultHeader.salt,
            wrappedMasterKey: vaultHeader.wrappedMasterKey, encryptedDatabaseSize: vaultHeader.encryptedDatabaseSize)
        try put("tampered/vault-rounds.header", weakened.serialized())
        cases.append(["file": "tampered/vault-rounds.header", "kind": "vaultHeader", "expect": "iterationsBelowMinimum"])

        // Single-shot media
        let photo = plaintext(20_000, 1)
        try put("photo.data.enc", SingleShotMedia.encrypt(photo, masterKey: master))
        cases.append(["file": "photo.data.enc", "kind": "singleShot", "folder": false, "count": 20_000, "seed": 1, "expect": "opens"])
        try put("photo-folder.data.enc", SingleShotMedia.encrypt(photo, masterKey: master, folderKey: folderKey))
        cases.append(["file": "photo-folder.data.enc", "kind": "singleShot", "folder": true, "count": 20_000, "seed": 1, "expect": "opens"])
        let sealed = try SingleShotMedia.encrypt(photo, masterKey: master)
        try put("tampered/photo-tag.data.enc", flipped(sealed, at: sealed.count - 1))
        cases.append(["file": "tampered/photo-tag.data.enc", "kind": "singleShot", "folder": false, "count": 20_000, "seed": 1,
                      "expect": "authenticationFailed"])

        // Chunked media
        // Version 2, which new files are written in, and version 1, which
        // every file from before it is and which must read forever.
        func chunked(_ name: String, count: Int, seed: Int, chunkSize: UInt32, folder: Bool,
                     version: UInt8 = ChunkedMediaHeader.currentVersion) throws {
            let source = directory.appendingPathComponent(".source.bin")
            try plaintext(count, seed).write(to: source)
            try ChunkedMediaEncryptor.encrypt(
                from: source, to: directory.appendingPathComponent(name),
                masterKey: master, folderKey: folder ? folderKey : nil, chunkSize: chunkSize, formatVersion: version)
            try fm.removeItem(at: source)
            cases.append(["file": name, "kind": "chunked", "folder": folder, "count": count, "seed": seed,
                          "chunkSize": Int(chunkSize), "version": Int(version), "expect": "opens"])
        }
        try chunked("video.data.enc", count: 200_000, seed: 2, chunkSize: 65_536, folder: false)
        try chunked("video-folder.data.enc", count: 200_000, seed: 2, chunkSize: 65_536, folder: true)
        try chunked("video-boundary.data.enc", count: 131_072, seed: 3, chunkSize: 65_536, folder: false)
        try chunked("video-empty.data.enc", count: 0, seed: 4, chunkSize: 65_536, folder: false)
        try chunked("video-small-chunks.data.enc", count: 10_000, seed: 5, chunkSize: 4_096, folder: true)
        try chunked("video-v1.data.enc", count: 200_000, seed: 2, chunkSize: 65_536, folder: false, version: 0x01)
        try chunked("video-folder-v1.data.enc", count: 200_000, seed: 2, chunkSize: 65_536, folder: true, version: 0x01)
        try chunked("video-empty-v1.data.enc", count: 0, seed: 4, chunkSize: 65_536, folder: false, version: 0x01)

        let video = try Data(contentsOf: directory.appendingPathComponent("video.data.enc"))
        let videoHeader = try ChunkedMediaHeader(parsing: video)
        func tamperedVideo(_ name: String, _ data: Data, _ expect: String) throws {
            try put("tampered/\(name)", data)
            cases.append(["file": "tampered/\(name)", "kind": "chunked", "folder": false, "count": 200_000, "seed": 2,
                          "chunkSize": 65_536, "expect": expect])
        }
        var swapped = video
        let size = videoHeader.encryptedSize(ofChunk: 0)
        let first = videoHeader.chunkOffset(0), second = videoHeader.chunkOffset(1)
        swapped.replaceSubrange(first..<first + size, with: video[second..<second + size])
        swapped.replaceSubrange(second..<second + size, with: video[first..<first + size])
        try tamperedVideo("video-swapped.data.enc", swapped, "chunkNonceMismatch")
        try tamperedVideo("video-truncated.data.enc", video.dropLast(10), "chunkedFileSizeMismatch")
        try tamperedVideo("video-flipped.data.enc", flipped(video, at: videoHeader.chunkOffset(2) + 20), "authenticationFailed")
        // A changed salt derives other keys.
        try tamperedVideo("video-salt.data.enc", flipped(video, at: 40), "authenticationFailed")
        // Cut short at a chunk boundary with the length lowered to match: the
        // new last chunk carries no end mark.
        var cut = Data(video.prefix(videoHeader.chunkOffset(2)))
        cut.replaceSubrange(9..<17, with: withUnsafeBytes(of: UInt64(2 * 65_536).bigEndian) { Data($0) })
        try tamperedVideo("video-cut.data.enc", cut, "chunkNonceMismatch")
        // Cut to its header and called empty: an empty file still has a chunk.
        var emptied = Data(video.prefix(videoHeader.byteCount))
        emptied.replaceSubrange(9..<17, with: Data(count: 8))
        try tamperedVideo("video-emptied.data.enc", emptied, "chunkedFileSizeMismatch")
        var hostile = Data(video.prefix(videoHeader.byteCount))
        hostile.replaceSubrange(9..<17, with: Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0]))
        try tamperedVideo("video-hostile-length.data.enc", hostile, "invalidChunkedHeader")
        var unknown = video
        unknown[4] = 0x03
        try tamperedVideo("video-version.data.enc", unknown, "invalidChunkedHeader")

        // Export
        cases += try writeExport(to: directory, vaultHeader: vaultHeader, vaultPassword: vaultPassword,
                                 master: master, folderKey: folderKey)

        // Shared items
        cases += try writeSharedItems(to: directory)

        let manifest: [String: Any] = [
            "format": 1,
            "generatedBy": generatedBy,
            "vaultPassword": vaultPassword,
            "folderPassword": folderPassword,
            "masterKeyFingerprint": master.fingerprint,
            "folderKeyFingerprint": folderKey.fingerprint,
            "databaseSize": databaseSize,
            "folder": [
                "passwordSalt": protection.salt.base64EncodedString(),
                "passwordHash": protection.passwordHash.base64EncodedString(),
                "folderKeyEncrypted": protection.wrappedFolderKey.base64EncodedString(),
            ],
            "cases": cases,
        ]
        let json = try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        try put("compat.json", asciiOnly(json) + Data("\n".utf8))
    }

    /// Escapes everything outside ASCII, so no tool between writer and reader can normalise a password.
    private static func asciiOnly(_ json: Data) -> Data {
        var out = ""
        for unit in String(decoding: json, as: UTF8.self).utf16 {
            if unit < 128 { out.unicodeScalars.append(Unicode.Scalar(unit)!) } else { out += String(format: "\\u%04x", unit) }
        }
        return Data(out.utf8)
    }

    // MARK: Export

    private static func writeExport(
        to directory: URL, vaultHeader: VaultHeader, vaultPassword: String, master: SecureBytes, folderKey: SecureBytes
    ) throws -> [[String: Any]] {
        let fm = FileManager.default
        let vaultFile = vaultHeader.serialized() + plaintext(90_000, 9)

        let chunkedSource = directory.appendingPathComponent(".media.bin")
        let chunkedFile = directory.appendingPathComponent(".media.enc")
        try plaintext(150_000, 6).write(to: chunkedSource)
        try ChunkedMediaEncryptor.encrypt(from: chunkedSource, to: chunkedFile, masterKey: master, chunkSize: 65_536)
        let media: [(id: String, data: Data, thumb: Data)] = [
            ("A3E42A38-8C9A-483D-BAE4-1AEE61FF133A", try SingleShotMedia.encrypt(plaintext(3_000, 7), masterKey: master),
             try SingleShotMedia.encrypt(plaintext(400, 8), masterKey: master)),
            ("B73D3715-51FA-4CFD-81F8-863C3D37D73F", try Data(contentsOf: chunkedFile),
             try SingleShotMedia.encrypt(plaintext(300, 10), masterKey: master)),
            ("919120EA-50E6-417C-8F1A-714F5A286E56",
             try SingleShotMedia.encrypt(plaintext(2_000, 11), masterKey: master, folderKey: folderKey), Data()),
        ]
        try fm.removeItem(at: chunkedSource)
        try fm.removeItem(at: chunkedFile)

        let manifestJSON = """
            {"exportVersion":1,"vaultSalt":"\(vaultHeader.salt.base64EncodedString())",\
            "encryptedMEK":"\(vaultHeader.wrappedMasterKey.base64EncodedString())",\
            "databaseSize":\(vaultFile.count),"mediaFiles":[\
            \(media.map { "{\"mediaId\":\"\($0.id)\",\"dataSize\":\($0.data.count),\"thumbSize\":\($0.thumb.count)}" }.joined(separator: ","))]}
            """

        func export(_ name: String) throws -> Data {
            let writer = try TestExportWriter(password: vaultPassword)
            try writer.record(Data(manifestJSON.utf8))
            try writer.file(vaultFile)
            for item in media {
                try writer.file(item.data)
                try writer.file(item.thumb)
            }
            try writer.output.write(to: directory.appendingPathComponent(name))
            return writer.output
        }
        let good = try export("export.obscura")

        // Version 2, in small records so the files run across several.
        let files = [vaultFile] + media.flatMap { [$0.data, $0.thumb] }
        let export2 = directory.appendingPathComponent("export2.obscura")
        let writer = try ExportWriter(url: export2, password: vaultPassword, manifest: Data(manifestJSON.utf8), attributes: nil,
                                      rounds: KeyDerivation.vaultIterations, recordSize: Self.exportRecordSize)
        for file in files { try writer.write(file) }
        try writer.finish()
        try TestExportWriterVersion2.write(password: vaultPassword, manifest: Data(manifestJSON.utf8), files: files,
                                           recordSize: Self.exportRecordSize)
            .write(to: directory.appendingPathComponent("export2-spec.obscura"))

        let mediaCase = media.map { ["id": $0.id, "dataSha256": sha256($0.data), "thumbSha256": sha256($0.thumb)] }
        func exportCase(_ file: String, _ expect: String, password: String? = nil) -> [String: Any] {
            var entry: [String: Any] = ["file": file, "kind": "export", "expect": expect,
                                        "databaseSha256": sha256(vaultFile), "media": mediaCase]
            if let password { entry["password"] = password }
            return entry
        }

        var flipped = good
        flipped[flipped.count - 30] ^= 0x01
        try flipped.write(to: directory.appendingPathComponent("tampered/export-flipped.obscura"))
        try good.dropLast(100).write(to: directory.appendingPathComponent("tampered/export-truncated.obscura"))
        let version2Cases = try tamperedExports(Data(contentsOf: export2), in: directory)
        return [
            exportCase("export.obscura", "opens"),
            exportCase("export.obscura", "wrongPassword", password: "not the password"),
            exportCase("tampered/export-flipped.obscura", "authenticationFailed"),
            exportCase("tampered/export-truncated.obscura", "invalidExport"),
            exportCase("export2.obscura", "opens"),
            exportCase("export2-spec.obscura", "opens"),
            exportCase("export2.obscura", "wrongPassword", password: "not the password"),
        ] + version2Cases.map { exportCase($0.file, $0.expect) }
    }

    /// Plaintext bytes in each record of the version 2 export fixtures. As in the Kotlin writer.
    static let exportRecordSize = 4_096

    /// A version 2 export altered each way a reader must notice. As in the Kotlin writer.
    static func tamperedExports(_ good: Data, in directory: URL) throws -> [(file: String, expect: String)] {
        func put(_ name: String, _ data: Data) throws -> String {
            try data.write(to: directory.appendingPathComponent("tampered/\(name)"))
            return "tampered/\(name)"
        }
        var flipped = good
        flipped[flipped.count - 30] ^= 0x01
        // A reserved header byte: the password still checks, but every record is sealed to the header as it was.
        var header = good
        header[90] ^= 0x01
        // A file only a newer version can read, and one with a flag this version must understand.
        var newer = good
        newer[5] = 3
        newer[7] = 3
        var flagged = good
        flagged[9] |= 0x01
        // The key block says it holds a lock that is not there.
        var keyBlock = good
        keyBlock[ExportHeader.version2Size] = 1
        // The last record moved to the front, and a record appended after the end mark.
        let headerSize = try ExportHeader(parsing: good).byteCount
        let records = (good.count - headerSize) / (exportRecordSize + AESGCM.overhead)
        let recordBytes = exportRecordSize + AESGCM.overhead
        let body = good.dropFirst(headerSize)
        let last = body.suffix(recordBytes)
        let swapped = good.prefix(headerSize) + last + body.dropLast(recordBytes)
        precondition(records > 2)
        return [
            (try put("export2-flipped.obscura", flipped), "invalidExport"),
            (try put("export2-truncated.obscura", good.dropLast(100)), "invalidExport"),
            (try put("export2-last-record-dropped.obscura", good.dropLast(recordBytes)), "invalidExport"),
            (try put("export2-reordered.obscura", swapped), "invalidExport"),
            (try put("export2-appended.obscura", good + last), "invalidExport"),
            (try put("export2-header-altered.obscura", header), "invalidExport"),
            (try put("export2-key-block-altered.obscura", keyBlock), "invalidExport"),
            (try put("export2-newer.obscura", newer), "exportNewerVersion"),
            (try put("export2-required-flag.obscura", flagged), "exportNewerVersion"),
        ]
    }
}

extension CompatWriter {

    /// What every `.obscurashared` fixture holds: each kind, a Live Photo's two
    /// parts, a title outside ASCII, and parts over several records. The
    /// records are small, which the format allows, so the files stay small.
    static let sharedItems: [(kind: SharedItemsFile.Kind, type: String?, name: String?,
                              parts: [(role: String, count: Int, seed: Int)])] = [
        (.photo, "image/jpeg", nil, [("file", 9_000, 21)]),
        (.gif, "image/gif", nil, [("file", 800, 22)]),
        (.video, "video/quicktime", nil, [("file", 12_000, 23)]),
        (.livePhoto, "image/heic", nil, [("file", 3_000, 24), ("motion", 4_100, 25)]),
        (.pdf, "application/pdf", "Lease, M\u{00FC}ller \u{65E5}\u{672C}", [("file", 1_500, 26)]),
    ]
    static let sharedRecordSize = 4_096

    static func writeSharedItems(to directory: URL) throws -> [[String: Any]] {
        let fm = FileManager.default
        let password = "swift shared pass"
        var sources: [SharedItemsFile.Source] = []
        var plaintextFiles: [URL] = []
        defer { plaintextFiles.forEach { try? fm.removeItem(at: $0) } }
        for (index, item) in sharedItems.enumerated() {
            let urls = try item.parts.map { part -> URL in
                let url = directory.appendingPathComponent(".shared-\(index)-\(part.role).bin")
                try plaintext(part.count, part.seed).write(to: url)
                return url
            }
            plaintextFiles += urls
            sources.append(.init(url: urls[0], kind: item.kind, pairedVideo: urls.count > 1 ? urls[1] : nil,
                                 name: item.name, mimeType: item.type))
        }
        /// `change` rewrites the real manifest's JSON, for files whose
        /// manifest no writer makes.
        @discardableResult
        func write(_ name: String, password: String?, rounds: UInt32 = KeyDerivation.vaultIterations,
                   padding: UInt8 = 0, change: ((String) -> String)? = nil) throws -> Data {
            let url = directory.appendingPathComponent(name)
            try SharedItemsFile.write(sources, password: password, to: url, attributes: nil, rounds: rounds,
                                      recordSize: sharedRecordSize, padding: padding)
            if let change {
                let real = try SharedItemsReader(url: url, password: password).manifest
                let changed = Data(change(String(decoding: SharedItemsJSON.encode(real), as: UTF8.self)).utf8)
                try SharedItemsFile.write(sources, password: password, to: url, attributes: nil, rounds: rounds,
                                          recordSize: sharedRecordSize, manifestOverride: changed, padding: padding)
            }
            return try Data(contentsOf: url)
        }

        let items: [[String: Any]] = sharedItems.map { item in
            var entry: [String: Any] = ["kind": item.kind.rawValue,
                                        "parts": item.parts.map { ["role": $0.role, "count": $0.count, "seed": $0.seed] }]
            if let type = item.type { entry["type"] = type }
            if let name = item.name { entry["name"] = name }
            return entry
        }
        func sharedCase(_ file: String, _ expect: String, password: String?) -> [String: Any] {
            var entry: [String: Any] = ["file": file, "kind": "sharedItems", "expect": expect, "items": items]
            if let password { entry["password"] = password }
            return entry
        }

        let locked = try write("shared-password.obscurashared", password: password)
        let open = try write("shared-open.obscurashared", password: nil)
        var cases = [
            sharedCase("shared-password.obscurashared", "opens", password: password),
            sharedCase("shared-open.obscurashared", "opens", password: nil),
            sharedCase("shared-password.obscurashared", "wrongPassword", password: "not the password"),
            // An open file must not pass for one sealed with the password the
            // receiver expected.
            sharedCase("shared-open.obscurashared", "sharedItemsNotLocked", password: password),
        ]
        func tampered(_ name: String, _ data: Data, _ expect: String, password: String? = nil) throws {
            try data.write(to: directory.appendingPathComponent("tampered/\(name)"))
            cases.append(sharedCase("tampered/\(name)", expect, password: password))
        }
        func written(_ name: String, _ expect: String, password: String? = nil, rounds: UInt32 = KeyDerivation.vaultIterations,
                     padding: UInt8 = 0, change: ((String) -> String)? = nil) throws {
            try write("tampered/\(name)", password: password, rounds: rounds, padding: padding, change: change)
            cases.append(sharedCase("tampered/\(name)", expect, password: password))
        }
        let record = sharedRecordSize + AESGCM.overhead
        var flipped = open
        flipped[flipped.count - 30] ^= 0x01
        try tampered("shared-flipped.obscurashared", flipped, "sharedItemsDamaged")
        // A reserved header byte: the header is every record's associated
        // data, and the password lock's.
        var header = open
        header[40] ^= 0x01
        try tampered("shared-header.obscurashared", header, "sharedItemsDamaged")
        var lockHeader = locked
        lockHeader[40] ^= 0x01
        try tampered("shared-lock-header.obscurashared", lockHeader, "wrongPassword", password: password)
        // The key commitment, the first byte of the key block: an open lock's
        // key no longer matches it, and a password lock that opens gives a key
        // the file does not commit to.
        var commitment = open
        commitment[SharedItemsFile.headerSize] ^= 0x01
        try tampered("shared-commitment.obscurashared", commitment, "sharedItemsDamaged")
        var lockCommitment = locked
        lockCommitment[SharedItemsFile.headerSize] ^= 0x01
        try tampered("shared-lock-commitment.obscurashared", lockCommitment, "wrongPassword", password: password)
        try tampered("shared-swapped.obscurashared", swappingRecords(open, 1, 2), "sharedItemsDamaged")
        try tampered("shared-truncated.obscurashared", open.dropLast(100), "sharedItemsDamaged")
        // A whole record off: the new last one has no end mark.
        try tampered("shared-cut.obscurashared", open.dropLast(record), "sharedItemsDamaged")
        try tampered("shared-appended.obscurashared", open + Data(count: 8), "sharedItemsDamaged")
        // Readable from version 4 only.
        var newer = open
        newer[5] = 4
        newer[7] = 4
        try tampered("shared-newer.obscurashared", newer, "sharedItemsNewerVersion")
        try written("shared-rounds.obscurashared", "invalidSharedItems", password: password, rounds: 100_000)
        try written("shared-padding.obscurashared", "sharedItemsDamaged", padding: 1)
        // Manifests each JSON library reads its own way, or not at all.
        try written("shared-twice.obscurashared", "sharedItemsDamaged") {
            $0.replacingOccurrences(of: #"{"kind":"photo""#, with: #"{"kind":"photo","kind":"pdf""#)
        }
        try written("shared-fraction.obscurashared", "sharedItemsDamaged") {
            $0.replacingOccurrences(of: #""size":9000,"#, with: #""size":9000.0,"#)
        }
        try written("shared-bom.obscurashared", "sharedItemsDamaged") { "\u{FEFF}" + $0 }
        try written("shared-title.obscurashared", "sharedItemsDamaged") {
            $0.replacingOccurrences(of: #""name":"Lease, "#, with: #""name":"Lease,\n"#)
        }
        // A zero-width space: shows nothing, so a title could hide text.
        try written("shared-invisible.obscurashared", "sharedItemsDamaged") {
            $0.replacingOccurrences(of: #""name":"Lease, "#, with: "\"name\":\"Lease,\u{200B} ")
        }
        return cases
    }

    /// `data`, an `.obscurashared` file, with two of its records swapped.
    static func swappingRecords(_ data: Data, _ a: Int, _ b: Int) -> Data {
        let start = SharedItemsFile.headerSize + Int(data.bigEndianUInt16(at: 10))
        let size = Int(data.bigEndianUInt32(at: 12)) + AESGCM.overhead
        var records = stride(from: start, to: data.count, by: size).map { data.subdata(in: $0..<min($0 + size, data.count)) }
        records.swapAt(a, b)
        return records.reduce(Data(data.prefix(start)), +)
    }
}

/// A version 2 `.obscura` writer built from the format description alone: the
/// 96-byte header and a key block of no locks, then records all of `recordSize` plaintext bytes, each one
/// AES-GCM message under the record key (HKDF-SHA256 over the export key,
/// salt 32 zero bytes, info "OBSV v2 records") with nonce `noncePrefix ||
/// index` (the index's top bit set on the last) and the header as associated
/// data. The header's commitment is the same HKDF with info "OBSV v2 key
/// commitment". They
/// hold the manifest's length (4 bytes), the manifest, the files end to end,
/// and zeros to the Padmé length rounded up to whole records.
private enum TestExportWriterVersion2 {
    static func write(password: String, manifest: Data, files: [Data], recordSize: Int) throws -> Data {
        let salt = try KeyDerivation.makeSalt()
        let prefix = Data((0..<4).map { _ in UInt8.random(in: 0...255) })
        let exportKey = try KeyDerivation.pbkdf2SHA256(password: password, salt: salt, iterations: KeyDerivation.vaultIterations).symmetricKey
        func derived(_ info: String) -> SymmetricKey {
            HKDF<SHA256>.deriveKey(inputKeyMaterial: exportKey, salt: Data(count: 32), info: Data(info.utf8), outputByteCount: 32)
        }
        let key = derived("OBSV v2 records")
        var header = Data("OBSV".utf8)
        header.appendBigEndian(UInt16(2))
        header.appendBigEndian(UInt16(2))
        header.appendBigEndian(UInt16(0))
        // A key block of one byte: no locks beside the password.
        header.appendBigEndian(UInt16(1))
        header.appendBigEndian(UInt32(recordSize))
        header.append(salt)
        header.appendBigEndian(KeyDerivation.vaultIterations)
        header.append(prefix)
        header.append(derived("OBSV v2 key commitment").withUnsafeBytes { Data($0) })
        header.append(Data(count: 8))
        header.append(0)

        var stream = Data()
        stream.appendBigEndian(UInt32(manifest.count))
        stream.append(manifest)
        files.forEach { stream.append($0) }
        // Padmé: keep the top bits of the length, as many as the bits of its exponent.
        let exponent = Int(log2(Double(stream.count)))
        let exponentBits = Int(log2(Double(exponent))) + 1
        let mask = (1 << (exponent - exponentBits)) - 1
        let padded = (stream.count + mask) & ~mask
        let count = (padded + recordSize - 1) / recordSize
        stream.append(Data(count: count * recordSize - stream.count))

        var output = header
        for index in 0..<count {
            var nonce = prefix
            nonce.appendBigEndian(UInt64(index) | (index == count - 1 ? 1 << 63 : 0))
            let plaintext = stream.subdata(in: index * recordSize ..< (index + 1) * recordSize)
            output.append(try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(data: nonce), authenticating: header).combined!)
        }
        return output
    }
}

/// An `.obscura` writer built from the format description alone: the 64-byte
/// header, then records of a 4-byte big-endian length and one AES-GCM message
/// whose nonce is `noncePrefix || index`. Version 1, as every iPhone wrote
/// until version 2.
private final class TestExportWriter {
    private(set) var output = Data()
    private let key: SymmetricKey
    private let noncePrefix: Data
    private var index: UInt64 = 0

    init(password: String) throws {
        let salt = try KeyDerivation.makeSalt()
        noncePrefix = Data((0..<4).map { _ in UInt8.random(in: 0...255) })
        let passwordKey = try KeyDerivation.pbkdf2SHA256(password: password, salt: salt, iterations: KeyDerivation.vaultIterations)
        key = try passwordKey.symmetricKey
        var maxNonce = noncePrefix
        maxNonce.appendBigEndian(UInt64.max)
        let check = try AES.GCM.seal(Data("OBSCURA_EXPORT_V1".utf8), using: key, nonce: AES.GCM.Nonce(data: maxNonce))

        output.append(Data("OBSV".utf8))
        output.appendBigEndian(UInt16(1))
        output.appendBigEndian(UInt16(0))
        output.append(salt)
        output.appendBigEndian(KeyDerivation.vaultIterations)
        output.append(check.tag)
        output.append(noncePrefix)
    }

    func record(_ plaintext: Data) throws {
        var nonce = noncePrefix
        nonce.appendBigEndian(index)
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(data: nonce)).combined!
        output.appendBigEndian(UInt32(sealed.count))
        output.append(sealed)
        index += 1
    }

    /// A file's bytes, in records of up to 1 MiB, each file starting a new record.
    func file(_ data: Data) throws {
        var offset = 0
        while offset < data.count {
            let end = min(offset + 1_048_576, data.count)
            try record(data.subdata(in: offset..<end))
            offset = end
        }
    }
}
