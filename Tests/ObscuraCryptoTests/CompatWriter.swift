// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CryptoKit
import Foundation
@testable import ObscuraCrypto

/// Writes this language's cross-language fixture set. See `CompatFixtureTests`.
///
/// The export is written here by a small independent writer built from the
/// format description, not by the iOS app and not by the Kotlin library, so
/// that the Kotlin reader is tested against a third implementation too.
enum CompatWriter {

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// The Swift case name, as the Kotlin side spells the same error.
    static func name(of error: ObscuraCryptoError) -> String {
        switch error {
        case .randomUnavailable: return "randomUnavailable"
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
        }
    }

    private static func plaintext(_ count: Int, _ seed: Int) -> Data {
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
        func chunked(_ name: String, count: Int, seed: Int, chunkSize: UInt32, folder: Bool) throws {
            let source = directory.appendingPathComponent(".source.bin")
            try plaintext(count, seed).write(to: source)
            try ChunkedMediaEncryptor.encrypt(
                from: source, to: directory.appendingPathComponent(name),
                masterKey: master, folderKey: folder ? folderKey : nil, chunkSize: chunkSize)
            try fm.removeItem(at: source)
            cases.append(["file": name, "kind": "chunked", "folder": folder, "count": count, "seed": seed,
                          "chunkSize": Int(chunkSize), "expect": "opens"])
        }
        try chunked("video.data.enc", count: 200_000, seed: 2, chunkSize: 65_536, folder: false)
        try chunked("video-folder.data.enc", count: 200_000, seed: 2, chunkSize: 65_536, folder: true)
        try chunked("video-boundary.data.enc", count: 131_072, seed: 3, chunkSize: 65_536, folder: false)
        try chunked("video-empty.data.enc", count: 0, seed: 4, chunkSize: 65_536, folder: false)
        try chunked("video-small-chunks.data.enc", count: 10_000, seed: 5, chunkSize: 4_096, folder: true)

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
        var hostile = Data(video.prefix(25))
        hostile.replaceSubrange(9..<17, with: Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0]))
        try tamperedVideo("video-hostile-length.data.enc", hostile, "invalidChunkedHeader")

        // Export
        cases += try writeExport(to: directory, vaultHeader: vaultHeader, vaultPassword: vaultPassword,
                                 master: master, folderKey: folderKey)

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
        return [
            exportCase("export.obscura", "opens"),
            exportCase("export.obscura", "wrongPassword", password: "not the password"),
            exportCase("tampered/export-flipped.obscura", "authenticationFailed"),
            exportCase("tampered/export-truncated.obscura", "invalidExport"),
        ]
    }
}

/// An `.obscura` writer built from the format description alone: the 64-byte
/// header, then records of a 4-byte big-endian length and one AES-GCM message
/// whose nonce is `noncePrefix || index`.
private final class TestExportWriter {
    private(set) var output = Data()
    private let key: SymmetricKey
    private let noncePrefix: Data
    private var index: UInt64 = 0

    init(password: String) throws {
        let salt = try KeyDerivation.makeSalt()
        noncePrefix = Data((0..<4).map { _ in UInt8.random(in: 0...255) })
        let passwordKey = try KeyDerivation.pbkdf2SHA256(password: password, salt: salt, iterations: KeyDerivation.vaultIterations)
        key = passwordKey.symmetricKey
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
