// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import Foundation

/// Turns stored media files back into ordinary photos and videos.
public enum MediaExtraction {

    public enum Outcome: Sendable, Equatable {
        /// Decrypted to this file.
        case extracted(URL)
        /// The master key does not open it. For a file the vault references,
        /// that means a protected folder's second layer.
        case notOpenedByMasterKey
    }

    /// Decrypts a stored `.data.enc` file, single-shot or chunked, into
    /// `directory` as `<id>.<extension>`, the extension chosen from what the
    /// decrypted bytes actually are.
    ///
    /// `id` becomes a file name, so it must be a UUID; anything else is
    /// refused. Never overwrites: a name already taken in `directory` is an
    /// error. Writes through a temporary file, so a failure leaves nothing.
    public static func extract(
        storedFile: URL,
        id: String,
        masterKey: SecureBytes,
        folderKey: SecureBytes? = nil,
        into directory: URL
    ) throws -> Outcome {
        guard UUID(uuidString: id) != nil else {
            throw ObscuraCryptoError.invalidExport("\(id) is not a media ID")
        }
        let temporary = directory.appendingPathComponent(".\(id).\(UUID().uuidString).partial")
        defer { try? FileManager.default.removeItem(at: temporary) }

        let prefix = try FileHandle(forReadingFrom: storedFile).read(upToCount: 4) ?? Data()
        do {
            switch MediaFormat.detect(prefix) {
            case .chunked:
                try ChunkedMediaReader(url: storedFile).decrypt(to: temporary, masterKey: masterKey, folderKey: folderKey)
            case .singleShot:
                let plaintext = try SingleShotMedia.decrypt(Data(contentsOf: storedFile), masterKey: masterKey, folderKey: folderKey)
                try plaintext.write(to: temporary)
            }
        } catch ObscuraCryptoError.authenticationFailed {
            return .notOpenedByMasterKey
        }

        let head = try FileHandle(forReadingFrom: temporary).read(upToCount: 16) ?? Data()
        let destination = directory.appendingPathComponent("\(id).\(fileExtension(for: head))")
        guard !FileManager.default.fileExists(atPath: destination.path) else {
            throw ObscuraCryptoError.invalidExport("\(destination.lastPathComponent) already exists")
        }
        try FileManager.default.moveItem(at: temporary, to: destination)
        return .extracted(destination)
    }

    /// Whether the master key opens a stored file, checked as cheaply as the
    /// format allows: a single-shot file whole, a chunked file by its first
    /// chunk.
    public static func masterKeyOpens(storedFile: URL, masterKey: SecureBytes) -> Bool {
        guard let prefix = try? FileHandle(forReadingFrom: storedFile).read(upToCount: 4) else { return false }
        switch MediaFormat.detect(prefix) {
        case .chunked:
            guard let reader = try? ChunkedMediaReader(url: storedFile) else { return false }
            guard reader.header.chunkCount > 0 else { return !reader.header.hasFolderLayer }
            return !reader.header.hasFolderLayer && (try? reader.readChunk(0, masterKey: masterKey)) != nil
        case .singleShot:
            guard let data = try? Data(contentsOf: storedFile) else { return false }
            return (try? SingleShotMedia.decrypt(data, masterKey: masterKey)) != nil
        }
    }

    /// A file extension from a file's first bytes.
    public static func fileExtension(for head: Data) -> String {
        let bytes = [UInt8](head.prefix(16))
        func starts(_ signature: [UInt8], at offset: Int = 0) -> Bool {
            bytes.count >= offset + signature.count && Array(bytes[offset..<offset + signature.count]) == signature
        }
        if starts([0xFF, 0xD8, 0xFF]) { return "jpg" }
        if starts([0x89, 0x50, 0x4E, 0x47]) { return "png" }
        if starts(Array("GIF8".utf8)) { return "gif" }
        if starts(Array("RIFF".utf8)) && starts(Array("WEBP".utf8), at: 8) { return "webp" }
        if starts([0x49, 0x49, 0x2A, 0x00]) || starts([0x4D, 0x4D, 0x00, 0x2A]) { return "tiff" }
        if starts(Array("ftyp".utf8), at: 4), bytes.count >= 12 {
            let brand = String(decoding: bytes[8..<12], as: UTF8.self)
            switch brand {
            case "heic", "heix", "hevc", "heim", "heis", "hevm", "hevs", "mif1", "msf1": return "heic"
            case "avif", "avis": return "avif"
            case "qt  ": return "mov"
            default: return "mp4"
            }
        }
        return "bin"
    }
}
