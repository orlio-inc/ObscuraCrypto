// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import Foundation
import ObscuraCrypto

/// `obscura shared encrypt | verify | decrypt`: the `.obscurashared` files the
/// app's Send Encrypted makes.
enum SharedCommands {

    /// What the app can add, by file extension: the kind and MIME type a file
    /// is sent as.
    static let types: [String: (SharedItemsFile.Kind, String)] = [
        "jpg": (.photo, "image/jpeg"), "jpeg": (.photo, "image/jpeg"), "png": (.photo, "image/png"),
        "heic": (.photo, "image/heic"), "heif": (.photo, "image/heif"), "tif": (.photo, "image/tiff"),
        "tiff": (.photo, "image/tiff"), "webp": (.photo, "image/webp"), "avif": (.photo, "image/avif"),
        "jxl": (.photo, "image/jxl"), "bmp": (.photo, "image/bmp"), "dng": (.photo, "image/x-adobe-dng"),
        "gif": (.gif, "image/gif"),
        "mov": (.video, "video/quicktime"), "mp4": (.video, "video/mp4"), "m4v": (.video, "video/x-m4v"),
        "3gp": (.video, "video/3gpp"), "3g2": (.video, "video/3gpp2"),
        "pdf": (.pdf, "application/pdf"),
    ]

    static func encrypt(_ arguments: Arguments, stdin: Bool) throws {
        let path = try arguments.positional(0, "out.obscurashared")
        if FileManager.default.fileExists(atPath: path), !arguments.has("force") {
            throw CLIError("\(path) already exists; use --force to replace it")
        }
        let inputs = arguments.positionals.dropFirst().map { URL(fileURLWithPath: $0) }
        guard !inputs.isEmpty else { throw CLIError("missing <file>: name the photos, videos and PDFs to seal") }
        let sources = try self.sources(inputs, pairingLivePhotos: arguments.has("live-photos"))

        guard !(arguments.has("open") && arguments.has("generate-password")) else {
            throw CLIError("--open and --generate-password do not go together")
        }
        var password: String?
        if arguments.has("generate-password") {
            password = try SharedItemsFile.suggestedPassword()
        } else if !arguments.has("open") {
            let typed = try Terminal.readPassword("New password for the file: ", fromStandardInput: stdin, confirm: !stdin)
            guard typed.unicodeScalars.count >= minimumPasswordLength else {
                throw CLIError("the password needs at least \(minimumPasswordLength) characters, as in the app")
            }
            password = typed
        }
        let output = URL(fileURLWithPath: path)
        try SharedItemsFile.write(sources, password: password, to: output)
        let size = try FileManager.default.attributesOfItem(atPath: output.path)[.size] as? UInt64 ?? 0
        var rows = [
            ("Created", path),
            ("Items", itemSummary(sources.map(\.kind.rawValue))),
            ("Lock", password == nil ? openLock : passwordLock(KeyDerivation.vaultIterations)),
            ("File size", Terminal.byteCount(size)),
        ]
        if arguments.has("generate-password"), let password {
            rows.append(("Password", "\(password)  (tell it to them some other way than the file)"))
        } else if let password, let problem = SharedItemsFile.passwordProblem(password) {
            rows.append(("Note", explanation(of: problem)))
        }
        Terminal.printFields(rows)
    }

    static func verify(_ arguments: Arguments, stdin: Bool) throws {
        let url = URL(fileURLWithPath: try arguments.positional(0, "file.obscurashared"))
        let reader = try open(url, stdin: stdin)
        var bytes: Int64 = 0
        for item in reader.manifest.items {
            for part in item.parts {
                try reader.skip(part)
                bytes += part.size
            }
        }
        try reader.finish()
        let preamble = reader.preamble
        var rows = [
            ("Format", "Obscura shared items, version \(preamble.formatVersion), readable from version \(preamble.readableBy)"),
            ("Lock", lockSummary(preamble)),
            ("Items", itemSummary(reader.manifest.items.map(\.kind))),
            ("Contents", Terminal.byteCount(UInt64(bytes))),
            ("Checked", "every record intact and in order, every item matching its SHA-256, nothing after the last"),
        ]
        if preamble.isOpen { rows.append(("Note", openNote)) }
        Terminal.printFields(rows)
    }

    static func decrypt(_ arguments: Arguments, stdin: Bool) throws {
        let url = URL(fileURLWithPath: try arguments.positional(0, "file.obscurashared"))
        let outDir = try outputDirectory(arguments)
        let reader = try open(url, stdin: stdin)
        try Interruption.cleaningUp(outDir) { try decrypt(reader, into: outDir) }
    }

    private static func decrypt(_ reader: SharedItemsReader, into outDir: URL) throws {
        // Every part is decrypted into a folder made fresh for this run, owner
        // only, and moved out only once the whole file has checked, so nothing
        // unverified ever appears in out-dir.
        let staging = try Interruption.makeStaging(in: outDir)
        defer { Interruption.removeStaging(staging) }

        var files: [(staged: URL, name: String)] = []
        var titles: [(name: String, title: String)] = []
        for (index, item) in reader.manifest.items.enumerated() {
            guard let kind = item.knownKind else {
                for part in item.parts { try reader.skip(part) }
                continue
            }
            var extensions: [String] = []
            for part in item.parts {
                let role = SharedItemsFile.Role(rawValue: part.role)
                guard role == .file || (role == .motion && kind == .livePhoto) else {
                    try reader.skip(part)
                    continue
                }
                Interruption.checkpoint()
                let staged = staging.appendingPathComponent("\(files.count)")
                FileManager.default.createFile(atPath: staged.path, contents: nil, attributes: [.posixPermissions: 0o600])
                let output = try FileHandle(forWritingTo: staged)
                do {
                    try reader.read(part) { try output.write(contentsOf: $0) }
                    try output.synchronize()
                    try output.close()
                } catch {
                    try? output.close()
                    throw error
                }
                let head = try FileHandle(forReadingFrom: staged).read(upToCount: 16) ?? Data()
                var name = "\(index + 1)-\(label(kind))"
                let ext = fileExtension(head: head, type: item.type, isMotion: role == .motion)
                // A Live Photo's two halves share a name, as Photos exports
                // them, unless their extensions would make them one file.
                if role == .motion, extensions.contains(ext) { name += "-motion" }
                // A made-up file can give the motion first; its still must
                // not then take the same name.
                if files.contains(where: { $0.name == "\(name).\(ext)" }) { name += "-\(part.role)" }
                extensions.append(ext)
                files.append((staged, "\(name).\(ext)"))
                if kind == .pdf, let title = item.name, !title.isEmpty {
                    titles.append(("\(name).\(ext)", printable(title)))
                }
            }
        }
        try reader.finish()

        for (_, name) in files {
            let destination = outDir.appendingPathComponent(name)
            // `attributesOfItem` does not follow links, so a link planted at
            // this name counts as taken.
            guard (try? FileManager.default.attributesOfItem(atPath: destination.path)) == nil else {
                throw CLIError("\(destination.path) already exists; decrypt into an empty folder")
            }
        }
        for (staged, name) in files {
            try FileManager.default.moveItem(at: staged, to: outDir.appendingPathComponent(name))
        }
        let unknown = reader.manifest.items.count - reader.supportedCount
        var rows = [("Decrypted", "\(reader.supportedCount) \(reader.supportedCount == 1 ? "item" : "items") to \(outDir.path)")]
        rows += files.map { ("", $0.name) }
        rows += titles.map { ("Title", "\($0.name) is \"\($0.title)\"") }
        if unknown > 0 {
            rows.append(("Not decrypted", "\(unknown) of a kind this version does not know, checked and read past"))
        }
        rows.append(("Lock", lockSummary(reader.preamble)))
        if reader.preamble.isOpen { rows.append(("Note", openNote)) }
        Terminal.printFields(rows)
    }

    // MARK: Helpers

    /// Opens `url`, asking at the terminal for its password only when it has
    /// one. A password given with `--password-stdin` is always used, so a
    /// script that expects a sealed file is refused one sent without a
    /// password (someone may have swapped it on the way).
    static func open(_ url: URL, stdin: Bool) throws -> SharedItemsReader {
        let password = try stdin || !SharedItemsPreamble(url: url).isOpen
            ? Terminal.readPassword("Password for the file: ", fromStandardInput: stdin) : nil
        return try SharedItemsReader(url: url, password: password)
    }

    static let openNote = "sent without a password: anyone who had the file on the way could have read it, "
        + "or made or changed it, so it does not show who sent it"

    /// One source per file, a Live Photo for each still and video sharing a
    /// name when asked to pair them, in the order given.
    static func sources(_ inputs: [URL], pairingLivePhotos: Bool) throws -> [SharedItemsFile.Source] {
        var sources: [SharedItemsFile.Source] = []
        for url in inputs {
            guard let (kind, type) = types[url.pathExtension.lowercased()] else {
                throw CLIError("\(url.lastPathComponent): not a photo, video or PDF the app can add")
            }
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory), !isDirectory.boolValue else {
                throw CLIError("\(url.path) is not a file")
            }
            sources.append(SharedItemsFile.Source(
                url: url, kind: kind, name: kind == .pdf ? url.deletingPathExtension().lastPathComponent : nil,
                mimeType: type))
        }
        guard pairingLivePhotos else { return sources }

        func stem(_ url: URL) -> String { url.deletingPathExtension().path.lowercased() }
        var paired: [SharedItemsFile.Source] = []
        var used = Set<Int>()
        for (index, source) in sources.enumerated() where !used.contains(index) {
            let partners = sources.indices.filter { $0 != index && !used.contains($0) && stem(sources[$0].url) == stem(source.url) }
            let stills = ([index] + partners).filter { sources[$0].kind == .photo }
            let videos = ([index] + partners).filter { sources[$0].kind == .video }
            if stills.count == 1, videos.count == 1 {
                var live = sources[stills[0]]
                live.kind = .livePhoto
                live.pairedVideo = sources[videos[0]].url
                paired.append(live)
                used.formUnion([stills[0], videos[0]])
            } else {
                paired.append(source)
                used.insert(index)
            }
        }
        return paired
    }

    /// The app asks the same of a password for Send Encrypted.
    static let minimumPasswordLength = 6

    /// Why a password the file was sealed under is easy to guess. Said, not
    /// refused: the choice is the sender's.
    static func explanation(of problem: SharedItemsFile.PasswordProblem) -> String {
        let reason: String
        switch problem {
        case .tooShort: reason = "it is under \(SharedItemsFile.recommendedPasswordLength) characters"
        case .tooSimple: reason = "it is simple (few different characters, digits alone, or a run like abcdefghij)"
        case .tooCommon: reason = "it is a well-known password with a few characters added"
        }
        return "this password is easy to guess, as \(reason); anyone who keeps a copy of the file can try as long as they like. --generate-password makes one that is not"
    }

    static let openLock = "open, no password: the key is in the file, so anyone who has the file can open it, or change it"

    static func passwordLock(_ rounds: UInt32) -> String {
        "password: PBKDF2-HMAC-SHA256, \(rounds) rounds, then AES-256-GCM"
    }

    static func lockSummary(_ preamble: SharedItemsPreamble) -> String {
        var text = preamble.isOpen ? openLock
            : preamble.locks.compactMap(\.rounds).first.map(passwordLock) ?? "password"
        if preamble.unknownLockCount > 0 {
            text += "; and \(preamble.unknownLockCount) of a kind this version does not know"
        }
        return text
    }

    /// "4: 1 photo, 1 video, 1 Live Photo, 1 document", in a fixed order.
    static func itemSummary(_ kinds: [String]) -> String {
        let names: [(SharedItemsFile.Kind, String, String)] = [
            (.photo, "photo", "photos"), (.gif, "GIF", "GIFs"), (.video, "video", "videos"),
            (.livePhoto, "Live Photo", "Live Photos"), (.pdf, "document", "documents"),
        ]
        var parts: [String] = names.compactMap { kind, one, many in
            let count = kinds.filter { $0 == kind.rawValue }.count
            return count == 0 ? nil : "\(count) \(count == 1 ? one : many)"
        }
        let unknown = kinds.filter { SharedItemsFile.Kind(rawValue: $0) == nil }.count
        if unknown > 0 { parts.append("\(unknown) of a kind this version does not know") }
        return "\(kinds.count): " + parts.joined(separator: ", ")
    }

    /// The extension for each MIME type in `types`.
    static let extensions: [String: String] = [
        "image/jpeg": "jpg", "image/png": "png", "image/heic": "heic", "image/heif": "heif", "image/tiff": "tiff",
        "image/webp": "webp", "image/avif": "avif", "image/jxl": "jxl", "image/bmp": "bmp", "image/x-adobe-dng": "dng",
        "image/gif": "gif", "video/quicktime": "mov", "video/mp4": "mp4", "video/x-m4v": "m4v", "video/3gpp": "3gp",
        "video/3gpp2": "3g2", "application/pdf": "pdf",
    ]

    /// From what the bytes are, as `export extract` names files; failing
    /// that, from the MIME type the sender gave (looked up, never used as
    /// it is), and a Live Photo's motion as a movie.
    static func fileExtension(head: Data, type: String?, isMotion: Bool) -> String {
        let sniffed = MediaExtraction.fileExtension(for: head)
        guard sniffed == "bin" else { return sniffed }
        if isMotion { return "mov" }
        return type.flatMap { extensions[$0] } ?? "bin"
    }

    static func label(_ kind: SharedItemsFile.Kind) -> String {
        switch kind {
        case .photo: return "photo"
        case .gif: return "gif"
        case .video: return "video"
        case .livePhoto: return "live-photo"
        case .pdf: return "document"
        }
    }

    /// A title as the sender wrote it, safe to print: no control or
    /// direction characters that could rewrite the terminal.
    static func printable(_ text: String) -> String {
        String(String.UnicodeScalarView(text.unicodeScalars.prefix(SharedItemsFile.maximumNameLength).map { scalar in
            let value = scalar.value
            let hidden = value < 0x20 || (0x7F...0x9F).contains(value) || value == 0x200E || value == 0x200F
                || (0x202A...0x202E).contains(value) || (0x2066...0x2069).contains(value)
            return hidden ? "?" : scalar
        }))
    }
}
