// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import Foundation
import ObscuraCrypto

let usage = """
obscura: create, inspect and decrypt Obscura vault and media files.

VAULT
  obscura vault create <file>         Write a new vault header, prompting for a password
  obscura vault inspect <file>        Show a vault header. Needs no password
  obscura vault unlock <file>         Check a password by unwrapping the master key
  obscura vault passwd <file>         Change the password; nothing else is re-encrypted
  obscura vault extract <file> <out-dir> [--media <dir>]
                                      Decrypt this vault's photos and videos to <out-dir>

MEDIA
  obscura media encrypt <in> <out> --vault <file> [--chunked] [--chunk-size <bytes>] [--folder <file>] [--force]
  obscura media decrypt <in> <out> --vault <file> [--folder <file>] [--force]
  obscura media inspect <file>        Show a media file's format. Needs no password

FOLDER
  obscura folder create <file>        Write folder protection, prompting for a folder password

EXPORT
  obscura export inspect <file.obscura>
                                      Show an export's header. Needs no password
  obscura export extract <file.obscura> <out-dir>
                                      Decrypt an export's photos and videos to <out-dir>

`vault extract` and `export extract` write only photos and videos, never the
vault's database or the export's manifest. Media in a password-protected folder
is not extracted: its second key lives in the vault's database.

OPTIONS
  --password-stdin    Read passwords from standard input, one per line, in the
                      order they are asked for. For scripts and tests.
  --force             Let media encrypt and decrypt replace an existing <out>.
                      Without it they refuse, so a mistyped path cannot
                      overwrite one of your files.

Passwords are never taken as arguments, so they stay out of shell history.
Keys are never printed. `unlock` shows a fingerprint: the first 8 bytes of
SHA-256 over the key, enough to confirm two tools agree and nothing more.
"""

let valuedOptions: Set<String> = ["vault", "folder", "chunk-size", "media"]

func run(_ raw: [String]) throws {
    guard raw.count >= 2 else {
        print(usage)
        return
    }
    let arguments = try Arguments(Array(raw.dropFirst(2)), valued: valuedOptions)
    let stdin = arguments.has("password-stdin")

    switch (raw[0], raw[1]) {
    case ("vault", "create"):
        let path = try arguments.positional(0, "file")
        guard !FileManager.default.fileExists(atPath: path) else {
            throw CLIError("\(path) already exists")
        }
        let password = try Terminal.readPassword("New vault password: ", fromStandardInput: stdin, confirm: !stdin)
        let (header, masterKey) = try VaultHeader.create(password: password)
        try header.serialized().write(to: URL(fileURLWithPath: path), options: .withoutOverwriting)
        Terminal.printFields([
            ("Created", path),
            ("Master key", "random, 32 bytes, fingerprint \(masterKey.fingerprint)"),
            ("Wrapped with", "PBKDF2-HMAC-SHA256, \(header.kdfIterations) rounds, then AES-256-GCM"),
        ])

    case ("vault", "inspect"):
        let path = try arguments.positional(0, "file")
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let header = try VaultHeader(parsing: data)
        Terminal.printFields([
            ("Format", "Obscura vault, version 3"),
            ("Cipher suite", String(format: "0x%02x, ", header.cipherSuite.rawValue) + header.cipherSuite.name),
            ("KDF rounds", "\(header.kdfIterations)"),
            ("Salt", Terminal.hex(header.salt)),
            ("Master key", "wrapped, \(header.wrappedMasterKey.count) bytes (12 nonce + 32 key + 16 tag)"),
            ("Checksum", "CRC-32 matches"),
            ("After header", Terminal.byteCount(UInt64(data.count - VaultHeader.size)) + ", the encrypted database and padding"),
        ])

    case ("vault", "unlock"):
        let path = try arguments.positional(0, "file")
        let header = try VaultHeader(parsing: try Data(contentsOf: URL(fileURLWithPath: path)))
        let masterKey = try header.unlock(password: Terminal.readPassword("Vault password: ", fromStandardInput: stdin))
        Terminal.printFields([
            ("Unlocked", path),
            ("Master key", "fingerprint \(masterKey.fingerprint)"),
            ("Database size", Terminal.byteCount(try header.databaseSize(masterKey: masterKey))),
        ])

    case ("vault", "passwd"):
        let path = try arguments.positional(0, "file")
        let url = URL(fileURLWithPath: path)
        var data = try Data(contentsOf: url)
        let header = try VaultHeader(parsing: data)
        let current = try Terminal.readPassword("Current password: ", fromStandardInput: stdin)
        let masterKey = try header.unlock(password: current)
        let replacement = try Terminal.readPassword("New password: ", fromStandardInput: stdin, confirm: !stdin)
        let updated = try header.changingPassword(from: current, to: replacement)
        data.replaceSubrange(0..<VaultHeader.size, with: updated.serialized())
        try data.write(to: url, options: .atomic)
        Terminal.printFields([
            ("Changed", path),
            ("Master key", "unchanged, fingerprint \(masterKey.fingerprint)"),
            ("Rewritten", "the \(VaultHeader.size)-byte header only, with a new salt"),
        ])

    case ("media", "encrypt"):
        let input = URL(fileURLWithPath: try arguments.positional(0, "in"))
        let output = try outputURL(arguments)
        let masterKey = try unlockVault(arguments, stdin: stdin)
        let folderKey = try unlockFolder(arguments, stdin: stdin)
        if arguments.has("chunked") {
            let chunkSize = try arguments.option("chunk-size").map { value -> UInt32 in
                guard let size = UInt32(value), size > 0 else { throw CLIError("--chunk-size must be a positive number of bytes") }
                return size
            } ?? ChunkedMediaHeader.defaultChunkSize
            let header = try ChunkedMediaEncryptor.encrypt(
                from: input, to: output, masterKey: masterKey, folderKey: folderKey, chunkSize: chunkSize)
            print("Encrypted \(header.chunkCount) chunks to \(output.path)\(folderKey == nil ? "" : ", with a folder layer")")
        } else {
            let sealed = try SingleShotMedia.encrypt(Data(contentsOf: input), masterKey: masterKey, folderKey: folderKey)
            try sealed.write(to: output, options: .atomic)
            print("Encrypted to \(output.path)\(folderKey == nil ? "" : ", with a folder layer")")
        }

    case ("media", "decrypt"):
        let input = URL(fileURLWithPath: try arguments.positional(0, "in"))
        let output = try outputURL(arguments)
        let masterKey = try unlockVault(arguments, stdin: stdin)
        let folderKey = try unlockFolder(arguments, stdin: stdin)
        let prefix = try FileHandle(forReadingFrom: input).read(upToCount: 4) ?? Data()
        switch MediaFormat.detect(prefix) {
        case .chunked:
            let reader = try ChunkedMediaReader(url: input)
            try reader.decrypt(to: output, masterKey: masterKey, folderKey: folderKey)
            print("Decrypted \(reader.header.chunkCount) chunks to \(output.path)")
        case .singleShot:
            try SingleShotMedia.decrypt(Data(contentsOf: input), masterKey: masterKey, folderKey: folderKey)
                .write(to: output, options: .atomic)
            print("Decrypted to \(output.path)")
        }

    case ("media", "inspect"):
        let url = URL(fileURLWithPath: try arguments.positional(0, "file"))
        let prefix = try FileHandle(forReadingFrom: url).read(upToCount: ChunkedMediaHeader.size) ?? Data()
        let size = try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? UInt64 ?? 0
        switch MediaFormat.detect(prefix) {
        case .chunked:
            let header = try ChunkedMediaReader(url: url).header
            Terminal.printFields([
                ("Format", "chunked (OBCM, version 1)"),
                ("Plaintext", Terminal.byteCount(header.totalPlaintextSize)),
                ("Chunks", "\(header.chunkCount) of up to \(header.chunkPlaintextSize) bytes"),
                ("Folder layer", header.hasFolderLayer ? "yes, 56 bytes of overhead per chunk" : "no, 28 bytes of overhead per chunk"),
                ("Nonce prefix", Terminal.hex(header.noncePrefix)),
                ("File length", "\(size) bytes, matches the header"),
            ])
        case .singleShot:
            Terminal.printFields([
                ("Format", "single-shot AES-256-GCM"),
                ("Nonce", Terminal.hex(prefix.prefix(AESGCM.nonceSize))),
                ("Ciphertext", "\(max(Int(size) - AESGCM.overhead, 0)) bytes, plus a 16-byte tag"),
                ("Folder layer", "cannot be told without the folder key"),
            ])
        }

    case ("folder", "create"):
        let path = try arguments.positional(0, "file")
        guard !FileManager.default.fileExists(atPath: path) else {
            throw CLIError("\(path) already exists")
        }
        let password = try Terminal.readPassword("New folder password: ", fromStandardInput: stdin, confirm: !stdin)
        let (protection, folderKey) = try FolderProtection.create(password: password)
        try FolderFile(protection).encoded().write(to: URL(fileURLWithPath: path), options: .withoutOverwriting)
        Terminal.printFields([
            ("Created", path),
            ("Folder key", "random, 32 bytes, fingerprint \(folderKey.fingerprint)"),
            ("Wrapped with", "PBKDF2-HMAC-SHA256, \(KeyDerivation.folderIterations) rounds, then AES-256-GCM"),
        ])

    case ("vault", "extract"):
        let vaultURL = URL(fileURLWithPath: try arguments.positional(0, "file"))
        let outDir = try outputDirectory(arguments)
        guard let pool = mediaPool(arguments, vaultURL: vaultURL) else {
            throw CLIError("no media folder found; give one with --media <dir>")
        }
        let masterKey = try unlockVaultFile(vaultURL, stdin: stdin)
        // The media pool is shared by every vault, and nothing in a file's name
        // says which vault it belongs to. The key does: a file this vault's
        // master key opens is this vault's. Thumbnails are tried first, being
        // small.
        let ids = try mediaIDs(in: pool).sorted()
        var extracted = 0
        for id in ids where opens(id, in: pool, masterKey: masterKey) {
            if case .extracted = try MediaExtraction.extract(
                storedFile: pool.appendingPathComponent("\(id).data.enc"), id: id, masterKey: masterKey, into: outDir) {
                extracted += 1
            }
        }
        Terminal.printFields([
            ("Extracted", "\(extracted) photos and videos to \(outDir.path)"),
            ("Not extracted", "\(ids.count - extracted) files that this vault's key does not open: "
                + "other vaults' files, and this vault's files in password-protected folders"),
        ])

    case ("export", "inspect"):
        let url = URL(fileURLWithPath: try arguments.positional(0, "file"))
        let header = try ExportHeader(parsing: try FileHandle(forReadingFrom: url).read(upToCount: ExportHeader.size) ?? Data())
        let size = try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? UInt64 ?? 0
        Terminal.printFields([
            ("Format", "Obscura export, version \(header.version)"),
            ("Key", "PBKDF2-HMAC-SHA256, \(header.kdfIterations) rounds, then AES-256-GCM"),
            ("Salt", Terminal.hex(header.salt)),
            ("Nonce prefix", Terminal.hex(header.noncePrefix)),
            ("Encrypted", Terminal.byteCount(size - UInt64(ExportHeader.size)) + " after the 64-byte header"),
        ])

    case ("export", "extract"):
        let url = URL(fileURLWithPath: try arguments.positional(0, "file.obscura"))
        let outDir = try outputDirectory(arguments)
        let password = try Terminal.readPassword("Export password: ", fromStandardInput: stdin)
        let archive = try ExportArchive(url: url, password: password)
        // The app exports with the vault's own password, which also unwraps
        // the master key; ask separately only if it does not.
        let masterKey: SecureBytes
        do {
            masterKey = try archive.index.unlockMasterKey(password: password)
        } catch ObscuraCryptoError.wrongPassword {
            masterKey = try archive.index.unlockMasterKey(
                password: Terminal.readPassword("Vault password: ", fromStandardInput: stdin))
        }

        try archive.skipDatabase()
        var extracted = 0, layered = 0
        for media in archive.index.mediaFiles {
            let stored = outDir.appendingPathComponent(".\(media.id).stored")
            defer { try? FileManager.default.removeItem(at: stored) }
            try archive.copyStoredFile(size: media.dataSize, to: stored)
            try archive.copyStoredFile(size: media.thumbnailSize, to: nil)
            guard media.dataSize > 0 else { continue }
            switch try MediaExtraction.extract(storedFile: stored, id: media.id, masterKey: masterKey, into: outDir) {
            case .extracted: extracted += 1
            case .notOpenedByMasterKey: layered += 1
            }
        }
        guard try archive.isAtEnd() else {
            throw CLIError("the export has data after its last media file; it may have been altered")
        }
        Terminal.printFields([
            ("Extracted", "\(extracted) photos and videos to \(outDir.path)"),
            ("Not extracted", "\(layered) in password-protected folders"),
        ])

    default:
        throw CLIError("unknown command \"\(raw[0]) \(raw[1])\"; run obscura with no arguments for help")
    }
}

/// `<out>`, refused if something is already there unless `--force` was given.
/// Checked before any password is asked for.
func outputURL(_ arguments: Arguments) throws -> URL {
    let path = try arguments.positional(1, "out")
    if FileManager.default.fileExists(atPath: path), !arguments.has("force") {
        throw CLIError("\(path) already exists; use --force to replace it")
    }
    return URL(fileURLWithPath: path)
}

func unlockVaultFile(_ url: URL, stdin: Bool) throws -> SecureBytes {
    let header = try VaultHeader(parsing: try FileHandle(forReadingFrom: url).read(upToCount: VaultHeader.size) ?? Data())
    return try header.unlock(password: Terminal.readPassword("Vault password: ", fromStandardInput: stdin))
}

/// `--media`, or the `media` folder beside the vault's `data` folder, as the
/// app lays them out.
func mediaPool(_ arguments: Arguments, vaultURL: URL) -> URL? {
    let candidate = arguments.option("media").map { URL(fileURLWithPath: $0, isDirectory: true) }
        ?? vaultURL.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("media", isDirectory: true)
    var isDirectory: ObjCBool = false
    return FileManager.default.fileExists(atPath: candidate.path, isDirectory: &isDirectory) && isDirectory.boolValue ? candidate : nil
}

/// IDs of the media files in a pool: `<UUID>.data.enc`.
func mediaIDs(in pool: URL) throws -> [String] {
    try FileManager.default.contentsOfDirectory(atPath: pool.path).compactMap { name in
        guard name.hasSuffix(".data.enc") else { return nil }
        let id = String(name.dropLast(".data.enc".count))
        return UUID(uuidString: id) != nil ? id : nil
    }
}

/// Whether `masterKey` opens a stored file, trying its thumbnail first.
func opens(_ id: String, in pool: URL, masterKey: SecureBytes) -> Bool {
    let thumb = pool.appendingPathComponent("\(id).thumb.enc")
    let file = FileManager.default.fileExists(atPath: thumb.path) ? thumb : pool.appendingPathComponent("\(id).data.enc")
    return MediaExtraction.masterKeyOpens(storedFile: file, masterKey: masterKey)
}

/// `<out-dir>`, created if it does not exist.
func outputDirectory(_ arguments: Arguments) throws -> URL {
    let url = URL(fileURLWithPath: try arguments.positional(1, "out-dir"), isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

func unlockVault(_ arguments: Arguments, stdin: Bool) throws -> SecureBytes {
    guard let path = arguments.option("vault") else { throw CLIError("--vault <file> is required") }
    let header = try VaultHeader(parsing: try Data(contentsOf: URL(fileURLWithPath: path)))
    return try header.unlock(password: Terminal.readPassword("Vault password: ", fromStandardInput: stdin))
}

func unlockFolder(_ arguments: Arguments, stdin: Bool) throws -> SecureBytes? {
    guard let path = arguments.option("folder") else { return nil }
    let protection = try FolderFile.decode(Data(contentsOf: URL(fileURLWithPath: path)))
    return try protection.unlock(password: Terminal.readPassword("Folder password: ", fromStandardInput: stdin))
}

/// Folder protection as JSON, with the same three base64 fields the app keeps
/// in its database for a protected folder.
struct FolderFile: Codable {
    let passwordSalt: String
    let passwordHash: String
    let folderKeyEncrypted: String

    init(_ protection: FolderProtection) {
        passwordSalt = protection.salt.base64EncodedString()
        passwordHash = protection.passwordHash.base64EncodedString()
        folderKeyEncrypted = protection.wrappedFolderKey.base64EncodedString()
    }

    func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(self)
    }

    static func decode(_ data: Data) throws -> FolderProtection {
        let file = try JSONDecoder().decode(FolderFile.self, from: data)
        guard let salt = Data(base64Encoded: file.passwordSalt),
              let hash = Data(base64Encoded: file.passwordHash),
              let wrapped = Data(base64Encoded: file.folderKeyEncrypted) else {
            throw CLIError("folder file fields are not valid base64")
        }
        return try FolderProtection(salt: salt, passwordHash: hash, wrappedFolderKey: wrapped)
    }
}

do {
    try run(Array(CommandLine.arguments.dropFirst()))
} catch {
    FileHandle.standardError.write(Data("obscura: \(error)\n".utf8))
    exit(1)
}
