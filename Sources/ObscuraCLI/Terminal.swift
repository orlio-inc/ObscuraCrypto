// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import Darwin
import Foundation

/// A command-line failure, printed without a stack trace.
struct CLIError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// The parsed command line: positional arguments, `--flag value` options and
/// bare `--switch`es.
struct Arguments {
    private(set) var positionals: [String] = []
    private var options: [String: String] = [:]
    private var switches: Set<String> = []

    /// `valued` names the options that take a value; any other `--name` is a switch.
    init(_ raw: [String], valued: Set<String>) throws {
        var iterator = raw.makeIterator()
        while let argument = iterator.next() {
            guard argument.hasPrefix("--") else {
                positionals.append(argument)
                continue
            }
            let name = String(argument.dropFirst(2))
            if valued.contains(name) {
                guard let value = iterator.next() else { throw CLIError("--\(name) needs a value") }
                options[name] = value
            } else {
                switches.insert(name)
            }
        }
    }

    func positional(_ index: Int, _ name: String) throws -> String {
        guard index < positionals.count else { throw CLIError("missing <\(name)>") }
        return positionals[index]
    }

    func option(_ name: String) -> String? { options[name] }
    func has(_ name: String) -> Bool { switches.contains(name) }
}

/// What a command leaves while it works, removed if it is stopped part way
/// with Control-C or a kill: Swift runs no `defer` when a signal ends the
/// process, so without this a decrypted file could stay behind in a hidden
/// staging folder or `.partial` file.
///
/// Only what this run made is removed: the staging folders it created, by
/// their exact paths, and new `.partial` files that are plain files, never a
/// folder or a link someone else put in the output folder. Once a signal has
/// come, the run makes no new file (`checkpoint`), and the folder is swept
/// more than once, for a file that was being created as the signal came.
enum Interruption {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var stopping = false
    nonisolated(unsafe) private static var staging: Set<URL> = []
    nonisolated(unsafe) private static var folders: [URL: Set<String>] = [:]
    nonisolated(unsafe) private static var sources: [DispatchSourceSignal] = []

    static func install() {
        for number in [SIGINT, SIGTERM, SIGHUP] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
            source.setEventHandler { stop(number) }
            source.resume()
            sources.append(source)
        }
    }

    /// Runs `body`, which writes into `folder`. If the process is stopped
    /// before it returns, `.partial` files that appeared there meanwhile are
    /// removed; ones that were there before are left alone.
    static func cleaningUp<Result>(_ folder: URL, _ body: () throws -> Result) rethrows -> Result {
        let before = Set(partials(in: folder))
        lock.withLock { folders[folder] = before }
        defer { lock.withLock { folders[folder] = nil } }
        return try body()
    }

    /// A new staging folder in `folder`, owner only, removed if the run is
    /// stopped before `removeStaging`.
    static func makeStaging(in folder: URL) throws -> URL {
        let url = folder.appendingPathComponent(".obscura-staging-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        lock.withLock { _ = staging.insert(url) }
        return url
    }

    static func removeStaging(_ url: URL) {
        try? FileManager.default.removeItem(at: url)
        lock.withLock { _ = staging.remove(url) }
    }

    /// Called before each file a run creates: once a signal has come, the
    /// run waits here to be ended rather than make another.
    static func checkpoint() {
        while lock.withLock({ stopping }) { sleep(1) }
    }

    private static func stop(_ number: Int32) -> Never {
        lock.withLock { stopping = true }
        for _ in 0..<3 {
            removeLeftovers()
            usleep(100_000)
        }
        removeLeftovers()
        exit(128 + number)
    }

    private static func partials(in folder: URL) -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? []).filter {
            $0.hasPrefix(".") && $0.hasSuffix(".partial")
        }
    }

    private static func removeLeftovers() {
        let (made, watched) = lock.withLock { (staging, folders) }
        // `removeItem` removes a link itself and never follows one.
        for url in made { try? FileManager.default.removeItem(at: url) }
        for (folder, before) in watched {
            for name in partials(in: folder) where !before.contains(name) {
                let url = folder.appendingPathComponent(name)
                guard (try? FileManager.default.attributesOfItem(atPath: url.path))?[.type] as? FileAttributeType
                        == .typeRegular else { continue }
                try? FileManager.default.removeItem(at: url)
            }
        }
    }

    /// Refuses a folder others can change: decrypted files are staged and
    /// moved there, and whoever can rename or replace its entries could send
    /// them elsewhere or have the cleanup remove what they put there. A
    /// folder only its owner can write to is fine, and so is one with the
    /// sticky bit (such as /tmp) owned by its user or by root.
    static func requirePrivateFolder(_ url: URL) throws {
        var info = stat()
        guard stat(url.path, &info) == 0 else { throw CLIError("cannot read \(url.path)") }
        let mode = info.st_mode
        let sticky = mode & S_ISVTX != 0
        let othersWrite = mode & (S_IWGRP | S_IWOTH) != 0
        let mine = info.st_uid == getuid()
        guard (!othersWrite || sticky) && (mine || (info.st_uid == 0 && sticky)) else {
            throw CLIError("\(url.path) can be changed by other users; use a folder only you can write to")
        }
    }
}

enum Terminal {
    /// Passwords come from `--password-stdin` when scripting, and otherwise from
    /// the terminal with echo off. Never from an argument, which would leave
    /// them in shell history and in the process list.
    static func readPassword(_ prompt: String, fromStandardInput: Bool, confirm: Bool = false) throws -> String {
        if fromStandardInput {
            guard let line = readLine(strippingNewline: true), !line.isEmpty else {
                throw CLIError("expected a password on standard input")
            }
            return line
        }
        let password = try prompted(prompt)
        if confirm, try prompted("Repeat to confirm: ") != password {
            throw CLIError("the passwords do not match")
        }
        return password
    }

    private static func prompted(_ prompt: String) throws -> String {
        var buffer = [CChar](repeating: 0, count: 1024)
        defer { buffer.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) } }
        guard readpassphrase(prompt, &buffer, buffer.count, RPP_REQUIRE_TTY) != nil else {
            throw CLIError("could not read a password from the terminal; use --password-stdin")
        }
        let length = buffer.firstIndex(of: 0) ?? buffer.count
        let password = String(decoding: buffer[..<length].map { UInt8(bitPattern: $0) }, as: UTF8.self)
        guard !password.isEmpty else { throw CLIError("empty password") }
        return password
    }

    static func printFields(_ rows: [(String, String)]) {
        let width = rows.map(\.0.count).max() ?? 0
        for (label, value) in rows {
            print(label.padding(toLength: width, withPad: " ", startingAt: 0) + "  " + value)
        }
    }

    /// Writes decrypted bytes owner-only: to a private temporary file beside
    /// `url`, then into place, so a file already there (with `--force`) is
    /// replaced whole and takes on the new file's permissions.
    static func writePrivately(_ data: Data, to url: URL) throws {
        let temporary = url.deletingLastPathComponent()
            .appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).partial")
        guard FileManager.default.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw CLIError("could not write beside \(url.path)")
        }
        do {
            let handle = try FileHandle(forWritingTo: temporary)
            defer { try? handle.close() }
            try handle.write(contentsOf: data)
            try handle.synchronize()
            if FileManager.default.fileExists(atPath: url.path) {
                _ = try FileManager.default.replaceItemAt(url, withItemAt: temporary, options: .usingNewMetadataOnly)
            } else {
                try FileManager.default.moveItem(at: temporary, to: url)
            }
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func byteCount(_ bytes: UInt64) -> String {
        guard bytes >= 1_000 else { return "\(bytes) bytes" }
        return ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file) + " (\(bytes) bytes)"
    }
}
