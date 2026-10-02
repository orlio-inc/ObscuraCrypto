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

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func byteCount(_ bytes: UInt64) -> String {
        guard bytes >= 1_000 else { return "\(bytes) bytes" }
        return ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file) + " (\(bytes) bytes)"
    }
}
