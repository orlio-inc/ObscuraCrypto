// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import Foundation

/// The manifest of an `.obscurashared` file, read and written by this
/// package's own code rather than by a platform JSON library.
///
/// Platform parsers disagree at the edges: on a key that appears twice
/// (Foundation keeps the first, kotlinx the last), on `5e3` or `5000.0` as a
/// whole number, on a byte-order mark, on a lone surrogate. Any of those
/// would let one file show different items on an iPhone and on an Android
/// phone. This reader takes one strict form of JSON and refuses everything
/// else, and the Kotlin library's reads the same form the same way:
///
/// - UTF-8 only, well formed, with no byte-order mark;
/// - objects, arrays, strings, whole numbers in 64 bits, `true`, `false`
///   and `null`; no fractions or exponents, no leading zeros;
/// - escapes as RFC 8259 lists them, a `\u` surrogate only as part of a pair,
///   and no unescaped control characters in strings;
/// - no key twice in one object, comparing the keys' code points exactly;
/// - at most 16 levels deep, and nothing but whitespace after the value.
///
/// An `.obscura` export's manifest is read the same way, except that it may
/// hold numbers with fractions or exponents (Swift's `JSONEncoder` writes
/// dates as seconds with a fraction) and nest up to 32 levels; such a number
/// is kept as written, as only whole numbers are ever read from it.
enum SharedItemsJSON {
    indirect enum Value: Equatable {
        case object([Member])
        case array([Value])
        case string(String)
        case integer(Int64)
        /// A number with a fraction or exponent, as written: export manifests only.
        case decimal(String)
        case bool(Bool)
        case null

        /// A member of an object, by name. Names are unique, as the reader
        /// refuses a repeated one.
        subscript(name: String) -> Value? {
            guard case .object(let members) = self else { return nil }
            return members.first { $0.name.unicodeScalars.elementsEqual(name.unicodeScalars) }?.value
        }
    }

    struct Member: Equatable {
        let name: String
        let value: Value
    }

    struct Malformed: Error, Equatable {
        let reason: String
    }

    static let maximumDepth = 16

    static func parse(_ data: Data, allowingDecimals: Bool = false, maximumDepth: Int = maximumDepth) throws -> Value {
        var parser = Parser(bytes: [UInt8](data), allowsDecimals: allowingDecimals, maximumDepth: maximumDepth)
        parser.skipWhitespace()
        let value = try parser.value(depth: 1)
        parser.skipWhitespace()
        guard parser.index == parser.bytes.count else { throw Malformed(reason: "data after the JSON") }
        return value
    }

    private struct Parser {
        let bytes: [UInt8]
        let allowsDecimals: Bool
        let maximumDepth: Int
        var index = 0

        mutating func skipWhitespace() {
            while index < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) { index += 1 }
        }

        private func at(_ ascii: Unicode.Scalar) -> Bool {
            index < bytes.count && bytes[index] == UInt8(ascii: ascii)
        }

        private mutating func expect(_ ascii: Unicode.Scalar) throws {
            guard at(ascii) else { throw Malformed(reason: "expected \(ascii)") }
            index += 1
        }

        mutating func value(depth: Int) throws -> Value {
            guard depth <= maximumDepth else { throw Malformed(reason: "nested too deeply") }
            guard index < bytes.count else { throw Malformed(reason: "ends early") }
            switch bytes[index] {
            case UInt8(ascii: "{"): return try object(depth: depth)
            case UInt8(ascii: "["): return try array(depth: depth)
            case UInt8(ascii: "\""): return .string(try string())
            case UInt8(ascii: "t"): try literal("true"); return .bool(true)
            case UInt8(ascii: "f"): try literal("false"); return .bool(false)
            case UInt8(ascii: "n"): try literal("null"); return .null
            case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"): return try number()
            default: throw Malformed(reason: "an unexpected byte")
            }
        }

        private mutating func object(depth: Int) throws -> Value {
            index += 1
            var members: [Member] = []
            var names = Set<[UInt8]>()
            skipWhitespace()
            if at("}") {
                index += 1
                return .object(members)
            }
            while true {
                skipWhitespace()
                guard at("\"") else { throw Malformed(reason: "a name that is not a string") }
                let name = try string()
                // The scalars' own bytes: Swift's String equality would take
                // "é" and "e" with a combining accent for one name.
                guard names.insert(Array(name.utf8)).inserted else { throw Malformed(reason: "a name appears twice") }
                skipWhitespace()
                try expect(":")
                skipWhitespace()
                members.append(Member(name: name, value: try value(depth: depth + 1)))
                skipWhitespace()
                if at(",") {
                    index += 1
                    continue
                }
                try expect("}")
                return .object(members)
            }
        }

        private mutating func array(depth: Int) throws -> Value {
            index += 1
            var elements: [Value] = []
            skipWhitespace()
            if at("]") {
                index += 1
                return .array(elements)
            }
            while true {
                skipWhitespace()
                elements.append(try value(depth: depth + 1))
                skipWhitespace()
                if at(",") {
                    index += 1
                    continue
                }
                try expect("]")
                return .array(elements)
            }
        }

        private mutating func literal(_ word: String) throws {
            for byte in word.utf8 {
                guard index < bytes.count, bytes[index] == byte else { throw Malformed(reason: "an unknown word") }
                index += 1
            }
        }

        /// A number in RFC 8259's form: a whole one within 64 bits, or, where
        /// decimals are allowed, one with a fraction or exponent, kept as text.
        private mutating func number() throws -> Value {
            let start = index
            if at("-") { index += 1 }
            try digits(leadingZeroAlone: true)
            guard at(".") || at("e") || at("E") else {
                guard let value = Int64(String(decoding: bytes[start..<index], as: UTF8.self)) else {
                    throw Malformed(reason: "a number out of range")
                }
                return .integer(value)
            }
            guard allowsDecimals else { throw Malformed(reason: "a number that is not whole") }
            if at(".") {
                index += 1
                try digits(leadingZeroAlone: false)
            }
            if at("e") || at("E") {
                index += 1
                if at("+") || at("-") { index += 1 }
                try digits(leadingZeroAlone: false)
            }
            return .decimal(String(decoding: bytes[start..<index], as: UTF8.self))
        }

        /// One or more digits; with `leadingZeroAlone`, a 0 may only stand alone.
        private mutating func digits(leadingZeroAlone: Bool) throws {
            guard index < bytes.count, (0x30...0x39).contains(bytes[index]) else { throw Malformed(reason: "a malformed number") }
            if leadingZeroAlone, bytes[index] == 0x30 {
                index += 1
                return
            }
            while index < bytes.count, (0x30...0x39).contains(bytes[index]) { index += 1 }
        }

        private mutating func string() throws -> String {
            index += 1
            var scalars = String.UnicodeScalarView()
            while true {
                guard index < bytes.count else { throw Malformed(reason: "a string that does not end") }
                let byte = bytes[index]
                if byte == UInt8(ascii: "\"") {
                    index += 1
                    return String(scalars)
                }
                if byte == UInt8(ascii: "\\") {
                    index += 1
                    scalars.append(try escape())
                } else if byte < 0x20 {
                    throw Malformed(reason: "a control character in a string")
                } else if byte < 0x80 {
                    scalars.append(Unicode.Scalar(byte))
                    index += 1
                } else {
                    scalars.append(try utf8Scalar())
                }
            }
        }

        private mutating func escape() throws -> Unicode.Scalar {
            guard index < bytes.count else { throw Malformed(reason: "a string that does not end") }
            let byte = bytes[index]
            index += 1
            switch byte {
            case UInt8(ascii: "\""): return "\""
            case UInt8(ascii: "\\"): return "\\"
            case UInt8(ascii: "/"): return "/"
            case UInt8(ascii: "b"): return "\u{08}"
            case UInt8(ascii: "f"): return "\u{0C}"
            case UInt8(ascii: "n"): return "\n"
            case UInt8(ascii: "r"): return "\r"
            case UInt8(ascii: "t"): return "\t"
            case UInt8(ascii: "u"):
                let unit = try hex4()
                if (0xDC00...0xDFFF).contains(unit) { throw Malformed(reason: "a lone surrogate") }
                guard (0xD800...0xDBFF).contains(unit) else { return Unicode.Scalar(unit)! }
                guard at("\\"), index + 1 < bytes.count, bytes[index + 1] == UInt8(ascii: "u") else {
                    throw Malformed(reason: "a lone surrogate")
                }
                index += 2
                let low = try hex4()
                guard (0xDC00...0xDFFF).contains(low) else { throw Malformed(reason: "a lone surrogate") }
                return Unicode.Scalar(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00))!
            default:
                throw Malformed(reason: "an unknown escape")
            }
        }

        private mutating func hex4() throws -> UInt32 {
            guard index + 4 <= bytes.count else { throw Malformed(reason: "a string that does not end") }
            var value: UInt32 = 0
            for byte in bytes[index..<index + 4] {
                let digit: UInt32
                switch byte {
                case 0x30...0x39: digit = UInt32(byte - 0x30)
                case 0x41...0x46: digit = UInt32(byte - 0x41 + 10)
                case 0x61...0x66: digit = UInt32(byte - 0x61 + 10)
                default: throw Malformed(reason: "a malformed \\u escape")
                }
                value = value << 4 | digit
            }
            index += 4
            return value
        }

        /// One scalar of well-formed UTF-8 (RFC 3629): no overlong forms, no
        /// surrogates, nothing above U+10FFFF.
        private mutating func utf8Scalar() throws -> Unicode.Scalar {
            let lead = bytes[index]
            let length: Int
            var second: ClosedRange<UInt8> = 0x80...0xBF
            switch lead {
            case 0xC2...0xDF: length = 2
            case 0xE0: length = 3; second = 0xA0...0xBF
            case 0xE1...0xEC, 0xEE...0xEF: length = 3
            case 0xED: length = 3; second = 0x80...0x9F
            case 0xF0: length = 4; second = 0x90...0xBF
            case 0xF1...0xF3: length = 4
            case 0xF4: length = 4; second = 0x80...0x8F
            default: throw Malformed(reason: "malformed UTF-8")
            }
            guard index + length <= bytes.count, second.contains(bytes[index + 1]) else {
                throw Malformed(reason: "malformed UTF-8")
            }
            var value = UInt32(lead) & (length == 2 ? 0x1F : length == 3 ? 0x0F : 0x07)
            for offset in 1..<length {
                let byte = bytes[index + offset]
                guard (0x80...0xBF).contains(byte) else { throw Malformed(reason: "malformed UTF-8") }
                value = value << 6 | UInt32(byte & 0x3F)
            }
            index += length
            return Unicode.Scalar(value)!
        }
    }

    // MARK: Writing

    /// The manifest as writers make it: keys in a fixed order, no
    /// whitespace, only `"`, `\` and control characters escaped.
    static func encode(_ manifest: SharedItemsFile.Manifest) -> Data {
        var out = "{\"items\":["
        for (index, item) in manifest.items.enumerated() {
            if index > 0 { out += "," }
            out += "{\"kind\":" + quoted(item.kind)
            if let type = item.type { out += ",\"type\":" + quoted(type) }
            if let name = item.name { out += ",\"name\":" + quoted(name) }
            out += ",\"parts\":["
            for (partIndex, part) in item.parts.enumerated() {
                if partIndex > 0 { out += "," }
                out += "{\"role\":" + quoted(part.role) + ",\"size\":\(part.size),\"sha256\":" + quoted(part.sha256) + "}"
            }
            out += "]}"
        }
        out += "]}"
        return Data(out.utf8)
    }

    static func quoted(_ text: String) -> String {
        var out = "\""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case _ where scalar.value < 0x20: out += String(format: "\\u%04x", scalar.value)
            default: out.unicodeScalars.append(scalar)
            }
        }
        return out + "\""
    }
}

extension SharedItemsFile.Manifest {
    /// Reads a manifest in the strict form `SharedItemsJSON` takes. Throws
    /// `SharedItemsJSON.Malformed` for anything else, a member of the wrong
    /// type included; whether the items make sense is `Item.isWellFormed`.
    init(json data: Data) throws {
        typealias Malformed = SharedItemsJSON.Malformed
        let root = try SharedItemsJSON.parse(data)
        guard case .object = root, case .array(let elements)? = root["items"] else {
            throw Malformed(reason: "no list of items")
        }
        func string(_ value: SharedItemsJSON.Value?, _ what: String) throws -> String {
            guard case .string(let text)? = value else { throw Malformed(reason: "\(what) is not a string") }
            return text
        }
        func optionalString(_ value: SharedItemsJSON.Value?, _ what: String) throws -> String? {
            switch value {
            case nil, .null?: return nil
            case .string(let text)?: return text
            default: throw Malformed(reason: "\(what) is not a string")
            }
        }
        let items = try elements.map { element -> SharedItemsFile.Item in
            guard case .object = element, case .array(let partElements)? = element["parts"] else {
                throw Malformed(reason: "an item without a list of parts")
            }
            let parts = try partElements.map { part -> SharedItemsFile.Part in
                guard case .object = part, case .integer(let size)? = part["size"] else {
                    throw Malformed(reason: "a part without a whole-number size")
                }
                return SharedItemsFile.Part(role: try string(part["role"], "a role"), size: size,
                                            sha256: try string(part["sha256"], "a hash"))
            }
            return SharedItemsFile.Item(kind: try string(element["kind"], "a kind"),
                                        type: try optionalString(element["type"], "a type"),
                                        name: try optionalString(element["name"], "a name"), parts: parts)
        }
        self.init(items: items)
    }
}
