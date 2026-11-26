// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

/**
 * The manifest of an `.obscurashared` file, read and written by this
 * library's own code rather than by kotlinx or another JSON library. The
 * Swift package's `SharedItemsJSON`, rule for rule: platform parsers disagree
 * at the edges (a key that appears twice, `5e3` as a whole number, a
 * byte-order mark, a lone surrogate), and any of those would let one file show
 * different items on an iPhone and an Android phone.
 *
 * The one form taken: UTF-8, well formed, no byte-order mark; objects,
 * arrays, strings, whole numbers in 64 bits, `true`, `false`, `null`, with no
 * fractions, exponents or leading zeros; RFC 8259 escapes, a `\u` surrogate
 * only as part of a pair, no unescaped control characters; no key twice in
 * one object, compared code point for code point; at most 16 levels deep; and
 * nothing but whitespace after the value.
 *
 * An `.obscura` export's manifest is read the same way, except that it may hold
 * numbers with fractions or exponents (Swift's `JSONEncoder` writes dates as
 * seconds with a fraction) and nest up to 32 levels; such a number is kept as
 * written, as only whole numbers are ever read from it.
 */
internal object SharedItemsJson {
    sealed class Value {
        data class Object(val members: List<Pair<String, Value>>) : Value() {
            /** A member by name. Names are unique, as the reader refuses a repeated one. */
            operator fun get(name: String): Value? = members.firstOrNull { it.first == name }?.second
        }

        data class Array(val elements: List<Value>) : Value()
        data class Text(val value: String) : Value()
        data class Integer(val value: Long) : Value()

        /** A number with a fraction or exponent, as written: export manifests only. */
        data class Decimal(val text: String) : Value()
        data class Bool(val value: Boolean) : Value()
        data object Null : Value()
    }

    class Malformed(val reason: String) : Exception(reason)

    const val MAXIMUM_DEPTH = 16

    fun parse(bytes: ByteArray, allowingDecimals: Boolean = false, maximumDepth: Int = MAXIMUM_DEPTH): Value {
        val parser = Parser(bytes, allowingDecimals, maximumDepth)
        parser.skipWhitespace()
        val value = parser.value(1)
        parser.skipWhitespace()
        if (parser.index != bytes.size) throw Malformed("data after the JSON")
        return value
    }

    private class Parser(private val bytes: ByteArray, private val allowsDecimals: Boolean, private val maximumDepth: Int) {
        var index = 0

        private fun byte(at: Int): Int = bytes[at].toInt() and 0xFF

        fun skipWhitespace() {
            while (index < bytes.size && byte(index) in WHITESPACE) index += 1
        }

        private fun at(ascii: Char): Boolean = index < bytes.size && byte(index) == ascii.code

        private fun expect(ascii: Char) {
            if (!at(ascii)) throw Malformed("expected $ascii")
            index += 1
        }

        fun value(depth: Int): Value {
            if (depth > maximumDepth) throw Malformed("nested too deeply")
            if (index >= bytes.size) throw Malformed("ends early")
            return when (byte(index)) {
                '{'.code -> obj(depth)
                '['.code -> array(depth)
                '"'.code -> Value.Text(string())
                't'.code -> { literal("true"); Value.Bool(true) }
                'f'.code -> { literal("false"); Value.Bool(false) }
                'n'.code -> { literal("null"); Value.Null }
                '-'.code, in '0'.code..'9'.code -> number()
                else -> throw Malformed("an unexpected byte")
            }
        }

        private fun obj(depth: Int): Value {
            index += 1
            val members = ArrayList<Pair<String, Value>>()
            val names = HashSet<String>()
            skipWhitespace()
            if (at('}')) {
                index += 1
                return Value.Object(members)
            }
            while (true) {
                skipWhitespace()
                if (!at('"')) throw Malformed("a name that is not a string")
                val name = string()
                if (!names.add(name)) throw Malformed("a name appears twice")
                skipWhitespace()
                expect(':')
                skipWhitespace()
                members += name to value(depth + 1)
                skipWhitespace()
                if (at(',')) {
                    index += 1
                    continue
                }
                expect('}')
                return Value.Object(members)
            }
        }

        private fun array(depth: Int): Value {
            index += 1
            val elements = ArrayList<Value>()
            skipWhitespace()
            if (at(']')) {
                index += 1
                return Value.Array(elements)
            }
            while (true) {
                skipWhitespace()
                elements += value(depth + 1)
                skipWhitespace()
                if (at(',')) {
                    index += 1
                    continue
                }
                expect(']')
                return Value.Array(elements)
            }
        }

        private fun literal(word: String) {
            for (c in word) {
                if (index >= bytes.size || byte(index) != c.code) throw Malformed("an unknown word")
                index += 1
            }
        }

        private fun isDigit(at: Int) = at < bytes.size && byte(at) in '0'.code..'9'.code

        /** A number in RFC 8259's form: a whole one within 64 bits, or, where decimals are allowed, one with a fraction or exponent, kept as text. */
        private fun number(): Value {
            val start = index
            if (at('-')) index += 1
            digits(leadingZeroAlone = true)
            if (!(at('.') || at('e') || at('E'))) {
                return Value.Integer(
                    String(bytes, start, index - start, Charsets.US_ASCII).toLongOrNull() ?: throw Malformed("a number out of range"),
                )
            }
            if (!allowsDecimals) throw Malformed("a number that is not whole")
            if (at('.')) {
                index += 1
                digits(leadingZeroAlone = false)
            }
            if (at('e') || at('E')) {
                index += 1
                if (at('+') || at('-')) index += 1
                digits(leadingZeroAlone = false)
            }
            return Value.Decimal(String(bytes, start, index - start, Charsets.US_ASCII))
        }

        /** One or more digits; with [leadingZeroAlone], a 0 may only stand alone. */
        private fun digits(leadingZeroAlone: Boolean) {
            if (!isDigit(index)) throw Malformed("a malformed number")
            if (leadingZeroAlone && byte(index) == '0'.code) {
                index += 1
                return
            }
            while (isDigit(index)) index += 1
        }

        private fun string(): String {
            index += 1
            val out = StringBuilder()
            while (true) {
                if (index >= bytes.size) throw Malformed("a string that does not end")
                val b = byte(index)
                when {
                    b == '"'.code -> {
                        index += 1
                        return out.toString()
                    }
                    b == '\\'.code -> {
                        index += 1
                        out.appendCodePoint(escape())
                    }
                    b < 0x20 -> throw Malformed("a control character in a string")
                    b < 0x80 -> {
                        out.append(b.toChar())
                        index += 1
                    }
                    else -> out.appendCodePoint(utf8CodePoint())
                }
            }
        }

        private fun escape(): Int {
            if (index >= bytes.size) throw Malformed("a string that does not end")
            val b = byte(index)
            index += 1
            return when (b) {
                '"'.code -> '"'.code
                '\\'.code -> '\\'.code
                '/'.code -> '/'.code
                'b'.code -> 0x08
                'f'.code -> 0x0C
                'n'.code -> 0x0A
                'r'.code -> 0x0D
                't'.code -> 0x09
                'u'.code -> {
                    val unit = hex4()
                    if (unit in 0xDC00..0xDFFF) throw Malformed("a lone surrogate")
                    if (unit !in 0xD800..0xDBFF) return unit
                    if (!at('\\') || index + 1 >= bytes.size || byte(index + 1) != 'u'.code) throw Malformed("a lone surrogate")
                    index += 2
                    val low = hex4()
                    if (low !in 0xDC00..0xDFFF) throw Malformed("a lone surrogate")
                    0x10000 + ((unit - 0xD800) shl 10) + (low - 0xDC00)
                }
                else -> throw Malformed("an unknown escape")
            }
        }

        private fun hex4(): Int {
            if (index + 4 > bytes.size) throw Malformed("a string that does not end")
            var value = 0
            for (i in 0 until 4) {
                val b = byte(index + i)
                val digit = when (b) {
                    in '0'.code..'9'.code -> b - '0'.code
                    in 'A'.code..'F'.code -> b - 'A'.code + 10
                    in 'a'.code..'f'.code -> b - 'a'.code + 10
                    else -> throw Malformed("a malformed \\u escape")
                }
                value = (value shl 4) or digit
            }
            index += 4
            return value
        }

        /** One code point of well-formed UTF-8 (RFC 3629): no overlong forms, no surrogates, nothing above U+10FFFF. */
        private fun utf8CodePoint(): Int {
            val lead = byte(index)
            var second = 0x80..0xBF
            val length = when (lead) {
                in 0xC2..0xDF -> 2
                0xE0 -> { second = 0xA0..0xBF; 3 }
                in 0xE1..0xEC, in 0xEE..0xEF -> 3
                0xED -> { second = 0x80..0x9F; 3 }
                0xF0 -> { second = 0x90..0xBF; 4 }
                in 0xF1..0xF3 -> 4
                0xF4 -> { second = 0x80..0x8F; 4 }
                else -> throw Malformed("malformed UTF-8")
            }
            if (index + length > bytes.size || byte(index + 1) !in second) throw Malformed("malformed UTF-8")
            var value = lead and (if (length == 2) 0x1F else if (length == 3) 0x0F else 0x07)
            for (offset in 1 until length) {
                val b = byte(index + offset)
                if (b !in 0x80..0xBF) throw Malformed("malformed UTF-8")
                value = (value shl 6) or (b and 0x3F)
            }
            index += length
            return value
        }

        companion object {
            private val WHITESPACE = setOf(0x20, 0x09, 0x0A, 0x0D)
        }
    }

    // MARK: Writing

    /** The manifest as writers make it: keys in a fixed order, no whitespace, only `"`, `\` and control characters escaped. */
    fun encode(manifest: SharedItemsFile.Manifest): ByteArray = buildString {
        append("{\"items\":[")
        manifest.items.forEachIndexed { index, item ->
            if (index > 0) append(',')
            append("{\"kind\":").append(quoted(item.kind))
            item.type?.let { append(",\"type\":").append(quoted(it)) }
            item.name?.let { append(",\"name\":").append(quoted(it)) }
            append(",\"parts\":[")
            item.parts.forEachIndexed { partIndex, part ->
                if (partIndex > 0) append(',')
                append("{\"role\":").append(quoted(part.role)).append(",\"size\":").append(part.size)
                append(",\"sha256\":").append(quoted(part.sha256)).append('}')
            }
            append("]}")
        }
        append("]}")
    }.toByteArray(Charsets.UTF_8)

    fun quoted(text: String): String = buildString {
        append('"')
        var i = 0
        while (i < text.length) {
            val point = text.codePointAt(i)
            when {
                point == '"'.code -> append("\\\"")
                point == '\\'.code -> append("\\\\")
                point < 0x20 -> append(String.format(java.util.Locale.ROOT, "\\u%04x", point))
                else -> appendCodePoint(point)
            }
            i += Character.charCount(point)
        }
        append('"')
    }

    /**
     * Reads a manifest in the strict form above. Throws [Malformed] for
     * anything else, a member of the wrong type included; whether the items
     * make sense is [SharedItemsFile.Item.isWellFormed].
     */
    fun manifest(bytes: ByteArray): SharedItemsFile.Manifest {
        val root = parse(bytes) as? Value.Object ?: throw Malformed("no list of items")
        val elements = root["items"] as? Value.Array ?: throw Malformed("no list of items")
        fun string(value: Value?, what: String): String = (value as? Value.Text)?.value ?: throw Malformed("$what is not a string")
        fun optionalString(value: Value?, what: String): String? = when (value) {
            null, Value.Null -> null
            is Value.Text -> value.value
            else -> throw Malformed("$what is not a string")
        }
        return SharedItemsFile.Manifest(
            elements.elements.map { element ->
                val item = element as? Value.Object ?: throw Malformed("an item without a list of parts")
                val parts = item["parts"] as? Value.Array ?: throw Malformed("an item without a list of parts")
                SharedItemsFile.Item(
                    kind = string(item["kind"], "a kind"),
                    type = optionalString(item["type"], "a type"),
                    name = optionalString(item["name"], "a name"),
                    parts = parts.elements.map { partElement ->
                        val part = partElement as? Value.Object ?: throw Malformed("a part without a whole-number size")
                        val size = part["size"] as? Value.Integer ?: throw Malformed("a part without a whole-number size")
                        SharedItemsFile.Part(string(part["role"], "a role"), size.value, string(part["sha256"], "a hash"))
                    },
                )
            },
        )
    }
}
