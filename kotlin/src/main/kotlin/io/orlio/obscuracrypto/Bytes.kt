// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

import java.io.InputStream
import java.util.zip.CRC32

/** The unsigned 32-bit big-endian number at [offset], as a Long. */
internal fun ByteArray.bigEndianUInt32(offset: Int): Long {
    var value = 0L
    for (i in 0 until 4) value = value shl 8 or (this[offset + i].toLong() and 0xFF)
    return value
}

/**
 * The 64-bit big-endian number at [offset]. The bits are returned as they are,
 * so a value of 2^63 or more reads as negative; callers that cannot accept
 * such a value check for it.
 */
internal fun ByteArray.bigEndianInt64(offset: Int): Long {
    var value = 0L
    for (i in 0 until 8) value = value shl 8 or (this[offset + i].toLong() and 0xFF)
    return value
}

internal fun bigEndianBytes(value: Long, size: Int): ByteArray {
    val bytes = ByteArray(size)
    for (i in 0 until size) bytes[size - 1 - i] = (value ushr (8 * i)).toByte()
    return bytes
}

internal fun littleEndianBytes(value: Long): ByteArray {
    val bytes = ByteArray(8)
    for (i in 0 until 8) bytes[i] = (value ushr (8 * i)).toByte()
    return bytes
}

internal fun ByteArray.range(from: Int, to: Int): ByteArray = copyOfRange(from, to)

internal fun ByteArray.startsWith(prefix: ByteArray): Boolean =
    size >= prefix.size && (prefix.indices).all { this[it] == prefix[it] }

/**
 * CRC-32 (IEEE 802.3), as zlib computes it. Used only to catch a damaged vault
 * header; it is not a security check, the AES-GCM tags are.
 */
internal fun crc32(bytes: ByteArray, length: Int = bytes.size): Long {
    val crc = CRC32()
    crc.update(bytes, 0, length)
    return crc.value
}

/** Compares two byte sequences in time that depends only on their length. */
internal fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
    if (a.size != b.size) return false
    var difference = 0
    for (i in a.indices) difference = difference or (a[i].toInt() xor b[i].toInt())
    return difference == 0
}

/** Reads until [buffer] is full, or the stream ends. Returns the bytes read. */
internal fun InputStream.readFully(buffer: ByteArray, length: Int = buffer.size): Int {
    var total = 0
    while (total < length) {
        val read = read(buffer, total, length - total)
        if (read < 0) break
        total += read
    }
    return total
}

internal fun InputStream.readExactly(count: Int): ByteArray? {
    val buffer = ByteArray(count)
    return if (readFully(buffer) == count) buffer else null
}


/** A UUID in the canonical 8-4-4-4-12 form, the only shape a media ID takes. */
internal fun isCanonicalUuid(text: String): Boolean = UUID_PATTERN.matches(text)

private val UUID_PATTERN =
    Regex("^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
