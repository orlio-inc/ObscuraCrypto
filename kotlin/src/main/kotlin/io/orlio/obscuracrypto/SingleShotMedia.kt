// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

/** How a media file is laid out. */
enum class MediaFormat {
    /** One AES-GCM sealed message: photos, thumbnails, camera videos. */
    SINGLE_SHOT,

    /** The chunked format: large videos, decryptable a piece at a time. */
    CHUNKED;

    companion object {
        /**
         * Tells the two apart from a file's first bytes.
         *
         * A chunked file starts with "OBCM"; a single-shot file starts with
         * its random nonce. A single-shot nonce that happened to begin with
         * those four bytes, a 1 in 2^32 chance, would be misread; the iOS app
         * decides the same way, so the two always agree.
         */
        fun detect(prefix: ByteArray): MediaFormat =
            if (prefix.startsWith(ChunkedMediaHeader.MAGIC)) CHUNKED else SINGLE_SHOT
    }
}

/**
 * Media encrypted in one piece: `nonce || ciphertext || tag`, sealed with the
 * vault's master key, and sealed again with the folder key if the media is in
 * a protected folder.
 *
 * Every file gets a fresh random nonce. Thumbnails use this format too.
 */
object SingleShotMedia {
    fun encrypt(plaintext: ByteArray, masterKey: SecureBytes, folderKey: SecureBytes? = null): ByteArray {
        val inner = AesGcm.seal(plaintext, masterKey)
        return if (folderKey == null) inner else AesGcm.seal(inner, folderKey)
    }

    /**
     * Decrypts, removing the folder layer first when a folder key is given.
     *
     * With a folder key, a file that turns out not to carry the folder layer
     * is still opened with the master key alone. The app reads files this way
     * because setting a folder password rewraps a large folder one file at a
     * time, and an interrupted run leaves some files without the layer. It is
     * not a bypass: AES-GCM is authenticated, so a file only ever reaches that
     * path if the folder key genuinely cannot open it, and it still has to
     * pass the master key.
     */
    fun decrypt(data: ByteArray, masterKey: SecureBytes, folderKey: SecureBytes? = null): ByteArray {
        if (folderKey == null) return AesGcm.open(data, masterKey)
        val inner = try {
            AesGcm.open(data, folderKey)
        } catch (e: ObscuraCryptoException) {
            return AesGcm.open(data, masterKey)
        }
        return AesGcm.open(inner, masterKey)
    }

    /** Whether [data] carries a folder layer that [folderKey] opens. */
    fun hasFolderLayer(data: ByteArray, folderKey: SecureBytes): Boolean =
        try {
            AesGcm.open(data, folderKey)
            true
        } catch (e: ObscuraCryptoException) {
            false
        }
}
