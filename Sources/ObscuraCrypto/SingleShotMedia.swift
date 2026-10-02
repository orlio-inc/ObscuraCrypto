// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import Foundation

/// How a media file is laid out.
public enum MediaFormat: Sendable, Equatable {
    /// One AES-GCM sealed message: photos, thumbnails, camera videos.
    case singleShot
    /// The chunked format: large videos, decryptable a piece at a time.
    case chunked

    /// Tells the two apart from a file's first bytes.
    ///
    /// A chunked file starts with "OBCM"; a single-shot file starts with its
    /// random nonce. A single-shot nonce that happened to begin with those four
    /// bytes, a 1 in 2^32 chance, would be misread; the app decides the same
    /// way, so the two always agree.
    public static func detect(_ prefix: Data) -> MediaFormat {
        prefix.prefix(4) == ChunkedMediaHeader.magic ? .chunked : .singleShot
    }
}

/// Media encrypted in one piece: `nonce || ciphertext || tag`, sealed with the
/// vault's master key, and sealed again with the folder key if the media is
/// in a protected folder.
///
/// Every file gets a fresh random nonce. Thumbnails use this format too.
public enum SingleShotMedia {
    public static func encrypt(_ plaintext: Data, masterKey: SecureBytes, folderKey: SecureBytes? = nil) throws -> Data {
        let inner = try AESGCM.seal(plaintext, key: masterKey)
        guard let folderKey else { return inner }
        return try AESGCM.seal(inner, key: folderKey)
    }

    /// Decrypts, removing the folder layer first when a folder key is given.
    ///
    /// With a folder key, a file that turns out not to carry the folder layer
    /// is still opened with the master key alone. The app reads files this
    /// way because setting a folder password rewraps a large folder one file
    /// at a time, and an interrupted run leaves some files without the layer.
    /// It is not a bypass: AES-GCM is authenticated, so a file only ever
    /// reaches that path if the folder key genuinely cannot open it, and it
    /// still has to pass the master key.
    public static func decrypt(_ data: Data, masterKey: SecureBytes, folderKey: SecureBytes? = nil) throws -> Data {
        guard let folderKey else {
            return try AESGCM.open(data, key: masterKey)
        }
        if let inner = try? AESGCM.open(data, key: folderKey) {
            return try AESGCM.open(inner, key: masterKey)
        }
        return try AESGCM.open(data, key: masterKey)
    }

    /// Whether `data` carries a folder layer that `folderKey` opens.
    public static func hasFolderLayer(_ data: Data, folderKey: SecureBytes) -> Bool {
        (try? AESGCM.open(data, key: folderKey)) != nil
    }
}
