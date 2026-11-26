# ObscuraCrypto for Kotlin

The same encryption as the Swift package, for the Android version of Obscura
Photo Vault: the vault header, folder passwords, single-shot and chunked media,
`.obscura` exports and Send Encrypted's `.obscurashared` files, in the byte
layouts of [FORMATS.md](../FORMATS.md). A vault written on an iPhone opens with
this library, and the reverse.

Plain JVM Kotlin with no Android dependency, so the tests run on a Mac or a
laptop. Everything cryptographic is the platform's JCA (`Cipher`, `Mac`,
`MessageDigest`, `SecureRandom`), and the export and shared-items manifests
are read by the library's own strict JSON reader, so it has no dependencies
beyond the Kotlin standard library.

```sh
cd kotlin
./gradlew check
```

`check` runs the whole suite twice: once with the JDK's own providers and once
with Conscrypt first, the BoringSSL-based provider Android ships. It needs JDK
21. Besides the library's own tests, it reads every file in
`../Tests/ObscuraCryptoTests/Fixtures`: the ones the iOS app wrote, and the sets
each language of this repository wrote for the other (see FORMATS.md).

## Recovery phrase

`RecoveryPhrase` writes a vault's master key as 24 words and reads them back,
in the same encoding as the Swift package (FORMATS.md), so words shown on an
iPhone open the vault on Android and the reverse. What the iOS app does with
it, for an Android port to match:

- **Showing the words:** `RecoveryPhrase.words(masterKey)` while the vault is
  open, after the password (or biometrics) is given again, except right after
  the vault is created.
- **Forgot password:** `RecoveryPhrase.masterKey(words)` first. Its three errors
  (wrong length, unknown word at a position, checksum mismatch) are typing
  mistakes: say which, and do not count them as a failed unlock. A phrase that
  passes them is a real 256-bit key: try `VaultHeader.opens(key)` on every
  slot's header, all of them before answering (do not stop at the first match,
  as with passwords), and count no match as one failed unlock.
- **Setting the new password:** `header.settingPassword(newPassword, key)`,
  then write the 145 new header bytes over the old ones the same crash-safe
  way a password change does. Nothing else in the vault changes, and the words
  stay valid afterwards.
- **Exports:** a `.obscura` export opens with the password it was made with,
  not the phrase.

## Send Encrypted files

`SharedItemsFile.write` seals files into an `.obscurashared` file and
`SharedItemsReader.open` reads one, from a `File` or from any `InputStream`
(what a received file opens as on Android). Format version 3 (FORMATS.md); the
layouts each app had before were never released and are refused.

For an app sending one: offer `SharedPassword.suggested()` (six words) first,
take a typed password of 6 characters or more, and when
`SharedPassword.problem` finds one easy to guess, say so without refusing it
(`write` takes any password). A file without a password is open to anyone who
has it, and can be changed by them: say so where it is made and where it is
opened.

For an app reading one:

- Read every part in the manifest's order, with `read` for what the app adds
  and `skip` for the rest (unknown kinds and roles included: they are still
  checked), then call `finish`, which refuses anything after the last part.
- A part is only good once `read` returns: its SHA-256 is checked at the end,
  so delete whatever was written from it when `read` throws.
- Errors to tell apart on screen: `WrongPassword`, `SharedItemsNewerVersion`
  (ask the person to update the app, never "damaged"), `SharedItemsDamaged`,
  `InvalidSharedItems` (not such a file at all) and `SharedItemsNotLocked`.
- Ask `SharedItemsPreamble.isOpen` first. Open a file sent without a password
  with `null`, after saying so; pass a password only for a sealed one. Given a
  password, a file without one is refused (`SharedItemsNotLocked`), so a
  sealed file swapped on the way for an open one never passes as the sender's.
- The sizes in the manifest are the sender's word: refuse items larger than
  the app can hold where it would hold them in memory, before reading them.

## Command line

`cli/` is the `obscura` tool of the Swift package for any computer with JDK 21:
the same commands (`vault`, `media`, `folder`, `export`, `shared`), the same output, and
files that open in either. See [VERIFYING.md](../VERIFYING.md).

```sh
./gradlew :cli:installDist
cli/build.nosync/install/obscura/bin/obscura vault inspect <file>
```

On a Mac with Swift, `cli/cross-check.sh` runs both tools on the same files and
fails if they disagree.

Licence: GPL-3.0-or-later, as the Swift package.

## What Kotlin cannot promise

`SecureBytes` zeroes its array when closed, but the JVM gives no guarantee that
the garbage collector has not moved the array first, and the JCA copies a key
into its own cipher state. Zeroing limits how long a key sits in memory; it does
not prove there is no other copy. The Swift package's `SecureBytes` keeps its
key in memory the program allocates itself, which no collector moves; in both
languages a cleared key refuses to be used, so nothing can be sealed under its
zeros.
