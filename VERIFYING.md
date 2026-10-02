# Verifying Obscura Photo Vault's encryption

This guide shows how to check, with your own phone and this repository, that Obscura Photo Vault stores your photos the way the [README](README.md) says it does. It needs no access to the app's source code and no cooperation from us.

It covers two things:

1. **The code.** That this package does what its documentation says, and reads files the app itself wrote.
2. **Your files.** That the vault and media files the App Store version of the app keeps on your iPhone are in exactly these formats: encrypted, openable only with your password, and unchanged by a password change.

What this cannot show is covered at the end.

## What you need

- A Mac with Xcode or the Swift toolchain (Swift 6, macOS 13 or later).
- An iPhone with Obscura Photo Vault installed and at least one vault with a few photos and a video in it.
- About 20 minutes, plus the time a phone backup takes.

## 1. Build the tool and run the tests

```sh
git clone <this repository>
cd ObscuraCrypto
swift test
swift build -c release
export PATH="$PWD/.build/release:$PATH"
```

`swift test` runs the whole suite. `AppCompatibilityTests` is the part that matters here: it decrypts a vault header and media files that the app's own code wrote (in `Tests/ObscuraCryptoTests/Fixtures`, with their passwords in `manifest.json`), and rewrites the app's header byte for byte. The rest checks the primitives against published test vectors and the formats against their documented layouts.

Read the code while you are at it. Everything that touches a key is in `Sources/ObscuraCrypto`, with no dependencies beyond Apple's CryptoKit, CommonCrypto and Security frameworks.

## 2. Get your vault files off the phone

iOS keeps each app's files in a private container. The way to read the app's files without our help is a local backup of the phone, which includes app data.

1. Connect the iPhone to the Mac and open it in Finder.
2. Choose **Back up all of the data on your iPhone to this Mac**. Leave **Encrypt local backup** off for this, so the backup's own files can be read directly. (The app's files are encrypted either way; the backup's encryption is a separate layer on top.)
3. Click **Back Up Now** and wait for it to finish.

An unencrypted backup holds everything else on the phone unencrypted on your Mac, so delete it when you are done (Finder, **Manage Backups**).

A local backup does not keep your files under their real names. Each file is stored under a scrambled name (a hash of where it lived on the phone), in folders named after the first two characters of that hash. To find anything, the backup includes `Manifest.db`: a small database that lists every file in the backup, from every app, with the app it belongs to and its original location. It is part of Apple's backup format, not of Obscura: Finder writes it into every iPhone backup, and Obscura never creates or reads it. The script below asks `Manifest.db` for the files belonging to Obscura (`AppDomain-Orlio.Obscura`) inside its `Documents/Vault` folder, and copies each one out under its real name. It only reads the backup; it changes nothing.

macOS only lets Terminal read the backup folder if Terminal has **Full Disk Access** (System Settings, Privacy & Security).

```sh
BACKUP=$(ls -td ~/Library/Application\ Support/MobileSync/Backup/*/ | head -1)
OUT=~/obscura-verify
mkdir -p "$OUT"

sqlite3 -separator '|' "$BACKUP/Manifest.db" \
  "SELECT fileID, relativePath FROM Files
   WHERE domain = 'AppDomain-Orlio.Obscura'
     AND relativePath LIKE 'Documents/Vault/%'
     AND flags = 1" |
while IFS='|' read -r id file; do
  mkdir -p "$OUT/$(dirname "$file")"
  cp "$BACKUP/${id:0:2}/$id" "$OUT/$file"
done

cd "$OUT/Documents/Vault"
ls data media
```

You should see a `data` folder of vault files named `<id>.db.enc` and a `media` folder of `<id>.data.enc` (photos and videos) and `<id>.thumb.enc` (thumbnails). The names are random, and nothing in them says which vault a file belongs to.

You may also see two more folders. `snapshots` is the app's on-device backup history: each snapshot is a dated copy of the vault files from `data`, kept so a vault can be rolled back. Its files have the same structure as those in `data`, and every check below applies to them too. `staging` is a short-lived working area used while a backup is being restored, and is normally empty. Neither holds anything unencrypted.

## 3. Check the vault files

**Every vault file has the same structure.** The app keeps at least 10 vault files whether you use them or not, and the unused ones are built exactly like real ones.

```sh
for f in data/*.db.enc; do echo "== $f"; obscura vault inspect "$f"; done
```

Each one should report version 3, cipher suite `0x01` (PBKDF2-HMAC-SHA256 + AES-256-GCM), 600000 KDF rounds, a valid checksum, and a different salt. Nothing in the output distinguishes the vault you use from the others.

The files are also padded to random sizes between 2 and 15 MB, so an empty vault and a full one are not told apart by size:

```sh
ls -l data/
```

**Only your password opens your vault.**

```sh
for f in data/*.db.enc; do echo "== $f"; obscura vault unlock "$f"; done
```

Type your vault password each time. It opens exactly one file, which prints a master key fingerprint and the size of the encrypted database inside it. Every other file answers `Wrong password`, the same answer whether it is an unused slot or another person's vault.

Note which file opened; the steps below call it `data/YOUR.db.enc`. To avoid retyping, you can give the password on standard input with `--password-stdin`, but it will then be in your shell history unless you take care.

## 4. Check the media files

**Nothing readable is stored.** A JPEG starts with the bytes `ff d8 ff` and a video has `ftyp` near its start. The app's files should show neither: the first 12 bytes are a random nonce, or the `OBCM` header of a chunked video.

```sh
for f in media/*.data.enc; do xxd -l 16 "$f"; done | head -20
```

Encrypted data does not compress. Compare each file's size with its size gzipped; they should be almost the same:

```sh
for f in media/*.data.enc; do
  printf '%10d %10d  %s\n' "$(wc -c < "$f")" "$(gzip -c "$f" | wc -c)" "$f"
done | head -20
```

**The formats are the documented ones.**

```sh
for f in media/*.data.enc; do echo "== $f"; obscura media inspect "$f"; done
```

Photos and short videos are single-shot: one AES-GCM message. Larger videos are chunked, and `inspect` checks that the file's length is exactly what its header describes.

**Your password decrypts them.**

```sh
obscura media decrypt media/<id>.data.enc ~/Desktop/check --vault data/YOUR.db.enc
file ~/Desktop/check
open ~/Desktop/check
```

`file` should report a JPEG, HEIC, PNG or QuickTime movie, and it opens as one of your photos or videos. Thumbnails decrypt the same way. A single-shot file decrypts to exactly 28 bytes fewer than its encrypted size: a 12-byte nonce and a 16-byte tag.

A file in a password-protected folder will not decrypt with the vault password alone. That failure is what the second layer looks like from outside: it is sealed again with the folder's own key, which lives in the vault's encrypted database.

**Get everything out as ordinary files.**

```sh
obscura vault extract data/YOUR.db.enc ~/Desktop/my-photos
```

Every photo and video in your vault outside protected folders, decrypted and named by type. The tool finds your files by trying your vault's key on every file in `media/`, so files belonging to other vaults stay untouched. The same works from an export file, without a phone backup:

```sh
obscura export extract ~/Downloads/backup.obscura ~/Desktop/from-export
```

## 5. Check that a password change re-encrypts nothing

This is the key hierarchy's central claim: your password protects a random master key, the master key protects your data, so changing the password rewraps 32 bytes and touches nothing else.

1. Record a fingerprint of every media file, and of the vault's master key:

   ```sh
   shasum -a 256 media/* > ~/before.txt
   obscura vault unlock data/YOUR.db.enc
   ```

2. In the app, change the vault password (Settings, Security, Change Password).
3. Make a new backup and copy the files out again as in step 2.
4. Compare:

   ```sh
   shasum -a 256 media/* | diff ~/before.txt - && echo "media unchanged"
   obscura vault unlock data/YOUR.db.enc        # now with the new password
   obscura vault inspect data/YOUR.db.enc
   ```

Every media file is byte-for-byte identical. The new password unlocks the same master key fingerprint as before, and `inspect` shows a new salt. The old password now answers `Wrong password`.

## 6. Check that tampering is detected

Every file is authenticated, so a single changed byte stops it decrypting rather than producing altered output:

```sh
cp media/<id>.data.enc /tmp/tampered
printf '\x01' | dd of=/tmp/tampered bs=1 seek=100 count=1 conv=notrunc
obscura media decrypt /tmp/tampered /tmp/out --vault data/YOUR.db.enc
```

This fails with an authentication error and writes no output. For a chunked video, moving a chunk to a different position is caught as well, because each chunk must carry the nonce its position requires; `MediaTests.testSwappedChunksAreRejected` shows how to construct that case.

## When you are done

The steps above leave copies behind. Delete them:

```sh
rm -rf ~/obscura-verify                                  # the vault files copied from the backup
rm -rf ~/Desktop/check ~/Desktop/my-photos ~/Desktop/from-export   # your decrypted photos
```

Then delete the phone backup in Finder (**Manage Backups**), since it holds everything else on the phone unencrypted.

## What this does not show

- **That the app on your phone was built from this code.** iOS has no reproducible builds, and the App Store re-signs and encrypts every app, so nobody outside Apple can prove which source a given binary came from. What the steps above do show is that the app's files match this code's formats exactly, which they could not do by accident.
- **What the app does while it runs.** That it clears keys from memory when it locks, keeps decrypted media out of temporary files, and never sends your photos or data anywhere. You can check the last of these yourself with a network monitor: the only traffic you should see is Apple's own, such as App Store purchase checks. The others are described in the [security paper](https://obscura-vault.com/security).
- **The vault database.** Folder and photo records live in a SQLCipher database inside each vault file, encrypted with the master key. This package reads the header in front of it and not the database itself.
- **How the 10 vault slots are managed.** How unused slots get their keys, and how the app checks your password against every slot in the same time. The steps above show the result, files that cannot be told apart, but not that code.

If you find something that does not match what is documented here, please report it as described in [SECURITY.md](SECURITY.md).
