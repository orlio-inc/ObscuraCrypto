# ObscuraCrypto

The encryption at the heart of [Obscura Photo Vault](https://obscura-vault.com), a private photo vault for iPhone and iPad.

It implements the same encryption, with the same file formats, that the app uses to protect your photos. It is published so you do not have to take the app's word for it: you can read it, run its tests, and check files from your own phone against it.

## What it is for

The app keeps your photos and videos in encrypted vaults, each opened by its own password. This package covers how the app:

- turns your password into keys,
- encrypts and decrypts every photo, video and thumbnail,
- adds the second lock for password-protected folders,
- reads `.obscura` backup files.

Obscura Photo Vault uses this package for all of the above from version 1.14.0, and the tests below open files the app itself wrote. Everything else stays inside the app and is not part of this package: the screens, the database of folders and photo details, how the app manages its vault slots, Face ID, and the app's behaviour while it runs. The [security paper](https://obscura-vault.com/security) describes those parts.

There is also a small command-line tool, `obscura`, that works with the same files: you can create a test vault, encrypt and decrypt files, and get your photos back out of a backup.

## Getting started

You need a Mac with Xcode, or the Swift toolchain, version 6 or later.

```sh
git clone <this repository>
cd ObscuraCrypto
swift test                         # run the test suite
swift build -c release             # build the command-line tool
cp .build/release/obscura /usr/local/bin/
```

The package has no third-party dependencies. Everything that touches a key is either in this repository or in Apple's own frameworks (CryptoKit, CommonCrypto, Security).

### Try it in a minute

```sh
obscura vault create demo.vault                     # asks for a password
obscura media encrypt photo.jpg photo.enc --vault demo.vault
obscura media inspect photo.enc                     # no password needed
obscura media decrypt photo.enc copy.jpg --vault demo.vault
obscura vault passwd demo.vault                     # change the password
obscura media decrypt photo.enc again.jpg --vault demo.vault
```

The last step works with the new password even though `photo.enc` was never touched. That is the key design in action, explained below.

### Get your photos out

```sh
obscura export extract backup.obscura my-photos/          # from an Obscura backup file
obscura vault extract Vault/data/<id>.db.enc my-photos/   # from a vault copied off your phone
```

Both write ordinary photo and video files, named by what they contain (`.jpg`, `.heic`, `.mov` and so on). They never write the app's database or its backup manifest. Photos in a password-protected folder are not extracted, because their second key lives inside the app's database.

To check your own phone's files against this code step by step, see [VERIFYING.md](VERIFYING.md).

The tool never takes a password on the command line, where it would end up in your shell history. It asks for it with typing hidden, or reads it from standard input with `--password-stdin` for scripts. It never prints a key.

## How it works

### Your password never encrypts your photos directly

```
your password
   │  slowed down: PBKDF2-HMAC-SHA256, 600,000 rounds, random salt
   ▼
password key  (never stored)
   │  unlocks
   ▼
master key    (32 random bytes, made once per vault, stored only locked)
   │  encrypts
   ▼
your photos, videos, thumbnails and database
```

Each vault has a random **master key**. Your password only unlocks it.

**Why:** changing your password just locks the same master key with the new password, so it takes about a second no matter how many gigabytes the vault holds. And the key that protects your photos is always fully random, however short your password is.

### Encryption: AES-256-GCM

Everything is encrypted with AES-256 in GCM mode, through Apple's CryptoKit.

**Why:** AES-256 is the most widely used and studied cipher there is, and Apple devices have hardware for it, so it is fast. GCM adds a tamper seal to every piece of encrypted data: if a single byte is changed, decryption fails instead of quietly producing something altered. No other cipher and no unsealed mode is used anywhere.

### Password to key: PBKDF2, 600,000 rounds

**Why:** turning a password into a key is deliberately slow, so that anyone trying to guess your password pays the same cost for every guess. 600,000 rounds of PBKDF2-HMAC-SHA256 is the current [OWASP recommendation](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) and takes about a second on an iPhone. It is built into Apple's own CommonCrypto, so no outside code is involved. Folder passwords use 100,000 rounds, because a folder only ever sits behind an unlocked vault.

### Large videos are encrypted in pieces

Large videos are sealed in fixed-size pieces rather than as one block. Each piece's position is built into how it is encrypted, so pieces cannot be reordered or swapped between files without the change being detected.

### Protected folders get a second lock

A folder with its own password gets its own random key. Its photos are encrypted with the vault's master key and then again with the folder key, so someone who knows the vault password still cannot open them.

### Backups

An `.obscura` backup file is the vault and its media, encrypted again as a whole with a password (the app uses your vault password). The tool checks the password, checks every piece of the file for tampering, and recovers the photos and videos. It reads only what it needs from the app's backup manifest and ignores the rest.

## Limits, and what they mean for you

**Your password is the whole lock.** If someone copies your vault, for example from a phone backup, they can try passwords on a computer as fast as it will go, with no limit on attempts. The 600,000 rounds make each guess expensive, but not impossible. As a rough guide for a determined attacker with one high-end graphics card:

| Your password | Rough time to guess |
|---|---|
| A common word or pattern | minutes |
| 6 random lowercase letters | hours to days |
| 8 random letters and digits | years |
| 4 random words, or 12+ random characters | out of reach |

Use a long passphrase. There is no password recovery: we cannot reset it, and neither can anyone else.

**PBKDF2 is not the strongest option available.** Newer methods such as Argon2 make guessing on graphics cards much more expensive, by also requiring lots of memory. PBKDF2 was chosen because it is built into Apple's platforms and meets current guidance. The file format has room for a stronger method later, without breaking existing vaults.

**Very large video libraries carry a small, known risk.** Each video gets a random 4-byte tag that keeps it apart from every other video under the same key. Two videos sharing a tag is very unlikely in a normal library: about 1 in 35,000 with 500 videos, rising to about 1 in 90 with 10,000. If it happened, someone with both files could learn something about those two videos, but could not open the vault or any other file. A future version of the format will remove this.

**File headers are not sealed.** Someone who can change files on your phone could cut a video short or swap two of your files around. They could not read anything, or slip in content of their own.

**Type accented passwords the same way.** A password is used exactly as typed, so the same accented letter entered differently on two keyboards would count as a different password.

**This code cannot prove what is on your phone.** Apple re-signs and encrypts every App Store app, so nobody can prove that the copy on your phone was built from this source. What you can prove is that your phone's files match this code's formats exactly, which they could not do by accident. [VERIFYING.md](VERIFYING.md) shows how.

## Tests

```sh
swift test
```

The suite checks:

- **Building blocks**: key derivation against published test values, encryption round trips, fresh randomness for every seal, and that a changed byte or a wrong key is always refused.
- **Vaults**: create, unlock, wrong password, a password change that keeps the same master key, and refusing a tampered file that asks for fewer rounds.
- **Media**: photos and videos of awkward sizes, folder locks on and off, and detection of reordered, cut-short or altered files.
- **Files from the app's own code**: `Tests/ObscuraCryptoTests/Fixtures` holds a vault, photos, videos and a backup file, encrypted by the app's own code, with the passwords needed to open them. The tests open every one, which shows this package reads what the app writes. Two parts are stand-ins, because they belong to the app rather than to this package: the database inside the vault file is random bytes of the same length, and the backup's manifest holds only the few fields this package reads. Everything this package decrypts is real.
- **Damaged and hostile files**: corrupt or deliberately crafted files are refused with an error, never a crash.

## How this matches the security paper

This package implements these parts of the [security paper](https://obscura-vault.com/security):

| Paper section | Where it is here |
|---|---|
| §2.1 Symmetric encryption | `Primitives.swift` (`AESGCM`) |
| §2.2 Key derivation | `Primitives.swift` (`KeyDerivation`) |
| §2.3 Salts and nonces | `Primitives.swift`, `ChunkedMedia.swift` |
| §2.4 Secure memory | `SecureBytes.swift` |
| §3 Key hierarchy | `VaultHeader.swift` |
| §4.3 Vault file format | `VaultHeader.swift` |
| §6.2 Chunked media | `ChunkedMedia.swift` |
| §7 Folder protection | `FolderProtection.swift`, `SingleShotMedia.swift` |
| §8 Export format | `ExportArchive.swift` |

The exact file layouts are in those source files.

## Security issues

Please report problems privately, as described in [SECURITY.md](SECURITY.md).

## Contributing

This repository does not accept pull requests. Its purpose is to let you check the app's encryption, so the code here has to stay the code the app ships. Security reports and questions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
