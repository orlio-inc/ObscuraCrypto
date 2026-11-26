# ObscuraCrypto

The encryption at the heart of [Obscura Photo Vault](https://obscura-vault.com), a private photo vault for iPhone, iPad and Android.

It implements the same encryption, with the same file formats, that the app uses to protect your photos. It is published so you do not have to take the app's word for it: you can read it, run its tests, and check files from your own phone against it.

## What it is for

The app keeps your photos, videos and documents in encrypted vaults, each opened by its own password. This package covers how the app:

- turns your password into keys,
- writes the vault's master key out as the 24-word recovery key, and turns the words back into the key,
- encrypts and decrypts every photo, video and thumbnail,
- adds the second lock for password-protected folders,
- writes and reads `.obscura` backup files,
- seals and opens the `.obscurashared` files that Send Encrypted uses to send photos, videos and documents to another person.

Obscura Photo Vault for iPhone uses this package for all of the above from version 1.24.0, and for its keys, photos, videos and folders from version 1.14.0. The tests below open files the app itself wrote. Everything else stays inside the app and is not part of this package: the screens, the database of folders and photo details, how the app manages its vault slots, Face ID, and the app's behaviour while it runs. The [security paper](https://obscura-vault.com/security) describes those parts.

The same encryption is also written in Kotlin, in the `kotlin/` folder, for the Android app. It follows the same written description of the formats ([FORMATS.md](FORMATS.md)), and both versions are tested against the same files: the ones the iPhone app wrote, and sets each version wrote for the other, including damaged ones that both must refuse. A vault exported on an iPhone opens with the Kotlin library, and the reverse. Obscura Photo Vault for Android, on [Google Play](https://play.google.com/store/apps/details?id=io.orlio.obscura), is built on it.

There is also a small command-line tool, `obscura`, that works with the same files: you can create a test vault, encrypt and decrypt files, get your photos back out of a backup, and make, check and open Send Encrypted files.

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

### Send Encrypted files

```sh
obscura shared verify photos.obscurashared               # check every item, write nothing
obscura shared decrypt photos.obscurashared received/    # the photos, videos and documents inside
obscura shared encrypt for-sam.obscurashared IMG_0001.HEIC IMG_0001.MOV lease.pdf --live-photos --generate-password
```

A file made with `shared encrypt` opens in the app on an iPhone or an Android phone, as one sent from the app does. `--generate-password` makes a password of six random words and shows it; a password you type needs at least 6 characters, and gets a note if it is easy to guess. `--open` makes a file without a password, which anyone who has it can open, and change.

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

Everything this package encrypts uses AES-256 in GCM mode: through Apple's CryptoKit on iPhone, and the Java platform's AES-GCM on Android.

**Why:** AES-256 is the most widely used and studied cipher there is, and phones have hardware for it, so it is fast. GCM adds a tamper seal to every piece of encrypted data: if a single byte is changed, decryption fails instead of quietly producing something altered. No other cipher and no unsealed mode is used anywhere in this package.

The one exception is outside this package: the app's database of folders and photo details is encrypted by SQLCipher, keyed with the vault's master key, which seals each page with AES-256 in CBC mode and a tamper seal of its own (HMAC-SHA512).

### Password to key: PBKDF2, 600,000 rounds

**Why:** turning a password into a key is deliberately slow, so that anyone trying to guess your password pays the same cost for every guess. 600,000 rounds of PBKDF2-HMAC-SHA256 is the current [OWASP recommendation](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) and takes up to about a second on an iPhone. On iPhone it is Apple's own CommonCrypto; on Android, the Java platform's, or the app's own native build of the same function, checked against published values before it is used.

Folder passwords set from ObscuraCrypto 1.2.0 (Kotlin 1.3.0) on use the same 600,000 rounds. The app uses these versions from Obscura 1.24.0 on iPhone and from the first Android release after 1.4.0. Those set before used 100,000, fewer than OWASP's figure, and keep them until the folder's password is set again: someone who already has the vault open can copy such a folder's lock and try passwords on a computer about six times faster. Either way, give a protected folder a long password: a short one falls quickly at any number of rounds.

### Large videos are encrypted in pieces

Large videos are sealed in fixed-size pieces rather than as one block. Each piece's position is built into how it is encrypted, so pieces cannot be reordered or swapped between files without the change being detected. From ObscuraCrypto 1.2.0 (Kotlin 1.3.0) each video is also sealed under keys of its own, derived from the vault's key and a random value stored with the video, so no two videos ever share a key.

### Protected folders get a second lock

A folder with its own password gets its own random key. Its photos are encrypted with the vault's master key and then again with the folder key, so someone who knows the vault password cannot open them without the folder password. They can still try folder passwords on a computer (see above), so a short folder password protects less than it seems.

### Sending items to someone

Send Encrypted puts the chosen photos, videos and documents in one `.obscurashared` file, sealed under a random key made for that file alone. The key is locked with a password the other person learns some other way, using the same 600,000 rounds as a vault. The file holds no vault and no vault key: it opens those items and nothing else.

**The password is the whole lock**, and the file travels through mail, chats and cloud drives where a copy can be kept and guessed at for as long as anyone likes. So the app suggests six random words first (about 66 bits, out of reach of guessing). You can type your own instead, of 6 characters or more; if it is short, a simple run or a well-known password with a few digits added, the app says it is easy to guess, and the choice stays yours. The same checks are in this package, in Swift and Kotlin, so every app built on it can give the same advice.

**Tampering**: every piece of a password-sealed file, its header included, carries a tamper seal, and each item's fingerprint is checked as it is read, so a change, a reordering or a cut is found. Items are handed over only once their own records have checked; anything after the damage is refused.

**What the file gives away**: only that it is such a file, how it is locked, and roughly how large it is. The items run on from one to the next inside records of equal size, and the end is padded, so the file does not show how many photos it holds or how large any one is. A file holding a single item does show that item's size roughly: to within about an eighth for a large item, and less closely for a small one.

**One file, one meaning**: the list of items inside is read by this package's own strict JSON reader, the same rules in Swift and Kotlin, rather than by each platform's library, which would disagree on odd input. A file that could be read two ways is refused on both. The file also commits to its key, so no lock can be made that opens it to different contents under different passwords.

You can also send a file without a password. The key then travels in the file: it keeps the photos out of photo libraries and previews on the way, but anyone who gets hold of the file can open it, and could change it without that showing. What protects such a file is sending it straight to the person, and the app says so on both ends. A file without a password never passes for one with: given a password, the app and this package refuse a file that has none, so it cannot be swapped on the way for one someone else made.

### Exported backup files

An `.obscura` file, made with Export Vault, is the vault and its media, encrypted again as a whole with a password (the app uses your vault password). The tool checks the password, checks every piece of the file for tampering, and recovers the photos and videos. It reads only what it needs from the app's backup manifest and ignores the rest.

Without the password, a backup file made by this version shows its header and its length, which says only roughly how much it holds: the files inside, how many there are and their sizes are sealed with them. Backup files made before it (version 1, which every reader still opens) also showed how many files they held and the size of each, as every stored file started on a record of its own. Neither shows anything of what the files are.

## Limits, and what they mean for you

**Your password is the whole lock.** If someone copies your vault, for example from a phone backup, they can try passwords on a computer as fast as it will go, with no limit on attempts. The 600,000 rounds make each guess expensive, but a short or common password still falls quickly. A password of six random words, the kind the app suggests for Send Encrypted files, or of 14 or more random letters and digits, has too many possibilities to be guessed with any hardware available today.

Use a long passphrase. We cannot reset a password, and neither can anyone else. The only way back in without it is the vault's recovery key, 24 words the app can show while the vault is open; keep them as safely as the password, as they open the vault too. The 24 words are the vault's master key written out, so changing the password does not change them: anyone who has seen them can still open the vault. Only making the vault a new master key, which seals every file again, retires them.

**A password change does not reach copies made before it.** Changing a vault password locks the same master key with the new password; nothing else is encrypted again. A copy of the vault made before the change, in a phone backup or an exported backup file, still opens with the old password, and that old password then unlocks the master key, which also opens photos added since. If you change a password because someone else learned it, keep in mind any copy they could have.

**PBKDF2 is not the strongest option available.** Newer methods such as Argon2 make guessing on graphics cards much more expensive, by also requiring lots of memory. PBKDF2 was chosen because it is built into Apple's platforms and meets current guidance. The file format has room for a stronger method later, without breaking existing vaults.

**Videos saved by older apps carry a small, known risk.** Before Obscura 1.24.0 on iPhone (on Android, before the first release after 1.4.0), each video got a random 4-byte tag that kept it apart from every other video under the same key. Two videos sharing a tag is very unlikely in a normal library: about 1 in 35,000 with 500 videos, rising to about 1 in 90 with 10,000. If it happened, someone holding both files could learn how the matching parts of those two videos differ from each other, and could alter other files of that vault they also hold a copy of (photos, thumbnails, older videos) without the app noticing. They could not open the vault or read anything else. Videos saved since have keys of their own and cannot share anything this way. The tags are stored in the clear, so the app finds any two older videos that share one and seals one of them again the new way, which protects against anyone who copies the files afterwards; making a vault a new key seals every file again and also covers copies taken before.

**Older videos can be cut short unnoticed.** For videos saved by those app versions on, every part of the file, its length included, is checked: a video cut short is refused once playing reaches the cut. For videos saved before, the header that says how long the file is, and how it is divided, is not checked, so someone who can change files on your phone could cut such a video short and the app would show it shorter. Anyone who can change files on your phone can also swap two of your files around, and the app would not necessarily notice. Apart from the collision above, they cannot read anything or put content of their own inside a file.

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
- **Send Encrypted files**: round trips with and without a password, the password rules, that sizes and counts do not show, every way of altering a file, manifests that JSON libraries read differently, files from later versions of the format, and a second reader and writer written from [FORMATS.md](FORMATS.md) alone.
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

Send Encrypted's `.obscurashared` files are in `SharedItems.swift`. The exact file layouts are in those source files and in [FORMATS.md](FORMATS.md).

## Security issues

Please report problems privately, as described in [SECURITY.md](SECURITY.md).

## Contributing

This repository does not accept pull requests. Its purpose is to let you check the app's encryption, so the code here has to stay the code the app ships. Security reports and questions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
