# Obscura file formats

The byte layouts that `ObscuraCrypto` reads and writes, written down once so the
Swift package (`Sources/`) and the Kotlin library (`kotlin/`) can be held to the
same text. Where the two disagree with this file, the code is wrong; where this
file disagrees with files the Obscura app has written, this file is wrong. The
shared fixtures in `Tests/ObscuraCryptoTests/Fixtures` are what keeps all three
honest.

All multi-byte numbers are **big-endian** unless a field says otherwise. There
is one exception, marked below, and it is deliberate.

## Primitives

| What | Definition |
|---|---|
| Password to key | PBKDF2-HMAC-SHA256, 32-byte output. The password is its **UTF-8 bytes, with no Unicode normalisation**: `"café"` and `"café"` are different passwords. |
| Rounds | Vault and export: 600,000. Folder: 100,000. A reader refuses a header with fewer. |
| Salt | 32 random bytes, never reused. |
| Sealing | AES-256-GCM, 12-byte nonce, 16-byte tag, no associated data. Stored **combined**: `nonce (12) \|\| ciphertext \|\| tag (16)`. 28 bytes of overhead. |
| Nonces | Random for one-off messages. Derived for chunked media and exports, below. |
| Key wrapping | A 32-byte key sealed as above: 60 bytes. |
| Fingerprint | First 8 bytes of SHA-256 over a key, as hex. For comparing keys between tools; not a secret. |

## Vault file header: 145 bytes

The start of every `.db.enc` vault file. A SQLCipher database, encrypted with the
master key, follows it, then random padding (files are padded to a random size
between 2 and 15 MB). The database and its schema belong to the app, not to this
package.

```
offset  size  field
     0     1  version, 0x03
     1     7  magic, "OBSCURA"
     8     1  cipher suite, 0x01 (PBKDF2-HMAC-SHA256 + AES-256-GCM)
     9     4  key derivation rounds, UInt32
    13    32  salt for the password
    45    60  master key, wrapped with the password key
   105    36  database length, sealed with the master key
   141     4  CRC-32 (IEEE, as zlib) of bytes 0..<141
```

- Password key = PBKDF2(password, salt, rounds). Master key = the unwrapped 32
  bytes. A wrong password and a damaged wrapped key are indistinguishable and
  both read as "wrong password".
- **Database length: the plaintext is 8 bytes, little-endian.** The only
  little-endian number in any format here. The app has always written it in the
  device's native byte order, which on every Apple device is little-endian.
- A reader checks in this order: length at least 145, version, magic, CRC,
  cipher suite. It refuses rounds below 600,000 and above 10,000,000 before
  deriving anything.
- Changing the password rewraps the master key under a fresh salt and leaves
  everything else untouched.

## Recovery phrase: the master key as 24 words

Not a file format: a way to write a vault's 32-byte master key on paper.

- Bits = master key (32 bytes) followed by the first byte of its SHA-256:
  264 bits. Read 11 bits at a time, most significant first, giving 24 numbers
  from 0 to 2047. Each is a position in the BIP-39 English word list
  (`bip-0039/english.txt` in github.com/bitcoin/bips, SHA-256
  `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`).
- This is exactly BIP-39's encoding of 256 bits of entropy, so its published
  test vectors apply. BIP-39's seed derivation (PBKDF2 over the words) is not
  used: the words decode straight back to the master key.
- Words compare after trimming and lowercasing. A word off the list, or a
  phrase whose last 8 bits are not the key's checksum, is refused before any
  vault is tried.
- Finding the vault: a phrase's key opens a vault header's database length
  field, sealed with the master key, and no other header's.
- The phrase is the key, so it outlives every password change and cannot be
  revoked short of re-encrypting the vault under a new master key.

## Folder protection

A protected folder has a random 32-byte folder key. Three values are stored in
the vault's database, base64-encoded:

| Value | Size | Meaning |
|---|---|---|
| salt | 32 | for the folder password |
| password hash | 32 | SHA-256 of the 32-byte password key, checked first so a wrong password reads as one |
| wrapped folder key | 60 | the folder key sealed with the password key |

The password key is PBKDF2(password, salt, 100,000). The hash is compared in
constant time.

## Single-shot media

`nonce (12) || ciphertext || tag (16)`, sealed with the master key. In a
protected folder that whole message is sealed again with the folder key (+28
more bytes). Photos, thumbnails and short videos use it.

A reader holding a folder key that finds a file the folder key does not open
opens it with the master key alone, because setting a folder password rewraps a
large folder one file at a time and an interrupted run leaves some files
without the layer. The master key still has to open it.

## Chunked media

Large videos. The first four bytes, `OBCM`, tell the two media formats apart (a
single-shot file starts with its random nonce; a clash is 1 in 2^32, and every
implementation decides the same way).

```
offset  size  field
     0     4  magic, "OBCM"
     4     1  version, 0x01
     5     4  nonce prefix, random per file
     9     8  total plaintext length, UInt64
    17     4  plaintext bytes per chunk, UInt32 (1,048,576 by default)
    21     4  flags, UInt32; bit 0 set means a folder layer
```

Chunks follow the header at fixed offsets. With `layers` = 1, or 2 for a
folder layer, each chunk carries `28 * layers` bytes of overhead:

```
chunkCount   = ceil(total / chunkSize)
offset(i)    = 25 + i * (chunkSize + 28 * layers)
size(i)      = plaintext(i) + 28 * layers        (the last chunk may be shorter)
file length  = 25 + total + chunkCount * 28 * layers      (25 when empty)
```

- **Master layer** of chunk `i`: combined AES-GCM under the master key, nonce
  `noncePrefix || i` (i as 8 big-endian bytes).
- **Folder layer**, when flagged: the master-sealed chunk sealed again under the
  folder key with nonce `noncePrefix || (chunkCount + i)`. The numbering
  continues past the last chunk so the two layers never share a nonce.
- To open chunk `i`, remove the folder layer first, then the master layer. A
  reader checks that **each layer's stored nonce equals the one its position
  requires**, as well as the tag: the tag only proves a chunk is intact, and the
  nonce travels inside it, so without the check chunks could be moved within a
  file or copied in from another under the same key.
- A reader checks the file's length against the header **before** using any key,
  and refuses a header whose implied length does not fit in a signed 64-bit
  number.
- Chunk sizes above 2^31 - 57 cannot be read by the Kotlin library (a chunk must
  fit in one array). No file the app has written comes near it.

## Export files (`.obscura`)

A 64-byte header, then records.

```
offset  size  field
     0     4  magic, "OBSV"
     4     2  version, UInt16, 1
     6     2  flags, reserved, 0
     8    32  salt for the export password
    40     4  rounds, UInt32 (600,000)
    44    16  password check
    60     4  nonce prefix, random per file
```

- Export key = PBKDF2(password, salt, rounds).
- **Password check** = the 16-byte GCM tag from sealing `OBSCURA_EXPORT_V1`
  (ASCII, 17 bytes) with the export key and nonce `noncePrefix || 0xFFFFFFFFFFFFFFFF`.
  Compared in constant time before anything is decrypted.
- **Record** = a 4-byte length `n`, then `n` bytes of combined AES-GCM under the
  export key, nonce `noncePrefix || i`, records numbered from 0. A reader
  checks the nonce. `n` is greater than 28 and at most 1,048,576 + 28 (the
  manifest, record 0, may be up to 256 MB).

The decrypted records, in order, are one stream:

1. **Record 0, alone: the manifest**, JSON (below).
2. **The vault file** (header, database, padding), `databaseSize` bytes, in
   records of up to 1 MiB.
3. **For each media file in the manifest's order**: its `.data.enc` bytes, then
   its `.thumb.enc` bytes, exactly as the vault stores them (still sealed under
   the vault's master key), each file starting a new record and never sharing
   one with the next. A size of 0 writes no records.

After the last file there are no more records; a reader treats leftover records
as an error.

### Manifest

JSON written by Swift's `JSONEncoder`. This package reads only the keys it needs
to split the stream and find the master key; the app reads the rest (folders,
photos, tags and so on) and ignores what it does not know.

| Key | Type | Meaning |
|---|---|---|
| `exportVersion` | integer | 1 |
| `vaultSalt` | base64 (standard alphabet, padded) | the vault header's salt |
| `encryptedMEK` | base64 | the vault header's 60-byte wrapped master key |
| `databaseSize` | integer | length of the vault file in the stream |
| `mediaFiles[]` | array | `{ "mediaId": UUID string, "dataSize": integer, "thumbSize": integer }` |

- A media ID must be a UUID in the canonical 8-4-4-4-12 form and unique: it
  becomes a file name. Sizes are not negative.
- Dates elsewhere in the manifest (`exportDate`, photo dates) are numbers of
  **seconds since 2001-01-01 00:00 UTC**, Swift's default `Date` encoding. Not
  Unix time. Binary fields are standard base64. The app's own parts of the
  manifest are specified by the app, not here.
- The unwrapped master key must be the exporting vault's own. The app exports
  with the vault's password, so the export password and the vault password are
  normally the same, but a reader derives the master key from the **vault**
  salt and `encryptedMEK` with the password it is given.

## Reading files safely

Every reader here refuses, rather than guesses: a header that is too short, a
wrong magic or version, a checksum that does not match, a length that does not
fit, a record whose nonce is wrong, a file whose length does not match its
header, and a tag that does not verify. Output goes to a temporary file that is
moved into place only when every chunk has verified, so a failure leaves no
partial plaintext and never touches an existing file.

## Keeping the implementations the same

- `Tests/ObscuraCryptoTests/Fixtures/*` (top level): files written by the iOS
  app's own code. Both languages open them.
- `Fixtures/FromSwift` and `Fixtures/FromKotlin`: a set written by each
  language, each with a `compat.json` listing what every file is and whether it
  must open or be refused, and with which error. Both languages read both
  sets. Tampered files (a flipped byte, two swapped chunks, a truncated file, a
  header asking for too few rounds, a hostile length) must be refused by both
  with the same error name.
- Rewriting a set: `OBSCURA_WRITE_SWIFT_FIXTURES=<dir> swift test --filter
  CompatFixtureTests/testWriteSwiftFixtures`, and
  `OBSCURA_WRITE_KOTLIN_FIXTURES=1 ./gradlew test-jdk --tests '*writeKotlinFixtures*'`
  in `kotlin/`. Do it deliberately and commit the result: the committed files
  are what a format change has to keep opening.
