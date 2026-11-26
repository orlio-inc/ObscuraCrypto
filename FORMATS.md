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
| Rounds | Vault, export, shared items and new folder passwords: 600,000. Folder passwords set before ObscuraCrypto 1.2.0 (Swift) and 1.3.0 (Kotlin): 100,000, still read. A reader refuses a vault, export or shared items header with fewer. |
| Salt | 32 random bytes, never reused. |
| Sealing | AES-256-GCM, 12-byte nonce, 16-byte tag, no associated data (except in shared items files, below). Stored **combined**: `nonce (12) \|\| ciphertext \|\| tag (16)`. 28 bytes of overhead. |
| Nonces | Random for one-off messages. Derived for chunked media, exports and shared items, below. |
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
- Both languages implement it (`RecoveryPhrase` in each, with
  `VaultHeader.opens` and `VaultHeader.settingPassword`), and both check the
  phrase of the app's own `Fixtures/vault.header` against the same 24 words,
  which were also worked out independently with Python's hashlib.

## Folder protection

A protected folder has a random 32-byte folder key. Three values are stored in
the vault's database, base64-encoded:

| Value | Size | Meaning |
|---|---|---|
| salt | 32 | for the folder password |
| password hash | 32 | SHA-256 of the 32-byte password key, checked first so a wrong password reads as one |
| wrapped folder key | 60 | the folder key sealed with the password key |

The password key is PBKDF2(password, salt, rounds). Folder passwords set from
ObscuraCrypto 1.2.0 (Swift) and 1.3.0 (Kotlin) use 600,000 rounds, as a vault
does; those set before used 100,000 and keep them until the password is set
again. The count is not stored, so a reader tries 100,000 and then 600,000.
Writers use 600,000 only.

## Single-shot media

`nonce (12) || ciphertext || tag (16)`, sealed with the master key. In a
protected folder that whole message is sealed again with the folder key (+28
more bytes). Photos, thumbnails and short videos use it.

A reader holding a folder key that finds a file the folder key does not open
opens it with the master key alone, because setting a folder password rewraps a
large folder one file at a time and an interrupted run leaves some files
without the layer. The master key still has to open it.

## Chunked media

Large videos, and large PDFs. The first four bytes, `OBCM`, tell the two media
formats apart (a single-shot file starts with its random nonce; a clash is 1 in
2^32, and every implementation decides the same way). Two versions exist: new
files are written in version 2, and version 1, which every file from before
ObscuraCrypto 1.2.0 (Swift) and 1.3.0 (Kotlin) is, is read forever.

```
offset  size  field
     0     4  magic, "OBCM"
     4     1  version, 0x02 (0x01)
     5     4  nonce prefix, random per file
     9     8  total plaintext length, UInt64
    17     4  plaintext bytes per chunk, UInt32 (1,048,576 by default)
    21     4  flags, UInt32; bit 0 set means a folder layer
    25    32  key salt, random per file (version 2 only)
```

Version 2 defines bit 0 of the flags only, and a reader refuses a version 2
header with any other bit set. Version 1 files are read as they always were.

The header is 57 bytes in version 2 and 25 in version 1 (`headerSize` below).
A reader reads up to 57 bytes and parses by the version byte; any other version
is refused. Chunks follow the header at fixed offsets. With `layers` = 1, or 2
for a folder layer, each chunk carries `28 * layers` bytes of overhead:

```
chunkCount   = ceil(total / chunkSize)            version 1
             = max(1, ceil(total / chunkSize))    version 2: an empty file has one empty chunk
offset(i)    = headerSize + i * (chunkSize + 28 * layers)
size(i)      = plaintext(i) + 28 * layers        (the last chunk may be shorter)
file length  = headerSize + total + chunkCount * 28 * layers
```

- **Keys.** Version 1 seals the master layer under the master key and the
  folder layer under the folder key, as they are. Version 2 seals each under a
  key of the file's own: HKDF-SHA256 (RFC 5869), salt = the header's key salt,
  32 bytes out, from the master key with info `OBCM v2 master layer` and from
  the folder key with info `OBCM v2 folder layer` (ASCII).
- **Master layer** of chunk `i`: combined AES-GCM under the master layer key,
  nonce `noncePrefix || i` (i as 8 big-endian bytes). In version 2 the last
  chunk (`i = chunkCount - 1`) sets the counter's top bit: `noncePrefix ||
  (i | 2^63)`, its first counter byte `0x80`.
- **Folder layer**, when flagged: the master-sealed chunk sealed again under the
  folder layer key with nonce `noncePrefix || (chunkCount + i)`. The numbering
  continues past the last chunk so the two layers never share a nonce.
- To open chunk `i`, remove the folder layer first, then the master layer. A
  reader checks that **each layer's stored nonce equals the one its position
  requires**, as well as the tag: the tag only proves a chunk is intact, and the
  nonce travels inside it, so without the check chunks could be moved within a
  file or copied in from another under the same key.
- Setting or removing a folder password rewrites each chunk's folder layer in
  place and changes only bit 0 of the flags: the version, prefix and salt stay.
- A reader checks the file's length against the header **before** using any key,
  and refuses a header whose implied length does not fit in a signed 64-bit
  number.
- Chunk sizes above 2^31 - 57 cannot be read by the Kotlin library (a chunk must
  fit in one array). No file the app has written comes near it.

Why version 2. In version 1 the 4-byte prefix is all that keeps two files under
one master key apart. Two that draw the same prefix (a 1 in 2^32 chance per
pair; about 1 in 90 among 10,000 files) seal their matching chunks under the
same key and nonce. That reveals how those chunks differ, and it also reveals
the key's GCM authentication key, which is the same for every nonce: whoever
holds both files can then alter any message sealed under that master key that
they hold a copy of (single-shot media, thumbnails, version 1 chunks) without
the change being detected. Sealing one of the pair again stops anyone who
copies the files afterwards; for copies taken before, only a new master key
ends it. In version 2 no two files share a key, so a shared prefix does no
harm. In version 2 the header is held to the
chunks too. A file cut short at a chunk boundary, with its recorded length
changed to match, ends on a chunk whose nonce lacks the end mark and is
refused; one cut down to its header is refused for its length, as even an
empty file has a chunk. A changed chunk size moves the offsets of a file of
more than one chunk, a changed folder flag asks for a layer that is not there,
any other flag is refused, and a changed salt derives other keys: none of them
opens. (A one-chunk file's chunk size can be raised or lowered while the chunk
still fits, which changes nothing that is read.) A reader that reads chunks as
they are needed, as a video player does, learns of a cut only when it reaches
the end. In version 1 a file cut short at a chunk boundary still opens,
shorter.

Test vectors: master or folder key bytes `00 01 … 1f`, salt bytes `20 21 … 3f`:

```
master layer key  d676bf9cc865de745fe168ae88fc29317550a8226bc3ccffcf6129972991f27b
folder layer key  acd57362adb473b5f8a1bdc93b87539be70ca8cf017c719f11e4155ddf38d831
```

Nonces, prefix `aa bb cc dd`, a version 2 file of 10 bytes in 4-byte chunks
(three chunks) with a folder layer:

```
master, chunk 1   aabbccdd 00 00 00 00 00 00 00 01
master, chunk 2   aabbccdd 80 00 00 00 00 00 00 02    the last
folder, chunk 2   aabbccdd 00 00 00 00 00 00 00 05
```

## Export files (`.obscura`)

Two versions. Writers make version 2 (from Swift 1.2.0 and Kotlin 1.3.0);
every reader still reads version 1, which every iPhone and Android build
before then wrote. Both carry the same plaintext stream under the same export
key, `PBKDF2(password, salt, rounds)`; they differ in how it is cut into
records and in what the file shows without its password.

The stream, in order:

1. **The manifest**, JSON (below).
2. **The vault file** (header, database, padding), `databaseSize` bytes.
3. **For each media file in the manifest's order**: its `.data.enc` bytes, then
   its `.thumb.enc` bytes, exactly as the vault stores them (still sealed under
   the vault's master key). A size of 0 is no bytes.

### Version 2

A 96-byte header and its key block, then records all of one size.

```
offset  size  field
     0     4  magic, "OBSV"
     4     2  version, UInt16, 2
     6     2  readable by: the oldest reader version that opens the file, 2
     8     2  flags: bits 0-7 must be understood, bits 8-15 may be ignored; none defined, 0
    10     2  key block length: bytes of the key block after the header, 1 to 4,096
    12     4  record size: plaintext bytes in every record, UInt32 (1,048,576)
    16    32  salt for the export password
    48     4  rounds, UInt32 (600,000)
    52     4  nonce prefix, random per file
    56    32  key commitment (below)
    88     8  reserved, 0
    96     n  key block: a lock count (1 byte), then each lock as
              type (1) || body length (2) || body
```

- **Key block**: room for more ways to open the file beside its password
  (a recovery key, for one), added later without a new version. A reader
  skips a lock of a type it does not know and opens the file with its
  password as before; a lock it does know but cannot use is passed over the
  same way. No type is defined yet, and writers write a block of one byte,
  a count of 0. The password, its salt and rounds and the key commitment
  stay in the fixed header. A count that does not account for every byte of
  the block, or a length past 4,096 or past the end of the file, is refused.
  The block is part of the header for everything below: records start
  after it, and every record authenticates it, so a lock cannot be added,
  removed or changed unnoticed.

- **Keys**: the export key, PBKDF2-HMAC-SHA256(password, salt, rounds), is
  never used as it is. HKDF-SHA256 over it, with a salt of 32 zero bytes,
  gives two 32-byte values: the **record key** (info `OBSV v2 records`) and
  the **key commitment** (info `OBSV v2 key commitment`). So no key is both
  an AES-GCM key and the source of the check stored in the clear.

- **Password check**: the key commitment, compared in constant time before
  anything is decrypted. It also ties the file to one key, which AES-GCM alone
  does not.
- A reader refuses a version it is not, or a `readable by` above its own
  version, or a required flag, with "needs a newer version" (`exportNewerVersion`),
  not as damage. A record size outside 4,096 to 1,048,576 is refused.
- **Record `i`**: `recordSize + 28` bytes of combined AES-GCM under the record
  key, nonce `noncePrefix || i` (8-byte big-endian index) with the index's top
  bit set on the last record, and **the header (its 96 bytes and the key block) as associated data**.
  No length prefix: every record is the same size. A reader checks each nonce
  against its position and end mark, so records reordered, dropped, copied,
  added after the last, or cut off are refused, and so is any change to the
  header (the password still checks; no record opens).
- **The records' plaintext**, end to end: the manifest's length (UInt32), the
  manifest, the stream above, then zeros to the Padmé length of all of that
  (at most 12% more), rounded up to whole records. A reader checks, once it
  has read the last file, that only zeros follow, to the record with the end
  mark.

**What an export shows without its password**: its header and its length,
which says only roughly how much it holds. Not how many files, nor the size of
any.

### Version 1

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

- **Password check** = the 16-byte GCM tag from sealing `OBSCURA_EXPORT_V1`
  (ASCII, 17 bytes) with the export key and nonce `noncePrefix || 0xFFFFFFFFFFFFFFFF`.
  Compared in constant time before anything is decrypted.
- **Record** = a 4-byte length `n`, then `n` bytes of combined AES-GCM under the
  export key, nonce `noncePrefix || i`, records numbered from 0. A reader
  checks the nonce. `n` is greater than 28 and at most 1,048,576 + 28 (the
  manifest, record 0, may be up to 256 MB).
- Record 0 is the manifest alone. Then the vault file and each media file in
  records of up to 1 MiB, each file starting a new record and never sharing
  one with the next.
- After the last file there are no more records; a reader checks for that once
  it has read the last file (`isAtEnd`) and treats leftover records as an error.

**What a version 1 export shows without its password**: its header, its
length, and how the records fall: every stored file starts on a record of its
own, so the records give the vault file's length, how many media files there
are and the size of each, to the byte. Nothing of what they are. Version 2
was made to close that.

### Manifest

JSON written by Swift's `JSONEncoder`. This package reads only the keys it needs
to split the stream and find the master key; the app reads the rest (folders,
photos, tags and so on) and ignores what it does not know.

Both libraries read it with the same strict reader as a shared file's manifest
(below), except that numbers may have fractions and exponents, as the app
writes dates that way, and it may nest 32 levels: no key twice, no byte-order
mark, nothing after the value. So one export never splits into files two ways.

| Key | Type | Meaning |
|---|---|---|
| `exportVersion` | integer | 1, in both file versions (the manifest's own version) |
| `vaultSalt` | base64 (standard alphabet, padded, nothing else taken) | the vault header's salt |
| `encryptedMEK` | base64 | the vault header's 60-byte wrapped master key |
| `databaseSize` | integer | length of the vault file in the stream |
| `mediaFiles[]` | array | `{ "mediaId": UUID string, "dataSize": integer, "thumbSize": integer }` |

- A media ID must be exactly 36 characters, a UUID in the 8-4-4-4-12 form, in
  either case, and unique ignoring case: it becomes a file name. Sizes are not
  negative.
- Dates elsewhere in the manifest (`exportDate`, photo dates) are numbers of
  **seconds since 2001-01-01 00:00 UTC**, Swift's default `Date` encoding. Not
  Unix time. Binary fields are standard base64. The app's own parts of the
  manifest are specified by the app, not here.
- The unwrapped master key must be the exporting vault's own. The app exports
  with the vault's password, so the export password and the vault password are
  normally the same, but a reader derives the master key from the **vault**
  salt and `encryptedMEK` with the password it is given.

## Shared items files (`.obscurashared`)

What Send Encrypted makes: photos, videos and documents chosen in one vault, for
another person to add to theirs, on either platform. Unlike an export it carries
no vault, no master key and nothing that opens anything but the items inside.
Both languages implement it (`SharedItemsFile`, `SharedItemsReader`, and the
password rules in `SharedPassword`), from ObscuraCrypto 1.2.0 (Swift) and 1.3.0
(Kotlin). This is format version 3; versions 1 and 2 were layouts that never
shipped, and readers refuse them.

A 64-byte header, a key block, then records.

```
offset  size  field
     0     4  magic, "OBSI"
     4     2  format version, UInt16: 3
     6     2  readable by: the oldest reader version that opens the file, 3
     8     2  flags: bits 0-7 must be understood, bits 8-15 may be ignored; none defined
    10     2  key block length
    12     4  record size: plaintext bytes in every record, 65,536 (4,096 to 1,048,576 accepted)
    16    16  file id, random
    32     4  nonce prefix, random
    36    28  reserved, written as zeros, ignored
```

**Key block**: a key commitment (32 bytes), a lock count (1 byte), then each
lock as `type (1) || body length (2) || body`. The items are under a random
32-byte **content key**, made for this file alone, and each lock holds it.

The content key is never used as it is. HKDF-SHA256 over it, with a salt of 32
zero bytes, gives two 32-byte values: the **record key** (info `OBSI v3
records`), which seals the records, and the **key commitment** (info `OBSI v3
key commitment`). AES-GCM does not commit to its key: a lock can be built
that opens under several passwords, each to a different key. A reader takes a
key from a lock only if it gives this commitment, so a file has one key, and
so one meaning, whichever lock opens it. A password lock that opens to another
key counts as not opened; an open lock that holds another key is damage.

| Type | Body | |
|---|---|---|
| 1, password | rounds (4) \|\| salt (32) \|\| sealed key (60) | the content key sealed with AES-256-GCM, a random nonce, and **the 64-byte header as associated data**, under PBKDF2(password, salt, rounds) |
| 2, open | the content key (32) | sent without a password |

Writers put one lock in the block: a password lock at 600,000 rounds, or an
open lock. A lock of another type is skipped by readers, which leaves room for
others (a recipient's public key, another password function) beside the old.

**Records** follow the key block back to back, each the same size: `record
size` bytes of plaintext sealed with AES-256-GCM under the record key and
stored combined (`nonce || ciphertext || tag`, 28 bytes more), with **the
header and key block together as associated data**, so neither can be changed
without every record failing. Record `i` has the nonce `noncePrefix || i`,
with the counter's top bit set on the last record (`0x80` in its first
counter byte), the end mark of chunked media version 2. A reader checks each
record's nonce against its position, and takes a record as the last when the
file ends right after it: so records cannot be reordered, dropped or repeated,
and a file cut short at a record boundary ends on a record without the mark.
The file is the preamble and whole records, nothing more.

The prefix is only 4 bytes, but every file has its own random content key, and
so its own record key: no two files share a key and their nonces cannot collide.

The records' plaintext is one stream:

```
manifest length (4) || manifest || every part of every item, in the manifest's order, end to end || zeros
```

Parts run on from one to the next, across records. The zeros fill the last
record. Writers pad further, to the [Padmé](https://petsymposium.org/popets/2019/popets-2019-0056.pdf)
length of the stream (at most 12% more), rounded up to whole records. Readers
take any number of zeros, whole records of them included, and refuse anything
else after the last part.

### What a file shows without the password

That it is one of these files, how it is locked (open, or a password with its
rounds), and its length: the content rounded up by Padmé and then to whole
records of 64 KB. Not how many items it holds, nor how large any of them is, nor
their kinds or titles: those are in the manifest and the records, sealed. A
file with a single item is the exception: its length gives that item's size to
within a few percent.

### Manifest

JSON, read and written by each library's own code (`SharedItemsJSON`,
`SharedItemsJson`) rather than a platform parser, because platform parsers
disagree at the edges and one file must not show different items on iPhone and
Android. The one form readers take, and refuse anything else as damaged:

- UTF-8, well formed (no overlong forms, surrogates or code points above
  U+10FFFF), with no byte-order mark;
- objects, arrays, strings, whole numbers within 64 bits, `true`, `false`,
  `null`: no fractions, exponents or leading zeros;
- string escapes as RFC 8259 lists them, a `\u` surrogate only as half of a
  pair, and no unescaped control characters;
- no key twice in one object, compared code point for code point (`é` and
  `e` with a combining accent are different keys);
- at most 16 levels deep, at most 2 MiB, nothing after the value but whitespace.

```
{"items": [{"kind": "photo", "type": "image/jpeg", "name": "…",
            "parts": [{"role": "file", "size": 5000, "sha256": "<64 lowercase hex>"}]}]}
```

| Field | Meaning |
|---|---|
| `kind` | `photo`, `gif`, `video`, `livePhoto` or `pdf`; 1 to 64 printable ASCII characters |
| `type` | the file part's MIME type, when the sender knew it; optional; 1 to 100 printable ASCII characters |
| `name` | a document's title; optional; at most 200 code points |
| `parts[]` | 1 to 16 parts: `role` (`file`, or `motion` for a Live Photo's video; 1 to 64 printable ASCII characters), `size` in bytes, above 0, and the lowercase hex SHA-256 of the plaintext |

A file holds 1 to 1,000 items. A known kind has a `file` part, and a `motion`
part exactly when it is a Live Photo; no role appears twice in an item. A title
holds no control characters (U+0000 to U+001F, U+007F to U+009F), line or
paragraph separators (U+2028, U+2029) or direction controls (U+061C, U+200E,
U+200F, U+202A to U+202E, U+2066 to U+2069), which writers turn into spaces,
and no characters that show nothing at all (U+180E, U+200B, U+2060 to U+2064,
U+206A to U+206F, U+FEFF, U+FFF9 to U+FFFB, and the tag characters U+E0000 to
U+E007F), which writers leave out, so a title cannot look blank, or like
another, while it holds more. The joiners U+200C and U+200D are allowed, as
some scripts and emoji need them. Writers then trim spaces at either end and
cut the title to 200 code points; readers refuse a title that still has one of
those characters. Writers make the manifest with keys in the order
above and no whitespace; readers take any order and ignore keys they do not
know.

### Passwords

The file leaves the phone by design, and whoever keeps a copy can try
passwords on their own hardware for as long as they like; the rounds make each
guess cost what a guess at a vault does, and the password has to do the rest.
The format takes any password, and the apps take any of 6 characters or more:
which password to use is the person's choice. What the libraries add is advice
(`passwordProblem`, `SharedPassword.problem`), which apps show as a note. A
password is easy to guess when it is:

- shorter than 10 characters (code points);
- simple: fewer than 5 different characters, digits alone, or a run along the
  alphabet or a keyboard row (`abcdefghij`, `qwertyuiop`, forwards or back);
- common: with any ASCII digits and symbols at either end taken off, the usual
  swaps inside undone (`0` o, `1` i, `3` e, `4` a, `5` s, `7` t, `@` a, `$` s,
  `!` i) and all but the letters a to z dropped, one of the most common
  password words, or one repeated (`Password123!`, `P@ssw0rd`, `iloveyou2024`).

The checks use ASCII alone, so both languages decide alike. Apps offer a
generated password first: six different words drawn uniformly from the
BIP-39 English list (the recovery phrase's), joined by hyphens, about 66 bits,
out of reach of guessing at 600,000 rounds.

### Reading

Readers refuse rather than guess, and never call a file damaged when it is
only newer:

- Refused as **not a shared items file**: a wrong magic, a format below 3,
  "readable by" below 3 or above the format, a key block length of 33 or less
  or over 4,096, a record size outside 4,096 to 1,048,576, a key block that does
  not parse to its exact length, or password locks that are all outside
  600,000 to 10,000,000 rounds.
- Refused as **needs a newer version**: "readable by" above the reader's
  version, a flag in bits 0-7 set, no lock of a type it knows, or no item of a
  kind it knows.
- Passed over: a higher format with a "readable by" the reader meets, flags in
  bits 8-15, locks, kinds of item, roles of part and JSON keys it does not
  know. Unknown parts and items are still decrypted and their hashes checked.
- Refused as **damaged**, once the key is known: a record whose nonce or tag is
  wrong, a file that is not whole records or ends early, a manifest length of 0
  or over 2 MiB, a manifest outside the strict form or listing an item that
  cannot be, a part whose SHA-256 does not match, and anything but zeros after
  the last part.

An open lock is used if there is one and no password was given; otherwise
password locks in order, at most four, and at most 10,000,000 rounds across them
all (about five seconds on a phone), so a made-up file cannot hold a reader for
long. A wrong password reads as "wrong password" only when a password lock with
acceptable rounds exists.

A reader given a password refuses a file with an open lock (`sharedItemsNotLocked`):
a file sent with a password could be swapped on the way for one anyone made,
and it must not then open as though it were the sender's.

### Without a password

An open file holds its own key. It still keeps the items out of photo
libraries, previews and scanners on the way, but anyone who has the file can
open it, and can change it and seal it again so that it still checks: nothing
in it shows who made it. Only a password-sealed file is both private and
known to come from someone who knew the password. Apps say so when they make
one and when they open one.

## Reading files safely

Every reader here refuses, rather than guesses: a header that is too short, a
wrong magic or version, a checksum that does not match, a length that does not
fit, a record whose nonce is wrong, a file whose length does not match its
header, and a tag that does not verify. Whole-file decryption goes to a temporary
file that is moved into place only when every chunk has verified, so a failure
leaves no partial plaintext at the destination. A process killed part way can
leave that temporary file (a hidden `.partial` file beside the destination); the
command-line tools remove theirs when stopped with Control-C or a kill.

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
