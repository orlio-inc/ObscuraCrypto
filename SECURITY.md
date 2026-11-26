# Reporting a security issue

Please report security problems privately, by email to support@orlio.io with "Security" in the subject line, rather than in a public issue. Include what you found, how to reproduce it, and what you believe the impact is. A test file or a few lines of code that show it are the most useful.

Please allow time for a fix to reach the App Store and Google Play before publishing details.

## In scope

Anything in this repository, Swift or Kotlin, that would:

- let someone read, alter or forge vault, media, exported backup (`.obscura`) or Send Encrypted (`.obscurashared`) data without the password or key;
- weaken key derivation, or let a file ask for weaker settings than the formats allow;
- reveal more about a file than [FORMATS.md](FORMATS.md) says it shows;
- make the two languages read the same file differently, or make the documented formats differ from what the code does;
- crash or hang a reader on a crafted file.

The app itself (its screens, the vault database, vault slots, Face ID, what it does while it runs) is not in this repository, but reports about it are welcome at the same address.
