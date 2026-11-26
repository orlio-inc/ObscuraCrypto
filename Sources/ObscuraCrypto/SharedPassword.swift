// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import Foundation

/// Passwords for `.obscurashared` files: advice, never a refusal.
///
/// A shared file leaves the phone by design, through mail, chat apps and
/// cloud drives, and whoever keeps a copy can try passwords against it on
/// their own hardware for as long as they like. The rounds of PBKDF2 make
/// each guess cost the same as against a vault; the password has to do the
/// rest. So apps offer a generated one first, six words drawn at random
/// from the 2,048 of the BIP-39 list, about 66 bits, which no one finishes
/// guessing, and say when a password of the person's own is easy to guess.
/// Which password to use stays the person's choice: the writer takes any.
///
/// The checks work on ASCII alone, so they decide the same way in Swift and
/// Kotlin. They catch what people pick most, not every weak password:
/// - at least 10 characters (Unicode code points) is the advice;
/// - at least 5 different characters, not digits alone, and not a run along
///   the alphabet or a keyboard row (`abcdefghij`, `qwertyuiop`);
/// - not one of the most common passwords with digits or symbols around it
///   (`Password123!`, `iloveyou2024`, `P@ssw0rd`), or such a word repeated.
extension SharedItemsFile {
    public enum PasswordProblem: String, Sendable, Equatable {
        case tooShort
        case tooSimple
        case tooCommon
    }

    /// Shorter is easier to guess; apps still take it.
    public static let recommendedPasswordLength = 10
    /// Words in a suggested password.
    public static let suggestedPasswordWords = 6

    /// What makes `password` easy to guess for a shared file, or nil: for
    /// telling the person, not for refusing it.
    public static func passwordProblem(_ password: String) -> PasswordProblem? {
        let scalars = Array(password.unicodeScalars)
        guard scalars.count >= recommendedPasswordLength else { return .tooShort }
        guard Set(scalars).count >= 5, !scalars.allSatisfy({ ("0"..."9").contains($0) }) else { return .tooSimple }
        let lower = String(String.UnicodeScalarView(scalars.map(asciiLowercased)))
        if keyboardRuns.contains(where: { $0.contains(lower) || String($0.reversed()).contains(lower) }) {
            return .tooSimple
        }
        return isCommon(scalars) ? .tooCommon : nil
    }

    /// Words from the BIP-39 list, all different, joined by hyphens: easy
    /// to read out and type on any keyboard.
    public static func suggestedPassword(words count: Int = suggestedPasswordWords) throws -> String {
        while true {
            var picked: [String] = []
            while picked.count < count {
                // 2,048 words, 11 bits: masking a random 16-bit number keeps
                // every word equally likely.
                let random = try SecureRandom.bytes(2)
                let word = RecoveryPhrase.words[Int(UInt16(random[0]) << 8 | UInt16(random[1])) & 0x7FF]
                if !picked.contains(word) { picked.append(word) }
            }
            let password = picked.joined(separator: "-")
            if passwordProblem(password) == nil { return password }
        }
    }

    private static let keyboardRuns = [
        "abcdefghijklmnopqrstuvwxyz", "01234567890", "qwertyuiopasdfghjklzxcvbnm", "qwertzuiopasdfghjklyxcvbnm",
        "azertyuiopqsdfghjklmwxcvbn", "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p", "qazwsxedcrfvtgbyhnujmikolp",
    ]

    private static func asciiLowercased(_ scalar: Unicode.Scalar) -> Unicode.Scalar {
        ("A"..."Z").contains(scalar) ? Unicode.Scalar(scalar.value + 32)! : scalar
    }

    /// The password with ASCII digits and symbols at either end taken off,
    /// the usual letter swaps inside undone (`@` for a, `0` for o), and
    /// everything else but a to z dropped: a common word, or one repeated,
    /// is common.
    private static func isCommon(_ scalars: [Unicode.Scalar]) -> Bool {
        func isLetter(_ scalar: Unicode.Scalar) -> Bool { ("a"..."z").contains(asciiLowercased(scalar)) }
        var core = scalars[...]
        while let first = core.first, first.isASCII, !isLetter(first) { core = core.dropFirst() }
        while let last = core.last, last.isASCII, !isLetter(last) { core = core.dropLast() }
        let letters = String(String.UnicodeScalarView(core.compactMap { scalar -> Unicode.Scalar? in
            isLetter(scalar) ? asciiLowercased(scalar) : leetLetters[scalar]
        }))
        guard !letters.isEmpty else { return false }
        return commonPasswords.contains { word in
            letters.count % word.count == 0 && String(repeating: word, count: letters.count / word.count) == letters
        }
    }

    private static let leetLetters: [Unicode.Scalar: Unicode.Scalar] = [
        "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i",
    ]

    /// The words most often found at the heart of leaked passwords, and
    /// the app's own.
    static let commonPasswords: [String] = [
        "password", "passwort", "motdepasse", "contrasena", "senha", "parola", "haslo", "wachtwoord",
        "qwerty", "qwertz", "azerty", "asdfgh", "zxcvbn", "qazwsx", "abc", "abcdef", "iloveyou", "iloveu",
        "loveyou", "love", "lovely", "admin", "administrator", "root", "user", "guest", "login", "welcome",
        "letmein", "pass", "test", "testing", "secret", "private", "hidden", "photo", "photos", "vault",
        "obscura", "gallery", "monkey", "dragon", "football", "baseball", "basketball", "soccer", "hockey",
        "sunshine", "princess", "master", "shadow", "superman", "batman", "spiderman", "trustno", "whatever",
        "starwars", "pokemon", "minecraft", "fortnite", "michael", "jennifer", "jordan", "hunter", "freedom",
        "charlie", "ashley", "jessica", "daniel", "thomas", "robert", "matthew", "andrew", "joshua", "nicole",
        "hannah", "summer", "winter", "spring", "autumn", "flower", "cookie", "chocolate", "butterfly",
        "purple", "orange", "banana", "apple", "cheese", "pepper", "ginger", "tigger", "buster", "mustang",
        "maverick", "computer", "internet", "samsung", "iphone", "google", "facebook", "instagram", "hello",
        "angel", "baby", "family", "mother", "father", "sister", "brother", "friend", "friends", "forever",
        "money", "lucky", "happy", "magic", "silver", "golden", "diamond", "killer", "liverpool", "chelsea",
        "arsenal", "barcelona", "madrid", "juventus", "yankees", "cowboys", "eagles", "lakers", "jesus",
        "christ", "blessed", "heaven", "music", "guitar", "dance", "letme", "changeme", "default", "access",
        "zaq", "qwe", "asd", "zxc", "aaa", "abcd", "abcde",
    ]
}
