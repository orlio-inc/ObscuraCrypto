// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

package io.orlio.obscuracrypto

/**
 * Passwords for `.obscurashared` files, the Swift package's checks decided the
 * same way: advice, never a refusal. A shared file leaves the phone by design
 * and whoever keeps a copy can guess at it on their own hardware, so apps offer
 * a generated one first (six different words from the BIP-39 list, about 66
 * bits) and say when a password of the person's own is easy to guess. Which
 * password to use stays the person's choice: the writer takes any.
 *
 * - at least 10 characters (code points) is the advice;
 * - at least 5 different characters, not digits alone, and not a run along the
 *   alphabet or a keyboard row (`abcdefghij`, `qwertyuiop`);
 * - not one of the most common passwords with digits or symbols around it
 *   (`Password123!`, `iloveyou2024`, `P@ssw0rd`), or such a word repeated.
 *
 * Everything works on ASCII alone, so no locale or Unicode table can make it
 * decide differently from Swift.
 */
object SharedPassword {
    enum class Problem(val id: String) {
        TOO_SHORT("tooShort"),
        TOO_SIMPLE("tooSimple"),
        TOO_COMMON("tooCommon"),
    }

    /** Shorter is easier to guess; apps still take it. */
    const val RECOMMENDED_LENGTH = 10

    /** Words in a suggested password. */
    const val SUGGESTED_WORDS = 6

    /** What makes [password] easy to guess for a shared file, or null: for telling the person, not for refusing it. */
    fun problem(password: String): Problem? {
        val points = password.codePoints().toArray()
        if (points.size < RECOMMENDED_LENGTH) return Problem.TOO_SHORT
        if (points.toSet().size < 5 || points.all { it in '0'.code..'9'.code }) return Problem.TOO_SIMPLE
        val lower = String(points.map(::asciiLowercased).toIntArray(), 0, points.size)
        if (KEYBOARD_RUNS.any { it.contains(lower) || it.reversed().contains(lower) }) return Problem.TOO_SIMPLE
        return if (isCommon(points)) Problem.TOO_COMMON else null
    }

    /** Different words from the BIP-39 list, joined by hyphens: easy to read out and type on any keyboard. */
    fun suggested(words: Int = SUGGESTED_WORDS): String {
        while (true) {
            val picked = ArrayList<String>()
            while (picked.size < words) {
                // 2,048 words, 11 bits: masking a random 16-bit number keeps every word equally likely.
                val random = Random.bytes(2)
                val index = (((random[0].toInt() and 0xFF) shl 8) or (random[1].toInt() and 0xFF)) and 0x7FF
                val word = RECOVERY_PHRASE_WORDS[index]
                if (word !in picked) picked += word
            }
            val password = picked.joinToString("-")
            if (problem(password) == null) return password
        }
    }

    private val KEYBOARD_RUNS = listOf(
        "abcdefghijklmnopqrstuvwxyz", "01234567890", "qwertyuiopasdfghjklzxcvbnm", "qwertzuiopasdfghjklyxcvbnm",
        "azertyuiopqsdfghjklmwxcvbn", "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p", "qazwsxedcrfvtgbyhnujmikolp",
    )

    private fun asciiLowercased(point: Int): Int = if (point in 'A'.code..'Z'.code) point + 32 else point

    private fun isLetter(point: Int): Boolean = asciiLowercased(point) in 'a'.code..'z'.code

    /**
     * The password with ASCII digits and symbols at either end taken off, the
     * usual letter swaps inside undone (`@` for a, `0` for o), and everything
     * else but a to z dropped: a common word, or one repeated, is common.
     */
    private fun isCommon(points: IntArray): Boolean {
        var start = 0
        var end = points.size
        while (start < end && points[start] < 0x80 && !isLetter(points[start])) start += 1
        while (end > start && points[end - 1] < 0x80 && !isLetter(points[end - 1])) end -= 1
        val letters = buildString {
            for (i in start until end) {
                val point = points[i]
                when {
                    isLetter(point) -> append(asciiLowercased(point).toChar())
                    LEET_LETTERS.containsKey(point) -> append(LEET_LETTERS.getValue(point))
                }
            }
        }
        if (letters.isEmpty()) return false
        return COMMON_PASSWORDS.any { word -> letters.length % word.length == 0 && word.repeat(letters.length / word.length) == letters }
    }

    private val LEET_LETTERS = mapOf(
        '0'.code to 'o', '1'.code to 'i', '3'.code to 'e', '4'.code to 'a', '5'.code to 's', '7'.code to 't',
        '@'.code to 'a', '$'.code to 's', '!'.code to 'i',
    )

    /** The words most often found at the heart of leaked passwords, and the app's own. The Swift package's list. */
    internal val COMMON_PASSWORDS = listOf(
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
    )
}
