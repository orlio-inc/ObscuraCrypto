// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Orlio Inc.

import CryptoKit
import XCTest
@testable import ObscuraCrypto

final class RecoveryPhraseTests: XCTestCase {

    /// The 256-bit vectors from BIP-39's reference test set (trezor/python-mnemonic
    /// vectors.json), entropy to words. The seed half of those vectors does not
    /// apply: a recovery phrase is never stretched into a seed.
    private let vectors: [(entropy: String, phrase: String)] = [
        (String(repeating: "00", count: 32),
         String(repeating: "abandon ", count: 23) + "art"),
        (String(repeating: "7f", count: 32),
         String(repeating: "legal winner thank year wave sausage worth useful ", count: 2)
            + "legal winner thank year wave sausage worth title"),
        (String(repeating: "80", count: 32),
         String(repeating: "letter advice cage absurd amount doctor acoustic avoid ", count: 2)
            + "letter advice cage absurd amount doctor acoustic bless"),
        (String(repeating: "ff", count: 32),
         String(repeating: "zoo ", count: 23) + "vote"),
        ("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
         "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"),
        ("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
         "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside"),
        ("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
         "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform"),
        ("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
         "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"),
    ]

    func testWordListIsThePublishedOne() {
        let file = RecoveryPhrase.words.map { $0 + "\n" }.joined()
        let hash = SHA256.hash(data: Data(file.utf8)).map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(hash, "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda")
        XCTAssertEqual(RecoveryPhrase.words.count, 2048)
        XCTAssertEqual(Set(RecoveryPhrase.words.map { $0.prefix(4) }).count, 2048,
                       "every word must be identified by its first four letters")
    }

    func testPublishedVectorsEncode() throws {
        for vector in vectors {
            let key = SecureBytes(copying: Data(hex: vector.entropy))
            XCTAssertEqual(try RecoveryPhrase.words(for: key).joined(separator: " "), vector.phrase)
        }
    }

    func testPublishedVectorsDecode() throws {
        for vector in vectors {
            let words = vector.phrase.split(separator: " ").map(String.init)
            XCTAssertEqual(try RecoveryPhrase.masterKey(from: words), SecureBytes(copying: Data(hex: vector.entropy)))
        }
    }

    func testRandomKeysRoundTrip() throws {
        for _ in 0..<200 {
            let key = try SecureBytes.random(count: 32)
            let words = try RecoveryPhrase.words(for: key)
            XCTAssertEqual(words.count, 24)
            XCTAssertEqual(try RecoveryPhrase.masterKey(from: words), key)
        }
    }

    func testCaseAndSurroundingSpaceAreIgnored() throws {
        let key = try SecureBytes.random(count: 32)
        let typed = try RecoveryPhrase.words(for: key).map { " \($0.uppercased())\n" }
        XCTAssertEqual(try RecoveryPhrase.masterKey(from: typed), key)
    }

    func testWrongWordCountIsRefused() throws {
        let words = try RecoveryPhrase.words(for: SecureBytes.random(count: 32))
        XCTAssertThrowsError(try RecoveryPhrase.masterKey(from: Array(words.dropLast()))) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .recoveryPhraseWrongLength(23))
        }
    }

    func testAWordNotOnTheListIsNamedByPosition() throws {
        var words = try RecoveryPhrase.words(for: SecureBytes.random(count: 32))
        words[6] = "abandn"
        XCTAssertThrowsError(try RecoveryPhrase.masterKey(from: words)) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .recoveryPhraseUnknownWord(position: 7))
        }
    }

    /// Two different list words swapped in, or a word replaced by another
    /// list word, almost always breaks the checksum. One in 256 such changes
    /// passes it, by design of an 8-bit checksum; that phrase then opens no
    /// vault, which the app checks next.
    func testSwappedWordsAreCaughtByTheChecksum() throws {
        let words = String(repeating: "abandon ", count: 23) + "art"
        var swapped = words.split(separator: " ").map(String.init)
        swapped.swapAt(0, 23)
        XCTAssertThrowsError(try RecoveryPhrase.masterKey(from: swapped)) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .recoveryPhraseChecksumMismatch)
        }
    }

    func testOnlyAThirtyTwoByteKeyIsEncoded() {
        XCTAssertThrowsError(try RecoveryPhrase.words(for: SecureBytes(count: 16))) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .invalidKeyLength(16))
        }
    }

    func testCompletions() {
        XCTAssertEqual(RecoveryPhrase.completions(for: "aba"), ["abandon"])
        XCTAssertEqual(RecoveryPhrase.completions(for: "Zo"), ["zone", "zoo"])
        XCTAssertEqual(RecoveryPhrase.completions(for: "ab", limit: 2), ["abandon", "ability"])
        XCTAssertEqual(RecoveryPhrase.completions(for: ""), [])
        XCTAssertEqual(RecoveryPhrase.completions(for: "qqq"), [])
    }

    // MARK: - With a vault header

    func testThePhraseOpensItsOwnVaultOnly() throws {
        let (header, masterKey) = try VaultHeader.create(password: "secret password", databaseSize: 7)
        let (other, otherKey) = try VaultHeader.create(password: "secret password", databaseSize: 7)
        let recovered = try RecoveryPhrase.masterKey(from: RecoveryPhrase.words(for: masterKey))
        XCTAssertTrue(header.opens(masterKey: recovered))
        XCTAssertFalse(other.opens(masterKey: recovered))
        XCTAssertFalse(header.opens(masterKey: otherKey))
    }

    func testANewPasswordFromThePhraseKeepsTheMasterKey() throws {
        let (header, masterKey) = try VaultHeader.create(password: "forgotten password", databaseSize: 9)
        let recovered = try RecoveryPhrase.masterKey(from: RecoveryPhrase.words(for: masterKey))

        let reset = try VaultHeader(parsing: header.settingPassword("new password", masterKey: recovered).serialized())
        XCTAssertEqual(try reset.unlock(password: "new password"), masterKey)
        XCTAssertEqual(try reset.databaseSize(masterKey: masterKey), 9)
        XCTAssertNotEqual(reset.salt, header.salt)
        XCTAssertThrowsError(try reset.unlock(password: "forgotten password"))
        XCTAssertTrue(reset.opens(masterKey: recovered), "a password change leaves the phrase valid")
    }

    func testANewPasswordNeedsTheVaultsOwnKey() throws {
        let (header, _) = try VaultHeader.create(password: "secret password")
        XCTAssertThrowsError(try header.settingPassword("new password", masterKey: SecureBytes.random(count: 32))) {
            XCTAssertEqual($0 as? ObscuraCryptoError, .authenticationFailed)
        }
    }
}

private extension Data {
    init(hex: String) {
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        self.init(bytes)
    }
}
