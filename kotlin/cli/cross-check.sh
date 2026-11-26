#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Runs the Swift and the Kotlin `obscura` on the same files and checks that they
# agree: the same output, the same decrypted bytes, and files made by one that
# the other opens. Needs a Mac with Swift and a JDK 21.
#
#   kotlin/cli/cross-check.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$here/../.."
fixtures="$repo/Tests/ObscuraCryptoTests/Fixtures"
password="correct horse battery staple"

(cd "$repo" && swift build -c release --product obscura >/dev/null)
(cd "$repo/kotlin" && ./gradlew --console=plain -q :cli:installDist >/dev/null)
swift_cli="$(cd "$repo" && swift build -c release --product obscura --show-bin-path)/obscura"
kotlin_cli="$repo/kotlin/cli/build.nosync/install/obscura/bin/obscura"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

pass() { echo "ok    $1"; }
fail() { echo "FAIL  $1"; failures=$((failures + 1)); }

# Same stdout from both tools.
same_output() {
  local label="$1"; shift
  same_output_with "$password" "$label" "$@"
}

# The same, with another password on standard input. A refusal is output
# too: both tools must refuse with the same words.
same_output_with() {
  local pw="$1" label="$2"; shift 2
  local s k
  s="$(printf '%s\n' "$pw" | "$swift_cli" "$@" --password-stdin 2>&1 | sed "s#$work#WORK#g" || true)"
  k="$(printf '%s\n' "$pw" | "$kotlin_cli" "$@" --password-stdin 2>&1 | sed "s#$work#WORK#g" || true)"
  if [ "$s" == "$k" ]; then pass "$label"; else fail "$label"; diff <(echo "$s") <(echo "$k") || true; fi
}

# The same with no password at all, for files sent without one, which ask
# for none.
same_output_open() {
  local label="$1"; shift
  local s k
  s="$("$swift_cli" "$@" </dev/null 2>&1 | sed "s#$work#WORK#g" || true)"
  k="$("$kotlin_cli" "$@" </dev/null 2>&1 | sed "s#$work#WORK#g" || true)"
  if [ "$s" == "$k" ]; then pass "$label"; else fail "$label"; diff <(echo "$s") <(echo "$k") || true; fi
}

# The checksum of every file in a folder, by name.
sums() { (cd "$1" && shasum -a 256 -- * 2>/dev/null | sort -k2); }

vault="$fixtures/vault/data/068E6368-A18E-45FD-96EB-95E9251F848A.db.enc"
same_output "vault inspect" vault inspect "$vault"
same_output "vault unlock" vault unlock "$vault"
for f in photo video photo-folder video-folder; do
  same_output "media inspect $f" media inspect "$fixtures/$f.data.enc"
done
same_output "export inspect" export inspect "$fixtures/vault.obscura"

# Extraction gives the same files.
mkdir "$work/s-vault" "$work/k-vault" "$work/s-export" "$work/k-export"
printf '%s\n' "$password" | "$swift_cli" vault extract "$vault" "$work/s-vault" --password-stdin >/dev/null
printf '%s\n' "$password" | "$kotlin_cli" vault extract "$vault" "$work/k-vault" --password-stdin >/dev/null
[ "$(sums "$work/s-vault")" == "$(sums "$work/k-vault")" ] && [ -n "$(sums "$work/s-vault")" ] && pass "vault extract" || fail "vault extract"

printf '%s\n' "$password" | "$swift_cli" export extract "$fixtures/vault.obscura" "$work/s-export" --password-stdin >/dev/null
printf '%s\n' "$password" | "$kotlin_cli" export extract "$fixtures/vault.obscura" "$work/k-export" --password-stdin >/dev/null
[ "$(sums "$work/s-export")" == "$(sums "$work/k-export")" ] && [ -n "$(sums "$work/s-export")" ] && pass "export extract" || fail "export extract"
[ -z "$(ls -A "$work/k-export" | grep '^\.' || true)" ] && pass "export extract leaves no staging files" || fail "export extract leaves staging files"

# Version 2 exports, each library's opened by both tools, and tampered ones
# refused with the same words.
for set in FromSwift FromKotlin; do
  export_password="$(plutil -extract vaultPassword raw -o - "$fixtures/$set/compat.json")"
  same_output "export inspect ($set, version 2)" export inspect "$fixtures/$set/export2.obscura"
  mkdir "$work/s-$set" "$work/k-$set"
  printf '%s\n' "$export_password" | "$swift_cli" export extract "$fixtures/$set/export2.obscura" "$work/s-$set" --password-stdin >/dev/null
  printf '%s\n' "$export_password" | "$kotlin_cli" export extract "$fixtures/$set/export2.obscura" "$work/k-$set" --password-stdin >/dev/null
  [ "$(sums "$work/s-$set")" == "$(sums "$work/k-$set")" ] && [ -n "$(sums "$work/s-$set")" ] && pass "export extract ($set, version 2)" || fail "export extract ($set, version 2)"
  # Each tool into its own folder: the same words, and the same files left.
  for tampered in reordered header-altered appended newer; do
    file="$fixtures/$set/tampered/export2-$tampered.obscura"
    s="$(printf '%s\n' "$export_password" | "$swift_cli" export extract "$file" "$work/ts-$set-$tampered" --password-stdin 2>&1 | sed "s#$work/ts-#WORK/t-#g" || true)"
    k="$(printf '%s\n' "$export_password" | "$kotlin_cli" export extract "$file" "$work/tk-$set-$tampered" --password-stdin 2>&1 | sed "s#$work/tk-#WORK/t-#g" || true)"
    if [ "$s" == "$k" ] && [ -n "$s" ] && [ "$(sums "$work/ts-$set-$tampered")" == "$(sums "$work/tk-$set-$tampered")" ]; then
      pass "export extract ($set, $tampered)"
    else
      fail "export extract ($set, $tampered)"; diff <(echo "$s") <(echo "$k") || true
    fi
  done
done

# Each tool's files open in the other.
head -c 3000000 /dev/urandom > "$work/plain.bin"
for maker in swift kotlin; do
  for opener in swift kotlin; do
    [ "$maker" == "$opener" ] && continue
    m="$([ "$maker" == swift ] && echo "$swift_cli" || echo "$kotlin_cli")"
    o="$([ "$opener" == swift ] && echo "$swift_cli" || echo "$kotlin_cli")"
    d="$work/$maker-made"; mkdir "$d"
    printf 'pw one\npw one\n' | "$m" vault create "$d/vault" --password-stdin >/dev/null
    printf 'folder pw\n' | "$m" folder create "$d/folder.json" --password-stdin >/dev/null
    printf 'pw one\n' | "$m" media encrypt "$work/plain.bin" "$d/single.enc" --vault "$d/vault" --password-stdin >/dev/null
    printf 'pw one\nfolder pw\n' | "$m" media encrypt "$work/plain.bin" "$d/chunked.enc" --vault "$d/vault" --folder "$d/folder.json" \
      --chunked --chunk-size 65536 --password-stdin >/dev/null
    printf 'pw one\n' | "$o" vault unlock "$d/vault" --password-stdin >/dev/null
    printf 'pw one\n' | "$o" media decrypt "$d/single.enc" "$d/single.out" --vault "$d/vault" --password-stdin >/dev/null
    printf 'pw one\nfolder pw\n' | "$o" media decrypt "$d/chunked.enc" "$d/chunked.out" --vault "$d/vault" --folder "$d/folder.json" --password-stdin >/dev/null
    if cmp -s "$work/plain.bin" "$d/single.out" && cmp -s "$work/plain.bin" "$d/chunked.out"; then
      pass "files made by $maker open in $opener"
    else
      fail "files made by $maker open in $opener"
    fi
  done
done

# Shared items: the same report and files from both, and each tool's files open in the other.
same_output_with "swift shared pass" "shared verify (Swift's file)" shared verify "$fixtures/FromSwift/shared-password.obscurashared"
same_output_with "kotlin shared pass" "shared verify (Kotlin's file)" shared verify "$fixtures/FromKotlin/shared-password.obscurashared"
same_output_open "shared verify (open)" shared verify "$fixtures/FromKotlin/shared-open.obscurashared"
same_output_with "a password" "shared verify (open, a password given)" shared verify "$fixtures/FromSwift/shared-open.obscurashared"
same_output_open "shared verify (tampered)" shared verify "$fixtures/FromSwift/tampered/shared-swapped.obscurashared"
same_output_open "shared verify (a manifest read two ways elsewhere)" shared verify "$fixtures/FromKotlin/tampered/shared-twice.obscurashared"
same_output_open "shared verify (an uncommitted key)" shared verify "$fixtures/FromKotlin/tampered/shared-commitment.obscurashared"
same_output_with "swift shared pass" "shared verify (wrong password)" shared verify "$fixtures/FromKotlin/shared-password.obscurashared"
# Into the same folder, emptied between the two, so the reports match word for word.
s="$(printf 'kotlin shared pass\n' | "$swift_cli" shared decrypt "$fixtures/FromKotlin/shared-password.obscurashared" "$work/shared-same" --password-stdin 2>&1 | sed "s#$work#WORK#g" || true)"
rm -rf "$work/shared-same"
k="$(printf 'kotlin shared pass\n' | "$kotlin_cli" shared decrypt "$fixtures/FromKotlin/shared-password.obscurashared" "$work/shared-same" --password-stdin 2>&1 | sed "s#$work#WORK#g" || true)"
if [ "$s" == "$k" ]; then pass "shared decrypt"; else fail "shared decrypt"; diff <(echo "$s") <(echo "$k") || true; fi
mkdir "$work/s-shared" "$work/k-shared"
printf 'swift shared pass\n' | "$swift_cli" shared decrypt "$fixtures/FromSwift/shared-password.obscurashared" "$work/s-shared" --password-stdin >/dev/null
printf 'swift shared pass\n' | "$kotlin_cli" shared decrypt "$fixtures/FromSwift/shared-password.obscurashared" "$work/k-shared" --password-stdin >/dev/null
[ "$(sums "$work/s-shared")" == "$(sums "$work/k-shared")" ] && [ -n "$(sums "$work/s-shared")" ] && pass "shared decrypt gives the same files" || fail "shared decrypt gives the same files"

mkdir "$work/live"
head -c 1500000 /dev/urandom > "$work/live/IMG_0001.HEIC"
head -c 2500000 /dev/urandom > "$work/live/IMG_0001.MOV"
printf '%%PDF-1.4 lease' > "$work/live/Lease.pdf"
cp "$work/plain.bin" "$work/live/beach.jpg"
for maker in swift kotlin; do
  for opener in swift kotlin; do
    [ "$maker" == "$opener" ] && continue
    m="$([ "$maker" == swift ] && echo "$swift_cli" || echo "$kotlin_cli")"
    o="$([ "$opener" == swift ] && echo "$swift_cli" || echo "$kotlin_cli")"
    d="$work/$maker-shared"; mkdir "$d"
    printf 'shared files pw\n' | "$m" shared encrypt "$d/sent.obscurashared" "$work/live/IMG_0001.HEIC" "$work/live/IMG_0001.MOV" \
      "$work/live/Lease.pdf" "$work/live/beach.jpg" --live-photos --password-stdin >/dev/null
    printf 'shared files pw\n' | "$o" shared decrypt "$d/sent.obscurashared" "$d/out" --password-stdin >/dev/null
    if cmp -s "$work/live/IMG_0001.HEIC" "$d/out/1-live-photo.heic" && cmp -s "$work/live/IMG_0001.MOV" "$d/out/1-live-photo.mov" \
       && cmp -s "$work/live/Lease.pdf" "$d/out/2-document.pdf" && cmp -s "$work/plain.bin" "$d/out/3-photo.jpg"; then
      pass "shared files made by $maker open in $opener"
    else
      fail "shared files made by $maker open in $opener"
    fi
  done
done

[ "$failures" -eq 0 ] && echo "All checks passed." || { echo "$failures check(s) failed."; exit 1; }
