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
  local s k
  s="$(printf '%s\n' "$password" | "$swift_cli" "$@" --password-stdin 2>&1 | sed "s#$work#WORK#g")"
  k="$(printf '%s\n' "$password" | "$kotlin_cli" "$@" --password-stdin 2>&1 | sed "s#$work#WORK#g")"
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

[ "$failures" -eq 0 ] && echo "All checks passed." || { echo "$failures check(s) failed."; exit 1; }
