#!/bin/sh
# THE UNITY PACKAGE CHECK. src/ is a Unity Package Manager package (installed by
# git URL with ?path=src), and an immutable package has rules the .NET build
# never sees:
#
#   - package.json's version is the library's version (src/Serialize.csproj
#     <Version>), so a tag installs the release it names;
#   - the asmdef names the assembly the README tells a project to reference;
#   - every tracked file under src/ has a .meta beside it, and no .meta is an
#     orphan: Unity ignores, with a warning, any asset in an immutable package
#     that has no .meta, and it cannot write one there itself;
#   - every .meta guid is 32 hex digits and unique, since two assets sharing a
#     guid break each other's references.
#
# Run from the repository root. Exit status is the verdict.
set -eu

fail() { echo "UNITY PACKAGE CHECK FAILED: $*"; exit 1; }

version=$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' src/Serialize.csproj)
[ -n "$version" ] || fail "src/Serialize.csproj carries no <Version>"
grep -q "\"version\": \"$version\"" src/package.json || fail "src/package.json's version is not $version, the library's"
grep -q '"name": "com.masbandwidth.serialize"' src/package.json || fail "src/package.json is not com.masbandwidth.serialize"
grep -q '"name": "MasBandwidth.Serialize"' src/MasBandwidth.Serialize.asmdef || fail "the asmdef does not name MasBandwidth.Serialize"

files=$(git ls-files src | grep -v '\.meta$')
[ -n "$files" ] || fail "no tracked files under src/"
for f in $files; do
    [ -f "$f.meta" ] || fail "$f has no $f.meta"
done
for m in $(git ls-files 'src/*.meta'); do
    [ -f "${m%.meta}" ] || fail "$m names no asset"
    grep -Eq '^guid: [0-9a-f]{32}$' "$m" || fail "$m has no 32-hex-digit guid"
done
dups=$(git ls-files 'src/*.meta' | xargs sed -n 's/^guid: //p' | sort | uniq -d)
[ -z "$dups" ] || fail "guid shared by two assets: $dups"

echo "unity package: com.masbandwidth.serialize $version, $(echo "$files" | wc -l | tr -d ' ') assets, every one with a unique .meta"
