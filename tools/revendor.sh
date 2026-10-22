#!/bin/sh
# Re-vendors the normative files from the reference repository at a tag, verbatim:
#
#   tools/revendor.sh <tag> [path-to-a-clone-of-mas-bandwidth/serialize]
#
# STANDARD.md, conformance/ and conformance-controls/ are copied from the clone
# checked out at <tag>, replacing what is here, and the diff is printed so the
# port can be read against what changed. Without a clone path the reference is
# cloned into a temporary directory. Exit code is nonzero if the tag does not
# exist.

set -e

TAG="$1"
if [ -z "$TAG" ]; then
    echo "usage: tools/revendor.sh <tag> [path-to-serialize-clone]" >&2
    exit 2
fi

cd "$(dirname "$0")/.."

WORK=""
SOURCE="$2"
if [ -z "$SOURCE" ]; then
    WORK="$(mktemp -d)"
    trap 'rm -rf "$WORK"' EXIT
    git clone --quiet https://github.com/mas-bandwidth/serialize.git "$WORK/serialize"
    SOURCE="$WORK/serialize"
fi

git -C "$SOURCE" -c advice.detachedHead=false checkout --quiet "$TAG"
echo "reference: mas-bandwidth/serialize $TAG @ $(git -C "$SOURCE" rev-parse HEAD)"

cp "$SOURCE/STANDARD.md" STANDARD.md
rm -rf conformance conformance-controls
cp -R "$SOURCE/conformance" conformance
cp -R "$SOURCE/conformance-controls" conformance-controls

git status --short -- STANDARD.md conformance conformance-controls
git --no-pager diff --stat -- STANDARD.md conformance conformance-controls
