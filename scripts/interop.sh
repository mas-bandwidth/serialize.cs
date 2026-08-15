#!/bin/sh
# The cross-language interop gate, runnable as one command. Exit code is the verdict.
#
#   scripts/interop.sh [path-to-cpp-serialize-clone]
#
# Builds the C++ half of the compat harness against the real serialize.h, then:
# both sides write, the files must be byte identical, and each side reads the other's.
#
# -ffp-contract=off is REQUIRED on the C++ build: strict IEEE evaluation is the
# normative wire. Default clang/gcc on ARM64 fuse the compressed float quantization
# into an FMA, which shifts the written integer by one wire quantum on rounding
# boundaries; the compat sequence contains a value pinned on such a boundary so a
# contracted build fails this gate instead of passing silently.
#
# CI pins the C++ clone to release tag v1.7.0 and runs this script with CXX=clang++;
# locally the default compiler is fine (Apple clang on macOS) and the clone may track
# HEAD. v1.7.0 is the family's one interop pin -- one policy, one version, every
# port's gate against the same current C++ release -- and it is the release that
# pins the compressed_float write arithmetic to float32 with two roundings on every
# architecture, so the byte-identity cmp doubles as the cross-language proof of that
# pin. The old floor still applies underneath: serialize.h before v1.6.2 asserts
# min < max, and the compat sequence carries a degenerate range (min == max), so an
# older clone aborts here.
#
# The C++ half is built WITHOUT -DNDEBUG on purpose: serialize_assert stays live, so
# the degenerate range has to pass with the library's own asserts enabled.

set -e

cd "$(dirname "$0")/.."

CXX="${CXX:-c++}"
CPP_SERIALIZE="${1:-../serialize}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== building C++ compat harness against $CPP_SERIALIZE"
"$CXX" -O2 -std=c++17 -ffp-contract=off -Wall -I "$CPP_SERIALIZE" -o "$WORK/compat-cpp" compat/cpp/compat.cpp

echo "== both sides write"
dotnet run -c Release --project compat/Compat.csproj -- write "$WORK/cs.bin"
"$WORK/compat-cpp" write "$WORK/cpp.bin"

echo "== byte identity"
cmp "$WORK/cs.bin" "$WORK/cpp.bin"

echo "== cross reads"
dotnet run -c Release --project compat/Compat.csproj -- read "$WORK/cpp.bin"
"$WORK/compat-cpp" read "$WORK/cs.bin"

echo "INTEROP GATE PASSED"
