#!/bin/sh
# The coverage-guided fuzz run, as one command. Exit code is the verdict: libFuzzer's.
#
#   scripts/fuzz.sh [seconds] [corpus-dir]
#
# Linux x64 only (libfuzzer-dotnet ships no macOS build). Steps:
#   1. fetch libfuzzer-dotnet at a pinned release and check its sha256
#   2. install the SharpFuzz command line tool at a pinned version
#   3. publish fuzz/Fuzz.csproj in Debug (the library's Debug.Assert contracts live,
#      like the C++ reference's Debug fuzz build), restored in locked mode
#   4. instrument the published Serialize.dll with SharpFuzz's edge coverage
#   5. run libFuzzer over it for [seconds] (default 60), growing [corpus-dir] if given
#
# Crash reproducers land in the working directory as crash-*, oom-* and timeout-*
# (libFuzzer's names). Re-run one without libFuzzer, on any OS:
#   dotnet run -c Debug --project fuzz/Fuzz.csproj -- --replay crash-<sha1>
#
# SERIALIZE_FUZZ_SABOTAGE=1 builds the NEGATIVE CONTROL instead: the library with a
# planted write/read asymmetry (SerializeFuzzSabotage, src/Serialize.csproj), which
# this run must then FAIL on. The ci workflow's fuzz job requires that, inverted.

set -e

DURATION=${1:-60}
CORPUS=${2:-}

# pinned tools: bump deliberately, in their own commit, with the new sha256
LIBFUZZER_DOTNET_VERSION=v2025.05.02.0904
LIBFUZZER_DOTNET_SHA256=c2c2a90d94c409a4af339a0d4f244e0442c5a5d249be0f1252ba07871f285958
SHARPFUZZ_VERSION=2.3.0   # SharpFuzz.CommandLine; the SharpFuzz package version lives in fuzz/Fuzz.csproj

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TOOLS="$ROOT/fuzz/.tools"
OUT="$ROOT/fuzz/out"

SABOTAGE=false
if [ "${SERIALIZE_FUZZ_SABOTAGE:-0}" = "1" ]; then
    SABOTAGE=true
    echo "NEGATIVE CONTROL: building the sabotaged library (SerializeFuzzSabotage=true)"
fi

mkdir -p "$TOOLS"

LIBFUZZER="$TOOLS/libfuzzer-dotnet-$LIBFUZZER_DOTNET_VERSION"
if [ ! -x "$LIBFUZZER" ]; then
    curl -fsSL -o "$LIBFUZZER.download" \
        "https://github.com/Metalnem/libfuzzer-dotnet/releases/download/$LIBFUZZER_DOTNET_VERSION/libfuzzer-dotnet-ubuntu"
    echo "$LIBFUZZER_DOTNET_SHA256  $LIBFUZZER.download" | sha256sum -c -
    chmod +x "$LIBFUZZER.download"
    mv "$LIBFUZZER.download" "$LIBFUZZER"
fi

SHARPFUZZ="$TOOLS/sharpfuzz"
if [ ! -x "$SHARPFUZZ" ]; then
    dotnet tool install SharpFuzz.CommandLine --version "$SHARPFUZZ_VERSION" --tool-path "$TOOLS"
fi

rm -rf "$OUT"
dotnet publish "$ROOT/fuzz/Fuzz.csproj" -c Debug -o "$OUT" -p:SerializeFuzzSabotage=$SABOTAGE

# instrument the library under test (and only it: the harness and SharpFuzz itself
# stay uninstrumented, so coverage is the library's)
"$SHARPFUZZ" "$OUT/Serialize.dll"

set -- -max_total_time="$DURATION" -timeout=10 -print_final_stats=1
if [ -n "$CORPUS" ]; then
    mkdir -p "$CORPUS"
    set -- "$@" "$CORPUS"
fi
exec "$LIBFUZZER" --target_path="$OUT/Fuzz" "$@"
