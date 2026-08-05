# serialize.cs

**Status: DRAFT** — not yet released.

C# port of the C++ [serialize](https://github.com/mas-bandwidth/serialize) bitpacking
library. Produces bit-for-bit identical output to the C++ library (and to the Go and
Rust ports), so streams written in one language can be read by any other. Wire
compatibility is proven, not asserted: a golden wire test pins 72 bytes copied verbatim
from the C++ test suite, and a live interop harness cross-checks against the real
`serialize.h` compiled with clang++.

Family values: zero third-party dependencies (including test frameworks); malicious
packet data never throws — reads fail cleanly with a sticky latched error (exceptions
are reserved for API misuse); no unsafe code; zero allocation on serialization paths
(strings on the read path are the documented exception).

## Layout

- `src/Serialize.cs` — the whole library, one file (mirrors the C++ single header):
  `BitWriter`, `BitReader`, `IBitStream`, `WriteStream`, `ReadStream`, `MeasureStream`,
  `SerializeUtil`, `ISerializer`.
- `tests/` — console test runner, no test framework: prints each test name, exit code
  is the verdict. Includes the golden wire test, an extended wire test pinning the
  64-bit paths, and deterministic differential/hostile seeded tests.
- `compat/` — the cross-language interop harness: `Compat.csproj` (C# half) and
  `cpp/compat.cpp` (C++ half, built against the real `serialize.h`).
- `scripts/interop.sh` — the interop gate as one runnable command.
- `STANDARD.md` — the wire format spec, vendored verbatim from the C++ repo
  (family precedent: CI should diff it against upstream and fail on drift).

## Build and test

```sh
dotnet build src/Serialize.csproj                          # builds net8.0 + net10.0
dotnet run --project tests/Tests.csproj -f net10.0         # add "short" to skip the 320 MB test
dotnet run --project tests/Tests.csproj -f net8.0          # the LTS leg (needs the .NET 8
                                                           # runtime, or DOTNET_ROLL_FORWARD=LatestMajor)
dotnet run --project tests/Tests.csproj -f net10.0 -- golden   # run only tests matching a substring
```

The library targets `net8.0` (LTS game servers) and `net10.0`. A
`netstandard2.1` target for Unity-class runtimes is an open deliverable: it needs
shims for `BitOperations`, the unsigned `BitConverter` bit casts, `Rune`
enumeration and `Utf8.IsValid`, each proven wire-neutral by the golden test per
TFM before it ships.

## Interop gate (head-to-head vs C++)

```sh
scripts/interop.sh path/to/serialize    # or run the steps below by hand
```

```sh
clang++ -O2 -std=c++17 -ffp-contract=off -Wall -I path/to/serialize -o compat-cpp compat/cpp/compat.cpp
dotnet run --project compat/Compat.csproj -- write cs.bin
./compat-cpp write cpp.bin
cmp cs.bin cpp.bin                                  # must be byte identical
dotnet run --project compat/Compat.csproj -- read cpp.bin
./compat-cpp read cs.bin
```

`-ffp-contract=off` on the C++ build is required, not optional: strict IEEE
evaluation is the normative wire for compressed floats. Default clang/gcc on ARM64
contract the quantization `normalized * maxInteger + 0.5f` into a fused
multiply-add, which rounds differently within 1 ULP of a `.5` boundary and shifts
the written integer by one wire quantum (~1 in 10^7 values). C# and Rust always
evaluate strictly; the compat sequence carries a value pinned on such a boundary
(`0.005f` in `[0,10]` res `0.01`), so a contracted C++ build fails the `cmp`
instead of passing silently. (The Go port on ARM64 currently fuses and should be
flagged upstream.)

When CI is created, pin the C++ clone to one release tag — the Go and Rust ports
pin `v1.4.3`; the sibling clone here is currently at a later head — and pick one
tag for both the interop job and the spec-sync job.

## Reading untrusted data

Errors are sticky: the first failure latches on the stream and later serialize calls
are no-ops that leave values unmodified. One rule follows: a value that controls a loop
must have its result checked before the loop uses it, otherwise a truncated or
malicious packet spins the loop forever. Use `stream.Continue(ref more)` /
`stream.Until(ref done)` for sentinel-driven loops, and check the result of any
serialized loop count before looping — on a reused stream a failed read leaves the
previous packet's count in place.

Two further rules:

- **Ranges are trusted inputs.** `min`, `max`, `resolution` and `bufferSize`
  parameters are validated as API misuse and throw `ArgumentException` — even on a
  stream with a latched error. If you compute a range from previously decoded packet
  data, validate it before passing it in, or one malicious packet becomes an
  unhandled exception.
- **Compressed float ranges must have a finite difference.** When `max - min`
  overflows to infinity (e.g. `[-3.4e38, +3.4e38]`), the read can decode NaN or
  infinity and still report success — behavior inherited from the C++ library for
  wire fidelity. Choose ranges whose difference is finite.

## License

License is pending the owner's decision; no license file is included yet.
