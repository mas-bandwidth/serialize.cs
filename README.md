# serialize.cs

**Status: released.** See the [releases page](https://github.com/mas-bandwidth/serialize.cs/releases) for tagged versions.

C# port of the C++ [serialize](https://github.com/mas-bandwidth/serialize) bitpacking
library. Produces bit-for-bit identical output to the C++ library (and to the Go and
Rust ports), so streams written in one language can be read by any other. Wire
compatibility is proven, not asserted: a golden wire test pins 72 bytes copied verbatim
from the C++ test suite, and CI runs a live interop harness against the real
`serialize.h`, compiled with clang++ from a pinned C++ release — on every push to
`main`, on every pull request targeting `main`, and on manual dispatch.

Family values: zero third-party dependencies (including test frameworks); malicious
packet data never throws — reads fail cleanly with a sticky latched error, and the
library throws no exceptions of its own; API misuse — writer contract violations
(out of range values, buffer overflow, oversized strings, ill-formed UTF-16 wstring
payloads, non-finite compressed floats) and trusted call-site parameters (bits
counts, min/max ordering, buffer sizes, Q formats) on every stream — is
`Debug.Assert`, compiled out without the `DEBUG` constant, matching the C++
library's `serialize_assert` (STANDARD.md "Writes assume trusted data", enacted for
C# per serialize#52; parameters joined per the 2026-08-16 check-model audit,
serialize.cs#15: minimal runtime checking in release); no unsafe code; zero
allocation on serialization paths (strings on the read path are the documented
exception).

## Layout

- `src/Serialize.cs` — the streams and the codec, one file (mirrors the C++ single
  header): `BitWriter`, `BitReader`, `IBitStream`, `WriteStream`, `ReadStream`,
  `MeasureStream`, `SerializeUtil`, `ISerializer`, plus the C#-only batch layer
  `WriteBatch` / `ReadBatch` (see below).
- `src/Int128Pair.cs` — `Int128Value` / `UInt128Value`, the emulated 128 bit pair the
  128 bit surface speaks on every target framework (see below).
- `tests/` — console test runner, no test framework: prints each test name, exit code
  is the verdict. Includes the golden wire test, an extended wire test pinning the
  64-bit paths, and deterministic differential/hostile seeded tests.
- `tests-ns21/` — the same test sources compiled against the `netstandard2.1` build of
  the library: the exact assembly surface a Unity project consumes. CI runs it.
- `compat/` — the cross-language interop harness: `Compat.csproj` (C# half) and
  `cpp/compat.cpp` (C++ half, built against the real `serialize.h`).
- `redteam/` — the hostile-input attack harness against the read path. It records
  findings instead of stopping at the first one, so one run gives the whole picture,
  then exits nonzero if any were recorded. CI runs it on every push and pull request;
  the exit code is the verdict.
- `scripts/interop.sh` — the interop gate as one runnable command.
- `.github/workflows/ci.yml` — five jobs: the test matrix (all three TFM legs, on
  Linux, macOS and Windows — Unity's authoring platform), the red team run, the
  analyzer/style check, the C++ interop gate, and the `STANDARD.md` spec-sync check.
- `STANDARD.md` — the wire format spec, vendored verbatim from the C++ repo; the
  spec-sync job diffs it against upstream and fails on drift.
- `SECURITY.md` — how to report a vulnerability privately, and what is in scope.

## Build and test

```sh
dotnet build src/Serialize.csproj                          # builds all three TFMs
dotnet run --project tests/Tests.csproj -f net10.0         # add "short" to skip the 320 MB test
dotnet run --project tests/Tests.csproj -f net8.0          # the LTS leg (needs the .NET 8
                                                           # runtime, or DOTNET_ROLL_FORWARD=LatestMajor)
dotnet run --project tests-ns21/TestsNs21.csproj           # the Unity-class leg: the same tests
                                                           # against the netstandard2.1 assembly
dotnet run --project tests/Tests.csproj -f net10.0 -- golden   # run only tests matching a substring
```

The library targets `net8.0` (LTS game servers), `net10.0`, and `netstandard2.1`
for Unity-class runtimes (Unity 2021+ through Unity 6) — `LangVersion` is pinned
to C# 9 on that target, so anything Unity's compiler would refuse fails here, in
CI, rather than in the editor. The 2.1 target is not a reduced library: shims for
`BitOperations`, the unsigned `BitConverter` bit casts, `Rune` enumeration and
`Utf8.IsValid` sit at the bottom of `Serialize.cs` as the single implementation
every TFM shares — unconditional except `LeadingZeroCount`, which keeps the
hardware intrinsic where it is guaranteed and takes a bit-identical software
fallback everywhere else — and the 128 bit surface runs there too, on the
emulated pair (see below). CI runs the whole suite against the netstandard2.1
assembly, golden wire pins included, which is what proves the shims wire-neutral.
The only tests that leg skips are the two `System.Int128` oracle cross-checks,
which need the framework type they check the pair against (49 tests there, 51 on
`net8.0`/`net10.0`).

## Batches: the hot path for tiny messages

The streams are heap objects, so even with the serialize methods inlined the JIT
reloads and stores the packer state (`scratch`, scratch bits, bits written) around
every call — heap fields cannot live in registers across calls, and on tiny
messages that traffic dominates. A batch lifts the state into the fields of a
`ref struct` at `BeginBatch`, serializes against locals with the same wire logic,
the same validation and the same latched error model — byte-for-byte identical
output, proven by a batch golden-wire test and randomized differential tests —
and stores the state back once at `End`:

```csharp
WriteBatch batch = stream.BeginBatch();   // ReadStream: ReadBatch
batch.SerializeBits(ref value, 8);
// ... the same serialize surface as the stream ...
batch.End();                              // always, on every path out
```

The contract is small: the batch owns the stream between `BeginBatch` and `End`
(stream calls or `Reset` while a batch is open are API misuse); always call `End`
on every path out — it is idempotent, and it is what publishes the batch's work
back to the stream. Fixed-size scalar operations up to 64 bits run
register-resident; everything else — bulk and variable-size operations
(`SerializeBytes`, strings, objects, `SerializeIntRelative`) and the 128 bit and
fixed point operations (`SerializeInt128`, `SerializeUInt128`, `SerializeFixed`) —
delegates to the class path and recaptures, byte identical. Batches are additive:
code that never begins one behaves exactly as before. `IBitStream`-based unified
serialize functions are unchanged — batches are for per-direction hot paths
(e.g. generated code) where tiny-message throughput matters.

Two measured rules (Apple M2, schema harness): pass a batch by ref only to
helpers marked `AggressiveInlining` — a real call taking `ref WriteBatch`
address-exposes the struct and kills enregistration for the whole scope,
measured slower than no batch at all; and batch scalar-dense bodies only — a
body dominated by one bulk op (length int + `SerializeBytes`) pays the batch
capture/restore without winning it back.

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
instead of passing silently. (The Go port's harness builds its C++ half without
`-ffp-contract=off` and carries no boundary value — its only compressed float is
`5.0f`, which quantizes identically either way — so it would not catch fusion. Its
CI runs on x86-64, where the default is no contraction; worth flagging upstream.)

CI runs this gate in its own job, with `CXX=clang++` and the C++ clone checked out
at release tag `v1.7.0` — the family's one interop pin: one policy, one version,
every port's gate against the same current C++ release. Under the four different
pins this replaced (`v1.6.2` here and in the Go port, `v1.4.3` in Rust, upstream
`HEAD` in C), each port certified against a different wire. `v1.7.0` is also the
release that pins the `compressed_float` write arithmetic to float32 with two
roundings on every architecture — the arithmetic `QuantizeCompressedFloat` here
mirrors — so the byte-identity `cmp` doubles as the cross-language proof of that
pin. The old constraint still holds underneath: `serialize.h` before `v1.6.2`
asserts `min < max`, and the compat sequence carries a degenerate range
(`min == max`), so an older clone aborts the gate. The C++ half is built with
asserts live (no `-DNDEBUG`), so that field has to pass against the library's own
checks rather than around them. Bump family-wide, deliberately, in its own commit
per repo. Locally the default compiler is fine and the clone may track HEAD.

The compat sequence's tail is the fixed point / 128 bit section: the six fields the
C++ `GoldenWireData` carries (`Q8.8`, `Q16.16` signed and unsigned, `Q48.16`,
`Q112.16` and `Q64.64` in 128 bit storage), values verbatim, with the golden
message's byte-aligned section structure — so the gate proves the Q format codec
and the emulated 128 bit pair against the real `serialize.h`, three group and four
group offset encodings included.

The spec-sync job deliberately does *not* use the interop tag: it diffs
`STANDARD.md` against upstream `main`, because catching drift against the newest
spec text is the point.

## Fixed point and 128 bit integers

The fixed point + 128 bit additions to the C++ library (merged upstream; in every
release the interop gate can pin) are ported in full. The 128 bit surface speaks `Int128Value` / `UInt128Value` — the
emulated pair in `src/Int128Pair.cs`, two's complement math on `(Hi, Lo)` ulong
halves, mirroring the C++ emulated types — on every target framework, including
`netstandard2.1` where `System.Int128` does not exist. One representation and one
code path everywhere, so wire behavior cannot diverge by framework. On .NET 7+
implicit conversions to and from `System.Int128` / `System.UInt128` make the pair
transparent at call boundaries (a `ref` parameter still needs a pair-typed local —
C# does not convert through `ref`), and the tests cross-check every pair operation
against the framework type as an oracle:

- `SerializeUInt128` — raw, always 128 bits on the wire: the low 64 bit half
  first, then the high half. When the stream is byte aligned the result is the 16
  bytes of the value in little endian order.
- `SerializeInt128` — the ranged counterpart of `SerializeInt64`:
  `SerializeUtil.BitsRequired128(min,max)` bits, computed and offset encoded in
  the unsigned domain (ranges wider than 2^127 are exact), written in 32 bit
  groups from least significant upward. Where the range fits 64 bits or fewer the
  bytes are identical to `SerializeInt64` over the same bounds, so a field can be
  widened from 64 to 128 bits without a wire change.
- `SerializeFixed` — Q format fixed point, one overload per integer storage type
  from 16 to 128 bits, signed and unsigned. The whole unit bounds are shifted to
  raw integer-exact bounds and the raw value is offset encoded in the minimal
  bits for the range; the codec touches no floats, so unlike
  `SerializeCompressedFloat` the round trip is exact and identical on every
  platform. For storage of 64 bits or fewer the wire is byte identical to
  `SerializeInt64` of the raw value over the raw bounds, and `fractionBits = 0`
  is a ranged integer.

Offsets smuggled into the bit headroom past the top of a range are rejected on
read, never clamped. The Q format and bounds are trusted parameters validated as
API misuse (see below), like every other range in the library.

The wire pins for all three operations were derived from STANDARD.md's text by an
independent oracle and cross-checked byte for byte against the pins in the C++
fixed-point test suite; `test_fixed_wire_format` pins the byte aligned fixed
point tail of the C++ 112 byte golden message, leaving the original 72 byte
golden pin untouched.

## Compressed floats from precomputed constants

`SerializeCompressedFloat(ref value, min, max, resolution)` derives four wire
constants on every call, and they depend only on the declaration, never on the
value. `SerializeCompressedFloatPrecomputed` takes them already derived, for
generated code that knows its declarations at code generation time:

```csharp
// once, at code generation time — or once per declaration at startup
SerializeUtil.CompressedFloatParams(-100.0f, 100.0f, 0.01f,
    out uint maxIntegerValue, out int bits, out float delta);   // 20000, 15, 200.0f

// at every call site, on any stream: write, read, measure and both batch surfaces
stream.SerializeCompressedFloatPrecomputed(ref value, maxIntegerValue, bits, delta, min);
```

A schema compiler emits the four literals per field and never pays the per-field
divide, clamp, ceiling and `BitsRequired` at serialization time. The wire bytes are
identical to `SerializeCompressedFloat` by construction: the derive-per-call entry
point runs exactly `SerializeUtil.CompressedFloatParams` and then exactly the
precomputed path's arithmetic. Both are additive — `SerializeCompressedFloat` is
untouched. The constants are trusted call-site parameters like every other range in
the library: constants that are not what `CompressedFloatParams` derives are API
misuse, `Debug.Assert`ed and compiled out of release builds.

`test_compressed_float_precomputed_differential` holds the derive-per-call path, the
precomputed path and the batch surface to a frozen verbatim copy of the pre-split
v1.4.0 arithmetic — identical measured bits, wire bytes, read acceptance and decoded
bit patterns, compared by bit pattern rather than tolerance, over 18 declarations and
4.4 million checks.

## Reading untrusted data

Errors are sticky: the first failure latches on the stream and later serialize calls
are no-ops that leave values unmodified. One rule follows: a value that controls a loop
must have its result checked before the loop uses it, otherwise a truncated or
malicious packet spins the loop forever. Use `stream.Continue(ref more)` /
`stream.Until(ref done)` for sentinel-driven loops, and check the result of any
serialized loop count before looping — on a reused stream a failed read leaves the
previous packet's count in place.

String content is validated on read (serialize#8): `SerializeString` refuses bytes
that are not well-formed UTF-8 and any interior NUL; `SerializeWideString` refuses
unpaired surrogates and interior NULs (each 32-bit group carries one UTF-16 code
unit per STANDARD.md, so a well-formed surrogate pair — an astral character — is
valid, and a group above `0xFFFF` fails with `ValueOutOfRange`). Malformed string
content fails with `InvalidString`, and the refusal happens in every build mode:
an interior NUL is the classic two-lengths smuggling primitive (the wire length
and the C-string length a downstream consumer perceives disagree), and an
unpaired surrogate would otherwise flow into the application as an ill-formed
.NET string.

Two further rules:

- **Ranges are trusted inputs.** `min`, `max`, `resolution`, `bufferSize` and
  fixed point Q format (`integerBits`, `fractionBits`, whole unit bounds)
  parameters are the caller's contract on every stream: `Debug.Assert` in debug
  builds, compiled out in release — exactly like the C++ library, whose
  `serialize_assert` and `static_assert` refusals vanish under `NDEBUG`. If you
  compute a range from previously decoded packet data, validate it before passing
  it in: in release a violated parameter contract yields garbage-in-garbage-out
  bytes (never memory unsafety — the runtime's own bounds checks are the floor),
  and a checked reader rejects the malformed stream.
- **Compressed float ranges must have a finite difference.** When `max - min`
  overflows to infinity (e.g. `[-3.4e38, +3.4e38]`), the read can decode NaN or
  infinity and still report success — behavior inherited from the C++ library for
  wire fidelity. Choose ranges whose difference is finite.

## Contributing

Contributions are accepted under the Más Bandwidth
[Contributor Assignment Agreement](https://github.com/mas-bandwidth/.github/blob/main/CAA.md)
(CAA). Before a pull request can merge, every human commit author on it signs by
posting this exact sentence as a comment on the pull request:

> I have read the CAA and I hereby sign it, assigning copyright in my contributions to Más Bandwidth LLC.

The signature ledger is organization-wide: signing once, on any Más Bandwidth
repository, covers all of them. The check runs automatically on every pull
request (`.github/workflows/cla.yml`); commenting `recheck` re-runs it after a
signature lands.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
