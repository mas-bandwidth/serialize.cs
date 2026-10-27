# serialize.cs

[![CI](https://github.com/mas-bandwidth/serialize.cs/actions/workflows/ci.yml/badge.svg)](https://github.com/mas-bandwidth/serialize.cs/actions/workflows/ci.yml)

![serialize.cs logo with a packed row of colored blocks](images/serialize.png)

**Status: released.** See the [releases page](https://github.com/mas-bandwidth/serialize.cs/releases) for tagged versions.

C# port of the C++ [serialize](https://github.com/mas-bandwidth/serialize) bitpacking
library. Produces bit-for-bit identical output to the C++ library (and to the Go and
Rust ports), so streams written in one language can be read by any other. It
implements **format version 2.0** of [STANDARD.md](STANDARD.md). Wire compatibility is
proven, not asserted: the shared conformance corpus runs on every build with every
refusal checked for its stated reason, a golden wire test pins the standard's 106 byte
whole message, and CI runs a live interop harness against the real
`serialize.h`, compiled with clang++ from a pinned C++ release — on every push to
`main`, on every pull request targeting `main`, and on manual dispatch.

Family values: zero third-party dependencies (including test frameworks); malicious
packet data never throws — reads fail cleanly with a sticky latched error, and the
library throws no exceptions of its own; API misuse — writer contract violations
(out of range values, buffer overflow, oversized strings, strings that are not
well-formed UTF-16 or hold U+0000, NaN and infinite floats and doubles, non-finite
compressed floats and declarations) and trusted call-site parameters (bits
counts, min/max ordering, buffer sizes, Q formats) on every stream — is
`Debug.Assert`, compiled out without the `DEBUG` constant, matching the C++
library's `serialize_assert`. A build with the `DEBUG` constant is what STANDARD.md
calls a **checked build**, and every check that page makes conditional on the build
is conditional on that constant here (STANDARD.md "Writes assume trusted data",
enacted for C# per serialize#52; parameters joined per the 2026-08-16 check-model audit,
serialize.cs#15: minimal runtime checking in release); no unsafe code; zero
allocation on serialization paths (strings on the read path are the documented
exception).

If this library helps you, **[please support it](https://www.patreon.com/MasBandwidth/membership)**

## Getting it

serialize.cs ships as source today. The implementation is ready and the package
is not yet published: `src/Serialize.csproj` carries the package identity
`MasBandwidth.Serialize`, and nothing under that id exists on NuGet. Pushing it
there is a separate round.

Two ways to consume the source, both exact:

**Project reference** — clone the repo beside yours and point at the library
project:

```sh
git clone https://github.com/mas-bandwidth/serialize.cs.git
dotnet add YourProject.csproj reference serialize.cs/src/Serialize.csproj
```

**Copy the files in** — the library is two files, `src/Serialize.cs` and
`src/Int128Pair.cs`. Drop both into your source tree and they compile with the
rest of it: there are no package references to satisfy, ever. This is the Unity
path — put them anywhere under `Assets/`, where the `netstandard2.1` shape CI
tests is the shape you get.

Either way, pin a release tag rather than tracking `main`. The newest is on the
[releases page](https://github.com/mas-bandwidth/serialize.cs/releases): a release states
a format version, and two endpoints interoperate only when they carry the same one.

## Format 2.0

The principle 2.0 adopts (STANDARD.md, Glenn Fiedler, 2026-10-22): **the wire carries
only integers and bytes, and every value has exactly one encoding.** Every finite
value 1.1 could carry keeps its exact bytes. What changed for a C# caller:

- **`SerializeWideString` is gone**, with the `wstring` operation. Text travels as
  `SerializeString`, which is UTF-8. A 1.1 stream carrying a `wstring` field has no
  2.0 reading.
- **`float` and `double` carry finite values only.** A read refuses NaN, any payload
  either sign, and both infinities as `NonFiniteFloat`, tested on the raw bits before
  the destination is written; writing one is a writer contract violation, asserted
  in debug. Negative zero and the subnormals travel bit exact.
- **A compressed float decode is finite.** A read refuses a non-finite decode as
  `NonFiniteFloat` whatever the declaration, and a declaration whose top integer
  decodes to an infinity asserts on write and measure in debug.
- **`int_relative` is canonical.** The absolute tier carrying a difference a bounded
  tier would have taken (69914 or less) is refused as `NonCanonical`, after the domain
  and ordering rule.
- **`SerializeEnd` is new, and a packet reader calls it.** It reads the end of the
  object: a whole byte left over is `TrailingData`, checked first, and a set bit in
  the final byte's padding is `NonzeroPadding`. Writing and measuring it costs
  nothing. Hand the reader exactly the bytes the writer reported:

  ```csharp
  // writer
  WriteStream writer = new WriteStream(buffer);
  writer.SerializeObject(ref packet);
  writer.SerializeEnd();                       // emits nothing
  writer.Flush();
  Send(buffer, (int)writer.BytesProcessed);    // exactly these bytes

  // reader
  ReadStream reader = new ReadStream(received, receivedBytes);
  if (!reader.SerializeObject(ref packet) || !reader.SerializeEnd())
  {
      // refused: reader.Error says why
  }
  ```

  Without the end, trailing bytes and padding go unexamined, and the guarantee that
  one value has one byte sequence does not hold for that read.
- **Every refusal names its reason.** `SerializeError` is the standard's closed list —
  `PastEnd`, `ValueOutOfRange`, `NonzeroPadding`, `TrailingData`, `NonFiniteFloat`,
  `InvalidUtf8`, `EmbeddedNul`, `NonCanonical` — and `SerializeUtil.RefusalName`
  spells each exactly as the standard does (`past_end`, `value_out_of_range`, ...).
  The stream keeps the **first** refusal's reason; later refusals on a failed stream
  are echoes. 1.x's `Overflow`, `Align` and `InvalidString` are `PastEnd`,
  `NonzeroPadding` and the pair `InvalidUtf8` / `EmbeddedNul`. A string's NUL scan
  runs before its UTF-8 check, so a payload that breaks both is `EmbeddedNul`.
- **Wide integers are exact**, as they always were here: 64 and 128 bit values are
  integers end to end, and the corpus now pins the edges a double would lose.

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
- `tools/revendor.sh` — re-vendors `STANDARD.md`, `conformance/` and
  `conformance-controls/` verbatim from a tag of the reference, and prints the diff.
- `.github/workflows/ci.yml` — eight jobs: the Release test matrix and the Debug test
  matrix (all three TFM legs, on Linux, macOS and Windows — Unity's authoring
  platform), the red team run, the checked-arithmetic leg, the conformance controls,
  the analyzer/style check, the C++ interop gate, and the spec-sync check over
  `STANDARD.md`, `conformance/` and `conformance-controls/`.
- `STANDARD.md` — the wire format spec, vendored verbatim from the upstream
  `mas-bandwidth/serialize` repo; the spec-sync job diffs it against upstream and fails
  on drift.
- `conformance/` — the shared conformance corpus, vendored verbatim from the same
  place and checked the same way: one file per covered operation, holding the accepted
  and refused vectors the standard's rules require. `test_conformance_vectors` runs
  every vector in it through this port's two readers — the stream, with and without
  slack past the data, and a `ReadBatch` held open across the whole vector — requiring
  every refusal's stated reason; a vector marked `writer = canonical` back out through
  the writer, one carrying `writer_input` through the writer from that input, and one
  carrying `measure_at_least` through the measure — in Debug and Release and on every
  target the test projects build for.
  The files are discovered by a glob, so a vector added upstream and copied across runs
  without a code change, and an operation this port cannot drive fails rather than being
  skipped. The corpus is written once for the whole family and vendored unchanged — a
  suite that regenerates its own expectations proves only that a port agrees with
  itself.
- `conformance-controls/` — the negative controls, vendored the same way. A corpus file
  whose operation has no runner must fail the run (`test_conformance_unknown_operation`,
  every build), and for each refusal rule a reader with that one rule deleted must fail
  exactly the vectors its `<rule>.expected` names. `-p:SerializeConformanceControls=true`
  compiles the switch that deletes one rule at a time, and `test_conformance_controls`
  runs all fifteen, through the stream and through the batch; CI runs it in its own
  job. Without the property the switch is a constant the JIT folds away.
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
dotnet run -c Release --project tests/Tests.csproj -f net10.0 \
    -p:SerializeConformanceControls=true -- conformance        # the negative controls
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
which need the framework type they check the pair against (61 tests there, 63 on
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

That boundary field is also the one the C# half writes through
`SerializeCompressedFloatPrecomputed` rather than deriving per call. The constants
are what the declaration derives, so the bytes do not move and the C++ half still
writes it plainly — but it puts the precomputed entry point under the byte-identity
`cmp` against the reference implementation, at the value that discriminates a
strictly evaluated quantization from a contracted one, in both directions. The
in-repo differential proves precomputed equals derive-per-call in C#, and this gate
proves derive-per-call equals C++; routing this one field through it is what closes
the triangle against the reference directly.

CI runs this gate in its own job, with `CXX=clang++` and the C++ clone checked out
at release tag `v2.0.1` (format 2.0, first carried by `v2.0.0`) — the family's one
interop pin: one policy, one version,
every port's gate against the same current C++ release. Under the four different
pins this replaced (`v1.6.2` here and in the Go port, `v1.4.3` in Rust, upstream
`HEAD` in C), each port certified against a different wire. `v1.7.0` remains the
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
group offset encodings included. The sequence closes with the end, so each side's
reader refuses a file one byte longer than the other side wrote.

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
  widened from 64 to 128 bits without a wire change. `min <= max` is the legal
  relation, as it is for every ranged operation: a degenerate range where
  `min == max` costs zero bits on the 128 bit width exactly as on the narrower ones —
  the writer emits nothing, the reader takes the value from `min` and consumes
  nothing, and a measure adds zero. Only `SerializeCompressedFloat` is excluded, and
  it requires `min < max`: it is not a ranged operation, and a zero delta has no
  quantization to define.
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
point tail of the golden message, whose whole 106 bytes `test_golden_wire_format`
pins.

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

A schema compiler emits the four literals per field, so the divide, clamp, ceiling
and `BitsRequired` never run at serialization time. The wire bytes are identical to
`SerializeCompressedFloat` by construction: the derive-per-call entry point runs
exactly `SerializeUtil.CompressedFloatParams` and then exactly the precomputed
path's arithmetic. Both are additive — `SerializeCompressedFloat` is untouched. The
constants are trusted call-site parameters like every other range in the library:
constants that are not what `CompressedFloatParams` derives are API misuse,
`Debug.Assert`ed and compiled out of release builds.

**What it is worth here, measured.** Where `min`, `max` and `resolution` reach the
call site as literals — what a schema compiler emits — RyuJIT already constant-folds
the entire derivation, so there is nothing left to hoist: on .NET 10 / arm64 the two
forms compile to the same 2360 bytes of machine code, with no ceiling and no
`BitsRequired` in either, and measure the same (1.99 vs 1.99 ns per field written,
1.90 vs 1.91 read). Reach for this entry point for the single audited home, not for
speed, and do not assume a C# emitter gets a win by switching to it. Where the
declaration is **not** a compile-time constant — a codec holding its declarations in
a table, or reading them from data — the derivation does run per field, and the
precomputed path removes it: 2.82 to 2.19 ns per field written, 2.71 to 2.28 read.

`test_compressed_float_precomputed_differential` holds the derive-per-call path, the
precomputed path and the batch surface to a frozen verbatim copy of the pre-split
v1.4.0 arithmetic — identical measured bits, wire bytes, read acceptance and decoded
bit patterns, compared by bit pattern rather than tolerance, over 18 declarations and
4.4 million checks.

## Reading untrusted data

**A failed read is terminal, and the stream enforces it.** Nothing after a failing
operation has a defined position, so nothing after it is interpretable. This port
satisfies that by latch: the first failure records an error on the stream, every public
read checks it before touching the buffer, and every later read fails consuming no bits
and writing nothing. The failure persists until `Reset` points the stream at a new
buffer. `test_read_terminality` proves it after a failure before consumption, after
partial consumption, on range headroom, on alignment, on a malformed string and on
`SerializeIntRelative`.

**A refused read leaves its destination unwritten.** When a read of a scalar fails,
your value is exactly what it was before the call — no partial value, no zero fill, no
wrap — so a caller who trusts the destination over the return code is not proceeding on
a value the stream never carried. Two things that rule does not reach, per the
standard: a read into a caller-owned buffer, which is `SerializeBytes` and
`SerializeString`, leaves that buffer's contents
**unspecified** after a refusal; and a composite read — `SerializeObject`, or any
sequence of reads over an array — may leave earlier members written, because it is a
sequence of primitive reads and each one carries the rule alone.

One rule follows from the latch: a value that controls a loop must have its result
checked before the loop uses it, otherwise a truncated or malicious packet spins the
loop forever. Use `stream.Continue(ref more)` / `stream.Until(ref done)` for
sentinel-driven loops, and check the result of any serialized loop count before looping
— on a reused stream a failed read leaves the previous packet's count in place.

`SerializeIntRelative` carries the non-negative int32 domain, 0 to 2^31 - 1: both
`previous` and `current` lie in it, and there are no wrapping sequence numbers — a
caller with a wrapping counter unwraps it before serializing. On read every tier
reconstructs `current` in a width that cannot wrap and refuses the read unless the
result is inside the domain and strictly greater than `previous`; the absolute tier's
32 raw bits are unsigned, so a group with the top bit set is outside the domain and
refused. The absolute tier is canonical too: carrying a `current` no more than 69914
above `previous`, which a bounded tier would have taken, it is refused as
`NonCanonical`. `previous` is your own state and never arrives off the wire, so a `previous`
outside the domain is API misuse: `Debug.Assert` on every stream, the read stream
included, and compiled out of release builds.

String content is validated on read (serialize#8, STANDARD.md "string"):
`SerializeString` refuses any NUL as `EmbeddedNul` — the classic two-lengths
smuggling primitive, where the wire length and the C-string length a downstream
consumer perceives disagree — and then bytes that are not well-formed UTF-8 as
`InvalidUtf8`, in that order and in every build mode. An accepted payload decodes to
exactly its characters: no normalization, no replacement character, no stripped byte
order mark, every plane. On write, a string that is not well-formed UTF-16 is a
writer contract violation asserted in debug, because `Encoding.UTF8` would silently
write an unpaired surrogate as U+FFFD.

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
- **Compressed float declarations must decode finite.** When `max - min` overflows to
  infinity (e.g. `[-3.4e38, +3.4e38]`), or the top integer decodes past `FLT_MAX`, the
  declaration is non-conforming: it asserts in debug, and in release a read refuses
  every non-finite decode as `NonFiniteFloat` rather than hand it back. Choose
  declarations whose difference and top decode are finite.

## Contributing

Contributions are accepted under the repository's
[BSD 3-Clause license](LICENSE).

## License

BSD 3-Clause. See [LICENSE](LICENSE).
