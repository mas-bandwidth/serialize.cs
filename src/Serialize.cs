/*
    Serialize.cs

    C# port of the C++ serialize bitpacking library (github.com/mas-bandwidth/serialize).

    The wire format is frozen and bit-for-bit identical to the C++ library: streams
    written in one language can be read by the other. The bit stream is written to
    memory in little endian order, which is considered network byte order for this
    library.

    Family invariants:
      1. Wire format frozen, proven by pinned golden bytes and a live C++ interop harness.
      2. Malicious packet data never throws: reads fail cleanly with a latched error.
         API misuse is Debug.Assert (the C++ serialize_assert analog), compiled out
         of release builds — the library throws no exceptions of its own.
      3. Zero third-party dependencies.
      4. Zero allocation on serialization paths (strings on the read path are the
         documented exception, consistent with the Go and Rust ports).

    Writes are trusted (STANDARD.md: "Writes assume trusted data — doctrine,
    ratified"; enacted for C# per serialize#52, the ruling verbatim: "Yes, then let
    C# match C++ too"): the write path performs NO validation of values or buffer
    capacity in release builds. Writer contract violations — a value outside its
    declared range, a write past the end of the buffer, a string that does not fit
    its buffer size, a non-finite compressed float value or declaration — are
    Debug.Assert, compiled out without the DEBUG constant, exactly as the C++
    library's serialize_assert compiles out under NDEBUG. A misbehaving writer in a
    release build is owed nothing: the bytes are unspecified (garbage in, garbage
    out; memory safety is the runtime's, not the library's). Trusted call-site
    PARAMETERS (bits counts, min/max ordering, buffer sizes, Q formats) are the
    same contract on every stream, read and write alike: Debug.Assert in debug
    builds, compiled out in release (the 2026-08-16 six-language check-model audit;
    the standard verbatim: "We want MINIMAL runtime checking in release"). The
    checks readers keep in every build mode validate PACKET DATA, never arguments:
    buffer-end, range, align and string-content refusals all latch errors, and the
    runtime's own array bounds checks remain the memory-safety floor.

    Error model (Go style, sticky): the first failure latches on the stream, every later
    serialize call returns false without touching the stream or the value, and the
    latched error is available from the Error property. You can check every call or
    serialize a whole object and check Error once at the end — with one rule: a value
    that controls a loop must have its result checked before the loop uses it, because
    after an error values are never updated again and a loop waiting for one spins
    forever on a truncated or malicious packet. Use SerializeUtil.Continue and
    SerializeUtil.Until for sentinel-driven loops. On a write or measure stream the
    only failure the library itself can latch is a user abort through SerializeObject
    (an object's Serialize returning false): write-side validation is debug asserts,
    so healthy write-mode serialize calls always return true.

    This file mirrors the single-header layout of the C++ original:
    error model / utilities / BitWriter / BitReader / stream interface / WriteStream /
    ReadStream / MeasureStream, followed by the C#-only batch layer:
    WriteBatch / ReadBatch (register-resident hot paths over the same streams).
*/

using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Text;

namespace Serialize
{
// NOTE: the namespace is a BLOCK, not file-scoped (C# 10), because Unity-class
// compilers are C# 9 — the body keeps its original single-level indentation
// to hold the diff to the wrap itself.

/// <summary>
/// The first failure latched on a stream. None until a serialize call fails.
/// </summary>
public enum SerializeError
{
    /// <summary>No error: the stream is healthy.</summary>
    None = 0,

    /// <summary>A read would go past the end of the buffer. Only reads latch this:
    /// on write, exceeding the buffer is a writer contract violation, caught by
    /// Debug.Assert in debug builds and unchecked in release (writes are
    /// trusted).</summary>
    Overflow,

    /// <summary>A value is outside the range it is serialized with. On read this
    /// typically means the packet is corrupt or maliciously crafted; reads latch it
    /// in every build mode. It also latches when a user's Serialize function aborts
    /// through SerializeObject. On write, an out of range value is a writer contract
    /// violation, caught by Debug.Assert in debug builds and unchecked in release
    /// (writes are trusted).</summary>
    ValueOutOfRange,

    /// <summary>The zero pad bits read by an align are not zero. This typically means
    /// the read and write serialize functions don't match.</summary>
    Align,

    /// <summary>A string payload read from the stream is malformed: bytes that are
    /// not valid UTF-8, an interior NUL (either width — the wire length and the
    /// C-string length a consumer perceives would disagree), or, for wide strings,
    /// ill-formed UTF-16 (an unpaired surrogate). Readers refuse malformed string
    /// content in every build mode (serialize#8 ruling; the write side is the
    /// writer's contract, debug-asserted).</summary>
    InvalidString,
}

/// <summary>
/// Implemented by objects that serialize themselves to a stream. Write one Serialize
/// method per type and it works for write, read and measure.
///
/// Return false to abort serialization: the standard pattern is to call serialize
/// methods for each field and return stream.Ok at the end.
///
/// Struct implementers must be serialized through the generic
/// SerializeObject&lt;T&gt;(ref T) overload: passing a struct to the non-generic
/// SerializeObject(ISerializer) boxes a copy, the read fills the box, and the caller's
/// struct is silently left unchanged.
///
/// IMPORTANT: A value that controls how much more work your serialize function does —
/// a loop count or a continuation bit — must have its serialize result checked before
/// you use it. Once an error latches, serialize calls are no-ops that leave values
/// unmodified, so a loop waiting for a serialized value to change spins forever on a
/// truncated or malicious packet. Use SerializeUtil.Continue or SerializeUtil.Until for
/// sentinel-driven loops.
/// </summary>
public interface ISerializer
{
    /// <summary>Serializes this object's fields against the stream: one function that
    /// writes, reads or measures depending on the stream passed. Returns true on
    /// success; the standard body ends with <c>return stream.Ok;</c>.</summary>
    bool Serialize(IBitStream stream);
}

/// <summary>
/// The unified serialization interface implemented by WriteStream, ReadStream and
/// MeasureStream. It is the C# equivalent of the templated stream parameter in the C++
/// serialize library: write one serialize function against IBitStream and it handles
/// write, read and measure.
///
/// All serialize methods take ref parameters so the same call reads or writes the value
/// depending on the stream. Every method returns true on success; after the first
/// failure the error latches on the stream (see Error) and every later call returns
/// false without touching the stream.
///
/// Write serialize functions against plain IBitStream parameters. Do not reach for
/// <c>Serialize&lt;TStream&gt;(TStream) where TStream : IBitStream</c> as an
/// optimization: the streams are sealed classes, so the shared generic instantiation
/// still dispatches through the interface and only adds generic-context overhead —
/// measured slower than the plain interface parameter.
/// </summary>
public interface IBitStream
{
    /// <summary>True if the stream writes or measures values (WriteStream and
    /// MeasureStream), false if it reads them.</summary>
    bool IsWriting { get; }

    /// <summary>True if the stream reads values (ReadStream).</summary>
    bool IsReading { get; }

    /// <summary>Serializes the low order bits of an unsigned integer. bits must be in
    /// [1,32]. A value in [0,31] can be serialized with just 5 bits and so on.</summary>
    bool SerializeBits(ref uint value, int bits);

    /// <summary>Serializes the low order bits of a 64 bit unsigned integer. bits must
    /// be in [1,64]. Values wider than 32 bits go low dword first.</summary>
    bool SerializeBits64(ref ulong value, int bits);

    /// <summary>Serializes a signed integer in [min,max], using only the bits required
    /// to represent the range. On read the value is guaranteed to be in [min,max] if
    /// the call succeeds.</summary>
    bool SerializeInt(ref int value, int min, int max);

    /// <summary>Serializes a signed 64 bit integer in [min,max], using only the bits
    /// required to represent the range. The full 64 bit range is supported.</summary>
    bool SerializeInt64(ref long value, long min, long max);

    /// <summary>Serializes a signed 128 bit integer in [min,max], using only the bits
    /// required to represent the range. The full 128 bit range is supported: the bit
    /// count and offset arithmetic run in the unsigned domain, so ranges wider than
    /// 2^127 are exact. The offset is written in 32 bit groups from least significant
    /// upward, so where the range fits 64 bits or fewer the bytes are identical to
    /// SerializeInt64 over the same bounds — a field can be widened from 64 to 128
    /// bits without changing the wire, provided the bounds do not change. On read the
    /// value is guaranteed to be in [min,max] if the call succeeds.</summary>
    bool SerializeInt128(ref Int128Value value, Int128Value min, Int128Value max);

    /// <summary>Serializes a byte (an unsigned 8 bit integer). Wire compatible with
    /// serialize_uint8 in the C++ library; the name follows the C# type vocabulary, as
    /// each port uses its own (Go SerializeUint8, Rust serialize_u8).</summary>
    bool SerializeByte(ref byte value);

    /// <summary>Serializes an unsigned 16 bit integer.</summary>
    bool SerializeUInt16(ref ushort value);

    /// <summary>Serializes an unsigned 32 bit integer.</summary>
    bool SerializeUInt32(ref uint value);

    /// <summary>Serializes an unsigned 64 bit integer (low dword first).</summary>
    bool SerializeUInt64(ref ulong value);

    /// <summary>Serializes an unsigned 128 bit integer. Always 128 bits on the wire:
    /// the low 64 bit half first, then the high half, each half low dword first —
    /// when the stream is byte aligned the result is the 16 bytes of the value in
    /// little endian order. Not ranged: do not confuse this with SerializeInt128,
    /// which uses only the bits the range requires.</summary>
    bool SerializeUInt128(ref UInt128Value value);

    /// <summary>Serializes a boolean value with one bit.</summary>
    bool SerializeBool(ref bool value);

    /// <summary>Serializes an uncompressed 32 bit floating point value.</summary>
    bool SerializeFloat(ref float value);

    /// <summary>Serializes an uncompressed 64 bit floating point value.</summary>
    bool SerializeDouble(ref double value);

    /// <summary>Serializes a floating point value in [min,max] with the given
    /// resolution, using only the bits required for the quantized range. On write the
    /// value is clamped into [min,max]; on read it is guaranteed to be in [min,max] if
    /// the call succeeds and max - min is finite. min, max and resolution are trusted
    /// parameters, and a declaration whose max - min overflows to infinity (for
    /// example min = -3.4e38f, max = +3.4e38f) is NON-CONFORMING (ruled 2026-08-15):
    /// it asserts in debug builds, and in a release build the quantization is
    /// meaningless — decoded values can be infinite or NaN even though the call
    /// succeeds. Sending a non-finite value (NaN, ±infinity) is likewise
    /// non-conforming and asserts on write in debug builds; in release it is
    /// silently clamped into range (NaN to the low end).</summary>
    bool SerializeCompressedFloat(ref float value, float min, float max, float resolution);

    /// <summary>Serializes a compressed float from precomputed wire constants — the
    /// precomputed companion to SerializeCompressedFloat, designed for generated
    /// code: a schema compiler derives maxIntegerValue, bits and delta from the
    /// declaration at code generation time with the same arithmetic as
    /// SerializeUtil.CompressedFloatParams and passes them as literals, so the
    /// per-field derivation (a divide, a clamp, a ceiling and a BitsRequired) is
    /// never paid at serialization time. Wire bytes are identical to
    /// SerializeCompressedFloat by construction. The constants must be exactly what
    /// SerializeUtil.CompressedFloatParams derives for a conforming declaration —
    /// anything else is a caller bug, debug-asserted per the writer-trusted model.
    /// On write the value is clamped into the declared range and quantized; sending
    /// a non-finite value is non-conforming and asserts in debug builds. On read, an
    /// integer above maxIntegerValue smuggled into the bit headroom fails with
    /// SerializeError.ValueOutOfRange.</summary>
    /// <param name="value">The float value to serialize. Written on write/measure,
    /// filled in on read.</param>
    /// <param name="maxIntegerValue">The quantization step count, in
    /// [1,4294967040].</param>
    /// <param name="bits">The wire width in bits. Must equal
    /// SerializeUtil.BitsRequired(0, maxIntegerValue).</param>
    /// <param name="delta">The range width max - min, in float32.</param>
    /// <param name="min">The minimum float value of the range.</param>
    bool SerializeCompressedFloatPrecomputed(ref float value, uint maxIntegerValue, int bits, float delta, float min);

    /// <summary>Serializes a fixed point value held in signed 64 bit storage as
    /// Q integerBits.fractionBits, where the raw integer is the real value scaled by
    /// 2^fractionBits and the sign bit counts toward integerBits (Q48.16 in a long is
    /// (48, 16)). min and max are bounds in whole real units; integerBits +
    /// fractionBits must equal the storage width, and all four parameters are part of
    /// the wire format, exactly like a ranged integer's bounds — they are trusted
    /// inputs, validated as API misuse. The raw value is serialized as an offset from
    /// min &lt;&lt; fractionBits in the minimal number of bits for the raw range; for
    /// storage of 64 bits or fewer the bytes are identical to SerializeInt64 of the
    /// raw value over the raw bounds, and with fractionBits = 0 the operation is a
    /// ranged integer. No float is ever involved, so unlike SerializeCompressedFloat
    /// the round trip is exact and deterministic on every platform. On read the raw
    /// value is guaranteed to be within the bounds if the call succeeds — out of
    /// range offsets are rejected, never clamped.</summary>
    bool SerializeFixed(ref long value, int integerBits, int fractionBits, long min, long max);

    /// <summary>Serializes a fixed point value held in unsigned 64 bit storage as
    /// Q integerBits.fractionBits. See the signed 64 bit overload for the
    /// contract.</summary>
    bool SerializeFixed(ref ulong value, int integerBits, int fractionBits, long min, long max);

    /// <summary>Serializes a fixed point value held in signed 32 bit storage as
    /// Q integerBits.fractionBits (Q16.16 in an int is (16, 16)). See the signed
    /// 64 bit overload for the contract.</summary>
    bool SerializeFixed(ref int value, int integerBits, int fractionBits, long min, long max);

    /// <summary>Serializes a fixed point value held in unsigned 32 bit storage as
    /// Q integerBits.fractionBits. See the signed 64 bit overload for the
    /// contract.</summary>
    bool SerializeFixed(ref uint value, int integerBits, int fractionBits, long min, long max);

    /// <summary>Serializes a fixed point value held in signed 16 bit storage as
    /// Q integerBits.fractionBits (Q8.8 in a short is (8, 8)). See the signed 64 bit
    /// overload for the contract.</summary>
    bool SerializeFixed(ref short value, int integerBits, int fractionBits, long min, long max);

    /// <summary>Serializes a fixed point value held in unsigned 16 bit storage as
    /// Q integerBits.fractionBits. See the signed 64 bit overload for the
    /// contract.</summary>
    bool SerializeFixed(ref ushort value, int integerBits, int fractionBits, long min, long max);

    /// <summary>Serializes a fixed point value held in signed 128 bit storage as
    /// Q integerBits.fractionBits (Q112.16 in an Int128Value is (112, 16), Q64.64 is
    /// (64, 64)). The offset is written in 32 bit groups from least significant
    /// upward, up to four groups. See the signed 64 bit overload for the rest of the
    /// contract.</summary>
    bool SerializeFixed(ref Int128Value value, int integerBits, int fractionBits, long min, long max);

    /// <summary>Serializes a fixed point value held in unsigned 128 bit storage as
    /// Q integerBits.fractionBits. See the 128 bit signed overload for the
    /// contract.</summary>
    bool SerializeFixed(ref UInt128Value value, int integerBits, int fractionBits, long min, long max);

    /// <summary>Serializes an array of bytes. The stream aligns to a byte boundary
    /// first, then block copies the data. Both sides must know the length: it is not
    /// sent.</summary>
    bool SerializeBytes(Span<byte> data);

    /// <summary>Serializes a string of fewer than bufferSize UTF-8 bytes: the length is
    /// serialized in [0,bufferSize-1], the stream aligns to a byte boundary, then the
    /// UTF-8 bytes are block copied. bufferSize mirrors the C++ API, where a string with
    /// its terminating null character must fit into the buffer, keeping streams
    /// compatible between the two languages. On read, bytes that are not valid UTF-8
    /// or that contain an interior NUL fail with SerializeError.InvalidString.</summary>
    bool SerializeString(ref string value, int bufferSize);

    /// <summary>Serializes a string as 32 bits per UTF-16 code unit, wire compatible
    /// with serialize_wstring in the C++ library (STANDARD.md, adopted 2026-08-15:
    /// one code unit per group, not one code point). The length is serialized in
    /// [0,bufferSize-1] code units. Surrogate pairs are valid — an astral character
    /// is two groups; the payload being well-formed UTF-16 is the writer's contract,
    /// debug-asserted. On read, a group above 0xFFFF fails with
    /// SerializeError.ValueOutOfRange (not a code unit — and char could not hold it:
    /// fail rather than truncate); an unpaired surrogate or an interior NUL fails
    /// with SerializeError.InvalidString.</summary>
    bool SerializeWideString(ref string value, int bufferSize);

    /// <summary>Pads the stream with zero bits to the next byte boundary. On read the
    /// padding is verified to be zero.</summary>
    bool SerializeAlign();

    /// <summary>Serializes an object that implements ISerializer. For struct
    /// implementers use the generic SerializeObject&lt;T&gt;(ref T) overload instead:
    /// this one boxes a copy of a struct and the caller's struct is silently left
    /// unchanged on read.</summary>
    bool SerializeObject(ISerializer obj);

    /// <summary>Serializes an object that implements ISerializer, by ref. This is the
    /// overload to use for struct implementers: it does not box, so on read the
    /// caller's struct receives the deserialized fields.</summary>
    bool SerializeObject<T>(ref T obj) where T : ISerializer;

    /// <summary>Serializes an integer relative to a previous integer, using fewer bits
    /// the closer the two values are. previous must be less than current.</summary>
    bool SerializeIntRelative(int previous, ref int current);

    /// <summary>The number of bits required to align the stream to the next byte
    /// boundary, in [0,7]. MeasureStream always answers the conservative worst case
    /// 7.</summary>
    int AlignBits { get; }

    /// <summary>The number of bits written to, read from or measured on the
    /// stream.</summary>
    long BitsProcessed { get; }

    /// <summary>The number of bits processed rounded up to the next byte. After
    /// writing, this is effectively the packet size.</summary>
    long BytesProcessed { get; }

    /// <summary>The first error latched on the stream, or SerializeError.None.</summary>
    SerializeError Error { get; }

    /// <summary>True while no error is latched on the stream. The canonical ending of
    /// a serialize function is <c>return stream.Ok;</c>.</summary>
    bool Ok { get; }

    /// <summary>An arbitrary context value passed through to serialize functions, for
    /// example lookup tables or min/max ranges needed to read and write values. It
    /// mirrors the context pointer in the C++ library.</summary>
    object? Context { get; set; }
}

/// <summary>
/// Bit twiddling utilities and the sentinel-loop guards for reading untrusted data.
/// </summary>
public static class SerializeUtil
{
    /// <summary>Returns the number of bits required to serialize an integer in range
    /// [min,max]. The result is in [0,32].</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int BitsRequired(uint min, uint max)
    {
        return min == max ? 0 : 32 - SerializeCompat.LeadingZeroCount(max - min);
    }

    /// <summary>Returns the number of bits required to serialize a 64 bit integer in
    /// range [min,max]. The result is in [0,64].</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int BitsRequired64(ulong min, ulong max)
    {
        // subtract in the unsigned domain: the range may be wider than 2^63
        return min == max ? 0 : 64 - SerializeCompat.LeadingZeroCount(max - min);
    }

    /// <summary>Returns the number of bits required to serialize a 128 bit integer in
    /// range [min,max]. The result is in [0,128]. The subtraction is performed in the
    /// unsigned domain, so ranges wider than 2^127 are exact.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int BitsRequired128(UInt128Value min, UInt128Value max)
    {
        if (min == max)
        {
            return 0;
        }
        // subtract in the unsigned domain: the range may be wider than 2^127
        UInt128Value diff = max - min;
        ulong high = (ulong)(diff >> 64);
        return high != 0 ? 64 + BitsRequired64(0, high) : BitsRequired64(0, (ulong)diff);
    }

    /// <summary>Converts a signed integer to an unsigned integer with zig-zag encoding.
    /// 0,-1,+1,-2,+2... becomes 0,1,2,3,4...</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint SignedToUnsigned(int n)
    {
        return ((uint)n << 1) ^ (0u - ((uint)n >> 31));
    }

    /// <summary>Converts an unsigned integer to a signed integer with zig-zag encoding.
    /// 0,1,2,3,4... becomes 0,-1,+1,-2,+2...</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int UnsignedToSigned(uint n)
    {
        return (int)((n >> 1) ^ (0u - (n & 1)));
    }

    /// <summary>
    /// Derives the compressed float wire constants from a (min, max, resolution)
    /// declaration. This is the derivation SerializeCompressedFloat performs on
    /// every call, exposed so it can be paid once instead: the constants depend only
    /// on the declaration, never on the value, so a schema compiler runs the same
    /// derivation at code generation time and passes the results to
    /// SerializeCompressedFloatPrecomputed at every call site.
    /// SerializeCompressedFloat itself derives with exactly this function and its
    /// serialization is statement for statement the precomputed entry point, so the
    /// two are wire identical by construction. The quantized range is clamped so it
    /// always fits in a uint, even for pathological delta / resolution ratios; the
    /// !&gt;= form of the clamp also catches NaN. A declaration whose
    /// delta = max - min (or delta / resolution) overflows to infinity is
    /// NON-CONFORMING — ruled 2026-08-15 ("it's non-conforming") — and asserts here
    /// at the param site in debug builds. Declarations are trusted call-site
    /// parameters, so the assert fires for whichever direction evaluates the
    /// non-conforming declaration; no release path carries the check, and no
    /// read-side check of packet data is affected. In release the old behavior
    /// remains: the call succeeds and decoded values can be infinite or NaN
    /// (garbage in, garbage out).
    /// </summary>
    /// <param name="min">The minimum float value. Must be less than max.</param>
    /// <param name="max">The maximum float value.</param>
    /// <param name="resolution">The resolution the float value is quantized
    /// to.</param>
    /// <param name="maxIntegerValue">The quantization step count:
    /// ceiling((max - min) / resolution), clamped to [1,4294967040]. Values quantize
    /// to integers in [0,maxIntegerValue].</param>
    /// <param name="bits">The wire width: BitsRequired(0, maxIntegerValue), the
    /// number of bits a quantized value occupies on the wire, in [1,32].</param>
    /// <param name="delta">The range width max - min, computed in float32. The
    /// quantization arithmetic is pinned to float32, so the wire depends on this
    /// exact value, not on the real-number difference.</param>
    public static void CompressedFloatParams(
        float min, float max, float resolution,
        out uint maxIntegerValue, out int bits, out float delta)
    {
        Debug.Assert(min < max && resolution > 0, SerializeInternal.FloatParamsMessage);

        delta = max - min;

        // finite min < max cannot produce NaN, only an infinite overflow
        Debug.Assert(!float.IsInfinity(delta), SerializeInternal.FloatDeltaAssertMessage);

        float values = delta / resolution;

        Debug.Assert(!float.IsInfinity(values), SerializeInternal.FloatValuesAssertMessage);

        if (!(values >= 1.0f))
        {
            values = 1.0f;
        }
        else if (values > 4294967040.0f) // largest float below 2^32
        {
            values = 4294967040.0f;
        }

        maxIntegerValue = (uint)Math.Ceiling((double)values);

        bits = BitsRequired(0, maxIntegerValue);
    }

    /// <summary>
    /// Serializes <paramref name="more"/> as a single continuation bit and reports
    /// whether a sentinel-driven loop should proceed, folding the stream error state
    /// into the loop condition: it returns false as soon as the stream has an error, so
    /// loops of this form always terminate on truncated or malicious data, bounded by
    /// the size of the packet.
    ///
    /// Never write the loop as <c>while (hasNext) { stream.SerializeBool(ref hasNext); ... }</c>:
    /// once the stream has an error the failed read leaves hasNext unmodified and the
    /// loop never exits.
    ///
    /// This is an extension method, so it reads <c>while (stream.Continue(ref more))</c>.
    /// </summary>
    public static bool Continue(this IBitStream stream, ref bool more)
    {
        if (!stream.SerializeBool(ref more))
        {
            return false;
        }
        return more;
    }

    /// <summary>
    /// Serializes <paramref name="done"/> as a single termination bit and reports
    /// whether a sentinel-driven loop should proceed. The inverse of Continue, for wire
    /// formats that mark the end of a sequence with a true bit instead of marking each
    /// element with a continuation bit. Like Continue, it returns false as soon as the
    /// stream has an error, so loops of this form always terminate on truncated or
    /// malicious data, bounded by the size of the packet.
    /// </summary>
    public static bool Until(this IBitStream stream, ref bool done)
    {
        if (!stream.SerializeBool(ref done))
        {
            return false;
        }
        return !done;
    }
}

/// <summary>
/// Shared internals: API-misuse Debug.Assert messages, the int-relative difference
/// buckets and the compressed float quantization arithmetic (the derivation itself
/// is public API: SerializeUtil.CompressedFloatParams).
/// </summary>
internal static class SerializeInternal
{
    // API misuse assert messages (parameters are the caller's contract on every
    // stream): Debug.Assert, never seen in release builds.
    internal const string BitsRangeMessage = "bits must be in [1,32]";
    internal const string BitsRange64Message = "bits must be in [1,64]";
    internal const string MinMaxMessage = "min must not be greater than max";
    internal const string BufferSizeMessage = "string buffer size must be at least 2";
    internal const string FloatParamsMessage = "compressed float requires min < max and resolution > 0";
    internal const string WriteOverflowMessage = "bit writer overflow";
    internal const string ReadOverflowMessage = "bit reader would read past the end of the buffer";
    internal const string NotAlignedMessage = "byte array serialization requires byte alignment";
    internal const string BufferBytesMessage = "bit writer buffer size must be a multiple of 8 bytes";
    internal const string ReaderBytesMessage = "bytes must be in [0, buffer.Length]";
    internal const string FixedIntegerBitsMessage = "fixed point needs at least one integer bit (the sign bit counts for signed storage)";
    internal const string FixedFractionBitsMessage = "fixed point fraction bits can't be negative";
    internal const string FixedWidthMessage = "fixed point integer bits plus fraction bits must equal the number of bits in the storage type";
    internal const string FixedBoundsMessage = "fixed point bounds in whole units do not fit the Q format";

    // Writer contract asserts (STANDARD.md writes-trusted doctrine, enacted for C#
    // per serialize#52): Debug.Assert messages, never seen in release builds.
    internal const string WriteRangeAssertMessage = "write value out of range: writes are trusted, the range is the writer's contract";
    internal const string WriteStringAssertMessage = "string does not fit in the buffer size: the writer's contract";
    internal const string WriteWideStringAssertMessage = "wstring payload is not well-formed UTF-16 (unpaired surrogate): the writer's contract";
    internal const string WriteIntRelativeAssertMessage = "int relative requires previous < current: the writer's contract";
    internal const string FloatDeltaAssertMessage = "compressed float declaration is non-conforming: max - min must be finite";
    internal const string FloatValuesAssertMessage = "compressed float declaration is non-conforming: (max - min) / resolution must be finite";
    internal const string FloatValueAssertMessage = "compressed float write value is non-conforming: NaN and infinities must not be sent";
    internal const string FloatPrecomputedMaxIntegerValueMessage = "precomputed compressed float constants are the caller's contract: maxIntegerValue must be at least 1";
    internal const string FloatPrecomputedBitsMessage = "precomputed compressed float constants are the caller's contract: bits must equal BitsRequired(0, maxIntegerValue)";
    internal const string FloatPrecomputedDeltaMessage = "precomputed compressed float constants are the caller's contract: delta must be positive";

    /// <summary>
    /// The difference buckets used by SerializeIntRelative. Each bucket costs one
    /// signal bit plus the bits required for its [min,max] range; differences past the
    /// last bucket fall back to an absolute 32 bit value.
    /// </summary>
    internal static readonly (uint Min, uint Max)[] IntRelativeBuckets =
    {
        (2, 6),
        (7, 23),
        (24, 280),
        (281, 4377),
        (4378, 69914),
    };

    /// <summary>
    /// Debug-asserts that precomputed compressed float constants are what
    /// SerializeUtil.CompressedFloatParams derives for a conforming declaration.
    /// The constants are trusted call-site parameters, exactly like the (min, max,
    /// resolution) declaration they were derived from, so a violation is API misuse:
    /// in particular a wire width that disagrees with the step count would make the
    /// field occupy a different number of bits than every other conforming
    /// implementation of the declaration expects. Conditional("DEBUG"): the whole
    /// call compiles out of release builds.
    /// </summary>
    [Conditional("DEBUG")]
    internal static void ValidatePrecomputedFloatParams(uint maxIntegerValue, int bits, float delta)
    {
        Debug.Assert(maxIntegerValue >= 1, FloatPrecomputedMaxIntegerValueMessage);
        Debug.Assert(bits == SerializeUtil.BitsRequired(0, maxIntegerValue), FloatPrecomputedBitsMessage);
        Debug.Assert(delta > 0.0f, FloatPrecomputedDeltaMessage);
        Debug.Assert(!float.IsInfinity(delta), FloatDeltaAssertMessage);
    }

    /// <summary>
    /// The write-side quantization of SerializeCompressedFloat, shared by the stream
    /// and batch write paths so the normative arithmetic exists in exactly one place.
    /// Returns the integer that goes on the wire.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static uint QuantizeCompressedFloat(float value, float min, float delta, uint maxIntegerValue)
    {
        // Sending a non-finite value through compressed float is NON-CONFORMING —
        // ruled 2026-08-15, verbatim: "attempting to send NaN or INF or anything
        // else through compressed float is non-conforming and should assert out on
        // write too." This is the shared write intake (stream and batch), so the
        // assert covers both write paths; in release the clamp below still forces
        // non-finite values into range (NaN to the low end), which is the old
        // silent behavior the assert replaces in debug builds.
        Debug.Assert(float.IsFinite(value), FloatValueAssertMessage);

        float normalizedValue = (value - min) / delta;
        if (!(normalizedValue >= 0.0f))
        {
            normalizedValue = 0.0f; // the !>= form of the clamp forces NaN into range too
        }
        else if (!(normalizedValue <= 1.0f))
        {
            normalizedValue = 1.0f;
        }
        // STANDARD.md pins this arithmetic to float32 with TWO roundings: the product
        // rounds to float32 before 0.5f is added, and the sum rounds to float32 before
        // the floor. ECMA-334 permits floating point operations to be performed at
        // higher precision than the result type, so the explicit (float) casts below
        // are the language-level guarantee that any excess precision is discarded --
        // without them the wire rests on an unwritten RyuJIT implementation detail.
        // The same rule already cost the family a live divergence once: on arm64 a
        // C++ compiler contracted this multiply-add into a single FMA (ONE rounding)
        // and quantized 0.005 over [0,10] at resolution 0.01 to 0 where every
        // conformant runtime writes 1. Widening to double diverges the same way on
        // the same values (0.005 / 0.025 / 0.105 / 9.995 -- only values exactly on a
        // quantum agree). Do not fold the product back into one expression, and do
        // not drop the casts. Matches serialize.h serialize_compressed_float_internal
        // (`const float scaled`) and serialize.c serialize_write_compressed_float.
        float scaled = (float)(normalizedValue * maxIntegerValue);
        return (uint)Math.Floor((double)(float)(scaled + 0.5f));
    }

    /// <summary>
    /// The read-side dequantization of SerializeCompressedFloat, shared by the
    /// stream and batch read paths (derive-per-call and precomputed alike) so the
    /// normative arithmetic exists in exactly one place. Takes the integer that came
    /// off the wire, already validated against maxIntegerValue, and returns the
    /// decoded float. Statement for statement the read arithmetic that lived inline
    /// in ReadStream and ReadBatch before the mas-bandwidth/schema#82 split;
    /// test_compressed_float_precomputed_differential holds it to bit identity
    /// against a frozen copy of the pre-split original.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static float DecodeCompressedFloat(uint integerValue, uint maxIntegerValue, float delta, float min)
    {
        float normalizedValue = (float)integerValue / maxIntegerValue;
        // STANDARD.md pins the DECODE the same way it pins the write quantization:
        // "the quotient rounds, the product rounds BEFORE min is added, and the sum
        // rounds", and an implementation "must not contract the multiply and the add
        // into a fused multiply-add". Fused, the decode rounds once instead of twice
        // and, whenever min is non-zero, lands one ulp from the conformant result --
        // which never changes the bytes being read but does change the value read
        // from them, so a value decoded here and re-encoded would produce different
        // wire from every other conforming runtime. ECMA-334 permits floating point
        // operations at higher precision than the result type, so, exactly as on the
        // write side above, the explicit (float) cast and the float local are the
        // language-level guarantee rather than an unwritten RyuJIT detail. This
        // mirrors serialize.h serialize_compressed_float_precomputed_internal
        // (`const float scaledValue`), whose comment carries the same instruction.
        // Do not fold these back into one expression.
        float scaledValue = (float)(normalizedValue * delta);
        return (float)(scaledValue + min);
    }

    /// <summary>Debug-asserts that a string buffer size can express a valid length
    /// range. Conditional("DEBUG"): the whole call compiles out of release builds.</summary>
    [Conditional("DEBUG")]
    internal static void ValidateBufferSize(int bufferSize)
    {
        Debug.Assert(bufferSize >= 2, BufferSizeMessage);
    }

    /// <summary>
    /// Validates a fixed point Q format against its storage and bounds. Everything
    /// here is a trusted parameter of the call site — part of the wire format like a
    /// ranged integer's bounds — so a violation is API misuse: Debug.Assert, the C#
    /// analog of the static_asserts in the C++ library, compiled out of release
    /// builds along with the whole call (Conditional("DEBUG")). The whole unit
    /// capacity math runs in the unsigned domain so the widest formats (Q64.0 and
    /// friends) cannot overflow signed arithmetic.
    /// </summary>
    [Conditional("DEBUG")]
    private static void ValidateFixedPointFormat(
        int storageBits, bool storageSigned, int integerBits, int fractionBits,
        long minUnits, long maxUnits)
    {
        Debug.Assert(integerBits >= 1, FixedIntegerBitsMessage);
        Debug.Assert(fractionBits >= 0, FixedFractionBitsMessage);
        Debug.Assert(integerBits + fractionBits == storageBits, FixedWidthMessage);
        Debug.Assert(minUnits <= maxUnits, MinMaxMessage);

        // the whole unit capacity of the Q format, in the 64 bit domain: with 65 or
        // more integer bits (128 bit storage) the capacity covers any long bound
        long minRepresentableUnits;
        long maxRepresentableUnits;
        if (storageSigned)
        {
            minRepresentableUnits = integerBits >= 65
                ? long.MinValue
                : (long)(0UL - (1UL << (integerBits - 1)));
            maxRepresentableUnits = integerBits >= 64
                ? long.MaxValue
                : (long)((1UL << (integerBits - 1)) - 1);
        }
        else
        {
            minRepresentableUnits = 0;
            maxRepresentableUnits = integerBits >= 64
                ? long.MaxValue
                : (long)((1UL << integerBits) - 1);
        }
        Debug.Assert(minUnits >= minRepresentableUnits && maxUnits <= maxRepresentableUnits, FixedBoundsMessage);
    }

    /// <summary>
    /// Validates a fixed point Q format with storage of 64 bits or fewer and computes
    /// the raw wire parameters shared by the write, read and measure implementations
    /// of SerializeFixed. The whole unit bounds are shifted into raw fixed point
    /// units in the unsigned domain, so negative bounds wrap two's complement — no
    /// float is ever involved.
    /// </summary>
    internal static void FixedPointParams(
        int storageBits, bool storageSigned, int integerBits, int fractionBits,
        long minUnits, long maxUnits,
        out ulong rawMin, out ulong rawMax, out int bits)
    {
        ValidateFixedPointFormat(storageBits, storageSigned, integerBits, fractionBits, minUnits, maxUnits);
        rawMin = (ulong)minUnits << fractionBits;
        rawMax = (ulong)maxUnits << fractionBits;
        bits = SerializeUtil.BitsRequired64(rawMin, rawMax);
    }

    /// <summary>
    /// The 128 bit storage counterpart of FixedPointParams: raw bounds in the
    /// unsigned 128 bit domain, where two's complement wrap is exact for signed
    /// storage. The wire cost comes from the 64 bit domain: the range in whole units
    /// is exact in a ulong, and shifting it left by fractionBits adds exactly
    /// fractionBits to its bit length — except when the range is DEGENERATE. A
    /// degenerate range (min == max) costs zero bits on every storage width, per
    /// STANDARD.md; adding fractionBits to the zero-width unit range would emit
    /// fractionBits of zeros here while the narrow path writes nothing, the exact
    /// 64/128 self-disagreement serialize#54 pins.
    /// </summary>
    internal static void FixedPointParams128(
        bool storageSigned, int integerBits, int fractionBits,
        long minUnits, long maxUnits,
        out UInt128Value rawMin, out UInt128Value rawMax, out int bits)
    {
        ValidateFixedPointFormat(128, storageSigned, integerBits, fractionBits, minUnits, maxUnits);
        // the Int128Value conversion sign extends the whole unit bounds before the shift
        rawMin = (UInt128Value)(Int128Value)minUnits << fractionBits;
        rawMax = (UInt128Value)(Int128Value)maxUnits << fractionBits;
        bits = minUnits == maxUnits
            ? 0
            : SerializeUtil.BitsRequired64((ulong)minUnits, (ulong)maxUnits) + fractionBits;
    }
}

/// <summary>
/// Bitpacks unsigned integer values to a buffer.
///
/// Integer bit values are written to a 64 bit scratch value from right to left. Once
/// the scratch fills to 64 bits it is stored to memory as a little endian qword and the
/// handful of bits that spilled past 64 carry over into the next scratch.
///
/// IMPORTANT: The buffer size must be a multiple of 8 bytes, because words are stored
/// to memory 8 bytes at a time. Bytes past the end of the written data are only ever
/// written as zeros.
/// </summary>
public sealed class BitWriter
{
    private byte[] _data = Array.Empty<byte>();
    private ulong _scratch;
    private long _numBits;
    private long _bitsWritten;
    private long _wordIndex;
    private int _scratchBits;

    /// <summary>Creates a bit writer that fills the given buffer with bitpacked data.
    /// The buffer size must be a multiple of 8 bytes.</summary>
    public BitWriter(byte[] buffer)
    {
        Reset(buffer);
    }

    /// <summary>Points the bit writer at a buffer and clears all write state, allowing
    /// a single writer to be reused without allocation. The buffer size must be a
    /// multiple of 8 bytes.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Reset(byte[] buffer)
    {
        Debug.Assert(buffer.Length % 8 == 0, SerializeInternal.BufferBytesMessage);
        _data = buffer;
        _scratch = 0;
        _numBits = (long)buffer.Length * 8;
        _bitsWritten = 0;
        _wordIndex = 0;
        _scratchBits = 0;
    }

    internal long NumBits => _numBits;

    /// <summary>
    /// Lifts the packer state out into locals for a WriteBatch, which serializes
    /// against register-resident copies of these fields and stores them back once
    /// via RestoreState. See WriteBatch.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void CaptureState(out byte[] data, out ulong scratch, out long numBits,
        out long bitsWritten, out long wordIndex, out int scratchBits)
    {
        data = _data;
        scratch = _scratch;
        numBits = _numBits;
        bitsWritten = _bitsWritten;
        wordIndex = _wordIndex;
        scratchBits = _scratchBits;
    }

    /// <summary>
    /// Stores batch-held packer state back into the writer. The buffer and its bit
    /// capacity cannot change while a batch is open (Reset mid-batch is API misuse),
    /// so only the mutable write state comes back.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void RestoreState(ulong scratch, long bitsWritten, long wordIndex, int scratchBits)
    {
        _scratch = scratch;
        _bitsWritten = bitsWritten;
        _wordIndex = wordIndex;
        _scratchBits = scratchBits;
    }

    /// <summary>
    /// The unchecked hot path shared by WriteBits and WriteStream, which perform their
    /// own validation before calling it. bits must be in [1,32] and the write must fit
    /// in the buffer.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void WriteBitsUnchecked(uint value, int bits)
    {
        value &= (uint)((1UL << bits) - 1);

        _scratch |= (ulong)value << _scratchBits;

        int newScratchBits = _scratchBits + bits;

        if (newScratchBits >= 64)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(_data.AsSpan((int)(_wordIndex * 8)), _scratch);
            _wordIndex++;
            // recover the bits that spilled past 64. newScratchBits >= 64 with
            // bits <= 32 implies the shift is in [1,32]
            _scratch = (ulong)value >> (64 - _scratchBits);
            _scratchBits = newScratchBits - 64;
        }
        else
        {
            _scratchBits = newScratchBits;
        }

        _bitsWritten += bits;
    }

    /// <summary>
    /// Writes the low order bits of value to the buffer, without padding to the nearest
    /// byte. bits must be in [1,32]; bits of value above that count are ignored. The
    /// width and buffer capacity are the caller's contract: Debug.Assert in debug
    /// builds, unchecked in release (a write past the end stops at the runtime's own
    /// bounds check).
    ///
    /// IMPORTANT: When you have finished writing, call FlushBits, otherwise the last
    /// word of data will not get flushed to memory!
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteBits(uint value, int bits)
    {
        Debug.Assert(bits >= 1 && bits <= 32, SerializeInternal.BitsRangeMessage);
        Debug.Assert(_bitsWritten + bits <= _numBits, SerializeInternal.WriteOverflowMessage);
        WriteBitsUnchecked(value, bits);
    }

    /// <summary>Pads the bit stream with zeros so the bit index becomes a multiple
    /// of 8. If the current bit index is already a multiple of 8, nothing is
    /// written.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteAlign()
    {
        int remainderBits = (int)(_bitsWritten % 8);
        if (remainderBits != 0)
        {
            WriteBits(0, 8 - remainderBits);
        }
    }

    /// <summary>
    /// The unchecked byte-run path shared by WriteBytes and WriteStream. The writer
    /// must be byte aligned and the write must fit in the buffer. Head bytes are
    /// bitpacked until the stream reaches a qword boundary, the middle is a straight
    /// copy, and the tail is bitpacked again.
    /// </summary>
    internal void WriteBytesUnchecked(ReadOnlySpan<byte> data)
    {
        int n = data.Length;

        int headBytes = (int)((8 - (_bitsWritten % 64) / 8) % 8);
        if (headBytes > n)
        {
            headBytes = n;
        }
        for (int i = 0; i < headBytes; i++)
        {
            WriteBitsUnchecked(data[i], 8);
        }
        if (headBytes == n)
        {
            return;
        }

        // the head bytes flushed the scratch exactly at the qword boundary, so the
        // scratch is zero here and the aligned middle is a straight copy
        int numWords = (n - headBytes) / 8;
        if (numWords > 0)
        {
            data.Slice(headBytes, numWords * 8).CopyTo(_data.AsSpan((int)(_wordIndex * 8)));
            _bitsWritten += (long)numWords * 64;
            _wordIndex += numWords;
        }

        for (int i = headBytes + numWords * 8; i < n; i++)
        {
            WriteBitsUnchecked(data[i], 8);
        }
    }

    /// <summary>Writes a run of bytes to the bit stream. Faster than writing each byte
    /// via WriteBits(value, 8), because the aligned middle of the data is block copied
    /// into the buffer without bitpacking. The writer must be aligned to a byte
    /// boundary: call WriteAlign first.</summary>
    public void WriteBytes(ReadOnlySpan<byte> data)
    {
        Debug.Assert(_bitsWritten % 8 == 0, SerializeInternal.NotAlignedMessage);
        Debug.Assert(_bitsWritten + (long)data.Length * 8 <= _numBits, SerializeInternal.WriteOverflowMessage);
        WriteBytesUnchecked(data);
    }

    /// <summary>
    /// Flushes any remaining bits in the scratch to memory. Call this once after you
    /// have finished writing bits. The flush stores a full qword: the buffer size is a
    /// multiple of 8 so this stays in bounds, and bytes past the written data are only
    /// ever written as zeros.
    ///
    /// FlushBits ends the write: writing more bits after a mid-stream flush corrupts
    /// the stream, because the flushed partial word cannot be resumed.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void FlushBits()
    {
        if (_scratchBits != 0)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(_data.AsSpan((int)(_wordIndex * 8)), _scratch);
            _scratch = 0;
            _scratchBits = 0;
            _wordIndex++;
        }
    }

    /// <summary>The number of align bits that would be written, if an align was written
    /// right now, in [0,7].</summary>
    public int AlignBits => (int)((8 - _bitsWritten % 8) % 8);

    /// <summary>The number of bits written so far.</summary>
    public long BitsWritten => _bitsWritten;

    /// <summary>The number of bits still available to write.</summary>
    public long BitsAvailable => _numBits - _bitsWritten;

    /// <summary>The number of bits written rounded up to the next byte. This is
    /// effectively the size of the packet you should send after you have finished
    /// bitpacking values with this writer.
    ///
    /// IMPORTANT: Call FlushBits first, otherwise you risk missing the last word of
    /// data.</summary>
    public long BytesWritten => (_bitsWritten + 7) / 8;

    /// <summary>The written portion of the buffer: the first BytesWritten bytes.
    ///
    /// IMPORTANT: Call FlushBits first, otherwise you risk missing the last word of
    /// data.</summary>
    public ReadOnlySpan<byte> Data => _data.AsSpan(0, (int)BytesWritten);
}

/// <summary>
/// Reads bitpacked integer values from a buffer.
///
/// The reader relies on the user reconstructing the exact same set of bit reads as bit
/// writes when the buffer was written. This is an unattributed bitpacked binary stream!
///
/// Reads are effectively branchless: each read loads a 64 bit little endian window at
/// the current byte position and shifts by the bit remainder. For the fastest reads,
/// pass a buffer that extends at least 7 bytes past the packet data — for example, read
/// packets into a large buffer and pass the packet length separately. The reader uses
/// the fully branchless window load wherever 8 bytes of buffer exist past the read
/// position; near the end of a slack-free buffer it assembles the window from the
/// remaining bytes instead. Slack bytes are loaded but never interpreted: bits past the
/// end of the data cannot reach the output of a read.
/// </summary>
public sealed class BitReader
{
    private byte[] _data = Array.Empty<byte>();
    private long _numBits;
    private long _bitsRead;

    /// <summary>Creates a bit reader that reads the first <paramref name="bytes"/>
    /// bytes of bitpacked data in the given buffer. Buffer bytes past
    /// <paramref name="bytes"/> are slack: loaded for speed, never interpreted.</summary>
    public BitReader(byte[] buffer, int bytes)
    {
        Reset(buffer, bytes);
    }

    /// <summary>Creates a bit reader over the whole buffer.</summary>
    public BitReader(byte[] buffer)
        : this(buffer, buffer.Length)
    {
    }

    /// <summary>Points the bit reader at a buffer and clears all read state, allowing a
    /// single reader to be reused without allocation.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Reset(byte[] buffer, int bytes)
    {
        Debug.Assert(bytes >= 0 && bytes <= buffer.Length, SerializeInternal.ReaderBytesMessage);
        _data = buffer;
        _numBits = (long)bytes * 8;
        _bitsRead = 0;
    }

    internal long NumBits => _numBits;

    /// <summary>
    /// Lifts the reader state out into locals for a ReadBatch, which reads against
    /// register-resident copies of these fields and stores the cursor back once via
    /// RestoreState. See ReadBatch.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void CaptureState(out byte[] data, out long numBits, out long bitsRead)
    {
        data = _data;
        numBits = _numBits;
        bitsRead = _bitsRead;
    }

    /// <summary>
    /// Stores a batch-held read cursor back into the reader. The buffer and its bit
    /// length cannot change while a batch is open (Reset mid-batch is API misuse),
    /// so only the cursor comes back.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void RestoreState(long bitsRead)
    {
        _bitsRead = bitsRead;
    }

    /// <summary>
    /// The unchecked hot path shared by ReadBits and ReadStream, which perform their
    /// own validation before calling it. bits must be in [1,32] and must not read past
    /// the end of the data.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal uint ReadBitsUnchecked(int bits)
    {
        int byteIndex = (int)(_bitsRead >> 3);

        ulong window;
        if (byteIndex + 8 <= _data.Length)
        {
            window = BinaryPrimitives.ReadUInt64LittleEndian(_data.AsSpan(byteIndex));
        }
        else
        {
            // near the end of a buffer with no slack past the data: assemble the
            // window from the remaining bytes
            window = 0;
            for (int i = _data.Length - byteIndex - 1; i >= 0; i--)
            {
                window = window << 8 | _data[byteIndex + i];
            }
        }

        uint output = (uint)(window >> (int)(_bitsRead & 7)) & (uint)((1UL << bits) - 1);

        _bitsRead += bits;

        return output;
    }

    /// <summary>True if reading the given number of bits would read past the end of the
    /// data.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool WouldReadPastEnd(int bits)
    {
        return _bitsRead + bits > _numBits;
    }

    /// <summary>Reads bits from the buffer and returns the integer value read, in range
    /// [0,(1&lt;&lt;bits)-1]. bits must be in [1,32]. Staying inside the data is the
    /// caller's contract on this raw API: Debug.Assert in debug builds, unchecked in
    /// release — check WouldReadPastEnd first when reading untrusted data, or use
    /// ReadStream, which performs all checks in every build and latches errors.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint ReadBits(int bits)
    {
        Debug.Assert(bits >= 1 && bits <= 32, SerializeInternal.BitsRangeMessage);
        Debug.Assert(_bitsRead + bits <= _numBits, SerializeInternal.ReadOverflowMessage);
        return ReadBitsUnchecked(bits);
    }

    /// <summary>Reads an align, corresponding to a WriteAlign call when the buffer was
    /// written, and skips ahead to the next byte boundary. As a safety check, it
    /// verifies that the padding bits are zero and returns false if they are not; this
    /// typically aborts the packet read.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool ReadAlign()
    {
        int remainderBits = (int)(_bitsRead % 8);
        if (remainderBits != 0)
        {
            uint value = ReadBits(8 - remainderBits);
            if (value != 0)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Returns the next n bytes of the underlying data without copying, advancing the
    /// read position. The reader must be byte aligned and the caller must have bounds
    /// checked the read.
    /// </summary>
    internal ReadOnlySpan<byte> ReadSliceUnchecked(int n)
    {
        int offset = (int)(_bitsRead >> 3);
        _bitsRead += (long)n * 8;
        return _data.AsSpan(offset, n);
    }

    /// <summary>Reads data.Length bytes from the bit stream into data, corresponding to
    /// a WriteBytes call when the buffer was written. The reader must be aligned to a
    /// byte boundary, and staying inside the data is the caller's contract: Debug.Assert
    /// in debug builds, unchecked in release — bounds check with BitsRemaining first
    /// when reading untrusted data, or use ReadStream.</summary>
    public void ReadBytes(Span<byte> data)
    {
        Debug.Assert(_bitsRead % 8 == 0, SerializeInternal.NotAlignedMessage);
        Debug.Assert(_bitsRead + (long)data.Length * 8 <= _numBits, SerializeInternal.ReadOverflowMessage);
        ReadSliceUnchecked(data.Length).CopyTo(data);
    }

    /// <summary>The number of align bits that would be read, if an align was read right
    /// now, in [0,7].</summary>
    public int AlignBits => (int)((8 - _bitsRead % 8) % 8);

    /// <summary>The number of bits read from the buffer so far.</summary>
    public long BitsRead => _bitsRead;

    /// <summary>The number of bits still available to read.</summary>
    public long BitsRemaining => _numBits - _bitsRead;
}

/// <summary>
/// Writes bitpacked data to a buffer, implementing IBitStream so unified serialize
/// functions can write with it. The writer is TRUSTED (STANDARD.md doctrine, enacted
/// for C# per serialize#52): values, buffer capacity, string lengths and compressed
/// float finiteness are the writer's contract, checked by Debug.Assert in debug
/// builds and not at all in release builds — matching the C++ WriteStream, whose
/// write path is serialize_assert only. Healthy serialize calls always return true;
/// the sticky latched error model remains for user aborts through SerializeObject,
/// and the caller can preflight capacity with BitsAvailable.
/// </summary>
public sealed class WriteStream : IBitStream
{
    private readonly BitWriter _writer;
    private SerializeError _error;

    /// <summary>Creates a write stream that writes to the given buffer. The buffer size
    /// must be a multiple of 8 bytes, because the bit writer stores qwords to
    /// memory.</summary>
    public WriteStream(byte[] buffer)
    {
        _writer = new BitWriter(buffer);
    }

    /// <summary>Points the stream at a buffer and clears all write state including any
    /// latched error, allowing a single stream to be reused without allocation. The
    /// context is kept.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Reset(byte[] buffer)
    {
        _writer.Reset(buffer);
        _error = SerializeError.None;
    }

    /// <inheritdoc/>
    public bool IsWriting => true;

    /// <inheritdoc/>
    public bool IsReading => false;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool Fail(SerializeError error)
    {
        if (_error == SerializeError.None)
        {
            _error = error;
        }
        return false;
    }

    /// <summary>Writes bits that have already been validated to [1,32]. Capacity is
    /// the writer's contract: asserted in debug, unchecked in release.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool WriteBits(uint value, int bits)
    {
        Debug.Assert(_writer.BitsWritten + bits <= _writer.NumBits, SerializeInternal.WriteOverflowMessage);
        _writer.WriteBitsUnchecked(value, bits);
        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool WriteBool(bool value)
    {
        return WriteBits(value ? 1u : 0u, 1);
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeBits(ref uint value, int bits)
    {
        Debug.Assert(bits >= 1 && bits <= 32, SerializeInternal.BitsRangeMessage);
        return WriteBits(value, bits);
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeBits64(ref ulong value, int bits)
    {
        Debug.Assert(bits >= 1 && bits <= 64, SerializeInternal.BitsRange64Message);
        if (bits <= 32)
        {
            return WriteBits((uint)value, bits);
        }
        Debug.Assert(_writer.BitsWritten + bits <= _writer.NumBits, SerializeInternal.WriteOverflowMessage);
        // low dword first, then the high remainder
        _writer.WriteBitsUnchecked((uint)value, 32);
        _writer.WriteBitsUnchecked((uint)(value >> 32), bits - 32);
        return true;
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeInt(ref int value, int min, int max)
    {
        Debug.Assert(min <= max, SerializeInternal.MinMaxMessage);
        int v = value;
        Debug.Assert(v >= min && v <= max, SerializeInternal.WriteRangeAssertMessage);
        int bits = SerializeUtil.BitsRequired((uint)min, (uint)max);
        // subtract in the unsigned domain: the range may be wider than 2^31
        return WriteBits((uint)v - (uint)min, bits);
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeInt64(ref long value, long min, long max)
    {
        Debug.Assert(min <= max, SerializeInternal.MinMaxMessage);
        long v = value;
        Debug.Assert(v >= min && v <= max, SerializeInternal.WriteRangeAssertMessage);
        int bits = SerializeUtil.BitsRequired64((ulong)min, (ulong)max);
        // subtract in the unsigned domain: the range may be wider than 2^63
        ulong unsigned = (ulong)v - (ulong)min;
        if (bits <= 32)
        {
            return WriteBits((uint)unsigned, bits);
        }
        Debug.Assert(_writer.BitsWritten + bits <= _writer.NumBits, SerializeInternal.WriteOverflowMessage);
        // low dword first, then the high remainder: same convention as SerializeBits64
        _writer.WriteBitsUnchecked((uint)unsigned, 32);
        _writer.WriteBitsUnchecked((uint)(unsigned >> 32), bits - 32);
        return true;
    }

    /// <summary>Writes a value in 32 bit groups, least significant group first: full
    /// 32 bit groups from the bottom with the final group carrying the remainder —
    /// the shared group structure of the 128 bit paths. bits must be in [1,128] and
    /// already bounds checked.</summary>
    private void WriteGroups128(UInt128Value value, int bits)
    {
        if (bits <= 32)
        {
            _writer.WriteBitsUnchecked((uint)value, bits);
        }
        else if (bits <= 64)
        {
            _writer.WriteBitsUnchecked((uint)value, 32);
            _writer.WriteBitsUnchecked((uint)(value >> 32), bits - 32);
        }
        else if (bits <= 96)
        {
            _writer.WriteBitsUnchecked((uint)value, 32);
            _writer.WriteBitsUnchecked((uint)(value >> 32), 32);
            _writer.WriteBitsUnchecked((uint)(value >> 64), bits - 64);
        }
        else
        {
            _writer.WriteBitsUnchecked((uint)value, 32);
            _writer.WriteBitsUnchecked((uint)(value >> 32), 32);
            _writer.WriteBitsUnchecked((uint)(value >> 64), 32);
            _writer.WriteBitsUnchecked((uint)(value >> 96), bits - 96);
        }
    }

    /// <inheritdoc/>
    public bool SerializeInt128(ref Int128Value value, Int128Value min, Int128Value max)
    {
        Debug.Assert(min <= max, SerializeInternal.MinMaxMessage);
        Int128Value v = value;
        Debug.Assert(v >= min && v <= max, SerializeInternal.WriteRangeAssertMessage);
        int bits = SerializeUtil.BitsRequired128((UInt128Value)min, (UInt128Value)max);
        // subtract in the unsigned domain: the range may be wider than 2^127
        UInt128Value unsigned = (UInt128Value)v - (UInt128Value)min;
        Debug.Assert(_writer.BitsWritten + bits <= _writer.NumBits, SerializeInternal.WriteOverflowMessage);
        WriteGroups128(unsigned, bits);
        return true;
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeByte(ref byte value) => WriteBits(value, 8);

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeUInt16(ref ushort value) => WriteBits(value, 16);

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeUInt32(ref uint value) => WriteBits(value, 32);

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeUInt64(ref ulong value)
    {
        Debug.Assert(_writer.BitsWritten + 64 <= _writer.NumBits, SerializeInternal.WriteOverflowMessage);
        _writer.WriteBitsUnchecked((uint)value, 32);
        _writer.WriteBitsUnchecked((uint)(value >> 32), 32);
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeUInt128(ref UInt128Value value)
    {
        Debug.Assert(_writer.BitsWritten + 128 <= _writer.NumBits, SerializeInternal.WriteOverflowMessage);
        // the low 64 bit half first, then the high half, each half low dword first
        WriteGroups128(value, 128);
        return true;
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeBool(ref bool value) => WriteBool(value);

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFloat(ref float value)
    {
        return WriteBits(SerializeCompat.SingleToUInt32Bits(value), 32);
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeDouble(ref double value)
    {
        ulong bits = SerializeCompat.DoubleToUInt64Bits(value);
        return SerializeUInt64(ref bits);
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeCompressedFloat(ref float value, float min, float max, float resolution)
    {
        SerializeUtil.CompressedFloatParams(min, max, resolution,
            out uint maxIntegerValue, out int bits, out float delta);
        uint integerValue = SerializeInternal.QuantizeCompressedFloat(value, min, delta, maxIntegerValue);
        return WriteBits(integerValue, bits);
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeCompressedFloatPrecomputed(ref float value, uint maxIntegerValue, int bits, float delta, float min)
    {
        SerializeInternal.ValidatePrecomputedFloatParams(maxIntegerValue, bits, delta);
        uint integerValue = SerializeInternal.QuantizeCompressedFloat(value, min, delta, maxIntegerValue);
        return WriteBits(integerValue, bits);
    }

    /// <summary>The shared write path of the fixed point overloads with storage of 64
    /// bits or fewer: raw value, bounds and offset all live in the unsigned 64 bit
    /// domain, where two's complement wrap is exact for signed storage. The wire is
    /// byte identical to SerializeInt64 of the raw value over the raw bounds.</summary>
    private bool WriteFixed(ulong raw, ulong rawMin, ulong rawMax, int bits)
    {
        // subtract in the unsigned domain: the raw range may be wider than 2^63
        ulong offset = raw - rawMin;
        Debug.Assert(offset <= rawMax - rawMin, SerializeInternal.WriteRangeAssertMessage);
        Debug.Assert(_writer.BitsWritten + bits <= _writer.NumBits, SerializeInternal.WriteOverflowMessage);
        if (bits <= 32)
        {
            _writer.WriteBitsUnchecked((uint)offset, bits);
        }
        else
        {
            // low dword first, then the high remainder: same convention as SerializeInt64
            _writer.WriteBitsUnchecked((uint)offset, 32);
            _writer.WriteBitsUnchecked((uint)(offset >> 32), bits - 32);
        }
        return true;
    }

    /// <summary>The 128 bit storage counterpart of WriteFixed: the offset is written
    /// in 32 bit groups, least significant group first.</summary>
    private bool WriteFixed128(UInt128Value raw, UInt128Value rawMin, UInt128Value rawMax, int bits)
    {
        // subtract in the unsigned domain: the raw range may be wider than 2^127
        UInt128Value offset = raw - rawMin;
        Debug.Assert(offset <= rawMax - rawMin, SerializeInternal.WriteRangeAssertMessage);
        Debug.Assert(_writer.BitsWritten + bits <= _writer.NumBits, SerializeInternal.WriteOverflowMessage);
        WriteGroups128(offset, bits);
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref long value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(64, true, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        return WriteFixed((ulong)value, rawMin, rawMax, bits);
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref ulong value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(64, false, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        return WriteFixed(value, rawMin, rawMax, bits);
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref int value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(32, true, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        return WriteFixed((ulong)value, rawMin, rawMax, bits);
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref uint value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(32, false, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        return WriteFixed(value, rawMin, rawMax, bits);
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref short value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(16, true, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        return WriteFixed((ulong)value, rawMin, rawMax, bits);
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref ushort value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(16, false, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        return WriteFixed(value, rawMin, rawMax, bits);
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref Int128Value value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams128(true, integerBits, fractionBits, min, max,
            out UInt128Value rawMin, out UInt128Value rawMax, out int bits);
        return WriteFixed128((UInt128Value)value, rawMin, rawMax, bits);
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref UInt128Value value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams128(false, integerBits, fractionBits, min, max,
            out UInt128Value rawMin, out UInt128Value rawMax, out int bits);
        return WriteFixed128(value, rawMin, rawMax, bits);
    }

    /// <inheritdoc/>
    public bool SerializeBytes(Span<byte> data)
    {
        if (!SerializeAlign())
        {
            return false;
        }
        Debug.Assert(_writer.BitsWritten + (long)data.Length * 8 <= _writer.NumBits, SerializeInternal.WriteOverflowMessage);
        _writer.WriteBytesUnchecked(data);
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeString(ref string value, int bufferSize)
    {
        SerializeInternal.ValidateBufferSize(bufferSize);
        int byteCount = Encoding.UTF8.GetByteCount(value);
        Debug.Assert(byteCount < bufferSize, SerializeInternal.WriteStringAssertMessage);
        int length = byteCount;
        if (!SerializeInt(ref length, 0, bufferSize - 1))
        {
            return false;
        }
        if (!SerializeAlign())
        {
            return false;
        }
        Debug.Assert(_writer.BitsWritten + (long)byteCount * 8 <= _writer.NumBits, SerializeInternal.WriteOverflowMessage);
        // encode through a bounded stackalloc buffer in chunks so strings of any
        // length allocate nothing on the write path. chunks split only at code point
        // boundaries (never inside a surrogate pair), so the bytes are identical to a
        // whole-string encode, and the writer stays byte aligned between chunks
        Span<byte> utf8 = stackalloc byte[512];
        ReadOnlySpan<char> remaining = value.AsSpan();
        while (remaining.Length > 0)
        {
            int take = Math.Min(remaining.Length, 128);
            if (take < remaining.Length && char.IsHighSurrogate(remaining[take - 1]))
            {
                take--; // take >= 1 still: take < remaining.Length implies take == 128
            }
            int encoded = Encoding.UTF8.GetBytes(remaining[..take], utf8);
            _writer.WriteBytesUnchecked(utf8[..encoded]);
            remaining = remaining[take..];
        }
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeWideString(ref string value, int bufferSize)
    {
        SerializeInternal.ValidateBufferSize(bufferSize);
        // each 32-bit group carries one UTF-16 CODE UNIT, not one code point
        // (STANDARD.md, adopted 2026-08-15), and the length field counts units. A C#
        // string IS a sequence of UTF-16 code units, so the split a 4-byte wchar_t
        // port performs at this boundary (astral code point -> surrogate pair) has
        // already happened in the string itself: transmit chars as they are. The
        // payload being well-formed UTF-16 (no unpaired surrogate) is the writer's
        // contract, debug-asserted per serialize#52; conforming readers refuse an
        // unpaired surrogate.
        Debug.Assert(SerializeCompat.Utf16IsValid(value), SerializeInternal.WriteWideStringAssertMessage);
        int length = value.Length;
        Debug.Assert(length < bufferSize, SerializeInternal.WriteStringAssertMessage);
        if (!SerializeInt(ref length, 0, bufferSize - 1))
        {
            return false;
        }
        // NO align here -- deliberately unlike the narrow path (STANDARD.md)
        for (int i = 0; i < value.Length; i++)
        {
            if (!WriteBits(value[i], 32))
            {
                return false;
            }
        }
        return true;
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeAlign()
    {
        int alignBits = _writer.AlignBits;
        if (alignBits == 0)
        {
            return true;
        }
        return WriteBits(0, alignBits);
    }

    /// <inheritdoc/>
    public bool SerializeObject(ISerializer obj)
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (!obj.Serialize(this))
        {
            // an object that aborts without a stream failure is an object-level
            // validation failure: latch it so later calls stay no-ops
            Fail(SerializeError.ValueOutOfRange);
            return false;
        }
        return _error == SerializeError.None;
    }

    /// <inheritdoc/>
    public bool SerializeObject<T>(ref T obj) where T : ISerializer
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (!obj.Serialize(this))
        {
            Fail(SerializeError.ValueOutOfRange);
            return false;
        }
        return _error == SerializeError.None;
    }

    /// <inheritdoc/>
    public bool SerializeIntRelative(int previous, ref int current)
    {
        Debug.Assert(previous < current, SerializeInternal.WriteIntRelativeAssertMessage);
        // difference in the unsigned domain: gaps wider than 2^31 wrap and fall
        // through to the absolute 32 bit encoding
        uint difference = (uint)current - (uint)previous;
        if (!WriteBool(difference == 1))
        {
            return false;
        }
        if (difference == 1)
        {
            return true;
        }
        foreach ((uint bucketMin, uint bucketMax) in SerializeInternal.IntRelativeBuckets)
        {
            bool inBucket = difference <= bucketMax;
            if (!WriteBool(inBucket))
            {
                return false;
            }
            if (inBucket)
            {
                int v = (int)difference;
                return SerializeInt(ref v, (int)bucketMin, (int)bucketMax);
            }
        }
        return WriteBits((uint)current, 32);
    }

    /// <summary>Flushes the last word of bits to memory. Always call this after you
    /// finish writing and before you use Data, or you risk truncating the last word of
    /// data. The flush ends the write: do not serialize more values after it.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Flush()
    {
        _writer.FlushBits();
    }

    /// <summary>
    /// Begins a batch: a register-resident view of this stream for hot serialize
    /// paths. The batch owns the stream until its End is called — always call End,
    /// on every path out. See WriteBatch for the contract and the reason it is
    /// faster.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public WriteBatch BeginBatch()
    {
        return new WriteBatch(this);
    }

    /// <summary>The bit writer, for batch state capture and delegated calls.</summary>
    internal BitWriter Writer => _writer;

    /// <summary>
    /// The latched error, batch transfer form: an open batch carries the error
    /// itself (seeded from the stream at BeginBatch) and preserves first-error
    /// latching internally, so storing it back is a plain assignment.
    /// </summary>
    internal SerializeError BatchError
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => _error;
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        set => _error = value;
    }

    /// <summary>The written portion of the buffer: the packet you should send.
    ///
    /// IMPORTANT: Call Flush first.</summary>
    public ReadOnlySpan<byte> Data => _writer.Data;

    /// <inheritdoc/>
    public int AlignBits => _writer.AlignBits;

    /// <inheritdoc/>
    public long BitsProcessed => _writer.BitsWritten;

    /// <inheritdoc/>
    public long BytesProcessed => _writer.BytesWritten;

    /// <summary>The number of bits still available to write, so callers can preflight
    /// whether a value fits without dropping to the BitWriter layer.</summary>
    public long BitsAvailable => _writer.BitsAvailable;

    /// <inheritdoc/>
    public SerializeError Error => _error;

    /// <inheritdoc/>
    public bool Ok => _error == SerializeError.None;

    /// <inheritdoc/>
    public object? Context { get; set; }
}

/// <summary>
/// Reads bitpacked data from a buffer. It wraps BitReader with bounds and range
/// checking on every read, so maliciously crafted packets fail with latched errors
/// instead of throwing or smuggling out of range values, and implements IBitStream so
/// unified serialize functions can read with it.
/// </summary>
public sealed class ReadStream : IBitStream
{
    private readonly BitReader _reader;
    private SerializeError _error;

    /// <summary>Creates a read stream over the first <paramref name="bytes"/> bytes of
    /// the given buffer. Buffer bytes past <paramref name="bytes"/> are slack: keeping
    /// at least 7 slack bytes gives branchless window loads everywhere. No slack is
    /// required for correctness.</summary>
    public ReadStream(byte[] buffer, int bytes)
    {
        _reader = new BitReader(buffer, bytes);
    }

    /// <summary>Creates a read stream over the whole buffer.</summary>
    public ReadStream(byte[] buffer)
        : this(buffer, buffer.Length)
    {
    }

    /// <summary>Points the stream at a buffer and clears all read state including any
    /// latched error, allowing a single stream to be reused without allocation. The
    /// context is kept.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Reset(byte[] buffer, int bytes)
    {
        _reader.Reset(buffer, bytes);
        _error = SerializeError.None;
    }

    /// <summary>Resets the stream over the whole buffer.</summary>
    public void Reset(byte[] buffer)
    {
        Reset(buffer, buffer.Length);
    }

    /// <inheritdoc/>
    public bool IsWriting => false;

    /// <inheritdoc/>
    public bool IsReading => true;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool Fail(SerializeError error)
    {
        if (_error == SerializeError.None)
        {
            _error = error;
        }
        return false;
    }

    /// <summary>Bounds checks and reads bits that have already been validated to [1,32].</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool ReadBits(ref uint value, int bits)
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (_reader.BitsRead + bits > _reader.NumBits)
        {
            return Fail(SerializeError.Overflow);
        }
        value = _reader.ReadBitsUnchecked(bits);
        return true;
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeBits(ref uint value, int bits)
    {
        Debug.Assert(bits >= 1 && bits <= 32, SerializeInternal.BitsRangeMessage);
        return ReadBits(ref value, bits);
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeBits64(ref ulong value, int bits)
    {
        Debug.Assert(bits >= 1 && bits <= 64, SerializeInternal.BitsRange64Message);
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (_reader.BitsRead + bits > _reader.NumBits)
        {
            return Fail(SerializeError.Overflow);
        }
        if (bits <= 32)
        {
            value = _reader.ReadBitsUnchecked(bits);
            return true;
        }
        // low dword first, then the high remainder
        uint lo = _reader.ReadBitsUnchecked(32);
        uint hi = _reader.ReadBitsUnchecked(bits - 32);
        value = (ulong)hi << 32 | lo;
        return true;
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeInt(ref int value, int min, int max)
    {
        Debug.Assert(min <= max, SerializeInternal.MinMaxMessage);
        if (_error != SerializeError.None)
        {
            return false;
        }
        int bits = SerializeUtil.BitsRequired((uint)min, (uint)max);
        if (_reader.BitsRead + bits > _reader.NumBits)
        {
            return Fail(SerializeError.Overflow);
        }
        uint unsigned = _reader.ReadBitsUnchecked(bits);
        // compare and add in the unsigned domain: the range may be wider than 2^31
        if (unsigned > (uint)max - (uint)min)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        value = (int)(unsigned + (uint)min);
        return true;
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeInt64(ref long value, long min, long max)
    {
        Debug.Assert(min <= max, SerializeInternal.MinMaxMessage);
        if (_error != SerializeError.None)
        {
            return false;
        }
        int bits = SerializeUtil.BitsRequired64((ulong)min, (ulong)max);
        if (_reader.BitsRead + bits > _reader.NumBits)
        {
            return Fail(SerializeError.Overflow);
        }
        ulong unsigned;
        if (bits <= 32)
        {
            unsigned = _reader.ReadBitsUnchecked(bits);
        }
        else
        {
            // low dword first, then the high remainder: same convention as SerializeBits64
            uint lo = _reader.ReadBitsUnchecked(32);
            uint hi = _reader.ReadBitsUnchecked(bits - 32);
            unsigned = (ulong)hi << 32 | lo;
        }
        // compare and add in the unsigned domain: the range may be wider than 2^63
        if (unsigned > (ulong)max - (ulong)min)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        value = (long)(unsigned + (ulong)min);
        return true;
    }

    /// <summary>Reads a value written in 32 bit groups, least significant group
    /// first: full 32 bit groups from the bottom with the final group carrying the
    /// remainder — the shared group structure of the 128 bit paths. bits must be in
    /// [1,128] and already bounds checked.</summary>
    private UInt128Value ReadGroups128(int bits)
    {
        if (bits <= 32)
        {
            return _reader.ReadBitsUnchecked(bits);
        }
        if (bits <= 64)
        {
            uint g0 = _reader.ReadBitsUnchecked(32);
            uint g1 = _reader.ReadBitsUnchecked(bits - 32);
            return (ulong)g1 << 32 | g0;
        }
        if (bits <= 96)
        {
            uint g0 = _reader.ReadBitsUnchecked(32);
            uint g1 = _reader.ReadBitsUnchecked(32);
            uint g2 = _reader.ReadBitsUnchecked(bits - 64);
            return (UInt128Value)g2 << 64 | ((ulong)g1 << 32 | g0);
        }
        {
            uint g0 = _reader.ReadBitsUnchecked(32);
            uint g1 = _reader.ReadBitsUnchecked(32);
            uint g2 = _reader.ReadBitsUnchecked(32);
            uint g3 = _reader.ReadBitsUnchecked(bits - 96);
            return (UInt128Value)g3 << 96 | (UInt128Value)g2 << 64 | ((ulong)g1 << 32 | g0);
        }
    }

    /// <inheritdoc/>
    public bool SerializeInt128(ref Int128Value value, Int128Value min, Int128Value max)
    {
        Debug.Assert(min <= max, SerializeInternal.MinMaxMessage);
        if (_error != SerializeError.None)
        {
            return false;
        }
        int bits = SerializeUtil.BitsRequired128((UInt128Value)min, (UInt128Value)max);
        if (_reader.BitsRead + bits > _reader.NumBits)
        {
            return Fail(SerializeError.Overflow);
        }
        UInt128Value unsigned = ReadGroups128(bits);
        // compare and add in the unsigned domain: the range may be wider than 2^127
        if (unsigned > (UInt128Value)max - (UInt128Value)min)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        value = (Int128Value)(unsigned + (UInt128Value)min);
        return true;
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeByte(ref byte value)
    {
        uint v = 0;
        if (!ReadBits(ref v, 8))
        {
            return false;
        }
        value = (byte)v;
        return true;
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeUInt16(ref ushort value)
    {
        uint v = 0;
        if (!ReadBits(ref v, 16))
        {
            return false;
        }
        value = (ushort)v;
        return true;
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeUInt32(ref uint value) => ReadBits(ref value, 32);

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeUInt64(ref ulong value)
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (_reader.BitsRead + 64 > _reader.NumBits)
        {
            return Fail(SerializeError.Overflow);
        }
        uint lo = _reader.ReadBitsUnchecked(32);
        uint hi = _reader.ReadBitsUnchecked(32);
        value = (ulong)hi << 32 | lo;
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeUInt128(ref UInt128Value value)
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (_reader.BitsRead + 128 > _reader.NumBits)
        {
            return Fail(SerializeError.Overflow);
        }
        // the low 64 bit half first, then the high half, each half low dword first
        value = ReadGroups128(128);
        return true;
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeBool(ref bool value)
    {
        uint v = 0;
        if (!ReadBits(ref v, 1))
        {
            return false;
        }
        value = v != 0;
        return true;
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFloat(ref float value)
    {
        uint v = 0;
        if (!ReadBits(ref v, 32))
        {
            return false;
        }
        value = SerializeCompat.UInt32BitsToSingle(v);
        return true;
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeDouble(ref double value)
    {
        ulong v = 0;
        if (!SerializeUInt64(ref v))
        {
            return false;
        }
        value = SerializeCompat.UInt64BitsToDouble(v);
        return true;
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeCompressedFloat(ref float value, float min, float max, float resolution)
    {
        SerializeUtil.CompressedFloatParams(min, max, resolution,
            out uint maxIntegerValue, out int bits, out float delta);
        uint integerValue = 0;
        if (!ReadBits(ref integerValue, bits))
        {
            return false;
        }
        if (integerValue > maxIntegerValue)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        value = SerializeInternal.DecodeCompressedFloat(integerValue, maxIntegerValue, delta, min);
        return true;
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeCompressedFloatPrecomputed(ref float value, uint maxIntegerValue, int bits, float delta, float min)
    {
        SerializeInternal.ValidatePrecomputedFloatParams(maxIntegerValue, bits, delta);
        uint integerValue = 0;
        if (!ReadBits(ref integerValue, bits))
        {
            return false;
        }
        if (integerValue > maxIntegerValue)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        value = SerializeInternal.DecodeCompressedFloat(integerValue, maxIntegerValue, delta, min);
        return true;
    }

    /// <summary>The shared read path of the fixed point overloads with storage of 64
    /// bits or fewer. On success raw holds the reconstructed raw fixed point value,
    /// guaranteed within [rawMin,rawMax]; offsets smuggled into the bit headroom are
    /// rejected, never clamped.</summary>
    private bool ReadFixed(ref ulong raw, ulong rawMin, ulong rawMax, int bits)
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (_reader.BitsRead + bits > _reader.NumBits)
        {
            return Fail(SerializeError.Overflow);
        }
        ulong offset;
        if (bits <= 32)
        {
            offset = _reader.ReadBitsUnchecked(bits);
        }
        else
        {
            // low dword first, then the high remainder: same convention as SerializeInt64
            uint lo = _reader.ReadBitsUnchecked(32);
            uint hi = _reader.ReadBitsUnchecked(bits - 32);
            offset = (ulong)hi << 32 | lo;
        }
        // compare and add in the unsigned domain: the raw range may be wider than 2^63
        if (offset > rawMax - rawMin)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        raw = rawMin + offset;
        return true;
    }

    /// <summary>The 128 bit storage counterpart of ReadFixed.</summary>
    private bool ReadFixed128(ref UInt128Value raw, UInt128Value rawMin, UInt128Value rawMax, int bits)
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (_reader.BitsRead + bits > _reader.NumBits)
        {
            return Fail(SerializeError.Overflow);
        }
        UInt128Value offset = ReadGroups128(bits);
        // compare and add in the unsigned domain: the raw range may be wider than 2^127
        if (offset > rawMax - rawMin)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        raw = rawMin + offset;
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref long value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(64, true, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        ulong raw = 0;
        if (!ReadFixed(ref raw, rawMin, rawMax, bits))
        {
            return false;
        }
        value = (long)raw;
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref ulong value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(64, false, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        ulong raw = 0;
        if (!ReadFixed(ref raw, rawMin, rawMax, bits))
        {
            return false;
        }
        value = raw;
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref int value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(32, true, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        ulong raw = 0;
        if (!ReadFixed(ref raw, rawMin, rawMax, bits))
        {
            return false;
        }
        value = (int)raw;
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref uint value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(32, false, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        ulong raw = 0;
        if (!ReadFixed(ref raw, rawMin, rawMax, bits))
        {
            return false;
        }
        value = (uint)raw;
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref short value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(16, true, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        ulong raw = 0;
        if (!ReadFixed(ref raw, rawMin, rawMax, bits))
        {
            return false;
        }
        value = (short)raw;
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref ushort value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(16, false, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        ulong raw = 0;
        if (!ReadFixed(ref raw, rawMin, rawMax, bits))
        {
            return false;
        }
        value = (ushort)raw;
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref Int128Value value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams128(true, integerBits, fractionBits, min, max,
            out UInt128Value rawMin, out UInt128Value rawMax, out int bits);
        UInt128Value raw = 0;
        if (!ReadFixed128(ref raw, rawMin, rawMax, bits))
        {
            return false;
        }
        value = (Int128Value)raw;
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref UInt128Value value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams128(false, integerBits, fractionBits, min, max,
            out UInt128Value rawMin, out UInt128Value rawMax, out int bits);
        UInt128Value raw = 0;
        if (!ReadFixed128(ref raw, rawMin, rawMax, bits))
        {
            return false;
        }
        value = raw;
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeBytes(Span<byte> data)
    {
        if (!SerializeAlign())
        {
            return false;
        }
        // compare in bytes rather than bits, consistent with the 64 bit bookkeeping
        if (data.Length > _reader.BitsRemaining / 8)
        {
            return Fail(SerializeError.Overflow);
        }
        _reader.ReadSliceUnchecked(data.Length).CopyTo(data);
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeString(ref string value, int bufferSize)
    {
        SerializeInternal.ValidateBufferSize(bufferSize);
        if (_error != SerializeError.None)
        {
            return false;
        }
        int length = 0;
        if (!SerializeInt(ref length, 0, bufferSize - 1))
        {
            return false;
        }
        if (!SerializeAlign())
        {
            return false;
        }
        if (length > _reader.BitsRemaining / 8)
        {
            return Fail(SerializeError.Overflow);
        }
        ReadOnlySpan<byte> utf8 = _reader.ReadSliceUnchecked(length);
        if (!SerializeCompat.Utf8IsValid(utf8))
        {
            return Fail(SerializeError.InvalidString);
        }
        // an interior NUL is valid UTF-8 but is refused (serialize#8 ruling): the
        // wire length field and the C-string length a downstream consumer perceives
        // would disagree -- the classic two-lengths smuggling primitive. The
        // terminator is never transmitted, so ANY NUL in the payload is interior.
        if (utf8.IndexOf((byte)0) >= 0)
        {
            return Fail(SerializeError.InvalidString);
        }
        value = Encoding.UTF8.GetString(utf8);
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeWideString(ref string value, int bufferSize)
    {
        SerializeInternal.ValidateBufferSize(bufferSize);
        if (_error != SerializeError.None)
        {
            return false;
        }
        int length = 0;
        if (!SerializeInt(ref length, 0, bufferSize - 1))
        {
            return false;
        }
        // bounds check the whole string before allocating
        if ((long)length * 32 > _reader.BitsRemaining)
        {
            return Fail(SerializeError.Overflow);
        }
        // each 32-bit group carries one UTF-16 CODE UNIT, not one code point
        // (STANDARD.md, adopted 2026-08-15). A C# string stores exactly these
        // units, so a valid surrogate pair "recombines" by adjacency: storing the
        // two units next to each other IS the astral character. What this reader
        // adds on top of the wire format is content validation (serialize#8
        // ruling: readers refuse): an unpaired surrogate is a refusal, not a
        // pass-through, and an interior NUL is refused as the two-lengths
        // smuggling primitive it is (wire length vs the shorter length a wcslen
        // consumer perceives; the terminator is never transmitted, so ANY NUL in
        // the payload is interior).
        char[] chars = new char[length];
        bool pendingHigh = false; // a high surrogate awaiting its low half
        for (int i = 0; i < length; i++)
        {
            uint unit = _reader.ReadBitsUnchecked(32);
            if (unit > 0xFFFF)
            {
                // not a UTF-16 code unit, and char could not hold it: fail
                // rather than truncate (the C 2-byte wchar_t path exactly)
                return Fail(SerializeError.ValueOutOfRange);
            }
            if (unit == 0)
            {
                return Fail(SerializeError.InvalidString); // interior NUL
            }
            if (pendingHigh)
            {
                if (unit < 0xDC00 || unit > 0xDFFF)
                {
                    return Fail(SerializeError.InvalidString); // high surrogate without its low half
                }
                pendingHigh = false;
            }
            else if (unit >= 0xD800 && unit <= 0xDBFF)
            {
                pendingHigh = true;
            }
            else if (unit >= 0xDC00 && unit <= 0xDFFF)
            {
                return Fail(SerializeError.InvalidString); // low surrogate with no high before it
            }
            chars[i] = (char)unit;
        }
        if (pendingHigh)
        {
            return Fail(SerializeError.InvalidString); // the payload ends inside a surrogate pair
        }
        value = new string(chars);
        return true;
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeAlign()
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        int alignBits = _reader.AlignBits;
        if (alignBits == 0)
        {
            return true;
        }
        if (_reader.BitsRead + alignBits > _reader.NumBits)
        {
            return Fail(SerializeError.Overflow);
        }
        if (_reader.ReadBitsUnchecked(alignBits) != 0)
        {
            return Fail(SerializeError.Align);
        }
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeObject(ISerializer obj)
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (!obj.Serialize(this))
        {
            Fail(SerializeError.ValueOutOfRange);
            return false;
        }
        return _error == SerializeError.None;
    }

    /// <inheritdoc/>
    public bool SerializeObject<T>(ref T obj) where T : ISerializer
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (!obj.Serialize(this))
        {
            Fail(SerializeError.ValueOutOfRange);
            return false;
        }
        return _error == SerializeError.None;
    }

    /// <inheritdoc/>
    public bool SerializeIntRelative(int previous, ref int current)
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        bool flag = false;
        if (!SerializeBool(ref flag))
        {
            return false;
        }
        if (flag)
        {
            // reconstruct in the unsigned domain: wraps rather than overflowing when
            // previous is near the top of the int range
            current = (int)((uint)previous + 1);
            return true;
        }
        foreach ((uint bucketMin, uint bucketMax) in SerializeInternal.IntRelativeBuckets)
        {
            if (!SerializeBool(ref flag))
            {
                return false;
            }
            if (flag)
            {
                int difference = 0;
                if (!SerializeInt(ref difference, (int)bucketMin, (int)bucketMax))
                {
                    return false;
                }
                current = (int)((uint)previous + (uint)difference);
                return true;
            }
        }
        uint v = 0;
        if (!ReadBits(ref v, 32))
        {
            return false;
        }
        // the absolute fallback encoding validates that the decoded value is greater
        // than previous
        if ((int)v <= previous)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        current = (int)v;
        return true;
    }

    /// <inheritdoc/>
    public int AlignBits => _reader.AlignBits;

    /// <inheritdoc/>
    public long BitsProcessed => _reader.BitsRead;

    /// <inheritdoc/>
    public long BytesProcessed => (_reader.BitsRead + 7) / 8;

    /// <summary>
    /// Begins a batch: a register-resident view of this stream for hot serialize
    /// paths. The batch owns the stream until its End is called — always call End,
    /// on every path out. See ReadBatch for the contract and the reason it is
    /// faster.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ReadBatch BeginBatch()
    {
        return new ReadBatch(this);
    }

    /// <summary>The bit reader, for batch state capture and delegated calls.</summary>
    internal BitReader Reader => _reader;

    /// <summary>
    /// The latched error, batch transfer form: an open batch carries the error
    /// itself (seeded from the stream at BeginBatch) and preserves first-error
    /// latching internally, so storing it back is a plain assignment.
    /// </summary>
    internal SerializeError BatchError
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => _error;
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        set => _error = value;
    }

    /// <summary>The number of bits still available to read, so callers can preflight a
    /// read without dropping to the BitReader layer.</summary>
    public long BitsRemaining => _reader.BitsRemaining;

    /// <inheritdoc/>
    public SerializeError Error => _error;

    /// <inheritdoc/>
    public bool Ok => _error == SerializeError.None;

    /// <inheritdoc/>
    public object? Context { get; set; }
}

/// <summary>
/// Counts how many bits it would take to serialize something, without writing any data.
/// It acts like a write stream (IsWriting is true), so a unified serialize function
/// measures the exact same fields it would write.
///
/// When the serialization includes alignment to byte boundaries, the measurement is an
/// estimate rather than exact, because the true pad depends on where the object lands
/// in the final bit stream. The estimate is guaranteed to be conservative: every align
/// is counted as the worst case 7 bits.
///
/// As a write-mode stream it shares the writer's trust contract (serialize#52): value
/// ranges are Debug.Assert in debug builds and unchecked in release, matching the C++
/// MeasureStream, so measure and write always agree about the same object.
/// </summary>
public sealed class MeasureStream : IBitStream
{
    private long _bitsWritten;
    private SerializeError _error;

    /// <summary>Creates a measure stream.</summary>
    public MeasureStream()
    {
    }

    /// <summary>Clears the measured bit count and any latched error. The context is
    /// kept.</summary>
    public void Reset()
    {
        _bitsWritten = 0;
        _error = SerializeError.None;
    }

    /// <inheritdoc/>
    public bool IsWriting => true;

    /// <inheritdoc/>
    public bool IsReading => false;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool Fail(SerializeError error)
    {
        if (_error == SerializeError.None)
        {
            _error = error;
        }
        return false;
    }

    /// <summary>Adds bits to the measured count. The count is 64 bit like the other
    /// streams, so bulk byte measurements never overflow.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool Measure(long bits)
    {
        _bitsWritten += bits;
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeBits(ref uint value, int bits)
    {
        Debug.Assert(bits >= 1 && bits <= 32, SerializeInternal.BitsRangeMessage);
        return Measure(bits);
    }

    /// <inheritdoc/>
    public bool SerializeBits64(ref ulong value, int bits)
    {
        Debug.Assert(bits >= 1 && bits <= 64, SerializeInternal.BitsRange64Message);
        return Measure(bits);
    }

    /// <inheritdoc/>
    public bool SerializeInt(ref int value, int min, int max)
    {
        Debug.Assert(min <= max, SerializeInternal.MinMaxMessage);
        Debug.Assert(value >= min && value <= max, SerializeInternal.WriteRangeAssertMessage);
        return Measure(SerializeUtil.BitsRequired((uint)min, (uint)max));
    }

    /// <inheritdoc/>
    public bool SerializeInt64(ref long value, long min, long max)
    {
        Debug.Assert(min <= max, SerializeInternal.MinMaxMessage);
        Debug.Assert(value >= min && value <= max, SerializeInternal.WriteRangeAssertMessage);
        return Measure(SerializeUtil.BitsRequired64((ulong)min, (ulong)max));
    }

    /// <inheritdoc/>
    public bool SerializeInt128(ref Int128Value value, Int128Value min, Int128Value max)
    {
        Debug.Assert(min <= max, SerializeInternal.MinMaxMessage);
        Debug.Assert(value >= min && value <= max, SerializeInternal.WriteRangeAssertMessage);
        return Measure(SerializeUtil.BitsRequired128((UInt128Value)min, (UInt128Value)max));
    }

    /// <inheritdoc/>
    public bool SerializeByte(ref byte value) => Measure(8);

    /// <inheritdoc/>
    public bool SerializeUInt16(ref ushort value) => Measure(16);

    /// <inheritdoc/>
    public bool SerializeUInt32(ref uint value) => Measure(32);

    /// <inheritdoc/>
    public bool SerializeUInt64(ref ulong value) => Measure(64);

    /// <inheritdoc/>
    public bool SerializeUInt128(ref UInt128Value value) => Measure(128);

    /// <inheritdoc/>
    public bool SerializeBool(ref bool value) => Measure(1);

    /// <inheritdoc/>
    public bool SerializeFloat(ref float value) => Measure(32);

    /// <inheritdoc/>
    public bool SerializeDouble(ref double value) => Measure(64);

    /// <inheritdoc/>
    public bool SerializeCompressedFloat(ref float value, float min, float max, float resolution)
    {
        SerializeUtil.CompressedFloatParams(min, max, resolution,
            out _, out int bits, out _);
        return Measure(bits);
    }

    /// <inheritdoc/>
    public bool SerializeCompressedFloatPrecomputed(ref float value, uint maxIntegerValue, int bits, float delta, float min)
    {
        SerializeInternal.ValidatePrecomputedFloatParams(maxIntegerValue, bits, delta);
        return Measure(bits);
    }

    /// <summary>The shared measure path of the fixed point overloads with storage of
    /// 64 bits or fewer: the value is range asserted like the write stream (debug
    /// builds only), then the exact bit cost of the range is counted — fixed point
    /// involves no alignment, so the measurement is exact, not just conservative.</summary>
    private bool MeasureFixed(ulong raw, ulong rawMin, ulong rawMax, int bits)
    {
        // compare in the unsigned domain: the raw range may be wider than 2^63
        Debug.Assert(raw - rawMin <= rawMax - rawMin, SerializeInternal.WriteRangeAssertMessage);
        return Measure(bits);
    }

    /// <summary>The 128 bit storage counterpart of MeasureFixed.</summary>
    private bool MeasureFixed128(UInt128Value raw, UInt128Value rawMin, UInt128Value rawMax, int bits)
    {
        // compare in the unsigned domain: the raw range may be wider than 2^127
        Debug.Assert(raw - rawMin <= rawMax - rawMin, SerializeInternal.WriteRangeAssertMessage);
        return Measure(bits);
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref long value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(64, true, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        return MeasureFixed((ulong)value, rawMin, rawMax, bits);
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref ulong value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(64, false, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        return MeasureFixed(value, rawMin, rawMax, bits);
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref int value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(32, true, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        return MeasureFixed((ulong)value, rawMin, rawMax, bits);
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref uint value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(32, false, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        return MeasureFixed(value, rawMin, rawMax, bits);
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref short value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(16, true, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        return MeasureFixed((ulong)value, rawMin, rawMax, bits);
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref ushort value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams(16, false, integerBits, fractionBits, min, max,
            out ulong rawMin, out ulong rawMax, out int bits);
        return MeasureFixed(value, rawMin, rawMax, bits);
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref Int128Value value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams128(true, integerBits, fractionBits, min, max,
            out UInt128Value rawMin, out UInt128Value rawMax, out int bits);
        return MeasureFixed128((UInt128Value)value, rawMin, rawMax, bits);
    }

    /// <inheritdoc/>
    public bool SerializeFixed(ref UInt128Value value, int integerBits, int fractionBits, long min, long max)
    {
        SerializeInternal.FixedPointParams128(false, integerBits, fractionBits, min, max,
            out UInt128Value rawMin, out UInt128Value rawMax, out int bits);
        return MeasureFixed128(value, rawMin, rawMax, bits);
    }

    /// <inheritdoc/>
    public bool SerializeBytes(Span<byte> data)
    {
        if (!SerializeAlign())
        {
            return false;
        }
        return Measure((long)data.Length * 8);
    }

    /// <inheritdoc/>
    public bool SerializeString(ref string value, int bufferSize)
    {
        SerializeInternal.ValidateBufferSize(bufferSize);
        int byteCount = Encoding.UTF8.GetByteCount(value);
        Debug.Assert(byteCount < bufferSize, SerializeInternal.WriteStringAssertMessage);
        int length = byteCount;
        if (!SerializeInt(ref length, 0, bufferSize - 1))
        {
            return false;
        }
        if (!SerializeAlign())
        {
            return false;
        }
        return Measure((long)byteCount * 8);
    }

    /// <inheritdoc/>
    public bool SerializeWideString(ref string value, int bufferSize)
    {
        SerializeInternal.ValidateBufferSize(bufferSize);
        // counts UTF-16 code units -- value.Length is exactly the group count the
        // write transmits (STANDARD.md, adopted 2026-08-15), so measure and write
        // agree bit for bit
        int length = value.Length;
        Debug.Assert(length < bufferSize, SerializeInternal.WriteStringAssertMessage);
        if (!SerializeInt(ref length, 0, bufferSize - 1))
        {
            return false;
        }
        return Measure((long)length * 32);
    }

    /// <inheritdoc/>
    public bool SerializeAlign()
    {
        return Measure(AlignBits);
    }

    /// <inheritdoc/>
    public bool SerializeObject(ISerializer obj)
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (!obj.Serialize(this))
        {
            Fail(SerializeError.ValueOutOfRange);
            return false;
        }
        return _error == SerializeError.None;
    }

    /// <inheritdoc/>
    public bool SerializeObject<T>(ref T obj) where T : ISerializer
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (!obj.Serialize(this))
        {
            Fail(SerializeError.ValueOutOfRange);
            return false;
        }
        return _error == SerializeError.None;
    }

    /// <inheritdoc/>
    public bool SerializeIntRelative(int previous, ref int current)
    {
        Debug.Assert(previous < current, SerializeInternal.WriteIntRelativeAssertMessage);
        uint difference = (uint)current - (uint)previous;
        int bits = 1;
        if (difference != 1)
        {
            bool matched = false;
            foreach ((uint bucketMin, uint bucketMax) in SerializeInternal.IntRelativeBuckets)
            {
                bits++;
                if (difference <= bucketMax)
                {
                    bits += SerializeUtil.BitsRequired(bucketMin, bucketMax);
                    matched = true;
                    break;
                }
            }
            if (!matched)
            {
                bits += 32;
            }
        }
        return Measure(bits);
    }

    /// <summary>The worst case align of 7 bits: the true pad depends on where the
    /// object lands in the final bit stream, so the measurement is
    /// conservative.</summary>
    public int AlignBits => 7;

    /// <inheritdoc/>
    public long BitsProcessed => _bitsWritten;

    /// <inheritdoc/>
    public long BytesProcessed => (_bitsWritten + 7) / 8;

    /// <inheritdoc/>
    public SerializeError Error => _error;

    /// <inheritdoc/>
    public bool Ok => _error == SerializeError.None;

    /// <inheritdoc/>
    public object? Context { get; set; }
}

/// <summary>
/// A register-resident view of a WriteStream for hot serialize paths.
///
/// The streams are heap objects, so the JIT reloads and stores the packer state
/// (scratch, scratch bit count, bits written) around every serialize call even
/// after inlining: heap fields cannot live in registers across calls. A batch
/// lifts that state into the fields of a ref struct at BeginBatch, serializes
/// against the locals — the same wire logic, the same validation, the same
/// latched error model, byte-for-byte identical output — and stores the state
/// back exactly once at End.
///
/// <code>
/// WriteBatch batch = stream.BeginBatch();
/// batch.SerializeBits(ref value, 8);
/// ...
/// batch.End();
/// </code>
///
/// Contract:
///   - The batch owns the stream between BeginBatch and End. Calling serialize
///     methods or Reset on the underlying stream, or beginning a second batch,
///     while a batch is open is API misuse, exactly like writing after
///     FlushBits.
///   - Always call End, on every path out of the serialize code, including
///     early aborts. End is idempotent, and it is what stores the packer state
///     and the latched error back to the stream: a batch dropped without End
///     silently loses its writes. Serialize calls on an ended batch are API
///     misuse.
///   - Batches nest by sequence, not by scope: End one batch before beginning
///     the next. Stream and batch calls can be interleaved freely at batch
///     granularity.
///
/// The fixed-size scalar operations up to 64 bits are the register-resident hot
/// path. Everything else — bulk, variable-size and object operations
/// (SerializeBytes, the strings, SerializeObject, SerializeIntRelative) and the
/// 128 bit and fixed point operations (SerializeInt128, SerializeUInt128, the
/// SerializeFixed overloads) — syncs the state down, runs through the underlying
/// stream, and recaptures — byte identical, at class-path speed.
///
/// Two measured rules for using batches well (Apple M2, schema harness):
///   - Only pass a batch by ref to helpers the JIT will inline
///     (MethodImplOptions.AggressiveInlining). A real call taking
///     <c>ref WriteBatch</c> address-exposes the struct and enregistration dies
///     for the whole calling scope — measured SLOWER than no batch at all
///     (probe_header write 0.71x vs 1.28x with the helper inlined).
///   - Batch scalar-dense serialize bodies. A body dominated by one bulk op
///     (a length int plus SerializeBytes, like a chat message) pays the batch
///     capture/restore without enough scalar traffic to win it back — measured
///     0.91x. Leave such types on the stream.
///
/// The batch is additive API: nothing about the streams changes, and code that
/// never begins a batch behaves exactly as before. Unified serialize functions
/// keep taking IBitStream; a batch is what generated or hand-tuned per-direction
/// code targets when tiny-message throughput matters.
/// </summary>
public ref struct WriteBatch
{
    private readonly WriteStream _stream;
    private byte[] _data;
    private ulong _scratch;
    private long _numBits;
    private long _bitsWritten;
    private long _wordIndex;
    private int _scratchBits;
    private SerializeError _error;
    private bool _ended;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal WriteBatch(WriteStream stream)
    {
        _stream = stream;
        stream.Writer.CaptureState(out _data, out _scratch, out _numBits,
            out _bitsWritten, out _wordIndex, out _scratchBits);
        _error = stream.BatchError;
        _ended = false;
    }

    /// <summary>True: a batch over a WriteStream writes values.</summary>
    public bool IsWriting => true;

    /// <summary>False: a batch over a WriteStream never reads.</summary>
    public bool IsReading => false;

    /// <summary>
    /// Ends the batch, storing the packer state and the latched error back to the
    /// stream. Idempotent. Always call this on every path out; the batch's writes
    /// are not visible to the stream until it runs.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void End()
    {
        if (_ended)
        {
            return;
        }
        _ended = true;
        Sync();
    }

    /// <summary>Stores the batch state down to the stream so a class-path call can
    /// run against current state.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void Sync()
    {
        _stream.Writer.RestoreState(_scratch, _bitsWritten, _wordIndex, _scratchBits);
        _stream.BatchError = _error;
    }

    /// <summary>Recaptures the stream state after a delegated class-path call.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void Recapture()
    {
        _stream.Writer.CaptureState(out _data, out _scratch, out _numBits,
            out _bitsWritten, out _wordIndex, out _scratchBits);
        _error = _stream.BatchError;
    }

    // no Fail here: the write path performs no validation of its own (writer
    // contract violations are Debug.Assert), so nothing in a WriteBatch latches an
    // error directly — errors only ride in from the stream via Recapture, where
    // first-error latching already happened.

    /// <summary>The BitWriter hot path against batch-local state: bit-identical logic
    /// to BitWriter.WriteBitsUnchecked.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void WriteBitsUnchecked(uint value, int bits)
    {
        value &= (uint)((1UL << bits) - 1);

        _scratch |= (ulong)value << _scratchBits;

        int newScratchBits = _scratchBits + bits;

        if (newScratchBits >= 64)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(_data.AsSpan((int)(_wordIndex * 8)), _scratch);
            _wordIndex++;
            // recover the bits that spilled past 64. newScratchBits >= 64 with
            // bits <= 32 implies the shift is in [1,32]
            _scratch = (ulong)value >> (64 - _scratchBits);
            _scratchBits = newScratchBits - 64;
        }
        else
        {
            _scratchBits = newScratchBits;
        }

        _bitsWritten += bits;
    }

    /// <summary>Writes bits that have already been validated to [1,32]. Capacity is
    /// the writer's contract: asserted in debug, unchecked in release — identical to
    /// WriteStream.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool WriteBits(uint value, int bits)
    {
        Debug.Assert(_bitsWritten + bits <= _numBits, SerializeInternal.WriteOverflowMessage);
        WriteBitsUnchecked(value, bits);
        return true;
    }

    /// <summary>Serializes the low order bits of an unsigned integer. bits must be in
    /// [1,32]. Identical semantics to WriteStream.SerializeBits.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeBits(ref uint value, int bits)
    {
        Debug.Assert(bits >= 1 && bits <= 32, SerializeInternal.BitsRangeMessage);
        return WriteBits(value, bits);
    }

    /// <summary>Serializes the low order bits of a 64 bit unsigned integer. bits must
    /// be in [1,64]. Identical semantics to WriteStream.SerializeBits64.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeBits64(ref ulong value, int bits)
    {
        Debug.Assert(bits >= 1 && bits <= 64, SerializeInternal.BitsRange64Message);
        if (bits <= 32)
        {
            return WriteBits((uint)value, bits);
        }
        Debug.Assert(_bitsWritten + bits <= _numBits, SerializeInternal.WriteOverflowMessage);
        // low dword first, then the high remainder
        WriteBitsUnchecked((uint)value, 32);
        WriteBitsUnchecked((uint)(value >> 32), bits - 32);
        return true;
    }

    /// <summary>Serializes a signed integer in [min,max]. Identical semantics to
    /// WriteStream.SerializeInt.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeInt(ref int value, int min, int max)
    {
        Debug.Assert(min <= max, SerializeInternal.MinMaxMessage);
        int v = value;
        Debug.Assert(v >= min && v <= max, SerializeInternal.WriteRangeAssertMessage);
        int bits = SerializeUtil.BitsRequired((uint)min, (uint)max);
        // subtract in the unsigned domain: the range may be wider than 2^31
        return WriteBits((uint)v - (uint)min, bits);
    }

    /// <summary>Serializes a signed 64 bit integer in [min,max]. Identical semantics
    /// to WriteStream.SerializeInt64.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeInt64(ref long value, long min, long max)
    {
        Debug.Assert(min <= max, SerializeInternal.MinMaxMessage);
        long v = value;
        Debug.Assert(v >= min && v <= max, SerializeInternal.WriteRangeAssertMessage);
        int bits = SerializeUtil.BitsRequired64((ulong)min, (ulong)max);
        // subtract in the unsigned domain: the range may be wider than 2^63
        ulong unsigned = (ulong)v - (ulong)min;
        if (bits <= 32)
        {
            return WriteBits((uint)unsigned, bits);
        }
        Debug.Assert(_bitsWritten + bits <= _numBits, SerializeInternal.WriteOverflowMessage);
        // low dword first, then the high remainder: same convention as SerializeBits64
        WriteBitsUnchecked((uint)unsigned, 32);
        WriteBitsUnchecked((uint)(unsigned >> 32), bits - 32);
        return true;
    }

    /// <summary>Serializes a byte. Identical semantics to WriteStream.SerializeByte.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeByte(ref byte value) => WriteBits(value, 8);

    /// <summary>Serializes an unsigned 16 bit integer. Identical semantics to
    /// WriteStream.SerializeUInt16.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeUInt16(ref ushort value) => WriteBits(value, 16);

    /// <summary>Serializes an unsigned 32 bit integer. Identical semantics to
    /// WriteStream.SerializeUInt32.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeUInt32(ref uint value) => WriteBits(value, 32);

    /// <summary>Serializes an unsigned 64 bit integer (low dword first). Identical
    /// semantics to WriteStream.SerializeUInt64.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeUInt64(ref ulong value)
    {
        Debug.Assert(_bitsWritten + 64 <= _numBits, SerializeInternal.WriteOverflowMessage);
        WriteBitsUnchecked((uint)value, 32);
        WriteBitsUnchecked((uint)(value >> 32), 32);
        return true;
    }

    /// <summary>Serializes a boolean value with one bit. Identical semantics to
    /// WriteStream.SerializeBool.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeBool(ref bool value) => WriteBits(value ? 1u : 0u, 1);

    /// <summary>Serializes an uncompressed 32 bit floating point value. Identical
    /// semantics to WriteStream.SerializeFloat.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFloat(ref float value)
    {
        return WriteBits(SerializeCompat.SingleToUInt32Bits(value), 32);
    }

    /// <summary>Serializes an uncompressed 64 bit floating point value. Identical
    /// semantics to WriteStream.SerializeDouble.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeDouble(ref double value)
    {
        ulong bits = SerializeCompat.DoubleToUInt64Bits(value);
        return SerializeUInt64(ref bits);
    }

    /// <summary>Serializes a floating point value in [min,max] with the given
    /// resolution. Identical semantics to WriteStream.SerializeCompressedFloat.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeCompressedFloat(ref float value, float min, float max, float resolution)
    {
        SerializeUtil.CompressedFloatParams(min, max, resolution,
            out uint maxIntegerValue, out int bits, out float delta);
        uint integerValue = SerializeInternal.QuantizeCompressedFloat(value, min, delta, maxIntegerValue);
        return WriteBits(integerValue, bits);
    }

    /// <summary>Serializes a compressed float from precomputed wire constants.
    /// Identical semantics to WriteStream.SerializeCompressedFloatPrecomputed.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeCompressedFloatPrecomputed(ref float value, uint maxIntegerValue, int bits, float delta, float min)
    {
        SerializeInternal.ValidatePrecomputedFloatParams(maxIntegerValue, bits, delta);
        uint integerValue = SerializeInternal.QuantizeCompressedFloat(value, min, delta, maxIntegerValue);
        return WriteBits(integerValue, bits);
    }

    /// <summary>Pads the stream with zero bits to the next byte boundary. Identical
    /// semantics to WriteStream.SerializeAlign.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeAlign()
    {
        int alignBits = (int)((8 - _bitsWritten % 8) % 8);
        if (alignBits == 0)
        {
            return true;
        }
        return WriteBits(0, alignBits);
    }

    /// <summary>Serializes an array of bytes, aligning first. Delegated: syncs state
    /// down, runs WriteStream.SerializeBytes, recaptures — byte identical to the
    /// stream call.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeBytes(Span<byte> data)
    {
        Sync();
        bool ok = _stream.SerializeBytes(data);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a string of fewer than bufferSize UTF-8 bytes. Delegated:
    /// syncs state down, runs WriteStream.SerializeString, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeString(ref string value, int bufferSize)
    {
        Sync();
        bool ok = _stream.SerializeString(ref value, bufferSize);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a string as 32 bits per UTF-16 code unit. Delegated: syncs state
    /// down, runs WriteStream.SerializeWideString, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeWideString(ref string value, int bufferSize)
    {
        Sync();
        bool ok = _stream.SerializeWideString(ref value, bufferSize);
        Recapture();
        return ok;
    }

    /// <summary>Serializes an object that implements ISerializer. Delegated: the
    /// object's Serialize function runs against the underlying stream. For struct
    /// implementers use the generic overload, which does not box.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeObject(ISerializer obj)
    {
        Sync();
        bool ok = _stream.SerializeObject(obj);
        Recapture();
        return ok;
    }

    /// <summary>Serializes an object that implements ISerializer, by ref, without
    /// boxing. Delegated: the object's Serialize function runs against the underlying
    /// stream.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeObject<T>(ref T obj) where T : ISerializer
    {
        Sync();
        bool ok = _stream.SerializeObject(ref obj);
        Recapture();
        return ok;
    }

    /// <summary>Serializes an integer relative to a previous integer. Delegated:
    /// syncs state down, runs WriteStream.SerializeIntRelative, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeIntRelative(int previous, ref int current)
    {
        Sync();
        bool ok = _stream.SerializeIntRelative(previous, ref current);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a signed 128 bit integer in [min,max]. Delegated: syncs
    /// state down, runs WriteStream.SerializeInt128, recaptures — byte identical to
    /// the stream call.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeInt128(ref Int128Value value, Int128Value min, Int128Value max)
    {
        Sync();
        bool ok = _stream.SerializeInt128(ref value, min, max);
        Recapture();
        return ok;
    }

    /// <summary>Serializes an unsigned 128 bit integer as a full 128 bits. Delegated:
    /// syncs state down, runs WriteStream.SerializeUInt128, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeUInt128(ref UInt128Value value)
    {
        Sync();
        bool ok = _stream.SerializeUInt128(ref value);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a fixed point value with signed 64 bit storage. Delegated:
    /// syncs state down, runs the WriteStream overload, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFixed(ref long value, int integerBits, int fractionBits, long min, long max)
    {
        Sync();
        bool ok = _stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a fixed point value with unsigned 64 bit storage. Delegated:
    /// syncs state down, runs the WriteStream overload, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFixed(ref ulong value, int integerBits, int fractionBits, long min, long max)
    {
        Sync();
        bool ok = _stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a fixed point value with signed 32 bit storage. Delegated:
    /// syncs state down, runs the WriteStream overload, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFixed(ref int value, int integerBits, int fractionBits, long min, long max)
    {
        Sync();
        bool ok = _stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a fixed point value with unsigned 32 bit storage. Delegated:
    /// syncs state down, runs the WriteStream overload, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFixed(ref uint value, int integerBits, int fractionBits, long min, long max)
    {
        Sync();
        bool ok = _stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a fixed point value with signed 16 bit storage. Delegated:
    /// syncs state down, runs the WriteStream overload, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFixed(ref short value, int integerBits, int fractionBits, long min, long max)
    {
        Sync();
        bool ok = _stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a fixed point value with unsigned 16 bit storage. Delegated:
    /// syncs state down, runs the WriteStream overload, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFixed(ref ushort value, int integerBits, int fractionBits, long min, long max)
    {
        Sync();
        bool ok = _stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a fixed point value with signed 128 bit storage. Delegated:
    /// syncs state down, runs the WriteStream overload, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFixed(ref Int128Value value, int integerBits, int fractionBits, long min, long max)
    {
        Sync();
        bool ok = _stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a fixed point value with unsigned 128 bit storage. Delegated:
    /// syncs state down, runs the WriteStream overload, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFixed(ref UInt128Value value, int integerBits, int fractionBits, long min, long max)
    {
        Sync();
        bool ok = _stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
        Recapture();
        return ok;
    }

    /// <summary>The number of bits required to align to the next byte boundary, in
    /// [0,7], from the batch's current position.</summary>
    public int AlignBits => (int)((8 - _bitsWritten % 8) % 8);

    /// <summary>The number of bits written, counting the batch's own writes.</summary>
    public long BitsProcessed => _bitsWritten;

    /// <summary>The number of bits written rounded up to the next byte, counting the
    /// batch's own writes.</summary>
    public long BytesProcessed => (_bitsWritten + 7) / 8;

    /// <summary>The number of bits still available to write.</summary>
    public long BitsAvailable => _numBits - _bitsWritten;

    /// <summary>The first error latched on the batch or carried in from the stream,
    /// or SerializeError.None.</summary>
    public SerializeError Error => _error;

    /// <summary>True while no error is latched.</summary>
    public bool Ok => _error == SerializeError.None;

    /// <summary>The context value of the underlying stream.</summary>
    public object? Context
    {
        get => _stream.Context;
        set => _stream.Context = value;
    }
}

/// <summary>
/// A register-resident view of a ReadStream for hot serialize paths: the read-side
/// counterpart of WriteBatch, lifting the read cursor into a ref struct so the JIT
/// can keep it in registers across calls. Same wire logic, same validation and
/// hostile-data guarantees, same latched error model, identical decode results.
/// The contract is WriteBatch's: the batch owns the stream between BeginBatch and
/// End; always call End on every path out; End is idempotent.
/// </summary>
public ref struct ReadBatch
{
    private readonly ReadStream _stream;
    private byte[] _data;
    private long _numBits;
    private long _bitsRead;
    private SerializeError _error;
    private bool _ended;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal ReadBatch(ReadStream stream)
    {
        _stream = stream;
        stream.Reader.CaptureState(out _data, out _numBits, out _bitsRead);
        _error = stream.BatchError;
        _ended = false;
    }

    /// <summary>False: a batch over a ReadStream never writes.</summary>
    public bool IsWriting => false;

    /// <summary>True: a batch over a ReadStream reads values.</summary>
    public bool IsReading => true;

    /// <summary>
    /// Ends the batch, storing the read cursor and the latched error back to the
    /// stream. Idempotent. Always call this on every path out; the batch's reads
    /// are not visible to the stream until it runs.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void End()
    {
        if (_ended)
        {
            return;
        }
        _ended = true;
        Sync();
    }

    /// <summary>Stores the batch state down to the stream so a class-path call can
    /// run against current state.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void Sync()
    {
        _stream.Reader.RestoreState(_bitsRead);
        _stream.BatchError = _error;
    }

    /// <summary>Recaptures the stream state after a delegated class-path call.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void Recapture()
    {
        _stream.Reader.CaptureState(out _data, out _numBits, out _bitsRead);
        _error = _stream.BatchError;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool Fail(SerializeError error)
    {
        if (_error == SerializeError.None)
        {
            _error = error;
        }
        return false;
    }

    /// <summary>The BitReader hot path against batch-local state: bit-identical logic
    /// to BitReader.ReadBitsUnchecked, including the slack-free window assembly near
    /// the end of the buffer.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private uint ReadBitsUnchecked(int bits)
    {
        int byteIndex = (int)(_bitsRead >> 3);

        ulong window;
        if (byteIndex + 8 <= _data.Length)
        {
            window = BinaryPrimitives.ReadUInt64LittleEndian(_data.AsSpan(byteIndex));
        }
        else
        {
            // near the end of a buffer with no slack past the data: assemble the
            // window from the remaining bytes
            window = 0;
            for (int i = _data.Length - byteIndex - 1; i >= 0; i--)
            {
                window = window << 8 | _data[byteIndex + i];
            }
        }

        uint output = (uint)(window >> (int)(_bitsRead & 7)) & (uint)((1UL << bits) - 1);

        _bitsRead += bits;

        return output;
    }

    /// <summary>Bounds checks and reads bits that have already been validated to [1,32].</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool ReadBits(ref uint value, int bits)
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (_bitsRead + bits > _numBits)
        {
            return Fail(SerializeError.Overflow);
        }
        value = ReadBitsUnchecked(bits);
        return true;
    }

    /// <summary>Serializes the low order bits of an unsigned integer. bits must be in
    /// [1,32]. Identical semantics to ReadStream.SerializeBits.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeBits(ref uint value, int bits)
    {
        Debug.Assert(bits >= 1 && bits <= 32, SerializeInternal.BitsRangeMessage);
        return ReadBits(ref value, bits);
    }

    /// <summary>Serializes the low order bits of a 64 bit unsigned integer. bits must
    /// be in [1,64]. Identical semantics to ReadStream.SerializeBits64.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeBits64(ref ulong value, int bits)
    {
        Debug.Assert(bits >= 1 && bits <= 64, SerializeInternal.BitsRange64Message);
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (_bitsRead + bits > _numBits)
        {
            return Fail(SerializeError.Overflow);
        }
        if (bits <= 32)
        {
            value = ReadBitsUnchecked(bits);
            return true;
        }
        // low dword first, then the high remainder
        uint lo = ReadBitsUnchecked(32);
        uint hi = ReadBitsUnchecked(bits - 32);
        value = (ulong)hi << 32 | lo;
        return true;
    }

    /// <summary>Serializes a signed integer in [min,max]. Identical semantics to
    /// ReadStream.SerializeInt: on success the value is guaranteed in range.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeInt(ref int value, int min, int max)
    {
        Debug.Assert(min <= max, SerializeInternal.MinMaxMessage);
        if (_error != SerializeError.None)
        {
            return false;
        }
        int bits = SerializeUtil.BitsRequired((uint)min, (uint)max);
        if (_bitsRead + bits > _numBits)
        {
            return Fail(SerializeError.Overflow);
        }
        uint unsigned = ReadBitsUnchecked(bits);
        // compare and add in the unsigned domain: the range may be wider than 2^31
        if (unsigned > (uint)max - (uint)min)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        value = (int)(unsigned + (uint)min);
        return true;
    }

    /// <summary>Serializes a signed 64 bit integer in [min,max]. Identical semantics
    /// to ReadStream.SerializeInt64: on success the value is guaranteed in range.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeInt64(ref long value, long min, long max)
    {
        Debug.Assert(min <= max, SerializeInternal.MinMaxMessage);
        if (_error != SerializeError.None)
        {
            return false;
        }
        int bits = SerializeUtil.BitsRequired64((ulong)min, (ulong)max);
        if (_bitsRead + bits > _numBits)
        {
            return Fail(SerializeError.Overflow);
        }
        ulong unsigned;
        if (bits <= 32)
        {
            unsigned = ReadBitsUnchecked(bits);
        }
        else
        {
            // low dword first, then the high remainder: same convention as SerializeBits64
            uint lo = ReadBitsUnchecked(32);
            uint hi = ReadBitsUnchecked(bits - 32);
            unsigned = (ulong)hi << 32 | lo;
        }
        // compare and add in the unsigned domain: the range may be wider than 2^63
        if (unsigned > (ulong)max - (ulong)min)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        value = (long)(unsigned + (ulong)min);
        return true;
    }

    /// <summary>Serializes a byte. Identical semantics to ReadStream.SerializeByte.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeByte(ref byte value)
    {
        uint v = 0;
        if (!ReadBits(ref v, 8))
        {
            return false;
        }
        value = (byte)v;
        return true;
    }

    /// <summary>Serializes an unsigned 16 bit integer. Identical semantics to
    /// ReadStream.SerializeUInt16.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeUInt16(ref ushort value)
    {
        uint v = 0;
        if (!ReadBits(ref v, 16))
        {
            return false;
        }
        value = (ushort)v;
        return true;
    }

    /// <summary>Serializes an unsigned 32 bit integer. Identical semantics to
    /// ReadStream.SerializeUInt32.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeUInt32(ref uint value) => ReadBits(ref value, 32);

    /// <summary>Serializes an unsigned 64 bit integer (low dword first). Identical
    /// semantics to ReadStream.SerializeUInt64.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeUInt64(ref ulong value)
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (_bitsRead + 64 > _numBits)
        {
            return Fail(SerializeError.Overflow);
        }
        uint lo = ReadBitsUnchecked(32);
        uint hi = ReadBitsUnchecked(32);
        value = (ulong)hi << 32 | lo;
        return true;
    }

    /// <summary>Serializes a boolean value with one bit. Identical semantics to
    /// ReadStream.SerializeBool.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeBool(ref bool value)
    {
        uint v = 0;
        if (!ReadBits(ref v, 1))
        {
            return false;
        }
        value = v != 0;
        return true;
    }

    /// <summary>Serializes an uncompressed 32 bit floating point value. Identical
    /// semantics to ReadStream.SerializeFloat.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFloat(ref float value)
    {
        uint v = 0;
        if (!ReadBits(ref v, 32))
        {
            return false;
        }
        value = SerializeCompat.UInt32BitsToSingle(v);
        return true;
    }

    /// <summary>Serializes an uncompressed 64 bit floating point value. Identical
    /// semantics to ReadStream.SerializeDouble.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeDouble(ref double value)
    {
        ulong v = 0;
        if (!SerializeUInt64(ref v))
        {
            return false;
        }
        value = SerializeCompat.UInt64BitsToDouble(v);
        return true;
    }

    /// <summary>Serializes a floating point value in [min,max] with the given
    /// resolution. Identical semantics to ReadStream.SerializeCompressedFloat.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeCompressedFloat(ref float value, float min, float max, float resolution)
    {
        SerializeUtil.CompressedFloatParams(min, max, resolution,
            out uint maxIntegerValue, out int bits, out float delta);
        uint integerValue = 0;
        if (!ReadBits(ref integerValue, bits))
        {
            return false;
        }
        if (integerValue > maxIntegerValue)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        value = SerializeInternal.DecodeCompressedFloat(integerValue, maxIntegerValue, delta, min);
        return true;
    }

    /// <summary>Serializes a compressed float from precomputed wire constants.
    /// Identical semantics to ReadStream.SerializeCompressedFloatPrecomputed.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeCompressedFloatPrecomputed(ref float value, uint maxIntegerValue, int bits, float delta, float min)
    {
        SerializeInternal.ValidatePrecomputedFloatParams(maxIntegerValue, bits, delta);
        uint integerValue = 0;
        if (!ReadBits(ref integerValue, bits))
        {
            return false;
        }
        if (integerValue > maxIntegerValue)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        value = SerializeInternal.DecodeCompressedFloat(integerValue, maxIntegerValue, delta, min);
        return true;
    }

    /// <summary>Reads an align, verifying the padding bits are zero. Identical
    /// semantics to ReadStream.SerializeAlign.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeAlign()
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        int alignBits = (int)((8 - _bitsRead % 8) % 8);
        if (alignBits == 0)
        {
            return true;
        }
        if (_bitsRead + alignBits > _numBits)
        {
            return Fail(SerializeError.Overflow);
        }
        if (ReadBitsUnchecked(alignBits) != 0)
        {
            return Fail(SerializeError.Align);
        }
        return true;
    }

    /// <summary>Serializes an array of bytes, aligning first. Delegated: syncs state
    /// down, runs ReadStream.SerializeBytes, recaptures — identical decode.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeBytes(Span<byte> data)
    {
        Sync();
        bool ok = _stream.SerializeBytes(data);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a string of fewer than bufferSize UTF-8 bytes. Delegated:
    /// syncs state down, runs ReadStream.SerializeString, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeString(ref string value, int bufferSize)
    {
        Sync();
        bool ok = _stream.SerializeString(ref value, bufferSize);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a string as 32 bits per UTF-16 code unit. Delegated: syncs state
    /// down, runs ReadStream.SerializeWideString, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeWideString(ref string value, int bufferSize)
    {
        Sync();
        bool ok = _stream.SerializeWideString(ref value, bufferSize);
        Recapture();
        return ok;
    }

    /// <summary>Serializes an object that implements ISerializer. Delegated: the
    /// object's Serialize function runs against the underlying stream. For struct
    /// implementers use the generic overload, which does not box.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeObject(ISerializer obj)
    {
        Sync();
        bool ok = _stream.SerializeObject(obj);
        Recapture();
        return ok;
    }

    /// <summary>Serializes an object that implements ISerializer, by ref, without
    /// boxing. Delegated: the object's Serialize function runs against the underlying
    /// stream.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeObject<T>(ref T obj) where T : ISerializer
    {
        Sync();
        bool ok = _stream.SerializeObject(ref obj);
        Recapture();
        return ok;
    }

    /// <summary>Serializes an integer relative to a previous integer. Delegated:
    /// syncs state down, runs ReadStream.SerializeIntRelative, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeIntRelative(int previous, ref int current)
    {
        Sync();
        bool ok = _stream.SerializeIntRelative(previous, ref current);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a signed 128 bit integer in [min,max]. Delegated: syncs
    /// state down, runs ReadStream.SerializeInt128, recaptures — identical decode.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeInt128(ref Int128Value value, Int128Value min, Int128Value max)
    {
        Sync();
        bool ok = _stream.SerializeInt128(ref value, min, max);
        Recapture();
        return ok;
    }

    /// <summary>Serializes an unsigned 128 bit integer as a full 128 bits. Delegated:
    /// syncs state down, runs ReadStream.SerializeUInt128, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeUInt128(ref UInt128Value value)
    {
        Sync();
        bool ok = _stream.SerializeUInt128(ref value);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a fixed point value with signed 64 bit storage. Delegated:
    /// syncs state down, runs the ReadStream overload, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFixed(ref long value, int integerBits, int fractionBits, long min, long max)
    {
        Sync();
        bool ok = _stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a fixed point value with unsigned 64 bit storage. Delegated:
    /// syncs state down, runs the ReadStream overload, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFixed(ref ulong value, int integerBits, int fractionBits, long min, long max)
    {
        Sync();
        bool ok = _stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a fixed point value with signed 32 bit storage. Delegated:
    /// syncs state down, runs the ReadStream overload, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFixed(ref int value, int integerBits, int fractionBits, long min, long max)
    {
        Sync();
        bool ok = _stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a fixed point value with unsigned 32 bit storage. Delegated:
    /// syncs state down, runs the ReadStream overload, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFixed(ref uint value, int integerBits, int fractionBits, long min, long max)
    {
        Sync();
        bool ok = _stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a fixed point value with signed 16 bit storage. Delegated:
    /// syncs state down, runs the ReadStream overload, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFixed(ref short value, int integerBits, int fractionBits, long min, long max)
    {
        Sync();
        bool ok = _stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a fixed point value with unsigned 16 bit storage. Delegated:
    /// syncs state down, runs the ReadStream overload, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFixed(ref ushort value, int integerBits, int fractionBits, long min, long max)
    {
        Sync();
        bool ok = _stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a fixed point value with signed 128 bit storage. Delegated:
    /// syncs state down, runs the ReadStream overload, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFixed(ref Int128Value value, int integerBits, int fractionBits, long min, long max)
    {
        Sync();
        bool ok = _stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
        Recapture();
        return ok;
    }

    /// <summary>Serializes a fixed point value with unsigned 128 bit storage. Delegated:
    /// syncs state down, runs the ReadStream overload, recaptures.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool SerializeFixed(ref UInt128Value value, int integerBits, int fractionBits, long min, long max)
    {
        Sync();
        bool ok = _stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
        Recapture();
        return ok;
    }

    /// <summary>The number of bits required to align to the next byte boundary, in
    /// [0,7], from the batch's current position.</summary>
    public int AlignBits => (int)((8 - _bitsRead % 8) % 8);

    /// <summary>The number of bits read, counting the batch's own reads.</summary>
    public long BitsProcessed => _bitsRead;

    /// <summary>The number of bits read rounded up to the next byte, counting the
    /// batch's own reads.</summary>
    public long BytesProcessed => (_bitsRead + 7) / 8;

    /// <summary>The number of bits still available to read.</summary>
    public long BitsRemaining => _numBits - _bitsRead;

    /// <summary>The first error latched on the batch or carried in from the stream,
    /// or SerializeError.None.</summary>
    public SerializeError Error => _error;

    /// <summary>True while no error is latched.</summary>
    public bool Ok => _error == SerializeError.None;

    /// <summary>The context value of the underlying stream.</summary>
    public object? Context
    {
        get => _stream.Context;
        set => _stream.Context = value;
    }
}

/// <summary>
/// Framework-compat shims: the single implementations every TFM shares, so
/// wire behavior can never diverge by framework. netstandard2.1 (Unity-class
/// runtimes: C# 9, no System.Int128, no BitOperations, no Rune, no Utf8.IsValid) is
/// a first-class target — these shims are the whole difference, and only
/// LeadingZeroCount branches per framework (to keep the hardware intrinsic
/// where it exists; the software fallback is bit-identical by definition,
/// including 32/64 for zero).
/// </summary>
internal static class SerializeCompat
{
    /// <summary>Leading zero count of a 32 bit value; 32 when the value is zero.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int LeadingZeroCount(uint value)
    {
        // inverted sense on purpose: the intrinsic only where it is GUARANTEED
        // (NET7+); every other surface — SDK netstandard2.1 builds AND Unity,
        // which defines NET_STANDARD_2_1 with underscores, not NETSTANDARD2_1 —
        // takes the software path. Identical results by definition.
#if !NET7_0_OR_GREATER
        if (value == 0)
        {
            return 32;
        }
        int count = 0;
        if ((value & 0xFFFF0000u) == 0) { count += 16; value <<= 16; }
        if ((value & 0xFF000000u) == 0) { count += 8; value <<= 8; }
        if ((value & 0xF0000000u) == 0) { count += 4; value <<= 4; }
        if ((value & 0xC0000000u) == 0) { count += 2; value <<= 2; }
        if ((value & 0x80000000u) == 0) { count += 1; }
        return count;
#else
        return System.Numerics.BitOperations.LeadingZeroCount(value);
#endif
    }

    /// <summary>Leading zero count of a 64 bit value; 64 when the value is zero.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int LeadingZeroCount(ulong value)
    {
#if !NET7_0_OR_GREATER
        uint high = (uint)(value >> 32);
        return high != 0 ? LeadingZeroCount(high) : 32 + LeadingZeroCount((uint)value);
#else
        return System.Numerics.BitOperations.LeadingZeroCount(value);
#endif
    }

    // The unsigned float bit casts are .NET 6+; the signed ones are
    // netstandard2.1. unchecked reinterpret casts between the two are exact.

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint SingleToUInt32Bits(float value) => unchecked((uint)BitConverter.SingleToInt32Bits(value));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static float UInt32BitsToSingle(uint value) => BitConverter.Int32BitsToSingle(unchecked((int)value));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong DoubleToUInt64Bits(double value) => unchecked((ulong)BitConverter.DoubleToInt64Bits(value));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static double UInt64BitsToDouble(ulong value) => BitConverter.Int64BitsToDouble(unchecked((long)value));

    /// <summary>Well-formed UTF-16: every high surrogate is immediately followed
    /// by a low surrogate, and no low surrogate stands alone. The wstring writer's
    /// contract (STANDARD.md, adopted 2026-08-15), referenced only from
    /// Debug.Assert — the C# analog of serialize_wstring_is_valid_utf16 in the C
    /// port, taking its 2-byte wchar_t shape, which is what a C# string is.</summary>
    public static bool Utf16IsValid(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 >= value.Length || !char.IsLowSurrogate(value[i + 1]))
                {
                    return false; // high surrogate without its low half
                }
                i++;
            }
            else if (char.IsLowSurrogate(c))
            {
                return false; // low surrogate with no high before it
            }
        }
        return true;
    }

    /// <summary>Strict well-formed UTF-8 validation, matching
    /// System.Text.Unicode.Utf8.IsValid: shortest-form encodings only, no
    /// surrogate code points, nothing above U+10FFFF.</summary>
    public static bool Utf8IsValid(ReadOnlySpan<byte> data)
    {
        int i = 0;
        while (i < data.Length)
        {
            byte b = data[i];
            if (b < 0x80)
            {
                i++;
                continue;
            }
            int length;
            if ((b & 0xE0) == 0xC0)
            {
                length = 2;
            }
            else if ((b & 0xF0) == 0xE0)
            {
                length = 3;
            }
            else if ((b & 0xF8) == 0xF0)
            {
                length = 4;
            }
            else
            {
                return false; // continuation byte or invalid lead
            }
            if (i + length > data.Length)
            {
                return false; // truncated sequence
            }
            uint codePoint = (uint)(b & (0xFF >> (length + 1)));
            for (int k = 1; k < length; k++)
            {
                byte continuation = data[i + k];
                if ((continuation & 0xC0) != 0x80)
                {
                    return false;
                }
                codePoint = (codePoint << 6) | (uint)(continuation & 0x3F);
            }
            if (length == 2 && codePoint < 0x80)
            {
                return false; // overlong
            }
            if (length == 3 && codePoint < 0x800)
            {
                return false; // overlong
            }
            if (length == 4 && codePoint < 0x10000)
            {
                return false; // overlong
            }
            if (codePoint > 0x10FFFF)
            {
                return false;
            }
            if (codePoint >= 0xD800 && codePoint <= 0xDFFF)
            {
                return false; // surrogate code points are not scalar values
            }
            i += length;
        }
        return true;
    }
}
}
