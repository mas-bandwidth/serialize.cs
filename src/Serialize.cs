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
         Exceptions are reserved for API misuse only (the C++ debug-assert analog).
      3. Zero third-party dependencies.
      4. Zero allocation on serialization paths (strings on the read path are the
         documented exception, consistent with the Go and Rust ports).

    Error model (Go style, sticky): the first failure latches on the stream, every later
    serialize call returns false without touching the stream or the value, and the
    latched error is available from the Error property. You can check every call or
    serialize a whole object and check Error once at the end — with one rule: a value
    that controls a loop must have its result checked before the loop uses it, because
    after an error values are never updated again and a loop waiting for one spins
    forever on a truncated or malicious packet. Use SerializeUtil.Continue and
    SerializeUtil.Until for sentinel-driven loops.

    This file mirrors the single-header layout of the C++ original:
    error model / utilities / BitWriter / BitReader / stream interface / WriteStream /
    ReadStream / MeasureStream.
*/

using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Text;

namespace Serialize;

/// <summary>
/// The first failure latched on a stream. None until a serialize call fails.
/// </summary>
public enum SerializeError
{
    /// <summary>No error: the stream is healthy.</summary>
    None = 0,

    /// <summary>A read or write would go past the end of the buffer.</summary>
    Overflow,

    /// <summary>A value is outside the range it is serialized with. On read this
    /// typically means the packet is corrupt or maliciously crafted.</summary>
    ValueOutOfRange,

    /// <summary>The zero pad bits read by an align are not zero. This typically means
    /// the read and write serialize functions don't match.</summary>
    Align,

    /// <summary>String bytes read from the stream are not valid UTF-8.</summary>
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

    /// <summary>Serializes a boolean value with one bit.</summary>
    bool SerializeBool(ref bool value);

    /// <summary>Serializes an uncompressed 32 bit floating point value.</summary>
    bool SerializeFloat(ref float value);

    /// <summary>Serializes an uncompressed 64 bit floating point value.</summary>
    bool SerializeDouble(ref double value);

    /// <summary>Serializes a floating point value in [min,max] with the given
    /// resolution, using only the bits required for the quantized range. On write the
    /// value is clamped into [min,max]; on read it is guaranteed to be in [min,max] if
    /// the call succeeds and max - min is finite. When max - min overflows to infinity
    /// (for example min = -3.4e38f, max = +3.4e38f) the quantization is meaningless and
    /// decoded values can be infinite or NaN even though the call succeeds — behavior
    /// inherited from the C++ library for wire fidelity. min, max and resolution are
    /// trusted parameters: choose ranges with a finite difference.</summary>
    bool SerializeCompressedFloat(ref float value, float min, float max, float resolution);

    /// <summary>Serializes an array of bytes. The stream aligns to a byte boundary
    /// first, then block copies the data. Both sides must know the length: it is not
    /// sent.</summary>
    bool SerializeBytes(Span<byte> data);

    /// <summary>Serializes a string of fewer than bufferSize UTF-8 bytes: the length is
    /// serialized in [0,bufferSize-1], the stream aligns to a byte boundary, then the
    /// UTF-8 bytes are block copied. bufferSize mirrors the C++ API, where a string with
    /// its terminating null character must fit into the buffer, keeping streams
    /// compatible between the two languages. On read, bytes that are not valid UTF-8
    /// fail with SerializeError.InvalidString.</summary>
    bool SerializeString(ref string value, int bufferSize);

    /// <summary>Serializes a string as 32 bits per code point, wire compatible with
    /// serialize_wstring in the C++ library. The length is serialized in
    /// [0,bufferSize-1] code points. On read, code points that are not valid
    /// (surrogates or values above 0x10FFFF) fail with
    /// SerializeError.ValueOutOfRange.</summary>
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
        return min == max ? 0 : 32 - BitOperations.LeadingZeroCount(max - min);
    }

    /// <summary>Returns the number of bits required to serialize a 64 bit integer in
    /// range [min,max]. The result is in [0,64].</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int BitsRequired64(ulong min, ulong max)
    {
        // subtract in the unsigned domain: the range may be wider than 2^63
        return min == max ? 0 : 64 - BitOperations.LeadingZeroCount(max - min);
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
/// Shared internals: API-misuse exception messages, the int-relative difference
/// buckets and the compressed float quantization parameters.
/// </summary>
internal static class SerializeInternal
{
    internal const string BitsRangeMessage = "bits must be in [1,32]";
    internal const string BitsRange64Message = "bits must be in [1,64]";
    internal const string MinMaxMessage = "min must be less than max";
    internal const string BufferSizeMessage = "string buffer size must be at least 2";
    internal const string FloatParamsMessage = "compressed float requires min < max and resolution > 0";
    internal const string WriteOverflowMessage = "bit writer overflow";
    internal const string ReadOverflowMessage = "bit reader would read past the end of the buffer";
    internal const string NotAlignedMessage = "byte array serialization requires byte alignment";
    internal const string BufferBytesMessage = "bit writer buffer size must be a multiple of 8 bytes";
    internal const string ReaderBytesMessage = "bytes must be in [0, buffer.Length]";

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
    /// Computes the quantization parameters shared by the write, read and measure
    /// implementations of SerializeCompressedFloat. The quantized range is clamped so
    /// it always fits in a uint, even for pathological delta / resolution ratios; the
    /// !&gt;= form of the clamp also catches NaN. A delta that overflows to infinity is
    /// deliberately NOT rejected, for parity with the C++ library (see the
    /// SerializeCompressedFloat doc on IBitStream); rejecting it as API misuse is an
    /// open family decision.
    /// </summary>
    internal static void CompressedFloatParams(
        float min, float max, float resolution,
        out uint maxIntegerValue, out int bits, out float delta)
    {
        if (!(min < max) || !(resolution > 0))
        {
            throw new ArgumentException(FloatParamsMessage);
        }

        delta = max - min;

        float values = delta / resolution;

        if (!(values >= 1.0f))
        {
            values = 1.0f;
        }
        else if (values > 4294967040.0f) // largest float below 2^32
        {
            values = 4294967040.0f;
        }

        maxIntegerValue = (uint)Math.Ceiling((double)values);

        bits = SerializeUtil.BitsRequired(0, maxIntegerValue);
    }

    /// <summary>Throws if a string buffer size cannot express a valid length range.</summary>
    internal static void ValidateBufferSize(int bufferSize)
    {
        if (bufferSize < 2)
        {
            throw new ArgumentException(BufferSizeMessage, nameof(bufferSize));
        }
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
    public void Reset(byte[] buffer)
    {
        if (buffer.Length % 8 != 0)
        {
            throw new ArgumentException(SerializeInternal.BufferBytesMessage, nameof(buffer));
        }
        _data = buffer;
        _scratch = 0;
        _numBits = (long)buffer.Length * 8;
        _bitsWritten = 0;
        _wordIndex = 0;
        _scratchBits = 0;
    }

    internal long NumBits => _numBits;

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
    /// byte. bits must be in [1,32]; bits of value above that count are ignored. Throws
    /// if the write would go past the end of the buffer.
    ///
    /// IMPORTANT: When you have finished writing, call FlushBits, otherwise the last
    /// word of data will not get flushed to memory!
    /// </summary>
    public void WriteBits(uint value, int bits)
    {
        if (bits < 1 || bits > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(bits), SerializeInternal.BitsRangeMessage);
        }
        if (_bitsWritten + bits > _numBits)
        {
            throw new InvalidOperationException(SerializeInternal.WriteOverflowMessage);
        }
        WriteBitsUnchecked(value, bits);
    }

    /// <summary>Pads the bit stream with zeros so the bit index becomes a multiple
    /// of 8. If the current bit index is already a multiple of 8, nothing is
    /// written.</summary>
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
        if (_bitsWritten % 8 != 0)
        {
            throw new InvalidOperationException(SerializeInternal.NotAlignedMessage);
        }
        if (_bitsWritten + (long)data.Length * 8 > _numBits)
        {
            throw new InvalidOperationException(SerializeInternal.WriteOverflowMessage);
        }
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
    public void Reset(byte[] buffer, int bytes)
    {
        if (bytes < 0 || bytes > buffer.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(bytes), SerializeInternal.ReaderBytesMessage);
        }
        _data = buffer;
        _numBits = (long)bytes * 8;
        _bitsRead = 0;
    }

    internal long NumBits => _numBits;

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
    public bool WouldReadPastEnd(int bits)
    {
        return _bitsRead + bits > _numBits;
    }

    /// <summary>Reads bits from the buffer and returns the integer value read, in range
    /// [0,(1&lt;&lt;bits)-1]. bits must be in [1,32]. Throws if the read would go past the
    /// end of the data: check WouldReadPastEnd first when reading untrusted data, or
    /// use ReadStream, which performs all checks and latches errors instead.</summary>
    public uint ReadBits(int bits)
    {
        if (bits < 1 || bits > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(bits), SerializeInternal.BitsRangeMessage);
        }
        if (_bitsRead + bits > _numBits)
        {
            throw new InvalidOperationException(SerializeInternal.ReadOverflowMessage);
        }
        return ReadBitsUnchecked(bits);
    }

    /// <summary>Reads an align, corresponding to a WriteAlign call when the buffer was
    /// written, and skips ahead to the next byte boundary. As a safety check, it
    /// verifies that the padding bits are zero and returns false if they are not; this
    /// typically aborts the packet read.</summary>
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
    /// byte boundary. Throws if the read would go past the end of the data: bounds
    /// check with BitsRemaining first when reading untrusted data, or use
    /// ReadStream.</summary>
    public void ReadBytes(Span<byte> data)
    {
        if (_bitsRead % 8 != 0)
        {
            throw new InvalidOperationException(SerializeInternal.NotAlignedMessage);
        }
        if (_bitsRead + (long)data.Length * 8 > _numBits)
        {
            throw new InvalidOperationException(SerializeInternal.ReadOverflowMessage);
        }
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
/// Writes bitpacked data to a buffer. It wraps BitWriter with overflow and range
/// checking that latches errors instead of throwing, and implements IBitStream so
/// unified serialize functions can write with it.
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

    /// <summary>Bounds checks and writes bits that have already been validated to [1,32].</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool WriteBits(uint value, int bits)
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (_writer.BitsWritten + bits > _writer.NumBits)
        {
            return Fail(SerializeError.Overflow);
        }
        _writer.WriteBitsUnchecked(value, bits);
        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool WriteBool(bool value)
    {
        return WriteBits(value ? 1u : 0u, 1);
    }

    /// <inheritdoc/>
    public bool SerializeBits(ref uint value, int bits)
    {
        if (bits < 1 || bits > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(bits), SerializeInternal.BitsRangeMessage);
        }
        return WriteBits(value, bits);
    }

    /// <inheritdoc/>
    public bool SerializeBits64(ref ulong value, int bits)
    {
        if (bits < 1 || bits > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(bits), SerializeInternal.BitsRange64Message);
        }
        if (bits <= 32)
        {
            return WriteBits((uint)value, bits);
        }
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (_writer.BitsWritten + bits > _writer.NumBits)
        {
            return Fail(SerializeError.Overflow);
        }
        // low dword first, then the high remainder
        _writer.WriteBitsUnchecked((uint)value, 32);
        _writer.WriteBitsUnchecked((uint)(value >> 32), bits - 32);
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeInt(ref int value, int min, int max)
    {
        if (min >= max)
        {
            throw new ArgumentException(SerializeInternal.MinMaxMessage);
        }
        if (_error != SerializeError.None)
        {
            return false;
        }
        int v = value;
        if (v < min || v > max)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        int bits = SerializeUtil.BitsRequired((uint)min, (uint)max);
        // subtract in the unsigned domain: the range may be wider than 2^31
        return WriteBits((uint)v - (uint)min, bits);
    }

    /// <inheritdoc/>
    public bool SerializeInt64(ref long value, long min, long max)
    {
        if (min >= max)
        {
            throw new ArgumentException(SerializeInternal.MinMaxMessage);
        }
        if (_error != SerializeError.None)
        {
            return false;
        }
        long v = value;
        if (v < min || v > max)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        int bits = SerializeUtil.BitsRequired64((ulong)min, (ulong)max);
        // subtract in the unsigned domain: the range may be wider than 2^63
        ulong unsigned = (ulong)v - (ulong)min;
        if (bits <= 32)
        {
            return WriteBits((uint)unsigned, bits);
        }
        if (_writer.BitsWritten + bits > _writer.NumBits)
        {
            return Fail(SerializeError.Overflow);
        }
        // low dword first, then the high remainder: same convention as SerializeBits64
        _writer.WriteBitsUnchecked((uint)unsigned, 32);
        _writer.WriteBitsUnchecked((uint)(unsigned >> 32), bits - 32);
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeByte(ref byte value) => WriteBits(value, 8);

    /// <inheritdoc/>
    public bool SerializeUInt16(ref ushort value) => WriteBits(value, 16);

    /// <inheritdoc/>
    public bool SerializeUInt32(ref uint value) => WriteBits(value, 32);

    /// <inheritdoc/>
    public bool SerializeUInt64(ref ulong value)
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (_writer.BitsWritten + 64 > _writer.NumBits)
        {
            return Fail(SerializeError.Overflow);
        }
        _writer.WriteBitsUnchecked((uint)value, 32);
        _writer.WriteBitsUnchecked((uint)(value >> 32), 32);
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeBool(ref bool value) => WriteBool(value);

    /// <inheritdoc/>
    public bool SerializeFloat(ref float value)
    {
        return WriteBits(BitConverter.SingleToUInt32Bits(value), 32);
    }

    /// <inheritdoc/>
    public bool SerializeDouble(ref double value)
    {
        ulong bits = BitConverter.DoubleToUInt64Bits(value);
        return SerializeUInt64(ref bits);
    }

    /// <inheritdoc/>
    public bool SerializeCompressedFloat(ref float value, float min, float max, float resolution)
    {
        SerializeInternal.CompressedFloatParams(min, max, resolution,
            out uint maxIntegerValue, out int bits, out float delta);
        if (_error != SerializeError.None)
        {
            return false;
        }
        float normalizedValue = (value - min) / delta;
        if (!(normalizedValue >= 0.0f))
        {
            normalizedValue = 0.0f; // the !>= form of the clamp forces NaN into range too
        }
        else if (!(normalizedValue <= 1.0f))
        {
            normalizedValue = 1.0f;
        }
        uint integerValue = (uint)Math.Floor((double)(normalizedValue * maxIntegerValue + 0.5f));
        return WriteBits(integerValue, bits);
    }

    /// <inheritdoc/>
    public bool SerializeBytes(Span<byte> data)
    {
        if (!SerializeAlign())
        {
            return false;
        }
        if (_writer.BitsWritten + (long)data.Length * 8 > _writer.NumBits)
        {
            return Fail(SerializeError.Overflow);
        }
        _writer.WriteBytesUnchecked(data);
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
        int byteCount = Encoding.UTF8.GetByteCount(value);
        if (byteCount >= bufferSize)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        int length = byteCount;
        if (!SerializeInt(ref length, 0, bufferSize - 1))
        {
            return false;
        }
        if (!SerializeAlign())
        {
            return false;
        }
        if (_writer.BitsWritten + (long)byteCount * 8 > _writer.NumBits)
        {
            return Fail(SerializeError.Overflow);
        }
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
        if (_error != SerializeError.None)
        {
            return false;
        }
        int length = 0;
        foreach (System.Text.Rune _ in value.EnumerateRunes())
        {
            length++;
        }
        if (length >= bufferSize)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        if (!SerializeInt(ref length, 0, bufferSize - 1))
        {
            return false;
        }
        foreach (System.Text.Rune rune in value.EnumerateRunes())
        {
            if (!WriteBits((uint)rune.Value, 32))
            {
                return false;
            }
        }
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeAlign()
    {
        if (_error != SerializeError.None)
        {
            return false;
        }
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
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (previous >= current)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
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
    public void Flush()
    {
        _writer.FlushBits();
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
    public bool SerializeBits(ref uint value, int bits)
    {
        if (bits < 1 || bits > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(bits), SerializeInternal.BitsRangeMessage);
        }
        return ReadBits(ref value, bits);
    }

    /// <inheritdoc/>
    public bool SerializeBits64(ref ulong value, int bits)
    {
        if (bits < 1 || bits > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(bits), SerializeInternal.BitsRange64Message);
        }
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
    public bool SerializeInt(ref int value, int min, int max)
    {
        if (min >= max)
        {
            throw new ArgumentException(SerializeInternal.MinMaxMessage);
        }
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
    public bool SerializeInt64(ref long value, long min, long max)
    {
        if (min >= max)
        {
            throw new ArgumentException(SerializeInternal.MinMaxMessage);
        }
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

    /// <inheritdoc/>
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
    public bool SerializeUInt32(ref uint value) => ReadBits(ref value, 32);

    /// <inheritdoc/>
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
    public bool SerializeFloat(ref float value)
    {
        uint v = 0;
        if (!ReadBits(ref v, 32))
        {
            return false;
        }
        value = BitConverter.UInt32BitsToSingle(v);
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeDouble(ref double value)
    {
        ulong v = 0;
        if (!SerializeUInt64(ref v))
        {
            return false;
        }
        value = BitConverter.UInt64BitsToDouble(v);
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeCompressedFloat(ref float value, float min, float max, float resolution)
    {
        SerializeInternal.CompressedFloatParams(min, max, resolution,
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
        float normalizedValue = (float)integerValue / maxIntegerValue;
        value = normalizedValue * delta + min;
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
        if (!System.Text.Unicode.Utf8.IsValid(utf8))
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
        char[] chars = new char[(long)length * 2];
        int position = 0;
        for (int i = 0; i < length; i++)
        {
            uint codePoint = _reader.ReadBitsUnchecked(32);
            if (codePoint > 0x10FFFF || (codePoint >= 0xD800 && codePoint <= 0xDFFF))
            {
                return Fail(SerializeError.ValueOutOfRange);
            }
            position += new System.Text.Rune((int)codePoint).EncodeToUtf16(chars.AsSpan(position));
        }
        value = new string(chars, 0, position);
        return true;
    }

    /// <inheritdoc/>
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
        if (_error != SerializeError.None)
        {
            return false;
        }
        _bitsWritten += bits;
        return true;
    }

    /// <inheritdoc/>
    public bool SerializeBits(ref uint value, int bits)
    {
        if (bits < 1 || bits > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(bits), SerializeInternal.BitsRangeMessage);
        }
        return Measure(bits);
    }

    /// <inheritdoc/>
    public bool SerializeBits64(ref ulong value, int bits)
    {
        if (bits < 1 || bits > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(bits), SerializeInternal.BitsRange64Message);
        }
        return Measure(bits);
    }

    /// <inheritdoc/>
    public bool SerializeInt(ref int value, int min, int max)
    {
        if (min >= max)
        {
            throw new ArgumentException(SerializeInternal.MinMaxMessage);
        }
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (value < min || value > max)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        return Measure(SerializeUtil.BitsRequired((uint)min, (uint)max));
    }

    /// <inheritdoc/>
    public bool SerializeInt64(ref long value, long min, long max)
    {
        if (min >= max)
        {
            throw new ArgumentException(SerializeInternal.MinMaxMessage);
        }
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (value < min || value > max)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
        return Measure(SerializeUtil.BitsRequired64((ulong)min, (ulong)max));
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
    public bool SerializeBool(ref bool value) => Measure(1);

    /// <inheritdoc/>
    public bool SerializeFloat(ref float value) => Measure(32);

    /// <inheritdoc/>
    public bool SerializeDouble(ref double value) => Measure(64);

    /// <inheritdoc/>
    public bool SerializeCompressedFloat(ref float value, float min, float max, float resolution)
    {
        SerializeInternal.CompressedFloatParams(min, max, resolution,
            out _, out int bits, out _);
        return Measure(bits);
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
        if (_error != SerializeError.None)
        {
            return false;
        }
        int byteCount = Encoding.UTF8.GetByteCount(value);
        if (byteCount >= bufferSize)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
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
        if (_error != SerializeError.None)
        {
            return false;
        }
        int length = 0;
        foreach (System.Text.Rune _ in value.EnumerateRunes())
        {
            length++;
        }
        if (length >= bufferSize)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
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
        if (_error != SerializeError.None)
        {
            return false;
        }
        if (previous >= current)
        {
            return Fail(SerializeError.ValueOutOfRange);
        }
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
