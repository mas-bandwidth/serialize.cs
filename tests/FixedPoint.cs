/*
    FixedPoint.cs

    Test-for-test port of the fixed point + 128 bit integer tests from the C++
    serialize library (serialize.h, fixed-point branch): test_bits_required128,
    test_serialize_fixed, test_serialize_fixed_validation,
    test_serialize_fixed_matches_int64, test_serialize_fixed_wide,
    test_serialize_uint128 and test_serialize_int128, plus the fixed point golden
    wire pin.

    The C++ emulated-pair tests (test_uint128_emulation, test_int128_emulation,
    test_serialize_fixed_wide_emulated, the native/emulated differential) have no C#
    counterpart by design: both target frameworks are net7.0+, so the port uses the
    native System.Int128 / System.UInt128 and there is exactly one representation.

    GOLDEN PIN PROVENANCE. Every pinned byte array below was derived from
    STANDARD.md's text by an independent oracle (a bit packer implementing only the
    spec's stated rules: LSB-first packing, 32 bit groups least significant first,
    offset encodings over shifted raw bounds), and the oracle's output was then
    cross-checked byte for byte against the pins in the C++ fixed-point test suite
    (golden_uint128_bytes, golden_int128_bytes, and bytes 72..111 of
    golden_wire_bytes). Spec and reference implementation agree; the arrays here
    transcribe that agreement. Never regenerate them from this implementation.
*/

using System;

namespace Serialize.Tests;

// The fixed point section of the C++ fixed-point golden message. In the C++ golden
// message this section begins byte aligned ("the fixed point section starts byte
// aligned, so every byte pinned above it stays put"), so serializing it from a fresh
// stream produces exactly the tail bytes of the C++ 112 byte golden vector. The
// pre-existing 72 byte GoldenWireData message is untouched: it still matches the
// C++ release the interop gate pins (v1.4.3) and the Go and Rust ports.
internal sealed class FixedWireData
{
    public short FixedQ8_8;
    public int FixedQ16_16;
    public long FixedQ48_16;
    public uint FixedQ16_16Unsigned;
    public Int128 FixedQ112_16Wide;
    public Int128 FixedQ64_64Wide;

    public static FixedWireData Init()
    {
        return new FixedWireData
        {
            FixedQ8_8 = -(3 * 256 + 64),                            // -3.25 in Q8.8
            FixedQ16_16 = 1234 * 65536 + 32768,                     // 1234.5 in Q16.16
            FixedQ48_16 = -(54321L * 65536 + 12345),                // -54321.1883... in Q48.16
            FixedQ16_16Unsigned = 29999u * 65536u + 65535u,         // 29999.99998... in Q16.16: every fraction bit set
            FixedQ112_16Wide = -(98765432109L * 65536 + 4321),      // -98765432109.066 in Q112.16: 75 bits on the wire, three groups
            FixedQ64_64Wide = ((Int128)0x0123456789ABCDEF << 64)
                            + 0x0FEDCBA987654321,                   // Q64.64 over the full unit range: 128 bits, four groups, every group distinct
        };
    }

    public static bool Serialize(IBitStream stream, FixedWireData data)
    {
        stream.SerializeFixed(ref data.FixedQ8_8, 8, 8, -100, +100);
        stream.SerializeFixed(ref data.FixedQ16_16, 16, 16, -2000, +2000);
        stream.SerializeFixed(ref data.FixedQ48_16, 48, 16, -100000, +100000);
        stream.SerializeFixed(ref data.FixedQ16_16Unsigned, 16, 16, 0, 30000);
        stream.SerializeAlign();                                    // the wide fixed section starts byte aligned
        stream.SerializeFixed(ref data.FixedQ112_16Wide, 112, 16, -144115188075855872, +144115188075855872); // ±2^57 units: 75 bits, the three group structure
        stream.SerializeFixed(ref data.FixedQ64_64Wide, 64, 64, long.MinValue, long.MaxValue);               // full unit range: 128 bits, the four group structure
        return stream.Ok;
    }
}

/// <summary>The storage type a fixed point test case runs through, so one helper can
/// drive every SerializeFixed overload. The carrier is an Int128 holding the raw
/// value's two's complement bit pattern.</summary>
internal enum FixedStorage
{
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    I128,
    U128,
}

internal static partial class Program
{
    // FixedWireBytes pin the fixed point section of the golden message: derived from
    // STANDARD.md's rules by an independent oracle, cross-checked byte identical
    // against bytes 72..111 of golden_wire_bytes in the C++ fixed-point test suite.
    // Never regenerate. Decoding the first two bytes against the spec by hand:
    // Q8.8 over [-100,+100] costs 16 bits; 0xC0 0x60 is the offset 0x60C0 = 24768;
    // adding raw_min (-100 << 8 = -25600) gives raw -832 = -3.25 in Q8.8.
    private static readonly byte[] FixedWireBytes =
    {
        0xC0, 0x60, 0x00, 0x80, 0xA2, 0x7C, 0xFC, 0xEC, 0x26, 0xCB, 0xFF, 0xFF,
        0x4B, 0x1D, 0x1F, 0xEF, 0xD2, 0x1A, 0x1F, 0x01, 0xE9, 0xFF, 0xFF, 0x09,
        0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x78, 0x6F, 0x5E, 0x4D, 0x3C,
        0x2B, 0x1A, 0x09, 0x04,
    };

    // Uint128GoldenBytes pin the raw uint128 wire format: "the 16 bytes of the value
    // in little-endian order" when byte aligned. Derived from STANDARD.md, matches
    // golden_uint128_bytes in the C++ fixed-point test suite. Never regenerate.
    private static readonly byte[] Uint128GoldenBytes =
    {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
        0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
    };

    // Int128GoldenBytes pin the ranged int128 encoding of -0x0123456789ABCDEF over
    // [-2^70, +2^70]: 72 bits, the THREE group structure (32, 32, then 8). Derived
    // from STANDARD.md, matches the 9 meaningful bytes of golden_int128_bytes in the
    // C++ fixed-point test suite (whose array carries three additional zero bytes of
    // C++ qword flush padding past the 9 byte payload). Never regenerate.
    private static readonly byte[] Int128GoldenBytes =
    {
        0x11, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x3F,
    };

    private static void TestBitsRequired128()
    {
        Check(SerializeUtil.BitsRequired128(0, 0) == 0, "BitsRequired128(0,0) != 0");
        Check(SerializeUtil.BitsRequired128(0, 1) == 1, "BitsRequired128(0,1) != 1");
        Check(SerializeUtil.BitsRequired128(0, 255) == 8, "BitsRequired128(0,255) != 8");
        Check(SerializeUtil.BitsRequired128(0, 4294967295) == 32, "BitsRequired128(0,2^32-1) != 32");
        Check(SerializeUtil.BitsRequired128(0, 4294967296) == 33, "BitsRequired128(0,2^32) != 33");
        Check(SerializeUtil.BitsRequired128(0, ulong.MaxValue) == 64, "BitsRequired128(0,2^64-1) != 64");
        Check(SerializeUtil.BitsRequired128(0, (UInt128)1 << 64) == 65, "BitsRequired128(0,2^64) != 65");
        Check(SerializeUtil.BitsRequired128(0, (UInt128)1 << 127) == 128, "BitsRequired128(0,2^127) != 128");
        Check(SerializeUtil.BitsRequired128(0, UInt128.MaxValue) == 128, "BitsRequired128(0,2^128-1) != 128");

        // must agree with the 64 bit variant wherever both apply
        Check(SerializeUtil.BitsRequired128(0, 4294967296) == SerializeUtil.BitsRequired64(0, 4294967296),
            "BitsRequired128 disagrees with BitsRequired64 at 2^32");
        Check(SerializeUtil.BitsRequired128(0, 1UL << 40) == SerializeUtil.BitsRequired64(0, 1UL << 40),
            "BitsRequired128 disagrees with BitsRequired64 at 2^40");

        // a signed range converted through the unsigned 128 bit domain
        Check(SerializeUtil.BitsRequired128((UInt128)(Int128)(-5000000000L), (UInt128)(Int128)5000000000L) == 34,
            "BitsRequired128 over signed [-5e9,+5e9] != 34");

        // the same numbers zero extended instead of sign extended are a wrapped range
        Check(SerializeUtil.BitsRequired128(unchecked((ulong)(-5000000000L)), 5000000000UL) == 128,
            "BitsRequired128 over a wrapped range != 128");

        Check(SerializeUtil.BitsRequired128(1, UInt128.MaxValue) == 128, "BitsRequired128(1,2^128-1) != 128");
    }

    /// <summary>Drives the SerializeFixed overload selected by storage, carrying the
    /// raw value's two's complement bit pattern in an Int128.</summary>
    private static bool SerializeFixedAs(
        FixedStorage storage, IBitStream stream, ref Int128 carrier,
        int integerBits, int fractionBits, long min, long max)
    {
        switch (storage)
        {
            case FixedStorage.I16:
            {
                short value = (short)carrier;
                bool ok = stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.U16:
            {
                ushort value = (ushort)carrier;
                bool ok = stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.I32:
            {
                int value = (int)carrier;
                bool ok = stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.U32:
            {
                uint value = (uint)carrier;
                bool ok = stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.I64:
            {
                long value = (long)carrier;
                bool ok = stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.U64:
            {
                ulong value = (ulong)carrier;
                bool ok = stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.I128:
            {
                Int128 value = carrier;
                bool ok = stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            default:
            {
                UInt128 value = (UInt128)carrier;
                bool ok = stream.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = (Int128)value;
                return ok;
            }
        }
    }

    /// <summary>One fixed point round trip: write, measure (must agree exactly with
    /// the write — fixed point involves no alignment), read back exact.</summary>
    private static void CheckFixedRoundTrip(
        FixedStorage storage, int integerBits, int fractionBits, long minUnits, long maxUnits,
        Int128 rawValue)
    {
        string label = $"fixed {storage} Q{integerBits}.{fractionBits} [{minUnits},{maxUnits}] raw {rawValue}";

        byte[] buffer = new byte[32];

        WriteStream writeStream = new WriteStream(buffer);
        Int128 written = rawValue;
        Check(SerializeFixedAs(storage, writeStream, ref written, integerBits, fractionBits, minUnits, maxUnits),
            $"{label}: write failed: {writeStream.Error}");
        writeStream.Flush();

        MeasureStream measureStream = new MeasureStream();
        Int128 measured = rawValue;
        Check(SerializeFixedAs(storage, measureStream, ref measured, integerBits, fractionBits, minUnits, maxUnits),
            $"{label}: measure failed: {measureStream.Error}");
        Check(measureStream.BitsProcessed == writeStream.BitsProcessed,
            $"{label}: measure {measureStream.BitsProcessed} != write {writeStream.BitsProcessed}");

        ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
        Int128 readBack = 0;
        Check(SerializeFixedAs(storage, readStream, ref readBack, integerBits, fractionBits, minUnits, maxUnits),
            $"{label}: read failed: {readStream.Error}");
        Check(readBack == rawValue, $"{label}: read back {readBack}");
    }

    /// <summary>The case list every configuration in the matrix runs: exact raw
    /// bounds, one raw step inside each, whole unit values inside each bound, all
    /// fraction bits set, the middle of the range, and zero / +1.0 / -1.0 units where
    /// the bounds allow them. The port of the C++ check_fixed_cases.</summary>
    private static void CheckFixedCases(
        FixedStorage storage, int integerBits, int fractionBits, long minUnits, long maxUnits,
        Int128 oneUnit)
    {
        Int128 rawMin = oneUnit * minUnits;
        Int128 rawMax = oneUnit * maxUnits;

        // exact raw bounds, and one raw step inside each
        CheckFixedRoundTrip(storage, integerBits, fractionBits, minUnits, maxUnits, rawMin);
        CheckFixedRoundTrip(storage, integerBits, fractionBits, minUnits, maxUnits, rawMax);
        CheckFixedRoundTrip(storage, integerBits, fractionBits, minUnits, maxUnits, rawMin + 1);
        CheckFixedRoundTrip(storage, integerBits, fractionBits, minUnits, maxUnits, rawMax - 1);

        // whole unit values one unit inside each bound
        CheckFixedRoundTrip(storage, integerBits, fractionBits, minUnits, maxUnits, oneUnit * (minUnits + 1));
        CheckFixedRoundTrip(storage, integerBits, fractionBits, minUnits, maxUnits, oneUnit * (maxUnits - 1));

        // a value with every fraction bit set
        CheckFixedRoundTrip(storage, integerBits, fractionBits, minUnits, maxUnits, rawMin + oneUnit - 1);

        // the middle of the range, computed without overflowing the storage type
        CheckFixedRoundTrip(storage, integerBits, fractionBits, minUnits, maxUnits, rawMin / 2 + rawMax / 2);

        // zero, one and minus one whole units, where the bounds allow them
        if (minUnits <= 0 && maxUnits >= 0)
        {
            CheckFixedRoundTrip(storage, integerBits, fractionBits, minUnits, maxUnits, 0);
        }
        if (minUnits <= 1 && maxUnits >= 1)
        {
            CheckFixedRoundTrip(storage, integerBits, fractionBits, minUnits, maxUnits, oneUnit);
        }
        if (minUnits <= -1 && maxUnits >= -1)
        {
            CheckFixedRoundTrip(storage, integerBits, fractionBits, minUnits, maxUnits, -oneUnit);
        }
    }

    /// <summary>All three streams must refuse an invalid Q format or bounds as API
    /// misuse — the C# runtime analog of the C++ static_assert refusals, validated
    /// before the stream state is consulted.</summary>
    private static void CheckFixedThrows(
        FixedStorage storage, int integerBits, int fractionBits, long minUnits, long maxUnits)
    {
        IBitStream[] streams =
        {
            new WriteStream(new byte[16]),
            new ReadStream(new byte[16]),
            new MeasureStream(),
        };
        foreach (IBitStream stream in streams)
        {
            bool threw = false;
            try
            {
                Int128 value = 0;
                SerializeFixedAs(storage, stream, ref value, integerBits, fractionBits, minUnits, maxUnits);
            }
            catch (ArgumentException)
            {
                threw = true;
            }
            Check(threw,
                $"fixed {storage} Q{integerBits}.{fractionBits} [{minUnits},{maxUnits}]: expected ArgumentException");
        }
    }

    private static void TestSerializeFixed()
    {
        // the storage x Q format matrix, mirroring the C++ test_serialize_fixed

        // short storage
        CheckFixedCases(FixedStorage.I16, 8, 8, -100, +100, 256);
        CheckFixedCases(FixedStorage.I16, 12, 4, -2000, +2000, 16);

        // int storage
        CheckFixedCases(FixedStorage.I32, 16, 16, -30000, +30000, 65536);
        CheckFixedCases(FixedStorage.I32, 24, 8, -8000000, +8000000, 256);
        CheckFixedCases(FixedStorage.I32, 32, 0, -100000, +100000, 1);                  // pure integer Q: fractionBits == 0 is legal

        // long storage
        CheckFixedCases(FixedStorage.I64, 48, 16, -100000000000, +100000000000, 65536);
        CheckFixedCases(FixedStorage.I64, 32, 32, -1000000, +1000000, (Int128)1 << 32);
        CheckFixedCases(FixedStorage.I64, 64, 0, -5000000000, +5000000000, 1);          // pure integer Q at full width

        // unsigned storage
        CheckFixedCases(FixedStorage.U16, 16, 0, 0, 60000, 1);
        CheckFixedCases(FixedStorage.U32, 16, 16, 0, 60000, 65536);
        CheckFixedCases(FixedStorage.U64, 48, 16, 0, 1000000000, 65536);

        // single unit range: the whole wire is the fractional part
        CheckFixedCases(FixedStorage.I32, 16, 16, 0, 1, 65536);

        // asymmetric bounds
        CheckFixedCases(FixedStorage.I64, 48, 16, -3, +100000, 65536);

        // the wire cost is a constant of the call site. pin a few
        {
            byte[] buffer = new byte[16];
            WriteStream stream = new WriteStream(buffer);
            long value = 12345L * 65536 + 32768;                                        // 12345.5 in Q48.16
            Check(stream.SerializeFixed(ref value, 48, 16, -100000, +100000), "write failed");
            Check(stream.BitsProcessed == 34,                                           // 200000 << 16 raw values needs 34 bits
                $"expected 34 bits, got {stream.BitsProcessed}");
        }
        {
            byte[] buffer = new byte[8];
            WriteStream stream = new WriteStream(buffer);
            int value = 65536 / 2;                                                      // 0.5 in Q16.16
            Check(stream.SerializeFixed(ref value, 16, 16, 0, 1), "write failed");
            Check(stream.BitsProcessed == 17,                                           // 1 << 16 raw values needs 17 bits
                $"expected 17 bits, got {stream.BitsProcessed}");
        }
        {
            byte[] buffer = new byte[8];
            WriteStream stream = new WriteStream(buffer);
            short value = -832;                                                         // -3.25 in Q8.8
            Check(stream.SerializeFixed(ref value, 8, 8, -100, +100), "write failed");
            Check(stream.BitsProcessed == 16,                                           // 200 << 8 raw values needs 16 bits
                $"expected 16 bits, got {stream.BitsProcessed}");
        }

        // API misuse refusals: the C++ compile time static_asserts are runtime
        // ArgumentExceptions here, so unlike the C++ suite they run instead of
        // living in comments
        CheckFixedThrows(FixedStorage.I32, 16, 8, 0, 100);          // 16 + 8 != 32: the Q format doesn't fill the storage type
        CheckFixedThrows(FixedStorage.I32, 16, 16, -40000, +40000); // bounds exceed the Q16.16 whole unit capacity [-32768,32767]
        CheckFixedThrows(FixedStorage.I32, 16, 16, 100, 100);       // min must be below max
        CheckFixedThrows(FixedStorage.I32, 16, 16, 200, 100);       // min must be below max
        CheckFixedThrows(FixedStorage.I32, 0, 32, 0, 100);          // at least one integer bit
        CheckFixedThrows(FixedStorage.I32, 33, -1, 0, 100);         // fraction bits can't be negative
        CheckFixedThrows(FixedStorage.U32, 16, 16, -5, 100);        // negative bound on unsigned storage
        CheckFixedThrows(FixedStorage.U16, 16, 0, 0, 70000);        // bounds exceed the Q16.0 unsigned capacity [0,65535]
        CheckFixedThrows(FixedStorage.I128, 16, 16, 0, 100);        // 16 + 16 != 128
        CheckFixedThrows(FixedStorage.I128, 16, 112, -40000, +40000); // bounds exceed the wide Q16.112 whole unit capacity
        CheckFixedThrows(FixedStorage.U128, 112, 16, -5, 100);      // negative bound on unsigned wide storage
    }

    /// <summary>Hand builds a stream encoding an offset of exactly rawRange + 1 — one
    /// raw step past rawMax, smuggled into the bit headroom — and requires the read
    /// to reject it. Wire parameters recomputed independently of the codec. The port
    /// of the C++ check_fixed_rejects_out_of_range.</summary>
    private static void CheckFixedRejectsOutOfRange(
        FixedStorage storage, int integerBits, int fractionBits, long minUnits, long maxUnits)
    {
        ulong rawRange = ((ulong)maxUnits << fractionBits) - ((ulong)minUnits << fractionBits);
        int bits = SerializeUtil.BitsRequired64(0, rawRange);

        ulong maxEncodable = bits < 64 ? (1UL << bits) - 1 : ulong.MaxValue;
        if (rawRange == maxEncodable)
        {
            return; // no headroom: every encoding decodes in range for this configuration
        }

        ulong smuggled = rawRange + 1;

        byte[] buffer = new byte[16];
        WriteStream writeStream = new WriteStream(buffer);
        if (bits <= 32)
        {
            uint value = (uint)smuggled;
            writeStream.SerializeBits(ref value, bits);
        }
        else
        {
            uint lo = (uint)smuggled;
            uint hi = (uint)(smuggled >> 32);
            writeStream.SerializeBits(ref lo, 32);
            writeStream.SerializeBits(ref hi, bits - 32);
        }
        writeStream.Flush();

        ReadStream readStream = new ReadStream(buffer);
        Int128 value128 = 0;
        Check(!SerializeFixedAs(storage, readStream, ref value128, integerBits, fractionBits, minUnits, maxUnits),
            $"fixed {storage} Q{integerBits}.{fractionBits} [{minUnits},{maxUnits}]: expected the smuggled offset to be rejected");
        Check(readStream.Error == SerializeError.ValueOutOfRange,
            $"fixed {storage} Q{integerBits}.{fractionBits}: expected ValueOutOfRange, got {readStream.Error}");
        Check(value128 == 0, "a failed read must leave the value unmodified");
    }

    private static void TestSerializeFixedValidation()
    {
        // a malicious packet can smuggle a raw value past rawMax into the bit
        // headroom of the offset encoding. reads must reject one raw step past the
        // top of the range, on every configuration in the matrix that has headroom.
        CheckFixedRejectsOutOfRange(FixedStorage.I16, 8, 8, -100, +100);
        CheckFixedRejectsOutOfRange(FixedStorage.I16, 12, 4, -2000, +2000);
        CheckFixedRejectsOutOfRange(FixedStorage.I32, 16, 16, -30000, +30000);
        CheckFixedRejectsOutOfRange(FixedStorage.I32, 24, 8, -8000000, +8000000);
        CheckFixedRejectsOutOfRange(FixedStorage.I32, 32, 0, -100000, +100000);
        CheckFixedRejectsOutOfRange(FixedStorage.I64, 48, 16, -100000000000, +100000000000);
        CheckFixedRejectsOutOfRange(FixedStorage.I64, 32, 32, -1000000, +1000000);
        CheckFixedRejectsOutOfRange(FixedStorage.I64, 64, 0, -5000000000, +5000000000);
        CheckFixedRejectsOutOfRange(FixedStorage.U16, 16, 0, 0, 60000);
        CheckFixedRejectsOutOfRange(FixedStorage.U32, 16, 16, 0, 60000);
        CheckFixedRejectsOutOfRange(FixedStorage.U64, 48, 16, 0, 1000000000);
        CheckFixedRejectsOutOfRange(FixedStorage.I32, 16, 16, 0, 1);
        CheckFixedRejectsOutOfRange(FixedStorage.I64, 48, 16, -3, +100000);

        // reads past the end of the buffer must fail cleanly
        {
            byte[] buffer = new byte[8];
            ReadStream readStream = new ReadStream(buffer, 2);
            long value = 424242; // sentinel
            Check(!readStream.SerializeFixed(ref value, 48, 16, -100000000000, +100000000000),
                "expected the truncated read to fail");
            Check(readStream.Error == SerializeError.Overflow, $"expected Overflow, got {readStream.Error}");
            Check(value == 424242, "a failed read must leave the value unmodified");
        }
    }

    private static void TestSerializeFixedMatchesInt64()
    {
        // for storage of 64 bits or fewer the fixed point wire format is byte
        // identical to SerializeInt64 of the raw value over the raw bounds. sweep
        // values and require identical bytes and identical bit counts: this
        // equivalence binds the new path to the proven one.

        // > 32 bit range: the two dword path, pure integer Q at full width
        {
            long[] values = { -5000000000, -4999999999, -1, 0, +1, 12345678, 4999999999, 5000000000 };

            foreach (long value in values)
            {
                byte[] fixedBuffer = new byte[16];
                WriteStream fixedStream = new WriteStream(fixedBuffer);
                long fixedValue = value;
                Check(fixedStream.SerializeFixed(ref fixedValue, 64, 0, -5000000000, +5000000000),
                    "fixed write failed");
                fixedStream.Flush();

                byte[] int64Buffer = new byte[16];
                WriteStream int64Stream = new WriteStream(int64Buffer);
                long int64Value = value;
                Check(int64Stream.SerializeInt64(ref int64Value, -5000000000, +5000000000),
                    "int64 write failed");
                int64Stream.Flush();

                Check(fixedStream.BitsProcessed == int64Stream.BitsProcessed,
                    $"value {value}: fixed {fixedStream.BitsProcessed} bits != int64 {int64Stream.BitsProcessed} bits");
                Check(fixedBuffer.AsSpan().SequenceEqual(int64Buffer),
                    $"value {value}: fixed bytes differ from int64 bytes");
            }
        }

        // <= 32 bit range: the single dword path, on int storage
        {
            int[] values = { -100000, -99999, -1, 0, +1, 54321, 99999, 100000 };

            foreach (int value in values)
            {
                byte[] fixedBuffer = new byte[16];
                WriteStream fixedStream = new WriteStream(fixedBuffer);
                int fixedValue = value;
                Check(fixedStream.SerializeFixed(ref fixedValue, 32, 0, -100000, +100000),
                    "fixed write failed");
                fixedStream.Flush();

                byte[] int64Buffer = new byte[16];
                WriteStream int64Stream = new WriteStream(int64Buffer);
                long int64Value = value;
                Check(int64Stream.SerializeInt64(ref int64Value, -100000, +100000),
                    "int64 write failed");
                int64Stream.Flush();

                Check(fixedStream.BitsProcessed == int64Stream.BitsProcessed,
                    $"value {value}: fixed {fixedStream.BitsProcessed} bits != int64 {int64Stream.BitsProcessed} bits");
                Check(fixedBuffer.AsSpan().SequenceEqual(int64Buffer),
                    $"value {value}: fixed bytes differ from int64 bytes");
            }
        }

        // the equivalence is not limited to fractionBits == 0: for any Q format the
        // wire is SerializeInt64 of the raw value over the raw bounds. fixed point
        // adds no wire structure, only the scaling convention.
        {
            int[] rawValues = { -30000 * 65536, -(3 * 65536 + 16384), 0, 65536 / 2, 12345 * 65536 + 1, 30000 * 65536 };

            foreach (int rawValue in rawValues)
            {
                byte[] fixedBuffer = new byte[16];
                WriteStream fixedStream = new WriteStream(fixedBuffer);
                int fixedValue = rawValue;
                Check(fixedStream.SerializeFixed(ref fixedValue, 16, 16, -30000, +30000),
                    "fixed write failed");
                fixedStream.Flush();

                byte[] int64Buffer = new byte[16];
                WriteStream int64Stream = new WriteStream(int64Buffer);
                long int64Value = rawValue;
                Check(int64Stream.SerializeInt64(ref int64Value, -30000L * 65536, +30000L * 65536),
                    "int64 write failed");
                int64Stream.Flush();

                Check(fixedStream.BitsProcessed == int64Stream.BitsProcessed,
                    $"raw {rawValue}: fixed {fixedStream.BitsProcessed} bits != int64 {int64Stream.BitsProcessed} bits");
                Check(fixedBuffer.AsSpan().SequenceEqual(int64Buffer),
                    $"raw {rawValue}: fixed bytes differ from int64 bytes");
            }
        }
    }

    /// <summary>The wide storage counterpart of CheckFixedRejectsOutOfRange: wire
    /// parameters recomputed in the unsigned 128 bit domain, the smuggled offset
    /// written through every group structure.</summary>
    private static void CheckFixedWideRejectsOutOfRange(
        FixedStorage storage, int integerBits, int fractionBits, long minUnits, long maxUnits)
    {
        UInt128 rawMin = (UInt128)(Int128)minUnits << fractionBits;
        UInt128 rawMax = (UInt128)(Int128)maxUnits << fractionBits;
        UInt128 rawRange = rawMax - rawMin;

        int bits = 0;
        for (UInt128 x = rawRange; x != 0; x >>= 1)
        {
            bits++;
        }

        UInt128 maxEncodable = bits < 128 ? ((UInt128)1 << bits) - 1 : UInt128.MaxValue;
        if (rawRange == maxEncodable)
        {
            return; // no headroom: every encoding decodes in range for this configuration
        }

        UInt128 smuggled = rawRange + 1;

        byte[] buffer = new byte[24];
        WriteStream writeStream = new WriteStream(buffer);
        int bitsLeft = bits;
        while (bitsLeft > 0)
        {
            int groupBits = Math.Min(bitsLeft, 32);
            uint group = (uint)smuggled;
            writeStream.SerializeBits(ref group, groupBits);
            smuggled >>= groupBits;
            bitsLeft -= groupBits;
        }
        writeStream.Flush();

        ReadStream readStream = new ReadStream(buffer);
        Int128 value = 0;
        Check(!SerializeFixedAs(storage, readStream, ref value, integerBits, fractionBits, minUnits, maxUnits),
            $"fixed {storage} Q{integerBits}.{fractionBits} [{minUnits},{maxUnits}]: expected the smuggled offset to be rejected");
        Check(readStream.Error == SerializeError.ValueOutOfRange,
            $"fixed {storage} Q{integerBits}.{fractionBits}: expected ValueOutOfRange, got {readStream.Error}");
        Check(value == 0, "a failed read must leave the value unmodified");
    }

    private static void TestSerializeFixedWide()
    {
        // the matrix, wide: Q112.16 with a raw range past 64 bits (three groups on
        // the wire), Q112.16 with a small range (a single group on wide storage),
        // Q64.64 (the fraction alone spans 64 bits), Q64.64 over the full unit range
        // (128 bits on the wire, four groups), and the unsigned wide case.
        CheckFixedCases(FixedStorage.I128, 112, 16, -1152921504606846976, +1152921504606846976, 65536); // ±2^60 units: 78 bits on the wire
        CheckFixedCases(FixedStorage.I128, 112, 16, -2, +2, 65536);
        CheckFixedCases(FixedStorage.I128, 64, 64, -1000, +1000, (Int128)1 << 64);
        CheckFixedCases(FixedStorage.I128, 64, 64, long.MinValue, long.MaxValue, (Int128)1 << 64);      // full unit range: 128 bits on the wire
        CheckFixedCases(FixedStorage.U128, 112, 16, 0, 2305843009213693952, 65536);                     // 2^61 units, unsigned

        // the 33..64 bit two group band on wide storage: both boundaries exactly,
        // plus the C++ example's own Q112.16 ±1e11 shape (54 bits)
        CheckFixedCases(FixedStorage.I128, 112, 16, -32768, +32768, 65536);                             // 33 bits: the band's low edge
        CheckFixedCases(FixedStorage.I128, 112, 16, -100000000000, +100000000000, 65536);               // 54 bits: the example's shape
        CheckFixedCases(FixedStorage.I128, 112, 16, -140737488355328, +140737488355327, 65536);         // 64 bits: the band's high edge

        // the wire cost is a constant of the call site, wide paths included. pin a few
        {
            byte[] buffer = new byte[16];
            WriteStream stream = new WriteStream(buffer);
            Int128 value = (Int128)12345 * 65536;
            Check(stream.SerializeFixed(ref value, 112, 16, -1152921504606846976, +1152921504606846976), "write failed");
            Check(stream.BitsProcessed == 78, $"expected 78 bits, got {stream.BitsProcessed}");         // 2^61 << 16 raw values needs 78 bits
        }
        {
            byte[] buffer = new byte[24];
            WriteStream stream = new WriteStream(buffer);
            Int128 value = 0;
            Check(stream.SerializeFixed(ref value, 64, 64, long.MinValue, long.MaxValue), "write failed");
            Check(stream.BitsProcessed == 128, $"expected 128 bits, got {stream.BitsProcessed}");       // the full unit range costs the full storage width
        }
        {
            byte[] buffer = new byte[16];
            WriteStream stream = new WriteStream(buffer);
            Int128 value = (Int128)12345678901 * 65536;
            Check(stream.SerializeFixed(ref value, 112, 16, -100000000000, +100000000000), "write failed");
            Check(stream.BitsProcessed == 54, $"expected 54 bits, got {stream.BitsProcessed}");         // the example's shape, inside the two group band
        }
        {
            byte[] buffer = new byte[16];
            WriteStream stream = new WriteStream(buffer);
            Int128 value = 0;
            Check(stream.SerializeFixed(ref value, 112, 16, -32768, +32768), "write failed");
            Check(stream.BitsProcessed == 33, $"expected 33 bits, got {stream.BitsProcessed}");         // the band's low edge
        }
        {
            byte[] buffer = new byte[16];
            WriteStream stream = new WriteStream(buffer);
            Int128 value = 0;
            Check(stream.SerializeFixed(ref value, 112, 16, -140737488355328, +140737488355327), "write failed");
            Check(stream.BitsProcessed == 64, $"expected 64 bits, got {stream.BitsProcessed}");         // the band's high edge
        }

        // one raw step past rawMax must be rejected on read, through every group
        // structure — the 33..64 bit two group band included
        CheckFixedWideRejectsOutOfRange(FixedStorage.I128, 112, 16, -1152921504606846976, +1152921504606846976);
        CheckFixedWideRejectsOutOfRange(FixedStorage.I128, 112, 16, -2, +2);
        CheckFixedWideRejectsOutOfRange(FixedStorage.I128, 64, 64, -1000, +1000);
        CheckFixedWideRejectsOutOfRange(FixedStorage.U128, 112, 16, 0, 2305843009213693952);
        CheckFixedWideRejectsOutOfRange(FixedStorage.I128, 112, 16, -32768, +32768);
        CheckFixedWideRejectsOutOfRange(FixedStorage.I128, 112, 16, -100000000000, +100000000000);
        CheckFixedWideRejectsOutOfRange(FixedStorage.I128, 112, 16, -140737488355328, +140737488355327);

        // reads past the end of the buffer must fail cleanly
        {
            byte[] buffer = new byte[8];
            ReadStream readStream = new ReadStream(buffer, 4);
            Int128 value = 424242; // sentinel
            Check(!readStream.SerializeFixed(ref value, 112, 16, -1152921504606846976, +1152921504606846976),
                "expected the truncated read to fail");
            Check(readStream.Error == SerializeError.Overflow, $"expected Overflow, got {readStream.Error}");
            Check(value == 424242, "a failed read must leave the value unmodified");
        }
    }

    private static void TestSerializeUInt128()
    {
        // round trips across the value patterns: zero, max, each half alone,
        // alternating bits, distinct halves; always exactly 128 bits, measure agrees
        {
            UInt128[] values =
            {
                0,
                UInt128.MaxValue,
                (UInt128)0xFFFFFFFFFFFFFFFF << 64,                                      // high half only
                0xFFFFFFFFFFFFFFFF,                                                     // low half only
                ((UInt128)0xAAAAAAAAAAAAAAAA << 64) | 0x5555555555555555,               // alternating bits
                ((UInt128)0x0123456789ABCDEF << 64) | 0xFEDCBA9876543210,               // distinct halves
            };

            foreach (UInt128 expected in values)
            {
                byte[] buffer = new byte[16];

                WriteStream writeStream = new WriteStream(buffer);
                UInt128 written = expected;
                Check(writeStream.SerializeUInt128(ref written), "write failed");
                writeStream.Flush();

                MeasureStream measureStream = new MeasureStream();
                UInt128 measured = expected;
                Check(measureStream.SerializeUInt128(ref measured), "measure failed");
                Check(measureStream.BitsProcessed == writeStream.BitsProcessed,
                    $"measure {measureStream.BitsProcessed} != write {writeStream.BitsProcessed}");
                Check(writeStream.BitsProcessed == 128,
                    $"expected 128 bits, got {writeStream.BitsProcessed}");

                ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
                UInt128 readBack = 0;
                Check(readStream.SerializeUInt128(ref readBack), "read failed");
                Check(readBack == expected, $"read back {readBack}, expected {expected}");
            }
        }

        // cross form consistency: SerializeUInt128 must be byte identical to two
        // SerializeUInt64 operations on the halves, low half first. this is the
        // portability story: an implementation without a 128 bit type reproduces the
        // wire exactly with two 64 bit operations.
        {
            const ulong lowHalf = 0xFEDCBA9876543210;
            const ulong highHalf = 0x0123456789ABCDEF;

            byte[] uint128Buffer = new byte[16];
            WriteStream uint128Stream = new WriteStream(uint128Buffer);
            UInt128 value = ((UInt128)highHalf << 64) | lowHalf;
            Check(uint128Stream.SerializeUInt128(ref value), "uint128 write failed");
            uint128Stream.Flush();

            byte[] halvesBuffer = new byte[16];
            WriteStream halvesStream = new WriteStream(halvesBuffer);
            ulong lo = lowHalf;
            ulong hi = highHalf;
            Check(halvesStream.SerializeUInt64(ref lo), "low half write failed");
            Check(halvesStream.SerializeUInt64(ref hi), "high half write failed");
            halvesStream.Flush();

            Check(uint128Stream.BitsProcessed == halvesStream.BitsProcessed,
                "uint128 and two-halves bit counts differ");
            Check(uint128Buffer.AsSpan().SequenceEqual(halvesBuffer),
                "uint128 bytes differ from two SerializeUInt64 halves");
        }

        // the golden pin: 16 bytes, little endian, low half first. write side must
        // produce exactly the pinned bytes; the pinned bytes must decode back.
        {
            UInt128 goldenValue = ((UInt128)0x0123456789ABCDEF << 64) | 0xFEDCBA9876543210;

            byte[] buffer = new byte[16];
            WriteStream writeStream = new WriteStream(buffer);
            UInt128 written = goldenValue;
            Check(writeStream.SerializeUInt128(ref written), "write failed");
            writeStream.Flush();
            Check(writeStream.BytesProcessed == Uint128GoldenBytes.Length,
                $"expected {Uint128GoldenBytes.Length} bytes, got {writeStream.BytesProcessed}");
            Check(writeStream.Data.SequenceEqual(Uint128GoldenBytes),
                $"uint128 golden mismatch:\nexpected {Convert.ToHexString(Uint128GoldenBytes)}\ngot      {Convert.ToHexString(writeStream.Data)}");

            ReadStream readStream = new ReadStream(Uint128GoldenBytes);
            UInt128 readBack = 0;
            Check(readStream.SerializeUInt128(ref readBack), "golden read failed");
            Check(readBack == goldenValue, "golden bytes decoded to the wrong value");
        }
    }

    private static void TestSerializeInt128()
    {
        // 1. WIRE IDENTITY with SerializeInt64 wherever the range fits 64 bits: this
        //    is what lets a schema widen a field without a wire change, so it is
        //    pinned by byte comparison rather than assumed.
        {
            const long min64 = -5000000000;
            const long max64 = +5000000000;
            long[] values = { min64, min64 + 1, -1, 0, +1, 4123456789, max64 - 1, max64 };

            foreach (long value in values)
            {
                byte[] buffer128 = new byte[32];
                WriteStream w128 = new WriteStream(buffer128);
                Int128 v128 = value;
                Check(w128.SerializeInt128(ref v128, min64, max64), "int128 write failed");
                w128.Flush();

                byte[] buffer64 = new byte[32];
                WriteStream w64 = new WriteStream(buffer64);
                long v64 = value;
                Check(w64.SerializeInt64(ref v64, min64, max64), "int64 write failed");
                w64.Flush();

                Check(w128.BitsProcessed == w64.BitsProcessed,
                    $"value {value}: int128 {w128.BitsProcessed} bits != int64 {w64.BitsProcessed} bits");
                Check(w128.BytesProcessed == w64.BytesProcessed, "byte counts differ");
                Check(buffer128.AsSpan().SequenceEqual(buffer64),
                    $"value {value}: int128 bytes differ from int64 bytes");

                ReadStream readStream = new ReadStream(buffer128, (int)w128.BytesProcessed);
                Int128 readBack = 0;
                Check(readStream.SerializeInt128(ref readBack, min64, max64), "read failed");
                Check(readBack == value, $"read back {readBack}, expected {value}");
            }
        }

        // 2. the wide bands the 64 bit path cannot express at all: three group
        //    ranges, including offsets only a 128 bit domain can hold
        {
            Int128 wideMin = -((Int128)1 << 100);
            Int128 wideMax = (Int128)1 << 100;
            Int128[] values = { wideMin, wideMin + 1, -1, 0, 1, (Int128)1 << 99, wideMax - 1, wideMax };

            foreach (Int128 value in values)
            {
                byte[] buffer = new byte[32];
                WriteStream writeStream = new WriteStream(buffer);
                Int128 v = value;
                Check(writeStream.SerializeInt128(ref v, wideMin, wideMax), "write failed");
                writeStream.Flush();
                Check(writeStream.BitsProcessed == 102,                     // BitsRequired128(-2^100, 2^100) == 102
                    $"expected 102 bits, got {writeStream.BitsProcessed}");

                ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
                Int128 readBack = 0;
                Check(readStream.SerializeInt128(ref readBack, wideMin, wideMax), "read failed");
                Check(readBack == value, $"read back {readBack}, expected {value}");
            }
        }

        // 3. the full 128 bit range: every group full, and the range is wider than
        //    2^127 — the unsigned domain subtraction a signed one would overflow
        {
            Int128 fullMin = Int128.MinValue;
            Int128 fullMax = Int128.MaxValue;
            Int128[] values = { fullMin, fullMin + 1, -1, 0, 1, fullMax - 1, fullMax };

            foreach (Int128 value in values)
            {
                byte[] buffer = new byte[32];
                WriteStream writeStream = new WriteStream(buffer);
                Int128 v = value;
                Check(writeStream.SerializeInt128(ref v, fullMin, fullMax), "write failed");
                writeStream.Flush();
                Check(writeStream.BitsProcessed == 128,
                    $"expected 128 bits, got {writeStream.BitsProcessed}");

                ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
                Int128 readBack = 0;
                Check(readStream.SerializeInt128(ref readBack, fullMin, fullMax), "read failed");
                Check(readBack == value, $"read back {readBack}, expected {value}");
            }
        }

        // 4. the measure stream must agree with the write stream exactly, at every
        //    group width
        {
            (Int128 Value, Int128 Min, Int128 Max)[] cases =
            {
                (0, 0, 255),
                (7, -5000000000, +5000000000),
                (1, -((Int128)1 << 100), (Int128)1 << 100),
                (0, Int128.MinValue, Int128.MaxValue),
            };

            foreach ((Int128 value, Int128 min, Int128 max) in cases)
            {
                byte[] buffer = new byte[32];
                WriteStream writeStream = new WriteStream(buffer);
                Int128 v = value;
                Check(writeStream.SerializeInt128(ref v, min, max), "write failed");
                writeStream.Flush();

                MeasureStream measureStream = new MeasureStream();
                Int128 m = value;
                Check(measureStream.SerializeInt128(ref m, min, max), "measure failed");
                Check(measureStream.BitsProcessed == writeStream.BitsProcessed,
                    $"measure {measureStream.BitsProcessed} != write {writeStream.BitsProcessed}");
            }
        }

        // 5. a value outside the bounds must be REFUSED on read. the bit count is
        //    identical for both bound pairs here, so the reader consumes the same
        //    bits and the range check is what convicts it
        {
            byte[] buffer = new byte[32];
            WriteStream writeStream = new WriteStream(buffer);
            Int128 written = 255;
            Check(writeStream.SerializeInt128(ref written, 0, 255), "write failed");
            writeStream.Flush();

            Check(SerializeUtil.BitsRequired128(0, 200) == 8, "expected [0,200] to cost 8 bits too");

            ReadStream readStream = new ReadStream(buffer);
            Int128 readBack = -777; // sentinel
            Check(!readStream.SerializeInt128(ref readBack, 0, 200), "expected the read to fail");
            Check(readStream.Error == SerializeError.ValueOutOfRange,
                $"expected ValueOutOfRange, got {readStream.Error}");
            Check(readBack == -777, "a failed read must leave the value unmodified");
        }

        // 6. a truncated buffer must be refused rather than read past the end
        {
            byte[] buffer = new byte[32];
            ReadStream readStream = new ReadStream(buffer, 4);      // 32 bits available, 128 required
            Int128 readBack = 424242; // sentinel
            Check(!readStream.SerializeInt128(ref readBack, Int128.MinValue, Int128.MaxValue),
                "expected the truncated read to fail");
            Check(readStream.Error == SerializeError.Overflow, $"expected Overflow, got {readStream.Error}");
            Check(readBack == 424242, "a failed read must leave the value unmodified");
        }

        // 7. THE GOLDEN PIN: bounds of ±2^70 need 72 bits, the THREE group structure
        //    (32, 32, then 8). write side must produce exactly the pinned bytes; the
        //    pinned bytes must decode back. see the pin's provenance note above.
        {
            Int128 goldenMin = -((Int128)1 << 70);
            Int128 goldenMax = (Int128)1 << 70;
            Int128 goldenValue = -(Int128)0x0123456789ABCDEF;

            byte[] buffer = new byte[16];
            WriteStream writeStream = new WriteStream(buffer);
            Int128 written = goldenValue;
            Check(writeStream.SerializeInt128(ref written, goldenMin, goldenMax), "write failed");
            writeStream.Flush();
            Check(writeStream.BitsProcessed == 72, $"expected 72 bits, got {writeStream.BitsProcessed}");
            Check(writeStream.BytesProcessed == Int128GoldenBytes.Length,
                $"expected {Int128GoldenBytes.Length} bytes, got {writeStream.BytesProcessed}");
            Check(writeStream.Data.SequenceEqual(Int128GoldenBytes),
                $"int128 golden mismatch:\nexpected {Convert.ToHexString(Int128GoldenBytes)}\ngot      {Convert.ToHexString(writeStream.Data)}");

            ReadStream readStream = new ReadStream(Int128GoldenBytes);
            Int128 readBack = 0;
            Check(readStream.SerializeInt128(ref readBack, goldenMin, goldenMax), "golden read failed");
            Check(readBack == goldenValue, "golden bytes decoded to the wrong value");
        }
    }

    private static void TestFixedWireFormat()
    {
        // write side: serializing the fixed point golden values must produce exactly
        // the pinned bytes — the byte aligned tail of the C++ fixed-point golden
        // message, derived independently from STANDARD.md
        {
            byte[] buffer = new byte[64];
            WriteStream stream = new WriteStream(buffer);
            FixedWireData data = FixedWireData.Init();
            Check(FixedWireData.Serialize(stream, data), $"write failed: {stream.Error}");
            stream.Flush();
            Check(stream.BytesProcessed == FixedWireBytes.Length,
                $"expected {FixedWireBytes.Length} bytes, got {stream.BytesProcessed}");
            Check(stream.Data.SequenceEqual(FixedWireBytes),
                $"fixed golden mismatch:\nexpected {Convert.ToHexString(FixedWireBytes)}\ngot      {Convert.ToHexString(stream.Data)}");
        }

        // read side: the pinned bytes must decode to the expected values, on every
        // platform, forever — and exactly: fixed point has no quantization step
        {
            ReadStream stream = new ReadStream(FixedWireBytes);
            FixedWireData data = new FixedWireData();
            Check(FixedWireData.Serialize(stream, data), $"read failed: {stream.Error}");

            FixedWireData expected = FixedWireData.Init();
            Check(data.FixedQ8_8 == expected.FixedQ8_8, $"Q8.8 mismatch: got {data.FixedQ8_8}");
            Check(data.FixedQ16_16 == expected.FixedQ16_16, $"Q16.16 mismatch: got {data.FixedQ16_16}");
            Check(data.FixedQ48_16 == expected.FixedQ48_16, $"Q48.16 mismatch: got {data.FixedQ48_16}");
            Check(data.FixedQ16_16Unsigned == expected.FixedQ16_16Unsigned,
                $"unsigned Q16.16 mismatch: got {data.FixedQ16_16Unsigned}");
            Check(data.FixedQ112_16Wide == expected.FixedQ112_16Wide,
                $"Q112.16 mismatch: got {data.FixedQ112_16Wide}");
            Check(data.FixedQ64_64Wide == expected.FixedQ64_64Wide,
                $"Q64.64 mismatch: got {data.FixedQ64_64Wide}");
        }
    }
}
