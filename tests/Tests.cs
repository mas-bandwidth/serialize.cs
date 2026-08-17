/*
    Tests.cs

    Console test runner for the C# serialize port. Zero third-party dependencies,
    including test frameworks (family value): each test prints its name, a failed check
    prints and exits nonzero — the exact shape of serialize_check / SERIALIZE_RUN_TEST
    in the C++ library.

    The suite is a test-for-test port of the C++ suite in serialize.h (minus
    test_endian, irrelevant with explicit little endian primitives), plus the tests the
    Go and Rust ports added, plus deterministic differential/hostile seeded tests in
    Differential.cs.
*/

using System;
#if DEBUG
using System.Diagnostics;
#endif

namespace Serialize.Tests;

internal sealed class TestContext
{
    public int Min;
    public int Max;
}

internal sealed class TestObject : ISerializer
{
    public const int MaxItems = 11;

    public int A, B, C;
    public uint D, E, F;
    public bool G;
    public int NumItems;
    public int[] Items = new int[MaxItems];
    public float FloatValue;
    public float CompressedFloatValue;
    public double DoubleValue;
    public byte UInt8Value;
    public ushort UInt16Value;
    public uint UInt32Value;
    public ulong UInt64Value;
    public int IntRelative;
    public long Int64Full;
    public long Int64Range;
    public byte[] Bytes = new byte[17];
    public string Str = "";
    public string WStr = "";

    public void Init()
    {
        A = 1;
        B = -2;
        C = 150;
        D = 55;
        E = 255;
        F = 127;
        G = true;

        NumItems = MaxItems / 2;
        for (int i = 0; i < NumItems; i++)
        {
            Items[i] = i + 10;
        }

        CompressedFloatValue = 2.13f;
        FloatValue = 3.1415926f;
        DoubleValue = 1.0 / 3.0;
        UInt8Value = 123;
        UInt16Value = 0x1234;
        UInt32Value = 0x12345678;
        UInt64Value = 0x1234567898765432;
        IntRelative = 5;
        Int64Full = -123456789012345;
        Int64Range = 4123456789;

        for (int i = 0; i < Bytes.Length; i++)
        {
            Bytes[i] = (byte)((i + 5) * 13);
        }

        Str = "hello world!";
        WStr = "привіт, світ!"; // "привіт, світ!"
    }

    public bool Serialize(IBitStream stream)
    {
        TestContext context = (TestContext)stream.Context!;

        stream.SerializeInt(ref A, context.Min, context.Max);
        stream.SerializeInt(ref B, context.Min, context.Max);

        stream.SerializeInt(ref C, -100, 10000);

        stream.SerializeBits(ref D, 6);
        stream.SerializeBits(ref E, 8);
        stream.SerializeBits(ref F, 7);

        stream.SerializeAlign();

        stream.SerializeBool(ref G);

        // NumItems controls the loop below, so its result must be checked before the
        // loop: on a truncated packet the failed read leaves the previous value in place
        if (!stream.SerializeInt(ref NumItems, 0, MaxItems - 1))
        {
            return false;
        }
        for (int i = 0; i < NumItems; i++)
        {
            uint item = (uint)Items[i];
            stream.SerializeBits(ref item, 8);
            Items[i] = (int)item;
        }

        stream.SerializeFloat(ref FloatValue);

        stream.SerializeCompressedFloat(ref CompressedFloatValue, 0, 10, 0.01f);

        stream.SerializeDouble(ref DoubleValue);

        stream.SerializeByte(ref UInt8Value);
        stream.SerializeUInt16(ref UInt16Value);
        stream.SerializeUInt32(ref UInt32Value);
        stream.SerializeUInt64(ref UInt64Value);

        stream.SerializeIntRelative(A, ref IntRelative);

        stream.SerializeInt64(ref Int64Full, long.MinValue, long.MaxValue);
        stream.SerializeInt64(ref Int64Range, -5000000000, +5000000000);

        stream.SerializeBytes(Bytes);

        stream.SerializeString(ref Str, 256);
        stream.SerializeWideString(ref WStr, 256);

        return stream.Error == SerializeError.None;
    }

    public bool DataEquals(TestObject other)
    {
        return A == other.A && B == other.B && C == other.C
            && D == other.D && E == other.E && F == other.F
            && G == other.G
            && NumItems == other.NumItems
            && Items.AsSpan().SequenceEqual(other.Items)
            && FloatValue == other.FloatValue
            && CompressedFloatValue == other.CompressedFloatValue
            && DoubleValue == other.DoubleValue
            && UInt8Value == other.UInt8Value
            && UInt16Value == other.UInt16Value
            && UInt32Value == other.UInt32Value
            && UInt64Value == other.UInt64Value
            && IntRelative == other.IntRelative
            && Int64Full == other.Int64Full
            && Int64Range == other.Int64Range
            && Bytes.AsSpan().SequenceEqual(other.Bytes)
            && Str == other.Str
            && WStr == other.WStr;
    }
}

internal sealed class FailingObject : ISerializer
{
    public bool Serialize(IBitStream stream)
    {
        return false; // object-level validation failure
    }
}

// Golden wire format data. The exact bytes produced by the serializer are pinned down
// here and must never change. They are copied verbatim from the C++ serialize library
// test suite, so this test also proves the C# implementation is wire compatible with
// the C++ implementation.
internal sealed class GoldenWireData
{
    public uint Bits4;
    public uint Bits11;
    public uint Bits24;
    public uint Bits32;
    public int IntSmall;
    public int IntFull;
    public bool Flag;
    public float FloatValue;
    public float CompressedFloatValue;
    public double DoubleValue;
    public byte UInt8Value;
    public ushort UInt16Value;
    public uint UInt32Value;
    public ulong UInt64Value;
    public int RelativeNear;
    public int RelativeFar;
    public byte[] Bytes = new byte[7];
    public string Str = "";
    public string WStr = "";

    public static GoldenWireData Init()
    {
        return new GoldenWireData
        {
            Bits4 = 13,
            Bits11 = 1445,
            Bits24 = 11259375,
            Bits32 = 0xDEADBEEF,
            IntSmall = -37,
            IntFull = -123456789,
            Flag = true,
            FloatValue = 3.1415926f, // the LITERAL, bits 0x40490FDA — NOT MathF.PI
            CompressedFloatValue = 5.0f, // 5.0 in [0,10] normalizes to exactly 0.5: quantizes identically everywhere
            DoubleValue = 1.0 / 3.0,
            UInt8Value = 0x7F,
            UInt16Value = 0x1234,
            UInt32Value = 0x12345678,
            UInt64Value = 0x123456789ABCDEF0,
            RelativeNear = 101, // difference of 1 from the base: exercises the one bit branch
            RelativeFar = 2100, // difference of 2000 from the base: exercises the twelve bit bucket
            Bytes = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x01 },
            Str = "golden",
            WStr = "мир", // "мир": cyrillic, BMP only, explicit code points so source encoding can never change the bytes
        };
    }

    public static bool Serialize(IBitStream stream, GoldenWireData data)
    {
        const int relativeBase = 100;
        stream.SerializeBits(ref data.Bits4, 4);
        stream.SerializeBits(ref data.Bits11, 11);
        stream.SerializeBits(ref data.Bits24, 24);
        stream.SerializeBits(ref data.Bits32, 32);
        stream.SerializeInt(ref data.IntSmall, -100, +100);
        stream.SerializeInt(ref data.IntFull, int.MinValue, int.MaxValue);
        stream.SerializeBool(ref data.Flag);
        stream.SerializeFloat(ref data.FloatValue);
        stream.SerializeCompressedFloat(ref data.CompressedFloatValue, 0.0f, 10.0f, 0.01f);
        stream.SerializeDouble(ref data.DoubleValue);
        stream.SerializeByte(ref data.UInt8Value);
        stream.SerializeUInt16(ref data.UInt16Value);
        stream.SerializeUInt32(ref data.UInt32Value);
        stream.SerializeUInt64(ref data.UInt64Value);
        stream.SerializeIntRelative(relativeBase, ref data.RelativeNear);
        stream.SerializeIntRelative(relativeBase, ref data.RelativeFar);
        stream.SerializeAlign();
        stream.SerializeBytes(data.Bytes);
        stream.SerializeString(ref data.Str, 16);
        stream.SerializeWideString(ref data.WStr, 8);
        return stream.Error == SerializeError.None;
    }
}

// Extended wire format data: the golden sequence plus the 64 bit paths the golden test
// does not cover (SerializeBits64 above 32 bits, SerializeInt64 full range and two
// dword range) plus a compressed float pinned on an FMA rounding boundary. It mirrors
// the compat harness sequence exactly (compat/Compat.cs / compat/cpp/compat.cpp): any
// change there must be mirrored here, and never changes the wire format.
internal sealed class ExtendedWireData
{
    public GoldenWireData Golden = new GoldenWireData();
    public ulong Bits33;
    public long Int64Full;
    public long Int64Range;
    public float FmaBoundaryFloat;

    public static ExtendedWireData Init()
    {
        return new ExtendedWireData
        {
            Golden = GoldenWireData.Init(),
            Bits33 = 0x1DEADBEEF,
            Int64Full = -123456789012345,
            Int64Range = 4123456789,
            // 0.005 in [0,10] res 0.01 sits exactly on a t = 1.0f quantization
            // boundary: strict IEEE mul-then-add (C#, Rust, C++ with
            // -ffp-contract=off) writes integer 1, a fused multiply-add writes 0.
            // strict evaluation is the normative wire; this value pins it.
            FmaBoundaryFloat = 0.005f,
        };
    }

    public static bool Serialize(IBitStream stream, ExtendedWireData data)
    {
        GoldenWireData.Serialize(stream, data.Golden);
        stream.SerializeBits64(ref data.Bits33, 33);
        stream.SerializeInt64(ref data.Int64Full, long.MinValue, long.MaxValue);
        stream.SerializeInt64(ref data.Int64Range, -5000000000, +5000000000);
        stream.SerializeCompressedFloat(ref data.FmaBoundaryFloat, 0.0f, 10.0f, 0.01f);
        return stream.Ok;
    }
}

internal static partial class Program
{
    // goldenWireBytes are copied verbatim from the C++ serialize library test suite
    // (transcribed from serialize.go/serialize_test.go:882, itself pinned to
    // serialize/serialize.h:3195). Never regenerate these.
    private static readonly byte[] GoldenWireBytes =
    {
        0x5D, 0xDA, 0xF7, 0xE6, 0xD5, 0x77, 0xDF, 0x56, 0xEF, 0x9F, 0x75, 0x19,
        0x52, 0xBC, 0xDA, 0x0F, 0x49, 0x40, 0xF4, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0xFF, 0xFC, 0xD1, 0x48, 0xE0, 0x59, 0xD1, 0x48, 0xC0, 0x7B,
        0xF3, 0x6A, 0xE2, 0x59, 0xD1, 0x48, 0x84, 0xB7, 0x06, 0xDE, 0xAD, 0xBE,
        0xEF, 0xCA, 0xFE, 0x01, 0x06, 0x67, 0x6F, 0x6C, 0x64, 0x65, 0x6E, 0xE3,
        0x21, 0x00, 0x00, 0xC0, 0x21, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00,
    };

    // ExtendedWireBytes pin the extended sequence (golden + 64 bit paths + FMA
    // boundary float). Transcribed from the output of compat/cpp/compat.cpp built
    // against serialize/serialize.h with clang++ -O2 -std=c++17 -ffp-contract=off
    // (strict IEEE evaluation is the normative wire; see compat/cpp/compat.cpp),
    // cross-checked byte identical against the C# compat write. Never regenerate.
    private static readonly byte[] ExtendedWireBytes =
    {
        0x5D, 0xDA, 0xF7, 0xE6, 0xD5, 0x77, 0xDF, 0x56, 0xEF, 0x9F, 0x75, 0x19,
        0x52, 0xBC, 0xDA, 0x0F, 0x49, 0x40, 0xF4, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0xFF, 0xFC, 0xD1, 0x48, 0xE0, 0x59, 0xD1, 0x48, 0xC0, 0x7B,
        0xF3, 0x6A, 0xE2, 0x59, 0xD1, 0x48, 0x84, 0xB7, 0x06, 0xDE, 0xAD, 0xBE,
        0xEF, 0xCA, 0xFE, 0x01, 0x06, 0x67, 0x6F, 0x6C, 0x64, 0x65, 0x6E, 0xE3,
        0x21, 0x00, 0x00, 0xC0, 0x21, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x78,
        0xF7, 0x6D, 0xF5, 0x7E, 0x08, 0x22, 0x9F, 0x77, 0xFB, 0xF8, 0xFF, 0x57,
        0x71, 0xCE, 0xFC, 0x61, 0x00,
    };

    private static void Check(bool condition, string message)
    {
        if (!condition)
        {
            Console.Error.WriteLine($"    check failed: {message}");
            Environment.Exit(1);
        }
    }

    // optional substring filter from the command line: run only matching tests, so a
    // single failing test can be debugged without running the whole suite
    private static string? s_filter;
    private static int s_testsRun;

    private static void RunTest(string name, Action test)
    {
        if (s_filter != null && !name.Contains(s_filter, StringComparison.Ordinal))
        {
            return;
        }
        Console.WriteLine(name);
        s_testsRun++;
        test();
    }

    private static int Main(string[] args)
    {
        // usage: [short] [filter-substring]
        bool shortMode = false;
        foreach (string arg in args)
        {
            if (arg == "short")
            {
                shortMode = true;
            }
            else
            {
                s_filter = arg;
            }
        }

        RunTest("test_bitpacker", TestBitpacker);
        RunTest("test_degenerate_range", TestDegenerateRange);
        RunTest("test_bits_required", TestBitsRequired);
        RunTest("test_bits_required64", TestBitsRequired64);
        RunTest("test_bits_required128", TestBitsRequired128);
        RunTest("test_zigzag", TestZigZag);
        RunTest("test_serialize", TestSerialize);
        RunTest("test_read_write", TestReadWrite);
        RunTest("test_serialize_integer_validation", TestSerializeIntegerValidation);
        RunTest("test_serialize_integer_full_range", TestSerializeIntegerFullRange);
        RunTest("test_serialize_int64_full_range", TestSerializeInt64FullRange);
        RunTest("test_serialize_int64_validation", TestSerializeInt64Validation);
        RunTest("test_serialize_bytes_validation", TestSerializeBytesValidation);
        RunTest("test_string_validation", TestStringValidation);
        RunTest("test_wstring_validation", TestWStringValidation);
        RunTest("test_int_relative_validation", TestIntRelativeValidation);
        RunTest("test_compressed_float_validation", TestCompressedFloatValidation);
        RunTest("test_compressed_float_quantization_boundaries", TestCompressedFloatQuantizationBoundaries);
        RunTest("test_serialize_fixed", TestSerializeFixed);
        RunTest("test_serialize_fixed_validation", TestSerializeFixedValidation);
        RunTest("test_serialize_fixed_matches_int64", TestSerializeFixedMatchesInt64);
        RunTest("test_serialize_fixed_wide", TestSerializeFixedWide);
        RunTest("test_serialize_uint128", TestSerializeUInt128);
        RunTest("test_serialize_int128", TestSerializeInt128);
        RunTest("test_golden_wire_format", TestGoldenWireFormat);
        RunTest("test_extended_wire_format", TestExtendedWireFormat);
        RunTest("test_fixed_wire_format", TestFixedWireFormat);
        RunTest("test_write_bytes_qword_phases", TestWriteBytesQwordPhases);
        RunTest("test_write_trusted", TestWriteTrusted);
#if DEBUG
        // only in debug builds: the write-side contracts are Debug.Assert, compiled
        // out without the DEBUG constant — in a release build there is nothing to fire
        RunTest("test_write_contract_asserts", TestWriteContractAsserts);
        // ...and the API misuse parameter contracts, Debug.Assert on every stream
        // since the 2026-08-16 check-model audit (the throws they replaced were this
        // port's invention; the C++ library compiles serialize_assert out in release)
        RunTest("test_api_misuse_asserts", TestApiMisuseAsserts);
#else
        // only in release builds: the production spine carries none of the misuse
        // checks — the proof they compiled out (the release half of the audit)
        RunTest("test_api_misuse_checks_absent_in_release", TestApiMisuseChecksAbsentInRelease);
#endif
        RunTest("test_align_validation", TestAlignValidation);
        RunTest("test_measure_stream", TestMeasureStream);
        RunTest("test_continue", TestContinue);
        RunTest("test_until", TestUntil);
        RunTest("test_sentinel_loop_termination", TestSentinelLoopTermination);
        RunTest("test_count_loop_termination", TestCountLoopTermination);
        RunTest("test_serialize_object_struct", TestSerializeObjectStruct);
        RunTest("test_string_long_write", TestStringLongWrite);
        RunTest("test_serialize_object_error_propagation", TestSerializeObjectErrorPropagation);
        RunTest("test_stream_reset", TestStreamReset);
        RunTest("test_differential_round_trip", TestDifferentialRoundTrip);
        RunTest("test_hostile_read", TestHostileRead);
        RunTest("test_write_batch_golden_wire", TestWriteBatchGoldenWire);
        RunTest("test_write_batch_differential", TestWriteBatchDifferential);
        RunTest("test_read_batch_differential", TestReadBatchDifferential);
        RunTest("test_batch_error_latch", TestBatchErrorLatch);
        RunTest("test_batch_end_idempotent", TestBatchEndIdempotent);
        RunTest("test_batch_allocation", TestBatchAllocation);
        RunTest("test_batch_properties", TestBatchProperties);

        RunTest("test_int128_pair_basics", TestInt128PairBasics);
#if SERIALIZE_HAS_INT128
        RunTest("test_int128_pair_unsigned_oracle", TestInt128PairUnsignedOracle);
        RunTest("test_int128_pair_signed_oracle", TestInt128PairSignedOracle);
#endif // SERIALIZE_HAS_INT128
        if (!shortMode)
        {
            RunTest("test_large_buffer", TestLargeBuffer);
        }

        if (s_testsRun == 0)
        {
            Console.Error.WriteLine($"no tests match filter \"{s_filter}\"");
            return 1;
        }

        Console.WriteLine();
        Console.WriteLine($"ALL TESTS PASSED ({s_testsRun} tests)");
        return 0;
    }

    private static void TestBitpacker()
    {
        const int bufferSize = 256;

        byte[] buffer = new byte[bufferSize];

        BitWriter writer = new BitWriter(buffer);

        Check(writer.BitsWritten == 0 && writer.BytesWritten == 0 && writer.BitsAvailable == bufferSize * 8,
            "bad initial writer state");

        writer.WriteBits(0, 1);
        writer.WriteBits(1, 1);
        writer.WriteBits(10, 8);
        writer.WriteBits(255, 8);
        writer.WriteBits(1000, 10);
        writer.WriteBits(50000, 16);
        writer.WriteBits(9999999, 32);
        // a dirty value: bits above the count are documented as ignored, so the
        // neighbors must be undisturbed even though the value has all 32 bits set
        writer.WriteBits(0xFFFFFFFF, 5);
        // the last value has its high bits set so the final byte of the guarded-tail
        // window (exact-allocation reader below) is load bearing
        writer.WriteBits(0xDEADBEEF, 32);
        writer.FlushBits();

        const int bitsWritten = 1 + 1 + 8 + 8 + 10 + 16 + 32 + 5 + 32;

        Check(writer.BytesWritten == 15, $"expected 15 bytes written, got {writer.BytesWritten}");
        Check(writer.BitsWritten == bitsWritten, $"expected {bitsWritten} bits written, got {writer.BitsWritten}");
        Check(writer.BitsAvailable == bufferSize * 8 - bitsWritten, "bad bits available");

        long bytesWritten = writer.BytesWritten;

        // read twice: once with slack past the data (branchless window loads), once
        // from an exact size buffer with no slack (guarded tail path)
        BitReader[] readers =
        {
            new BitReader(buffer, (int)bytesWritten),   // slack extends into the original buffer
            new BitReader(writer.Data.ToArray()),       // exact allocation
        };

        foreach (BitReader reader in readers)
        {
            Check(reader.BitsRead == 0 && reader.BitsRemaining == bytesWritten * 8, "bad initial reader state");

            uint a = reader.ReadBits(1);
            uint b = reader.ReadBits(1);
            uint c = reader.ReadBits(8);
            uint d = reader.ReadBits(8);
            uint e = reader.ReadBits(10);
            uint f = reader.ReadBits(16);
            uint g = reader.ReadBits(32);
            uint h = reader.ReadBits(5);
            uint i = reader.ReadBits(32);

            Check(a == 0 && b == 1 && c == 10 && d == 255 && e == 1000 && f == 50000 && g == 9999999,
                $"read values do not match written values: {a} {b} {c} {d} {e} {f} {g}");
            Check(h == 31, $"dirty write must be masked to its bit count: expected 31, got {h}");
            Check(i == 0xDEADBEEF, $"expected 0xDEADBEEF in the tail window, got {i:x}");

            Check(reader.BitsRead == bitsWritten, "bad bits read");
            Check(reader.BitsRemaining == bytesWritten * 8 - bitsWritten, "bad bits remaining");
            Check(!reader.WouldReadPastEnd((int)reader.BitsRemaining), "reading the remaining bits must not read past the end");
            Check(reader.WouldReadPastEnd((int)reader.BitsRemaining + 1), "reading past the remaining bits must report past the end");
        }
    }

    // STANDARD.md: a degenerate range where min == max costs ZERO BITS -- the
    // value is known from the range alone and nothing is written.
    //
    // Every stream used to throw ArgumentException on min >= max, rejecting
    // exactly that case. The C++ and C ports support it, so this was a
    // cross-language divergence: the same sequence works against one runtime
    // and throws against this one.
    private static void TestDegenerateRange()
    {
        byte[] buffer = new byte[64];

        WriteStream write = new WriteStream(buffer);
        int degenerate = 5;
        int after = 3;
        Check(write.SerializeInt(ref degenerate, 5, 5), "write degenerate range");
        Check(write.BitsProcessed == 0, $"degenerate range wrote {write.BitsProcessed} bits, expected 0");
        Check(write.SerializeInt(ref after, 0, 7), "write after");
        // the next field must still start at bit 0 -- if the degenerate range
        // consumed bit space, everything downstream shifts and the wire stops
        // matching the other ports
        Check(write.BitsProcessed == 3, $"after the degenerate range the stream is at {write.BitsProcessed} bits, expected 3");
        write.Flush();

        ReadStream read = new ReadStream(buffer, (int)write.BytesProcessed);
        int readDegenerate = 0;
        int readAfter = 0;
        Check(read.SerializeInt(ref readDegenerate, 5, 5), "read degenerate range");
        Check(readDegenerate == 5, $"degenerate read back {readDegenerate}, expected 5 (recovered from the range)");
        Check(read.BitsProcessed == 0, $"degenerate range read {read.BitsProcessed} bits, expected 0");
        Check(read.SerializeInt(ref readAfter, 0, 7), "read after");
        Check(readAfter == 3, $"after read back {readAfter}, expected 3");

        MeasureStream measure = new MeasureStream();
        int measured = 5;
        Check(measure.SerializeInt(ref measured, 5, 5), "measure degenerate range");
        Check(measure.BitsProcessed == 0, $"measure says the degenerate range costs {measure.BitsProcessed} bits, expected 0");

        // 64 bit too
        WriteStream write64 = new WriteStream(buffer);
        long v64 = -42;
        Check(write64.SerializeInt64(ref v64, -42, -42), "write degenerate 64");
        Check(write64.BitsProcessed == 0, "degenerate 64 bit range must be free");
        write64.Flush();
        ReadStream read64 = new ReadStream(buffer, 8);
        long out64 = 0;
        Check(read64.SerializeInt64(ref out64, -42, -42), "read degenerate 64");
        Check(out64 == -42, $"degenerate 64 read back {out64}, expected -42");

        // Relaxing the guard was meant to admit the degenerate case, not to stop
        // validating: an inverted range is still API misuse — Debug.Assert on every
        // stream, compiled out in release (the 2026-08-16 check-model audit; the
        // standard verbatim: "We want MINIMAL runtime checking in release").
#if DEBUG
        Check(AssertFires(() =>
        {
            WriteStream bad = new WriteStream(buffer);
            int v = 0;
            bad.SerializeInt(ref v, 10, 5);
        }), "min > max must assert in debug");
#else
        {
            // the release twin: the misuse check is gone from the release binary —
            // the call completes without throwing, and the result is GIGO
            WriteStream bad = new WriteStream(buffer);
            int v = 0;
            Check(bad.SerializeInt(ref v, 10, 5), "in release the misuse check is compiled out");
        }
#endif
    }

    private static void TestBitsRequired()
    {
        (uint Min, uint Max, int Expected)[] cases =
        {
            (0, 0, 0), (0, 1, 1), (0, 2, 2), (0, 3, 2), (0, 4, 3), (0, 5, 3), (0, 6, 3),
            (0, 7, 3), (0, 8, 4), (0, 255, 8), (0, 65535, 16), (0, 4294967295, 32),
        };
        foreach ((uint min, uint max, int expected) in cases)
        {
            int got = SerializeUtil.BitsRequired(min, max);
            Check(got == expected, $"BitsRequired({min},{max}) = {got}, expected {expected}");
        }
    }

    private static void TestBitsRequired64()
    {
        (ulong Min, ulong Max, int Expected)[] cases =
        {
            (0, 0, 0), (0, 1, 1), (0, 255, 8), (0, 4294967295, 32), (0, 4294967296, 33),
            (0, 1UL << 40, 41), (0, 0xFFFFFFFFFFFFFFFF, 64),
            (unchecked((ulong)long.MinValue), (ulong)long.MaxValue, 64),
            (unchecked((ulong)(-5000000000L)), 5000000000UL, 34),
        };
        foreach ((ulong min, ulong max, int expected) in cases)
        {
            int got = SerializeUtil.BitsRequired64(min, max);
            Check(got == expected, $"BitsRequired64({min},{max}) = {got}, expected {expected}");
        }
    }

    private static void TestZigZag()
    {
        (int Signed, uint Unsigned)[] encoded =
        {
            (0, 0), (-1, 1), (+1, 2), (-2, 3), (+2, 4),
            (int.MaxValue, 0xFFFFFFFE), (int.MinValue, 0xFFFFFFFF),
        };
        foreach ((int signedValue, uint unsignedValue) in encoded)
        {
            Check(SerializeUtil.SignedToUnsigned(signedValue) == unsignedValue,
                $"SignedToUnsigned({signedValue}) != {unsignedValue}");
            Check(SerializeUtil.UnsignedToSigned(unsignedValue) == signedValue,
                $"UnsignedToSigned({unsignedValue}) != {signedValue}");
        }

        int[] values = { 0, -1, +1, -2, +2, 12345, -12345, int.MaxValue, int.MinValue };
        foreach (int v in values)
        {
            Check(SerializeUtil.UnsignedToSigned(SerializeUtil.SignedToUnsigned(v)) == v,
                $"zigzag round trip failed for {v}");
        }
    }

    private static void TestSerialize()
    {
        byte[] buffer = new byte[1024];

        TestContext context = new TestContext { Min = -10, Max = +10 };

        WriteStream writeStream = new WriteStream(buffer);
        writeStream.Context = context;

        TestObject writeObject = new TestObject();
        writeObject.Init();
        Check(writeObject.Serialize(writeStream), $"write failed: {writeStream.Error}");
        writeStream.Flush();

        TestObject readObject = new TestObject();
        ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
        readStream.Context = context;
        Check(readObject.Serialize(readStream), $"read failed: {readStream.Error}");

        Check(readObject.DataEquals(writeObject), "read object does not match written object");
    }

    // The C# equivalent of writing separate read and write functions with the read_*
    // and write_* macros in the C++ library: read with a concrete ReadStream, checking
    // each value as it is read.
    private static void ReadFunction(ReadStream readStream)
    {
        uint u32 = 0;
        Check(readStream.SerializeBits(ref u32, 4), "read bits failed");
        Check(u32 == 13, $"expected 13, got {u32}");

        bool flag = false;
        Check(readStream.SerializeBool(ref flag), "read bool failed");
        Check(flag, "expected true");

        byte u8 = 0;
        Check(readStream.SerializeByte(ref u8), "read uint8 failed");
        Check(u8 == 255, $"expected 255, got {u8}");

        ushort u16 = 0;
        Check(readStream.SerializeUInt16(ref u16), "read uint16 failed");
        Check(u16 == 65535, $"expected 65535, got {u16}");

        Check(readStream.SerializeUInt32(ref u32), "read uint32 failed");
        Check(u32 == 0xFFFFFFFF, $"expected 0xFFFFFFFF, got {u32:x}");

        ulong u64 = 0;
        Check(readStream.SerializeUInt64(ref u64), "read uint64 failed");
        Check(u64 == 0xFFFFFFFFFFFFFFFF, $"expected 0xFFFFFFFFFFFFFFFF, got {u64:x}");

        int i32 = 0;
        Check(readStream.SerializeInt(ref i32, 10, 90), "read int failed");
        Check(i32 == 55, $"expected 55, got {i32}");

        long i64 = 0;
        Check(readStream.SerializeInt64(ref i64, -60000000000, 60000000000), "read int64 failed");
        Check(i64 == -50000000001, $"expected -50000000001, got {i64}");

        float f32 = 0;
        Check(readStream.SerializeFloat(ref f32), "read float failed");
        Check(f32 == 100.0f, $"expected 100.0, got {f32}");

        double f64 = 0;
        Check(readStream.SerializeDouble(ref f64), "read double failed");
        Check(f64 == 1000000000.0, $"expected 1000000000.0, got {f64}");

        byte[] data = new byte[5];
        Check(readStream.SerializeBytes(data), "read bytes failed");
        Check(data.AsSpan().SequenceEqual(new byte[] { 1, 2, 3, 4, 5 }), "expected {1,2,3,4,5}");

        string str = "";
        Check(readStream.SerializeString(ref str, 10), "read string failed");
        Check(str == "hello", $"expected \"hello\", got \"{str}\"");

        string wstr = "";
        Check(readStream.SerializeWideString(ref wstr, 20), "read wide string failed");
        Check(wstr == "привіт", $"expected \"привіт\", got \"{wstr}\"");

        Check(readStream.SerializeAlign(), "read align failed");

        TestContext context = new TestContext { Min = -10, Max = +10 };
        readStream.Context = context;

        TestObject expectedObject = new TestObject();
        expectedObject.Init();

        TestObject readObject = new TestObject();
        Check(readStream.SerializeObject(readObject), "read object failed");
        Check(readObject.DataEquals(expectedObject), "read object does not match expected object");

        int relative = 0;
        Check(readStream.SerializeIntRelative(100, ref relative), "read int relative failed");
        Check(relative == 105, $"expected 105, got {relative}");
    }

    private static void TestReadWrite()
    {
        byte[] buffer = new byte[10 * 1024];

        // write to the buffer with a concrete WriteStream
        WriteStream writeStream = new WriteStream(buffer);

        uint u32 = 13;
        writeStream.SerializeBits(ref u32, 4);
        bool flag = true;
        writeStream.SerializeBool(ref flag);
        byte u8 = 255;
        writeStream.SerializeByte(ref u8);
        ushort u16 = 65535;
        writeStream.SerializeUInt16(ref u16);
        u32 = 0xFFFFFFFF;
        writeStream.SerializeUInt32(ref u32);
        ulong u64 = 0xFFFFFFFFFFFFFFFF;
        writeStream.SerializeUInt64(ref u64);
        int i32 = 55;
        writeStream.SerializeInt(ref i32, 10, 90);
        long i64 = -50000000001;
        writeStream.SerializeInt64(ref i64, -60000000000, 60000000000);
        float f32 = 100.0f;
        writeStream.SerializeFloat(ref f32);
        double f64 = 1000000000.0;
        writeStream.SerializeDouble(ref f64);

        writeStream.SerializeBytes(new byte[] { 1, 2, 3, 4, 5 });

        string str = "hello";
        writeStream.SerializeString(ref str, 10);

        string wstr = "привіт"; // "привіт"
        writeStream.SerializeWideString(ref wstr, 20);

        writeStream.SerializeAlign();

        TestContext context = new TestContext { Min = -10, Max = +10 };
        writeStream.Context = context;

        TestObject obj = new TestObject();
        obj.Init();
        writeStream.SerializeObject(obj);

        int relative = 105;
        writeStream.SerializeIntRelative(100, ref relative);

        Check(writeStream.Error == SerializeError.None, $"write failed: {writeStream.Error}");

        writeStream.Flush();

        // read back from the buffer
        ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
        ReadFunction(readStream);
    }

    private static void TestSerializeIntegerValidation()
    {
        // BitsRequired(0,5) is 3 bits, so a malicious packet can encode 6 or 7.
        // reads must reject values above max.
        byte[] buffer = new byte[8];

        WriteStream writeStream = new WriteStream(buffer);
        uint outOfRange = 7;
        writeStream.SerializeBits(ref outOfRange, 3);
        writeStream.Flush();

        ReadStream readStream = new ReadStream(buffer, 4);
        int value = 123; // sentinel: a failed read must not publish the smuggled value
        Check(!readStream.SerializeInt(ref value, 0, 5), "expected the read to fail");
        Check(readStream.Error == SerializeError.ValueOutOfRange,
            $"expected ValueOutOfRange to latch, got {readStream.Error}");
        Check(value == 123, $"a failed read must leave the value unmodified, got {value}");
    }

    private static void TestSerializeIntegerFullRange()
    {
        // ranges wider than 2^31 overflow if [min,max] arithmetic is done signed
        int[] values = { int.MinValue, int.MinValue + 1, -1, 0, +1, int.MaxValue - 1, int.MaxValue };

        foreach (int expected in values)
        {
            byte[] buffer = new byte[8];

            WriteStream writeStream = new WriteStream(buffer);
            int v = expected;
            Check(writeStream.SerializeInt(ref v, int.MinValue, int.MaxValue), "write failed");
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer);
            int value = 0;
            Check(readStream.SerializeInt(ref value, int.MinValue, int.MaxValue), "read failed");
            Check(value == expected, $"expected {expected}, got {value}");
        }

        {
            byte[] buffer = new byte[8];

            WriteStream writeStream = new WriteStream(buffer);
            int v = 1000000000;
            Check(writeStream.SerializeInt(ref v, -2000000000, 2000000000), "write failed");
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer);
            int value = 0;
            Check(readStream.SerializeInt(ref value, -2000000000, 2000000000), "read failed");
            Check(value == 1000000000, $"expected 1000000000, got {value}");
        }
    }

    private static void TestSerializeInt64FullRange()
    {
        // ranges wider than 2^63 overflow if [min,max] arithmetic is done signed
        {
            long[] values = { long.MinValue, long.MinValue + 1, -1, 0, +1, long.MaxValue - 1, long.MaxValue };

            foreach (long expected in values)
            {
                byte[] buffer = new byte[16];

                WriteStream writeStream = new WriteStream(buffer);
                long v = expected;
                Check(writeStream.SerializeInt64(ref v, long.MinValue, long.MaxValue), "write failed");
                writeStream.Flush();

                ReadStream readStream = new ReadStream(buffer);
                long value = 0;
                Check(readStream.SerializeInt64(ref value, long.MinValue, long.MaxValue), "read failed");
                Check(value == expected, $"expected {expected}, got {value}");
            }
        }

        // ranges spanning more than 32 bits use the two dword path
        {
            const long min = -5000000000, max = +5000000000;
            long[] values = { min, min + 1, -1, 0, +1, 4123456789, max - 1, max };

            foreach (long expected in values)
            {
                byte[] buffer = new byte[16];

                WriteStream writeStream = new WriteStream(buffer);
                long v = expected;
                Check(writeStream.SerializeInt64(ref v, min, max), "write failed");
                writeStream.Flush();

                ReadStream readStream = new ReadStream(buffer);
                long value = 0;
                Check(readStream.SerializeInt64(ref value, min, max), "read failed");
                Check(value == expected, $"expected {expected}, got {value}");
            }
        }

        // small ranges use the single dword path and the minimal number of bits
        {
            byte[] buffer = new byte[8];

            WriteStream writeStream = new WriteStream(buffer);
            long v = 55;
            Check(writeStream.SerializeInt64(ref v, -100, +100), "write failed");
            writeStream.Flush();

            Check(writeStream.BitsProcessed == 8, // BitsRequired64(-100,100) == 8, same as the 32 bit path
                $"expected 8 bits processed, got {writeStream.BitsProcessed}");

            ReadStream readStream = new ReadStream(buffer);
            long value = 0;
            Check(readStream.SerializeInt64(ref value, -100, +100), "read failed");
            Check(value == 55, $"expected 55, got {value}");
        }
    }

    private static void TestSerializeInt64Validation()
    {
        // a malicious packet can smuggle an out of range value into the bit headroom of
        // the two dword path. reads must reject it.
        {
            byte[] buffer = new byte[16];

            WriteStream writeStream = new WriteStream(buffer);
            const ulong outOfRange = (1UL << 34) + 5; // range [0, 2^34] is 35 bits, so values above 2^34 fit in the headroom
            uint lo = (uint)(outOfRange & 0xFFFFFFFF);
            uint hi = (uint)(outOfRange >> 32);
            writeStream.SerializeBits(ref lo, 32);
            writeStream.SerializeBits(ref hi, 3);
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer);
            long value = -987654321; // sentinel: a failed read must not publish the smuggled value
            Check(!readStream.SerializeInt64(ref value, 0, 1L << 34), "expected the read to fail");
            Check(readStream.Error == SerializeError.ValueOutOfRange,
                $"expected ValueOutOfRange, got {readStream.Error}");
            Check(value == -987654321, $"a failed read must leave the value unmodified, got {value}");
        }

        // reads past the end of the buffer must fail cleanly
        {
            byte[] buffer = new byte[4];

            ReadStream readStream = new ReadStream(buffer);
            long value = 424242; // sentinel
            Check(!readStream.SerializeInt64(ref value, long.MinValue, long.MaxValue), "expected the read to fail");
            Check(readStream.Error == SerializeError.Overflow, $"expected Overflow, got {readStream.Error}");
            Check(value == 424242, $"a failed read must leave the value unmodified, got {value}");
        }
    }

    private static void TestSerializeBytesValidation()
    {
        // byte counts past the end of the stream must be rejected
        byte[] buffer = new byte[16];

        {
            ReadStream readStream = new ReadStream(buffer);
            byte[] data = new byte[17];
            Check(!readStream.SerializeBytes(data), "expected the read to fail");
            Check(readStream.Error == SerializeError.Overflow, $"expected Overflow, got {readStream.Error}");
        }

        {
            ReadStream readStream = new ReadStream(buffer);
            byte[] data = new byte[1 << 20];
            Check(!readStream.SerializeBytes(data), "expected the read to fail");
            Check(readStream.Error == SerializeError.Overflow, $"expected Overflow, got {readStream.Error}");
        }
    }

    private static void TestStringValidation()
    {
        string[] values = { "", "a", "hello world!", "héllo wörld \U0001F600", new string('x', 255) };

        foreach (string expected in values)
        {
            byte[] buffer = new byte[512];

            WriteStream writeStream = new WriteStream(buffer);
            string v = expected;
            Check(writeStream.SerializeString(ref v, 256), "write failed");
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
            string value = "";
            Check(readStream.SerializeString(ref value, 256), "read failed");
            Check(value == expected, $"expected \"{expected}\", got \"{value}\"");
        }

        // a string that does not fit in the buffer size is a writer contract
        // violation, no longer rejected at runtime (serialize#52: writes are
        // trusted): it asserts in debug builds — test_write_contract_asserts
        // proves the assert fires — and is unchecked in release

        // refusal (serialize#8): string bytes that are not valid UTF-8 must be
        // rejected on read. INVERTED CHECK — if the reader tested
        // `SerializeCompat.Utf8IsValid(utf8)` instead of `!SerializeCompat.
        // Utf8IsValid(utf8)` (or skipped the call), 0xC3 0x28 would decode via
        // Encoding.UTF8.GetString into "�(" and be handed to the application
        // as if the peer had sent it.
        {
            byte[] buffer = new byte[8];
            WriteStream writeStream = new WriteStream(buffer);
            int length = 2;
            writeStream.SerializeInt(ref length, 0, 255);
            writeStream.SerializeBytes(new byte[] { 0xC3, 0x28 }); // truncated 2-byte sequence
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer);
            string value = "unchanged";
            Check(!readStream.SerializeString(ref value, 256), "expected the read to fail");
            Check(readStream.Error == SerializeError.InvalidString,
                $"expected InvalidString, got {readStream.Error}");
            Check(value == "unchanged", "a failed read must leave the value unmodified");
        }

        // refusal (serialize#8): an interior NUL is valid UTF-8 but must be rejected
        // on read — the two-lengths smuggling primitive: the wire length says 3, a
        // C-string consumer downstream (strlen/strcpy, a native plugin, a logging
        // sink) perceives length 1, and the bytes after the NUL ride along unseen.
        // INVERTED CHECK — if the reader tested `utf8.IndexOf((byte)0) < 0` instead
        // of `>= 0` (or skipped it), this read would succeed and value would be
        // "a\0b": value.Length == 3 while the perceived C-string length is 1.
        {
            byte[] buffer = new byte[8];
            WriteStream writeStream = new WriteStream(buffer);
            int length = 3;
            writeStream.SerializeInt(ref length, 0, 255);
            writeStream.SerializeBytes(new byte[] { 0x61, 0x00, 0x62 }); // "a", NUL, "b"
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer);
            string value = "unchanged";
            Check(!readStream.SerializeString(ref value, 256), "expected the read to fail");
            Check(readStream.Error == SerializeError.InvalidString,
                $"expected InvalidString, got {readStream.Error}");
            Check(value == "unchanged", "a failed read must leave the value unmodified");
        }
    }

    private static void TestWStringValidation()
    {
        // BMP and astral strings round trip; empty string round trips. The astral
        // string rides as surrogate pairs — one UTF-16 code unit per 32-bit group
        // (STANDARD.md, adopted 2026-08-15), four groups for the two emoji
        string[] values = { "", "мир", "привіт, світ!", "\U0001F600\U0001F680" };

        foreach (string expected in values)
        {
            byte[] buffer = new byte[512];

            WriteStream writeStream = new WriteStream(buffer);
            string v = expected;
            Check(writeStream.SerializeWideString(ref v, 64), "write failed");
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
            string value = "";
            Check(readStream.SerializeWideString(ref value, 64), "read failed");
            Check(value == expected, $"expected \"{expected}\", got \"{value}\"");
        }

        // the longest legal string (bufferSize-1 UTF-16 code units) round trips, and
        // the measure stream agrees with the write
        {
            const int bufferSize = 8;
            string longest = new string('a', bufferSize - 1);

            byte[] buffer = new byte[64];
            WriteStream writeStream = new WriteStream(buffer);
            string v = longest;
            Check(writeStream.SerializeWideString(ref v, bufferSize), "write failed");
            writeStream.Flush();

            MeasureStream measureStream = new MeasureStream();
            string m = longest;
            Check(measureStream.SerializeWideString(ref m, bufferSize), "measure failed");
            Check(measureStream.BitsProcessed == writeStream.BitsProcessed,
                $"measure {measureStream.BitsProcessed} != write {writeStream.BitsProcessed}");

            ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
            string value = "";
            Check(readStream.SerializeWideString(ref value, bufferSize), "read failed");
            Check(value == longest, "longest legal string did not round trip");

            // one code unit too many is a writer contract violation, no longer
            // rejected at runtime (serialize#52: writes are trusted): it asserts in
            // debug builds — test_write_contract_asserts proves the assert fires
        }

        // THE CONFORMANCE PIN: "a\U0001F600" in a wchar_t[8] buffer is exactly these
        // 13 bytes — 3-bit length 3 (UNITS: 0x0061, then the surrogate pair 0xD83D
        // 0xDE00), then three unaligned 32-bit groups. Byte-for-byte what
        // serialize.c (mas-bandwidth/serialize.c#12) and the C++
        // wstring-surrogate-boundary branch emit for L"a\U0001F600" on EVERY
        // wchar_t width; derived with a reference bit packer validated against the
        // STANDARD.md worked example. Never regenerate these.
        //
        // Before the code-unit fix this pin was doubly unreachable: the writer
        // emitted CODE POINTS (3-bit length 2, groups 0x0061 and 0x1F600 — the bytes
        // were 0A 03 00 00 00 B0 0F 00 00), and the reader REFUSED these very bytes
        // at its group check, `codePoint > 0x10FFFF || (codePoint >= 0xD800 &&
        // codePoint <= 0xDFFF)` → ValueOutOfRange on the 0xD83D group — so a valid
        // astral wstring from a conforming port could never be read at all.
        {
            byte[] astralWireBytes =
            {
                0x0B, 0x03, 0x00, 0x00, 0xE8, 0xC1, 0x06, 0x00, 0x00, 0xF0, 0x06,
                0x00, 0x00,
            };
            const string astral = "a\U0001F600";
            const int bufferSize = 8;

            // write side: the writer must emit exactly the conforming bytes
            byte[] buffer = new byte[64];
            WriteStream writeStream = new WriteStream(buffer);
            string v = astral;
            Check(writeStream.SerializeWideString(ref v, bufferSize), "write failed");
            writeStream.Flush();
            Check(writeStream.BytesProcessed == astralWireBytes.Length,
                $"expected {astralWireBytes.Length} bytes, got {writeStream.BytesProcessed}");
            Check(writeStream.Data.SequenceEqual(astralWireBytes),
                $"astral bytes mismatch:\nexpected {Convert.ToHexString(astralWireBytes)}\ngot      {Convert.ToHexString(writeStream.Data)}");

            // measure agrees: 3 bits of length + 3 * 32 bits of units = 99 bits
            MeasureStream measureStream = new MeasureStream();
            string m = astral;
            Check(measureStream.SerializeWideString(ref m, bufferSize), "measure failed");
            Check(measureStream.BitsProcessed == 99,
                $"expected 99 bits measured, got {measureStream.BitsProcessed}");

            // read side: the conforming bytes (as another port would send them) must
            // decode — the pair recombines into the astral character
            ReadStream readStream = new ReadStream(astralWireBytes);
            string value = "";
            Check(readStream.SerializeWideString(ref value, bufferSize),
                $"read of the conforming astral vector failed: {readStream.Error}");
            Check(value == astral, $"expected \"{astral}\", got \"{value}\"");
        }

        // a group above 0xFFFF is not a UTF-16 code unit and must be rejected on
        // read — including 0x10000..0x10FFFF, the OLD format's astral code point
        // groups: under the code-unit format (STANDARD.md, adopted 2026-08-15) an
        // astral character is a surrogate pair, never a single group. This is also
        // the C# analog of the C 2-byte wchar_t path: char cannot hold the value,
        // so fail rather than truncate
        uint[] invalidUnits = { 0x10000, 0x10FFFF, 0x110000, 0xFFFFFFFF };
        foreach (uint invalidUnit in invalidUnits)
        {
            byte[] buffer = new byte[16];

            WriteStream writeStream = new WriteStream(buffer);
            int length = 1;
            writeStream.SerializeInt(ref length, 0, 63); // length prefix for bufferSize 64
            uint u = invalidUnit;
            writeStream.SerializeBits(ref u, 32);
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer);
            string value = "unchanged"; // sentinel: a failed read must not publish a partial string
            Check(!readStream.SerializeWideString(ref value, 64), $"unit {invalidUnit:x}: expected the read to fail");
            Check(readStream.Error == SerializeError.ValueOutOfRange,
                $"unit {invalidUnit:x}: expected ValueOutOfRange, got {readStream.Error}");
            Check(value == "unchanged", "a failed read must leave the value unmodified");
        }

        // refusal (serialize#8): unpaired or invalid surrogates must be rejected on
        // read — an unpaired surrogate is a refusal, not a pass-through. INVERTED
        // CHECK — if the reader stored lone surrogates as they arrived instead of
        // refusing (dropping the pendingHigh/lone-low branches), each of these would
        // succeed and publish an ill-formed .NET string: one that
        // char.IsSurrogate flags, that Encoding.UTF8.GetBytes silently rewrites to
        // U+FFFD, and that a conforming peer would itself refuse if echoed back.
        {
            uint[][] unpairedShapes =
            {
                new uint[] { 0xD83D },                    // lone high surrogate
                new uint[] { 0xD83D, 0x0041 },            // high followed by a BMP unit
                new uint[] { 0xD83D, 0xD83D },            // high followed by another high
                new uint[] { 0xDE00 },                    // lone low surrogate
                new uint[] { 0x0041, 0xDE00 },            // low with no high before it
                new uint[] { 0xD83D, 0xDE00, 0xD83D },    // valid pair, then ends inside a pair
            };
            foreach (uint[] units in unpairedShapes)
            {
                byte[] buffer = new byte[32];

                WriteStream writeStream = new WriteStream(buffer);
                int length = units.Length;
                writeStream.SerializeInt(ref length, 0, 63); // length prefix for bufferSize 64
                foreach (uint unit in units)
                {
                    uint u = unit;
                    writeStream.SerializeBits(ref u, 32);
                }
                writeStream.Flush();

                ReadStream readStream = new ReadStream(buffer);
                string value = "unchanged";
                string shape = string.Join(" ", Array.ConvertAll(units, x => x.ToString("x4")));
                Check(!readStream.SerializeWideString(ref value, 64), $"units [{shape}]: expected the read to fail");
                Check(readStream.Error == SerializeError.InvalidString,
                    $"units [{shape}]: expected InvalidString, got {readStream.Error}");
                Check(value == "unchanged", "a failed read must leave the value unmodified");
            }
        }

        // refusal (serialize#8): an interior NUL unit must be rejected on read — the
        // wide twin of the narrow smuggling primitive: wire length 3 versus the
        // length 1 a wcslen consumer perceives. INVERTED CHECK — if the reader
        // tested `unit != 0` instead of `unit == 0` (or skipped it), this read would
        // succeed and publish "a\0b" with value.Length == 3.
        {
            byte[] buffer = new byte[32];

            WriteStream writeStream = new WriteStream(buffer);
            int length = 3;
            writeStream.SerializeInt(ref length, 0, 63); // length prefix for bufferSize 64
            uint[] units = { 0x0061, 0x0000, 0x0062 }; // "a", NUL, "b"
            foreach (uint unit in units)
            {
                uint u = unit;
                writeStream.SerializeBits(ref u, 32);
            }
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer);
            string value = "unchanged";
            Check(!readStream.SerializeWideString(ref value, 64), "expected the read to fail");
            Check(readStream.Error == SerializeError.InvalidString,
                $"expected InvalidString, got {readStream.Error}");
            Check(value == "unchanged", "a failed read must leave the value unmodified");
        }
    }

    private static void TestIntRelativeValidation()
    {
        // the 32 bit fallback must reject values that violate the previous < current contract
        {
            byte[] buffer = new byte[8];

            WriteStream writeStream = new WriteStream(buffer);
            uint sixFalseBools = 0;
            writeStream.SerializeBits(ref sixFalseBools, 6);
            uint badCurrent = 50;
            writeStream.SerializeBits(ref badCurrent, 32);
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer);
            int current = 777; // sentinel: a failed read must not publish the bad value
            Check(!readStream.SerializeIntRelative(100, ref current), "expected the read to fail");
            Check(readStream.Error == SerializeError.ValueOutOfRange,
                $"expected ValueOutOfRange, got {readStream.Error}");
            Check(current == 777, $"a failed read must leave the value unmodified, got {current}");
        }

        // a legitimate fallback round trip must still succeed
        {
            byte[] buffer = new byte[8];

            WriteStream writeStream = new WriteStream(buffer);
            int written = 100000;
            Check(writeStream.SerializeIntRelative(100, ref written), "write failed");
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer);
            int current = 0;
            Check(readStream.SerializeIntRelative(100, ref current), "read failed");
            Check(current == written, $"expected {written}, got {current}");
        }

        // gaps wider than 2^31 overflow if the difference is computed in signed arithmetic
        {
            byte[] buffer = new byte[8];

            WriteStream writeStream = new WriteStream(buffer);
            int written = int.MaxValue;
            Check(writeStream.SerializeIntRelative(-1000, ref written), "write failed");
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer);
            int current = 0;
            Check(readStream.SerializeIntRelative(-1000, ref current), "read failed");
            Check(current == written, $"expected {written}, got {current}");
        }

        // read side reconstructs current = previous + difference; a large previous must
        // wrap in the unsigned domain rather than overflow
        {
            int[] differences = { 1, 5 }; // 1 exercises the one bit branch, 5 exercises a bucket branch

            foreach (int difference in differences)
            {
                byte[] buffer = new byte[8];

                WriteStream writeStream = new WriteStream(buffer);
                int written = 10 + difference;
                Check(writeStream.SerializeIntRelative(10, ref written), "write failed");
                writeStream.Flush();

                ReadStream readStream = new ReadStream(buffer);
                int current = 0;
                Check(readStream.SerializeIntRelative(int.MaxValue, ref current), "read failed");
                int expected = (int)((uint)int.MaxValue + (uint)difference);
                Check(current == expected, $"expected {expected}, got {current}");
            }
        }
    }

    private static void TestCompressedFloatValidation()
    {
        // a malicious packet can encode integer values above maxIntegerValue in the bit
        // headroom. reads must reject them.
        {
            byte[] buffer = new byte[8];

            WriteStream writeStream = new WriteStream(buffer);
            uint outOfRange = 1023; // maxIntegerValue is 1000 for [0,10] at res 0.01 -> 10 bits
            writeStream.SerializeBits(ref outOfRange, 10);
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer);
            float value = -42.5f; // sentinel: a failed read must not publish a decoded value
            Check(!readStream.SerializeCompressedFloat(ref value, 0, 10, 0.01f), "expected the read to fail");
            Check(readStream.Error == SerializeError.ValueOutOfRange,
                $"expected ValueOutOfRange, got {readStream.Error}");
            Check(value == -42.5f, $"a failed read must leave the value unmodified, got {value}");
        }

        // huge delta / resolution ratios must not overflow the uint quantization range
        {
            byte[] buffer = new byte[8];

            WriteStream writeStream = new WriteStream(buffer);
            float written = 5000000000.0f;
            Check(writeStream.SerializeCompressedFloat(ref written, 0, 10000000000.0f, 1.0f), "write failed");
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer);
            float value = 0;
            Check(readStream.SerializeCompressedFloat(ref value, 0, 10000000000.0f, 1.0f), "read failed");
            Check(Math.Abs(value - written) <= 4096.0, $"expected {written} within 4096, got {value}");
        }

        // sending NaN or infinity through compressed float is NON-CONFORMING (ruled
        // 2026-08-15: "attempting to send NaN or INF or anything else through
        // compressed float is non-conforming and should assert out on write too"):
        // it asserts on write in debug builds — test_write_contract_asserts proves
        // both the NaN and infinity asserts fire — and in release the quantizer's
        // clamp still forces non-finite values into range rather than corrupting
        // the stream. The read path is untouched: a decoded value from a conforming
        // declaration is always in [min,max].
    }

    private static void TestCompressedFloatQuantizationBoundaries()
    {
        // The write-side quantization is normatively float32 with TWO roundings: the
        // product rounds before 0.5f is added, the sum rounds before the floor
        // (SerializeInternal.QuantizeCompressedFloat). These values sit on the
        // boundaries where the two evaluations ECMA-334 would otherwise permit
        // diverge: a fused multiply-add rounds ONCE and writes 0 for 0.005, and
        // double-widened arithmetic writes 0 / 10 / 999 for 0.005 / 0.105 / 9.995.
        // 2.5 and 5.0 land exactly on a quantum, where every evaluation agrees --
        // they anchor the encoding itself, so a failure here isolates the arithmetic.
        (float value, uint expected)[] cases =
        {
            (0.0f, 0),
            (0.005f, 1),
            (0.025f, 3),
            (0.105f, 11),
            (2.5f, 250),
            (5.0f, 500),
            (9.995f, 1000),
            (10.0f, 1000),
        };

        foreach ((float value, uint expected) in cases)
        {
            // the stream write path
            {
                byte[] buffer = new byte[8];
                WriteStream writeStream = new WriteStream(buffer);
                float written = value;
                Check(writeStream.SerializeCompressedFloat(ref written, 0, 10, 0.01f), "write failed");
                writeStream.Flush();

                ReadStream readStream = new ReadStream(buffer);
                uint integer = 0;
                Check(readStream.SerializeBits(ref integer, 10), "read failed"); // [0,10] at res 0.01 -> 10 bits
                Check(integer == expected, $"stream: {value} must quantize to {expected}, got {integer}");
            }

            // the batch write path: the quantizer's other call site
            {
                byte[] buffer = new byte[8];
                WriteStream writeStream = new WriteStream(buffer);
                WriteBatch batch = writeStream.BeginBatch();
                float written = value;
                Check(batch.SerializeCompressedFloat(ref written, 0, 10, 0.01f), "batch write failed");
                batch.End();
                writeStream.Flush();

                ReadStream readStream = new ReadStream(buffer);
                uint integer = 0;
                Check(readStream.SerializeBits(ref integer, 10), "read failed");
                Check(integer == expected, $"batch: {value} must quantize to {expected}, got {integer}");
            }
        }
    }

    private static void TestGoldenWireFormat()
    {
        // the golden float is the literal 3.1415926f, never MathF.PI
        Check(BitConverter.SingleToUInt32Bits(3.1415926f) == 0x40490FDA, "golden float literal has the wrong bits");

        // write side: serializing the golden values must produce exactly the golden bytes
        {
            byte[] buffer = new byte[256];
            WriteStream stream = new WriteStream(buffer);
            GoldenWireData data = GoldenWireData.Init();
            Check(GoldenWireData.Serialize(stream, data), $"write failed: {stream.Error}");
            stream.Flush();
            Check(stream.BytesProcessed == GoldenWireBytes.Length,
                $"expected {GoldenWireBytes.Length} bytes, got {stream.BytesProcessed}");
            Check(stream.Data.SequenceEqual(GoldenWireBytes),
                $"golden bytes mismatch:\nexpected {Convert.ToHexString(GoldenWireBytes)}\ngot      {Convert.ToHexString(stream.Data)}");
        }

        // read side: the golden bytes must decode to the expected values, on every
        // platform, forever
        {
            ReadStream stream = new ReadStream(GoldenWireBytes);
            GoldenWireData data = new GoldenWireData();
            Check(GoldenWireData.Serialize(stream, data), $"read failed: {stream.Error}");

            GoldenWireData expected = GoldenWireData.Init();
            Check(Math.Abs(data.CompressedFloatValue - expected.CompressedFloatValue) <= 0.01,
                $"compressed float mismatch: expected {expected.CompressedFloatValue}, got {data.CompressedFloatValue}");
            Check(data.Bits4 == expected.Bits4 && data.Bits11 == expected.Bits11
                && data.Bits24 == expected.Bits24 && data.Bits32 == expected.Bits32
                && data.IntSmall == expected.IntSmall && data.IntFull == expected.IntFull
                && data.Flag == expected.Flag
                && data.FloatValue == expected.FloatValue
                && data.DoubleValue == expected.DoubleValue
                && data.UInt8Value == expected.UInt8Value
                && data.UInt16Value == expected.UInt16Value
                && data.UInt32Value == expected.UInt32Value
                && data.UInt64Value == expected.UInt64Value
                && data.RelativeNear == expected.RelativeNear
                && data.RelativeFar == expected.RelativeFar
                && data.Bytes.AsSpan().SequenceEqual(expected.Bytes)
                && data.Str == expected.Str
                && data.WStr == expected.WStr,
                "golden decode mismatch");
        }
    }

    private static void TestExtendedWireFormat()
    {
        // write side: the extended sequence must produce exactly the pinned bytes, so
        // the 64 bit wire paths (bits64 > 32, int64 full range, int64 two dword) and
        // the FMA boundary compressed float are defended on every test run, not only
        // when the interop gate happens to be executed
        {
            byte[] buffer = new byte[256];
            WriteStream stream = new WriteStream(buffer);
            ExtendedWireData data = ExtendedWireData.Init();
            Check(ExtendedWireData.Serialize(stream, data), $"write failed: {stream.Error}");
            stream.Flush();
            Check(stream.BytesProcessed == ExtendedWireBytes.Length,
                $"expected {ExtendedWireBytes.Length} bytes, got {stream.BytesProcessed}");
            Check(stream.Data.SequenceEqual(ExtendedWireBytes),
                $"extended bytes mismatch:\nexpected {Convert.ToHexString(ExtendedWireBytes)}\ngot      {Convert.ToHexString(stream.Data)}");
        }

        // read side: the pinned bytes must decode to the expected values
        {
            ReadStream stream = new ReadStream(ExtendedWireBytes);
            ExtendedWireData data = new ExtendedWireData();
            Check(ExtendedWireData.Serialize(stream, data), $"read failed: {stream.Error}");

            ExtendedWireData expected = ExtendedWireData.Init();
            Check(data.Bits33 == expected.Bits33, $"bits33 mismatch: got {data.Bits33:x}");
            Check(data.Int64Full == expected.Int64Full, $"int64 full mismatch: got {data.Int64Full}");
            Check(data.Int64Range == expected.Int64Range, $"int64 range mismatch: got {data.Int64Range}");
            // 0.005 quantizes to integer 1, which decodes to 0.01: within the resolution
            Check(Math.Abs(data.FmaBoundaryFloat - expected.FmaBoundaryFloat) <= 0.01f,
                $"fma boundary float mismatch: got {data.FmaBoundaryFloat}");
            // the pinned bytes carry quantized integer 1 (strict evaluation), not 0
            // (fused): integer 0 would decode to 0.0, integer 1 decodes to ~0.01
            Check(data.FmaBoundaryFloat > 0.005f,
                $"expected the strict IEEE quantization (~0.01), got {data.FmaBoundaryFloat}");
        }
    }

    // Adaptation of the C++ test_unaligned_writer: a C# byte[] cannot start at an
    // arbitrary offset of its allocation, and the span-based qword stores are
    // unaligned-safe by construction, so instead this exercises the WriteBytes
    // head/middle/tail store paths at every byte phase within a qword.
    private static void TestWriteBytesQwordPhases()
    {
        for (int phase = 0; phase < 8; phase++)
        {
            byte[] buffer = new byte[256];

            byte[] data = new byte[13];
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = (byte)(i * 47 + phase);
            }

            WriteStream writeStream = new WriteStream(buffer);
            for (int i = 0; i < phase; i++)
            {
                uint pad = 0xAA;
                writeStream.SerializeBits(ref pad, 8);
            }
            uint a = 0x12345678;
            writeStream.SerializeBits(ref a, 32);
            uint b = 123;
            writeStream.SerializeBits(ref b, 7);
            writeStream.SerializeBytes(data);
            uint c = 0xDEADBEEF;
            writeStream.SerializeBits(ref c, 32);
            Check(writeStream.Error == SerializeError.None, $"phase {phase}: write failed");
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
            for (int i = 0; i < phase; i++)
            {
                uint pad = 0;
                Check(readStream.SerializeBits(ref pad, 8) && pad == 0xAA, $"phase {phase}: bad pad byte");
            }
            uint ra = 0, rb = 0, rc = 0;
            byte[] readData = new byte[data.Length];
            Check(readStream.SerializeBits(ref ra, 32), "read failed");
            Check(readStream.SerializeBits(ref rb, 7), "read failed");
            Check(readStream.SerializeBytes(readData), "read failed");
            Check(readStream.SerializeBits(ref rc, 32), "read failed");
            Check(ra == a && rb == b && rc == c && readData.AsSpan().SequenceEqual(data),
                $"phase {phase}: read values do not match written values");
        }
    }

    private static void TestWriteTrusted()
    {
        // Writes are trusted (STANDARD.md doctrine; enacted for C# per serialize#52,
        // the ruling verbatim: "Yes, then let C# match C++ too"): the write path
        // performs no overflow or range checking in release builds. Exceeding the
        // buffer is a writer contract violation, caught by Debug.Assert in debug
        // builds (test_write_contract_asserts proves it fires). What the library
        // still owes a conforming writer is exact capacity accounting, so the
        // caller can preflight instead of relying on a rejection that no longer
        // exists. This test replaces test_write_overflow, which pinned the removed
        // write-side Overflow latch.
        byte[] buffer = new byte[8];

        WriteStream stream = new WriteStream(buffer);
        uint v = 1;
        Check(stream.BitsAvailable == 64, $"expected 64 bits available, got {stream.BitsAvailable}");
        Check(stream.SerializeBits(ref v, 32), "write failed");
        Check(stream.SerializeBits(ref v, 32), "write failed");
        Check(stream.BitsAvailable == 0, "a full buffer must report zero bits available");
        Check(stream.Ok, "filling the buffer exactly is not an error");
        stream.Flush();
        Check(stream.BitsProcessed == 64, $"expected 64 bits processed, got {stream.BitsProcessed}");

        // the write-side latch: a user abort through SerializeObject latches the
        // error, SerializeObject returns false, and the first error wins. The
        // per-field write spine carries NO sticky branch (the 2026-08-16 check-model
        // audit: the branch was this port's invention — the C++ write path has no
        // per-field error check): later field calls stay trusted, keep writing and
        // keep returning true, and the caller discards the packet by checking Error
        // once at the end. SerializeObject still refuses to descend into an object
        // after a latched error.
        WriteStream aborted = new WriteStream(new byte[8]);
        uint a = 7;
        Check(aborted.SerializeBits(ref a, 8), "write failed");
        Check(!aborted.SerializeObject(new FailingObject()), "expected the user abort to fail");
        Check(aborted.Error == SerializeError.ValueOutOfRange,
            $"expected ValueOutOfRange from the abort, got {aborted.Error}");
        bool flag = true;
        Check(aborted.SerializeBool(ref flag), "field writes after an abort stay trusted and branch-free");
        Check(aborted.BitsProcessed == 9, "trusted writes advance the stream even after a latched abort");
        Check(!aborted.SerializeObject(new FailingObject()), "SerializeObject stays guarded after a latch");
        Check(!aborted.Ok, "Ok must be false once an error is latched");
        Check(aborted.Error == SerializeError.ValueOutOfRange, "the first latched error must win");
    }

#if DEBUG
    /// <summary>Thrown by the throwing trace listener so a fired Debug.Assert
    /// surfaces as a catchable exception instead of terminating the process.</summary>
    private sealed class AssertFiredException : Exception
    {
        public AssertFiredException(string? message)
            : base(message)
        {
        }
    }

    private sealed class ThrowingTraceListener : TraceListener
    {
        public override void Write(string? message)
        {
        }

        public override void WriteLine(string? message)
        {
        }

        public override void Fail(string? message)
        {
            throw new AssertFiredException(message);
        }

        public override void Fail(string? message, string? detailMessage)
        {
            throw new AssertFiredException(message);
        }
    }

    /// <summary>Runs the action with a trace listener that turns a fired
    /// Debug.Assert into an exception; returns true if an assert fired.</summary>
    private static bool AssertFires(Action action)
    {
        TraceListener[] saved = new TraceListener[Trace.Listeners.Count];
        Trace.Listeners.CopyTo(saved, 0);
        Trace.Listeners.Clear();
        Trace.Listeners.Add(new ThrowingTraceListener());
        try
        {
            action();
            return false;
        }
        catch (AssertFiredException)
        {
            return true;
        }
        finally
        {
            Trace.Listeners.Clear();
            Trace.Listeners.AddRange(saved);
        }
    }

    private static void TestWriteContractAsserts()
    {
        // The proof that a deliberately-invalid write still asserts: every write-side
        // contract that used to be a release check (removed per serialize#52) fires
        // its Debug.Assert in a debug build. Ordered to cover each converted family:
        // value range, buffer overflow (stream and batch), fixed point offset,
        // string and wstring length, int relative ordering, the measure stream, and
        // the two compressed float rulings (non-finite value, non-finite declaration).

        // a fully conforming write sequence must not assert — surrogate PAIRS
        // included: a well-formed astral wstring is valid UTF-16, not a violation
        Check(!AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[64]);
            int i = 5;
            stream.SerializeInt(ref i, 0, 100);
            string s = "ok";
            stream.SerializeString(ref s, 16);
            string astral = "a\U0001F600";
            stream.SerializeWideString(ref astral, 8);
            float f = 2.5f;
            stream.SerializeCompressedFloat(ref f, 0, 10, 0.01f);
            stream.Flush();
        }), "a conforming write sequence must not assert");

        // value out of range
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            int outOfRange = 999;
            stream.SerializeInt(ref outOfRange, 0, 5);
        }), "an out of range write must assert in debug");

        // write past the end of the buffer
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            uint v = 1;
            stream.SerializeBits(ref v, 32);
            stream.SerializeBits(ref v, 32);
            stream.SerializeBits(ref v, 1); // the 65th bit
        }), "a write past the end of the buffer must assert in debug");

        // batch write past the end of the buffer
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            WriteBatch batch = stream.BeginBatch();
            ulong v = ~0ul;
            batch.SerializeBits64(ref v, 64);
            ulong w = 1;
            batch.SerializeBits64(ref w, 64); // past the end
            batch.End();
        }), "a batch write past the end of the buffer must assert in debug");

        // fixed point raw value outside the declared bounds
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[16]);
            long raw = 200000L << 16; // 200000.0 in Q48.16, bounds ±100000
            stream.SerializeFixed(ref raw, 48, 16, -100000, +100000);
        }), "an out of range fixed point write must assert in debug");

        // string that does not fit its buffer size
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[512]);
            string tooLong = new string('x', 256);
            stream.SerializeString(ref tooLong, 256);
        }), "an oversized string write must assert in debug");

        // wide string that does not fit its buffer size
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[512]);
            string tooLong = new string('a', 8);
            stream.SerializeWideString(ref tooLong, 8);
        }), "an oversized wide string write must assert in debug");

        // wide string payload that is not well-formed UTF-16: an unpaired surrogate
        // is a writer contract violation (STANDARD.md, adopted 2026-08-15), asserted
        // in debug; conforming READERS refuse it in every build mode
        // (test_wstring_validation pins the refusal)
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[512]);
            string unpaired = "a\uD83Db"; // high surrogate with no low half
            stream.SerializeWideString(ref unpaired, 8);
        }), "an ill-formed UTF-16 wide string write must assert in debug");

        // int relative with previous >= current
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            int current = 50;
            stream.SerializeIntRelative(100, ref current);
        }), "an unordered int relative write must assert in debug");

        // the measure stream shares the writer's contract
        Check(AssertFires(() =>
        {
            MeasureStream measure = new MeasureStream();
            int outOfRange = 999;
            measure.SerializeInt(ref outOfRange, 0, 5);
        }), "an out of range measure must assert in debug");

        // sending NaN through compressed float is non-conforming (ruled 2026-08-15:
        // "attempting to send NaN or INF or anything else through compressed float
        // is non-conforming and should assert out on write too")
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            float nan = BitConverter.UInt32BitsToSingle(0x7fc00000); // quiet NaN
            stream.SerializeCompressedFloat(ref nan, 0, 10, 0.01f);
        }), "a NaN compressed float write must assert in debug");

        // ...and infinity, through the batch write path (the quantizer is shared)
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            WriteBatch batch = stream.BeginBatch();
            float inf = float.PositiveInfinity;
            batch.SerializeCompressedFloat(ref inf, 0, 10, 0.01f);
            batch.End();
        }), "an infinite compressed float batch write must assert in debug");

        // a compressed float declaration whose delta overflows to infinity is
        // non-conforming (ruled 2026-08-15: "it's non-conforming") and asserts at
        // the param site
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            float v = 0.0f;
            stream.SerializeCompressedFloat(ref v, -3.4e38f, +3.4e38f, 1.0f);
        }), "a non-finite compressed float declaration must assert in debug");
    }

    private static void TestApiMisuseAsserts()
    {
        // The 2026-08-16 six-language check-model audit: trusted call-site parameter
        // validation (bits counts, min/max ordering, buffer sizes, Q formats) and the
        // raw bitpacker API's checks were release throws — this port's invention,
        // where the C++ library compiles serialize_assert out. They are Debug.Assert
        // on every stream now. One representative per converted class, read side
        // included: an argument is the caller's contract on every stream.

        // bits out of [1,32], write stream
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            uint v = 0;
            stream.SerializeBits(ref v, 0);
        }), "bits below range must assert in debug (write)");

        // bits out of [1,32], READ stream: same contract, same assert
        Check(AssertFires(() =>
        {
            ReadStream stream = new ReadStream(new byte[8]);
            uint v = 0;
            stream.SerializeBits(ref v, 33);
        }), "bits above range must assert in debug (read)");

        // bits out of [1,64], batch
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            WriteBatch batch = stream.BeginBatch();
            ulong v = 0;
            batch.SerializeBits64(ref v, 65);
            batch.End();
        }), "bits64 above range must assert in debug (batch)");

        // min > max on the read stream (the write-side twin is in
        // test_degenerate_range)
        Check(AssertFires(() =>
        {
            ReadStream stream = new ReadStream(new byte[8]);
            int v = 0;
            stream.SerializeInt(ref v, 10, 5);
        }), "min > max must assert in debug (read)");

        // string buffer size below 2
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            string s = "";
            stream.SerializeString(ref s, 1);
        }), "a string buffer size below 2 must assert in debug");

        // fixed point Q format that does not fill its storage
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            long v = 0;
            stream.SerializeFixed(ref v, 16, 8, 0, 100); // 16 + 8 != 64
        }), "a Q format that does not fill its storage must assert in debug");

        // compressed float with an invalid declaration (min >= max)
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            float v = 0.0f;
            stream.SerializeCompressedFloat(ref v, 10, 0, 0.01f);
        }), "an inverted compressed float declaration must assert in debug");

        // the raw bitpacker API: width, capacity and construction contracts
        Check(AssertFires(() =>
        {
            BitWriter writer = new BitWriter(new byte[8]);
            writer.WriteBits(0, 33);
        }), "a raw bitpacker width violation must assert in debug");

        Check(AssertFires(() =>
        {
            BitWriter writer = new BitWriter(new byte[8]);
            writer.WriteBits(0, 32);
            writer.WriteBits(0, 32);
            writer.WriteBits(0, 1); // the 65th bit
        }), "a raw bitpacker write past the end must assert in debug");

        Check(AssertFires(() =>
        {
            _ = new BitWriter(new byte[12]); // not a multiple of 8
        }), "a misaligned writer buffer must assert in debug");

        Check(AssertFires(() =>
        {
            _ = new BitReader(new byte[8], 9); // bytes past the buffer
        }), "reader bytes past the buffer must assert in debug");

        Check(AssertFires(() =>
        {
            BitReader reader = new BitReader(new byte[8]);
            reader.ReadBits(1);
            reader.ReadBits(32);
            reader.ReadBits(32); // 65 bits: past the end
        }), "a raw bitpacker read past the end must assert in debug");
    }
#endif // DEBUG

#if !DEBUG
    private static void TestApiMisuseChecksAbsentInRelease()
    {
        // The release half of the audit's proof: the misuse checks above are ABSENT
        // from the release binary — the calls complete without throwing, the results
        // are garbage-in-garbage-out, and memory safety is the runtime's own bounds
        // checks (the named language floor). Deterministic representatives only.

        // min > max: completes, GIGO (the write encodes against a wrapped range)
        {
            WriteStream stream = new WriteStream(new byte[64]);
            int v = 0;
            Check(stream.SerializeInt(ref v, 10, 5), "release: min > max write completes");
            stream.Flush();
            ReadStream read = new ReadStream(new byte[64]);
            int r = 0;
            Check(read.SerializeInt(ref r, 10, 5), "release: min > max read completes");
        }

        // bits = 0: completes as a zero-width write, no throw
        {
            WriteStream stream = new WriteStream(new byte[8]);
            uint v = 7;
            Check(stream.SerializeBits(ref v, 0), "release: zero-width write completes");
        }

        // string buffer size below 2: completes, no throw
        {
            WriteStream stream = new WriteStream(new byte[8]);
            string s = "";
            Check(stream.SerializeString(ref s, 1), "release: undersized string buffer completes");
        }
    }
#endif // !DEBUG

    private static void TestAlignValidation()
    {
        // nonzero padding bits mean the read and write serialize functions don't match
        byte[] buffer = new byte[8];
        buffer[0] = 0xFF;

        ReadStream stream = new ReadStream(buffer);
        uint v = 0;
        Check(stream.SerializeBits(ref v, 3), "read failed");
        Check(!stream.SerializeAlign(), "expected the align to fail");
        Check(stream.Error == SerializeError.Align, $"expected Align, got {stream.Error}");
    }

    private static void TestMeasureStream()
    {
        // measuring an object must never underestimate the bits required to write it
        TestContext context = new TestContext { Min = -10, Max = +10 };

        WriteStream writeStream = new WriteStream(new byte[1024]);
        writeStream.Context = context;
        TestObject writeObject = new TestObject();
        writeObject.Init();
        Check(writeObject.Serialize(writeStream), "write failed");

        MeasureStream measureStream = new MeasureStream();
        measureStream.Context = context;
        TestObject measureObject = new TestObject();
        measureObject.Init();
        Check(measureObject.Serialize(measureStream), "measure failed");

        Check(measureStream.BitsProcessed >= writeStream.BitsProcessed,
            $"measure underestimated: measured {measureStream.BitsProcessed} bits, wrote {writeStream.BitsProcessed} bits");

        // without aligns the measurement is exact
        measureStream.Reset();
        writeStream.Reset(new byte[1024]);

        foreach (IBitStream stream in new IBitStream[] { measureStream, writeStream })
        {
            uint v = 123;
            stream.SerializeBits(ref v, 23);
            int i = -55;
            stream.SerializeInt(ref i, -100, +100);
            ulong u = 0x123456789ABCDEF0;
            stream.SerializeUInt64(ref u);
            float f = 1.5f;
            stream.SerializeCompressedFloat(ref f, 0, 10, 0.01f);
            int relative = 105;
            stream.SerializeIntRelative(100, ref relative);
            UInt128Value u128 = ((UInt128Value)0x0123456789ABCDEF << 64) | 0xFEDCBA9876543210;
            stream.SerializeUInt128(ref u128);
            Int128Value i128 = -((Int128Value)1 << 99);
            stream.SerializeInt128(ref i128, -((Int128Value)1 << 100), (Int128Value)1 << 100);
            long fixedValue = -(54321L * 65536 + 12345);
            stream.SerializeFixed(ref fixedValue, 48, 16, -100000, +100000);
            Int128Value fixedWide = -(98765432109L * 65536 + 4321);
            stream.SerializeFixed(ref fixedWide, 112, 16, -144115188075855872, +144115188075855872);
            Check(stream.Error == SerializeError.None, "serialize failed");
        }

        Check(measureStream.BitsProcessed == writeStream.BitsProcessed,
            $"expected exact measurement: measured {measureStream.BitsProcessed} bits, wrote {writeStream.BitsProcessed} bits");
    }

    private static void TestContinue()
    {
        // round trip a variable length sequence with a continuation bit per element
        byte[] buffer = new byte[64];
        uint[] items = { 10, 20, 30, 40, 50 };

        WriteStream writeStream = new WriteStream(buffer);
        {
            int i = 0;
            bool hasNext = items.Length > 0;
            while (SerializeUtil.Continue(writeStream, ref hasNext))
            {
                writeStream.SerializeBits(ref items[i], 8);
                i++;
                hasNext = i < items.Length;
            }
        }
        Check(writeStream.Error == SerializeError.None, "write failed");
        writeStream.Flush();

        ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
        System.Collections.Generic.List<uint> read = new System.Collections.Generic.List<uint>();
        {
            bool hasNext = true;
            while (SerializeUtil.Continue(readStream, ref hasNext))
            {
                uint item = 0;
                readStream.SerializeBits(ref item, 8);
                read.Add(item);
            }
        }
        Check(readStream.Error == SerializeError.None, "read failed");
        Check(read.Count == items.Length, $"expected {items.Length} items, got {read.Count}");
        for (int i = 0; i < items.Length; i++)
        {
            Check(read[i] == items[i], $"item {i}: expected {items[i]}, got {read[i]}");
        }
    }

    private static void TestUntil()
    {
        // round trip a variable length sequence terminated by a done bit: a false bit
        // before each element and a true bit at the end
        byte[] buffer = new byte[64];
        uint[] items = { 10, 20, 30, 40, 50 };

        WriteStream writeStream = new WriteStream(buffer);
        {
            int i = 0;
            bool done = items.Length == 0;
            while (SerializeUtil.Until(writeStream, ref done))
            {
                writeStream.SerializeBits(ref items[i], 8);
                i++;
                done = i == items.Length;
            }
        }
        Check(writeStream.Error == SerializeError.None, "write failed");
        writeStream.Flush();

        // one sentinel bit per element plus the terminating bit
        long expectedBits = (long)items.Length * 9 + 1;
        Check(writeStream.BitsProcessed == expectedBits,
            $"expected {expectedBits} bits, got {writeStream.BitsProcessed}");

        ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
        System.Collections.Generic.List<uint> read = new System.Collections.Generic.List<uint>();
        {
            bool done = false;
            while (SerializeUtil.Until(readStream, ref done))
            {
                uint item = 0;
                readStream.SerializeBits(ref item, 8);
                read.Add(item);
            }
        }
        Check(readStream.Error == SerializeError.None, "read failed");
        Check(read.Count == items.Length, $"expected {items.Length} items, got {read.Count}");
        for (int i = 0; i < items.Length; i++)
        {
            Check(read[i] == items[i], $"item {i}: expected {items[i]}, got {read[i]}");
        }

        // an empty sequence is a single terminating bit
        writeStream.Reset(buffer);
        {
            bool done = true;
            while (SerializeUtil.Until(writeStream, ref done))
            {
                Check(false, "loop body must not run for an empty sequence");
            }
        }
        Check(writeStream.BitsProcessed == 1, $"expected 1 bit for an empty sequence, got {writeStream.BitsProcessed}");
    }

    private static void TestSentinelLoopTermination()
    {
        // a malicious packet of 0xFF bytes claims "another element follows" forever.
        // because every successful serialize call consumes at least one bit, a Continue
        // loop is bounded by the bit count of the packet and terminates with Overflow.
        {
            byte[] malicious = new byte[32];
            Array.Fill(malicious, (byte)0xFF);

            ReadStream stream = new ReadStream(malicious);
            int iterations = 0;
            bool hasNext = true;
            while (SerializeUtil.Continue(stream, ref hasNext))
            {
                uint item = 0;
                stream.SerializeBits(ref item, 8);
                iterations++;
            }
            Check(stream.Error == SerializeError.Overflow, $"expected Overflow, got {stream.Error}");
            Check(iterations <= malicious.Length * 8,
                $"loop ran {iterations} iterations, more than the bit count of the packet");
        }

        // a packet truncated in the middle of a sequence also terminates with an error
        {
            byte[] buffer = new byte[64];
            WriteStream writeStream = new WriteStream(buffer);
            uint[] items = { 1, 2, 3, 4, 5 };
            int i = 0;
            bool hasNext = items.Length > 0;
            while (SerializeUtil.Continue(writeStream, ref hasNext))
            {
                writeStream.SerializeBits(ref items[i], 32);
                i++;
                hasNext = i < items.Length;
            }
            writeStream.Flush();

            ReadStream stream = new ReadStream(buffer, 2); // truncated
            hasNext = true;
            while (SerializeUtil.Continue(stream, ref hasNext))
            {
                uint item = 0;
                stream.SerializeBits(ref item, 32);
            }
            Check(stream.Error == SerializeError.Overflow, $"expected Overflow, got {stream.Error}");
        }

        // a malicious packet of zero bytes claims "not done" forever. an Until loop is
        // bounded by the bit count of the packet and terminates with Overflow.
        {
            byte[] malicious = new byte[32];

            ReadStream stream = new ReadStream(malicious);
            int iterations = 0;
            bool done = false;
            while (SerializeUtil.Until(stream, ref done))
            {
                uint item = 0;
                stream.SerializeBits(ref item, 8);
                iterations++;
            }
            Check(stream.Error == SerializeError.Overflow, $"expected Overflow, got {stream.Error}");
            Check(iterations <= malicious.Length * 8,
                $"loop ran {iterations} iterations, more than the bit count of the packet");
        }

        // the unguarded patterns documented as WRONG really do spin, in both
        // polarities: after the first failure the no-op reads never update the
        // sentinel. capped here to keep the demonstration finite.
        {
            ReadStream stream = new ReadStream(Array.Empty<byte>());
            bool hasNext = true;
            int spins = 0;
            while (hasNext && spins < 10000)
            {
                stream.SerializeBool(ref hasNext); // no-op after the first failure
                spins++;
            }
            Check(spins == 10000, "expected the unguarded continuation bit loop to spin until the cap");
        }
        {
            ReadStream stream = new ReadStream(Array.Empty<byte>());
            bool done = false;
            int spins = 0;
            while (!done && spins < 10000)
            {
                stream.SerializeBool(ref done); // no-op after the first failure
                spins++;
            }
            Check(spins == 10000, "expected the unguarded termination bit loop to spin until the cap");
        }
    }

    private static void TestCountLoopTermination()
    {
        // the count-driven analog of the sentinel tests: a count that controls a loop
        // must have its serialize result checked before the loop uses it. On a REUSED
        // stream object a failed read leaves the count from the previous packet in
        // place, so the unchecked pattern does stale-count iterations of no-op work
        // (bounded by the range maximum — amplification, not a hang), while the
        // correct pattern does zero.
        const int maxItems = 1000;

        byte[] buffer = new byte[64];
        WriteStream writeStream = new WriteStream(buffer);
        int count = 5;
        writeStream.SerializeInt(ref count, 0, maxItems);
        for (int i = 0; i < count; i++)
        {
            uint item = (uint)(i + 10);
            writeStream.SerializeBits(ref item, 8);
        }
        Check(writeStream.Ok, "write failed");
        writeStream.Flush();

        // first packet reads fully; count is now 5 in the reused variable
        ReadStream stream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
        Check(stream.SerializeInt(ref count, 0, maxItems), "count read failed");
        Check(count == 5, $"expected count 5, got {count}");
        for (int i = 0; i < count; i++)
        {
            uint item = 0;
            Check(stream.SerializeBits(ref item, 8), "item read failed");
        }

        // second packet is empty (truncated): the failed count read must be detected
        // BEFORE the loop, and the correct pattern runs zero iterations
        stream.Reset(Array.Empty<byte>());
        {
            int iterations = 0;
            if (stream.SerializeInt(ref count, 0, maxItems)) // the correct pattern: check the result
            {
                for (int i = 0; i < count; i++)
                {
                    uint item = 0;
                    stream.SerializeBits(ref item, 8);
                    iterations++;
                }
            }
            Check(stream.Error == SerializeError.Overflow, $"expected Overflow, got {stream.Error}");
            Check(iterations == 0, $"the checked pattern must not loop on a failed count, ran {iterations}");
            Check(count == 5, "the failed read leaves the stale count in place — which is exactly why the unchecked pattern is wrong");
        }

        // demonstrate the WRONG pattern: not checking the result loops over the stale
        // count doing failed no-op reads. Bounded by the count (never infinite), but
        // pure wasted work driven by packet truncation.
        stream.Reset(Array.Empty<byte>());
        {
            int iterations = 0;
            stream.SerializeInt(ref count, 0, maxItems); // WRONG: result ignored, count stays 5
            for (int i = 0; i < count; i++)
            {
                uint item = 0;
                stream.SerializeBits(ref item, 8);
                iterations++;
            }
            Check(iterations == 5, $"expected the unchecked pattern to run the stale count of iterations, ran {iterations}");
        }
    }

    private struct StructPoint : ISerializer
    {
        public int X;
        public int Y;

        public bool Serialize(IBitStream stream)
        {
            stream.SerializeInt(ref X, -1000, 1000);
            stream.SerializeInt(ref Y, -1000, 1000);
            return stream.Ok;
        }
    }

    private static void TestSerializeObjectStruct()
    {
        // struct message types must round trip through the generic ref overload:
        // the non-generic interface overload would box a copy and silently discard
        // the read
        byte[] buffer = new byte[16];

        WriteStream writeStream = new WriteStream(buffer);
        StructPoint written = new StructPoint { X = 123, Y = -456 };
        Check(writeStream.SerializeObject(ref written), "struct write failed");
        writeStream.Flush();

        ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
        StructPoint read = default;
        Check(readStream.SerializeObject(ref read), "struct read failed");
        Check(read.X == 123 && read.Y == -456,
            $"struct fields did not round trip: got ({read.X},{read.Y})");

        MeasureStream measureStream = new MeasureStream();
        StructPoint measured = written;
        Check(measureStream.SerializeObject(ref measured), "struct measure failed");
        Check(measureStream.BitsProcessed == writeStream.BitsProcessed,
            $"measure {measureStream.BitsProcessed} != write {writeStream.BitsProcessed}");

        // error propagation matches the non-generic overload
        WriteStream failStream = new WriteStream(new byte[8]);
        FailingStruct failing = default;
        Check(!failStream.SerializeObject(ref failing), "expected the struct serialize to fail");
        Check(failStream.Error != SerializeError.None, "expected an error to latch");
    }

    private struct FailingStruct : ISerializer
    {
        public bool Serialize(IBitStream stream) => false;
    }

    private static void TestStringLongWrite()
    {
        // strings longer than the old 256 byte stackalloc bound go through the chunked
        // zero-allocation encoder; the bytes must be identical to a whole-string
        // encode, including surrogate pairs that land exactly on a chunk boundary
        string[] values =
        {
            new string('x', 300),                                    // 300 bytes: past the old bound
            new string('é', 400),                                    // 800 bytes: 2 byte code points
            new string('a', 127) + "\U0001F600" + new string('b', 200), // astral pair straddling the 128 char chunk boundary
            new string('a', 126) + "\U0001F600\U0001F680" + new string('b', 300),
        };

        foreach (string expected in values)
        {
            byte[] buffer = new byte[4096];

            WriteStream writeStream = new WriteStream(buffer);
            string v = expected;
            Check(writeStream.SerializeString(ref v, 4000), "long string write failed");
            writeStream.Flush();

            // the wire bytes after the length prefix and align are exactly the
            // whole-string UTF-8 encoding
            byte[] wholeEncode = System.Text.Encoding.UTF8.GetBytes(expected);
            ReadStream check = new ReadStream(buffer, (int)writeStream.BytesProcessed);
            int length = 0;
            Check(check.SerializeInt(ref length, 0, 3999) && length == wholeEncode.Length,
                $"length prefix mismatch: got {length}, expected {wholeEncode.Length}");
            Check(check.SerializeAlign(), "align failed");
            byte[] payload = new byte[length];
            Check(check.SerializeBytes(payload), "payload read failed");
            Check(payload.AsSpan().SequenceEqual(wholeEncode),
                "chunked encode does not match the whole-string encode");

            ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
            string value = "";
            Check(readStream.SerializeString(ref value, 4000), "long string read failed");
            Check(value == expected, "long string did not round trip");
        }
    }

    private static void TestSerializeObjectErrorPropagation()
    {
        // an object that aborts its own serialization must fail the stream and latch.
        // On the write side the latch is for the caller's final Error check and for
        // SerializeObject itself — the per-field write spine is branch-free and stays
        // trusted (2026-08-16 check-model audit), so field calls after the abort
        // keep returning true. The READ side keeps its sticky no-op model in full
        // (TestContinue and the redteam suite pin it).
        WriteStream stream = new WriteStream(new byte[8]);
        Check(!stream.SerializeObject(new FailingObject()), "expected the object serialize to fail");
        Check(stream.Error != SerializeError.None, "expected an error to latch on the stream");
        uint v = 1;
        Check(stream.SerializeBits(ref v, 8), "field writes after an abort stay trusted and branch-free");
        Check(!stream.SerializeObject(new FailingObject()), "SerializeObject stays guarded after a latch");
        Check(!stream.Ok, "the latch survives for the caller's final check");
    }

    private static void TestStreamReset()
    {
        // streams are reusable without allocation
        byte[] buffer = new byte[16];

        WriteStream writeStream = new WriteStream(buffer);
        uint v = 0xABCD;
        writeStream.SerializeBits(ref v, 16);
        writeStream.Flush();

        writeStream.Reset(buffer);
        v = 0x1234;
        Check(writeStream.SerializeBits(ref v, 16), "write failed");
        writeStream.Flush();

        ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
        uint value = 0;
        Check(readStream.SerializeBits(ref value, 16), "read failed");
        Check(value == 0x1234, $"expected 0x1234, got {value:x}");

        // reset clears a latched error
        readStream.Reset(buffer, 0);
        Check(!readStream.SerializeBits(ref value, 1), "expected Overflow on empty buffer");
        Check(readStream.Error == SerializeError.Overflow, "expected Overflow to latch");
        readStream.Reset(buffer, (int)writeStream.BytesProcessed);
        Check(readStream.Error == SerializeError.None, "expected Reset to clear the error");
        Check(readStream.SerializeBits(ref value, 16) && value == 0x1234,
            $"expected 0x1234 after reset, got {value:x}");
    }

    private static void TestLargeBuffer()
    {
        // bit counts are 64 bit, so buffers larger than 256 MB work. write a bulk block
        // that carries the stream past the 2^31 bit boundary, then verify that
        // bitpacked values round trip on the far side of it.
        const int bufferSize = 320 * 1024 * 1024;
        byte[] buffer = new byte[bufferSize];

        byte[] chunk = new byte[1024 * 1024];
        for (int i = 0; i < chunk.Length; i++)
        {
            chunk[i] = (byte)(i * 37);
        }

        const int numChunks = 300; // 300 MB of bulk data: past the 256 MB boundary

        WriteStream writeStream = new WriteStream(buffer);
        for (int i = 0; i < numChunks; i++)
        {
            Check(writeStream.SerializeBytes(chunk), "bulk write failed");
        }
        uint sentinel = 0xDEADBEEF;
        Check(writeStream.SerializeBits(ref sentinel, 32), "sentinel write failed");
        int value = -12345;
        Check(writeStream.SerializeInt(ref value, -100000, +100000), "value write failed");
        writeStream.Flush();
        Check(writeStream.BitsProcessed > 1L << 31, "expected the bit count to cross the 2^31 boundary");

        ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
        byte[] readChunk = new byte[chunk.Length];
        for (int i = 0; i < numChunks; i++)
        {
            Check(readStream.SerializeBytes(readChunk), "bulk read failed");
        }
        Check(readChunk.AsSpan().SequenceEqual(chunk), "the final chunk did not round trip");
        uint readSentinel = 0;
        Check(readStream.SerializeBits(ref readSentinel, 32), "sentinel read failed");
        Check(readSentinel == sentinel, $"expected sentinel {sentinel:x}, got {readSentinel:x}");
        int readValue = 0;
        Check(readStream.SerializeInt(ref readValue, -100000, +100000), "value read failed");
        Check(readValue == value, $"expected {value}, got {readValue}");
        Check(readStream.BitsProcessed > 1L << 31, "expected the read bit count to cross the 2^31 boundary");

        // measuring a single block of 256 MB or more crosses 2^31 bits in one call:
        // the multiply must happen in the 64 bit domain
        const int measureBytes = 270 * 1024 * 1024;
        MeasureStream measureStream = new MeasureStream();
        Check(measureStream.SerializeBytes(buffer.AsSpan(0, measureBytes)), "measure failed");
        long expectedMeasure = 7L + (long)measureBytes * 8;
        Check(measureStream.BitsProcessed == expectedMeasure,
            $"expected {expectedMeasure} measured bits, got {measureStream.BitsProcessed}");
    }
}
