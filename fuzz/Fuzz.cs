/*
    Fuzz.cs — the coverage-guided libFuzzer harness for Serialize.cs (SharpFuzz +
    libfuzzer-dotnet), the C# counterpart of fuzz.cpp in mas-bandwidth/serialize.

    Every input runs these passes:

    1. Hostile read (FuzzRead) across two bit-complementary sentinel patterns (0x5A
       and 0xA5). ReadStream is the trust boundary of this library: it must survive
       arbitrary hostile bytes, failing reads by returning false with a reason from the
       closed list, never by throwing or tripping a Debug.Assert (the library is built
       Debug here, so its asserts are live). Every refusal is checked: a reason is
       latched, the reason is one this operation can give, a refused scalar destination
       is left at its sentinel under both 0x5A and 0xA5 patterns, and every later call
       on the failed stream echoes the FIRST reason without advancing BitsProcessed.
       Every acceptance is checked against the declared range or rule.

    2. The same hostile bytes from an allocation with NO slack past the data. Pass 1's
       buffer carries 8 bytes of nonzero garbage past the packet; this one ends at the
       packet. The two runs must agree on every result, value, refusal and position:
       a reader that interprets a byte past its declared length, or whose no-slack path
       decodes differently from its windowed path, disagrees with itself here.

    3. Differential round trip (FuzzRoundTrip). Values generated from the input are
       written with WriteStream into a 0xAA-canaried buffer, measured with MeasureStream,
       read back with ReadStream and compared. Any write/read asymmetry fails, the
       flushed word tail must be zero, the 16-byte 0xAA canary past the last flushed
       word must stay intact, the reader must consume exactly the bits the writer wrote
       for each operation, and MeasureStream must never measure fewer bits than the
       writer wrote, per operation as well as in total. The read then ends exactly where
       the writer stopped, and one byte more is trailing_data.

    4. ReadBatch inline reads against ReadStream on the same bytes, with and without
       slack, across both 0x5A and 0xA5 sentinel patterns.

    The first 32 bytes of the input are an op program selecting which serialize calls
    run and with what parameter; the rest is the hostile bitstream for passes 1 and 2
    and the value pool for pass 3, exactly as in fuzz.cpp.

    A failed check throws: SharpFuzz reports the escaping exception to libFuzzer as a
    crash and libFuzzer writes the reproducer. Run `Fuzz --replay <file|dir>...` to
    re-run reproducers or a corpus without libFuzzer, `Fuzz --replay-corpus` to run
    the built-in deterministic corpus, or `Fuzz --controls` to verify that every
    harness negative control traps.
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using SharpFuzz;

namespace Serialize.Fuzz;

internal static class Program
{
    private const int NumOps = 32;
    private const int MaxPayloadBytes = 4096;
    private const int WriteBufferSize = 16 * 1024;
    private const int CanaryBytes = 16;

    // Q112.16 bounds of +-2^60 whole units: a raw range past 64 bits
    private const long Wide = 1152921504606846976;

    private static string? s_activeControl = Environment.GetEnvironmentVariable("SERIALIZE_FUZZ_CONTROL");

    private static bool ControlEnabled(string name) =>
        string.Equals(s_activeControl, name, StringComparison.Ordinal);

    public static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--controls")
        {
            RunControlsSelfTest();
            return 0;
        }
        if (args.Length > 0 && args[0] == "--replay-corpus")
        {
            List<byte[]> corpus = BuildDeterministicCorpus(256);
            foreach (byte[] input in corpus)
            {
                TestOneInput(input);
            }
            Console.WriteLine($"replayed {corpus.Count} deterministic corpus inputs, no findings");
            return 0;
        }
        if (args.Length > 0 && args[0] == "--replay")
        {
            int inputs = 0;
            for (int i = 1; i < args.Length; i++)
            {
                if (Directory.Exists(args[i]))
                {
                    string[] files = Directory.GetFiles(args[i]);
                    Array.Sort(files, StringComparer.Ordinal);
                    foreach (string file in files)
                    {
                        TestOneInput(File.ReadAllBytes(file));
                        inputs++;
                    }
                }
                else
                {
                    TestOneInput(File.ReadAllBytes(args[i]));
                    inputs++;
                }
            }
            Console.WriteLine($"replayed {inputs} inputs, no findings");
            return 0;
        }
        Fuzzer.LibFuzzer.Run(TestOneInput);
        return 0;
    }

    private static List<byte[]> BuildDeterministicCorpus(int count)
    {
        List<byte[]> corpus = new List<byte[]>(count + 4);

        // Seed 1: op 0 = bits (select 0, param 15 -> 16 bits) over a 1-byte payload (refuses PastEnd)
        byte[] truncatedBits = new byte[NumOps + 1];
        truncatedBits[0] = 0xF0;
        truncatedBits[NumOps] = 0x5A;
        corpus.Add(truncatedBits);

        // Seed 2: op 15 = uint8/uint16/uint32 with 0xFFFF in the uint16 slot
        byte[] uint16MaxSeed = new byte[NumOps + 9];
        uint16MaxSeed[0] = 15;
        for (int i = 1; i < NumOps; i++)
        {
            uint16MaxSeed[i] = 12; // align
        }
        uint16MaxSeed[NumOps] = 0x42;
        uint16MaxSeed[NumOps + 1] = 0xFF;
        uint16MaxSeed[NumOps + 2] = 0xFF;
        uint16MaxSeed[NumOps + 3] = 0xFF;
        uint16MaxSeed[NumOps + 4] = 0xFF;
        corpus.Add(uint16MaxSeed);

        // Seed 3: op 13 = int_relative medium tier (difference in [24..280])
        byte[] tierSeed = new byte[NumOps + 8];
        tierSeed[0] = 13;
        tierSeed[NumOps + 3] = 50;
        corpus.Add(tierSeed);

        uint state = 0x9E3779B9u;
        for (int n = 0; n < count; n++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            int payloadLen = 1 + (int)(state % 96);
            byte[] buf = new byte[NumOps + payloadLen];
            for (int i = 0; i < buf.Length; i++)
            {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                buf[i] = (byte)(state & 0xFF);
            }
            if (n % 7 == 0)
            {
                Array.Fill(buf, n % 2 == 0 ? (byte)0x00 : (byte)0xFF, NumOps, payloadLen);
            }
            corpus.Add(buf);
        }
        return corpus;
    }

    private static void RunControlsSelfTest()
    {
        List<byte[]> corpus = BuildDeterministicCorpus(128);
        s_activeControl = null;
        foreach (byte[] input in corpus)
        {
            TestOneInput(input);
        }

        (string Name, string Expected)[] controls = new (string Name, string Expected)[]
        {
            ("sentinel", "a refused read wrote its destination"),
            ("terminality", "a failed stream advanced BitsProcessed"),
            ("slack", "read with slack and read without slack disagree"),
            ("roundtrip", "roundtrip negative control"),
            ("canary", "canary byte"),
            ("trailing", "a byte past the writer's end was accepted"),
        };

        foreach ((string control, string expected) in controls)
        {
            s_activeControl = control;
            bool caught = false;
            try
            {
                foreach (byte[] input in corpus)
                {
                    TestOneInput(input);
                }
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("FUZZ CHECK FAILED:", StringComparison.Ordinal) &&
                                                      ex.Message.Contains(expected, StringComparison.Ordinal))
            {
                caught = true;
            }
            finally
            {
                s_activeControl = null;
            }
            if (!caught)
            {
                throw new InvalidOperationException("FUZZ CONTROL SELF-TEST FAILED: control '" + control + "' did not trap with '" + expected + "'");
            }
        }
        Console.WriteLine($"verified {corpus.Count} deterministic corpus inputs and {controls.Length} negative controls");
    }

    private static void Check(bool condition, string what)
    {
        if (!condition)
        {
            throw new InvalidOperationException("FUZZ CHECK FAILED: " + what);
        }
    }

    private static byte SentinelU8(byte pattern) => pattern;

    private static ushort SentinelU16(byte pattern) => (ushort)((pattern << 8) | pattern);

    private static short SentinelI16(byte pattern) => unchecked((short)SentinelU16(pattern));

    private static uint SentinelU32(byte pattern) => 0x01010101u * pattern;

    private static int SentinelI32(byte pattern) => unchecked((int)SentinelU32(pattern));

    private static ulong SentinelU64(byte pattern) => 0x0101010101010101ul * pattern;

    private static long SentinelI64(byte pattern) => unchecked((long)SentinelU64(pattern));

    private static bool SentinelBool(byte pattern) => pattern == 0x5A;

    private static float SentinelFloat(byte pattern) => pattern == 0x5A ? 1.5f : -2.25f;

    private static double SentinelDouble(byte pattern) => pattern == 0x5A ? 1.5 : -2.25;

    private static UInt128Value SentinelU128(byte pattern) =>
        new UInt128Value(SentinelU64(pattern), SentinelU64(unchecked((byte)~pattern)));

    private static Int128Value SentinelI128(byte pattern) =>
        new Int128Value(SentinelU64(pattern), SentinelU64(unchecked((byte)~pattern)));

    private static void TestOneInput(ReadOnlySpan<byte> data)
    {
        if (data.Length <= NumOps || data.Length > NumOps + MaxPayloadBytes)
        {
            return;
        }

        ReadOnlySpan<byte> ops = data.Slice(0, NumOps);
        byte[] payload = data.Slice(NumOps).ToArray();

        // pass 1: hostile read across two bit-complementary sentinels (0x5A and 0xA5),
        // with 8 bytes of nonzero garbage slack past the packet
        byte[] slack = new byte[payload.Length + 8];
        payload.CopyTo(slack, 0);
        for (int i = payload.Length; i < slack.Length; i++)
        {
            slack[i] = 0xA5;
        }
        Trace withSlack = new Trace();
        FuzzRead(new ReadStream(slack, payload.Length), ops, withSlack, 0x5A);

        Trace withSlackAlt = new Trace();
        FuzzRead(new ReadStream(slack, payload.Length), ops, withSlackAlt, 0xA5);
        Check(withSlack.Hash == withSlackAlt.Hash && withSlack.Calls == withSlackAlt.Calls,
            "two-sentinel hostile reads disagree on the same bytes");

        // pass 2: the same bytes from an allocation that ends at the packet
        Trace exact = new Trace();
        FuzzRead(new ReadStream(payload, payload.Length), ops, exact, 0x5A);
        if (ControlEnabled("slack"))
        {
            exact.Mix(1);
        }
        Check(withSlack.Hash == exact.Hash && withSlack.Calls == exact.Calls,
            "read with slack and read without slack disagree on the same bytes");

        // pass 3: differential round trip
        RoundTrip(ops, payload);

        // pass 4: the ReadBatch inline reads against the stream on the same bytes, with
        // and without slack, across both 0x5A and 0xA5 sentinels
        BatchAgreesWithStream(ops, slack, payload.Length, 0x5A);
        BatchAgreesWithStream(ops, slack, payload.Length, 0xA5);
        BatchAgreesWithStream(ops, payload, payload.Length, 0x5A);
    }

    // ---- pass 4: batch against stream -------------------------------------------

    private static void BatchAgreesWithStream(ReadOnlySpan<byte> ops, byte[] buffer, int bytes, byte pattern)
    {
        ReadStream stream = new ReadStream(buffer, bytes);
        ReadStream under = new ReadStream(buffer, bytes);
        ReadBatch batch = under.BeginBatch();
        for (int i = 0; i < ops.Length; i++)
        {
            int select = ops[i] & 7;
            int param = ops[i] >> 3; // [0,31]
            bool a, b;
            ulong va, vb;
            switch (select)
            {
                case 0:
                {
                    uint x = SentinelU32(pattern), y = SentinelU32(pattern);
                    a = stream.SerializeBits(ref x, param + 1);
                    b = batch.SerializeBits(ref y, param + 1);
                    if (!b)
                    {
                        Check(y == SentinelU32(pattern), "batch read bits: a refused read wrote its destination");
                    }
                    va = x; vb = y;
                    break;
                }
                case 1:
                {
                    ulong x = SentinelU64(pattern), y = SentinelU64(pattern);
                    int bits = param * 2 + 1; // [1,63]
                    a = stream.SerializeBits64(ref x, bits);
                    b = batch.SerializeBits64(ref y, bits);
                    if (!b)
                    {
                        Check(y == SentinelU64(pattern), "batch read bits64: a refused read wrote its destination");
                    }
                    va = x; vb = y;
                    break;
                }
                case 2:
                {
                    int x = SentinelI32(pattern), y = SentinelI32(pattern);
                    a = stream.SerializeInt(ref x, -param * 1000, param * 7 + 3);
                    b = batch.SerializeInt(ref y, -param * 1000, param * 7 + 3);
                    if (!b)
                    {
                        Check(y == SentinelI32(pattern), "batch read int: a refused read wrote its destination");
                    }
                    va = (ulong)x; vb = (ulong)y;
                    break;
                }
                case 3:
                {
                    long x = SentinelI64(pattern), y = SentinelI64(pattern);
                    long bound = 1L << (param * 2);
                    a = stream.SerializeInt64(ref x, -bound, bound);
                    b = batch.SerializeInt64(ref y, -bound, bound);
                    if (!b)
                    {
                        Check(y == SentinelI64(pattern), "batch read int64: a refused read wrote its destination");
                    }
                    va = (ulong)x; vb = (ulong)y;
                    break;
                }
                case 4:
                {
                    float x = SentinelFloat(pattern), y = SentinelFloat(pattern);
                    a = stream.SerializeFloat(ref x);
                    b = batch.SerializeFloat(ref y);
                    if (!b)
                    {
                        Check(BitConverter.SingleToUInt32Bits(y) == BitConverter.SingleToUInt32Bits(SentinelFloat(pattern)),
                            "batch read float: a refused read wrote its destination");
                    }
                    va = BitConverter.SingleToUInt32Bits(x); vb = BitConverter.SingleToUInt32Bits(y);
                    break;
                }
                case 5:
                {
                    double x = SentinelDouble(pattern), y = SentinelDouble(pattern);
                    a = stream.SerializeDouble(ref x);
                    b = batch.SerializeDouble(ref y);
                    if (!b)
                    {
                        Check(BitConverter.DoubleToUInt64Bits(y) == BitConverter.DoubleToUInt64Bits(SentinelDouble(pattern)),
                            "batch read double: a refused read wrote its destination");
                    }
                    va = BitConverter.DoubleToUInt64Bits(x); vb = BitConverter.DoubleToUInt64Bits(y);
                    break;
                }
                case 6:
                {
                    float x = SentinelFloat(pattern), y = SentinelFloat(pattern);
                    a = stream.SerializeCompressedFloat(ref x, -1.0f, 1.0f + param, 0.001f);
                    b = batch.SerializeCompressedFloat(ref y, -1.0f, 1.0f + param, 0.001f);
                    if (!b)
                    {
                        Check(BitConverter.SingleToUInt32Bits(y) == BitConverter.SingleToUInt32Bits(SentinelFloat(pattern)),
                            "batch read compressed float: a refused read wrote its destination");
                    }
                    va = BitConverter.SingleToUInt32Bits(x); vb = BitConverter.SingleToUInt32Bits(y);
                    break;
                }
                default:
                {
                    a = stream.SerializeAlign();
                    b = batch.SerializeAlign();
                    va = 0; vb = 0;
                    break;
                }
            }
            Check(a == b && va == vb, "batch and stream disagree on op " + select);
            Check(stream.Error == batch.Error && stream.BitsProcessed == batch.BitsProcessed,
                "batch and stream disagree on the stream state after op " + select);
        }
        batch.End();
        Check(under.Error == stream.Error && under.BitsProcessed == stream.BitsProcessed,
            "End did not carry the batch state to its stream");
    }

    // ---- pass 1: hostile read ---------------------------------------------------

    /// <summary>An order-sensitive digest of everything a read pass observed.</summary>
    private sealed class Trace
    {
        public ulong Hash = 0xCBF29CE484222325;
        public int Calls;

        public void Mix(ulong value)
        {
            Hash = (Hash ^ value) * 0x100000001B3;
            Hash ^= Hash >> 29;
        }
    }

    private static int Mask(SerializeError error) => 1 << (int)error;

    private static readonly int ClosedList =
        Mask(SerializeError.PastEnd) | Mask(SerializeError.ValueOutOfRange) |
        Mask(SerializeError.NonzeroPadding) | Mask(SerializeError.TrailingData) |
        Mask(SerializeError.NonFiniteFloat) | Mask(SerializeError.InvalidUtf8) |
        Mask(SerializeError.EmbeddedNul) | Mask(SerializeError.NonCanonical);

    private static readonly int PastEnd = Mask(SerializeError.PastEnd);
    private static readonly int Ranged = PastEnd | Mask(SerializeError.ValueOutOfRange);
    private static readonly int FloatReasons = PastEnd | Mask(SerializeError.NonFiniteFloat);
    private static readonly int CompressedReasons = Ranged | Mask(SerializeError.NonFiniteFloat);
    private static readonly int AlignReasons = PastEnd | Mask(SerializeError.NonzeroPadding);
    private static readonly int StringReasons = Ranged | Mask(SerializeError.NonzeroPadding) |
        Mask(SerializeError.InvalidUtf8) | Mask(SerializeError.EmbeddedNul);
    private static readonly int EndReasons = Mask(SerializeError.TrailingData) | Mask(SerializeError.NonzeroPadding);
    private static readonly int RelativeReasons = Ranged | Mask(SerializeError.NonCanonical);

    /// <summary>
    /// Checks one read call's result against the stream's failure state and returns
    /// whether the value it produced may be inspected. A refusal must carry a reason
    /// from the closed list that this operation can give; once the stream has failed,
    /// every call must refuse, the latched reason must stay the first one, and
    /// BitsProcessed must not advance.
    /// </summary>
    private static bool Accepted(
        ReadStream stream, bool ok, ref SerializeError first, ref long refusedBits,
        int allowed, string op, Trace trace)
    {
        trace.Calls++;
        trace.Mix(ok ? 1UL : 2UL);
        SerializeError error = stream.Error;
        trace.Mix((ulong)error);
        trace.Mix((ulong)stream.BitsProcessed);
        if (first != SerializeError.None)
        {
            long observedBits = ControlEnabled("terminality") ? stream.BitsProcessed + 1 : stream.BitsProcessed;
            Check(!ok, op + ": a failed stream accepted a read");
            Check(error == first, op + ": the latched reason changed from " + first + " to " + error);
            Check(observedBits == refusedBits,
                op + ": a failed stream advanced BitsProcessed from " + refusedBits + " to " + observedBits);
            return false;
        }
        if (ok)
        {
            Check(error == SerializeError.None, op + ": accepted with a latched error " + error);
            Check(stream.Ok, op + ": accepted but the stream is not Ok");
            return true;
        }
        Check(error != SerializeError.None, op + ": refused with no reason");
        Check((Mask(error) & ClosedList) != 0, op + ": reason " + (int)error + " is outside the closed list");
        Check((Mask(error) & allowed) != 0, op + ": refused for " + SerializeUtil.RefusalName(error) + ", a reason this operation cannot give");
        Check(!stream.Ok, op + ": refused but the stream is Ok");
        first = error;
        refusedBits = stream.BitsProcessed;
        return false;
    }

    private static void FuzzRead(ReadStream stream, ReadOnlySpan<byte> ops, Trace trace, byte pattern)
    {
        byte[] bytes = new byte[256];
        SerializeError first = SerializeError.None;
        long refusedBits = 0;

        for (int i = 0; i < ops.Length; i++)
        {
            int select = ops[i] & 15;
            int param = ops[i] >> 4; // [0,15]

            switch (select)
            {
                case 0:
                case 1:
                {
                    int bits = select == 0 ? param + 1 : param + 17; // [1,32]
                    uint sentinel = SentinelU32(pattern);
                    uint value = sentinel;
                    if (Accepted(stream, stream.SerializeBits(ref value, bits), ref first, ref refusedBits, PastEnd, "read bits", trace))
                    {
                        Check(bits == 32 || value < (1U << bits), "read bits: value wider than its bits");
                        trace.Mix(value);
                    }
                    else
                    {
                        if (ControlEnabled("sentinel") && pattern == 0xA5)
                        {
                            value ^= 1u;
                        }
                        Check(value == sentinel, "read bits: a refused read wrote its destination");
                    }
                    break;
                }

                case 2:
                {
                    int sentinel = SentinelI32(pattern);
                    int value = sentinel;
                    if (Accepted(stream, stream.SerializeInt(ref value, -100, +100), ref first, ref refusedBits, Ranged, "read int [-100,100]", trace))
                    {
                        Check(value >= -100 && value <= +100, "read int [-100,100]: value out of range");
                        trace.Mix((ulong)value);
                    }
                    else
                    {
                        Check(value == sentinel, "read int [-100,100]: a refused read wrote its destination");
                    }
                    break;
                }

                case 3:
                    ReadWide(stream, param, ref first, ref refusedBits, trace, pattern);
                    break;

                case 4:
                {
                    bool sentinel = SentinelBool(pattern);
                    bool value = sentinel;
                    if (Accepted(stream, stream.SerializeBool(ref value), ref first, ref refusedBits, PastEnd, "read bool", trace))
                    {
                        trace.Mix(value ? 1UL : 0UL);
                    }
                    else
                    {
                        Check(value == sentinel, "read bool: a refused read wrote its destination");
                    }
                    break;
                }

                case 5:
                {
                    // finite values only: whatever the bytes, an accepted float is never NaN or infinite
                    float sentinel = SentinelFloat(pattern);
                    float value = sentinel;
                    if (Accepted(stream, stream.SerializeFloat(ref value), ref first, ref refusedBits, FloatReasons, "read float", trace))
                    {
                        Check(float.IsFinite(value), "read float: accepted a non-finite value");
                        trace.Mix(BitConverter.SingleToUInt32Bits(value));
                    }
                    else
                    {
                        Check(BitConverter.SingleToUInt32Bits(value) == BitConverter.SingleToUInt32Bits(sentinel), "read float: a refused read wrote its destination");
                    }
                    break;
                }

                case 6:
                {
                    double sentinel = SentinelDouble(pattern);
                    double value = sentinel;
                    if (Accepted(stream, stream.SerializeDouble(ref value), ref first, ref refusedBits, FloatReasons, "read double", trace))
                    {
                        Check(double.IsFinite(value), "read double: accepted a non-finite value");
                        trace.Mix(BitConverter.DoubleToUInt64Bits(value));
                    }
                    else
                    {
                        Check(BitConverter.DoubleToUInt64Bits(value) == BitConverter.DoubleToUInt64Bits(sentinel), "read double: a refused read wrote its destination");
                    }
                    break;
                }

                case 7:
                {
                    float sentinel = SentinelFloat(pattern);
                    float value = sentinel;
                    if (Accepted(stream, stream.SerializeCompressedFloat(ref value, -10.0f, +10.0f, 0.01f), ref first, ref refusedBits, CompressedReasons, "read compressed float", trace))
                    {
                        Check(float.IsFinite(value) && value >= -10.001f && value <= +10.001f, "read compressed float: value outside [min,max]");
                        trace.Mix(BitConverter.SingleToUInt32Bits(value));
                    }
                    else
                    {
                        Check(BitConverter.SingleToUInt32Bits(value) == BitConverter.SingleToUInt32Bits(sentinel), "read compressed float: a refused read wrote its destination");
                    }

                    SerializeUtil.CompressedFloatParams(-10.0f, +10.0f, 0.01f, out uint maxIntegerValue, out int cbits, out float delta);
                    float pre = sentinel;
                    if (Accepted(stream, stream.SerializeCompressedFloatPrecomputed(ref pre, maxIntegerValue, cbits, delta, -10.0f), ref first, ref refusedBits, CompressedReasons, "read compressed float precomputed", trace))
                    {
                        Check(float.IsFinite(pre) && pre >= -10.001f && pre <= +10.001f, "read compressed float precomputed: value outside [min,max]");
                        trace.Mix(BitConverter.SingleToUInt32Bits(pre));
                    }
                    else
                    {
                        Check(BitConverter.SingleToUInt32Bits(pre) == BitConverter.SingleToUInt32Bits(sentinel), "read compressed float precomputed: a refused read wrote its destination");
                    }
                    break;
                }

                case 8:
                {
                    ulong sentinel64 = SentinelU64(pattern);
                    ulong value = sentinel64;
                    if (Accepted(stream, stream.SerializeUInt64(ref value), ref first, ref refusedBits, PastEnd, "read uint64", trace))
                    {
                        trace.Mix(value);
                    }
                    else
                    {
                        Check(value == sentinel64, "read uint64: a refused read wrote its destination");
                    }

                    UInt128Value sentinel128 = SentinelU128(pattern);
                    UInt128Value value128 = sentinel128;
                    if (Accepted(stream, stream.SerializeUInt128(ref value128), ref first, ref refusedBits, PastEnd, "read uint128", trace))
                    {
                        trace.Mix(value128.Lo);
                        trace.Mix(value128.Hi);
                    }
                    else
                    {
                        Check(value128 == sentinel128, "read uint128: a refused read wrote its destination");
                    }

                    int bits64 = param * 4 + 4; // [4,64]
                    ulong valueBits64 = sentinel64;
                    if (Accepted(stream, stream.SerializeBits64(ref valueBits64, bits64), ref first, ref refusedBits, PastEnd, "read bits64", trace))
                    {
                        Check(bits64 == 64 || valueBits64 < (1UL << bits64), "read bits64: value wider than its bits");
                        trace.Mix(valueBits64);
                    }
                    else
                    {
                        Check(valueBits64 == sentinel64, "read bits64: a refused read wrote its destination");
                    }
                    break;
                }

                case 9:
                {
                    int numBytes = param * 16 + 1; // [1,241]
                    Span<byte> span = bytes.AsSpan(0, numBytes);
                    span.Fill(pattern);
                    if (Accepted(stream, stream.SerializeBytes(span), ref first, ref refusedBits, AlignReasons, "read bytes", trace))
                    {
                        foreach (byte b in span)
                        {
                            trace.Mix(b);
                        }
                    }
                    else
                    {
                        for (int j = 0; j < span.Length; j++)
                        {
                            Check(span[j] == pattern, "read bytes: a refused read wrote its destination");
                        }
                    }
                    break;
                }

                case 10:
                {
                    string sentinelStr = pattern == 0x5A ? "sentinel-5A" : "sentinel-A5";
                    string value = sentinelStr;
                    if (Accepted(stream, stream.SerializeString(ref value, 256), ref first, ref refusedBits, StringReasons, "read string", trace))
                    {
                        Check(value.IndexOf('\0') < 0, "read string: accepted an embedded NUL");
                        Check(Encoding.UTF8.GetByteCount(value) <= 255, "read string: longer than its buffer");
                        foreach (char c in value)
                        {
                            trace.Mix(c);
                        }
                    }
                    else
                    {
                        Check(value == sentinelStr, "read string: a refused read wrote its destination");
                    }
                    break;
                }

                case 11:
                {
                    // the end of the object: an accepted end leaves nothing in the stream
                    if (Accepted(stream, stream.SerializeEnd(), ref first, ref refusedBits, EndReasons, "read end", trace))
                    {
                        Check(stream.BitsProcessed % 8 == 0, "read end: accepted end not on a byte boundary");
                        uint after = SentinelU32(pattern);
                        Check(!stream.SerializeBits(ref after, 1), "read end: a read after an accepted end succeeded");
                        Check(stream.Error == SerializeError.PastEnd, "read end: a read after an accepted end was not past_end");
                        Check(after == SentinelU32(pattern), "read end: a refused read after the end wrote its destination");
                    }
                    trace.Mix((ulong)stream.Error);
                    return;
                }

                case 12:
                {
                    Accepted(stream, stream.SerializeAlign(), ref first, ref refusedBits, AlignReasons, "read align", trace);
                    break;
                }

                case 13:
                {
                    int previous = param * 1000; // int_relative's domain starts at 0: a negative previous is caller error
                    int sentinel = SentinelI32(pattern);
                    int current = sentinel;
                    if (Accepted(stream, stream.SerializeIntRelative(previous, ref current), ref first, ref refusedBits, RelativeReasons, "read int_relative", trace))
                    {
                        Check(current > previous, "read int_relative: accepted a value not above previous");
                        trace.Mix((ulong)current);
                    }
                    else
                    {
                        Check(current == sentinel, "read int_relative: a refused read wrote its destination");
                    }
                    break;
                }

                case 14:
                {
                    int max = (param + 1) * 1000; // ranges of varying width exercise bits_required
                    int sentinel = SentinelI32(pattern);
                    int value = sentinel;
                    if (Accepted(stream, stream.SerializeInt(ref value, 0, max), ref first, ref refusedBits, Ranged, "read int [0,max]", trace))
                    {
                        Check(value >= 0 && value <= max, "read int [0,max]: value out of range");
                        trace.Mix((ulong)value);
                    }
                    else
                    {
                        Check(value == sentinel, "read int [0,max]: a refused read wrote its destination");
                    }
                    break;
                }

                case 15:
                {
                    byte sentinel8 = SentinelU8(pattern);
                    byte value8 = sentinel8;
                    if (Accepted(stream, stream.SerializeByte(ref value8), ref first, ref refusedBits, PastEnd, "read uint8", trace))
                    {
                        trace.Mix(value8);
                    }
                    else
                    {
                        Check(value8 == sentinel8, "read uint8: a refused read wrote its destination");
                    }
                    ushort sentinel16 = SentinelU16(pattern);
                    ushort value16 = sentinel16;
                    if (Accepted(stream, stream.SerializeUInt16(ref value16), ref first, ref refusedBits, PastEnd, "read uint16", trace))
                    {
                        trace.Mix(value16);
                    }
                    else
                    {
                        Check(value16 == sentinel16, "read uint16: a refused read wrote its destination");
                    }
                    uint sentinel32 = SentinelU32(pattern);
                    uint value32 = sentinel32;
                    if (Accepted(stream, stream.SerializeUInt32(ref value32), ref first, ref refusedBits, PastEnd, "read uint32", trace))
                    {
                        trace.Mix(value32);
                    }
                    else
                    {
                        Check(value32 == sentinel32, "read uint32: a refused read wrote its destination");
                    }
                    break;
                }
            }
        }

        if (first != SerializeError.None)
        {
            uint post = SentinelU32(pattern);
            Check(!stream.SerializeBits(ref post, 1), "post-refusal read bits: a failed stream accepted a read");
            Check(post == SentinelU32(pattern), "post-refusal read bits: a refused read wrote its destination");
            Check(stream.Error == first, "post-refusal read bits: the latched reason changed");
            Check(stream.BitsProcessed == refusedBits,
                "post-refusal read bits: a failed stream advanced BitsProcessed from " + refusedBits + " to " + stream.BitsProcessed);
        }
    }

    /// <summary>The wide integers and every fixed point storage width, off hostile bytes.</summary>
    private static void ReadWide(
        ReadStream stream, int param, ref SerializeError first, ref long refusedBits,
        Trace trace, byte pattern)
    {
        int sentinel32 = SentinelI32(pattern);
        int full = sentinel32;
        if (Accepted(stream, stream.SerializeInt(ref full, int.MinValue, int.MaxValue), ref first, ref refusedBits, PastEnd, "read int full range", trace))
        {
            trace.Mix((ulong)full);
        }
        else
        {
            Check(full == sentinel32, "read int full range: a refused read wrote its destination");
        }

        long sentinel64 = SentinelI64(pattern);
        long full64 = sentinel64;
        if (Accepted(stream, stream.SerializeInt64(ref full64, long.MinValue, long.MaxValue), ref first, ref refusedBits, PastEnd, "read int64 full range", trace))
        {
            trace.Mix((ulong)full64);
        }
        else
        {
            Check(full64 == sentinel64, "read int64 full range: a refused read wrote its destination");
        }

        long bound = (long)(param + 1) << 35; // spans of varying width exercise bits_required64
        long ranged64 = sentinel64;
        if (Accepted(stream, stream.SerializeInt64(ref ranged64, -bound, +bound), ref first, ref refusedBits, Ranged, "read int64 ranged", trace))
        {
            Check(ranged64 >= -bound && ranged64 <= +bound, "read int64 ranged: value out of range");
            trace.Mix((ulong)ranged64);
        }
        else
        {
            Check(ranged64 == sentinel64, "read int64 ranged: a refused read wrote its destination");
        }

        // fixed point: values read off hostile bytes must decode within the raw bounds or fail
        int fixed32 = sentinel32;
        if (Accepted(stream, stream.SerializeFixed(ref fixed32, 16, 16, -1000, +1000), ref first, ref refusedBits, Ranged, "read fixed Q16.16 int", trace))
        {
            Check(fixed32 >= -1000 * 65536 && fixed32 <= 1000 * 65536, "read fixed Q16.16 int: value out of range");
            trace.Mix((ulong)fixed32);
        }
        else
        {
            Check(fixed32 == sentinel32, "read fixed Q16.16 int: a refused read wrote its destination");
        }

        long fixed64 = sentinel64;
        if (Accepted(stream, stream.SerializeFixed(ref fixed64, 48, 16, -100000000000, +100000000000), ref first, ref refusedBits, Ranged, "read fixed Q48.16 long", trace))
        {
            Check(fixed64 >= -100000000000L * 65536 && fixed64 <= 100000000000L * 65536, "read fixed Q48.16 long: value out of range");
            trace.Mix((ulong)fixed64);
        }
        else
        {
            Check(fixed64 == sentinel64, "read fixed Q48.16 long: a refused read wrote its destination");
        }

        Int128Value sentinelI128 = SentinelI128(pattern);
        Int128Value wide = sentinelI128;
        Int128Value wideMin = (Int128Value)(-Wide) * (Int128Value)65536;
        Int128Value wideMax = (Int128Value)Wide * (Int128Value)65536;
        if (Accepted(stream, stream.SerializeFixed(ref wide, 112, 16, -Wide, +Wide), ref first, ref refusedBits, Ranged, "read fixed Q112.16 int128", trace))
        {
            Check(wide >= wideMin && wide <= wideMax, "read fixed Q112.16 int128: value out of range");
            trace.Mix(wide.Lo);
            trace.Mix(wide.Hi);
        }
        else
        {
            Check(wide == sentinelI128, "read fixed Q112.16 int128: a refused read wrote its destination");
        }

        short sentinel16 = SentinelI16(pattern);
        short fixed16 = sentinel16;
        if (Accepted(stream, stream.SerializeFixed(ref fixed16, 8, 8, -100, +100), ref first, ref refusedBits, Ranged, "read fixed Q8.8 short", trace))
        {
            Check(fixed16 >= -100 * 256 && fixed16 <= 100 * 256, "read fixed Q8.8 short: value out of range");
            trace.Mix((ulong)fixed16);
        }
        else
        {
            Check(fixed16 == sentinel16, "read fixed Q8.8 short: a refused read wrote its destination");
        }

        uint sentinelU32 = SentinelU32(pattern);
        uint ufixed32 = sentinelU32;
        if (Accepted(stream, stream.SerializeFixed(ref ufixed32, 16, 16, 0, 60000), ref first, ref refusedBits, Ranged, "read fixed Q16.16 uint", trace))
        {
            Check(ufixed32 <= 60000U * 65536, "read fixed Q16.16 uint: value out of range");
            trace.Mix(ufixed32);
        }
        else
        {
            Check(ufixed32 == sentinelU32, "read fixed Q16.16 uint: a refused read wrote its destination");
        }

        ulong sentinelU64 = SentinelU64(pattern);
        ulong ufixed64 = sentinelU64;
        if (Accepted(stream, stream.SerializeFixed(ref ufixed64, 48, 16, 0, 1000000000), ref first, ref refusedBits, Ranged, "read fixed Q48.16 ulong", trace))
        {
            Check(ufixed64 <= 1000000000UL * 65536, "read fixed Q48.16 ulong: value out of range");
            trace.Mix(ufixed64);
        }
        else
        {
            Check(ufixed64 == sentinelU64, "read fixed Q48.16 ulong: a refused read wrote its destination");
        }

        UInt128Value sentinelU128 = SentinelU128(pattern);
        UInt128Value ufixed128 = sentinelU128;
        if (Accepted(stream, stream.SerializeFixed(ref ufixed128, 112, 16, 0, 2 * Wide), ref first, ref refusedBits, Ranged, "read fixed Q112.16 uint128", trace))
        {
            Check(ufixed128 <= ((UInt128Value)(ulong)(2 * Wide) << 16), "read fixed Q112.16 uint128: value out of range");
            trace.Mix(ufixed128.Lo);
            trace.Mix(ufixed128.Hi);
        }
        else
        {
            Check(ufixed128 == sentinelU128, "read fixed Q112.16 uint128: a refused read wrote its destination");
        }

        // ranged 128 bit integers, the bound width varying with param so the run walks
        // every group structure: one group, two, three and four. hostile bytes must
        // decode inside the bounds or fail the read: never clamp, never wrap.
        Int128Value bound128 = Int128Value.One << (20 + param * 7); // 2^20 .. 2^125
        Int128Value ranged128 = sentinelI128;
        if (Accepted(stream, stream.SerializeInt128(ref ranged128, -bound128, bound128), ref first, ref refusedBits, Ranged, "read int128 ranged", trace))
        {
            Check(ranged128 >= -bound128 && ranged128 <= bound128, "read int128 ranged: value out of range");
            trace.Mix(ranged128.Lo);
            trace.Mix(ranged128.Hi);
        }
        else
        {
            Check(ranged128 == sentinelI128, "read int128 ranged: a refused read wrote its destination");
        }

        Int128Value full128 = sentinelI128;
        if (Accepted(stream, stream.SerializeInt128(ref full128, Int128Value.MinValue, Int128Value.MaxValue), ref first, ref refusedBits, PastEnd, "read int128 full range", trace))
        {
            trace.Mix(full128.Lo);
            trace.Mix(full128.Hi);
        }
        else
        {
            Check(full128 == sentinelI128, "read int128 full range: a refused read wrote its destination");
        }
    }

    // ---- pass 3: differential round trip --------------------------------------

    /// <summary>
    /// Hands out bytes from the fuzz input, wrapping around when exhausted. Every
    /// round trip pass regenerates the identical value sequence from a fresh pool, so
    /// nothing needs to be stored between passes.
    /// </summary>
    private sealed class ValuePool
    {
        private readonly byte[] _data;
        private int _index;

        public ValuePool(byte[] data)
        {
            _data = data;
        }

        public byte NextByte()
        {
            if (_data.Length == 0)
            {
                return 0;
            }
            if (_index >= _data.Length)
            {
                _index = 0;
            }
            return _data[_index++];
        }

        public uint NextUInt32()
        {
            uint value = 0;
            for (int i = 0; i < 4; i++)
            {
                value = (value << 8) | NextByte();
            }
            return value;
        }

        public ulong NextUInt64()
        {
            return ((ulong)NextUInt32() << 32) | NextUInt32();
        }

        public UInt128Value NextUInt128()
        {
            ulong hi = NextUInt64();
            ulong lo = NextUInt64();
            return new UInt128Value(hi, lo);
        }
    }

    private static string Kind(IBitStream stream) =>
        stream.IsReading ? "read" : stream is MeasureStream ? "measure" : "write";

    /// <summary>A serialize call in the round trip must succeed on every stream: the
    /// values are in contract, and the reader reads only what the writer wrote.</summary>
    private static void Ok(IBitStream stream, bool ok, string op)
    {
        Check(ok, "roundtrip " + op + ": the " + Kind(stream) + " call failed with " + stream.Error);
    }

    private static void RoundTrip(ReadOnlySpan<byte> ops, byte[] payload)
    {
        // worst case is ~300 bytes per op (a 241 byte bytes field plus alignment and
        // the wide integer group), so 32 ops fit comfortably
        byte[] writeBuffer = new byte[WriteBufferSize];
        Array.Fill(writeBuffer, (byte)0xAA);
        long[] writePositions = new long[NumOps + 1];
        long[] measurePositions = new long[NumOps + 1];
        long[] readPositions = new long[NumOps + 1];

        WriteStream writeStream = new WriteStream(writeBuffer);
        FuzzRoundTrip(writeStream, ops, new ValuePool(payload), writePositions);
        writeStream.Flush();

        int written8 = (int)writeStream.BytesProcessed;
        int wordBoundary = (written8 + 7) & ~7;
        for (int k = written8; k < wordBoundary; k++)
        {
            Check(writeBuffer[k] == 0x00, "roundtrip flush: trailing byte " + k + " inside flushed word is nonzero");
        }
        if (ControlEnabled("canary"))
        {
            writeBuffer[wordBoundary] ^= 0xFF;
        }
        for (int k = 0; k < CanaryBytes; k++)
        {
            Check(writeBuffer[wordBoundary + k] == 0xAA,
                "roundtrip canary: canary byte " + k + " past flushed word boundary was overwritten");
        }

        MeasureStream measureStream = new MeasureStream();
        FuzzRoundTrip(measureStream, ops, new ValuePool(payload), measurePositions);
        for (int i = 0; i < ops.Length; i++)
        {
            long written = writePositions[i + 1] - writePositions[i];
            long measured = measurePositions[i + 1] - measurePositions[i];
            Check(measured >= written, "roundtrip measure: op " + i + " (select " + (ops[i] & 15) + ") measured " + measured + " bits, wrote " + written);
        }
        Check(measureStream.BitsProcessed >= writeStream.BitsProcessed, "roundtrip measure: the measure is smaller than the write");

        // the 16 KB buffer extends well past the written bytes
        ReadStream readStream = new ReadStream(writeBuffer, written8);
        FuzzRoundTrip(readStream, ops, new ValuePool(payload), readPositions);
        for (int i = 0; i <= ops.Length; i++)
        {
            Check(readPositions[i] == writePositions[i], "roundtrip position: after op " + (i - 1) + " the reader is at bit " + readPositions[i] + ", the writer was at " + writePositions[i]);
        }
        Check(readStream.SerializeEnd(), "roundtrip end: the read did not end where the writer stopped (" + readStream.Error + ")");

        // one byte more than the writer reported is trailing data, refused at the end
        writeBuffer[written8] = 0;
        ReadStream longerStream = new ReadStream(writeBuffer, written8 + 1);
        FuzzRoundTrip(longerStream, ops, new ValuePool(payload), readPositions);
        bool longerAccepted = ControlEnabled("trailing") || longerStream.SerializeEnd();
        Check(!longerAccepted, "roundtrip end: a byte past the writer's end was accepted");
        Check(longerStream.Error == SerializeError.TrailingData, "roundtrip end: a byte past the writer's end was " + longerStream.Error + ", not trailing_data");
    }

    private static void FuzzRoundTrip(IBitStream stream, ReadOnlySpan<byte> ops, ValuePool pool, long[] positions)
    {
        bool writing = stream.IsWriting;
        positions[0] = stream.BitsProcessed;

        for (int i = 0; i < ops.Length; i++)
        {
            int select = ops[i] & 15;
            int param = ops[i] >> 4; // [0,15]

            switch (select)
            {
                case 0:
                case 1:
                {
                    int bits = select == 0 ? param + 1 : param + 17; // [1,32]
                    uint mask = bits == 32 ? 0xFFFFFFFF : (1U << bits) - 1;
                    uint expected = pool.NextUInt32() & mask;
                    uint value = writing ? expected : 0;
                    Ok(stream, stream.SerializeBits(ref value, bits), "bits");
                    if (stream.IsReading && ControlEnabled("roundtrip"))
                    {
                        value ^= 1u;
                    }
                    Check(value == expected, "roundtrip bits: wrote " + expected + ", read " + value + " (roundtrip negative control)");
                    break;
                }

                case 2:
                {
                    int expected = -100 + (int)(pool.NextUInt32() % 201);
                    int value = writing ? expected : 0;
                    Ok(stream, stream.SerializeInt(ref value, -100, +100), "int [-100,100]");
                    Check(value == expected, "roundtrip int [-100,100]: wrote " + expected + ", read " + value);
                    break;
                }

                case 3:
                    RoundTripWide(stream, param, pool);
                    break;

                case 4:
                {
                    bool expected = (pool.NextByte() & 1) != 0;
                    bool value = writing && expected;
                    Ok(stream, stream.SerializeBool(ref value), "bool");
                    Check(value == expected, "roundtrip bool: wrote " + expected + ", read " + value);
                    break;
                }

                case 5:
                {
                    // arbitrary FINITE bit patterns, -0 and subnormals included, round trip
                    // bit exact. A non-finite pattern is non-conforming on write (asserted),
                    // so its exponent is cleared, keeping the sign and mantissa entropy as a
                    // subnormal. Hostile non-finite bytes reach the reader in pass 1.
                    uint raw = pool.NextUInt32();
                    uint expected = (raw & 0x7FFFFFFF) < 0x7F800000 ? raw : raw & 0x807FFFFF;
                    float value = writing ? BitConverter.UInt32BitsToSingle(expected) : 0.0f;
                    Ok(stream, stream.SerializeFloat(ref value), "float");
                    Check(BitConverter.SingleToUInt32Bits(value) == expected, "roundtrip float: bits changed");
                    break;
                }

                case 6:
                {
                    ulong raw = pool.NextUInt64();
                    ulong expected = (raw & 0x7FFFFFFFFFFFFFFF) < 0x7FF0000000000000 ? raw : raw & 0x800FFFFFFFFFFFFF;
                    double value = writing ? BitConverter.UInt64BitsToDouble(expected) : 0.0;
                    Ok(stream, stream.SerializeDouble(ref value), "double");
                    Check(BitConverter.DoubleToUInt64Bits(value) == expected, "roundtrip double: bits changed");
                    break;
                }

                case 7:
                {
                    // arbitrary FINITE patterns: out of range values clamp into [min,max] on
                    // write, in range values round trip within the resolution
                    uint raw = pool.NextUInt32();
                    uint expectedBits = (raw & 0x7FFFFFFF) < 0x7F800000 ? raw : raw & 0x807FFFFF;
                    float expected = BitConverter.UInt32BitsToSingle(expectedBits);
                    float value = writing ? expected : 0.0f;
                    Ok(stream, stream.SerializeCompressedFloat(ref value, -10.0f, +10.0f, 0.01f), "compressed float");
                    if (!writing)
                    {
                        Check(value >= -10.001f && value <= +10.001f, "roundtrip compressed float: read outside [min,max]");
                        if (expected >= -10.0f && expected <= +10.0f)
                        {
                            Check(Math.Abs(value - expected) <= 0.011f, "roundtrip compressed float: wrote " + expected + ", read " + value);
                        }
                    }

                    // the precomputed form must agree with the derived parameters
                    SerializeUtil.CompressedFloatParams(-10.0f, +10.0f, 0.01f, out uint maxIntegerValue, out int cbits, out float delta);
                    uint raw2 = pool.NextUInt32();
                    uint expectedBits2 = (raw2 & 0x7FFFFFFF) < 0x7F800000 ? raw2 : raw2 & 0x807FFFFF;
                    float expected2 = BitConverter.UInt32BitsToSingle(expectedBits2);
                    float value2 = writing ? expected2 : 0.0f;
                    Ok(stream, stream.SerializeCompressedFloatPrecomputed(ref value2, maxIntegerValue, cbits, delta, -10.0f), "compressed float precomputed");
                    if (!writing)
                    {
                        Check(value2 >= -10.001f && value2 <= +10.001f, "roundtrip compressed float precomputed: read outside [min,max]");
                        if (expected2 >= -10.0f && expected2 <= +10.0f)
                        {
                            Check(Math.Abs(value2 - expected2) <= 0.011f, "roundtrip compressed float precomputed: wrote " + expected2 + ", read " + value2);
                        }
                    }
                    break;
                }

                case 8:
                {
                    ulong expected = pool.NextUInt64();
                    ulong value = writing ? expected : 0;
                    Ok(stream, stream.SerializeUInt64(ref value), "uint64");
                    Check(value == expected, "roundtrip uint64: wrote " + expected + ", read " + value);

                    UInt128Value expected128 = pool.NextUInt128();
                    UInt128Value value128 = writing ? expected128 : UInt128Value.Zero;
                    Ok(stream, stream.SerializeUInt128(ref value128), "uint128");
                    Check(value128 == expected128, "roundtrip uint128: wrote " + expected128 + ", read " + value128);

                    int bits64 = param * 4 + 4; // [4,64]
                    ulong mask64 = bits64 == 64 ? ulong.MaxValue : (1UL << bits64) - 1;
                    ulong expectedBits64 = pool.NextUInt64() & mask64;
                    ulong valueBits64 = writing ? expectedBits64 : 0;
                    Ok(stream, stream.SerializeBits64(ref valueBits64, bits64), "bits64");
                    Check(valueBits64 == expectedBits64, "roundtrip bits64: wrote " + expectedBits64 + ", read " + valueBits64);
                    break;
                }

                case 9:
                {
                    int numBytes = param * 16 + 1; // [1,241]
                    byte[] expected = new byte[numBytes];
                    for (int j = 0; j < numBytes; j++)
                    {
                        expected[j] = pool.NextByte();
                    }
                    byte[] value = writing ? (byte[])expected.Clone() : new byte[numBytes];
                    Ok(stream, stream.SerializeBytes(value), "bytes");
                    Check(value.AsSpan().SequenceEqual(expected), "roundtrip bytes: contents changed");
                    break;
                }

                case 10:
                {
                    // ASCII: the payload is well-formed UTF-8 by the writer's contract
                    // (asserted, and asserts are live here), and the reader refuses
                    // malformed payloads, so the round trip generates conforming content.
                    // Arbitrary bytes reach the reader in pass 1.
                    int length = pool.NextByte() % 31;
                    StringBuilder builder = new StringBuilder(length);
                    for (int j = 0; j < length; j++)
                    {
                        int c = pool.NextByte() & 0x7F;
                        builder.Append(c != 0 ? (char)c : ' ');
                    }
                    string expected = builder.ToString();
                    string value = writing ? expected : "";
                    Ok(stream, stream.SerializeString(ref value, 32), "string");
                    Check(value == expected, "roundtrip string: wrote \"" + expected + "\", read \"" + value + "\"");
                    break;
                }

                case 11:
                {
                    // real text: random Unicode scalar values, so every UTF-8 sequence length
                    // and every plane reaches the writer and must come back exactly. NUL and
                    // the surrogate block are not scalar text and are replaced
                    int characters = pool.NextByte() % 8;
                    StringBuilder builder = new StringBuilder();
                    for (int j = 0; j < characters; j++)
                    {
                        int code = (int)(pool.NextUInt32() % 0x110000);
                        if (code == 0 || (code >= 0xD800 && code <= 0xDFFF))
                        {
                            code = 0x7881; // 碁
                        }
                        builder.Append(char.ConvertFromUtf32(code));
                    }
                    string expected = builder.ToString();
                    string value = writing ? expected : "";
                    Ok(stream, stream.SerializeString(ref value, 40), "unicode string");
                    Check(value == expected, "roundtrip unicode string: text changed");
                    break;
                }

                case 12:
                    Ok(stream, stream.SerializeAlign(), "align");
                    break;

                case 13:
                {
                    int previous = param * 1000;
                    int expected = previous + 1 + (int)(pool.NextUInt32() % 1000000); // strictly greater than previous
                    int value = writing ? expected : 0;
                    Ok(stream, stream.SerializeIntRelative(previous, ref value), "int_relative");
                    Check(value == expected, "roundtrip int_relative: wrote " + expected + ", read " + value);
                    break;
                }

                case 14:
                {
                    int max = (param + 1) * 1000;
                    int expected = (int)(pool.NextUInt32() % (uint)(max + 1));
                    int value = writing ? expected : 0;
                    Ok(stream, stream.SerializeInt(ref value, 0, max), "int [0,max]");
                    Check(value == expected, "roundtrip int [0,max]: wrote " + expected + ", read " + value);
                    break;
                }

                case 15:
                {
                    byte expected8 = pool.NextByte();
                    ushort expected16 = (ushort)pool.NextUInt32();
                    uint expected32 = pool.NextUInt32();
                    byte value8 = writing ? expected8 : (byte)0;
                    ushort value16 = writing ? expected16 : (ushort)0;
                    uint value32 = writing ? expected32 : 0;
                    Ok(stream, stream.SerializeByte(ref value8), "uint8");
                    Ok(stream, stream.SerializeUInt16(ref value16), "uint16");
                    Ok(stream, stream.SerializeUInt32(ref value32), "uint32");
                    Check(value8 == expected8, "roundtrip uint8: wrote " + expected8 + ", read " + value8);
                    Check(value16 == expected16, "roundtrip uint16: wrote " + expected16 + ", read " + value16);
                    Check(value32 == expected32, "roundtrip uint32: wrote " + expected32 + ", read " + value32);
                    break;
                }
            }

            positions[i + 1] = stream.BitsProcessed;
        }
    }

    /// <summary>The wide integers and every fixed point storage width: values
    /// generated uniformly inside the bounds must round trip exactly.</summary>
    private static void RoundTripWide(IBitStream stream, int param, ValuePool pool)
    {
        bool writing = stream.IsWriting;

        int expected = (int)pool.NextUInt32();
        int value = writing ? expected : 0;
        Ok(stream, stream.SerializeInt(ref value, int.MinValue, int.MaxValue), "int full range");
        Check(value == expected, "roundtrip int full range: wrote " + expected + ", read " + value);

        long expected64 = (long)pool.NextUInt64();
        long value64 = writing ? expected64 : 0;
        Ok(stream, stream.SerializeInt64(ref value64, long.MinValue, long.MaxValue), "int64 full range");
        Check(value64 == expected64, "roundtrip int64 full range: wrote " + expected64 + ", read " + value64);

        long bound = (long)(param + 1) << 35;
        ulong span = (ulong)bound * 2 + 1;
        long expectedRanged = -bound + (long)(pool.NextUInt64() % span);
        long ranged64 = writing ? expectedRanged : 0;
        Ok(stream, stream.SerializeInt64(ref ranged64, -bound, +bound), "int64 ranged");
        Check(ranged64 == expectedRanged, "roundtrip int64 ranged: wrote " + expectedRanged + ", read " + ranged64);

        // signed Q16.16 in [-1000,+1000] whole units
        int expectedFixed32 = unchecked((int)((uint)(-1000 * 65536) + pool.NextUInt32() % (2000U * 65536 + 1)));
        int fixed32 = writing ? expectedFixed32 : 0;
        Ok(stream, stream.SerializeFixed(ref fixed32, 16, 16, -1000, +1000), "fixed Q16.16 int");
        Check(fixed32 == expectedFixed32, "roundtrip fixed Q16.16 int: wrote " + expectedFixed32 + ", read " + fixed32);

        // signed Q48.16 in [-1e11,+1e11] whole units
        ulong fixed64Range = 200000000000UL * 65536;
        long expectedFixed64 = unchecked((long)((ulong)(-100000000000L * 65536) + pool.NextUInt64() % (fixed64Range + 1)));
        long fixed64 = writing ? expectedFixed64 : 0;
        Ok(stream, stream.SerializeFixed(ref fixed64, 48, 16, -100000000000, +100000000000), "fixed Q48.16 long");
        Check(fixed64 == expectedFixed64, "roundtrip fixed Q48.16 long: wrote " + expectedFixed64 + ", read " + fixed64);

        // signed Q112.16 in +-2^60 whole units: a raw range of 2^77, past 64 bits
        UInt128Value wideRange = (UInt128Value)(ulong)Wide << 17;
        UInt128Value wideRawMin = (UInt128Value)(Int128Value)(-Wide) << 16;
        Int128Value expectedWide = (Int128Value)(wideRawMin + pool.NextUInt128() % (wideRange + 1));
        Int128Value wide = writing ? expectedWide : Int128Value.Zero;
        Ok(stream, stream.SerializeFixed(ref wide, 112, 16, -Wide, +Wide), "fixed Q112.16 int128");
        Check(wide == expectedWide, "roundtrip fixed Q112.16 int128: wrote " + expectedWide + ", read " + wide);

        // signed Q8.8 in [-100,+100]
        short expectedFixed16 = (short)(-25600 + (int)(pool.NextUInt32() % 51201));
        short fixed16 = writing ? expectedFixed16 : (short)0;
        Ok(stream, stream.SerializeFixed(ref fixed16, 8, 8, -100, +100), "fixed Q8.8 short");
        Check(fixed16 == expectedFixed16, "roundtrip fixed Q8.8 short: wrote " + expectedFixed16 + ", read " + fixed16);

        // unsigned Q16.16 in [0,60000]
        uint expectedUFixed32 = pool.NextUInt32() % (60000U * 65536 + 1);
        uint ufixed32 = writing ? expectedUFixed32 : 0;
        Ok(stream, stream.SerializeFixed(ref ufixed32, 16, 16, 0, 60000), "fixed Q16.16 uint");
        Check(ufixed32 == expectedUFixed32, "roundtrip fixed Q16.16 uint: wrote " + expectedUFixed32 + ", read " + ufixed32);

        // unsigned Q48.16 in [0,1e9]
        ulong expectedUFixed64 = pool.NextUInt64() % (1000000000UL * 65536 + 1);
        ulong ufixed64 = writing ? expectedUFixed64 : 0;
        Ok(stream, stream.SerializeFixed(ref ufixed64, 48, 16, 0, 1000000000), "fixed Q48.16 ulong");
        Check(ufixed64 == expectedUFixed64, "roundtrip fixed Q48.16 ulong: wrote " + expectedUFixed64 + ", read " + ufixed64);

        // unsigned Q112.16 in [0,2^61]: a raw range of 2^77
        UInt128Value expectedUFixed128 = pool.NextUInt128() % (((UInt128Value)(ulong)(2 * Wide) << 16) + 1);
        UInt128Value ufixed128 = writing ? expectedUFixed128 : UInt128Value.Zero;
        Ok(stream, stream.SerializeFixed(ref ufixed128, 112, 16, 0, 2 * Wide), "fixed Q112.16 uint128");
        Check(ufixed128 == expectedUFixed128, "roundtrip fixed Q112.16 uint128: wrote " + expectedUFixed128 + ", read " + ufixed128);

        // ranged 128 bit integers across every group structure (2^20 .. 2^125)
        Int128Value bound128 = Int128Value.One << (20 + param * 7);
        UInt128Value span128 = (UInt128Value)bound128 * 2 + 1;
        Int128Value expectedRanged128 = -bound128 + (Int128Value)(pool.NextUInt128() % span128);
        Int128Value ranged128 = writing ? expectedRanged128 : Int128Value.Zero;
        Ok(stream, stream.SerializeInt128(ref ranged128, -bound128, bound128), "int128 ranged");
        Check(ranged128 == expectedRanged128, "roundtrip int128 ranged: wrote " + expectedRanged128 + ", read " + ranged128);

        Int128Value expectedFull128 = (Int128Value)pool.NextUInt128();
        Int128Value full128 = writing ? expectedFull128 : Int128Value.Zero;
        Ok(stream, stream.SerializeInt128(ref full128, Int128Value.MinValue, Int128Value.MaxValue), "int128 full range");
        Check(full128 == expectedFull128, "roundtrip int128 full range: wrote " + expectedFull128 + ", read " + full128);
    }
}
