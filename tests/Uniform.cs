/*
    Uniform.cs

    IMPLEMENTING.md's uniform rules (reference v2.1.0, and v2.1.1's U6/U9/U15 rulings) that this port broke before
    2.1.0, one test per rule, each citing its number, plus the 2026-10-27 audit's batch
    finding. The rules this port already kept are proven where they always were
    (test_write_contract_asserts, test_api_misuse_asserts, test_serialize_reject,
    test_refusal_names).
*/

using System;
#if DEBUG
using System.Diagnostics;
#endif

namespace Serialize.Tests;

internal static partial class Program
{
    /// <summary>Runs the action and reports whether no Debug.Assert fired. In a
    /// release build there is nothing to fire: the action runs and the answer is
    /// true.</summary>
    private static bool RunsWithoutAssert(Action action)
    {
#if DEBUG
        return !AssertFires(action);
#else
        action();
        return true;
#endif
    }

    /// <summary>A read refusing a bad declaration: no assert, false, value_out_of_range
    /// latched, no bit consumed, the destination untouched, and terminal.</summary>
    private delegate bool ReadCall(ReadStream stream);

    private delegate bool BatchCall(ref ReadBatch batch);

    private static void CheckDeclarationRefused(string what, ReadCall call)
    {
        ReadStream stream = new ReadStream(new byte[32], 16);
        bool ok = true;
        Check(RunsWithoutAssert(() => ok = call(stream)), $"{what}: a read must never assert (U7)");
        Check(!ok, $"{what}: a read must refuse");
        Check(stream.Error == SerializeError.ValueOutOfRange,
            $"{what}: a read must refuse value_out_of_range (U16), got {stream.Error}");
        Check(stream.BitsProcessed == 0, $"{what}: refused before any bits move, consumed {stream.BitsProcessed}");
        uint after = 0xFFFFFFFF;
        Check(!stream.SerializeBits(ref after, 8) && after == 0xFFFFFFFF, $"{what}: the refusal is terminal");

        // the failure state is checked first: a stream that already failed keeps its
        // first reason
        ReadStream failed = new ReadStream(new byte[32], 0);
        uint v = 0;
        Check(!failed.SerializeBits(ref v, 8), "a read past the end refuses");
        Check(RunsWithoutAssert(() => ok = call(failed)), $"{what}: a read on a failed stream must never assert");
        Check(!ok && failed.Error == SerializeError.PastEnd,
            $"{what}: a failed stream keeps its first reason, got {failed.Error}");
    }

    private static void CheckBatchDeclarationRefused(string what, BatchCall call)
    {
        ReadStream stream = new ReadStream(new byte[32], 16);
        ReadBatch batch = stream.BeginBatch();
        bool ok;
#if DEBUG
        TraceListener[] saved = new TraceListener[Trace.Listeners.Count];
        Trace.Listeners.CopyTo(saved, 0);
        Trace.Listeners.Clear();
        Trace.Listeners.Add(new ThrowingTraceListener());
        try
        {
            ok = call(ref batch);
        }
        catch (AssertFiredException)
        {
            Check(false, $"{what}: a batch read must never assert (U7)");
            return;
        }
        finally
        {
            Trace.Listeners.Clear();
            Trace.Listeners.AddRange(saved);
        }
#else
        ok = call(ref batch);
#endif
        Check(!ok && batch.Error == SerializeError.ValueOutOfRange,
            $"{what}: a batch read must refuse value_out_of_range (U16), got {batch.Error}");
        Check(batch.BitsProcessed == 0, $"{what}: a batch refuses before any bits move");
        batch.End();
        Check(stream.Error == SerializeError.ValueOutOfRange, $"{what}: End carries the refusal to the stream");
    }

    private static void TestReadDeclarationsRefuse()
    {
        // IMPLEMENTING.md U7 and U16: a caller declaration that cannot be right is
        // refused on read as value_out_of_range, in every build, before any bits
        // move, and never asserted or thrown. Each was a Debug.Assert on read before
        // 2.1.0, and in release a rewound cursor and a throw (the audit's R4b).
        foreach (int bits in new[] { 0, 33, -8, int.MinValue, int.MaxValue })
        {
            CheckDeclarationRefused($"bits {bits}", s => { uint v = 7; bool r = s.SerializeBits(ref v, bits); Check(v == 7, "untouched"); return r; });
            CheckBatchDeclarationRefused($"batch bits {bits}", (ref ReadBatch b) => { uint v = 7; return b.SerializeBits(ref v, bits); });
        }
        foreach (int bits in new[] { 0, 65, -8 })
        {
            CheckDeclarationRefused($"bits64 {bits}", s => { ulong v = 7; return s.SerializeBits64(ref v, bits); });
            CheckBatchDeclarationRefused($"batch bits64 {bits}", (ref ReadBatch b) => { ulong v = 7; return b.SerializeBits64(ref v, bits); });
        }
        CheckDeclarationRefused("int min > max", s => { int v = 7; bool r = s.SerializeInt(ref v, 10, 5); Check(v == 7, "untouched"); return r; });
        CheckBatchDeclarationRefused("batch int min > max", (ref ReadBatch b) => { int v = 7; return b.SerializeInt(ref v, 10, 5); });
        CheckDeclarationRefused("int64 min > max", s => { long v = 7; return s.SerializeInt64(ref v, 10, 5); });
        CheckBatchDeclarationRefused("batch int64 min > max", (ref ReadBatch b) => { long v = 7; return b.SerializeInt64(ref v, 10, 5); });
        CheckDeclarationRefused("int128 min > max", s => { Int128Value v = 7; return s.SerializeInt128(ref v, 10, 5); });
        CheckBatchDeclarationRefused("batch int128 min > max", (ref ReadBatch b) => { Int128Value v = 7; return b.SerializeInt128(ref v, 10, 5); });

        // compressed float declarations CompressedFloatParams would assert on
        float[][] badFloats =
        {
            new[] { 10.0f, 0.0f, 0.01f },                    // min > max
            new[] { 1.0f, 1.0f, 0.01f },                     // min == max
            new[] { 0.0f, 1.0f, 0.0f },                      // resolution 0
            new[] { 0.0f, 1.0f, -1.0f },                     // negative resolution
            new[] { float.NaN, 1.0f, 0.01f },                // NaN bound
            new[] { 0.0f, 1.0f, float.NaN },                 // NaN resolution
            new[] { -float.MaxValue, float.MaxValue, 1.0f }, // the range overflows
            new[] { 0.0f, 1.0e30f, 1.0e-30f },               // the step count overflows
        };
        foreach (float[] f in badFloats)
        {
            float min = f[0], max = f[1], resolution = f[2];
            CheckDeclarationRefused($"compressed float [{min},{max}] / {resolution}",
                s => { float v = 0.5f; bool r = s.SerializeCompressedFloat(ref v, min, max, resolution); Check(v == 0.5f, "untouched"); return r; });
            CheckBatchDeclarationRefused($"batch compressed float [{min},{max}] / {resolution}",
                (ref ReadBatch b) => { float v = 0.5f; return b.SerializeCompressedFloat(ref v, min, max, resolution); });
        }

        // precomputed constants that cannot be right (U16)
        (uint maxIntegerValue, int bits, float delta)[] badPrecomputed =
        {
            (1000, 11, 10.0f),           // bits disagree with the step count
            (1000, -8, 10.0f),           // the audit's R4b
            (0, 1, 1.0f),                // no steps
            (4294967295u, 32, 1.0f),     // above 4294967040
            (1000, 10, 0.0f),            // delta zero
            (1000, 10, -10.0f),          // delta negative
            (1000, 10, float.NaN),       // delta NaN
            (1000, 10, float.PositiveInfinity),
        };
        foreach ((uint maxIntegerValue, int bits, float delta) in badPrecomputed)
        {
            CheckDeclarationRefused($"precomputed ({maxIntegerValue},{bits},{delta})",
                s => { float v = 0.5f; return s.SerializeCompressedFloatPrecomputed(ref v, maxIntegerValue, bits, delta, 0.0f); });
            CheckBatchDeclarationRefused($"batch precomputed ({maxIntegerValue},{bits},{delta})",
                (ref ReadBatch b) => { float v = 0.5f; return b.SerializeCompressedFloatPrecomputed(ref v, maxIntegerValue, bits, delta, 0.0f); });
        }

        // fixed point declarations that do not fit their Q format
        CheckDeclarationRefused("fixed Q16.8 in 64 bits", s => { long v = 7; return s.SerializeFixed(ref v, 16, 8, 0, 100); });
        CheckDeclarationRefused("fixed min > max", s => { int v = 7; return s.SerializeFixed(ref v, 16, 16, 100, 0); });
        CheckDeclarationRefused("fixed bound past the Q format", s => { short v = 7; return s.SerializeFixed(ref v, 8, 8, 0, 1000); });
        CheckDeclarationRefused("fixed negative fraction bits", s => { int v = 7; return s.SerializeFixed(ref v, 33, -1, 0, 1); });
        CheckDeclarationRefused("fixed unsigned negative bound", s => { uint v = 7; return s.SerializeFixed(ref v, 16, 16, -1, 1); });
        CheckDeclarationRefused("fixed 128 Q8.8", s => { Int128Value v = 7; return s.SerializeFixed(ref v, 8, 8, 0, 1); });
        CheckBatchDeclarationRefused("batch fixed Q16.8 in 64 bits", (ref ReadBatch b) => { long v = 7; return b.SerializeFixed(ref v, 16, 8, 0, 100); });

        // int_relative previous outside its domain, and a string buffer below 1
        CheckDeclarationRefused("int_relative previous -1", s => { int v = 7; bool r = s.SerializeIntRelative(-1, ref v); Check(v == 7, "untouched"); return r; });
        CheckBatchDeclarationRefused("batch int_relative previous -1", (ref ReadBatch b) => { int v = 7; return b.SerializeIntRelative(-1, ref v); });
        CheckDeclarationRefused("string buffer 0", s => { string v = "keep"; bool r = s.SerializeString(ref v, 0); Check(v == "keep", "untouched"); return r; });

        // a good declaration still reads: the refusals cost nothing to correct code
        {
            ReadStream stream = new ReadStream(new byte[16], 8);
            uint v = 0;
            Check(stream.SerializeBits(ref v, 32) && stream.SerializeBits(ref v, 1), "good bit counts still read");
            int i = 0;
            Check(stream.SerializeInt(ref i, 5, 5) && i == 5, "a degenerate range is not a bad declaration");
        }
    }

    private static void TestReadStreamBytesOutsideBuffer()
    {
        // IMPLEMENTING.md U7: a byte count outside the buffer is caller misuse on a
        // read stream, refused at initialization, never a throw on a later read (the
        // audit's R4c: a byte read threw ArgumentOutOfRangeException, and a negative
        // count read as an empty, healthy stream)
        foreach (int bytes in new[] { -4, -1, 5, 64, int.MaxValue, int.MinValue })
        {
            ReadStream stream = null!;
            Check(RunsWithoutAssert(() => stream = new ReadStream(new byte[4], bytes)), $"bytes {bytes}: must not assert");
            Check(stream.Error == SerializeError.ValueOutOfRange,
                $"bytes {bytes}: initialization must latch value_out_of_range, got {stream.Error}");
            byte[] dst = new byte[16];
            Check(!stream.SerializeBytes(dst), $"bytes {bytes}: a byte read refuses, never throws");
            Check(!stream.SerializeEnd(), $"bytes {bytes}: the end refuses");
            Check(stream.Error == SerializeError.ValueOutOfRange, $"bytes {bytes}: the first reason is kept");

            // Reset follows the same rule, and a good Reset clears it (U13)
            ReadStream reset = new ReadStream(new byte[4]);
            Check(RunsWithoutAssert(() => reset.Reset(new byte[4], bytes)), $"Reset bytes {bytes}: must not assert");
            Check(reset.Error == SerializeError.ValueOutOfRange, $"Reset bytes {bytes}: refused");
            reset.Reset(new byte[4], 4);
            Check(reset.Ok, "a good Reset clears the latch");
        }
        Check(new ReadStream(new byte[4], 0).Ok && new ReadStream(new byte[4], 4).Ok, "0 and the whole buffer are in range");
    }

    private static void TestPublicFail()
    {
        // IMPLEMENTING.md U14: a public Fail. On a read stream it latches the stated
        // reason, the first wins, and none or a value outside the closed list records
        // rejected; on write and measure it records nothing and returns false, in
        // every build, never asserting (U6, U9)
        {
            ReadStream stream = new ReadStream(new byte[8]);
            Check(!stream.Fail(SerializeError.NonCanonical), "Fail returns false");
            Check(stream.Error == SerializeError.NonCanonical, $"Fail latches its reason, got {stream.Error}");
            Check(!stream.Fail(SerializeError.PastEnd) && stream.Error == SerializeError.NonCanonical, "the first reason wins");
        }
        foreach (SerializeError odd in new[] { SerializeError.None, (SerializeError)10, (SerializeError)(-1), (SerializeError)int.MaxValue })
        {
            ReadStream stream = new ReadStream(new byte[8]);
            IBitStream generic = stream;
            Check(!generic.Fail(odd), "Fail returns false");
            Check(stream.Error == SerializeError.Rejected,
                $"Fail({(int)odd}) must record rejected, never none or an unknown reason, got {stream.Error}");
            uint v = 0;
            Check(!stream.SerializeBits(ref v, 1) && stream.Error == SerializeError.Rejected,
                "a later read is refused as an echo, not relabelled past_end");

            ReadStream batched = new ReadStream(new byte[8]);
            ReadBatch batch = batched.BeginBatch();
            Check(!batch.Fail(odd) && batch.Error == SerializeError.Rejected, "batch Fail records rejected");
            batch.End();
            Check(batched.Error == SerializeError.Rejected, "End carries it to the stream");
        }
        {
            WriteStream writer = new WriteStream(new byte[8]);
            MeasureStream measure = new MeasureStream();
            WriteStream batched = new WriteStream(new byte[8]);
            WriteBatch batch = batched.BeginBatch();
            bool w = true, m = true, b = true;
            Check(RunsWithoutAssert(() => { w = writer.Fail(SerializeError.PastEnd); m = measure.Fail(SerializeError.Rejected); }),
                "Fail on write and measure must not assert (U9)");
            b = batch.Fail(SerializeError.PastEnd);
            batch.End();
            Check(!w && !m && !b, "Fail on write and measure returns false");
            Check(writer.Ok && measure.Ok && batched.Ok, "Fail on write and measure records nothing (U6)");
        }
    }

    private static void TestBatchAfterEnd()
    {
        // The 2026-10-27 audit (cs, medium, R4a): a ReadBatch used after End synced its
        // stale cursor and error back into the stream, clearing a refusal the stream
        // latched after the batch ended. A batch is dead after End: every read refuses
        // and nothing is written back
        {
            byte[] buf = new byte[16];
            ReadStream stream = new ReadStream(buf, 2);
            ReadBatch batch = stream.BeginBatch();
            bool x = false;
            Check(batch.SerializeBool(ref x), "the batch read before End");
            batch.End();
            uint big = 0;
            Check(!stream.SerializeBits(ref big, 32), "the stream refuses past its end");
            long bits = stream.BitsProcessed;
            string str = "keep";
            Check(!batch.SerializeString(ref str, 4) && str == "keep", "a delegated read after End refuses");
            Check(!batch.SerializeBool(ref x), "an inline read after End refuses");
            uint w = 0x1234;
            Check(!batch.SerializeBits(ref w, 8) && w == 0x1234, "an inline read after End writes nothing");
            batch.End();
            Check(stream.Error == SerializeError.PastEnd && stream.BitsProcessed == bits,
                $"the stream keeps its refusal and cursor, got {stream.Error} at {stream.BitsProcessed}");
            Check(batch.Error == SerializeError.PastEnd && !batch.Ok, "an ended batch reports the stream's state");
            byte by = 0;
            Check(!stream.SerializeByte(ref by), "the stream's later reads still refuse");
        }
        {
            // a healthy stream: the dead batch still reads nothing, and the stream's
            // own reads after End stand
            byte[] buf = { 0xFF, 0xFF, 0, 0, 0, 0, 0, 0 };
            ReadStream stream = new ReadStream(buf, 2);
            ReadBatch batch = stream.BeginBatch();
            uint v = 0;
            Check(batch.SerializeBits(ref v, 4), "read in the batch");
            batch.End();
            Check(stream.SerializeBits(ref v, 4), "read on the stream after End");
            Check(!batch.SerializeBits(ref v, 4), "the ended batch refuses");
            Check(stream.Ok && stream.BitsProcessed == 8, "the stream is untouched by the dead batch");
            Check(batch.Ok, "an ended batch reports the stream's health");
        }

        // WriteBatch: the same pattern (audit R4a's write twin). Use after End is write
        // misuse: asserted in debug, and in release the delegated call writes nothing
        // back, so the stream's cursor never rewinds
        {
            WriteStream stream = new WriteStream(new byte[16]);
            WriteBatch batch = stream.BeginBatch();
            uint v = 1;
            batch.SerializeBits(ref v, 4);
            batch.End();
            stream.SerializeBits(ref v, 8);
            long bits = stream.BitsProcessed;
            string s = "a";
#if DEBUG
            Check(AssertFires(() =>
            {
                WriteStream inner = new WriteStream(new byte[16]);
                WriteBatch b = inner.BeginBatch();
                b.End();
                string t = "a";
                b.SerializeString(ref t, 4);
            }), "a write batch used after End must assert in debug");
#else
            Check(!batch.SerializeString(ref s, 4), "a delegated write after End returns false");
#endif
            _ = s;
            Check(stream.BitsProcessed == bits, $"the write stream's cursor stands, {stream.BitsProcessed} vs {bits}");
        }
    }

    private sealed class OneBitObject : ISerializer
    {
        public bool Serialize(IBitStream stream)
        {
            bool b = true;
            return stream.SerializeBool(ref b);
        }
    }

    private struct FailingValue : ISerializer
    {
        public bool Serialize(IBitStream stream)
        {
            return false;
        }
    }

    private static void TestWriteMisuseNeverLatches()
    {
        // IMPLEMENTING.md U9 (2.1.1): write misuse never latches, and a nested object
        // whose Serialize returns false on a write or a measure makes the object
        // operation return false and records nothing. U6: a measure latches nothing.
        // Before 2.1.1 this port recorded rejected on the write and measure streams
        // and refused every later object
        WriteStream writer = new WriteStream(new byte[16]);
        Check(!writer.SerializeObject(new FailingObject()), "a failing object returns false on write");
        FailingValue failing = default;
        Check(!writer.SerializeObject(ref failing), "a failing struct object returns false on write");
        Check(writer.Ok && writer.Error == SerializeError.None,
            $"a failing object records nothing on a write stream (U9), got {writer.Error}");
        Check(writer.SerializeObject(new OneBitObject()), "a later object writes: nothing latched (U9)");
        Check(writer.BitsProcessed == 1, $"and only its bit was written, at {writer.BitsProcessed}");

        MeasureStream measure = new MeasureStream();
        Check(!measure.SerializeObject(new FailingObject()), "a failing object returns false on measure");
        Check(!measure.SerializeObject(ref failing), "a failing struct object returns false on measure");
        Check(measure.Ok && measure.Error == SerializeError.None,
            $"a failing object records nothing on a measure stream (U6), got {measure.Error}");
        Check(measure.SerializeObject(new OneBitObject()), "a later object measures: nothing latched (U6)");
        Check(measure.BitsProcessed == 1, $"and only its bit was counted, at {measure.BitsProcessed}");

        WriteStream batched = new WriteStream(new byte[16]);
        WriteBatch batch = batched.BeginBatch();
        Check(!batch.SerializeObject(new FailingObject()), "a failing object returns false on a write batch");
        Check(batch.Ok && batch.Error == SerializeError.None,
            $"a failing object records nothing on a write batch (U9), got {batch.Error}");
        Check(batch.SerializeObject(new OneBitObject()), "a later batch object writes: nothing latched (U9)");
        batch.End();
        Check(batched.Ok && batched.BitsProcessed == 1, "End carries nothing to the stream");
    }

    private static void TestCopyString()
    {
        // IMPLEMENTING.md U15 (2.1.1), the reference's test_copy_string vectors in
        // UTF-16: dest_size counts the bytes of the strict UTF-8 encoding. The two
        // ill-formed byte vectors cannot be held by a C# string and are skipped, as
        // the ruling allows for value-string ports
        Check(SerializeUtil.CopyString("abc", 8) == "abc", "(\"abc\", 8) -> \"abc\"");
        Check(SerializeUtil.CopyString("a\0bc", 8) == "a", "(\"a\\0bc\", 8) -> \"a\"");
        Check(SerializeUtil.CopyString("abcdefghij", 4) == "abc", "(\"abcdefghij\", 4) -> \"abc\"");
        Check(SerializeUtil.CopyString("éé", 4) == "é", "(\"éé\", 4) -> \"é\"");
        Check(SerializeUtil.CopyString("éé", 3) == "é", "(\"éé\", 3) -> \"é\"");
        Check(SerializeUtil.CopyString("a\U0001F600", 3) == "a", "(\"a😀\", 3) -> \"a\"");
        Check(SerializeUtil.CopyString("a\U0001F600", 4) == "a", "(\"a😀\", 4) -> \"a\"");
        Check(SerializeUtil.CopyString("a\U0001F600", 5) == "a", "(\"a😀\", 5) -> \"a\"");
        Check(SerializeUtil.CopyString("a\U0001F600", 6) == "a\U0001F600", "(\"a😀\", 6) -> whole");
        Check(SerializeUtil.CopyString("abc", 1) == "", "(\"abc\", 1) -> \"\"");
#if DEBUG
        // U3, U9: a source the strict UTF-8 codec refuses is write misuse, trapped by
        // Debug.Assert, high and low halves alike, wherever they stand; and
        // dest_size below 1 is write misuse
        Check(AssertFires(() => SerializeUtil.CopyString("a\uD83D", 8)), "a lone high surrogate source must assert (U3)");
        Check(AssertFires(() => SerializeUtil.CopyString("a\uDE00b", 8)), "a lone low surrogate source must assert (U3)");
        Check(AssertFires(() => SerializeUtil.CopyString("abcdef\uD83D", 2)), "a lone surrogate past the cut must assert (U3)");
        Check(AssertFires(() => SerializeUtil.CopyString("abc", 0)), "dest_size 0 must assert (U9)");
        Check(!AssertFires(() => SerializeUtil.CopyString("a\U0001F600", 4)), "a surrogate pair is well formed");
#endif

        // IMPLEMENTING.md U15: serialize_copy_string must exist everywhere. The copy
        // stops at a NUL and holds at most bufferSize - 1 UTF-8 bytes, cut at a
        // character boundary (U3)
        Check(SerializeUtil.CopyString("hello", 6) == "hello", "a string that fits is kept");
        Check(SerializeUtil.CopyString("hello", 5) == "hell", "the copy leaves room for bufferSize - 1 bytes");
        Check(SerializeUtil.CopyString("hello", 1) == "", "bufferSize 1 holds the empty string");
        Check(SerializeUtil.CopyString("ab\0cd", 16) == "ab", "the copy stops at a NUL");
        Check(SerializeUtil.CopyString("é", 2) == "", "a two byte character is never split");
        Check(SerializeUtil.CopyString("aé", 3) == "a", "a two byte character needs both bytes");
        Check(SerializeUtil.CopyString("aé", 4) == "aé", "and fits with them");
        Check(SerializeUtil.CopyString("世界", 6) == "世", "a three byte character is never split");
        Check(SerializeUtil.CopyString("\U0001F600x", 4) == "", "a surrogate pair is four bytes, kept or dropped whole");
        Check(SerializeUtil.CopyString("\U0001F600x", 5) == "\U0001F600", "a whole pair is kept");

        // every copy writes and reads back through a field of that size
        foreach (string source in new[] { "hello", "aé世\U0001F600z", "ab\0cd", "" })
        {
            for (int bufferSize = 1; bufferSize <= 16; bufferSize++)
            {
                string copy = SerializeUtil.CopyString(source, bufferSize);
                WriteStream writer = new WriteStream(new byte[32]);
                Check(writer.SerializeString(ref copy, bufferSize), "the copy writes");
                writer.Flush();
                ReadStream reader = new ReadStream(writer.Data.ToArray(), (int)writer.BytesProcessed);
                string back = "";
                Check(reader.SerializeString(ref back, bufferSize) && back == copy,
                    $"the copy of \"{source}\" at {bufferSize} reads back");
            }
        }
    }

#if DEBUG
    private static void TestWriteUniformAsserts()
    {
        // IMPLEMENTING.md U8: an over-wide value is caught in the checked build, never
        // masked, on every write surface
        Check(AssertFires(() => { uint v = 0x100; new WriteStream(new byte[8]).SerializeBits(ref v, 8); }),
            "an over-wide bits write must assert (U8)");
        Check(AssertFires(() => { ulong v = 1UL << 40; new WriteStream(new byte[8]).SerializeBits64(ref v, 40); }),
            "an over-wide bits64 write must assert (U8)");
        Check(AssertFires(() => { uint v = 2; new MeasureStream().SerializeBits(ref v, 1); }),
            "an over-wide bits measure must assert (U8)");
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            WriteBatch batch = stream.BeginBatch();
            uint v = 0x10;
            batch.SerializeBits(ref v, 4);
        }), "an over-wide batch bits write must assert (U8)");
        // U6, U9: a measure traps a non-finite compressed float as a write does,
        // never clamping it in a checked build
        Check(AssertFires(() => { float v = float.NaN; new MeasureStream().SerializeCompressedFloat(ref v, 0, 10, 0.01f); }),
            "a NaN compressed float measure must assert (U6, U9)");
        Check(AssertFires(() => { float v = float.NegativeInfinity; new MeasureStream().SerializeCompressedFloat(ref v, 0, 10, 0.01f); }),
            "an infinite compressed float measure must assert (U6, U9)");
        Check(AssertFires(() =>
        {
            SerializeUtil.CompressedFloatParams(0, 10, 0.01f, out uint maxIntegerValue, out int bits, out float delta);
            float v = float.NaN;
            new MeasureStream().SerializeCompressedFloatPrecomputed(ref v, maxIntegerValue, bits, delta, 0);
        }), "a NaN precomputed compressed float measure must assert (U6, U9)");
        Check(!AssertFires(() =>
        {
            uint v = uint.MaxValue;
            ulong w = ulong.MaxValue;
            WriteStream stream = new WriteStream(new byte[16]);
            stream.SerializeBits(ref v, 32);
            stream.SerializeBits64(ref w, 64);
        }), "full-width values fit");

        // IMPLEMENTING.md U10: a write checks room for the whole operation before
        // writing any of it: no length or align bits ahead of a payload that does
        // not fit
        {
            WriteStream stream = new WriteStream(new byte[8]);
            uint v = 0;
            stream.SerializeBits(ref v, 30);
            string s = "hello";
            Check(AssertFires(() => stream.SerializeString(ref s, 32)), "a string that cannot fit must assert (U10)");
            Check(stream.BitsProcessed == 30, $"before any bit of it is written, at {stream.BitsProcessed}");
        }
        {
            WriteStream stream = new WriteStream(new byte[8]);
            uint v = 0;
            stream.SerializeBits(ref v, 3);
            byte[] payload = new byte[8];
            Check(AssertFires(() => stream.SerializeBytes(payload)), "bytes that cannot fit must assert (U10)");
            Check(stream.BitsProcessed == 3, $"before the align is written, at {stream.BitsProcessed}");
        }
        Check(!AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            string s = "abcdef";
            stream.SerializeString(ref s, 8); // 3 length bits, 5 align, 48 payload
        }), "a string that exactly fits does not assert");
    }
#endif
}
