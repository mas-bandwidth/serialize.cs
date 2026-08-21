/*
    CompressedFloat.cs

    The mas-bandwidth/schema#82 differential: the derive-per-call compressed float
    against the precomputed one. Four implementations must be indistinguishable in
    measured bits, wire bytes, read acceptance and decoded BIT PATTERNS on every
    input:

      frozen      -- FrozenCompressedFloat* below, a verbatim copy of the compressed
                     float arithmetic as it stood in v1.4.0, BEFORE the schema#82
                     split moved the derivation to SerializeUtil.CompressedFloatParams
                     and the read dequantization to
                     SerializeInternal.DecodeCompressedFloat. FROZEN: never edit it.
                     it is the code the audited homes replaced, kept so the
                     differential proves the split changed nothing, forever.
      legacy      -- SerializeCompressedFloat(ref value, min, max, res), which since
                     the split derives the constants per call and forwards to the
                     audited homes.
      precomputed -- SerializeCompressedFloatPrecomputed(ref value, ...) with
                     constants derived once per declaration by
                     SerializeUtil.CompressedFloatParams, exactly as a schema
                     compiler derives them at generation time.
      batch       -- the same precomputed entry point on the WriteBatch / ReadBatch
                     surface, the C#-only batch layer's leg of the same law.

    The declaration corpus is every compressed float declaration the schema
    compiler's examples, bench corpus and test data emit (harvested from the
    mas-bandwidth/schema PR #79 differential, via the C++ reference differential in
    serialize.h), plus this repo's golden and quantization-boundary declarations,
    plus shapes at the edges of the derivation itself: resolution coarser than the
    range, a step count that exactly fills its wire width, a million steps, and the
    clamp at the largest float below 2^32.

    Inputs per declaration: a dense sweep with overshoot past both bounds, the
    quantization step edges and midpoints with their one-ulp neighbors (the
    midpoints are where a fused or widened writer diverges — STANDARD.md's
    0.005-over-[0,10] class), specials (bounds and their one-ulp neighbors, negative
    zero, subnormals, float extremes), LCG uniform in-range values and LCG uniform
    float32 bit patterns — and on the read side every representable wire integer
    including the bit headroom, exhaustively up to 16-bit widths and sampled with
    the boundary codes pinned above that. Decoded values compare by BIT PATTERN,
    never by tolerance: the divergence a fused or widened decode produces is one
    ulp, invisible to any tolerance.
*/

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Serialize.Tests;

internal static partial class Program
{
    // ---------------------------------------------------------------------------
    // The frozen pre-split arithmetic, v1.4.0. Comments elided, assert message
    // constants inlined, statements identical (the float locals and casts included:
    // they are what pin the roundings). DO NOT EDIT.
    // ---------------------------------------------------------------------------

    private static void FrozenCompressedFloatParams(
        float min, float max, float resolution,
        out uint maxIntegerValue, out int bits, out float delta)
    {
        // verbatim v1.4.0 SerializeInternal.CompressedFloatParams
        Debug.Assert(min < max && resolution > 0, "compressed float requires min < max and resolution > 0");

        delta = max - min;

        Debug.Assert(!float.IsInfinity(delta), "compressed float declaration is non-conforming: max - min must be finite");

        float values = delta / resolution;

        Debug.Assert(!float.IsInfinity(values), "compressed float declaration is non-conforming: (max - min) / resolution must be finite");

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

    private static bool FrozenCompressedFloatWrite(WriteStream stream, float value, float min, float max, float resolution)
    {
        FrozenCompressedFloatParams(min, max, resolution,
            out uint maxIntegerValue, out int bits, out float delta);

        // verbatim v1.4.0 SerializeInternal.QuantizeCompressedFloat
        Debug.Assert(float.IsFinite(value), "compressed float write value is non-conforming: NaN and infinities must not be sent");

        float normalizedValue = (value - min) / delta;
        if (!(normalizedValue >= 0.0f))
        {
            normalizedValue = 0.0f;
        }
        else if (!(normalizedValue <= 1.0f))
        {
            normalizedValue = 1.0f;
        }
        float scaled = (float)(normalizedValue * maxIntegerValue);
        uint integerValue = (uint)Math.Floor((double)(float)(scaled + 0.5f));

        return stream.SerializeBits(ref integerValue, bits);
    }

    private static bool FrozenCompressedFloatMeasure(MeasureStream stream, float min, float max, float resolution)
    {
        FrozenCompressedFloatParams(min, max, resolution, out _, out int bits, out _);
        // verbatim v1.4.0 MeasureStream.SerializeCompressedFloat: Measure(bits)
        uint integerValue = 0;
        return stream.SerializeBits(ref integerValue, bits);
    }

    private static bool FrozenCompressedFloatRead(ReadStream stream, ref float value, float min, float max, float resolution)
    {
        FrozenCompressedFloatParams(min, max, resolution,
            out uint maxIntegerValue, out int bits, out float delta);
        uint integerValue = 0;
        if (!stream.SerializeBits(ref integerValue, bits))
        {
            return false;
        }
        if (integerValue > maxIntegerValue)
        {
            // v1.4.0 latches SerializeError.ValueOutOfRange here; the latch is the
            // stream's bookkeeping, not the arithmetic — the differential compares
            // acceptance by return value
            return false;
        }
        // verbatim v1.4.0 ReadStream.SerializeCompressedFloat decode
        float normalizedValue = (float)integerValue / maxIntegerValue;
        value = normalizedValue * delta + min;
        return true;
    }

    // ---------------------------------------------------------------------------
    // The declaration corpus: min, max, res, and the constants a schema compiler
    // emits for the declaration, pinned (the first eleven rows are the values the
    // schema PR #79 differential published).
    // ---------------------------------------------------------------------------

    private static readonly (float Min, float Max, float Res, uint MaxIntegerValue, int Bits)[] CompressedFloatShapes =
    {
        // the schema compiler's corpus: examples, bench/corpus/RealWorld.schema and its test data
        (0.0f, 2000.0f, 0.1f, 20000, 15),
        (-2.0f, 2.0f, 0.25f, 16, 5),
        (-90.0f, 90.0f, 0.5f, 360, 9),
        (0.0f, 30.0f, 0.5f, 60, 6),
        (-100.0f, 100.0f, 0.25f, 800, 10),
        (0.0f, 2000.0f, 1.0f, 2000, 11),
        (0.0f, 10.0f, 0.02f, 500, 9),
        (0.0f, 100.0f, 0.01f, 10000, 14),
        (-180.0f, 180.0f, 0.01f, 36000, 16),
        (0.0f, 10.0f, 0.01f, 1000, 10),         // also this repo's golden wire declaration
        (-5.0f, 5.0f, 0.001f, 10000, 14),
        // the family's own declarations (the C++ reference repo's conformance, fuzz and example shapes)
        (-100.0f, 100.0f, 0.01f, 20000, 15),    // the non-zero-min conformance vector
        (-10.0f, 10.0f, 0.01f, 2000, 11),       // the C++ fuzz harness declaration
        (-1.0f, 1.0f, 0.001f, 2000, 11),        // example orientation declaration
        // shapes at the edges of the derivation itself
        (0.0f, 1.0f, 2.0f, 1, 1),               // resolution coarser than the range: values clamps up to 1
        (0.0f, 15.0f, 1.0f, 15, 4),             // step count exactly fills the wire width: no headroom to refuse
        (0.0f, 1000000.0f, 1.0f, 1000000, 20),  // a million steps
        (0.0f, 10000000000.0f, 1.0f, 4294967040u, 32), // values clamps down to the largest float below 2^32
    };

    // ---------------------------------------------------------------------------
    // THE NEGATIVE CONTROLS — proof that this differential's eyes are open.
    //
    // Every check below compares implementations that are SUPPOSED to agree, and a
    // test where everything agrees cannot distinguish "the split changed nothing"
    // from "the comparison cannot see this class of change". The distinction is not
    // hypothetical: the whole FMA discipline in the audited homes is a pair of
    // (float) casts through float locals, and whether DELETING them is visible
    // depends on machinery outside this source file.
    //
    // In C and C++ that machinery is a compiler flag, and the reference measured
    // what it does (mas-bandwidth/schema#82, and serialize.c#38 / serialize#86):
    // folding the reader's two roundings into one expression leaves the differential
    // GREEN at -ffp-contract=off, GREEN at =fast and RED only at =on. The two "safe"
    // settings are blind for opposite reasons — `off` forbids contraction in the
    // frozen oracle too, so both spellings compute the same thing; `fast` fuses
    // ACROSS statements, so the frozen oracle fuses as well and the two spellings
    // stop being distinguishable. A differential built at either is decoration.
    //
    // C# has no such flag, and that is not a reason to skip this: it is the reason
    // to do it in the only way that works here. RyuJIT does not contract today, so
    // the same fold is currently a no-op in this language — which means the fold
    // falsification proves nothing about C#, and a hand-driven sweep has nothing to
    // sweep. What CAN change the arithmetic is a widened or single-rounding
    // evaluation, which ECMA-334 explicitly permits an implementation to perform
    // ("floating point operations may be performed with higher precision than the
    // result type") and which the (float) casts in the audited homes exist to
    // forbid. The two sentinels below are exactly that perturbation, spelled in
    // DOUBLE so no JIT behaviour and no hardware is required to produce it.
    //
    // Each runs alongside the real path over the whole corpus, and the differential
    // FAILS if either ever stops diverging — i.e. if a future edit, or a future JIT,
    // ever leaves the wire bytes or the decoded bit patterns blind to a
    // single-rounding quantization. That is the part that generalises: a sweep is
    // something a person has to remember to run, and it proves the property once; a
    // control that fails when it stops diverging is permanent and needs nobody to
    // choose the right flag. In the C port the same control immediately paid for
    // itself — at -ffp-contract=fast its read half drops to ZERO and fails the suite
    // by name, which is the state the reference had to find by hand.
    //
    // The sentinels are deliberately NOT compared against the frozen oracle for
    // equality. They are supposed to disagree. That is the whole point. The
    // divergence counts print every run, so the mass is visible and not just the
    // verdict.
    // ---------------------------------------------------------------------------

    private static ulong s_compressedFloatSentinelWriteDivergences;
    private static ulong s_compressedFloatSentinelReadDivergences;

    /// <summary>The writer's quantization with the two float roundings collapsed:
    /// the product and the +0.5 both taken in double, rounded once by the floor.
    /// The "widened to double" perturbation, permanently on watch.</summary>
    private static uint SentinelWriteCodeOneRounding(float value, uint maxIntegerValue, float delta, float min)
    {
        float normalized = (value - min) / delta;
        if (!(normalized >= 0.0f))
        {
            normalized = 0.0f;
        }
        else if (!(normalized <= 1.0f))
        {
            normalized = 1.0f;
        }
        return (uint)Math.Floor(((double)normalized * maxIntegerValue) + 0.5);
    }

    /// <summary>The reader's reconstruction with the multiply and the add collapsed
    /// into one rounding — what an FMA contraction produces, spelled in double so it
    /// happens on every runtime and every host regardless.</summary>
    private static float SentinelReadValueOneRounding(uint integerValue, uint maxIntegerValue, float delta, float min)
    {
        float normalized = (float)integerValue / maxIntegerValue;
        return (float)(((double)normalized * delta) + min);
    }

    // ---------------------------------------------------------------------------
    // Does THIS runtime fuse, and does it fuse ACROSS statements?
    //
    // Reported, never inferred. -ffp-contract has no C# counterpart and RyuJIT emits
    // no fmadd for a * b + c today — serialize.cs#19 confirmed that against the
    // instruction stream rather than against a green test — but "today" is a fact
    // about a JIT version, not about the language, and ECMA-334 permits higher
    // precision than the result type unless an explicit conversion intervenes. So
    // the suite measures it and says which, and a green log never claims a
    // discipline it did not exercise.
    //
    // The three spellings live in their own NoInlining methods on purpose: written
    // as three expressions in one method they share the subexpression a * b, the
    // compiler merges it, and the probe would then be a question about common
    // subexpression elimination rather than about the runtime's rounding.
    // ---------------------------------------------------------------------------

    private static volatile float s_fpProbeSink;

    /// <summary>Contractible: one expression with no cast, so a runtime permitted to
    /// evaluate at higher precision may round it once.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static float FpProbeOneExpression(float a, float b, float c)
    {
        return (a * b) + c;
    }

    /// <summary>Two statements through a cast float local — the shape of both audited
    /// homes. Only an implementation rounding ACROSS the statement boundary, in
    /// defiance of the explicit conversion, can make this agree with the fused
    /// spelling.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static float FpProbeTwoStatements(float a, float b, float c)
    {
        float product = (float)(a * b);
        return (float)(product + c);
    }

    /// <summary>The reference: a volatile store forces the product to memory as
    /// float32, so nothing can carry extra precision through it. The other two are
    /// measured against this.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static float FpProbeForcedUnfused(float a, float b, float c)
    {
        s_fpProbeSink = a * b;
        return s_fpProbeSink + c;
    }

    private static bool FpContractionIsLive()
    {
        for (uint code = 1; code < 20000; code++)
        {
            float norm = code / 20000.0f;
            float fused = FpProbeOneExpression(norm, 200.0f, -100.0f);
            float unfused = FpProbeForcedUnfused(norm, 200.0f, -100.0f);
            if (BitConverter.SingleToUInt32Bits(fused) != BitConverter.SingleToUInt32Bits(unfused))
            {
                return true;
            }
        }
        return false;
    }

    private static bool FpContractionCrossesStatements()
    {
        for (uint code = 1; code < 20000; code++)
        {
            float norm = code / 20000.0f;
            float across = FpProbeTwoStatements(norm, 200.0f, -100.0f);
            float unfused = FpProbeForcedUnfused(norm, 200.0f, -100.0f);
            if (BitConverter.SingleToUInt32Bits(across) != BitConverter.SingleToUInt32Bits(unfused))
            {
                return true;
            }
        }
        return false;
    }

    // the coverage floor lives on this counter: if the differential ever silently
    // shrinks below the mass it was built with, that is a test bug, and it fails
    // instead of fading quietly
    private static ulong s_compressedFloatDifferentialChecks;
    private static string s_compressedFloatShape = "";

    private static void DifferentialCheck(bool condition, string what)
    {
        if (!condition)
        {
            Check(false, $"{what} (shape {s_compressedFloatShape})");
        }
        s_compressedFloatDifferentialChecks++;
    }

    /// <summary>One written value through all four implementations: measured bits,
    /// wire bytes and decoded bit patterns must agree exactly.</summary>
    private static void CheckCompressedFloatValueAgrees(
        float value, float min, float max, float res, uint maxIntegerValue, int bits, float delta)
    {
        // measure: all forms agree on cost
        MeasureStream measureFrozen = new MeasureStream();
        DifferentialCheck(FrozenCompressedFloatMeasure(measureFrozen, min, max, res), "frozen measure failed");
        MeasureStream measureLegacy = new MeasureStream();
        float measureValue = value;
        DifferentialCheck(measureLegacy.SerializeCompressedFloat(ref measureValue, min, max, res), "legacy measure failed");
        MeasureStream measurePrecomputed = new MeasureStream();
        measureValue = value;
        DifferentialCheck(measurePrecomputed.SerializeCompressedFloatPrecomputed(ref measureValue, maxIntegerValue, bits, delta, min), "precomputed measure failed");
        DifferentialCheck(measureFrozen.BitsProcessed == measureLegacy.BitsProcessed, "legacy measure disagrees with frozen");
        DifferentialCheck(measureFrozen.BitsProcessed == measurePrecomputed.BitsProcessed, "precomputed measure disagrees with frozen");

        // write: byte identical wire from all four
        byte[] bufferFrozen = new byte[8];
        byte[] bufferLegacy = new byte[8];
        byte[] bufferPrecomputed = new byte[8];
        byte[] bufferBatch = new byte[8];

        WriteStream writeFrozen = new WriteStream(bufferFrozen);
        DifferentialCheck(FrozenCompressedFloatWrite(writeFrozen, value, min, max, res), "frozen write failed");
        writeFrozen.Flush();

        WriteStream writeLegacy = new WriteStream(bufferLegacy);
        float writeValue = value;
        DifferentialCheck(writeLegacy.SerializeCompressedFloat(ref writeValue, min, max, res), "legacy write failed");
        writeLegacy.Flush();

        WriteStream writePrecomputed = new WriteStream(bufferPrecomputed);
        writeValue = value;
        DifferentialCheck(writePrecomputed.SerializeCompressedFloatPrecomputed(ref writeValue, maxIntegerValue, bits, delta, min), "precomputed write failed");
        writePrecomputed.Flush();

        WriteStream writeBatchStream = new WriteStream(bufferBatch);
        WriteBatch writeBatch = writeBatchStream.BeginBatch();
        writeValue = value;
        DifferentialCheck(writeBatch.SerializeCompressedFloatPrecomputed(ref writeValue, maxIntegerValue, bits, delta, min), "batch precomputed write failed");
        writeBatch.End();
        writeBatchStream.Flush();

        DifferentialCheck(writeFrozen.BitsProcessed == writeLegacy.BitsProcessed, "legacy write bits disagree with frozen");
        DifferentialCheck(writeFrozen.BitsProcessed == writePrecomputed.BitsProcessed, "precomputed write bits disagree with frozen");
        DifferentialCheck(bufferFrozen.AsSpan().SequenceEqual(bufferLegacy), "legacy wire bytes disagree with frozen");
        DifferentialCheck(bufferFrozen.AsSpan().SequenceEqual(bufferPrecomputed), "precomputed wire bytes disagree with frozen");
        DifferentialCheck(bufferFrozen.AsSpan().SequenceEqual(bufferBatch), "batch precomputed wire bytes disagree with frozen");

        // read: decoded BIT PATTERNS agree exactly — one ulp of divergence must fail
        ReadStream readFrozen = new ReadStream(bufferFrozen);
        float decodedFrozen = 0.0f;
        DifferentialCheck(FrozenCompressedFloatRead(readFrozen, ref decodedFrozen, min, max, res), "frozen read failed");

        ReadStream readLegacy = new ReadStream(bufferFrozen);
        float decodedLegacy = 0.0f;
        DifferentialCheck(readLegacy.SerializeCompressedFloat(ref decodedLegacy, min, max, res), "legacy read failed");

        ReadStream readPrecomputed = new ReadStream(bufferFrozen);
        float decodedPrecomputed = 0.0f;
        DifferentialCheck(readPrecomputed.SerializeCompressedFloatPrecomputed(ref decodedPrecomputed, maxIntegerValue, bits, delta, min), "precomputed read failed");

        ReadStream readBatchStream = new ReadStream(bufferFrozen);
        ReadBatch readBatch = readBatchStream.BeginBatch();
        float decodedBatch = 0.0f;
        DifferentialCheck(readBatch.SerializeCompressedFloatPrecomputed(ref decodedBatch, maxIntegerValue, bits, delta, min), "batch precomputed read failed");
        readBatch.End();

        uint patternFrozen = BitConverter.SingleToUInt32Bits(decodedFrozen);
        DifferentialCheck(patternFrozen == BitConverter.SingleToUInt32Bits(decodedLegacy), "legacy decode disagrees with frozen");
        DifferentialCheck(patternFrozen == BitConverter.SingleToUInt32Bits(decodedPrecomputed), "precomputed decode disagrees with frozen");
        DifferentialCheck(patternFrozen == BitConverter.SingleToUInt32Bits(decodedBatch), "batch precomputed decode disagrees with frozen");

        // the write-side negative control: the one-rounding quantization must still
        // be able to produce a DIFFERENT wire code than the audited home does, or
        // the byte comparisons above have gone blind. The code is read back off the
        // frozen wire rather than recomputed, so the control is measured against the
        // bytes the comparison actually made.
        ReadStream sentinelStream = new ReadStream(bufferFrozen);
        uint wireCode = 0;
        if (sentinelStream.SerializeBits(ref wireCode, bits)
            && SentinelWriteCodeOneRounding(value, maxIntegerValue, delta, min) != wireCode)
        {
            s_compressedFloatSentinelWriteDivergences++;
        }
    }

    /// <summary>One wire integer through all four read paths: acceptance must agree
    /// (the headroom refusal), and accepted codes must decode to identical bit
    /// patterns.</summary>
    private static void CheckCompressedFloatCodeAgrees(
        uint code, float min, float max, float res, uint maxIntegerValue, int bits, float delta)
    {
        byte[] buffer = new byte[8];
        WriteStream writeStream = new WriteStream(buffer);
        uint raw = code;
        DifferentialCheck(writeStream.SerializeBits(ref raw, bits), "code write failed");
        writeStream.Flush();

        ReadStream readFrozen = new ReadStream(buffer);
        float decodedFrozen = 0.0f;
        bool okFrozen = FrozenCompressedFloatRead(readFrozen, ref decodedFrozen, min, max, res);

        ReadStream readLegacy = new ReadStream(buffer);
        float decodedLegacy = 0.0f;
        bool okLegacy = readLegacy.SerializeCompressedFloat(ref decodedLegacy, min, max, res);

        ReadStream readPrecomputed = new ReadStream(buffer);
        float decodedPrecomputed = 0.0f;
        bool okPrecomputed = readPrecomputed.SerializeCompressedFloatPrecomputed(ref decodedPrecomputed, maxIntegerValue, bits, delta, min);

        ReadStream readBatchStream = new ReadStream(buffer);
        ReadBatch readBatch = readBatchStream.BeginBatch();
        float decodedBatch = 0.0f;
        bool okBatch = readBatch.SerializeCompressedFloatPrecomputed(ref decodedBatch, maxIntegerValue, bits, delta, min);
        readBatch.End();

        DifferentialCheck(okFrozen == okLegacy, "legacy read acceptance disagrees with frozen");
        DifferentialCheck(okFrozen == okPrecomputed, "precomputed read acceptance disagrees with frozen");
        DifferentialCheck(okFrozen == okBatch, "batch precomputed read acceptance disagrees with frozen");
        DifferentialCheck(okFrozen == (code <= maxIntegerValue), "the headroom refusal itself");

        if (okFrozen)
        {
            uint patternFrozen = BitConverter.SingleToUInt32Bits(decodedFrozen);
            DifferentialCheck(patternFrozen == BitConverter.SingleToUInt32Bits(decodedLegacy), "legacy code decode disagrees with frozen");
            DifferentialCheck(patternFrozen == BitConverter.SingleToUInt32Bits(decodedPrecomputed), "precomputed code decode disagrees with frozen");
            DifferentialCheck(patternFrozen == BitConverter.SingleToUInt32Bits(decodedBatch), "batch precomputed code decode disagrees with frozen");

            // the read-side negative control: a one-rounding reconstruction must
            // still be able to land on a DIFFERENT bit pattern, or the pattern
            // comparisons above have gone blind. The divergence is one ulp, which is
            // exactly why this differential never compares decoded values with a
            // tolerance.
            uint patternSentinel = BitConverter.SingleToUInt32Bits(
                SentinelReadValueOneRounding(code, maxIntegerValue, delta, min));
            if (patternSentinel != patternFrozen)
            {
                s_compressedFloatSentinelReadDivergences++;
            }
        }
    }

    private static void TestCompressedFloatPrecomputedValidation()
    {
        // the constants SerializeCompressedFloat derives on every call, derived once
        // instead: the derivation is pinned, and the precomputed read path must
        // refuse the same smuggled integers and accept the same conforming ones as
        // the derive-per-call path (test_compressed_float_validation's twin).
        SerializeUtil.CompressedFloatParams(0.0f, 10.0f, 0.01f,
            out uint maxIntegerValue, out int bits, out float delta);
        Check(maxIntegerValue == 1000, $"expected maxIntegerValue 1000, got {maxIntegerValue}");
        Check(bits == 10, $"expected bits 10, got {bits}");
        Check(delta == 10.0f, $"expected delta 10, got {delta}");

        // a malicious packet can encode integer values above maxIntegerValue in the
        // bit headroom. the precomputed read must reject them.
        {
            byte[] buffer = new byte[8];

            WriteStream writeStream = new WriteStream(buffer);
            uint outOfRange = 1023; // maxIntegerValue is 1000 for [0,10] at res 0.01 -> 10 bits
            writeStream.SerializeBits(ref outOfRange, 10);
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer);
            float value = -42.5f; // sentinel: a failed read must not publish a decoded value
            Check(!readStream.SerializeCompressedFloatPrecomputed(ref value, maxIntegerValue, bits, delta, 0.0f),
                "expected the precomputed read to fail");
            Check(readStream.Error == SerializeError.ValueOutOfRange,
                $"expected ValueOutOfRange, got {readStream.Error}");
            Check(value == -42.5f, $"a failed read must leave the value unmodified, got {value}");
        }

        // the highest conforming integer still decodes
        {
            byte[] buffer = new byte[8];

            WriteStream writeStream = new WriteStream(buffer);
            uint topOfRange = 1000;
            writeStream.SerializeBits(ref topOfRange, 10);
            writeStream.Flush();

            ReadStream readStream = new ReadStream(buffer);
            float value = 0.0f;
            Check(readStream.SerializeCompressedFloatPrecomputed(ref value, maxIntegerValue, bits, delta, 0.0f),
                "expected the precomputed read to succeed");
            Check(value == 10.0f, $"1000 / 1000 * 10 + 0 must decode exactly to 10 at the top of the range, got {value}");
        }
    }

    // The non-zero-min conformance vector of the C++ reference
    // (test_compressed_float_precomputed_conformance in serialize.h), through the
    // PRECOMPUTED entry point, with the constants a schema compiler derives for
    // [-100,100] at resolution 0.01 written as literals — exactly what generated
    // code would pass. Same pinned bytes, same pinned decoded bit patterns: the
    // precomputed path is held to the conformance law directly, independently of
    // the differential.

    private static bool CompressedFloatPrecomputedConformanceSerialize(IBitStream stream, ref float a, ref float b, ref float c)
    {
        if (!stream.SerializeCompressedFloatPrecomputed(ref a, 20000, 15, 200.0f, -100.0f))
        {
            return false;
        }
        if (!stream.SerializeCompressedFloatPrecomputed(ref b, 20000, 15, 200.0f, -100.0f))
        {
            return false;
        }
        if (!stream.SerializeCompressedFloatPrecomputed(ref c, 20000, 15, 200.0f, -100.0f))
        {
            return false;
        }
        return stream.SerializeAlign();
    }

    private static void TestCompressedFloatPrecomputedConformance()
    {
        byte[] pinnedBytes = { 0x10, 0xA7, 0x06, 0x80, 0x82, 0x06 };

        // write side: the precomputed quantization must produce exactly the pinned bytes
        {
            byte[] buffer = new byte[64];
            WriteStream stream = new WriteStream(buffer);
            float a = 0.0f;
            float b = -99.875f;
            float c = -33.34f;
            Check(CompressedFloatPrecomputedConformanceSerialize(stream, ref a, ref b, ref c),
                $"conformance write failed: {stream.Error}");
            stream.Flush();
            Check(stream.BytesProcessed == pinnedBytes.Length,
                $"expected {pinnedBytes.Length} bytes, got {stream.BytesProcessed}");
            Check(buffer.AsSpan(0, pinnedBytes.Length).SequenceEqual(pinnedBytes),
                $"conformance bytes mismatch:\nexpected {Convert.ToHexString(pinnedBytes)}\ngot      {Convert.ToHexString(buffer.AsSpan(0, pinnedBytes.Length))}");
        }

        // read side: the decoded floats are pinned bit-exactly
        {
            ReadStream stream = new ReadStream(pinnedBytes);
            float a = -1.0f;
            float b = -1.0f;
            float c = -1.0f;
            Check(CompressedFloatPrecomputedConformanceSerialize(stream, ref a, ref b, ref c),
                $"conformance read failed: {stream.Error}");
            Check(BitConverter.SingleToUInt32Bits(a) == 0x00000000u,
                $"decoded a has the wrong bits: 0x{BitConverter.SingleToUInt32Bits(a):X8}");
            Check(BitConverter.SingleToUInt32Bits(b) == 0xC2C7BD71u,
                $"decoded b has the wrong bits: 0x{BitConverter.SingleToUInt32Bits(b):X8}");
            Check(BitConverter.SingleToUInt32Bits(c) == 0xC2055C2Au,
                $"decoded c has the wrong bits: 0x{BitConverter.SingleToUInt32Bits(c):X8}");
        }
    }

    private static void TestCompressedFloatPrecomputedDifferential()
    {
        const float floatMax = 3.402823466e+38f; // FLT_MAX, the C++ reference's spelling

        s_compressedFloatDifferentialChecks = 0;
        s_compressedFloatSentinelWriteDivergences = 0;
        s_compressedFloatSentinelReadDivergences = 0;

        // what this runtime actually does with the arithmetic under test. Reported,
        // not asserted: a runtime that keeps the roundings distinct is the expected
        // and conforming case, and there is no flag here to have got wrong.
        bool contractionIsLive = FpContractionIsLive();
        bool contractionCrossesStatements = FpContractionCrossesStatements();
        Console.WriteLine("    (this runtime "
            + (!contractionIsLive ? "does NOT contract a * b + c: the audited homes' (float) casts are compiled but not exercised"
                : contractionCrossesStatements ? "contracts ACROSS statements, in defiance of the explicit conversions — refused below"
                : "contracts a * b + c but honours the explicit conversions: the audited homes' casts are under test")
            + ")");

        // An implementation that carried extra precision THROUGH an explicit (float)
        // conversion would fuse the audited homes, the frozen pre-split oracle and
        // every other spelling of this arithmetic all at once: the differential would
        // agree with itself while the decode moved one ulp and the wire moved with
        // it. STANDARD.md does not admit that, ECMA-334 does not permit it, and no
        // shipping RyuJIT does it — but if one ever does, the honest report is the
        // name of the problem, not a pinned bit pattern that reads like a port bug.
        Check(!contractionCrossesStatements,
            "this runtime evaluates float arithmetic across an explicit (float) conversion: the compressed float's two "
            + "roundings collapse into one, the wire moves by one ulp, and every differential in this suite goes blind "
            + "at the same time. The wire cannot be certified from this runtime.");

        ulong lcg = 0xC0FFEE1234567890UL; // fixed seed: failures reproduce

        ulong NextLcg()
        {
            lcg = lcg * 6364136223846793005UL + 1442695040888963407UL;
            return lcg;
        }

        foreach ((float min, float max, float res, uint expectedMaxIntegerValue, int expectedBits) in CompressedFloatShapes)
        {
            s_compressedFloatShape = $"[{min},{max}] res {res}";

            SerializeUtil.CompressedFloatParams(min, max, res,
                out uint maxIntegerValue, out int bits, out float delta);

            // the derived constants are pinned against the schema compiler's
            // generation-time table
            DifferentialCheck(maxIntegerValue == expectedMaxIntegerValue, "derived maxIntegerValue disagrees with the pinned table");
            DifferentialCheck(bits == expectedBits, "derived bits disagree with the pinned table");
            DifferentialCheck(delta == max - min, "derived delta disagrees with max - min");

            double dmin = min;
            double ddelta = delta;

            // dense sweep with overshoot a quarter of the range past both bounds
            {
                const int sweepSteps = 2048;
                double lo = dmin - 0.25 * ddelta;
                double span = 1.5 * ddelta;
                for (int i = 0; i <= sweepSteps; i++)
                {
                    float value = (float)(lo + span * i / sweepSteps);
                    CheckCompressedFloatValueAgrees(value, min, max, res, maxIntegerValue, bits, delta);
                }
            }

            // quantization step edges and midpoints, with their one-ulp neighbors.
            // the midpoints are the discriminating band: 0.005 over [0,10] at 0.01
            // quantizes to 1 under the required two roundings and to 0 under a fused
            // or widened writer (STANDARD.md)
            {
                uint stride = maxIntegerValue / 512 + 1;
                for (ulong k = 0; k <= maxIntegerValue; k += stride) // 64 bit: k += stride must not wrap at the 2^32-clamped shape
                {
                    float onQuantum = (float)(dmin + ddelta * (k / (double)maxIntegerValue));
                    float midpoint = (float)(dmin + ddelta * ((k + 0.5) / maxIntegerValue));
                    CheckCompressedFloatValueAgrees(onQuantum, min, max, res, maxIntegerValue, bits, delta);
                    CheckCompressedFloatValueAgrees(MathF.BitDecrement(onQuantum), min, max, res, maxIntegerValue, bits, delta);
                    CheckCompressedFloatValueAgrees(MathF.BitIncrement(onQuantum), min, max, res, maxIntegerValue, bits, delta);
                    CheckCompressedFloatValueAgrees(midpoint, min, max, res, maxIntegerValue, bits, delta);
                    CheckCompressedFloatValueAgrees(MathF.BitDecrement(midpoint), min, max, res, maxIntegerValue, bits, delta);
                    CheckCompressedFloatValueAgrees(MathF.BitIncrement(midpoint), min, max, res, maxIntegerValue, bits, delta);
                }
            }

            // specials: the bounds and their one-ulp neighbors, both zeros,
            // subnormals, extremes
            {
                float[] specials =
                {
                    min,
                    max,
                    MathF.BitDecrement(min),
                    MathF.BitIncrement(min),
                    MathF.BitDecrement(max),
                    MathF.BitIncrement(max),
                    min - res,
                    max + res,
                    min + res * 0.5f,
                    max - res * 0.5f,
                    min - delta,
                    max + delta,
                    0.0f,
                    -0.0f,
                    res,
                    -res,
                    floatMax,
                    -floatMax,
                    1.175494351e-38f,   // FLT_MIN
                    -1.175494351e-38f,
                    1.401298464e-45f,   // the smallest subnormal
                    -1.401298464e-45f,
                    1.0e30f,
                    -1.0e30f,
                };
                foreach (float special in specials)
                {
                    CheckCompressedFloatValueAgrees(special, min, max, res, maxIntegerValue, bits, delta);
                }
            }

#if !DEBUG
            // non-finite inputs are non-conforming and assert in debug (proven by
            // test_compressed_float_precomputed_asserts), so the release build is
            // where the differential can drive them: the clamp must force NaN and
            // both infinities to the same wire in all four implementations
            {
                uint[] nonFinitePatterns = { 0x7F800000u, 0xFF800000u, 0x7FC00000u, 0x7F800001u, 0xFFC00001u };
                foreach (uint pattern in nonFinitePatterns)
                {
                    float value = BitConverter.UInt32BitsToSingle(pattern);
                    CheckCompressedFloatValueAgrees(value, min, max, res, maxIntegerValue, bits, delta);
                }
            }
#endif // #if !DEBUG

            // LCG uniform values across the range and its overshoot band
            {
                for (int i = 0; i < 2048; i++)
                {
                    double fraction = (NextLcg() >> 11) * (1.0 / 9007199254740992.0); // [0,1) in 53 bits
                    float value = (float)(dmin - 0.25 * ddelta + fraction * 1.5 * ddelta);
                    CheckCompressedFloatValueAgrees(value, min, max, res, maxIntegerValue, bits, delta);
                }
            }

            // LCG uniform float32 bit patterns, finite ones (non-finite writes
            // assert in debug; the release-only block above drives those
            // deliberately)
            {
                for (int i = 0; i < 2048; i++)
                {
                    uint pattern = (uint)(NextLcg() >> 32);
                    float value = BitConverter.UInt32BitsToSingle(pattern);
                    if (float.IsFinite(value))
                    {
                        CheckCompressedFloatValueAgrees(value, min, max, res, maxIntegerValue, bits, delta);
                    }
                }
            }

            // the read side: every representable wire integer, including the bit
            // headroom a malicious packet can encode into. exhaustive up to 16-bit
            // widths; above that the boundary codes are pinned and the interior is
            // sampled
            {
                uint topCode = bits == 32 ? 0xFFFFFFFFu : (1u << bits) - 1u;
                if (bits <= 16)
                {
                    for (uint code = 0; code <= topCode; code++)
                    {
                        CheckCompressedFloatCodeAgrees(code, min, max, res, maxIntegerValue, bits, delta);
                    }
                }
                else
                {
                    for (uint code = 0; code <= 1024; code++)
                    {
                        CheckCompressedFloatCodeAgrees(code, min, max, res, maxIntegerValue, bits, delta);
                    }
                    uint windowLo = maxIntegerValue - 512; // maxIntegerValue >= 2^16 here, so no underflow
                    uint windowHi = topCode - maxIntegerValue < 512 ? topCode : maxIntegerValue + 512;
                    for (uint code = windowLo; code <= windowHi && code >= windowLo; code++)
                    {
                        CheckCompressedFloatCodeAgrees(code, min, max, res, maxIntegerValue, bits, delta);
                    }
                    for (uint code = topCode - 64; code <= topCode && code >= topCode - 64; code++)
                    {
                        CheckCompressedFloatCodeAgrees(code, min, max, res, maxIntegerValue, bits, delta);
                    }
                    for (int i = 0; i < 2048; i++)
                    {
                        uint code = (uint)(NextLcg() >> 32) & topCode;
                        CheckCompressedFloatCodeAgrees(code, min, max, res, maxIntegerValue, bits, delta);
                    }
                }
            }
        }

        // the coverage floor: if the differential ever silently shrinks below the
        // mass it was built with, that is a test bug, and it fails here instead of
        // fading quietly
        Check(s_compressedFloatDifferentialChecks >= 2000000,
            $"differential coverage collapsed: {s_compressedFloatDifferentialChecks} checks");

        Console.WriteLine($"    ({s_compressedFloatDifferentialChecks} checks, four implementations, {CompressedFloatShapes.Length} declarations)");

        // the negative controls, CHECKED rather than merely reported: if a
        // one-rounding writer ever stops producing a different wire code, or a
        // one-rounding reader ever stops producing a different bit pattern, then
        // everything above agrees for a reason that has nothing to do with the split
        // being correct, and this differential is decoration.
        Check(s_compressedFloatSentinelWriteDivergences > 0,
            "the write negative control stopped diverging: a one-rounding quantization now produces the same wire "
            + "codes as the audited home, so the byte comparisons above cannot see that class of change");
        Check(s_compressedFloatSentinelReadDivergences > 0,
            "the read negative control stopped diverging: a one-rounding reconstruction now produces the same decoded "
            + "bit patterns as the audited home, so the pattern comparisons above cannot see that class of change");

        Console.WriteLine($"    (negative controls diverge on {s_compressedFloatSentinelWriteDivergences} wire codes and "
            + $"{s_compressedFloatSentinelReadDivergences} decoded patterns — both must be nonzero, or the comparison "
            + "cannot see a single-rounding quantization)");
    }

#if DEBUG
    private static void TestCompressedFloatPrecomputedAsserts()
    {
        // the precomputed entry point carries the same write-side contract as
        // SerializeCompressedFloat (a non-finite value asserts, STANDARD.md) plus
        // its own: constants that are not what SerializeUtil.CompressedFloatParams
        // derives are a caller bug. prove each assert fires.

        // a fully conforming precomputed sequence must not assert, on any surface
        Check(!AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            float value = 5.0f;
            stream.SerializeCompressedFloatPrecomputed(ref value, 1000, 10, 10.0f, 0.0f);
            stream.Flush();

            MeasureStream measure = new MeasureStream();
            value = 5.0f;
            measure.SerializeCompressedFloatPrecomputed(ref value, 1000, 10, 10.0f, 0.0f);

            ReadStream read = new ReadStream(new byte[8]);
            value = 0.0f;
            read.SerializeCompressedFloatPrecomputed(ref value, 1000, 10, 10.0f, 0.0f);
        }), "a conforming precomputed sequence must not assert");

        // sending NaN through the precomputed write path is non-conforming (the
        // same ruling the derive-per-call path enforces; the quantizer is shared)
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            float nan = BitConverter.UInt32BitsToSingle(0x7fc00000); // quiet NaN
            stream.SerializeCompressedFloatPrecomputed(ref nan, 1000, 10, 10.0f, 0.0f);
        }), "a NaN precomputed compressed float write must assert in debug");

        // a wire width that disagrees with the step count is a caller bug: the
        // field would not occupy the width every other conforming implementation of
        // the declaration expects
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            float value = 5.0f;
            stream.SerializeCompressedFloatPrecomputed(ref value, 1000, 11, 10.0f, 0.0f);
        }), "inconsistent precomputed bits must assert in debug (write)");

        // ...and on the read stream: the constants are the caller's contract on
        // every stream
        Check(AssertFires(() =>
        {
            ReadStream stream = new ReadStream(new byte[8]);
            float value = 0.0f;
            stream.SerializeCompressedFloatPrecomputed(ref value, 1000, 11, 10.0f, 0.0f);
        }), "inconsistent precomputed bits must assert in debug (read)");

        // a zero step count can never come out of the derivation (values clamps up
        // to 1)
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            float value = 0.0f;
            stream.SerializeCompressedFloatPrecomputed(ref value, 0, 1, 1.0f, 0.0f);
        }), "a zero precomputed maxIntegerValue must assert in debug");

        // ...nor a non-positive delta
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[8]);
            float value = 0.0f;
            stream.SerializeCompressedFloatPrecomputed(ref value, 1000, 10, -10.0f, 0.0f);
        }), "a non-positive precomputed delta must assert in debug");
    }
#endif // DEBUG
}
