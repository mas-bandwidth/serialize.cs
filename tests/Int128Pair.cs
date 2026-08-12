/*
    The pair vs the oracle: on .NET 7+ every Int128Value/UInt128Value operation
    is checked against System.Int128/System.UInt128 over deliberate edge values
    and a large random sweep — the oracle is the platform type itself, so a
    single mismatched bit in the emulated arithmetic fails loudly. On
    netstandard2.1 there is no oracle; cross-TFM correctness rides the golden
    wire pins, which this same arithmetic feeds, plus the TFM-independent
    algebra checks at the bottom.
*/

using System;
using Serialize;

namespace Serialize.Tests;

internal static partial class Program
{
    private static readonly ulong[] s_edgeWords =
    {
        0ul, 1ul, 2ul, 0x7fff_ffff_ffff_fffful, 0x8000_0000_0000_0000ul,
        0xffff_ffff_ffff_fffful, 0xffff_fffful, 0x1_0000_0000ul, 0xdead_beef_cafe_f00dul,
    };

    private static UInt128Value RandomPairValue(Random rng)
    {
        byte[] bytes = new byte[16];
        rng.NextBytes(bytes);
        return new UInt128Value(BitConverter.ToUInt64(bytes, 8), BitConverter.ToUInt64(bytes, 0));
    }

#if SERIALIZE_HAS_INT128

    private static void TestInt128PairUnsignedOracle()
    {
        var rng = new Random(12345);
        var edges = new System.Collections.Generic.List<UInt128Value>();
        foreach (ulong hi in s_edgeWords)
        {
            foreach (ulong lo in s_edgeWords)
            {
                edges.Add(new UInt128Value(hi, lo));
            }
        }
        int iterations = 10000;
        for (int i = 0; i < iterations; i++)
        {
            UInt128Value a = i < edges.Count ? edges[i] : RandomPairValue(rng);
            UInt128Value b = i < edges.Count ? edges[edges.Count - 1 - i] : RandomPairValue(rng);
            UInt128 oa = a;
            UInt128 ob = b;

            Check((UInt128)(a + b) == unchecked(oa + ob), "pair add matches the oracle");
            Check((UInt128)(a - b) == unchecked(oa - ob), "pair sub matches the oracle");
            Check((UInt128)(a | b) == (oa | ob), "pair or matches the oracle");
            Check((UInt128)(a & b) == (oa & ob), "pair and matches the oracle");
            Check((oa == ob) == (a == b), "pair equality matches the oracle");
            Check((oa < ob) == (a < b), "pair less-than matches the oracle");
            Check((oa > ob) == (a > b), "pair greater-than matches the oracle");
            Check((oa <= ob) == (a <= b), "pair less-equal matches the oracle");
            Check((oa >= ob) == (a >= b), "pair greater-equal matches the oracle");
            Check((uint)oa == (uint)a, "pair uint cast matches the oracle");
            Check((ulong)oa == (ulong)a, "pair ulong cast matches the oracle");

            for (int shift = 0; shift < 128; shift++)
            {
                Check((UInt128)(a << shift) == oa << shift, "pair left shift matches the oracle");
                Check((UInt128)(a >> shift) == oa >> shift, "pair right shift matches the oracle");
            }
        }
    }

    private static void TestInt128PairSignedOracle()
    {
        var rng = new Random(54321);
        int iterations = 10000;
        for (int i = 0; i < iterations; i++)
        {
            Int128Value a = (Int128Value)RandomPairValue(rng);
            Int128Value b = (Int128Value)RandomPairValue(rng);
            Int128 oa = a;
            Int128 ob = b;

            Check((Int128)(a + b) == unchecked(oa + ob), "signed pair add matches the oracle");
            Check((Int128)(a - b) == unchecked(oa - ob), "signed pair sub matches the oracle");
            Check((oa == ob) == (a == b), "signed pair equality matches the oracle");
            Check((oa < ob) == (a < b), "signed pair less-than matches the oracle");
            Check((oa > ob) == (a > b), "signed pair greater-than matches the oracle");
            Check((oa <= ob) == (a <= b), "signed pair less-equal matches the oracle");
            Check((oa >= ob) == (a >= b), "signed pair greater-equal matches the oracle");
            Check(unchecked((long)oa) == (long)a, "signed pair long cast matches the oracle");
            Check((Int128Value)(UInt128Value)a == a, "the reinterpret pair round-trips bits");
        }

        // conversions at the edges
        long[] signedEdges = { 0, 1, -1, long.MaxValue, long.MinValue, int.MaxValue, int.MinValue, -12345 };
        foreach (long v in signedEdges)
        {
            Check((Int128)(Int128Value)v == (Int128)v, "long conversion matches the oracle");
            Check((UInt128)(UInt128Value)v == unchecked((UInt128)(Int128)v), "long-to-unsigned conversion matches the oracle");
        }
        Check((Int128Value)Int128.MinValue == Int128Value.MinValue, "MinValue round-trips");
        Check((Int128Value)Int128.MaxValue == Int128Value.MaxValue, "MaxValue round-trips");
        Check((UInt128Value)UInt128.MaxValue == UInt128Value.MaxValue, "unsigned MaxValue round-trips");
    }

#endif // SERIALIZE_HAS_INT128

    // TFM-independent: the constants and basic algebra hold everywhere,
    // including netstandard2.1 where there is no oracle.
    private static void TestInt128PairBasics()
    {
        Check(UInt128Value.MaxValue + UInt128Value.One == UInt128Value.Zero, "unsigned wraps at 2^128");
        Check(Int128Value.MaxValue + Int128Value.One == Int128Value.MinValue, "signed wraps to MinValue");
        Check(Int128Value.MinValue < Int128Value.Zero, "MinValue is below zero");
        Check(Int128Value.Zero < Int128Value.MaxValue, "zero is below MaxValue");
        Check(UInt128Value.Zero < UInt128Value.MaxValue, "unsigned ordering holds");

        UInt128Value v = new UInt128Value(0xdead_beef_0000_0000, 0x0000_0000_cafe_f00d);
        Check((v << 64) >> 64 == new UInt128Value(0, 0x0000_0000_cafe_f00d), "shift by 64 round-trips the low half");
        Check(v.ToString() == "0xdeadbeef0000000000000000cafef00d", "hex ToString");

        // add/sub carry across the half boundary
        UInt128Value nearCarry = new UInt128Value(0, ulong.MaxValue);
        Check(nearCarry + UInt128Value.One == new UInt128Value(1, 0), "carry crosses into the high half");
        Check(new UInt128Value(1, 0) - UInt128Value.One == nearCarry, "borrow crosses out of the high half");
    }
}
