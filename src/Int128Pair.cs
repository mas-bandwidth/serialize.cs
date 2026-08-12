// The emulated 128 bit pair: Int128Value / UInt128Value.
//
// One API on every TFM (decision: Glenn, 2026-08-12, option b): the 128 bit
// serialize surface speaks THESE types everywhere, so netstandard2.1 (Unity-
// class runtimes, no System.Int128) carries the full surface, and wire
// behavior cannot diverge by framework — the same emulated arithmetic runs on
// every TFM. On .NET 7+ implicit conversions to and from System.Int128 /
// System.UInt128 make the pair transparent at call boundaries (ref parameters
// still need a pair-typed local — C# does not convert through ref).
//
// The operation set is exactly what the serialize paths need — add, subtract,
// shifts, or, compares, word casts — implemented as two's-complement math on
// (Hi, Lo) ulong halves. Nothing speculative: no mul/div/parse. ToString is
// hex, for diagnostics.

using System;
using System.Runtime.CompilerServices;

// CS1591 (missing XML docs) is disabled for the OPERATORS of the pair: `+`,
// `-`, shifts, compares and Equals/GetHashCode on a numeric emulation are
// self-describing, and thirty boilerplate summaries would bury the comments
// that carry real contract (conversion semantics, shift masking). Everything
// with a contract worth stating is documented.
#pragma warning disable CS1591

namespace Serialize
{

/// <summary>Unsigned 128 bit value as (Hi, Lo) ulong halves — the emulated
/// stand-in for System.UInt128, available on every TFM.</summary>
public struct UInt128Value : IEquatable<UInt128Value>
{
    /// <summary>The low 64 bits.</summary>
    public ulong Lo;

    /// <summary>The high 64 bits.</summary>
    public ulong Hi;

    /// <summary>Constructs from explicit high and low halves.</summary>
    public UInt128Value(ulong hi, ulong lo)
    {
        Hi = hi;
        Lo = lo;
    }

    public static readonly UInt128Value Zero = new UInt128Value(0, 0);
    public static readonly UInt128Value One = new UInt128Value(0, 1);
    public static readonly UInt128Value MaxValue = new UInt128Value(ulong.MaxValue, ulong.MaxValue);
    public static readonly UInt128Value MinValue = new UInt128Value(0, 0);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static UInt128Value operator +(UInt128Value a, UInt128Value b)
    {
        ulong lo = unchecked(a.Lo + b.Lo);
        ulong carry = lo < a.Lo ? 1ul : 0ul;
        return new UInt128Value(unchecked(a.Hi + b.Hi + carry), lo);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static UInt128Value operator -(UInt128Value a, UInt128Value b)
    {
        ulong lo = unchecked(a.Lo - b.Lo);
        ulong borrow = a.Lo < b.Lo ? 1ul : 0ul;
        return new UInt128Value(unchecked(a.Hi - b.Hi - borrow), lo);
    }

    /// <summary>Logical left shift. The count is masked to 0..127, matching
    /// System.UInt128's shift semantics.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static UInt128Value operator <<(UInt128Value v, int count)
    {
        count &= 127;
        if (count == 0)
        {
            return v;
        }
        if (count < 64)
        {
            return new UInt128Value((v.Hi << count) | (v.Lo >> (64 - count)), v.Lo << count);
        }
        return new UInt128Value(v.Lo << (count - 64), 0);
    }

    /// <summary>Logical right shift. The count is masked to 0..127, matching
    /// System.UInt128's shift semantics.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static UInt128Value operator >>(UInt128Value v, int count)
    {
        count &= 127;
        if (count == 0)
        {
            return v;
        }
        if (count < 64)
        {
            return new UInt128Value(v.Hi >> count, (v.Lo >> count) | (v.Hi << (64 - count)));
        }
        return new UInt128Value(0, v.Hi >> (count - 64));
    }

    /// <summary>The high 64 bits of a 64x64 multiply, by 32 bit limbs —
    /// netstandard2.1 has no Math.BigMul(ulong, ulong).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong MulHi64(ulong a, ulong b)
    {
        unchecked
        {
            ulong aLo = (uint)a;
            ulong aHi = a >> 32;
            ulong bLo = (uint)b;
            ulong bHi = b >> 32;
            ulong t = aLo * bLo;
            ulong carry = t >> 32;
            t = aHi * bLo + carry;
            ulong mid = (uint)t;
            ulong high = t >> 32;
            t = aLo * bHi + mid;
            return aHi * bHi + high + (t >> 32);
        }
    }

    /// <summary>Truncating (mod 2^128) multiply — the fixed point tests scale
    /// raw values with it. Matches System.UInt128's unchecked semantics.</summary>
    public static UInt128Value operator *(UInt128Value a, UInt128Value b)
    {
        unchecked
        {
            ulong lo = a.Lo * b.Lo;
            ulong hi = MulHi64(a.Lo, b.Lo) + a.Lo * b.Hi + a.Hi * b.Lo;
            return new UInt128Value(hi, lo);
        }
    }

    /// <summary>Quotient and remainder by shift-subtract long division — present
    /// because the test harnesses need them (offset generation, fixed point
    /// reference math). O(128) iterations; fine for tests and occasional use,
    /// not a hot-path primitive. Division by zero throws DivideByZeroException,
    /// matching the platform type.</summary>
    private static UInt128Value DivRem(UInt128Value a, UInt128Value b, out UInt128Value remainder)
    {
        if (b == Zero)
        {
            throw new DivideByZeroException();
        }
        if (a < b)
        {
            remainder = a;
            return Zero;
        }
        UInt128Value quotient = Zero;
        remainder = Zero;
        for (int i = 127; i >= 0; i--)
        {
            remainder = remainder << 1;
            if (((a >> i) & One) == One)
            {
                remainder = remainder | One;
            }
            if (remainder >= b)
            {
                remainder = remainder - b;
                quotient = quotient | (One << i);
            }
        }
        return quotient;
    }

    public static UInt128Value operator %(UInt128Value a, UInt128Value b)
    {
        DivRem(a, b, out UInt128Value remainder);
        return remainder;
    }

    public static UInt128Value operator /(UInt128Value a, UInt128Value b) => DivRem(a, b, out _);

    public static UInt128Value operator -(UInt128Value v) => Zero - v;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static UInt128Value operator |(UInt128Value a, UInt128Value b) =>
        new UInt128Value(a.Hi | b.Hi, a.Lo | b.Lo);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static UInt128Value operator &(UInt128Value a, UInt128Value b) =>
        new UInt128Value(a.Hi & b.Hi, a.Lo & b.Lo);

    public static bool operator ==(UInt128Value a, UInt128Value b) => a.Hi == b.Hi && a.Lo == b.Lo;
    public static bool operator !=(UInt128Value a, UInt128Value b) => !(a == b);

    public static bool operator <(UInt128Value a, UInt128Value b) =>
        a.Hi != b.Hi ? a.Hi < b.Hi : a.Lo < b.Lo;
    public static bool operator >(UInt128Value a, UInt128Value b) => b < a;
    public static bool operator <=(UInt128Value a, UInt128Value b) => !(b < a);
    public static bool operator >=(UInt128Value a, UInt128Value b) => !(a < b);

    // word casts — the serialize group writers read the low words
    public static explicit operator uint(UInt128Value v) => (uint)v.Lo;
    public static explicit operator ulong(UInt128Value v) => v.Lo;

    // the rest of the integer conversion matrix — System.UInt128 defines every
    // integer conversion directly, and without these the two-hop paths are
    // ambiguous to overload resolution. Narrowing casts truncate (unchecked).
    public static explicit operator int(UInt128Value v) => unchecked((int)v.Lo);
    public static explicit operator long(UInt128Value v) => unchecked((long)v.Lo);
    public static explicit operator ushort(UInt128Value v) => unchecked((ushort)v.Lo);
    public static explicit operator short(UInt128Value v) => unchecked((short)v.Lo);
    public static explicit operator byte(UInt128Value v) => unchecked((byte)v.Lo);
    public static explicit operator sbyte(UInt128Value v) => unchecked((sbyte)v.Lo);
    public static implicit operator UInt128Value(byte v) => new UInt128Value(0, v);
    public static implicit operator UInt128Value(ushort v) => new UInt128Value(0, v);
    public static implicit operator UInt128Value(sbyte v) =>
        new UInt128Value(v < 0 ? ulong.MaxValue : 0, unchecked((ulong)(long)v));
    public static implicit operator UInt128Value(short v) =>
        new UInt128Value(v < 0 ? ulong.MaxValue : 0, unchecked((ulong)(long)v));

    // widening conversions. Signed sources sign-extend into the high half,
    // matching System.UInt128's unchecked conversion semantics.
    public static implicit operator UInt128Value(uint v) => new UInt128Value(0, v);
    public static implicit operator UInt128Value(ulong v) => new UInt128Value(0, v);
    public static implicit operator UInt128Value(int v) =>
        new UInt128Value(v < 0 ? ulong.MaxValue : 0, unchecked((ulong)(long)v));
    public static implicit operator UInt128Value(long v) =>
        new UInt128Value(v < 0 ? ulong.MaxValue : 0, unchecked((ulong)v));

    // the signed/unsigned reinterpret pair — same bits, other domain
    public static explicit operator Int128Value(UInt128Value v) => new Int128Value(v.Hi, v.Lo);

#if NET7_0_OR_GREATER
    public static implicit operator System.UInt128(UInt128Value v) =>
        new System.UInt128(v.Hi, v.Lo);
    public static implicit operator UInt128Value(System.UInt128 v) =>
        new UInt128Value((ulong)(v >> 64), (ulong)v);
#endif // NET7_0_OR_GREATER

    public bool Equals(UInt128Value other) => this == other;
    public override bool Equals(object? obj) => obj is UInt128Value v && this == v;
    public override int GetHashCode() => (Hi ^ Lo).GetHashCode();

    /// <summary>Hex, for diagnostics: 0x&lt;Hi&gt;&lt;Lo&gt;.</summary>
    public override string ToString() => $"0x{Hi:x16}{Lo:x16}";
}

/// <summary>Signed (two's complement) 128 bit value as (Hi, Lo) ulong halves —
/// the emulated stand-in for System.Int128, available on every TFM.</summary>
public struct Int128Value : IEquatable<Int128Value>
{
    /// <summary>The low 64 bits.</summary>
    public ulong Lo;

    /// <summary>The high 64 bits (sign bit lives at bit 63 here).</summary>
    public ulong Hi;

    /// <summary>Constructs from explicit high and low halves (raw two's complement bits).</summary>
    public Int128Value(ulong hi, ulong lo)
    {
        Hi = hi;
        Lo = lo;
    }

    public static readonly Int128Value Zero = new Int128Value(0, 0);
    public static readonly Int128Value One = new Int128Value(0, 1);
    public static readonly Int128Value MaxValue = new Int128Value(0x7fff_ffff_ffff_ffff, ulong.MaxValue);
    public static readonly Int128Value MinValue = new Int128Value(0x8000_0000_0000_0000, 0);

    // two's complement: same bit math as unsigned
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Int128Value operator +(Int128Value a, Int128Value b) =>
        (Int128Value)((UInt128Value)a + (UInt128Value)b);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Int128Value operator -(Int128Value a, Int128Value b) =>
        (Int128Value)((UInt128Value)a - (UInt128Value)b);

    /// <summary>Logical left shift (bits are bits; sign is just bit 127).
    /// The count is masked to 0..127, matching System.Int128.</summary>
    public static Int128Value operator <<(Int128Value v, int count) =>
        (Int128Value)((UInt128Value)v << count);

    /// <summary>ARITHMETIC right shift — the sign bit fills in from the top,
    /// matching System.Int128.</summary>
    public static Int128Value operator >>(Int128Value v, int count)
    {
        count &= 127;
        if (count == 0)
        {
            return v;
        }
        UInt128Value u = (UInt128Value)v >> count;
        if ((long)v.Hi < 0)
        {
            // fill the vacated top bits with ones
            u = u | (UInt128Value.MaxValue << (128 - count));
        }
        return (Int128Value)u;
    }

    public static Int128Value operator -(Int128Value v) => Zero - v;

    /// <summary>Truncated-toward-zero division, matching System.Int128: divide
    /// the magnitudes in the unsigned domain, then apply the sign.</summary>
    public static Int128Value operator /(Int128Value a, Int128Value b)
    {
        bool negA = (long)a.Hi < 0;
        bool negB = (long)b.Hi < 0;
        UInt128Value magA = negA ? (UInt128Value)(Zero - a) : (UInt128Value)a;
        UInt128Value magB = negB ? (UInt128Value)(Zero - b) : (UInt128Value)b;
        UInt128Value q = magA / magB;
        return negA != negB ? Zero - (Int128Value)q : (Int128Value)q;
    }

    /// <summary>Truncating (mod 2^128) multiply — two's complement shares the
    /// unsigned bit pattern. Matches System.Int128's unchecked semantics.</summary>
    public static Int128Value operator *(Int128Value a, Int128Value b) =>
        (Int128Value)((UInt128Value)a * (UInt128Value)b);

    public static bool operator ==(Int128Value a, Int128Value b) => a.Hi == b.Hi && a.Lo == b.Lo;
    public static bool operator !=(Int128Value a, Int128Value b) => !(a == b);

    public static bool operator <(Int128Value a, Int128Value b) =>
        a.Hi != b.Hi ? (long)a.Hi < (long)b.Hi : a.Lo < b.Lo;
    public static bool operator >(Int128Value a, Int128Value b) => b < a;
    public static bool operator <=(Int128Value a, Int128Value b) => !(b < a);
    public static bool operator >=(Int128Value a, Int128Value b) => !(a < b);

    // truncating word casts (unchecked semantics, matching System.Int128)
    public static explicit operator long(Int128Value v) => unchecked((long)v.Lo);
    public static explicit operator ulong(Int128Value v) => v.Lo;

    // the rest of the integer conversion matrix — same reasoning as the
    // unsigned half: direct conversions keep overload resolution unambiguous.
    public static explicit operator int(Int128Value v) => unchecked((int)v.Lo);
    public static explicit operator uint(Int128Value v) => unchecked((uint)v.Lo);
    public static explicit operator ushort(Int128Value v) => unchecked((ushort)v.Lo);
    public static explicit operator short(Int128Value v) => unchecked((short)v.Lo);
    public static explicit operator byte(Int128Value v) => unchecked((byte)v.Lo);
    public static explicit operator sbyte(Int128Value v) => unchecked((sbyte)v.Lo);
    public static implicit operator Int128Value(byte v) => new Int128Value(0, v);
    public static implicit operator Int128Value(ushort v) => new Int128Value(0, v);
    public static implicit operator Int128Value(sbyte v) =>
        new Int128Value(v < 0 ? ulong.MaxValue : 0, unchecked((ulong)(long)v));
    public static implicit operator Int128Value(short v) =>
        new Int128Value(v < 0 ? ulong.MaxValue : 0, unchecked((ulong)(long)v));

    // widening conversions — sign-extend into the high half
    public static implicit operator Int128Value(int v) =>
        new Int128Value(v < 0 ? ulong.MaxValue : 0, unchecked((ulong)(long)v));
    public static implicit operator Int128Value(long v) =>
        new Int128Value(v < 0 ? ulong.MaxValue : 0, unchecked((ulong)v));
    public static implicit operator Int128Value(uint v) => new Int128Value(0, v);
    public static implicit operator Int128Value(ulong v) => new Int128Value(0, v);

    // the signed/unsigned reinterpret pair — same bits, other domain
    public static explicit operator UInt128Value(Int128Value v) => new UInt128Value(v.Hi, v.Lo);

#if NET7_0_OR_GREATER
    public static implicit operator System.Int128(Int128Value v) =>
        new System.Int128(v.Hi, v.Lo);
    public static implicit operator Int128Value(System.Int128 v) =>
        new Int128Value((ulong)(v >> 64), unchecked((ulong)v));
#endif // NET7_0_OR_GREATER

    public bool Equals(Int128Value other) => this == other;
    public override bool Equals(object? obj) => obj is Int128Value v && this == v;
    public override int GetHashCode() => (Hi ^ Lo).GetHashCode();

    /// <summary>Hex (raw two's complement bits), for diagnostics.</summary>
    public override string ToString() => $"0x{Hi:x16}{Lo:x16}";
}
} // namespace Serialize
