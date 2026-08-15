/*
    Compat.cs

    The C# half of the cross language wire compatibility harness. Its C++ twin is
    cpp/compat.cpp, built directly against the C++ serialize.h; the interop gate runs
    both against each other: each side writes its stream to a file, the two files must
    be byte identical, and each side must read the other's file back to the exact
    values.

    The value sequence starts as the golden wire format sequence (pinned to bytes
    copied verbatim from the C++ test suite) and extends it with the 64 bit paths the
    golden test does not cover, matching the Go port's compat harness. Any change here
    must be mirrored in cpp/compat.cpp, and never changes the wire format.

    The sequence carries a degenerate range (min == max) in the MIDDLE, which costs
    zero bits: it proves the field is free on the wire AND that every field after it
    stays put, which a trailing field could not show. Because it writes nothing, adding
    it left the bytes identical -- the gate's byte-identity cmp is the proof.

    The tail is the fixed point / 128 bit section, the six fields the C++
    GoldenWireData carries, with the golden message's structure: the section starts
    byte aligned, and the two wide (128 bit storage) fields start byte aligned again.
    The values are the C++ golden values verbatim, so the gate proves the Q format
    codec and the emulated 128 bit pair against the real serialize.h -- three group
    and four group offset encodings included.
*/

using System;
using System.IO;

namespace Serialize.Compat;

internal sealed class CompatData
{
    public uint Bits4;
    public uint Bits11;
    public uint Bits24;
    public uint Bits32;
    public int IntSmall;
    public int IntFull;
    public int Degenerate;
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
    public ulong Bits33;
    public long Int64Full;
    public long Int64Range;
    public float FmaBoundaryFloat;
    public short FixedQ8_8;
    public int FixedQ16_16;
    public long FixedQ48_16;
    public uint FixedQ16_16Unsigned;
    public Int128Value FixedQ112_16Wide;
    public Int128Value FixedQ64_64Wide;

    public static CompatData Init()
    {
        return new CompatData
        {
            Bits4 = 13,
            Bits11 = 1445,
            Bits24 = 11259375,
            Bits32 = 0xDEADBEEF,
            IntSmall = -37,
            IntFull = -123456789,
            Degenerate = 42, // min == max: known from the range alone, zero bits on the wire
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
            Bits33 = 0x1DEADBEEF,
            Int64Full = -123456789012345,
            Int64Range = 4123456789,
            // 0.005 in [0,10] res 0.01 normalizes to a t = 1.0f quantization boundary:
            // strict IEEE mul-then-add rounds up to integer 1, a fused multiply-add
            // rounds down to 0. C# always evaluates strictly; the C++ half must be
            // built with -ffp-contract=off (strict evaluation is the normative wire)
            FmaBoundaryFloat = 0.005f,
            // the C++ GoldenWireData fixed point values, verbatim
            FixedQ8_8 = -(3 * 256 + 64),                        // -3.25 in Q8.8
            FixedQ16_16 = 1234 * 65536 + 32768,                 // 1234.5 in Q16.16
            FixedQ48_16 = -(54321L * 65536 + 12345),            // -54321.1883... in Q48.16
            FixedQ16_16Unsigned = 29999u * 65536u + 65535u,     // 29999.99998... in Q16.16: every fraction bit set
            FixedQ112_16Wide = -(98765432109L * 65536 + 4321),  // -98765432109.066 in Q112.16: 75 bits on the wire, three groups
            FixedQ64_64Wide = ((Int128Value)0x0123456789ABCDEF << 64)
                            + 0x0FEDCBA987654321,               // Q64.64 over the full unit range: 128 bits, four groups, every group distinct
        };
    }

    public bool Serialize(IBitStream stream)
    {
        const int relativeBase = 100;
        stream.SerializeBits(ref Bits4, 4);
        stream.SerializeBits(ref Bits11, 11);
        stream.SerializeBits(ref Bits24, 24);
        stream.SerializeBits(ref Bits32, 32);
        stream.SerializeInt(ref IntSmall, -100, +100);
        stream.SerializeInt(ref IntFull, int.MinValue, int.MaxValue);
        // the degenerate range: zero bits, and every field below must stay put
        stream.SerializeInt(ref Degenerate, 42, 42);
        stream.SerializeBool(ref Flag);
        stream.SerializeFloat(ref FloatValue);
        stream.SerializeCompressedFloat(ref CompressedFloatValue, 0.0f, 10.0f, 0.01f);
        stream.SerializeDouble(ref DoubleValue);
        stream.SerializeByte(ref UInt8Value);
        stream.SerializeUInt16(ref UInt16Value);
        stream.SerializeUInt32(ref UInt32Value);
        stream.SerializeUInt64(ref UInt64Value);
        stream.SerializeIntRelative(relativeBase, ref RelativeNear);
        stream.SerializeIntRelative(relativeBase, ref RelativeFar);
        stream.SerializeAlign();
        stream.SerializeBytes(Bytes);
        stream.SerializeString(ref Str, 16);
        stream.SerializeWideString(ref WStr, 8);
        stream.SerializeBits64(ref Bits33, 33);
        stream.SerializeInt64(ref Int64Full, long.MinValue, long.MaxValue);
        stream.SerializeInt64(ref Int64Range, -5000000000, +5000000000);
        stream.SerializeCompressedFloat(ref FmaBoundaryFloat, 0.0f, 10.0f, 0.01f);
        // the fixed point / 128 bit section, with the golden message's structure:
        // it starts byte aligned, so every bit above it stays put
        stream.SerializeAlign();
        stream.SerializeFixed(ref FixedQ8_8, 8, 8, -100, +100);
        stream.SerializeFixed(ref FixedQ16_16, 16, 16, -2000, +2000);
        stream.SerializeFixed(ref FixedQ48_16, 48, 16, -100000, +100000);
        stream.SerializeFixed(ref FixedQ16_16Unsigned, 16, 16, 0, 30000);
        stream.SerializeAlign(); // the wide fixed section starts byte aligned too
        stream.SerializeFixed(ref FixedQ112_16Wide, 112, 16, -144115188075855872, +144115188075855872); // ±2^57 units: 75 bits, the three group structure
        stream.SerializeFixed(ref FixedQ64_64Wide, 64, 64, long.MinValue, long.MaxValue);               // full unit range: 128 bits, the four group structure
        return stream.Error == SerializeError.None;
    }

    public bool DataEquals(CompatData other)
    {
        return Bits4 == other.Bits4
            && Bits11 == other.Bits11
            && Bits24 == other.Bits24
            && Bits32 == other.Bits32
            && IntSmall == other.IntSmall
            && IntFull == other.IntFull
            && Degenerate == other.Degenerate
            && Flag == other.Flag
            && FloatValue == other.FloatValue
            && CompressedFloatValue == other.CompressedFloatValue
            && DoubleValue == other.DoubleValue
            && UInt8Value == other.UInt8Value
            && UInt16Value == other.UInt16Value
            && UInt32Value == other.UInt32Value
            && UInt64Value == other.UInt64Value
            && RelativeNear == other.RelativeNear
            && RelativeFar == other.RelativeFar
            && Bytes.AsSpan().SequenceEqual(other.Bytes)
            && Str == other.Str
            && WStr == other.WStr
            && Bits33 == other.Bits33
            && Int64Full == other.Int64Full
            && Int64Range == other.Int64Range
            && FixedQ8_8 == other.FixedQ8_8
            && FixedQ16_16 == other.FixedQ16_16
            && FixedQ48_16 == other.FixedQ48_16
            && FixedQ16_16Unsigned == other.FixedQ16_16Unsigned
            && FixedQ112_16Wide == other.FixedQ112_16Wide
            && FixedQ64_64Wide == other.FixedQ64_64Wide
            // compare within the resolution: 0.005 decodes to 0.01
            && Math.Abs(FmaBoundaryFloat - other.FmaBoundaryFloat) <= 0.01f;
    }
}

internal static class Program
{
    private static int Write(string path)
    {
        byte[] buffer = new byte[256];
        WriteStream stream = new WriteStream(buffer);
        CompatData data = CompatData.Init();
        if (!data.Serialize(stream))
        {
            Console.Error.WriteLine($"compat cs write: serialize failed: {stream.Error}");
            return 1;
        }
        stream.Flush();
        File.WriteAllBytes(path, stream.Data.ToArray());
        Console.WriteLine("compat cs write ok");
        return 0;
    }

    private static int Read(string path)
    {
        byte[] packet = File.ReadAllBytes(path);
        // keep 8 bytes of slack past the packet for branchless window loads (optional
        // for correctness, but it exercises the fast path the C++ reader requires)
        byte[] buffer = new byte[packet.Length + 8];
        packet.CopyTo(buffer, 0);
        ReadStream stream = new ReadStream(buffer, packet.Length);
        CompatData data = new CompatData();
        if (!data.Serialize(stream))
        {
            Console.Error.WriteLine($"compat cs read: serialize failed: {stream.Error}");
            return 1;
        }
        CompatData expected = CompatData.Init();
        if (!data.DataEquals(expected))
        {
            Console.Error.WriteLine("compat cs read: decoded values do not match");
            return 1;
        }
        Console.WriteLine("compat cs read ok");
        return 0;
    }

    private static int Main(string[] args)
    {
        if (args.Length != 2 || (args[0] != "write" && args[0] != "read"))
        {
            Console.Error.WriteLine("usage: compat write|read <file>");
            return 2;
        }
        return args[0] == "write" ? Write(args[1]) : Read(args[1]);
    }
}
