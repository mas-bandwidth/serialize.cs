/*
    Differential.cs

    Deterministic differential and hostile-read tests, modeled on the Rust port's
    tests/differential.rs (itself the C++ fuzz harness fuzz.cpp recast as
    dependency-free deterministic tests): a write→read round trip that fails on any
    write/read asymmetry and checks MeasureStream never under-measures, plus a hostile
    read of arbitrary bytes through every ReadStream primitive that must fail cleanly,
    never throw.
*/

using System;

namespace Serialize.Tests;

/// <summary>A splitmix-style generator: deterministic, seedable, no dependencies.</summary>
internal sealed class Rng
{
    private ulong _state;

    public Rng(ulong seed)
    {
        _state = seed;
    }

    public ulong Next()
    {
        _state += 0x9E3779B97F4A7C15;
        ulong z = _state;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB;
        return z ^ (z >> 31);
    }

    public ulong Range(ulong bound)
    {
        return Next() % bound;
    }
}

internal enum ValueKind
{
    Bits,
    Bits64,
    Int,
    Int64,
    Bool,
    Float,
    Double,
    Bytes,
    Align,
    String,
    IntRelative,
}

internal sealed class Value
{
    public ValueKind Kind;
    public uint U32;
    public ulong U64;
    public int Bits;
    public int I32, I32Min, I32Max;
    public long I64, I64Min, I64Max;
    public bool Flag;
    public float F32;
    public double F64;
    public byte[] Bytes = Array.Empty<byte>();
    public string Str = "";
    public int Previous, Current;
}

internal static partial class Program
{
    private static Value RandomValue(Rng rng)
    {
        switch (rng.Range(11))
        {
            case 0:
            {
                int bits = (int)rng.Range(32) + 1;
                uint value = (uint)rng.Next() & (uint)((1UL << bits) - 1);
                return new Value { Kind = ValueKind.Bits, U32 = value, Bits = bits };
            }
            case 1:
            {
                int bits = (int)rng.Range(64) + 1;
                ulong mask = bits == 64 ? ulong.MaxValue : (1UL << bits) - 1;
                return new Value { Kind = ValueKind.Bits64, U64 = rng.Next() & mask, Bits = bits };
            }
            case 2:
            {
                int a = (int)(uint)rng.Next();
                int b = (int)(uint)rng.Next();
                int min, max;
                if (a < b)
                {
                    (min, max) = (a, b);
                }
                else if (a > b)
                {
                    (min, max) = (b, a);
                }
                else if (a == int.MaxValue)
                {
                    (min, max) = (a - 1, a);
                }
                else
                {
                    (min, max) = (a, a + 1);
                }
                // pick a value in [min,max] in the unsigned domain so wide ranges
                // cannot overflow
                uint range = (uint)max - (uint)min;
                uint offset = range == uint.MaxValue ? (uint)rng.Next() : (uint)rng.Next() % (range + 1);
                int value = (int)((uint)min + offset);
                return new Value { Kind = ValueKind.Int, I32 = value, I32Min = min, I32Max = max };
            }
            case 3:
            {
                long a = (long)rng.Next();
                long b = (long)rng.Next();
                long min, max;
                if (a < b)
                {
                    (min, max) = (a, b);
                }
                else if (a > b)
                {
                    (min, max) = (b, a);
                }
                else if (a == long.MaxValue)
                {
                    (min, max) = (a - 1, a);
                }
                else
                {
                    (min, max) = (a, a + 1);
                }
                ulong span = (ulong)max - (ulong)min + 1;
                ulong offset = span == 0 ? rng.Next() : rng.Next() % span;
                long value = (long)((ulong)min + offset);
                return new Value { Kind = ValueKind.Int64, I64 = value, I64Min = min, I64Max = max };
            }
            case 4:
                return new Value { Kind = ValueKind.Bool, Flag = rng.Range(2) == 1 };
            case 5:
                return new Value { Kind = ValueKind.Float, F32 = BitConverter.UInt32BitsToSingle((uint)rng.Next()) };
            case 6:
                return new Value { Kind = ValueKind.Double, F64 = BitConverter.UInt64BitsToDouble(rng.Next()) };
            case 7:
            {
                byte[] data = new byte[rng.Range(32)];
                for (int i = 0; i < data.Length; i++)
                {
                    data[i] = (byte)rng.Next();
                }
                return new Value { Kind = ValueKind.Bytes, Bytes = data };
            }
            case 8:
                return new Value { Kind = ValueKind.Align };
            case 9:
            {
                int len = (int)rng.Range(14);
                char[] chars = new char[len];
                for (int i = 0; i < len; i++)
                {
                    chars[i] = (char)('a' + (int)rng.Range(26));
                }
                return new Value { Kind = ValueKind.String, Str = new string(chars) };
            }
            default:
            {
                int previous = (int)(uint)rng.Next();
                uint gap = (uint)rng.Range(1 << 20) + 1;
                int current = (int)((uint)previous + gap);
                // int relative requires previous < current in the signed domain on the
                // write side
                if (previous < current)
                {
                    return new Value { Kind = ValueKind.IntRelative, Previous = previous, Current = current };
                }
                return new Value { Kind = ValueKind.IntRelative, Previous = 0, Current = (int)gap };
            }
        }
    }

    private static bool SerializeValue(IBitStream stream, Value value)
    {
        switch (value.Kind)
        {
            case ValueKind.Bits: return stream.SerializeBits(ref value.U32, value.Bits);
            case ValueKind.Bits64: return stream.SerializeBits64(ref value.U64, value.Bits);
            case ValueKind.Int: return stream.SerializeInt(ref value.I32, value.I32Min, value.I32Max);
            case ValueKind.Int64: return stream.SerializeInt64(ref value.I64, value.I64Min, value.I64Max);
            case ValueKind.Bool: return stream.SerializeBool(ref value.Flag);
            case ValueKind.Float: return stream.SerializeFloat(ref value.F32);
            case ValueKind.Double: return stream.SerializeDouble(ref value.F64);
            case ValueKind.Bytes: return stream.SerializeBytes(value.Bytes);
            case ValueKind.Align: return stream.SerializeAlign();
            case ValueKind.String: return stream.SerializeString(ref value.Str, 16);
            default: return stream.SerializeIntRelative(value.Previous, ref value.Current);
        }
    }

    private static Value Blank(Value value)
    {
        switch (value.Kind)
        {
            case ValueKind.Bits: return new Value { Kind = ValueKind.Bits, U32 = 0, Bits = value.Bits };
            case ValueKind.Bits64: return new Value { Kind = ValueKind.Bits64, U64 = 0, Bits = value.Bits };
            case ValueKind.Int: return new Value { Kind = ValueKind.Int, I32 = value.I32Min, I32Min = value.I32Min, I32Max = value.I32Max };
            case ValueKind.Int64: return new Value { Kind = ValueKind.Int64, I64 = value.I64Min, I64Min = value.I64Min, I64Max = value.I64Max };
            case ValueKind.Bool: return new Value { Kind = ValueKind.Bool, Flag = false };
            case ValueKind.Float: return new Value { Kind = ValueKind.Float, F32 = 0 };
            case ValueKind.Double: return new Value { Kind = ValueKind.Double, F64 = 0 };
            case ValueKind.Bytes: return new Value { Kind = ValueKind.Bytes, Bytes = new byte[value.Bytes.Length] };
            case ValueKind.Align: return new Value { Kind = ValueKind.Align };
            case ValueKind.String: return new Value { Kind = ValueKind.String, Str = "" };
            default: return new Value { Kind = ValueKind.IntRelative, Previous = value.Previous, Current = 0 };
        }
    }

    /// <summary>Compare a written value against its read-back. Floats compare by bit
    /// pattern so NaN round trips count as equal.</summary>
    private static bool Matches(Value written, Value read)
    {
        if (written.Kind != read.Kind)
        {
            return false;
        }
        switch (written.Kind)
        {
            case ValueKind.Bits: return written.U32 == read.U32;
            case ValueKind.Bits64: return written.U64 == read.U64;
            case ValueKind.Int: return written.I32 == read.I32;
            case ValueKind.Int64: return written.I64 == read.I64;
            case ValueKind.Bool: return written.Flag == read.Flag;
            case ValueKind.Float:
                return BitConverter.SingleToUInt32Bits(written.F32) == BitConverter.SingleToUInt32Bits(read.F32);
            case ValueKind.Double:
                return BitConverter.DoubleToUInt64Bits(written.F64) == BitConverter.DoubleToUInt64Bits(read.F64);
            case ValueKind.Bytes: return written.Bytes.AsSpan().SequenceEqual(read.Bytes);
            case ValueKind.Align: return true;
            case ValueKind.String: return written.Str == read.Str;
            default: return written.Current == read.Current;
        }
    }

    private const ulong RoundTripSeeds = 500;
    private const ulong HostileSeeds = 2000;

    private static void TestDifferentialRoundTrip()
    {
        // write a random value sequence, then a read of the same sequence must return
        // exactly the written values, and the measure stream must never under-measure
        // the write
        for (ulong seed = 0; seed < RoundTripSeeds; seed++)
        {
            Rng rng = new Rng(seed);
            int numValues = (int)rng.Range(30) + 1;
            Value[] values = new Value[numValues];
            for (int i = 0; i < numValues; i++)
            {
                values[i] = RandomValue(rng);
            }

            byte[] buffer = new byte[4096];

            WriteStream writeStream = new WriteStream(buffer);
            foreach (Value value in values)
            {
                Check(SerializeValue(writeStream, value), $"seed {seed}: write failed: {writeStream.Error}");
            }
            writeStream.Flush();
            long bitsWritten = writeStream.BitsProcessed;
            int bytesWritten = (int)writeStream.BytesProcessed;

            MeasureStream measureStream = new MeasureStream();
            foreach (Value value in values)
            {
                Check(SerializeValue(measureStream, value), $"seed {seed}: measure failed: {measureStream.Error}");
            }
            Check(measureStream.BitsProcessed >= bitsWritten,
                $"seed {seed}: measure under-measured: {measureStream.BitsProcessed} < {bitsWritten}");

            ReadStream readStream = new ReadStream(buffer, bytesWritten);
            for (int index = 0; index < numValues; index++)
            {
                Value read = Blank(values[index]);
                Check(SerializeValue(readStream, read),
                    $"seed {seed} value {index}: read failed: {readStream.Error}");
                Check(Matches(values[index], read),
                    $"seed {seed} value {index}: read does not match written value (kind {values[index].Kind})");
            }
        }
    }

    /// <summary>A field-for-field copy, used to verify that failed hostile reads leave
    /// the caller's value bit identical.</summary>
    private static Value Snapshot(Value value)
    {
        return new Value
        {
            Kind = value.Kind,
            U32 = value.U32,
            U64 = value.U64,
            Bits = value.Bits,
            I32 = value.I32,
            I32Min = value.I32Min,
            I32Max = value.I32Max,
            I64 = value.I64,
            I64Min = value.I64Min,
            I64Max = value.I64Max,
            Flag = value.Flag,
            F32 = value.F32,
            F64 = value.F64,
            Bytes = (byte[])value.Bytes.Clone(),
            Str = value.Str,
            Previous = value.Previous,
            Current = value.Current,
        };
    }

    private static void TestHostileRead()
    {
        // arbitrary bytes driven through every ReadStream primitive must fail cleanly
        // with a latched error, never throw; a failed call must leave the caller's
        // value bit identical and a non-None error latched on the stream. mirrors the
        // hostile pass of the C++ fuzz harness.
        for (ulong seed = 0; seed < HostileSeeds; seed++)
        {
            Rng rng = new Rng(~seed);

            int len = (int)rng.Range(64);
            byte[] buffer = new byte[len + 8];
            for (int i = 0; i < buffer.Length; i++)
            {
                buffer[i] = (byte)rng.Next();
            }

            ReadStream stream = new ReadStream(buffer, len);

            for (int i = 0; i < 40; i++)
            {
                // hostile data may or may not decode; when a call reports failure the
                // value must be untouched and an error must be latched
                Value op = RandomValue(rng);
                if (op.Kind == ValueKind.String)
                {
                    string s = op.Str;
                    if (!stream.SerializeString(ref s, 64))
                    {
                        Check(s == op.Str, $"seed {seed}: failed string read modified the value");
                        Check(stream.Error != SerializeError.None,
                            $"seed {seed}: failed read did not latch an error");
                    }
                }
                else
                {
                    Value before = Snapshot(op);
                    if (!SerializeValue(stream, op))
                    {
                        Check(Matches(before, op),
                            $"seed {seed}: failed read modified the value (kind {op.Kind})");
                        Check(stream.Error != SerializeError.None,
                            $"seed {seed}: failed read did not latch an error");
                    }
                }

                // wide strings are not in RandomValue (the write side would need valid
                // code points), so drive them here against the hostile bytes too
                string wide = "unchanged";
                if (!stream.SerializeWideString(ref wide, 64))
                {
                    Check(wide == "unchanged", $"seed {seed}: failed wide string read modified the value");
                    Check(stream.Error != SerializeError.None,
                        $"seed {seed}: failed read did not latch an error");
                }
            }

            // the reader never consumes past the declared packet length
            Check(stream.BitsProcessed <= (long)len * 8,
                $"seed {seed}: consumed {stream.BitsProcessed} bits from a {len} byte packet");
        }
    }
}
