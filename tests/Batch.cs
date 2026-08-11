/*
    Batch.cs

    Tests for the batch layer: WriteBatch and ReadBatch, the register-resident views
    of WriteStream and ReadStream. The wire law is proven three ways: the batch write
    of the golden sequences (the golden message and the fixed point section) must
    produce the pinned golden bytes exactly, a randomized differential pass must be
    byte identical to the class path with batches begun and ended at arbitrary points
    (including direct stream calls between batches), and the delegated operations
    (bytes, strings, objects, int relative, the 128 bit integers and fixed point)
    ride the class path inside those sequences. Error latching, End idempotence and
    the zero-allocation invariant are pinned separately.
*/

using System;

namespace Serialize.Tests;

internal static partial class Program
{
    // The golden serialize mirrored onto the batch surface: the exact same calls as
    // GoldenWireData.Serialize, method for method. Any change there must be mirrored
    // here, and never changes the wire format.
    private static bool SerializeGoldenBatch(ref WriteBatch stream, GoldenWireData data)
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

    private static bool SerializeGoldenBatch(ref ReadBatch stream, GoldenWireData data)
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

#if SERIALIZE_HAS_INT128 // fixed point rides the gated 128 surface
    // The fixed point golden serialize mirrored onto the batch surface: the exact
    // same calls as FixedWireData.Serialize, method for method — the fixed point and
    // wide integer section of the wire law, proven through the batch layer too.
    private static bool SerializeFixedWireBatch(ref WriteBatch stream, FixedWireData data)
    {
        stream.SerializeFixed(ref data.FixedQ8_8, 8, 8, -100, +100);
        stream.SerializeFixed(ref data.FixedQ16_16, 16, 16, -2000, +2000);
        stream.SerializeFixed(ref data.FixedQ48_16, 48, 16, -100000, +100000);
        stream.SerializeFixed(ref data.FixedQ16_16Unsigned, 16, 16, 0, 30000);
        stream.SerializeAlign();                                    // the wide fixed section starts byte aligned
        stream.SerializeFixed(ref data.FixedQ112_16Wide, 112, 16, -144115188075855872, +144115188075855872);
        stream.SerializeFixed(ref data.FixedQ64_64Wide, 64, 64, long.MinValue, long.MaxValue);
        return stream.Error == SerializeError.None;
    }

    private static bool SerializeFixedWireBatch(ref ReadBatch stream, FixedWireData data)
    {
        stream.SerializeFixed(ref data.FixedQ8_8, 8, 8, -100, +100);
        stream.SerializeFixed(ref data.FixedQ16_16, 16, 16, -2000, +2000);
        stream.SerializeFixed(ref data.FixedQ48_16, 48, 16, -100000, +100000);
        stream.SerializeFixed(ref data.FixedQ16_16Unsigned, 16, 16, 0, 30000);
        stream.SerializeAlign();                                    // the wide fixed section starts byte aligned
        stream.SerializeFixed(ref data.FixedQ112_16Wide, 112, 16, -144115188075855872, +144115188075855872);
        stream.SerializeFixed(ref data.FixedQ64_64Wide, 64, 64, long.MinValue, long.MaxValue);
        return stream.Error == SerializeError.None;
    }
#endif // SERIALIZE_HAS_INT128

#if SERIALIZE_HAS_INT128 // gated out when the library TFM lacks the 128 bit surface (netstandard2.1)
    /// <summary>Drives the WriteBatch SerializeFixed overload selected by storage:
    /// the batch counterpart of SerializeFixedAs(FixedStorage, IBitStream, ...) in
    /// FixedPoint.cs. Ref structs cannot implement IBitStream, so the dispatch is
    /// mirrored onto each batch surface.</summary>
    private static bool SerializeFixedAs(
        FixedStorage storage, ref WriteBatch batch, ref Int128 carrier,
        int integerBits, int fractionBits, long min, long max)
    {
        switch (storage)
        {
            case FixedStorage.I16:
            {
                short value = (short)carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.U16:
            {
                ushort value = (ushort)carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.I32:
            {
                int value = (int)carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.U32:
            {
                uint value = (uint)carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.I64:
            {
                long value = (long)carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.U64:
            {
                ulong value = (ulong)carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.I128:
            {
                Int128 value = carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            default:
            {
                UInt128 value = (UInt128)carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = (Int128)value;
                return ok;
            }
        }
    }

    /// <summary>The ReadBatch counterpart of the WriteBatch SerializeFixedAs above.</summary>
    private static bool SerializeFixedAs(
        FixedStorage storage, ref ReadBatch batch, ref Int128 carrier,
        int integerBits, int fractionBits, long min, long max)
    {
        switch (storage)
        {
            case FixedStorage.I16:
            {
                short value = (short)carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.U16:
            {
                ushort value = (ushort)carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.I32:
            {
                int value = (int)carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.U32:
            {
                uint value = (uint)carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.I64:
            {
                long value = (long)carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.U64:
            {
                ulong value = (ulong)carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            case FixedStorage.I128:
            {
                Int128 value = carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            default:
            {
                UInt128 value = (UInt128)carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = (Int128)value;
                return ok;
            }
        }
    }
#endif // SERIALIZE_HAS_INT128

    // The differential value dispatch mirrored onto the batch surfaces: the same
    // switch as SerializeValue(IBitStream, Value), case for case. A new ValueKind
    // must be added here explicitly — a default bucket that aliases another kind's
    // operation silently miswires the batch side of the differential.
    private static bool SerializeValueBatch(ref WriteBatch batch, Value value)
    {
        switch (value.Kind)
        {
            case ValueKind.Bits: return batch.SerializeBits(ref value.U32, value.Bits);
            case ValueKind.Bits64: return batch.SerializeBits64(ref value.U64, value.Bits);
            case ValueKind.Int: return batch.SerializeInt(ref value.I32, value.I32Min, value.I32Max);
            case ValueKind.Int64: return batch.SerializeInt64(ref value.I64, value.I64Min, value.I64Max);
            case ValueKind.Bool: return batch.SerializeBool(ref value.Flag);
            case ValueKind.Float: return batch.SerializeFloat(ref value.F32);
            case ValueKind.Double: return batch.SerializeDouble(ref value.F64);
            case ValueKind.Bytes: return batch.SerializeBytes(value.Bytes);
            case ValueKind.Align: return batch.SerializeAlign();
            case ValueKind.String: return batch.SerializeString(ref value.Str, 16);
            case ValueKind.IntRelative: return batch.SerializeIntRelative(value.Previous, ref value.Current);
#if SERIALIZE_HAS_INT128 // gated out when the library TFM lacks the 128 bit surface (netstandard2.1)
            case ValueKind.UInt128: return batch.SerializeUInt128(ref value.U128);
            case ValueKind.Int128: return batch.SerializeInt128(ref value.I128, value.I128Min, value.I128Max);
#endif // SERIALIZE_HAS_INT128
#if SERIALIZE_HAS_INT128
            default:
            {
                (FixedStorage storage, int integerBits, int fractionBits, long min, long max) = FixedConfigs[value.FixedConfig];
                return SerializeFixedAs(storage, ref batch, ref value.I128, integerBits, fractionBits, min, max);
            }
#else
            default:
            {
                Check(false, "the 128/fixed kinds are not generated without the 128 surface");
                return false;
            }
#endif // SERIALIZE_HAS_INT128
        }
    }

    private static bool SerializeValueBatch(ref ReadBatch batch, Value value)
    {
        switch (value.Kind)
        {
            case ValueKind.Bits: return batch.SerializeBits(ref value.U32, value.Bits);
            case ValueKind.Bits64: return batch.SerializeBits64(ref value.U64, value.Bits);
            case ValueKind.Int: return batch.SerializeInt(ref value.I32, value.I32Min, value.I32Max);
            case ValueKind.Int64: return batch.SerializeInt64(ref value.I64, value.I64Min, value.I64Max);
            case ValueKind.Bool: return batch.SerializeBool(ref value.Flag);
            case ValueKind.Float: return batch.SerializeFloat(ref value.F32);
            case ValueKind.Double: return batch.SerializeDouble(ref value.F64);
            case ValueKind.Bytes: return batch.SerializeBytes(value.Bytes);
            case ValueKind.Align: return batch.SerializeAlign();
            case ValueKind.String: return batch.SerializeString(ref value.Str, 16);
            case ValueKind.IntRelative: return batch.SerializeIntRelative(value.Previous, ref value.Current);
#if SERIALIZE_HAS_INT128 // gated out when the library TFM lacks the 128 bit surface (netstandard2.1)
            case ValueKind.UInt128: return batch.SerializeUInt128(ref value.U128);
            case ValueKind.Int128: return batch.SerializeInt128(ref value.I128, value.I128Min, value.I128Max);
#endif // SERIALIZE_HAS_INT128
#if SERIALIZE_HAS_INT128
            default:
            {
                (FixedStorage storage, int integerBits, int fractionBits, long min, long max) = FixedConfigs[value.FixedConfig];
                return SerializeFixedAs(storage, ref batch, ref value.I128, integerBits, fractionBits, min, max);
            }
#else
            default:
            {
                Check(false, "the 128/fixed kinds are not generated without the 128 surface");
                return false;
            }
#endif // SERIALIZE_HAS_INT128
        }
    }

    private static void TestWriteBatchGoldenWire()
    {
        // write side: the batch must produce exactly the pinned golden bytes
        {
            byte[] buffer = new byte[256];
            WriteStream stream = new WriteStream(buffer);
            GoldenWireData data = GoldenWireData.Init();
            WriteBatch batch = stream.BeginBatch();
            Check(SerializeGoldenBatch(ref batch, data), $"batch write failed: {batch.Error}");
            batch.End();
            stream.Flush();
            Check(stream.BytesProcessed == GoldenWireBytes.Length,
                $"expected {GoldenWireBytes.Length} bytes, got {stream.BytesProcessed}");
            Check(stream.Data.SequenceEqual(GoldenWireBytes),
                $"golden bytes mismatch:\nexpected {Convert.ToHexString(GoldenWireBytes)}\ngot      {Convert.ToHexString(stream.Data)}");
        }

        // read side: a batch read of the golden bytes must decode the expected values
        {
            ReadStream stream = new ReadStream(GoldenWireBytes);
            GoldenWireData data = new GoldenWireData();
            ReadBatch batch = stream.BeginBatch();
            Check(SerializeGoldenBatch(ref batch, data), $"batch read failed: {batch.Error}");
            batch.End();

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
                "batch read of the golden bytes decoded the wrong values");
        }

#if SERIALIZE_HAS_INT128 // the fixed golden sections ride the gated surface
        // write side, fixed point section: the batch fixed point and wide integer
        // ops must produce exactly the pinned fixed golden bytes
        {
            byte[] buffer = new byte[64];
            WriteStream stream = new WriteStream(buffer);
            FixedWireData data = FixedWireData.Init();
            WriteBatch batch = stream.BeginBatch();
            Check(SerializeFixedWireBatch(ref batch, data), $"batch fixed write failed: {batch.Error}");
            batch.End();
            stream.Flush();
            Check(stream.BytesProcessed == FixedWireBytes.Length,
                $"expected {FixedWireBytes.Length} bytes, got {stream.BytesProcessed}");
            Check(stream.Data.SequenceEqual(FixedWireBytes),
                $"batch fixed golden mismatch:\nexpected {Convert.ToHexString(FixedWireBytes)}\ngot      {Convert.ToHexString(stream.Data)}");
        }

        // read side, fixed point section: a batch read of the pinned fixed bytes
        // must decode the expected values exactly — fixed point has no quantization
        {
            ReadStream stream = new ReadStream(FixedWireBytes);
            FixedWireData data = new FixedWireData();
            ReadBatch batch = stream.BeginBatch();
            Check(SerializeFixedWireBatch(ref batch, data), $"batch fixed read failed: {batch.Error}");
            batch.End();

            FixedWireData expected = FixedWireData.Init();
            Check(data.FixedQ8_8 == expected.FixedQ8_8
                && data.FixedQ16_16 == expected.FixedQ16_16
                && data.FixedQ48_16 == expected.FixedQ48_16
                && data.FixedQ16_16Unsigned == expected.FixedQ16_16Unsigned
                && data.FixedQ112_16Wide == expected.FixedQ112_16Wide
                && data.FixedQ64_64Wide == expected.FixedQ64_64Wide,
                "batch read of the fixed golden bytes decoded the wrong values");
        }
#endif // SERIALIZE_HAS_INT128
    }

    private const ulong BatchDifferentialSeeds = 300;

    private static void TestWriteBatchDifferential()
    {
        // a batch write of a random value sequence must be byte identical to the class
        // path, with batches begun and ended at arbitrary points in the sequence and
        // direct stream calls interleaved between batches
        for (ulong seed = 0; seed < BatchDifferentialSeeds; seed++)
        {
            Rng rng = new Rng(seed * 7919 + 1);
            int numValues = (int)rng.Range(30) + 1;
            Value[] values = new Value[numValues];
            for (int i = 0; i < numValues; i++)
            {
                values[i] = RandomValue(rng);
            }

            byte[] reference = new byte[4096];
            WriteStream referenceStream = new WriteStream(reference);
            foreach (Value value in values)
            {
                Check(SerializeValue(referenceStream, value),
                    $"seed {seed}: reference write failed: {referenceStream.Error}");
            }
            referenceStream.Flush();

            byte[] actual = new byte[4096];
            WriteStream stream = new WriteStream(actual);
            WriteBatch batch = stream.BeginBatch();
            foreach (Value value in values)
            {
                ulong segment = rng.Range(4);
                if (segment == 0)
                {
                    // batch boundary: end this batch, begin the next
                    batch.End();
                    batch = stream.BeginBatch();
                }
                else if (segment == 1)
                {
                    // batch boundary with a direct stream call in between
                    batch.End();
                    Check(SerializeValue(stream, value),
                        $"seed {seed}: interleaved stream write failed: {stream.Error}");
                    batch = stream.BeginBatch();
                    continue;
                }
                Check(SerializeValueBatch(ref batch, value),
                    $"seed {seed}: batch write failed: {batch.Error}");
            }
            batch.End();
            stream.Flush();

            Check(stream.BitsProcessed == referenceStream.BitsProcessed,
                $"seed {seed}: batch wrote {stream.BitsProcessed} bits, class path wrote {referenceStream.BitsProcessed}");
            Check(actual.AsSpan().SequenceEqual(reference),
                $"seed {seed}: batch write differs from the class path");
        }
    }

    private static void TestReadBatchDifferential()
    {
        // a batch read of a class-written sequence must decode exactly the written
        // values, with the same arbitrary batch segmentation as the write test
        for (ulong seed = 0; seed < BatchDifferentialSeeds; seed++)
        {
            Rng rng = new Rng(seed * 104729 + 3);
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
                Check(SerializeValue(writeStream, value),
                    $"seed {seed}: write failed: {writeStream.Error}");
            }
            writeStream.Flush();

            ReadStream stream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
            ReadBatch batch = stream.BeginBatch();
            for (int index = 0; index < numValues; index++)
            {
                Value read = Blank(values[index]);
                ulong segment = rng.Range(4);
                if (segment == 0)
                {
                    batch.End();
                    batch = stream.BeginBatch();
                }
                else if (segment == 1)
                {
                    batch.End();
                    Check(SerializeValue(stream, read),
                        $"seed {seed} value {index}: interleaved stream read failed: {stream.Error}");
                    Check(Matches(values[index], read),
                        $"seed {seed} value {index}: interleaved read does not match (kind {values[index].Kind})");
                    batch = stream.BeginBatch();
                    continue;
                }
                Check(SerializeValueBatch(ref batch, read),
                    $"seed {seed} value {index}: batch read failed: {batch.Error}");
                Check(Matches(values[index], read),
                    $"seed {seed} value {index}: batch read does not match (kind {values[index].Kind})");
            }
            batch.End();

            Check(stream.BitsProcessed == writeStream.BitsProcessed,
                $"seed {seed}: batch read {stream.BitsProcessed} bits, write produced {writeStream.BitsProcessed}");
        }
    }

    private static void TestBatchErrorLatch()
    {
        // an overflow inside a batch latches on the batch, later calls are no-ops, and
        // End carries the error to the stream
        {
            WriteStream stream = new WriteStream(new byte[8]);
            WriteBatch batch = stream.BeginBatch();
            ulong v = ~0ul;
            Check(batch.SerializeBits64(ref v, 64), "the first 64 bits must fit");
            Check(!batch.SerializeBits64(ref v, 64), "expected the second 64 bits to overflow");
            Check(batch.Error == SerializeError.Overflow, $"expected Overflow, got {batch.Error}");
            uint one = 1;
            Check(!batch.SerializeBits(ref one, 1), "calls after a latched error must be no-ops");
            // a delegated call after a latched error is a no-op too: the error rides
            // down to the stream and back
            string s = "abc";
            Check(!batch.SerializeString(ref s, 16), "delegated calls after a latched error must be no-ops");
            Check(batch.Error == SerializeError.Overflow, $"expected Overflow to stay latched, got {batch.Error}");
            batch.End();
            Check(stream.Error == SerializeError.Overflow, $"expected Overflow on the stream, got {stream.Error}");
        }

        // a pre-latched stream error seeds the batch: it begins errored
        {
            WriteStream stream = new WriteStream(new byte[8]);
            ulong v = 0;
            Check(stream.SerializeBits64(ref v, 64), "the first 64 bits must fit");
            uint one = 1;
            Check(!stream.SerializeBits(ref one, 1), "expected the stream to overflow");
            WriteBatch batch = stream.BeginBatch();
            Check(!batch.Ok, "a batch begun on an errored stream must begin errored");
            Check(!batch.SerializeBits(ref one, 1), "batch calls on a carried-in error must be no-ops");
            batch.End();
            Check(stream.Error == SerializeError.Overflow, $"expected Overflow to survive, got {stream.Error}");
        }

        // a read align of nonzero padding fails with Align through the batch
        {
            byte[] buffer = new byte[8];
            buffer[0] = 0xFF;
            ReadStream stream = new ReadStream(buffer);
            ReadBatch batch = stream.BeginBatch();
            uint v = 0;
            Check(batch.SerializeBits(ref v, 3), "the 3 bit read must succeed");
            Check(!batch.SerializeAlign(), "nonzero padding must fail the align");
            Check(batch.Error == SerializeError.Align, $"expected Align, got {batch.Error}");
            batch.End();
            Check(stream.Error == SerializeError.Align, $"expected Align on the stream, got {stream.Error}");
        }

        // a read past the end fails with Overflow through the batch and leaves the
        // value untouched
        {
            ReadStream stream = new ReadStream(new byte[8], 1);
            ReadBatch batch = stream.BeginBatch();
            uint v = 777;
            Check(batch.SerializeBits(ref v, 8), "the first byte must read");
            uint w = 777;
            Check(!batch.SerializeBits(ref w, 8), "expected the second byte to overflow");
            Check(w == 777, "a failed read must leave the value unmodified");
            Check(batch.Error == SerializeError.Overflow, $"expected Overflow, got {batch.Error}");
            batch.End();
            Check(stream.Error == SerializeError.Overflow, $"expected Overflow on the stream, got {stream.Error}");
        }
    }

    private static void TestBatchEndIdempotent()
    {
        byte[] buffer = new byte[16];
        WriteStream stream = new WriteStream(buffer);

        WriteBatch batch = stream.BeginBatch();
        uint a = 0xABC;
        Check(batch.SerializeBits(ref a, 12), "batch write failed");
        // the stream does not see the batch's bits until End
        Check(stream.BitsProcessed == 0, "an open batch must not touch the stream");
        batch.End();
        batch.End(); // idempotent: a second End must not disturb the stream state
        Check(stream.BitsProcessed == 12, $"expected 12 bits after End, got {stream.BitsProcessed}");

        // the stream is usable again after End, and a second batch continues from it
        uint b = 0xD;
        Check(stream.SerializeBits(ref b, 4), "stream write after End failed");
        WriteBatch second = stream.BeginBatch();
        uint c = 0xEEEE;
        Check(second.SerializeBits(ref c, 16), "second batch write failed");
        second.End();
        stream.Flush();
        Check(stream.BitsProcessed == 32, $"expected 32 bits, got {stream.BitsProcessed}");

        ReadStream readStream = new ReadStream(buffer, (int)stream.BytesProcessed);
        uint ra = 0, rb = 0, rc = 0;
        Check(readStream.SerializeBits(ref ra, 12) && readStream.SerializeBits(ref rb, 4)
            && readStream.SerializeBits(ref rc, 16), "read back failed");
        Check(ra == a && rb == b && rc == c,
            $"round trip mismatch: {ra:x}/{rb:x}/{rc:x} vs {a:x}/{b:x}/{c:x}");
    }

    private static void BatchAllocationWriteRound(WriteStream stream, byte[] buffer, byte[] payload)
    {
        stream.Reset(buffer);
        WriteBatch batch = stream.BeginBatch();
        uint bits = 0x15;
        batch.SerializeBits(ref bits, 5);
        int ranged = -3;
        batch.SerializeInt(ref ranged, -10, +10);
        bool flag = true;
        batch.SerializeBool(ref flag);
        ulong wide = 0x0123456789ABCDEF;
        batch.SerializeUInt64(ref wide);
        batch.SerializeAlign();
        batch.SerializeBytes(payload);
        batch.End();
        stream.Flush();
    }

    private static void BatchAllocationReadRound(ReadStream stream, byte[] buffer, byte[] scratch)
    {
        stream.Reset(buffer);
        ReadBatch batch = stream.BeginBatch();
        uint bits = 0;
        batch.SerializeBits(ref bits, 5);
        int ranged = 0;
        batch.SerializeInt(ref ranged, -10, +10);
        bool flag = false;
        batch.SerializeBool(ref flag);
        ulong wide = 0;
        batch.SerializeUInt64(ref wide);
        batch.SerializeAlign();
        batch.SerializeBytes(scratch);
        batch.End();
        // constant message: an interpolated string here would itself allocate per round
        Check(stream.Ok, "allocation round read failed");
    }

    private static void TestBatchAllocation()
    {
        // family invariant: zero allocation on serialization paths. batches are ref
        // structs over reused streams, so a write+read round through the batch layer —
        // including the delegated SerializeBytes — must allocate nothing.
        byte[] buffer = new byte[64];
        byte[] payload = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01 };
        byte[] scratch = new byte[5];
        WriteStream writeStream = new WriteStream(buffer);
        ReadStream readStream = new ReadStream(buffer);

        // warm up so tiering and first-call setup are behind us
        BatchAllocationWriteRound(writeStream, buffer, payload);
        BatchAllocationReadRound(readStream, buffer, scratch);

        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 1000; i++)
        {
            BatchAllocationWriteRound(writeStream, buffer, payload);
            BatchAllocationReadRound(readStream, buffer, scratch);
        }
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Check(allocated == 0, $"batch serialization allocated {allocated} bytes over 1000 rounds");
        Check(scratch.AsSpan().SequenceEqual(payload), "the byte payload did not round trip");
    }

    private static void TestBatchProperties()
    {
        byte[] buffer = new byte[16];

        WriteStream stream = new WriteStream(buffer);
        stream.Context = "ctx";
        WriteBatch batch = stream.BeginBatch();
        Check(batch.IsWriting && !batch.IsReading, "WriteBatch direction flags are wrong");
        Check((string?)batch.Context == "ctx", "WriteBatch must surface the stream context");
        uint v = 5;
        Check(batch.SerializeBits(ref v, 3), "batch write failed");
        Check(batch.BitsProcessed == 3, $"expected 3 bits processed, got {batch.BitsProcessed}");
        Check(batch.BytesProcessed == 1, $"expected 1 byte processed, got {batch.BytesProcessed}");
        Check(batch.AlignBits == 5, $"expected 5 align bits, got {batch.AlignBits}");
        Check(batch.BitsAvailable == 128 - 3, $"expected 125 bits available, got {batch.BitsAvailable}");
        Check(batch.Ok && batch.Error == SerializeError.None, "expected a healthy batch");
        batch.End();
        stream.Flush();

        ReadStream readStream = new ReadStream(buffer, (int)stream.BytesProcessed);
        readStream.Context = "rctx";
        ReadBatch readBatch = readStream.BeginBatch();
        Check(!readBatch.IsWriting && readBatch.IsReading, "ReadBatch direction flags are wrong");
        Check((string?)readBatch.Context == "rctx", "ReadBatch must surface the stream context");
        uint r = 0;
        Check(readBatch.SerializeBits(ref r, 3) && r == 5, "batch read failed");
        Check(readBatch.BitsProcessed == 3, $"expected 3 bits processed, got {readBatch.BitsProcessed}");
        Check(readBatch.BytesProcessed == 1, $"expected 1 byte processed, got {readBatch.BytesProcessed}");
        Check(readBatch.AlignBits == 5, $"expected 5 align bits, got {readBatch.AlignBits}");
        Check(readBatch.BitsRemaining == 5, $"expected 5 bits remaining, got {readBatch.BitsRemaining}");
        Check(readBatch.Ok && readBatch.Error == SerializeError.None, "expected a healthy batch");
        readBatch.End();
        Check(readStream.BitsProcessed == 3, $"expected the cursor to store back, got {readStream.BitsProcessed}");
    }
}
