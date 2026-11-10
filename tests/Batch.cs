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
        stream.SerializeString(ref data.Stones, 8);
        stream.SerializeAlign();                                    // the fixed point section starts byte aligned
        SerializeFixedWireBatch(ref stream, data.Fixed);
        stream.SerializeEnd();
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
        stream.SerializeString(ref data.Stones, 8);
        stream.SerializeAlign();                                    // the fixed point section starts byte aligned
        SerializeFixedWireBatch(ref stream, data.Fixed);
        stream.SerializeEnd();
        return stream.Error == SerializeError.None;
    }

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

    /// <summary>Drives the WriteBatch SerializeFixed overload selected by storage:
    /// the batch counterpart of SerializeFixedAs(FixedStorage, IBitStream, ...) in
    /// FixedPoint.cs. Ref structs cannot implement IBitStream, so the dispatch is
    /// mirrored onto each batch surface.</summary>
    private static bool SerializeFixedAs(
        FixedStorage storage, ref WriteBatch batch, ref Int128Value carrier,
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
                Int128Value value = carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            default:
            {
                UInt128Value value = (UInt128Value)carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = (Int128Value)value;
                return ok;
            }
        }
    }

    /// <summary>The ReadBatch counterpart of the WriteBatch SerializeFixedAs above.</summary>
    private static bool SerializeFixedAs(
        FixedStorage storage, ref ReadBatch batch, ref Int128Value carrier,
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
                Int128Value value = carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = value;
                return ok;
            }
            default:
            {
                UInt128Value value = (UInt128Value)carrier;
                bool ok = batch.SerializeFixed(ref value, integerBits, fractionBits, min, max);
                carrier = (Int128Value)value;
                return ok;
            }
        }
    }

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
            case ValueKind.UInt128Value: return batch.SerializeUInt128(ref value.U128);
            case ValueKind.Int128Value: return batch.SerializeInt128(ref value.I128, value.I128Min, value.I128Max);
            default:
            {
                (FixedStorage storage, int integerBits, int fractionBits, long min, long max) = FixedConfigs[value.FixedConfig];
                return SerializeFixedAs(storage, ref batch, ref value.I128, integerBits, fractionBits, min, max);
            }
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
            case ValueKind.UInt128Value: return batch.SerializeUInt128(ref value.U128);
            case ValueKind.Int128Value: return batch.SerializeInt128(ref value.I128, value.I128Min, value.I128Max);
            default:
            {
                (FixedStorage storage, int integerBits, int fractionBits, long min, long max) = FixedConfigs[value.FixedConfig];
                return SerializeFixedAs(storage, ref batch, ref value.I128, integerBits, fractionBits, min, max);
            }
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

            Check(data.DataEquals(GoldenWireData.Init()), "batch read of the golden bytes decoded the wrong values");
            Check(stream.BitsProcessed == GoldenWireBytes.Length * 8, "the batch end did not consume the final byte's padding");
        }

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
        // a write batch has no refusal state (IMPLEMENTING.md U9, 2.1.1): a user
        // abort through a delegated SerializeObject returns false and records
        // nothing, on the batch or the stream, and later writes keep writing
        {
            WriteStream stream = new WriteStream(new byte[8]);
            WriteBatch batch = stream.BeginBatch();
            uint v = 5;
            Check(batch.SerializeBits(ref v, 3), "the first write must succeed");
            Check(!batch.SerializeObject(new FailingObject()), "expected the user abort to fail");
            Check(batch.Ok && batch.Error == SerializeError.None, $"nothing latches on a write batch, got {batch.Error}");
            uint one = 1;
            Check(batch.SerializeBits(ref one, 1), "field writes after an abort keep writing");
            string s = "abc";
            Check(batch.SerializeString(ref s, 16), "delegated writes after an abort keep writing");
            batch.End();
            Check(stream.Ok && stream.Error == SerializeError.None, $"nothing on the stream either, got {stream.Error}");
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
            Check(batch.Error == SerializeError.NonzeroPadding, $"expected NonzeroPadding, got {batch.Error}");
            batch.End();
            Check(stream.Error == SerializeError.NonzeroPadding, $"expected NonzeroPadding on the stream, got {stream.Error}");
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
            Check(batch.Error == SerializeError.PastEnd, $"expected PastEnd, got {batch.Error}");
            Check(batch.BitsRemaining == -1, $"expected BitsRemaining -1 on a failed batch, got {batch.BitsRemaining}");
            batch.End();
            Check(stream.Error == SerializeError.PastEnd, $"expected PastEnd on the stream, got {stream.Error}");
        }

        // a struct passed to the delegated non-generic read overload is refused
        // with ValueOutOfRange before any bits move
        {
            ReadStream stream = new ReadStream(new byte[8]);
            ReadBatch batch = stream.BeginBatch();
            StructPoint boxed = default;
            Check(!batch.SerializeObject(boxed), "a struct read through the non-generic batch overload must refuse");
            Check(batch.Error == SerializeError.ValueOutOfRange, $"expected ValueOutOfRange, got {batch.Error}");
            Check(batch.BitsProcessed == 0, $"the refusal consumed {batch.BitsProcessed} bits, expected 0");
            batch.End();
            Check(stream.Error == SerializeError.ValueOutOfRange, $"expected ValueOutOfRange on the stream, got {stream.Error}");
        }

        // a refusal on an ended read batch is recorded on the stream
        {
            ReadStream stream = new ReadStream(new byte[8]);
            ReadBatch batch = stream.BeginBatch();
            uint v = 0;
            Check(batch.SerializeBits(ref v, 3), "the 3 bit read must succeed");
            batch.End();
            Check(!batch.Reject(), "Reject must return false");
            Check(!stream.Ok && stream.Error == SerializeError.Rejected, $"expected Rejected on the stream, got {stream.Error}");
        }
        {
            ReadStream stream = new ReadStream(new byte[8]);
            ReadBatch batch = stream.BeginBatch();
            uint v = 0;
            Check(batch.SerializeBits(ref v, 3), "the 3 bit read must succeed");
            batch.End();
            Check(!batch.Fail(SerializeError.ValueOutOfRange), "Fail must return false");
            Check(!stream.Ok && stream.Error == SerializeError.ValueOutOfRange, $"expected ValueOutOfRange on the stream, got {stream.Error}");
        }

        TestBatchSentinelLoops();
    }

    private static void TestBatchSentinelLoops()
    {
        // a sentinel loop written with batch.Continue and batch.Until round trips
        // through a read batch, byte identical to the class path
        {
            uint[] items = { 1, 2, 3, 4, 5 };
            byte[] buffer = new byte[64];
            WriteStream writeStream = new WriteStream(buffer);
            WriteBatch writeBatch = writeStream.BeginBatch();
            int i = 0;
            bool more = items.Length > 0;
            while (writeBatch.Continue(ref more))
            {
                writeBatch.SerializeBits(ref items[i], 8);
                i++;
                more = i < items.Length;
            }
            i = 0;
            bool done = items.Length == 0;
            while (writeBatch.Until(ref done))
            {
                writeBatch.SerializeBits(ref items[i], 8);
                i++;
                done = i == items.Length;
            }
            writeBatch.End();
            writeStream.Flush();

            byte[] reference = new byte[64];
            WriteStream referenceStream = new WriteStream(reference);
            i = 0;
            more = items.Length > 0;
            while (referenceStream.Continue(ref more))
            {
                referenceStream.SerializeBits(ref items[i], 8);
                i++;
                more = i < items.Length;
            }
            i = 0;
            done = items.Length == 0;
            while (referenceStream.Until(ref done))
            {
                referenceStream.SerializeBits(ref items[i], 8);
                i++;
                done = i == items.Length;
            }
            referenceStream.Flush();
            Check(writeStream.BitsProcessed == referenceStream.BitsProcessed && buffer.AsSpan().SequenceEqual(reference),
                "a batch sentinel loop must write the same bits as the class path");

            ReadStream readStream = new ReadStream(buffer, (int)writeStream.BytesProcessed);
            ReadBatch readBatch = readStream.BeginBatch();
            uint[] continued = new uint[items.Length];
            int continuedCount = 0;
            more = false;
            while (continuedCount < continued.Length && readBatch.Continue(ref more))
            {
                Check(readBatch.SerializeBits(ref continued[continuedCount], 8), "a Continue element must read");
                continuedCount++;
            }
            Check(continuedCount == items.Length && !readBatch.Continue(ref more),
                "the Continue loop must end after the last element");
            uint[] untilDone = new uint[items.Length];
            int untilCount = 0;
            done = false;
            while (untilCount < untilDone.Length && readBatch.Until(ref done))
            {
                Check(readBatch.SerializeBits(ref untilDone[untilCount], 8), "an Until element must read");
                untilCount++;
            }
            Check(untilCount == items.Length && !readBatch.Until(ref done),
                "the Until loop must end after the last element");
            Check(readBatch.Ok, $"the round trip must not fail, got {readBatch.Error}");
            readBatch.End();
            Check(continued.AsSpan().SequenceEqual(items), "the Continue loop must read back every element");
            Check(untilDone.AsSpan().SequenceEqual(items), "the Until loop must read back every element");
            Check(readStream.BitsProcessed == writeStream.BitsProcessed,
                $"read {readStream.BitsProcessed} bits, wrote {writeStream.BitsProcessed}");
        }

        // on a packet of all ones the Continue loop on a read batch is bounded by the
        // packet and ends with PastEnd; once failed, Continue and Until end at once
        {
            byte[] packet = new byte[4];
            Array.Fill(packet, (byte)0xFF);
            ReadStream stream = new ReadStream(packet);
            ReadBatch batch = stream.BeginBatch();
            int iterations = 0;
            bool more = true;
            while (batch.Continue(ref more))
            {
                uint item = 0;
                batch.SerializeBits(ref item, 8);
                iterations++;
            }
            Check(batch.Error == SerializeError.PastEnd, $"expected PastEnd, got {batch.Error}");
            Check(iterations <= packet.Length * 8, $"loop ran {iterations} iterations, more than the packet's bits");

            more = true;
            Check(!batch.Continue(ref more), "Continue on a failed batch must end the loop");
            bool done = false;
            Check(!batch.Until(ref done), "Until on a failed batch must end the loop");
            Check(batch.Error == SerializeError.PastEnd, $"expected PastEnd to stay latched, got {batch.Error}");
            batch.End();
            Check(stream.Error == SerializeError.PastEnd, $"expected PastEnd on the stream, got {stream.Error}");
        }

        // a read batch over an empty packet ends a Until loop on its first bit
        {
            ReadStream stream = new ReadStream(new byte[8], 0);
            ReadBatch batch = stream.BeginBatch();
            bool done = false;
            Check(!batch.Until(ref done), "Until on an empty packet must end the loop");
            Check(batch.Error == SerializeError.PastEnd, $"expected PastEnd, got {batch.Error}");
            batch.End();
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

    private static void TestBatchSyncAndGeneration()
    {
        // (1) a ReadBatch copied by value whose copy refuses PastEnd and ends before
        // the original batch ends must keep the stream refused
        {
            static void ReadPastEndOnByValueCopy(ReadBatch copy)
            {
                uint overflow = 0;
                Check(!copy.SerializeBits(ref overflow, 16), "expected 16-bit read on 1-byte stream to refuse");
                Check(copy.Error == SerializeError.PastEnd, $"expected PastEnd on copy, got {copy.Error}");
                copy.End();
            }

            ReadStream stream = new ReadStream(new byte[8], 1);
            ReadBatch batch = stream.BeginBatch();
            uint first = 0;
            Check(batch.SerializeBits(ref first, 4), "the 4-bit read must succeed");
            ReadPastEndOnByValueCopy(batch);
            batch.End();
            Check(stream.Error != SerializeError.None && !stream.Ok,
                $"expected stream refusal to remain latched after outer End, got {stream.Error}");
            uint after = 0;
            Check(!stream.SerializeBits(ref after, 4), "subsequent stream reads must refuse");
        }

        // a ReadBatch copied by value whose copy reads and ends without refusing
        // still mismatches the stream generation when the outer copy syncs or ends,
        // latching ValueOutOfRange on the stream instead of rewinding the cursor
        {
            static void ReadAndEndByValueCopy(ReadBatch copy)
            {
                uint inner = 0;
                Check(copy.SerializeBits(ref inner, 4), "inner 4-bit read must succeed");
                copy.End();
            }

            byte[] buf = { 0xAB, 0xCD, 0, 0, 0, 0, 0, 0 };
            ReadStream stream = new ReadStream(buf, 2);
            ReadBatch batch = stream.BeginBatch();
            uint outer = 0;
            Check(batch.SerializeBits(ref outer, 4), "outer 4-bit read must succeed");
            ReadAndEndByValueCopy(batch);
            Check(stream.BitsProcessed == 8, $"expected 8 bits after inner End, got {stream.BitsProcessed}");
            batch.End();
            Check(stream.Error == SerializeError.ValueOutOfRange && !stream.Ok,
                $"expected ValueOutOfRange on generation mismatch, got {stream.Error}");
            Check(stream.BitsProcessed == 8, $"expected cursor not to rewind, got {stream.BitsProcessed}");
        }

        // (2) a stream refusal while a ReadBatch is open followed by batch.End()
        // must keep the stream refusal latched
        {
            ReadStream stream = new ReadStream(new byte[8], 1);
            ReadBatch batch = stream.BeginBatch();
            uint first = 0;
            Check(batch.SerializeBits(ref first, 4), "the 4-bit batch read must succeed");
            uint directOverflow = 0;
            Check(!stream.SerializeBits(ref directOverflow, 16), "direct 16-bit read on 1-byte stream must refuse");
            Check(stream.Error == SerializeError.PastEnd, $"expected PastEnd on stream, got {stream.Error}");
            batch.End();
            Check(stream.Error == SerializeError.PastEnd && !stream.Ok,
                $"expected PastEnd to remain latched after batch.End(), got {stream.Error}");
        }
    }

#if DEBUG
    private static void TestBatchAfterEndInline()
    {
        // Inline writes pack bits in the batch. On an ended WriteBatch that is
        // misuse, asserted in debug. Release leaves the call unspecified.
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[16]);
            WriteBatch batch = stream.BeginBatch();
            batch.End();
            uint value = 1;
            batch.SerializeBits(ref value, 4);
        }), "an inline write on an ended write batch must assert in debug");
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[16]);
            WriteBatch batch = stream.BeginBatch();
            batch.End();
            ulong value = 1;
            batch.SerializeBits64(ref value, 40);
        }), "a wide bits write on an ended write batch must assert in debug");
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[16]);
            WriteBatch batch = stream.BeginBatch();
            batch.End();
            long value = 0;
            batch.SerializeInt64(ref value, long.MinValue, long.MaxValue);
        }), "a wide int64 write on an ended write batch must assert in debug");
        Check(AssertFires(() =>
        {
            WriteStream stream = new WriteStream(new byte[16]);
            WriteBatch batch = stream.BeginBatch();
            batch.End();
            ulong value = 1;
            batch.SerializeUInt64(ref value);
        }), "a uint64 write on an ended write batch must assert in debug");
    }
#endif
}
