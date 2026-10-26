/*
    RedTeam.cs — hostile-input attack harness against Serialize.cs's READ path.

    Rule under test: no packet, however malformed, may make a ReadStream throw, hang,
    over-allocate or read out of bounds. Errors must be values.

    Every attack records findings instead of exiting, so one run gives the whole picture.
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using Serialize;

namespace Serialize.RedTeam;

internal static class RedTeam
{
    private static readonly List<string> Findings = new List<string>();
    private static readonly Dictionary<string, int> Classes = new Dictionary<string, int>();
    private static int _cases;

    // dedup by class (the text with digits stripped) so one bug cannot mask the others
    private static void Finding(string s)
    {
        StringBuilder key = new StringBuilder();
        foreach (char c in s)
        {
            if (!char.IsDigit(c) && c != '-' && c != '.') key.Append(c);
        }
        string k = key.ToString();
        if (Classes.TryGetValue(k, out int n))
        {
            Classes[k] = n + 1;
            return;
        }
        Classes[k] = 1;
        Findings.Add(s);
    }

    // golden bytes copied verbatim from tests/Tests.cs:253 (pinned to serialize.h:3195)
    private static readonly byte[] Golden =
    {
        0x5D, 0xDA, 0xF7, 0xE6, 0xD5, 0x77, 0xDF, 0x56, 0xEF, 0x9F, 0x75, 0x19,
        0x52, 0xBC, 0xDA, 0x0F, 0x49, 0x40, 0xF4, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0xFF, 0xFC, 0xD1, 0x48, 0xE0, 0x59, 0xD1, 0x48, 0xC0, 0x7B,
        0xF3, 0x6A, 0xE2, 0x59, 0xD1, 0x48, 0x84, 0xB7, 0x06, 0xDE, 0xAD, 0xBE,
        0xEF, 0xCA, 0xFE, 0x01, 0x06, 0x67, 0x6F, 0x6C, 0x64, 0x65, 0x6E, 0xE3,
        0x21, 0x00, 0x00, 0xC0, 0x21, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00,
    };

    // ---- the victim: a serialize function that touches every read primitive ----

    private sealed class Packet
    {
        public uint Bits4, Bits11, Bits24, Bits32;
        public ulong Bits64;
        public int IntSmall, IntFull;
        public long Int64Full, Int64Wide;
        public bool Flag;
        public float F, CF;
        public float CFWide; // decoded from an infinite-delta field: every decode is non-finite, so every read of it is refused
        public double D;
        public byte U8;
        public ushort U16;
        public uint U32;
        public ulong U64;
        public int RelNear, RelFar;
        public byte[] Bytes = new byte[7];
        public string Str = "";
        public string Stones = "";
        // the wide surface: 128 bit integers and fixed point in every storage
        public UInt128Value U128;
        public Int128Value I128Full, I128Group96, I128Group64, I128Group32, I128Degenerate;
        public long FixedS64;
        public ulong FixedU64;
        public int FixedS32;
        public uint FixedU32;
        public short FixedS16;
        public ushort FixedU16;
        public Int128Value FixedI128;
        public UInt128Value FixedU128;
        public long FixedFrac0;
        public Int128Value FixedI128Frac0;
    }

    // exactly the golden sequence: what a real server's read path looks like
    private static bool ReadGolden(IBitStream s, Packet p)
    {
        const int relativeBase = 100;
        s.SerializeBits(ref p.Bits4, 4);
        s.SerializeBits(ref p.Bits11, 11);
        s.SerializeBits(ref p.Bits24, 24);
        s.SerializeBits(ref p.Bits32, 32);
        s.SerializeInt(ref p.IntSmall, -100, +100);
        s.SerializeInt(ref p.IntFull, int.MinValue, int.MaxValue);
        s.SerializeBool(ref p.Flag);
        s.SerializeFloat(ref p.F);
        s.SerializeCompressedFloat(ref p.CF, 0.0f, 10.0f, 0.01f);
        s.SerializeDouble(ref p.D);
        s.SerializeByte(ref p.U8);
        s.SerializeUInt16(ref p.U16);
        s.SerializeUInt32(ref p.U32);
        s.SerializeUInt64(ref p.U64);
        s.SerializeIntRelative(relativeBase, ref p.RelNear);
        s.SerializeIntRelative(relativeBase, ref p.RelFar);
        s.SerializeAlign();
        s.SerializeBytes(p.Bytes);
        s.SerializeString(ref p.Str, 16);
        s.SerializeString(ref p.Stones, 8);
        s.SerializeEnd();
        return s.Error == SerializeError.None;
    }

    // a wider surface: hostile ranges, strings with big buffer sizes, 64 bit paths, and
    // the floats every NaN and infinity pattern of a hostile packet reaches
    private static bool ReadWide(IBitStream s, Packet p)
    {
        s.SerializeBits64(ref p.Bits64, 33);
        s.SerializeBits64(ref p.Bits64, 64);
        s.SerializeInt64(ref p.Int64Full, long.MinValue, long.MaxValue);
        s.SerializeInt64(ref p.Int64Wide, -5000000000L, 5000000000L);
        s.SerializeInt64(ref p.Int64Wide, 0, 255);
        s.SerializeInt(ref p.IntSmall, 0, 5);            // 3 bit headroom over max 5
        s.SerializeInt(ref p.IntFull, -1, 0);            // 1 bit, straddles zero
        s.SerializeCompressedFloat(ref p.CFWide, -3.4e38f, 3.4e38f, 1e-30f); // pathological: delta overflows to +inf
        s.SerializeAlign();
        s.SerializeString(ref p.Str, 512);
        s.SerializeString(ref p.Stones, 4096);
        s.SerializeString(ref p.Str, int.MaxValue);      // length field takes 31 bits
        s.SerializeDouble(ref p.D);
        s.SerializeIntRelative(0, ref p.RelFar);
        s.SerializeBytes(p.Bytes);
        s.SerializeEnd();
        return s.Error == SerializeError.None;
    }

    // the wide surface: UInt128, signed Int128 across the 32/64/96/128 group
    // boundaries (plus a degenerate zero-bit range), and fixed point in every
    // storage width, with zero and nonzero fraction configurations. The same
    // sequence runs on the write side to build canonical witnesses, so the
    // reader under attack is held to bytes this function itself produced.
    private static bool ReadWide128(IBitStream s, Packet p)
    {
        s.SerializeUInt128(ref p.U128);
        s.SerializeInt128(ref p.I128Full, Int128Value.MinValue, Int128Value.MaxValue);
        s.SerializeInt128(ref p.I128Group96, Int128Value.Zero, new Int128Value(0xFFFFFFFFUL, ulong.MaxValue));
        s.SerializeInt128(ref p.I128Group64, (Int128Value)long.MinValue, (Int128Value)long.MaxValue);
        s.SerializeInt128(ref p.I128Group32, Int128Value.Zero, new Int128Value(0, 0xFFFFFFFFUL));
        s.SerializeInt128(ref p.I128Degenerate, (Int128Value)42, (Int128Value)42);
        s.SerializeFixed(ref p.FixedS64, 48, 16, -100000, +100000);
        s.SerializeFixed(ref p.FixedU64, 32, 32, 0, 30000);
        s.SerializeFixed(ref p.FixedS32, 16, 16, -2000, +2000);
        s.SerializeFixed(ref p.FixedU32, 16, 16, 0, 30000);
        s.SerializeFixed(ref p.FixedS16, 8, 8, -100, +100);
        s.SerializeFixed(ref p.FixedU16, 8, 8, 0, 200);
        s.SerializeAlign();
        s.SerializeFixed(ref p.FixedI128, 112, 16, -144115188075855872, +144115188075855872);
        s.SerializeFixed(ref p.FixedU128, 64, 64, 0, long.MaxValue);
        s.SerializeFixed(ref p.FixedFrac0, 64, 0, -1000000, +1000000);
        s.SerializeFixed(ref p.FixedI128Frac0, 128, 0, -1000, +1000);
        s.SerializeEnd();
        return s.Error == SerializeError.None;
    }

    // the batch twin of ReadWide128: identical calls through a ReadBatch, whose
    // 128 bit and fixed point operations delegate to the stream. The batch is
    // ended on every path, and the verdict is the stream's latched error.
    private static bool ReadWide128Batch(ReadStream stream, Packet p)
    {
        ReadBatch b = stream.BeginBatch();
        b.SerializeUInt128(ref p.U128);
        b.SerializeInt128(ref p.I128Full, Int128Value.MinValue, Int128Value.MaxValue);
        b.SerializeInt128(ref p.I128Group96, Int128Value.Zero, new Int128Value(0xFFFFFFFFUL, ulong.MaxValue));
        b.SerializeInt128(ref p.I128Group64, (Int128Value)long.MinValue, (Int128Value)long.MaxValue);
        b.SerializeInt128(ref p.I128Group32, Int128Value.Zero, new Int128Value(0, 0xFFFFFFFFUL));
        b.SerializeInt128(ref p.I128Degenerate, (Int128Value)42, (Int128Value)42);
        b.SerializeFixed(ref p.FixedS64, 48, 16, -100000, +100000);
        b.SerializeFixed(ref p.FixedU64, 32, 32, 0, 30000);
        b.SerializeFixed(ref p.FixedS32, 16, 16, -2000, +2000);
        b.SerializeFixed(ref p.FixedU32, 16, 16, 0, 30000);
        b.SerializeFixed(ref p.FixedS16, 8, 8, -100, +100);
        b.SerializeFixed(ref p.FixedU16, 8, 8, 0, 200);
        b.SerializeAlign();
        b.SerializeFixed(ref p.FixedI128, 112, 16, -144115188075855872, +144115188075855872);
        b.SerializeFixed(ref p.FixedU128, 64, 64, 0, long.MaxValue);
        b.SerializeFixed(ref p.FixedFrac0, 64, 0, -1000000, +1000000);
        b.SerializeFixed(ref p.FixedI128Frac0, 128, 0, -1000, +1000);
        b.SerializeEnd();
        b.End();
        return stream.Error == SerializeError.None;
    }

    private delegate bool ReadFn(IBitStream s, Packet p);

    // Runs one hostile packet. Returns null on clean behaviour, else the failure text.
    private static string? Attempt(ReadFn fn, byte[] data, int bytes, int slack, string label)
    {
        _cases++;
        byte[] buffer;
        if (slack == 0)
        {
            buffer = new byte[bytes];
            Array.Copy(data, buffer, bytes);
        }
        else
        {
            buffer = new byte[bytes + slack];
            Array.Copy(data, buffer, bytes);
            for (int i = bytes; i < buffer.Length; i++)
            {
                buffer[i] = 0xFF; // poisoned slack: must never reach an output value
            }
        }
        try
        {
            ReadStream s = new ReadStream(buffer, bytes);
            Packet p = new Packet();
            bool ok = fn(s, p);
            // post-conditions that must hold whatever the packet said
            if (s.BitsProcessed > (long)bytes * 8)
            {
                return $"{label}: BitsProcessed {s.BitsProcessed} exceeds packet {(long)bytes * 8} bits";
            }
            if (!ok && s.Error == SerializeError.None)
            {
                return $"{label}: read reported failure with Error == None";
            }
            if (ok && s.Error != SerializeError.None)
            {
                return $"{label}: read reported success with Error == {s.Error}";
            }
            if (ok)
            {
                // decoded values must respect their declared ranges
                if (p.IntSmall < -100 || p.IntSmall > 100)
                {
                    // ReadWide reuses IntSmall with [0,5]; check the loose bound only
                    return $"{label}: IntSmall {p.IntSmall} outside any declared range";
                }
                if (p.CF < -float.MaxValue || p.CF > float.MaxValue || float.IsNaN(p.CF))
                {
                    return $"{label}: compressed float decoded to {p.CF}";
                }
                // CFWide is decoded over [-3.4e38, 3.4e38], whose delta overflows to
                // +inf: a non-conforming declaration, and every decode through it is
                // non-finite. STANDARD.md 2.0, "The decode must be finite": a reader
                // refuses a non-finite decode whatever the declaration, so no read
                // that succeeded may hand one back.
                if (float.IsNaN(p.CFWide) || float.IsInfinity(p.CFWide))
                {
                    return $"{label}: compressed float over an infinite delta decoded to {p.CFWide} and was accepted";
                }
            }
            return null;
        }
        catch (Exception e)
        {
            return $"{label}: THREW {e.GetType().Name}: {e.Message}";
        }
    }

    private static void Run(ReadFn fn, byte[] data, int bytes, string label)
    {
        foreach (int slack in new[] { 0, 1, 7, 8, 64 })
        {
            string? f = Attempt(fn, data, bytes, slack, $"{label} slack={slack}");
            if (f != null)
            {
                Finding(f);
            }
        }
    }

    // ---- attack 1: bit-flip sweep over a valid golden stream ----

    private static void AttackBitFlipSweep()
    {
        // single flips
        for (int bit = 0; bit < Golden.Length * 8; bit++)
        {
            byte[] d = (byte[])Golden.Clone();
            d[bit >> 3] ^= (byte)(1 << (bit & 7));
            Run(ReadGolden, d, d.Length, $"flip1 bit={bit}");
        }
        // double flips, bounded: every pair within a 24 bit sliding window
        for (int a = 0; a < Golden.Length * 8; a++)
        {
            for (int b = a + 1; b < Math.Min(a + 24, Golden.Length * 8); b++)
            {
                byte[] d = (byte[])Golden.Clone();
                d[a >> 3] ^= (byte)(1 << (a & 7));
                d[b >> 3] ^= (byte)(1 << (b & 7));
                string? f = Attempt(ReadGolden, d, d.Length, 0, $"flip2 {a},{b}");
                if (f != null) Finding(f);
            }
        }
        // whole-byte substitutions: every byte position takes every value
        for (int i = 0; i < Golden.Length; i++)
        {
            for (int v = 0; v < 256; v++)
            {
                byte[] d = (byte[])Golden.Clone();
                d[i] = (byte)v;
                string? f = Attempt(ReadGolden, d, d.Length, 0, $"byte {i}={v}");
                if (f != null) Finding(f);
                f = Attempt(ReadGolden, d, d.Length, 8, $"byte {i}={v} slack");
                if (f != null) Finding(f);
            }
        }
    }

    // ---- attack 2: truncation at every length, x every trailing-byte value ----

    private static void AttackTruncationSweep()
    {
        for (int len = 0; len <= Golden.Length; len++)
        {
            Run(ReadGolden, Golden, len, $"truncate len={len}");
            if (len == 0) continue;
            // truncation combined with corruption of the last surviving byte
            for (int v = 0; v < 256; v++)
            {
                byte[] d = (byte[])Golden.Clone();
                d[len - 1] = (byte)v;
                string? f = Attempt(ReadGolden, d, len, 0, $"truncate {len} tail={v}");
                if (f != null) Finding(f);
                f = Attempt(ReadGolden, d, len, 8, $"truncate {len} tail={v} slack");
                if (f != null) Finding(f);
            }
        }
    }

    // ---- attack 3: the wide surface under truncation and random bytes ----

    private static void AttackWideSurface()
    {
        Rng rng = new Rng(0xDEADBEEF);
        for (int len = 0; len <= 96; len++)
        {
            byte[] d = new byte[Math.Max(len, 1)];
            // all zeros, all ones, and random fills
            Run(ReadWide, d, len, $"wide zeros len={len}");
            for (int i = 0; i < d.Length; i++) d[i] = 0xFF;
            Run(ReadWide, d, len, $"wide ones len={len}");
            for (int trial = 0; trial < 2000; trial++)
            {
                for (int i = 0; i < d.Length; i++) d[i] = (byte)rng.Next();
                string? f = Attempt(ReadWide, d, len, 0, $"wide rand len={len} t={trial}");
                if (f != null) Finding(f);
                f = Attempt(ReadWide, d, len, 8, $"wide rand slack len={len} t={trial}");
                if (f != null) Finding(f);
            }
        }
    }

    // ---- attack 4: random packets through the golden reader ----

    private static void AttackRandomFuzz()
    {
        Rng rng = new Rng(12345);
        for (int trial = 0; trial < 10000000; trial++)
        {
            int len = (int)rng.Range(96);
            byte[] d = new byte[Math.Max(len, 1)];
            for (int i = 0; i < d.Length; i++) d[i] = (byte)rng.Next();
            string? f = Attempt(ReadGolden, d, len, (trial & 1) == 0 ? 0 : 8, $"fuzz seed-trial={trial}");
            if (f != null) Finding(f);
        }
    }

    // ---- attack 5: hand-built hostile fields ----

    private static void AttackTargeted()
    {
        // a) string claiming the maximum length with nothing behind it
        {
            byte[] buf = new byte[8];
            WriteStream w = new WriteStream(buf);
            uint len = 15; // bufferSize 16 -> length field is [0,15], 4 bits
            w.SerializeBits(ref len, 4);
            w.Flush();
            for (int bytes = 1; bytes <= 8; bytes++)
            {
                _cases++;
                try
                {
                    ReadStream r = new ReadStream(buf, bytes);
                    string s = "";
                    bool ok = r.SerializeString(ref s, 16);
                    if (ok && Encoding.UTF8.GetByteCount(s) != 15)
                    {
                        Finding($"string len=15 bytes={bytes}: decoded {s.Length} chars from a claim of 15");
                    }
                }
                catch (Exception e)
                {
                    Finding($"string len=15 bytes={bytes}: THREW {e.GetType().Name}: {e.Message}");
                }
            }
        }

        // c) same allocation question for SerializeString
        foreach (int bufferSize in new[] { 0, 16, 4096, 1 << 24, int.MaxValue })
        {
            byte[] buf = new byte[16];
            WriteStream w = new WriteStream(buf);
            int claim = bufferSize - 1;
            w.SerializeInt(ref claim, 0, bufferSize - 1);
            w.Flush();
            for (int bytes = 1; bytes <= 16; bytes++)
            {
                _cases++;
                long before = GC.GetAllocatedBytesForCurrentThread();
                try
                {
                    ReadStream r = new ReadStream(buf, bytes);
                    string s = "";
                    r.SerializeString(ref s, bufferSize);
                    long alloc = GC.GetAllocatedBytesForCurrentThread() - before;
                    if (alloc > 4096 + (long)bytes * 8)
                    {
                        Finding($"string claim={claim} packet={bytes}B: allocated {alloc} bytes");
                    }
                }
                catch (Exception e)
                {
                    Finding($"string claim={claim} bytes={bytes}: THREW {e.GetType().Name}: {e.Message}");
                }
            }
        }

        // e) every refused payload shape through SerializeString: the invalid UTF-8
        // shapes, plus an interior NUL — valid UTF-8, refused anyway (serialize#8):
        // the wire length and the perceived C-string length would disagree
        {
            byte[][] bad =
            {
                new byte[] { 0x80 },
                new byte[] { 0xC0, 0x80 },
                new byte[] { 0xE0, 0x80, 0x80 },
                new byte[] { 0xED, 0xA0, 0x80 },       // surrogate
                new byte[] { 0xF4, 0x90, 0x80, 0x80 }, // > U+10FFFF
                new byte[] { 0xF8, 0x88, 0x80, 0x80, 0x80 },
                new byte[] { 0xE2, 0x28, 0xA1 },
                new byte[] { 0xC2 },                   // truncated sequence
                new byte[] { 0x61, 0x00, 0x62 },       // interior NUL (two-lengths smuggling)
                new byte[] { 0xFF, 0x00 },             // both rules broken: the NUL wins
            };
            foreach (byte[] payload in bad)
            {
                byte[] buf = new byte[32];
                WriteStream w = new WriteStream(buf);
                int len = payload.Length;
                w.SerializeInt(ref len, 0, 15);
                w.SerializeAlign();
                w.SerializeBytes(payload);
                w.Flush();
                _cases++;
                try
                {
                    ReadStream r = new ReadStream(buf, 32);
                    string s = "SENTINEL";
                    bool ok = r.SerializeString(ref s, 16);
                    if (ok)
                    {
                        Finding($"invalid UTF-8 {Convert.ToHexString(payload)} accepted as \"{s}\"");
                    }
                    else if (r.Error != (Array.IndexOf(payload, (byte)0) >= 0 ? SerializeError.EmbeddedNul : SerializeError.InvalidUtf8))
                    {
                        Finding($"invalid UTF-8 {Convert.ToHexString(payload)}: error {r.Error}, expected EmbeddedNul for a NUL and InvalidUtf8 otherwise");
                    }
                    if (s != "SENTINEL" && !ok)
                    {
                        Finding($"invalid UTF-8 {Convert.ToHexString(payload)}: failed read still wrote the value");
                    }
                }
                catch (Exception e)
                {
                    Finding($"invalid UTF-8 {Convert.ToHexString(payload)}: THREW {e.GetType().Name}: {e.Message}");
                }
            }
        }

        // f) integer smuggled into bit headroom, every range shape
        {
            (int Min, int Max)[] ranges =
            {
                (0, 1), (0, 5), (0, 6), (-100, 100), (-1, 0), (int.MinValue, int.MaxValue),
                (int.MinValue, int.MinValue + 1), (int.MaxValue - 1, int.MaxValue),
                (0, int.MaxValue), (int.MinValue, 0), (-3, -2), (0, (int)0x7FFFFFFE),
            };
            foreach ((int min, int max) in ranges)
            {
                int bits = SerializeUtil.BitsRequired((uint)min, (uint)max);
                if (bits == 0 || bits > 32) { Finding($"BitsRequired({min},{max}) = {bits}"); continue; }
                ulong space = bits == 32 ? 0x100000000UL : 1UL << bits;
                ulong legal = (ulong)((uint)max - (uint)min) + 1;
                // walk the whole code space for small widths, else just the edges
                ulong[] probes = bits <= 12
                    ? null!
                    : new ulong[] { 0, legal - 1, legal, space - 1, space / 2 };
                IEnumerable<ulong> seq = probes ?? EnumerateAll(space);
                foreach (ulong raw in seq)
                {
                    if (raw >= space) continue;
                    byte[] buf = new byte[8];
                    WriteStream w = new WriteStream(buf);
                    uint rv = (uint)raw;
                    w.SerializeBits(ref rv, bits);
                    w.Flush();
                    _cases++;
                    try
                    {
                        ReadStream r = new ReadStream(buf, 8);
                        int value = 12345;
                        bool ok = r.SerializeInt(ref value, min, max);
                        bool shouldPass = raw < legal;
                        if (ok != shouldPass)
                        {
                            Finding($"int[{min},{max}] raw={raw}: returned {ok}, expected {shouldPass}");
                        }
                        if (ok && (value < min || value > max))
                        {
                            Finding($"int[{min},{max}] raw={raw}: decoded {value}, OUT OF RANGE");
                        }
                        if (!ok && value != 12345)
                        {
                            Finding($"int[{min},{max}] raw={raw}: failed read modified the value to {value}");
                        }
                    }
                    catch (Exception e)
                    {
                        Finding($"int[{min},{max}] raw={raw}: THREW {e.GetType().Name}: {e.Message}");
                    }
                }
            }
        }

        // g) 64 bit headroom smuggling, including the two-dword path
        {
            (long Min, long Max)[] ranges =
            {
                (0, 5), (0, 255), (-5000000000L, 5000000000L), (long.MinValue, long.MaxValue),
                (0, (long)1 << 40), (long.MinValue, 0), (0, long.MaxValue),
                (long.MinValue, long.MinValue + 1), (long.MaxValue - 1, long.MaxValue),
                // NOTE: (0, (long)0xFFFF...FE) is min > max — API misuse, throws by design.
            };
            foreach ((long min, long max) in ranges)
            {
                int bits = SerializeUtil.BitsRequired64((ulong)min, (ulong)max);
                ulong legalSpan = (ulong)max - (ulong)min; // largest legal raw
                ulong[] probes =
                {
                    0, legalSpan, legalSpan + 1, ulong.MaxValue,
                    bits >= 64 ? ulong.MaxValue : (1UL << bits) - 1,
                    legalSpan / 2,
                };
                foreach (ulong raw in probes)
                {
                    ulong masked = bits >= 64 ? raw : raw & ((1UL << bits) - 1);
                    byte[] buf = new byte[16];
                    WriteStream w = new WriteStream(buf);
                    ulong rv = masked;
                    w.SerializeBits64(ref rv, bits);
                    w.Flush();
                    _cases++;
                    try
                    {
                        for (int bytes = 0; bytes <= 16; bytes++)
                        {
                            ReadStream r = new ReadStream(buf, bytes);
                            long value = 999;
                            bool ok = r.SerializeInt64(ref value, min, max);
                            if (ok && (value < min || value > max))
                            {
                                Finding($"int64[{min},{max}] raw={masked} bytes={bytes}: decoded {value} OUT OF RANGE");
                            }
                            if (ok && masked > legalSpan)
                            {
                                Finding($"int64[{min},{max}] raw={masked}: accepted above the legal span {legalSpan}");
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Finding($"int64[{min},{max}] raw={masked}: THREW {e.GetType().Name}: {e.Message}");
                    }
                }
            }
        }

        // h) nonzero align padding at every phase
        for (int prefixBits = 1; prefixBits <= 8; prefixBits++)
        {
            for (int pad = 0; pad < 256; pad++)
            {
                byte[] buf = new byte[8];
                WriteStream w = new WriteStream(buf);
                uint z = 0;
                w.SerializeBits(ref z, prefixBits);
                int alignBits = (8 - prefixBits % 8) % 8;
                if (alignBits > 0)
                {
                    uint p = (uint)pad & (uint)((1 << alignBits) - 1);
                    w.SerializeBits(ref p, alignBits);
                }
                w.Flush();
                _cases++;
                try
                {
                    ReadStream r = new ReadStream(buf, 8);
                    uint got = 0;
                    r.SerializeBits(ref got, prefixBits);
                    bool ok = r.SerializeAlign();
                    uint expectPad = alignBits == 0 ? 0 : (uint)pad & (uint)((1 << alignBits) - 1);
                    if (ok != (expectPad == 0))
                    {
                        Finding($"align prefix={prefixBits} pad={expectPad}: returned {ok}");
                    }
                    if (!ok && r.Error != SerializeError.NonzeroPadding)
                    {
                        Finding($"align prefix={prefixBits} pad={expectPad}: error {r.Error}, expected NonzeroPadding");
                    }
                }
                catch (Exception e)
                {
                    Finding($"align prefix={prefixBits} pad={pad}: THREW {e.GetType().Name}: {e.Message}");
                }
            }
        }

        // i) SerializeBytes with a caller span larger than the packet
        foreach (int want in new[] { 1, 7, 8, 63, 64, 1 << 16 })
        {
            for (int bytes = 0; bytes <= 16; bytes++)
            {
                _cases++;
                try
                {
                    byte[] buf = new byte[16];
                    ReadStream r = new ReadStream(buf, bytes);
                    byte[] dst = new byte[want];
                    bool ok = r.SerializeBytes(dst);
                    if (ok != (want <= bytes))
                    {
                        Finding($"bytes want={want} packet={bytes}: returned {ok}");
                    }
                }
                catch (Exception e)
                {
                    Finding($"bytes want={want} packet={bytes}: THREW {e.GetType().Name}: {e.Message}");
                }
            }
        }

        // j) compressed float: every raw value in the code space, plus hostile params
        {
            (float Min, float Max, float Res)[] shapes =
            {
                (0f, 10f, 0.01f), (0f, 1f, 1f), (-1f, 1f, 0.5f),
                (0f, 10000000000f, 1f), (-3.4e38f, 3.4e38f, 1e-30f),
                (0f, float.MaxValue, float.Epsilon),
            };
            foreach ((float min, float max, float res) in shapes)
            {
                for (int raw = 0; raw < 4096; raw++)
                {
                    byte[] buf = new byte[8];
                    WriteStream w = new WriteStream(buf);
                    uint v = (uint)raw;
                    w.SerializeBits(ref v, 32);
                    w.Flush();
                    _cases++;
                    try
                    {
                        ReadStream r = new ReadStream(buf, 8);
                        float value = -12345f;
                        bool ok = r.SerializeCompressedFloat(ref value, min, max, res);
                        // STANDARD.md 2.0: an accepted decode is finite whatever the
                        // declaration -- an infinite delta (max - min overflows float)
                        // included, whose every decode is refused as non_finite_float
                        if (ok && (float.IsNaN(value) || float.IsInfinity(value) || value < min || value > max))
                        {
                            Finding($"cfloat[{min},{max},{res}] raw={raw}: decoded {value}, outside [min,max] or not finite");
                            break;
                        }
                        if (!ok && float.IsInfinity(max - min) && r.Error != SerializeError.NonFiniteFloat
                            && r.Error != SerializeError.ValueOutOfRange && r.Error != SerializeError.PastEnd)
                        {
                            Finding($"cfloat[{min},{max},{res}] raw={raw}: refused as {r.Error}");
                            break;
                        }
                    }
                    catch (Exception e)
                    {
                        Finding($"cfloat[{min},{max},{res}] raw={raw}: THREW {e.GetType().Name}: {e.Message}");
                        break;
                    }
                }
            }
        }

        // k) int-relative: exhaustive over the encoding prefix space at every truncation
        {
            for (int raw = 0; raw < 1 << 16; raw++)
            {
                byte[] buf = new byte[8];
                buf[0] = (byte)raw;
                buf[1] = (byte)(raw >> 8);
                // previous is the caller's own state and lives in the int_relative
                // domain, 0 to 2^31 - 1 (STANDARD.md, "int_relative"): the sweep draws
                // from inside it, both ends included, because a previous outside the
                // domain is caller error with no defined wire meaning to attack
                foreach (int previous in new[] { 100, 0, 1, int.MaxValue, int.MaxValue - 1, int.MaxValue - 69914 })
                {
                    for (int bytes = 0; bytes <= 8; bytes += 4)
                    {
                        _cases++;
                        try
                        {
                            ReadStream r = new ReadStream(buf, bytes);
                            int current = 777;
                            bool ok = r.SerializeIntRelative(previous, ref current);
                            if (!ok && current != 777)
                            {
                                Finding($"intrel raw={raw} prev={previous} bytes={bytes}: failed read wrote {current}");
                            }
                        }
                        catch (Exception e)
                        {
                            Finding($"intrel raw={raw} prev={previous} bytes={bytes}: THREW {e.GetType().Name}: {e.Message}");
                        }
                    }
                }
            }
        }
    }

    private static IEnumerable<ulong> EnumerateAll(ulong space)
    {
        for (ulong i = 0; i < space; i++)
        {
            yield return i;
        }
    }

    // ---- attack 5b: the wide surface (128 bit + fixed point), stream and batch ----
    //
    // Bounded pairwise matrix, not a second Cartesian fuzz: each wide field is
    // attacked on its own (so a refusal's destination and terminal latch are
    // observable), the combined sequence is attacked whole (so stream and batch
    // must agree bit for bit), and canonical witnesses pin the accepted side to
    // values and bytes the unit suites already hold (tests/FixedPoint.cs).

    private static int _wideCases;
    private static int _wideStream;
    private static int _wideBatch;

    private static string WideDigest(Packet p)
    {
        return string.Join('|',
            p.U128, p.I128Full, p.I128Group96, p.I128Group64, p.I128Group32, p.I128Degenerate,
            p.FixedS64, p.FixedU64, p.FixedS32, p.FixedU32, p.FixedS16, p.FixedU16,
            p.FixedI128, p.FixedU128, p.FixedFrac0, p.FixedI128Frac0);
    }

    private static void SetWideSentinels(Packet p)
    {
        p.U128 = new UInt128Value(0xA5A5A5A5A5A5A5A5UL, 0x5A5A5A5A5A5A5A5AUL);
        p.I128Full = new Int128Value(0xA5A5A5A5A5A5A5A5UL, 0x5A5A5A5A5A5A5A5AUL);
        p.I128Group96 = p.I128Full;
        p.I128Group64 = p.I128Full;
        p.I128Group32 = p.I128Full;
        p.I128Degenerate = p.I128Full;
        p.FixedS64 = -777777777L;
        p.FixedU64 = 777777777UL;
        p.FixedS32 = -777777;
        p.FixedU32 = 777777U;
        p.FixedS16 = -7777;
        p.FixedU16 = 7777;
        p.FixedI128 = p.I128Full;
        p.FixedU128 = p.U128;
        p.FixedFrac0 = -777777777L;
        p.FixedI128Frac0 = p.I128Full;
    }

    private sealed class WideField
    {
        public string Name = "";
        public Func<IBitStream, Packet, bool> Stream = null!;
        public Func<ReadStream, Packet, bool> Batch = null!;
        public Func<Packet, bool> InRange = null!;
    }

    private static WideField[] WideFields()
    {
        return new WideField[]
        {
            new WideField { Name = "u128", Stream = (s, p) => s.SerializeUInt128(ref p.U128),
                Batch = (rs, p) => { ReadBatch b = rs.BeginBatch(); bool ok = b.SerializeUInt128(ref p.U128); b.End(); return ok; },
                InRange = p => true },
            new WideField { Name = "i128-128", Stream = (s, p) => s.SerializeInt128(ref p.I128Full, Int128Value.MinValue, Int128Value.MaxValue),
                Batch = (rs, p) => { ReadBatch b = rs.BeginBatch(); bool ok = b.SerializeInt128(ref p.I128Full, Int128Value.MinValue, Int128Value.MaxValue); b.End(); return ok; },
                InRange = p => true },
            new WideField { Name = "i128-96", Stream = (s, p) => s.SerializeInt128(ref p.I128Group96, Int128Value.Zero, new Int128Value(0xFFFFFFFFUL, ulong.MaxValue)),
                Batch = (rs, p) => { ReadBatch b = rs.BeginBatch(); bool ok = b.SerializeInt128(ref p.I128Group96, Int128Value.Zero, new Int128Value(0xFFFFFFFFUL, ulong.MaxValue)); b.End(); return ok; },
                InRange = p => p.I128Group96 >= Int128Value.Zero && p.I128Group96 <= new Int128Value(0xFFFFFFFFUL, ulong.MaxValue) },
            new WideField { Name = "i128-64", Stream = (s, p) => s.SerializeInt128(ref p.I128Group64, (Int128Value)long.MinValue, (Int128Value)long.MaxValue),
                Batch = (rs, p) => { ReadBatch b = rs.BeginBatch(); bool ok = b.SerializeInt128(ref p.I128Group64, (Int128Value)long.MinValue, (Int128Value)long.MaxValue); b.End(); return ok; },
                InRange = p => p.I128Group64 >= (Int128Value)long.MinValue && p.I128Group64 <= (Int128Value)long.MaxValue },
            new WideField { Name = "i128-32", Stream = (s, p) => s.SerializeInt128(ref p.I128Group32, Int128Value.Zero, new Int128Value(0, 0xFFFFFFFFUL)),
                Batch = (rs, p) => { ReadBatch b = rs.BeginBatch(); bool ok = b.SerializeInt128(ref p.I128Group32, Int128Value.Zero, new Int128Value(0, 0xFFFFFFFFUL)); b.End(); return ok; },
                InRange = p => p.I128Group32 >= Int128Value.Zero && p.I128Group32 <= new Int128Value(0, 0xFFFFFFFFUL) },
            new WideField { Name = "i128-degenerate", Stream = (s, p) => s.SerializeInt128(ref p.I128Degenerate, (Int128Value)42, (Int128Value)42),
                Batch = (rs, p) => { ReadBatch b = rs.BeginBatch(); bool ok = b.SerializeInt128(ref p.I128Degenerate, (Int128Value)42, (Int128Value)42); b.End(); return ok; },
                InRange = p => p.I128Degenerate == (Int128Value)42 },
            new WideField { Name = "fixed-s64-q48.16", Stream = (s, p) => s.SerializeFixed(ref p.FixedS64, 48, 16, -100000, +100000),
                Batch = (rs, p) => { ReadBatch b = rs.BeginBatch(); bool ok = b.SerializeFixed(ref p.FixedS64, 48, 16, -100000, +100000); b.End(); return ok; },
                InRange = p => p.FixedS64 >= (-100000L << 16) && p.FixedS64 <= (100000L << 16) },
            new WideField { Name = "fixed-u64-q32.32", Stream = (s, p) => s.SerializeFixed(ref p.FixedU64, 32, 32, 0, 30000),
                Batch = (rs, p) => { ReadBatch b = rs.BeginBatch(); bool ok = b.SerializeFixed(ref p.FixedU64, 32, 32, 0, 30000); b.End(); return ok; },
                InRange = p => p.FixedU64 <= (30000UL << 32) },
            new WideField { Name = "fixed-s32-q16.16", Stream = (s, p) => s.SerializeFixed(ref p.FixedS32, 16, 16, -2000, +2000),
                Batch = (rs, p) => { ReadBatch b = rs.BeginBatch(); bool ok = b.SerializeFixed(ref p.FixedS32, 16, 16, -2000, +2000); b.End(); return ok; },
                InRange = p => p.FixedS32 >= (-2000 << 16) && p.FixedS32 <= (2000 << 16) },
            new WideField { Name = "fixed-u32-q16.16", Stream = (s, p) => s.SerializeFixed(ref p.FixedU32, 16, 16, 0, 30000),
                Batch = (rs, p) => { ReadBatch b = rs.BeginBatch(); bool ok = b.SerializeFixed(ref p.FixedU32, 16, 16, 0, 30000); b.End(); return ok; },
                InRange = p => p.FixedU32 <= (30000U << 16) },
            new WideField { Name = "fixed-s16-q8.8", Stream = (s, p) => s.SerializeFixed(ref p.FixedS16, 8, 8, -100, +100),
                Batch = (rs, p) => { ReadBatch b = rs.BeginBatch(); bool ok = b.SerializeFixed(ref p.FixedS16, 8, 8, -100, +100); b.End(); return ok; },
                InRange = p => p.FixedS16 >= (-100 << 8) && p.FixedS16 <= (100 << 8) },
            new WideField { Name = "fixed-u16-q8.8", Stream = (s, p) => s.SerializeFixed(ref p.FixedU16, 8, 8, 0, 200),
                Batch = (rs, p) => { ReadBatch b = rs.BeginBatch(); bool ok = b.SerializeFixed(ref p.FixedU16, 8, 8, 0, 200); b.End(); return ok; },
                InRange = p => p.FixedU16 <= (200 << 8) },
            new WideField { Name = "fixed-i128-q112.16", Stream = (s, p) => s.SerializeFixed(ref p.FixedI128, 112, 16, -144115188075855872, +144115188075855872),
                Batch = (rs, p) => { ReadBatch b = rs.BeginBatch(); bool ok = b.SerializeFixed(ref p.FixedI128, 112, 16, -144115188075855872, +144115188075855872); b.End(); return ok; },
                InRange = p => p.FixedI128 >= ((Int128Value)(-144115188075855872L) << 16) && p.FixedI128 <= ((Int128Value)144115188075855872L << 16) },
            new WideField { Name = "fixed-u128-q64.64", Stream = (s, p) => s.SerializeFixed(ref p.FixedU128, 64, 64, 0, long.MaxValue),
                Batch = (rs, p) => { ReadBatch b = rs.BeginBatch(); bool ok = b.SerializeFixed(ref p.FixedU128, 64, 64, 0, long.MaxValue); b.End(); return ok; },
                InRange = p => p.FixedU128 <= ((UInt128Value)long.MaxValue << 64) },
            new WideField { Name = "fixed-s64-q64.0", Stream = (s, p) => s.SerializeFixed(ref p.FixedFrac0, 64, 0, -1000000, +1000000),
                Batch = (rs, p) => { ReadBatch b = rs.BeginBatch(); bool ok = b.SerializeFixed(ref p.FixedFrac0, 64, 0, -1000000, +1000000); b.End(); return ok; },
                InRange = p => p.FixedFrac0 >= -1000000 && p.FixedFrac0 <= 1000000 },
            new WideField { Name = "fixed-i128-q128.0", Stream = (s, p) => s.SerializeFixed(ref p.FixedI128Frac0, 128, 0, -1000, +1000),
                Batch = (rs, p) => { ReadBatch b = rs.BeginBatch(); bool ok = b.SerializeFixed(ref p.FixedI128Frac0, 128, 0, -1000, +1000); b.End(); return ok; },
                InRange = p => p.FixedI128Frac0 >= (Int128Value)(-1000) && p.FixedI128Frac0 <= (Int128Value)1000 },
        };
    }

    private static void AttemptWideField(WideField field, byte[] data, int bytes, int slack, bool batch, string label)
    {
        _cases++;
        _wideCases++;
        if (batch) { _wideBatch++; } else { _wideStream++; }
        byte[] buffer = new byte[bytes + slack];
        Array.Copy(data, buffer, Math.Min(bytes, data.Length));
        for (int i = bytes; i < buffer.Length; i++) buffer[i] = 0xFF;
        Packet p = new Packet();
        SetWideSentinels(p);
        string before = WideDigest(p);
        try
        {
            ReadStream rs = new ReadStream(buffer, bytes);
            bool ok = batch ? field.Batch(rs, p) : field.Stream(rs, p);
            if (rs.BitsProcessed > (long)bytes * 8)
            {
                Finding($"{label}: BitsProcessed {rs.BitsProcessed} exceeds packet {(long)bytes * 8} bits");
            }
            if (!ok)
            {
                if (rs.Error == SerializeError.None)
                {
                    Finding($"{label}: wide read reported failure with Error == None");
                }
                if (WideDigest(p) != before)
                {
                    Finding($"{label}: refused wide read wrote its destination ({WideDigest(p)})");
                }
                // terminal latch: a second read on the failed stream must also
                // refuse, keep the first error, and still not write
                SerializeError first = rs.Error;
                bool again = batch ? field.Batch(rs, p) : field.Stream(rs, p);
                if (again || rs.Error != first || WideDigest(p) != before)
                {
                    Finding($"{label}: wide read after failure not latched (again={again}, error {first} -> {rs.Error})");
                }
            }
            else
            {
                if (rs.Error != SerializeError.None)
                {
                    Finding($"{label}: wide read reported success with Error == {rs.Error}");
                }
                if (!field.InRange(p))
                {
                    Finding($"{label}: wide read decoded out of range ({WideDigest(p)})");
                }
            }
        }
        catch (Exception e)
        {
            Finding($"{label}: THREW {e.GetType().Name}: {e.Message}");
        }
    }

    private static string WideBatchDigest(byte[] data, int bytes, int slack, byte poison)
    {
        byte[] buffer = new byte[bytes + slack];
        Array.Copy(data, buffer, Math.Min(bytes, data.Length));
        for (int i = bytes; i < buffer.Length; i++) buffer[i] = poison;
        ReadStream s = new ReadStream(buffer, bytes);
        Packet p = new Packet();
        bool ok;
        try { ok = ReadWide128Batch(s, p); }
        catch (Exception e) { return "THREW " + e.GetType().Name + ": " + e.Message; }
        return Digest(p, ok, s.Error, s.BitsProcessed);
    }

    private static Packet WideCanonicalPacket()
    {
        Packet p = new Packet();
        p.U128 = new UInt128Value(0x0123456789ABCDEFUL, 0xFEDCBA9876543210UL);
        p.I128Full = new Int128Value(0x0123456789ABCDEFUL, 0x0FEDCBA987654321UL);
        p.I128Group96 = new Int128Value(0x89ABCDEFUL, 0x0123456789ABCDEFUL);
        p.I128Group64 = (Int128Value)(-5000000000L);
        p.I128Group32 = new Int128Value(0, 0xDEADBEEFUL);
        p.I128Degenerate = (Int128Value)42;
        p.FixedS64 = -(54321L * 65536 + 12345);
        p.FixedU64 = (29999UL << 32) + 12345UL;
        p.FixedS32 = 1234 * 65536 + 32768;
        p.FixedU32 = 29999U * 65536U + 65535U;
        p.FixedS16 = -(3 * 256 + 64);
        p.FixedU16 = 199 * 256 + 255;
        p.FixedI128 = (Int128Value)(-(98765432109L * 65536 + 4321));
        p.FixedU128 = new UInt128Value(0x0123456789ABCDEFUL, 0x0FEDCBA987654321UL);
        p.FixedFrac0 = -999999;
        p.FixedI128Frac0 = (Int128Value)(-1000);
        return p;
    }

    private static bool WriteWide128Batch(ref WriteBatch b, Packet p)
    {
        b.SerializeUInt128(ref p.U128);
        b.SerializeInt128(ref p.I128Full, Int128Value.MinValue, Int128Value.MaxValue);
        b.SerializeInt128(ref p.I128Group96, Int128Value.Zero, new Int128Value(0xFFFFFFFFUL, ulong.MaxValue));
        b.SerializeInt128(ref p.I128Group64, (Int128Value)long.MinValue, (Int128Value)long.MaxValue);
        b.SerializeInt128(ref p.I128Group32, Int128Value.Zero, new Int128Value(0, 0xFFFFFFFFUL));
        b.SerializeInt128(ref p.I128Degenerate, (Int128Value)42, (Int128Value)42);
        b.SerializeFixed(ref p.FixedS64, 48, 16, -100000, +100000);
        b.SerializeFixed(ref p.FixedU64, 32, 32, 0, 30000);
        b.SerializeFixed(ref p.FixedS32, 16, 16, -2000, +2000);
        b.SerializeFixed(ref p.FixedU32, 16, 16, 0, 30000);
        b.SerializeFixed(ref p.FixedS16, 8, 8, -100, +100);
        b.SerializeFixed(ref p.FixedU16, 8, 8, 0, 200);
        b.SerializeAlign();
        b.SerializeFixed(ref p.FixedI128, 112, 16, -144115188075855872, +144115188075855872);
        b.SerializeFixed(ref p.FixedU128, 64, 64, 0, long.MaxValue);
        b.SerializeFixed(ref p.FixedFrac0, 64, 0, -1000000, +1000000);
        b.SerializeFixed(ref p.FixedI128Frac0, 128, 0, -1000, +1000);
        b.SerializeEnd();
        return b.Error == SerializeError.None;
    }

    // pinned bytes from tests/FixedPoint.cs (derived there from STANDARD.md by
    // an independent oracle, cross-checked against the C++ suite; never
    // regenerated from this implementation)
    private static readonly byte[] WideUint128Golden =
    {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
        0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
    };

    private static readonly byte[] WideInt128Golden =
    {
        0x11, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x3F,
    };

    private static readonly byte[] WideFixedGolden =
    {
        0xC0, 0x60, 0x00, 0x80, 0xA2, 0x7C, 0xFC, 0xEC, 0x26, 0xCB, 0xFF, 0xFF,
        0x4B, 0x1D, 0x1F, 0xEF, 0xD2, 0x1A, 0x1F, 0x01, 0xE9, 0xFF, 0xFF, 0x09,
        0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x78, 0x6F, 0x5E, 0x4D, 0x3C,
        0x2B, 0x1A, 0x09, 0x04,
    };

    private static void AttackWide128()
    {
        // canonical witness: stream write, batch write, stream read, batch read
        // must all agree on the same bytes and the same values, at exact
        // capacity and with poisoned slack
        Packet canonical = WideCanonicalPacket();
        byte[] streamBuf = new byte[512];
        WriteStream ws = new WriteStream(streamBuf);
        ReadWide128(ws, canonical);
        ws.Flush();
        int canonicalBytes = (int)ws.BytesProcessed;
        byte[] batchBuf = new byte[512];
        WriteStream wb = new WriteStream(batchBuf);
        WriteBatch batch = wb.BeginBatch();
        Packet batchPacket = WideCanonicalPacket();
        WriteWide128Batch(ref batch, batchPacket);
        batch.End();
        wb.Flush();
        _cases++;
        if ((int)wb.BytesProcessed != canonicalBytes
            || !streamBuf.AsSpan(0, canonicalBytes).SequenceEqual(batchBuf.AsSpan(0, canonicalBytes)))
        {
            Finding("wide canonical: stream and batch writes differ");
        }
        foreach (int slack in new[] { 0, 1, 8, 64 })
        {
            _cases++;
            string viaStream = ReadDigest(ReadWide128, streamBuf, canonicalBytes, slack, 0xFF);
            string viaBatch = WideBatchDigest(streamBuf, canonicalBytes, slack, 0xFF);
            Packet back = new Packet();
            ReadStream rs = new ReadStream(streamBuf, canonicalBytes);
            bool ok = ReadWide128(rs, back);
            if (!ok || WideDigest(back) != WideDigest(canonical))
            {
                Finding($"wide canonical slack={slack}: stream read back differs (ok={ok})");
            }
            if (viaStream != viaBatch)
            {
                Finding($"wide canonical slack={slack}: stream and batch digests differ\n      stream: {viaStream}\n      batch:  {viaBatch}");
            }
        }

        // pinned witnesses: the exact bytes the unit suites already hold
        {
            _cases++;
            UInt128Value expectU = new UInt128Value(0x0123456789ABCDEFUL, 0xFEDCBA9876543210UL);
            Packet p = new Packet();
            ReadStream rs = new ReadStream(WideUint128Golden, WideUint128Golden.Length);
            if (!rs.SerializeUInt128(ref p.U128) || p.U128 != expectU)
            {
                Finding($"wide pinned uint128: stream decoded {p.U128}, expected {expectU}");
            }
            Packet pb = new Packet();
            ReadStream rsb = new ReadStream(WideUint128Golden, WideUint128Golden.Length);
            ReadBatch bb = rsb.BeginBatch();
            bool okb = bb.SerializeUInt128(ref pb.U128);
            bb.End();
            if (!okb || pb.U128 != expectU)
            {
                Finding($"wide pinned uint128: batch decoded {pb.U128}, expected {expectU}");
            }
        }
        {
            _cases++;
            UInt128Value mag = (UInt128Value)1 << 70;
            Int128Value min = Int128Value.Zero - (Int128Value)mag;
            Int128Value max = (Int128Value)mag;
            Int128Value expect = Int128Value.Zero - (Int128Value)(UInt128Value)0x0123456789ABCDEFUL;
            Packet p = new Packet();
            ReadStream rs = new ReadStream(WideInt128Golden, WideInt128Golden.Length);
            if (!rs.SerializeInt128(ref p.I128Full, min, max) || p.I128Full != expect)
            {
                Finding($"wide pinned int128: stream decoded {p.I128Full}, expected {expect}");
            }
            Packet pb = new Packet();
            ReadStream rsb = new ReadStream(WideInt128Golden, WideInt128Golden.Length);
            ReadBatch bb = rsb.BeginBatch();
            bool okb = bb.SerializeInt128(ref pb.I128Full, min, max);
            bb.End();
            if (!okb || pb.I128Full != expect)
            {
                Finding($"wide pinned int128: batch decoded {pb.I128Full}, expected {expect}");
            }
        }
        {
            _cases++;
            // the fixed point golden section, exactly as FixedWireData writes it
            short q88 = 0;
            int q1616 = 0;
            long q4816 = 0;
            uint q1616u = 0;
            Int128Value q112 = Int128Value.Zero;
            Int128Value q6464 = Int128Value.Zero;
            ReadStream rs = new ReadStream(WideFixedGolden, WideFixedGolden.Length);
            rs.SerializeFixed(ref q88, 8, 8, -100, +100);
            rs.SerializeFixed(ref q1616, 16, 16, -2000, +2000);
            rs.SerializeFixed(ref q4816, 48, 16, -100000, +100000);
            rs.SerializeFixed(ref q1616u, 16, 16, 0, 30000);
            rs.SerializeAlign();
            rs.SerializeFixed(ref q112, 112, 16, -144115188075855872, +144115188075855872);
            rs.SerializeFixed(ref q6464, 64, 64, long.MinValue, long.MaxValue);
            bool ok = rs.Error == SerializeError.None
                && q88 == -(3 * 256 + 64)
                && q1616 == 1234 * 65536 + 32768
                && q4816 == -(54321L * 65536 + 12345)
                && q1616u == 29999U * 65536U + 65535U
                && q112 == (Int128Value)(-(98765432109L * 65536 + 4321))
                && q6464 == ((Int128Value)0x0123456789ABCDEF << 64) + 0x0FEDCBA987654321;
            if (!ok)
            {
                Finding($"wide pinned fixed: stream decoded ({q88},{q1616},{q4816},{q1616u},{q112},{q6464}) error={rs.Error}");
            }
        }

        // hostile single-field matrix: all-zero / all-one / truncated / random
        // buffers, stream and batch, exact capacity and poisoned slack
        WideField[] fields = WideFields();
        Rng rng = new Rng(0x128128);
        foreach (WideField field in fields)
        {
            foreach (int len in new[] { 0, 1, 2, 4, 8, 12, 16, 20, 24, 32 })
            {
                byte[] zeros = new byte[Math.Max(len, 1)];
                byte[] ones = new byte[Math.Max(len, 1)];
                for (int i = 0; i < ones.Length; i++) ones[i] = 0xFF;
                AttemptWideField(field, zeros, len, 0, false, $"wide {field.Name} zeros len={len}");
                AttemptWideField(field, zeros, len, 8, true, $"wide {field.Name} zeros len={len} batch");
                AttemptWideField(field, ones, len, 0, true, $"wide {field.Name} ones len={len}");
                AttemptWideField(field, ones, len, 8, false, $"wide {field.Name} ones len={len} slack");
            }
            for (int trial = 0; trial < 150; trial++)
            {
                int len = (int)rng.Range(33);
                byte[] d = new byte[Math.Max(len, 1)];
                for (int i = 0; i < d.Length; i++) d[i] = (byte)rng.Next();
                AttemptWideField(field, d, len, (trial & 1) == 0 ? 0 : 8, (trial & 1) == 0, $"wide {field.Name} rand t={trial} len={len}");
            }
        }

        // hostile combined sequence: canonical bytes truncated at every length,
        // flipped at every 32 bit group boundary, and mutated in high groups;
        // stream and batch must agree exactly, whatever either decides
        for (int len = 0; len <= canonicalBytes; len++)
        {
            _cases++;
            string viaStream = ReadDigest(ReadWide128, streamBuf, len, 0, 0x00);
            string viaBatch = WideBatchDigest(streamBuf, len, 0, 0x00);
            if (viaStream != viaBatch)
            {
                Finding($"wide combined truncate len={len}: stream and batch differ\n      stream: {viaStream}\n      batch:  {viaBatch}");
            }
        }
        foreach (int bit in new[] { 0, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128, 255, 256 })
        {
            if (bit >= canonicalBytes * 8) continue;
            byte[] d = new byte[canonicalBytes];
            Array.Copy(streamBuf, d, canonicalBytes);
            d[bit >> 3] ^= (byte)(1 << (bit & 7));
            foreach (int slack in new[] { 0, 8 })
            {
                _cases++;
                string viaStream = ReadDigest(ReadWide128, d, canonicalBytes, slack, 0xFF);
                string viaBatch = WideBatchDigest(d, canonicalBytes, slack, 0xFF);
                if (viaStream != viaBatch)
                {
                    Finding($"wide combined flip bit={bit} slack={slack}: stream and batch differ");
                }
                string? f = Attempt(ReadWide128, d, canonicalBytes, slack, $"wide combined flip bit={bit} slack={slack}");
                if (f != null) Finding(f);
            }
        }
        for (int trial = 0; trial < 500; trial++)
        {
            int len = (int)rng.Range((ulong)canonicalBytes + 1);
            byte[] d = new byte[Math.Max(len, 1)];
            for (int i = 0; i < d.Length; i++) d[i] = (byte)rng.Next();
            _cases++;
            string viaStream = ReadDigest(ReadWide128, d, len, trial % 3 == 0 ? 8 : 0, 0xFF);
            string viaBatch = WideBatchDigest(d, len, trial % 3 == 0 ? 8 : 0, 0xFF);
            if (viaStream != viaBatch)
            {
                Finding($"wide combined rand t={trial} len={len}: stream and batch differ");
            }
        }

        // allocation: a refused wide read must not allocate, stream or batch
        {
            byte[] tiny = new byte[8];
            Packet p = new Packet();
            ReadStream rs = new ReadStream(tiny, 0);
            for (int i = 0; i < 200; i++)
            {
                rs.Reset(tiny, 0);
                SetWideSentinels(p);
                ReadWide128(rs, p);
                rs.Reset(tiny, 0);
                SetWideSentinels(p);
                ReadWide128Batch(rs, p);
            }
            long before = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < 1000; i++)
            {
                rs.Reset(tiny, 0);
                SetWideSentinels(p);
                ReadWide128(rs, p);
                rs.Reset(tiny, 8);
                SetWideSentinels(p);
                ReadWide128Batch(rs, p);
            }
            long alloc = GC.GetAllocatedBytesForCurrentThread() - before;
            Console.WriteLine($"  wide128 refused reads:    {alloc} bytes over 1000 stream+batch pairs");
            _cases++;
            if (alloc > 0)
            {
                Finding($"refused wide128 reads allocate {alloc} bytes over 1000 stream+batch pairs");
            }
        }

        Console.WriteLine($"  wide128 cases: {_wideCases} single-field (stream {_wideStream}, batch {_wideBatch}) plus combined/canonical, seed 0x128128, canonical {canonicalBytes} bytes");
    }

    // ---- attack 6: loop termination guards ----

    private static void AttackLoopTermination()
    {
        // build a packet with a long continuation chain, then truncate it everywhere.
        // the guarded loop must terminate within the packet's bit budget in every case.
        // the source buffer is sized for the full 200-entry chain (1800 bits = 225 bytes):
        // writes are writer-trusted (serialize#52) — overflowing a write buffer is a harness
        // bug, not an attack surface. the reader-side sweep below still uses only the first
        // 64 bytes, so the hostile prefixes are unchanged.
        byte[] full = new byte[256];
        {
            WriteStream w = new WriteStream(full);
            for (int i = 0; i < 200; i++)
            {
                bool more = true;
                w.SerializeBool(ref more);
                uint payload = (uint)i;
                w.SerializeBits(ref payload, 8);
            }
            w.Flush();
        }

        for (int bytes = 0; bytes <= 64; bytes++)
        {
            for (int fill = 0; fill < 2; fill++)
            {
                byte[] d = new byte[bytes == 0 ? 1 : bytes];
                Array.Copy(full, d, Math.Min(full.Length, d.Length));
                if (fill == 1)
                {
                    for (int i = 0; i < d.Length; i++) d[i] = 0xFF; // every continuation bit set
                }

                // guarded form: SerializeUtil.Continue
                {
                    _cases++;
                    ReadStream r = new ReadStream(d, bytes);
                    bool more = true;
                    long iterations = 0;
                    long cap = (long)bytes * 8 + 16;
                    while (SerializeUtil.Continue(r, ref more))
                    {
                        uint payload = 0;
                        r.SerializeBits(ref payload, 8);
                        if (++iterations > cap)
                        {
                            Finding($"Continue loop did not terminate: bytes={bytes} fill={fill}, " +
                                    $"{iterations} iterations past the {cap} bit budget");
                            break;
                        }
                    }
                }

                // guarded form: SerializeUtil.Until
                {
                    _cases++;
                    ReadStream r = new ReadStream(d, bytes);
                    bool done = false;
                    long iterations = 0;
                    long cap = (long)bytes * 8 + 16;
                    while (SerializeUtil.Until(r, ref done))
                    {
                        uint payload = 0;
                        r.SerializeBits(ref payload, 8);
                        if (++iterations > cap)
                        {
                            Finding($"Until loop did not terminate: bytes={bytes} fill={fill}");
                            break;
                        }
                    }
                }

                // the NAIVE form the docs warn about, run under a cap: records whether the
                // hazard is real (it should be — this is why Continue/Until exist)
                {
                    _cases++;
                    ReadStream r = new ReadStream(d, bytes);
                    bool more = true;
                    long iterations = 0;
                    long cap = (long)bytes * 8 + 4096;
                    while (more)
                    {
                        r.SerializeBool(ref more);
                        uint payload = 0;
                        r.SerializeBits(ref payload, 8);
                        if (++iterations > cap)
                        {
                            NaiveHangs++;
                            break;
                        }
                    }
                }

                // a count-driven loop where the count is NOT checked before use
                {
                    _cases++;
                    ReadStream r = new ReadStream(d, bytes);
                    int count = 1000000; // stale value from a previous packet
                    r.SerializeInt(ref count, 0, 1000000);
                    long work = 0;
                    for (int i = 0; i < count; i++)
                    {
                        uint payload = 0;
                        if (!r.SerializeBits(ref payload, 8)) { }
                        if (++work > (long)bytes * 8 + 64)
                        {
                            CountAmplification++;
                            break;
                        }
                    }
                }
            }
        }
    }

    private static int NaiveHangs;
    private static int CountAmplification;

    // ---- attack 7: allocation on the read hot path ----

    private static void AttackAllocations()
    {
        byte[] buffer = new byte[128];
        Array.Copy(Golden, buffer, Golden.Length);

        // warm up the JIT
        for (int i = 0; i < 200; i++)
        {
            ReadStream r = new ReadStream(buffer, Golden.Length);
            Packet p = new Packet();
            ReadGolden(r, p);
        }

        // reused stream, no strings: this is the path that must be allocation free
        {
            ReadStream r = new ReadStream(buffer, Golden.Length);
            Packet p = new Packet();
            long before = GC.GetAllocatedBytesForCurrentThread();
            bool allOk = true;
            for (int i = 0; i < 1000; i++)
            {
                r.Reset(buffer, buffer.Length);
                allOk &= ReadNoStrings(r, p);
            }
            long alloc = GC.GetAllocatedBytesForCurrentThread() - before;
            Console.WriteLine($"  non-string read path: {alloc} bytes over 1000 reads ({alloc / 1000.0:F2} B/read), all fields decoded={allOk}");
            if (alloc > 0)
            {
                Finding($"non-string read path allocates {alloc / 1000.0:F2} bytes per read");
            }
        }

        // full golden read including strings
        {
            ReadStream r = new ReadStream(buffer, Golden.Length);
            Packet p = new Packet();
            long before = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < 1000; i++)
            {
                r.Reset(buffer, Golden.Length);
                ReadGolden(r, p);
            }
            long alloc = GC.GetAllocatedBytesForCurrentThread() - before;
            Console.WriteLine($"  golden read (2 strings):  {alloc / 1000.0:F2} B/read");
        }

        // hostile read that fails on the first field: the cheap-failure requirement
        {
            byte[] tiny = new byte[8];
            ReadStream r = new ReadStream(tiny, 0);
            Packet p = new Packet();
            long before = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < 1000; i++)
            {
                r.Reset(tiny, 0);
                ReadGolden(r, p);
            }
            long alloc = GC.GetAllocatedBytesForCurrentThread() - before;
            Console.WriteLine($"  rejected empty packet:    {alloc / 1000.0:F2} B/read");
            if (alloc > 0)
            {
                Finding($"rejecting an empty packet allocates {alloc / 1000.0:F2} bytes");
            }
        }

        // random hostile packets: what does the attacker make us allocate per packet?
        {
            Rng rng = new Rng(99);
            byte[] hostile = new byte[128];
            ReadStream r = new ReadStream(hostile, 72);
            Packet p = new Packet();
            for (int i = 0; i < 200; i++) { r.Reset(hostile, 72); ReadGolden(r, p); }
            long before = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < 10000; i++)
            {
                for (int j = 0; j < 72; j++) hostile[j] = (byte)rng.Next();
                r.Reset(hostile, 72);
                ReadGolden(r, p);
            }
            long alloc = GC.GetAllocatedBytesForCurrentThread() - before;
            Console.WriteLine($"  random hostile packet:    {alloc / 10000.0:F2} B/packet (attacker controlled)");
        }
    }

    private static bool ReadNoStrings(IBitStream s, Packet p)
    {
        s.SerializeBits(ref p.Bits4, 4);
        s.SerializeBits(ref p.Bits11, 11);
        s.SerializeBits(ref p.Bits24, 24);
        s.SerializeBits(ref p.Bits32, 32);
        s.SerializeInt(ref p.IntSmall, -100, +100);
        s.SerializeInt(ref p.IntFull, int.MinValue, int.MaxValue);
        s.SerializeBool(ref p.Flag);
        s.SerializeFloat(ref p.F);
        s.SerializeCompressedFloat(ref p.CF, 0.0f, 10.0f, 0.01f);
        s.SerializeDouble(ref p.D);
        s.SerializeByte(ref p.U8);
        s.SerializeUInt16(ref p.U16);
        s.SerializeUInt32(ref p.U32);
        s.SerializeUInt64(ref p.U64);
        s.SerializeIntRelative(100, ref p.RelNear);
        s.SerializeIntRelative(100, ref p.RelFar);
        s.SerializeAlign();
        s.SerializeBytes(p.Bytes);
        s.SerializeBits64(ref p.Bits64, 33);
        s.SerializeInt64(ref p.Int64Wide, -5000000000L, 5000000000L);
        return s.Error == SerializeError.None;
    }

    // ---- attack 8: the low level BitReader on untrusted data ----

    private static void AttackBitReader()
    {
        for (int bytes = 0; bytes <= 16; bytes++)
        {
            byte[] buf = new byte[16];
            for (int i = 0; i < 16; i++) buf[i] = 0xFF;
            for (int bits = 1; bits <= 32; bits++)
            {
                _cases++;
                BitReader r = new BitReader(buf, bytes);
                try
                {
                    if (!r.WouldReadPastEnd(bits))
                    {
                        r.ReadBits(bits);
                    }
                }
                catch (Exception e)
                {
                    Finding($"BitReader.ReadBits guarded by WouldReadPastEnd still THREW: bytes={bytes} bits={bits} {e.GetType().Name}");
                }
            }
            // ReadAlign is the low level align: does it have a guard of its own?
            _cases++;
            try
            {
                BitReader r = new BitReader(buf, bytes);
                if (bytes > 0 && !r.WouldReadPastEnd(1))
                {
                    r.ReadBits(1);
                }
                r.ReadAlign();
            }
            catch (Exception e)
            {
                BitReaderAlignThrows.Add($"bytes={bytes}: {e.GetType().Name}: {e.Message}");
            }
        }
    }

    private static readonly List<string> BitReaderAlignThrows = new List<string>();

    // ---- focused probe: 64 bit headroom, full detail, no dedup ----

    private static void ProbeInt64Headroom()
    {
        (long Min, long Max)[] ranges =
        {
            (0, 5), (0, 255), (-5000000000L, 5000000000L), (long.MinValue, long.MaxValue),
            (0, (long)1 << 40), (long.MinValue, 0), (0, long.MaxValue),
            (long.MinValue, long.MinValue + 1), (long.MaxValue - 1, long.MaxValue),
            (-1, 0), (1, 2), (-(1L << 40), (1L << 40)),
        };
        int reported = 0;
        foreach ((long min, long max) in ranges)
        {
            int bits = SerializeUtil.BitsRequired64((ulong)min, (ulong)max);
            ulong legalSpan = (ulong)max - (ulong)min;
            ulong space = bits >= 64 ? 0 : 1UL << bits; // 0 means "whole 64 bit space"
            ulong[] probes = { 0, legalSpan, legalSpan + 1, space == 0 ? ulong.MaxValue : space - 1, legalSpan / 2 };
            foreach (ulong raw in probes)
            {
                if (space != 0 && raw >= space) continue;
                byte[] buf = new byte[16];
                WriteStream w = new WriteStream(buf);
                ulong rv = raw;
                w.SerializeBits64(ref rv, bits);
                w.Flush();
                ReadStream r = new ReadStream(buf, 16);
                long value = 999;
                bool ok = r.SerializeInt64(ref value, min, max);
                bool shouldPass = raw <= legalSpan;
                if (ok != shouldPass || (ok && (value < min || value > max)))
                {
                    reported++;
                    Console.WriteLine($"  int64[{min},{max}] bits={bits} span={legalSpan} raw={raw}: " +
                                      $"ok={ok} (expected {shouldPass}) value={value}");
                }
            }
        }
        Console.WriteLine($"  int64 headroom anomalies: {reported}");
    }

    // ---- attack 9: slack bytes must never reach an output value ----
    //
    // The reader loads 8 byte windows past the packet whenever the buffer allows it.
    // If any decoded value, error, or bit count differs between a slack free buffer and
    // one whose slack is poisoned with 0xFF, out of bounds data has leaked into the
    // packet's meaning.

    private static string Digest(Packet p, bool ok, SerializeError err, long bits)
    {
        return string.Join('|',
            p.Bits4, p.Bits11, p.Bits24, p.Bits32, p.Bits64,
            p.IntSmall, p.IntFull, p.Int64Full, p.Int64Wide, p.Flag,
            BitConverter.SingleToUInt32Bits(p.F), BitConverter.SingleToUInt32Bits(p.CF),
            BitConverter.DoubleToUInt64Bits(p.D), p.U8, p.U16, p.U32, p.U64,
            p.RelNear, p.RelFar, Convert.ToHexString(p.Bytes), p.Str, p.Stones,
            p.U128, p.I128Full, p.I128Group96, p.I128Group64, p.I128Group32, p.I128Degenerate,
            p.FixedS64, p.FixedU64, p.FixedS32, p.FixedU32, p.FixedS16, p.FixedU16,
            p.FixedI128, p.FixedU128, p.FixedFrac0, p.FixedI128Frac0,
            ok, err, bits);
    }

    private static string ReadDigest(ReadFn fn, byte[] data, int bytes, int slack, byte poison)
    {
        byte[] buffer = new byte[bytes + slack];
        Array.Copy(data, buffer, Math.Min(bytes, data.Length));
        for (int i = bytes; i < buffer.Length; i++) buffer[i] = poison;
        ReadStream s = new ReadStream(buffer, bytes);
        Packet p = new Packet();
        bool ok;
        try { ok = fn(s, p); }
        catch (Exception e) { return "THREW " + e.GetType().Name + ": " + e.Message; }
        return Digest(p, ok, s.Error, s.BitsProcessed);
    }

    private static void AttackSlackIndependence()
    {
        Rng rng = new Rng(0xA5A5A5A5);
        ReadFn[] fns = { ReadGolden, ReadWide, ReadWide128 };
        foreach (ReadFn fn in fns)
        {
            for (int trial = 0; trial < 300000; trial++)
            {
                int bytes = (int)rng.Range(90);
                byte[] d = new byte[Math.Max(bytes, 1)];
                for (int i = 0; i < d.Length; i++) d[i] = (byte)rng.Next();
                _cases++;
                string bare = ReadDigest(fn, d, bytes, 0, 0x00);
                foreach (byte poison in new byte[] { 0x00, 0xFF, 0xA5 })
                {
                    foreach (int slack in new[] { 1, 3, 7, 8, 9, 64 })
                    {
                        string with = ReadDigest(fn, d, bytes, slack, poison);
                        if (with != bare)
                        {
                            Finding($"SLACK LEAK: bytes={bytes} slack={slack} poison=0x{poison:X2}\n" +
                                    $"      no slack: {bare}\n      w/ slack: {with}");
                        }
                    }
                }
            }
        }
        // the golden packet itself, at every truncation
        for (int bytes = 0; bytes <= Golden.Length; bytes++)
        {
            _cases++;
            string bare = ReadDigest(ReadGolden, Golden, bytes, 0, 0x00);
            foreach (byte poison in new byte[] { 0x00, 0xFF })
            {
                for (int slack = 1; slack <= 16; slack++)
                {
                    string with = ReadDigest(ReadGolden, Golden, bytes, slack, poison);
                    if (with != bare)
                    {
                        Finding($"SLACK LEAK (golden truncated to {bytes}): slack={slack} poison=0x{poison:X2}");
                    }
                }
            }
        }
    }

    // ---- attack 10: exhaustive short packet spaces ----

    private static void AttackExhaustiveShort()
    {
        byte[] d = new byte[4];
        // all 2 byte packets, both readers, several slack modes
        for (int v = 0; v < 1 << 16; v++)
        {
            d[0] = (byte)v; d[1] = (byte)(v >> 8);
            foreach (ReadFn fn in new ReadFn[] { ReadGolden, ReadWide })
            {
                foreach (int slack in new[] { 0, 1, 8 })
                {
                    string? f = Attempt(fn, d, 2, slack, $"exhaustive2 0x{v:X4}");
                    if (f != null) Finding(f);
                }
            }
        }
        // all 3 byte packets through the golden reader, no slack (the guarded window path)
        for (int v = 0; v < 1 << 24; v++)
        {
            d[0] = (byte)v; d[1] = (byte)(v >> 8); d[2] = (byte)(v >> 16);
            string? f = Attempt(ReadGolden, d, 3, 0, $"exhaustive3 0x{v:X6}");
            if (f != null) Finding(f);
        }
    }

    // ---- driver ----

    private static void Main()
    {
        Stopwatch sw = Stopwatch.StartNew();

        Stage("bit flip / byte substitution sweep", AttackBitFlipSweep);
        Stage("truncation sweep", AttackTruncationSweep);
        Stage("wide surface (64 bit, big buffer sizes)", AttackWideSurface);
        Stage("wide surface (128 bit + fixed, stream and batch)", AttackWide128);
        Stage("random packet fuzz", AttackRandomFuzz);
        Stage("targeted hostile fields", AttackTargeted);
        Stage("loop termination guards", AttackLoopTermination);
        Stage("int64 headroom probe", ProbeInt64Headroom);
        Stage("low level BitReader", AttackBitReader);
        Stage("slack independence (OOB leak)", AttackSlackIndependence);
        Stage("exhaustive 2 and 3 byte packet spaces", AttackExhaustiveShort);
        Stage("read path allocations", AttackAllocations);

        Console.WriteLine();
        Console.WriteLine($"hostile cases run: {_cases:N0} in {sw.Elapsed.TotalSeconds:F1}s");
        Console.WriteLine($"naive while(more) loops that spun past the cap: {NaiveHangs}");
        Console.WriteLine($"unchecked-count loops that over-worked: {CountAmplification}");
        if (BitReaderAlignThrows.Count > 0)
        {
            Console.WriteLine($"BitReader.ReadAlign threw in {BitReaderAlignThrows.Count} cases, e.g. {BitReaderAlignThrows[0]}");
        }
        Console.WriteLine();
        if (Findings.Count == 0)
        {
            Console.WriteLine("NO FINDINGS: the read path held.");
        }
        else
        {
            Console.WriteLine($"FINDINGS ({Findings.Count} distinct classes):");
            foreach (string f in Findings)
            {
                StringBuilder key = new StringBuilder();
                foreach (char c in f) { if (!char.IsDigit(c) && c != '-' && c != '.') key.Append(c); }
                Console.WriteLine($"  [x{Classes[key.ToString()]}] {f}");
            }
        }
        Environment.Exit(Findings.Count == 0 ? 0 : 1);
    }

    private static void Stage(string name, Action a)
    {
        Stopwatch sw = Stopwatch.StartNew();
        int before = Findings.Count;
        a();
        Console.WriteLine($"{name}: {sw.Elapsed.TotalSeconds:F1}s, {Findings.Count - before} findings");
    }

    private sealed class Rng
    {
        private ulong _state;
        public Rng(ulong seed) { _state = seed; }
        public ulong Next()
        {
            _state += 0x9E3779B97F4A7C15;
            ulong z = _state;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EB;
            return z ^ (z >> 31);
        }
        public ulong Range(ulong bound) { return Next() % bound; }
    }
}
