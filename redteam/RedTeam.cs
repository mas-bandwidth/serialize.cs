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
    private static long InfiniteDeltaDecodes; // documented non-finite decodes from infinite-delta params: noted, never a finding

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
        public float CFWide; // decoded from an infinite-delta field: non-finite by documented behavior
        public double D;
        public byte U8;
        public ushort U16;
        public uint U32;
        public ulong U64;
        public int RelNear, RelFar;
        public byte[] Bytes = new byte[7];
        public string Str = "";
        public string WStr = "";
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
        s.SerializeWideString(ref p.WStr, 8);
        return s.Error == SerializeError.None;
    }

    // a wider surface: hostile ranges, wide strings with big buffer sizes, 64 bit paths
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
        s.SerializeWideString(ref p.WStr, 4096);
        s.SerializeString(ref p.Str, int.MaxValue);      // length field takes 31 bits
        s.SerializeWideString(ref p.WStr, int.MaxValue);
        s.SerializeBytes(p.Bytes);
        return s.Error == SerializeError.None;
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
                // +inf. The library documents that an infinite delta is deliberately
                // NOT rejected (parity with C++; rejecting it as API misuse is an open
                // family decision), and its decode is non-finite: normalized * inf.
                // Counted loudly in the summary rather than failing the verdict, so
                // the exit code stays armed for what the rule actually promises.
                if (float.IsNaN(p.CFWide) || float.IsInfinity(p.CFWide))
                {
                    InfiniteDeltaDecodes++;
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

        // b) wide string claiming a huge code point count (allocation attack)
        foreach (int bufferSize in new[] { 8, 4096, 1 << 20, int.MaxValue })
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
                    r.SerializeWideString(ref s, bufferSize);
                    long alloc = GC.GetAllocatedBytesForCurrentThread() - before;
                    if (alloc > 4096 + (long)bytes * 8)
                    {
                        Finding($"wstring claim={claim} packet={bytes}B: allocated {alloc} bytes " +
                                "(allocation not bounded by packet size)");
                    }
                }
                catch (Exception e)
                {
                    Finding($"wstring claim={claim} bytes={bytes}: THREW {e.GetType().Name}: {e.Message}");
                }
            }
        }

        // c) same allocation question for SerializeString
        foreach (int bufferSize in new[] { 16, 4096, 1 << 24, int.MaxValue })
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

        // d) every 32 bit code point value through the wide string reader
        {
            uint[] hostile =
            {
                0, 0x41, 0xD7FF, 0xD800, 0xDBFF, 0xDC00, 0xDFFF, 0xE000, 0xFFFE, 0xFFFF,
                0x10000, 0x10FFFF, 0x110000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
            };
            foreach (uint cp in hostile)
            {
                byte[] buf = new byte[16];
                WriteStream w = new WriteStream(buf);
                int one = 1;
                w.SerializeInt(ref one, 0, 7);
                uint v = cp;
                w.SerializeBits(ref v, 32);
                w.Flush();
                _cases++;
                try
                {
                    ReadStream r = new ReadStream(buf, 16);
                    string s = "";
                    bool ok = r.SerializeWideString(ref s, 8);
                    bool legal = cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF);
                    if (ok != legal)
                    {
                        Finding($"wstring code point 0x{cp:X}: read returned {ok}, expected {legal}");
                    }
                }
                catch (Exception e)
                {
                    Finding($"wstring code point 0x{cp:X}: THREW {e.GetType().Name}: {e.Message}");
                }
            }
        }

        // e) every invalid UTF-8 shape through SerializeString
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
                    else if (r.Error != SerializeError.InvalidString)
                    {
                        Finding($"invalid UTF-8 {Convert.ToHexString(payload)}: error {r.Error}, expected InvalidString");
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
                    if (!ok && r.Error != SerializeError.Align)
                    {
                        Finding($"align prefix={prefixBits} pad={expectPad}: error {r.Error}, expected Align");
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
                        if (ok && (float.IsNaN(value) || value < min || value > max))
                        {
                            // an infinite delta (max - min overflows float) is documented
                            // as deliberately not rejected -- parity with C++, rejecting
                            // it as API misuse is an open family decision -- and every
                            // decode through it is non-finite. Note it, do not fail on it.
                            if (float.IsInfinity(max - min) && (float.IsNaN(value) || float.IsInfinity(value)))
                            {
                                InfiniteDeltaDecodes++;
                            }
                            else
                            {
                                Finding($"cfloat[{min},{max},{res}] raw={raw}: decoded {value} outside [min,max]");
                                break;
                            }
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
                foreach (int previous in new[] { 100, 0, -1000, int.MaxValue, int.MinValue, int.MaxValue - 1 })
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

    // ---- attack 6: loop termination guards ----

    private static void AttackLoopTermination()
    {
        // build a packet with a long continuation chain, then truncate it everywhere.
        // the guarded loop must terminate within the packet's bit budget in every case.
        byte[] full = new byte[64];
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
            p.RelNear, p.RelFar, Convert.ToHexString(p.Bytes), p.Str, p.WStr,
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
        ReadFn[] fns = { ReadGolden, ReadWide };
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
        Console.WriteLine($"non-finite decodes from infinite-delta params (documented; open family decision): {InfiniteDeltaDecodes}");
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
