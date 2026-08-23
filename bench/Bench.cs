/*
    Bench.cs

    Console benchmark for the C# serialize port, following the family bench methodology
    (the C++ library's bench.cpp, ported to Rust in serialize.rs benches/throughput.rs):
    fixed iteration counts, the workload varied per iteration by a serially dependent
    LCG the JIT cannot fold, several trials with the best one reported, and every
    result accumulated into a sink so no serialization work can be dead code
    eliminated. Zero third-party dependencies (family value): plain Stopwatch, no
    benchmark framework.

    First rows (mas-bandwidth/schema#64): string + wstring — until these landed no
    string or wstring row existed anywhere in the family's benches, and the
    measure-first rule says rows land before or with any string/wstring change. The
    corpus is IDENTICAL to the one in serialize.rs benches/throughput.rs, so the rows
    are directly comparable across the family.

    Run in Release; every timed closure runs one full untimed warmup pass first, so
    the optimizing JIT tier is what the trials measure:

        dotnet run --project bench/Bench.csproj -c Release -f net10.0
*/

using System;
using System.Diagnostics;

namespace Serialize.Bench;

internal static class Program
{
    private const int NumTrials = 5;
    private const int NumItems = 1_000_000;
    private const int NumVariants = 8;
    private const ulong VariantMask = NumVariants - 1;

    // the bufferSize argument to SerializeString/SerializeWideString: lengths fit
    // [0,255], so the length field is exactly 8 bits and the narrow path's align
    // after it is zero bits
    private const int StringBufferSize = 256;

    // holds the largest wire image StringBufferSize permits (wstring: 1 length byte +
    // 255 groups * 4 bytes = 1021), rounded up to the writer's multiple-of-8 contract
    private const int WireBufferSize = 1024;

    // every result is accumulated here and the total is observed in Main, so no
    // serialization work can be dead code eliminated
    private static long s_sink;

    // ASCII, game-flavored, lengths 2..59 bytes — names, k=v state, chat, a system line
    private static readonly string[] StringCorpus =
    {
        "gg",
        "hello",
        "player_042",
        "the quick brown fox",
        "id=12345;hp=100;team=red",
        "a fairly typical chat message, nothing special",
        "[system] player_042 has joined the match on map overgrowth",
        "yes",
    };

    // BMP text across several scripts plus astral chars (surrogate pairs in the
    // string itself, one 32 bit group per UTF-16 code unit on the wire), so the
    // surrogate handling on both sides is part of what the wstring rows measure
    private static readonly string[] WideCorpus =
    {
        "gg",
        "héllo wörld",
        "こんにちは世界",
        "Привет, мир",
        "café ☕ break",
        "good game 😀👍",
        "𝔘𝔫𝔦𝔠𝔬𝔡𝔢 𝔴𝔦𝔡𝔢",
        "mixed ascii と 日本語 and 😀",
    };

    // the serially dependent generator, same constants as the C++ bench.cpp and the
    // Rust benches/throughput.rs
    private static ulong LcgNext(ulong rng)
    {
        return (rng * 6364136223846793005UL) + 1442695040888963407UL;
    }

    private static double BestOf(Action f)
    {
        // one full untimed pass: with tiered compilation the first pass runs partly at
        // tier 0 while OSR and call counting promote the loop and everything it calls,
        // so what the trials then time is the optimizing tier
        f();
        double best = double.MaxValue;
        for (int i = 0; i < NumTrials; i++)
        {
            Stopwatch timer = Stopwatch.StartNew();
            f();
            double elapsed = timer.Elapsed.TotalSeconds;
            if (elapsed < best)
            {
                best = elapsed;
            }
        }
        return best;
    }

    private static void BenchStringFamily(string label, string[] corpus, bool wide)
    {
        byte[] buffer = new byte[WireBufferSize];
        WriteStream write = new WriteStream(buffer);

        // one variant buffer per corpus entry, for the read rows. One string per fresh
        // stream, so every corpus entry has a fixed wire size; data this much shorter
        // than the buffer also keeps the reader on its fast path.
        byte[][] variantBuffers = new byte[NumVariants][];
        int[] variantBytes = new int[NumVariants];
        for (int i = 0; i < NumVariants; i++)
        {
            variantBuffers[i] = new byte[WireBufferSize];
            write.Reset(variantBuffers[i]);
            string setup = corpus[i];
            bool setupOk = wide
                ? write.SerializeWideString(ref setup, StringBufferSize)
                : write.SerializeString(ref setup, StringBufferSize);
            write.Flush();
            if (!setupOk)
            {
                Console.Error.WriteLine($"corpus entry {i} failed to serialize");
                Environment.Exit(1);
            }
            variantBytes[i] = (int)write.BytesProcessed;
        }

        // every timed loop walks the same deterministic index sequence, so the wire
        // byte total is computed once here, outside the timing
        long totalBytes = 0;
        {
            ulong rng = 1;
            for (int i = 0; i < NumItems; i++)
            {
                rng = LcgNext(rng);
                totalBytes += variantBytes[(int)((rng >> 33) & VariantMask)];
            }
        }

        double bestWrite = BestOf(() =>
        {
            ulong rng = 1;
            for (int i = 0; i < NumItems; i++)
            {
                rng = LcgNext(rng);
                int idx = (int)((rng >> 33) & VariantMask);
                write.Reset(buffer);
                string value = corpus[idx];
                bool ok = wide
                    ? write.SerializeWideString(ref value, StringBufferSize)
                    : write.SerializeString(ref value, StringBufferSize);
                write.Flush();
                s_sink += write.BytesProcessed + (ok ? 1 : 0);
            }
        });

        // the read path allocates the result string per call — the documented
        // exception to the zero-allocation rule — so these rows honestly include the
        // allocator and whatever GC time those allocations induce. (The Rust rows
        // reuse the read target's capacity; comparable is not identical here.)
        ReadStream read = new ReadStream(buffer);
        double bestRead = BestOf(() =>
        {
            string value = string.Empty;
            ulong rng = 1;
            for (int i = 0; i < NumItems; i++)
            {
                rng = LcgNext(rng);
                int idx = (int)((rng >> 33) & VariantMask);
                read.Reset(variantBuffers[idx], variantBytes[idx]);
                bool ok = wide
                    ? read.SerializeWideString(ref value, StringBufferSize)
                    : read.SerializeString(ref value, StringBufferSize);
                s_sink += value.Length + (ok ? 1 : 0);
            }
        });

        // unlike a fixed-layout packet measure, string measure is real work — the
        // narrow length is a UTF-8 byte count over the value — so this row earns
        // its keep
        MeasureStream measure = new MeasureStream();
        double bestMeasure = BestOf(() =>
        {
            ulong rng = 1;
            for (int i = 0; i < NumItems; i++)
            {
                rng = LcgNext(rng);
                int idx = (int)((rng >> 33) & VariantMask);
                measure.Reset();
                string value = corpus[idx];
                bool ok = wide
                    ? measure.SerializeWideString(ref value, StringBufferSize)
                    : measure.SerializeString(ref value, StringBufferSize);
                s_sink += measure.BitsProcessed + (ok ? 1 : 0);
            }
        });

        double totalMB = totalBytes / (1024.0 * 1024.0);
        double items = NumItems / 1_000_000.0;

        Console.WriteLine($"{label + " write:",-18}{totalMB / bestWrite,8:F1} MB/s  ({items / bestWrite:F1} M strings/s)");
        Console.WriteLine($"{label + " read:",-18}{totalMB / bestRead,8:F1} MB/s  ({items / bestRead:F1} M strings/s)");
        Console.WriteLine($"{label + " measure:",-18}{items / bestMeasure,19:F1} M strings/s");
    }

    private static int Main()
    {
        Console.WriteLine();
        Console.WriteLine("[serialize.cs benchmark]");
        Console.WriteLine();
#if DEBUG
        Console.WriteLine("WARNING: Debug build. only Release numbers are meaningful!");
        Console.WriteLine();
#endif

        BenchStringFamily("string", StringCorpus, wide: false);
        BenchStringFamily("wstring", WideCorpus, wide: true);

        Console.WriteLine();

        // observing the sink is what makes it a sink; it is always nonzero after a
        // successful run (the ok bits alone contribute NumItems per row)
        return s_sink != 0 ? 0 : 1;
    }
}
