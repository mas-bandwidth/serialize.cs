/*
    Conformance.cs

    The shared conformance corpus, run through this port's reader, writer and measure.

    conformance/ is vendored verbatim from mas-bandwidth/serialize beside STANDARD.md,
    and CI fails when either drifts. The corpus is the normative instrument: it holds
    the accepted and refused vectors the standard's rules require, written once for
    every implementation, so no port checks its codec against its own regenerated
    expectations (STANDARD.md, "The shared corpus is the conformance instrument").

    Every vector file embedded in the test assembly runs here, and the embedding is a
    glob over conformance/ that MSBuild re-evaluates, so a vector added upstream and
    copied across runs without a code change. An empty corpus is a failed run.

    An operation this file cannot drive is a FAILURE, never a skip. So is a parameter it
    does not understand and a fixed point Q format whose storage width it cannot name: a
    vector whose declaration is not the one being exercised proves nothing, and a silent
    skip is how a gap stays one.

    One step machine drives both the single operation files and the sequence, object and
    message files. A single operation vector is a one or two step sequence built from the
    record's own parameters, so there is exactly one execution path and the sequence
    files cannot drift away from the operation files.

    Accepted vectors must yield the stated value and consume the stated bit count. A
    vector marked `writer = canonical` is additionally re-emitted through the write
    stream and compared byte for byte, flush included, which is where the trailing bits
    obligation bites: the unused bits of the final byte must be zero. A vector carrying
    `measure_at_least` runs the same steps through the measure stream, and the check is
    an inequality because STANDARD.md makes a measure a bound and not the packet size.

    Refused vectors must be refused FOR THE REASON THE VECTOR STATES (the stream's first
    latched error, spelled by SerializeUtil.RefusalName), must leave the caller's SCALAR
    destination exactly as the caller left it, and must leave the stream TERMINAL.
    STANDARD.md leaves a caller owned BUFFER unspecified after a refusal — bytes and
    string — so those destinations are not checked. Terminality is checked by BEHAVIOR rather than by
    an accessor, so the same check ports to every implementation in the family: every
    later step of a sequence must also refuse however many readable bits remain, and a
    further read the vector does not name must fail, consume no bits and write nothing.

    THE BUFFER CONTRACT. This reader requires no slack past the data, and its window
    loads take a different path depending on whether slack is present, so every stream is
    presented twice: once with slack bytes set to a non-zero pattern, so a decode that
    depends on memory past the end cannot pass by reading zeros, and once with the buffer
    sized exactly to the vector. An end refuses on the stream's stated length, never on
    the slack.

    THE SECOND READ PATH. ReadBatch is a reader of its own: it carries inline copies of
    the hot reads (bits, the ranged ints, the floats, align) against register-resident
    state. So every vector is presented a third time, through one ReadBatch opened over
    the whole stream, and must reach the same verdict, the same reason, the same values
    and the same bit count. A rule missing from the batch is red here.

    A vector carrying `writer_input` hands the writer that float32, refused vectors
    included, and requires the record's bytes exactly.

    The negative controls run the same machinery with one rule deleted at a time (a
    build with SerializeConformanceControls=true) and require the failing vectors to be
    exactly conformance-controls/<rule>.expected, once through the streams and once
    through the batch; and the unknown-operation control, run in every build, requires a
    corpus file whose operation has no runner to go red.
*/

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace Serialize.Tests;

internal static partial class Program
{
    // the slack presentation: enough for a full window load, filled with a pattern that
    // is visible if it is ever interpreted
    private const int ConformanceSlack = 8;
    private const byte ConformanceSlackFill = 0xA5;

    // room for the widest vector in the corpus plus the writer's qword granularity
    private const int ConformanceScratchBytes = 128;

    // Destination sentinels for the refusal check. They must survive the narrowing this
    // runner performs on the way to each operation's own width — 32 bits for float and
    // for the ranged int — or a destination the library correctly left alone still reads
    // as written.
    private static readonly UInt128Value ConformanceSentinelBits = 0xCAFEF00Du;
    private static readonly Int128Value ConformanceSentinelNumber = -1234567;

    private static int s_conformanceFailures;
    private static int s_conformanceChecked;
    private static int s_conformanceWriterChecks;
    private static int s_conformanceMeasureChecks;
    private static int s_conformanceBatchChecks;

    // the controls run the corpus quietly and read back which vectors failed
    private static bool s_conformanceQuiet;
    private static readonly HashSet<string> s_conformanceFailedNames = new HashSet<string>();

    // which readers the corpus is presented to: the stream (twice, with and without
    // slack), the batch, or both
    private static bool s_conformanceStreams = true;
    private static bool s_conformanceBatch = true;

    // the bool destination's sentinel, true in one presentation and false in the
    // other, so a refused bool read that wrote either value is seen
    private static bool s_conformanceBoolSentinel = true;

    private enum ConformanceExpect
    {
        Refused,
        Value,
        Bits,       // compared as a bit pattern, never as a value
    }

    private enum StepKind
    {
        Bits,
        Bool,
        UInt128,
        Align,
        Int,
        Int64,
        Int128,
        IntRelative,
        Float,
        Double,
        CompressedFloat,
        Bytes,
        String,
        Fixed,
        End,
        Object,     // opens a nested object over the steps that follow
    }

    private sealed class Step
    {
        public StepKind Kind;
        public int Width;               // bits, count, buffer_size, or the object's step count
        public Int128Value Min;
        public Int128Value Max;
        public float FloatMin;
        public float FloatMax;
        public float FloatResolution;
        public int IntegerBits;
        public int FractionBits;
        public int Previous;

        // outputs
        public UInt128Value Bits;       // the decoded value, where a bit pattern is what is pinned
        public Int128Value Number;
        public bool Boolean;
        public byte[] Buffer = Array.Empty<byte>();
        public string Text = "";
    }

    private sealed class ConformanceVector
    {
        public string Source = "";
        public string Operation = "";
        public string Name = "";
        public List<KeyValuePair<string, string>> Params = new List<KeyValuePair<string, string>>();
        public List<string> StepText = new List<string>();
        public byte[] Bytes = Array.Empty<byte>();
        public ConformanceExpect Expect = ConformanceExpect.Value;
        public string ExpectedValue = "";
        public string ExpectedReason = "";
        public string Malformed = "";   // why the record cannot be run as written
        public bool HasWriterInput;
        public uint WriterInput;
        public long Consumed;
        public bool HasConsumed;
        public long MeasureAtLeast;
        public bool HasMeasure;
        public bool WriterCanonical;
    }

    private static void TestConformanceVectors()
    {
        List<ConformanceVector> vectors = LoadConformanceVectors();
        Check(vectors.Count > 0,
            "no conformance vectors were embedded: the corpus is the conformance instrument, and an empty run is a failure");

        RunConformanceCorpus(vectors);

        Check(s_conformanceFailures == 0,
            $"{s_conformanceFailures} of {s_conformanceChecked} conformance vectors failed: this implementation and the shared corpus disagree, and the implementation is the bug");

        if (Verbose.Enabled)
        {
            Console.WriteLine($"    {s_conformanceChecked} conformance vectors passed: {s_conformanceBatchChecks} batch reads, {s_conformanceWriterChecks} writer checks, {s_conformanceMeasureChecks} measure checks");
        }
    }

    // Runs every vector through the presentations selected, counting failures and
    // recording which vectors failed, which is what the negative controls read back.
    private static void RunConformanceCorpus(List<ConformanceVector> vectors)
    {
        s_conformanceFailures = 0;
        s_conformanceChecked = 0;
        s_conformanceWriterChecks = 0;
        s_conformanceMeasureChecks = 0;
        s_conformanceBatchChecks = 0;
        s_conformanceFailedNames.Clear();

        // STANDARD.md, "The vector format": a name is a stable identifier, unique
        // across the corpus, which is what lets a control's .expected list name its
        // vectors and nothing else
        HashSet<string> names = new HashSet<string>();
        foreach (ConformanceVector vector in vectors)
        {
            if (!names.Add(vector.Name))
            {
                ConformanceFail(vector, "the name is not unique across the corpus");
            }
        }

        foreach (ConformanceVector vector in vectors)
        {
            RunConformanceVector(vector);
        }
    }

    // which reader a failure came from, for the diagnosis
    private static string s_conformancePresentation = "";

    private static void ConformanceFail(ConformanceVector vector, string detail)
    {
        if (!s_conformanceQuiet)
        {
            string where = s_conformancePresentation.Length > 0 ? $" ({s_conformancePresentation})" : "";
            Console.Error.WriteLine($"    FAIL {vector.Name}{where}: {detail} [{vector.Source}]");
        }
        s_conformanceFailures++;
        s_conformanceFailedNames.Add(vector.Name);
    }

    // ---------------------------------------------------------------------------------
    // the negative controls

    /*
        THE UNKNOWN-OPERATION CONTROL (STANDARD.md, "A runner discovers the directory and
        runs every vector in it"): a corpus file whose operation has no runner must fail
        the run, never be skipped. It runs in every build against the vendored control
        file, and against the records this port must also refuse to drive: wstring, the
        operation format 2.0 removed, and refused records whose reason is missing or is
        not on the standard's list.
    */
    private static void TestConformanceUnknownOperation()
    {
        string[] records =
        {
            ReadConformanceResource(ControlResourcePrefix + "unknown-operation.txt"),
            "operation wstring\nname control-wstring-is-gone-in-2-0\nparam buffer_size = 8\nbytes 00\nexpect value = \nconsumed 3\n",
            "operation bits\nname control-a-refusal-without-a-reason\nparam bits = 8\nbytes\nexpect refused\n",
            "operation bits\nname control-a-refusal-with-an-unknown-reason\nparam bits = 8\nbytes\nexpect refused overflow\n",
            "operation compressed_float\nname control-writer-input-is-not-a-float32\nparam min = 0\nparam max = 10\nparam res = 0.01\nwriter_input value = 1\nbytes 01 00\nexpect bits = 0x3C23D70B\nconsumed 10\n",
        };
        foreach (string record in records)
        {
            List<ConformanceVector> vectors = new List<ConformanceVector>();
            ParseConformanceFile("control", record, vectors);
            Check(vectors.Count == 1, "a control record did not parse as one vector");

            s_conformanceQuiet = true;
            RunConformanceCorpus(vectors);
            s_conformanceQuiet = false;

            Check(s_conformanceFailures == 1,
                $"control {vectors[0].Name}: the runner went green on a record it cannot drive; a gate that skips is not a gate");
        }

        // the reversed witness of the reason check: the same refused vector, stated with
        // the reason the reader gives and with another, goes green and red respectively
        foreach ((string reason, int failures) in new[] { ("past_end", 0), ("value_out_of_range", 1) })
        {
            List<ConformanceVector> vectors = new List<ConformanceVector>();
            ParseConformanceFile("control",
                $"operation bits\nname control-reason-{reason}\nparam bits = 8\nbytes\nexpect refused {reason}\n", vectors);
            s_conformanceQuiet = true;
            RunConformanceCorpus(vectors);
            s_conformanceQuiet = false;
            Check(s_conformanceFailures == failures,
                $"a past-the-end read stated as {reason}: expected {failures} failures, got {s_conformanceFailures}");
        }
    }

#if SERIALIZE_CONFORMANCE_CONTROLS
    /*
        THE RULE CONTROLS (STANDARD.md, "A gate nobody has seen go red is a claim, not a
        measurement"). For each conformance-controls/<rule>.expected the reader runs with
        that one rule deleted, against the real corpus, and must fail exactly the vectors
        the file names: a sabotage that breaks more than its rule, or less, is a control
        that has stopped measuring. Each runs twice, once through the stream and once
        through the batch, so a rule the batch carries inline is proven load-bearing on
        both read paths.
    */
    private static void TestConformanceControls()
    {
        List<ConformanceVector> vectors = LoadConformanceVectors();
        int controls = 0;
        foreach (string resource in typeof(Program).Assembly.GetManifestResourceNames())
        {
            if (!resource.StartsWith(ControlResourcePrefix, StringComparison.Ordinal)
                || !resource.EndsWith(".expected", StringComparison.Ordinal))
            {
                continue;
            }
            string rule = resource.Substring(ControlResourcePrefix.Length,
                resource.Length - ControlResourcePrefix.Length - ".expected".Length);
            HashSet<string> expected = new HashSet<string>();
            foreach (string rawLine in ReadConformanceResource(resource).Split('\n'))
            {
                string line = rawLine.Trim();
                if (line.Length > 0 && line[0] != '#')
                {
                    expected.Add(line);
                }
            }
            Check(expected.Count > 0, $"control {rule}: its .expected names no vectors");
            controls++;

            foreach (bool batch in new[] { false, true })
            {
                SerializeConformanceControls.Deleted = rule;
                s_conformanceStreams = !batch;
                s_conformanceBatch = batch;
                s_conformanceQuiet = true;
                RunConformanceCorpus(vectors);
                s_conformanceQuiet = false;
                s_conformanceStreams = true;
                s_conformanceBatch = true;
                SerializeConformanceControls.Deleted = "";

                List<string> unexpected = new List<string>();
                foreach (string name in s_conformanceFailedNames)
                {
                    if (!expected.Contains(name))
                    {
                        unexpected.Add(name);
                    }
                }
                List<string> missed = new List<string>();
                foreach (string name in expected)
                {
                    if (!s_conformanceFailedNames.Contains(name))
                    {
                        missed.Add(name);
                    }
                }
                string reader = batch ? "batch" : "stream";
                Check(unexpected.Count == 0 && missed.Count == 0,
                    $"control {rule} ({reader}): failed [{string.Join(", ", unexpected)}] beyond its rule and missed [{string.Join(", ", missed)}]");
                if (Verbose.Enabled)
                {
                    Console.WriteLine($"    control {rule} ({reader}): failed exactly its {expected.Count} vectors");
                }
            }
        }
        Check(controls > 0, "no conformance controls were embedded");
    }
#endif

    // ---------------------------------------------------------------------------------
    // running one vector

    private static void RunConformanceVector(ConformanceVector vector)
    {
        s_conformanceChecked++;
        s_conformancePresentation = "";

        // a record the runner cannot run as written is a failure, never a skip: a
        // refusal without its reason, or with a reason the standard does not list,
        // states nothing a reader could be held to
        if (vector.Malformed.Length > 0)
        {
            ConformanceFail(vector, vector.Malformed);
            return;
        }

        foreach (KeyValuePair<string, string> param in vector.Params)
        {
            if (!OperationTakesParam(vector.Operation, param.Key))
            {
                ConformanceFail(vector, $"no runner for parameter \"{param.Key}\" on operation \"{vector.Operation}\"");
                return;
            }
        }
        if (vector.StepText.Count > 0 && vector.Operation != "sequence")
        {
            ConformanceFail(vector, "steps are only meaningful on a sequence");
            return;
        }
        if (vector.HasWriterInput && vector.Operation != "compressed_float")
        {
            ConformanceFail(vector, "writer_input is only meaningful on a compressed_float record");
            return;
        }

        List<Step>? steps = BuildSteps(vector);
        if (steps == null)
        {
            // a corpus file this runner does not know how to drive is a gap in the
            // runner, not a pass
            ConformanceFail(vector, "no runner for this operation, or for one of its parameters");
            return;
        }

        int failuresBefore = s_conformanceFailures;
        RunConformanceReader(vector, steps);

        // the writer and the measure are handed the values the reader decoded, so running
        // them after a reader failure reports a second failure about a value that was
        // never decoded. One vector, one diagnosis.
        if (s_conformanceFailures != failuresBefore)
        {
            return;
        }
        s_conformancePresentation = "writer";
        if (vector.HasWriterInput)
        {
            RunConformanceWriterInput(vector, steps);
        }
        if (vector.Expect != ConformanceExpect.Refused)
        {
            if (vector.WriterCanonical)
            {
                RunConformanceWriter(vector, steps);
            }
            if (vector.HasMeasure)
            {
                s_conformancePresentation = "measure";
                RunConformanceMeasure(vector, steps);
            }
        }
    }

    private static byte[] ConformanceBuffer(ConformanceVector vector, int slack)
    {
        byte[] buffer = new byte[vector.Bytes.Length + slack];
        for (int i = 0; i < buffer.Length; i++)
        {
            buffer[i] = ConformanceSlackFill;
        }
        Array.Copy(vector.Bytes, buffer, vector.Bytes.Length);
        return buffer;
    }

    // The reader leg. It runs once per buffer presentation: with non-zero slack past the
    // data, and with a buffer sized exactly to the vector, through the stream; then once
    // more through a ReadBatch. The decoded values the writer and measure legs consume
    // are the ones the last presentation left behind, and the presentations must agree
    // or one of them has already been reported.
    private static void RunConformanceReader(ConformanceVector vector, List<Step> steps)
    {
        int failuresBefore = s_conformanceFailures;

        if (s_conformanceStreams)
        {
            s_conformancePresentation = "stream, slack";
            ReadConformanceVector(vector, steps, new ReadStream(ConformanceBuffer(vector, ConformanceSlack), vector.Bytes.Length));

            // one vector, one diagnosis: a presentation that already reported does not
            // report the same defect again from the other side of the buffer contract
            if (s_conformanceFailures != failuresBefore)
            {
                return;
            }
            s_conformancePresentation = "stream, exact buffer";
            s_conformanceBoolSentinel = false;
            ReadConformanceVector(vector, steps, new ReadStream(ConformanceBuffer(vector, 0), vector.Bytes.Length));
            s_conformanceBoolSentinel = true;
            if (s_conformanceFailures != failuresBefore)
            {
                return;
            }
        }

        if (s_conformanceBatch)
        {
            // the batch carries its own copy of the window load, slack and slack free
            // paths both, so it is presented both ways too
            s_conformanceBatchChecks++;
            s_conformancePresentation = "batch, slack";
            ReadConformanceVectorBatch(vector, steps, new ReadStream(ConformanceBuffer(vector, ConformanceSlack), vector.Bytes.Length));
            if (s_conformanceFailures != failuresBefore)
            {
                return;
            }
            s_conformancePresentation = "batch, exact buffer";
            s_conformanceBoolSentinel = false;
            ReadConformanceVectorBatch(vector, steps, new ReadStream(ConformanceBuffer(vector, 0), vector.Bytes.Length));
            s_conformanceBoolSentinel = true;
        }
    }

    private static void ResetStepDestinations(List<Step> steps)
    {
        foreach (Step step in steps)
        {
            step.Bits = ConformanceSentinelBits;
            step.Number = ConformanceSentinelNumber;
            step.Boolean = s_conformanceBoolSentinel;   // a refused bool read must leave this alone
            step.Text = "";
            step.Buffer = new byte[Math.Max(step.Width, 0)];
        }
    }

    // The checks every refused vector carries at the point of refusal: the stream latched
    // an error, the error is the reason the vector states, and the refused scalar read
    // left its destination alone.
    private static bool CheckConformanceRefusal(ConformanceVector vector, SerializeError error, StepRun run)
    {
        if (error == SerializeError.None)
        {
            ConformanceFail(vector, "the read was refused without latching an error");
            return false;
        }

        // STANDARD.md, "Refusal reasons": a reader must refuse for the reason the vector
        // states, and a refusal for any other reason is a disagreement about the format
        // however red the stream ends up. The latched error is the FIRST refusal's.
        string reason = SerializeUtil.RefusalName(error);
        if (reason != vector.ExpectedReason)
        {
            ConformanceFail(vector, $"refused as {reason}, the corpus states {vector.ExpectedReason}");
            return false;
        }

        // STANDARD.md, "A refused read must leave its destination unwritten". The rule
        // reaches the scalars only: a read into a caller owned buffer — bytes and
        // string — leaves that buffer's contents unspecified after a refusal, and the
        // document says so in as many words.
        Step? failed = run.FailedStep;
        if (failed != null)
        {
            Int128Value sentinel = failed.Kind == StepKind.Fixed ? FixedSentinel(failed) : ConformanceSentinelNumber;
            if ((StepValueIsABitPattern(failed.Kind) && failed.Bits != ConformanceSentinelBits) ||
                (StepValueIsANumber(failed.Kind) && failed.Number != sentinel) ||
                (failed.Kind == StepKind.Bool && failed.Boolean != s_conformanceBoolSentinel))
            {
                ConformanceFail(vector, "the refused read wrote to the destination");
                return false;
            }
        }
        return true;
    }

    // The scalar sentinel as a fixed point step's storage width carries it: the runner
    // narrows on the way in, so an untouched destination reads back narrowed.
    private static Int128Value FixedSentinel(Step step)
    {
        switch (step.IntegerBits + step.FractionBits)
        {
            case 16: return (short)(long)ConformanceSentinelNumber;
            case 32: return (int)(long)ConformanceSentinelNumber;
            default: return ConformanceSentinelNumber;
        }
    }

    // The checks every accepted vector carries: the stated values, then the bits consumed.
    private static void CheckConformanceAccepted(ConformanceVector vector, List<Step> steps, long bitsProcessed)
    {
        string[] entries = SplitExpect(vector.ExpectedValue);

        // one expect entry per step, objects, aligns and ends included, which state `-`.
        // A leading preceding_bits step carries no expectation of its own: it exists to
        // place the stream, and the record states only the operation under test.
        int offset = steps.Count - entries.Length;
        int leading = vector.Operation != "sequence" && steps.Count == 2 ? 1 : 0;
        if (offset != leading)
        {
            ConformanceFail(vector, $"the expect list states {entries.Length} values for {steps.Count - leading} steps");
            return;
        }

        for (int i = 0; i < entries.Length; i++)
        {
            if (entries[i] == "-")
            {
                continue;
            }
            if (!ExpectationMatches(steps[offset + i], entries[i]))
            {
                ConformanceFail(vector,
                    $"step {offset + i + 1} decoded {RenderStepValue(steps[offset + i])}, the corpus states {entries[i]}");
                return;
            }
        }

        if (vector.HasConsumed && bitsProcessed != vector.Consumed)
        {
            ConformanceFail(vector, $"consumed {bitsProcessed} bits, the corpus states {vector.Consumed}");
        }
    }

    private static void ReadConformanceVector(ConformanceVector vector, List<Step> steps, ReadStream stream)
    {
        ResetStepDestinations(steps);

        StepRun run = new StepRun();
        bool accepted = RunSteps(stream, steps, 0, steps.Count, run);

        if (vector.Expect == ConformanceExpect.Refused)
        {
            if (accepted)
            {
                ConformanceFail(vector, $"the read succeeded, the corpus requires refusal as {vector.ExpectedReason}");
                return;
            }
            if (!CheckConformanceRefusal(vector, stream.Error, run))
            {
                return;
            }

            // Failure is terminal, and a sequence states its own successors: every step
            // after the failing one must fail too, however many readable bits the stream
            // still holds. The vectors are built so a reader without the latch passes the
            // successor, and one of them makes the successor a DEGENERATE RANGE — a read
            // that consumes no bits and would otherwise always succeed, which is the case
            // an implementation checking the length before the width gets wrong.
            for (int i = run.StoppedAt + StepSpan(steps, run.StoppedAt); i < steps.Count; i += StepSpan(steps, i))
            {
                if (RunSteps(stream, steps, i, StepSpan(steps, i), new StepRun()))
                {
                    ConformanceFail(vector,
                        $"step {i + 1} succeeded after step {run.StoppedAt + 1} was refused; failure must be terminal");
                    return;
                }
            }

            // and the same rule against a read the vector does not name, so every refused
            // vector carries the terminality check and not only the sequences that spell a
            // successor
            FailUnlessStreamIsTerminal(vector, stream);

            // the echoes keep the first reason
            if (SerializeUtil.RefusalName(stream.Error) != vector.ExpectedReason)
            {
                ConformanceFail(vector, $"a later refusal replaced the first reason with {SerializeUtil.RefusalName(stream.Error)}");
            }
            return;
        }

        if (!accepted)
        {
            ConformanceFail(vector,
                $"the read was refused as {SerializeUtil.RefusalName(stream.Error)}, the corpus requires it to be accepted");
            return;
        }

        CheckConformanceAccepted(vector, steps, stream.BitsProcessed);
    }

    // The same leg through the second read path: one ReadBatch over the whole stream,
    // held open across every step, so the batch's register-resident cursor carries from
    // one read to the next exactly as it does in a hot serialize function. Ending the
    // batch stores its cursor and error back, and the stream must then agree with it.
    private static void ReadConformanceVectorBatch(ConformanceVector vector, List<Step> steps, ReadStream stream)
    {
        ResetStepDestinations(steps);

        StepRun run = new StepRun();
        ReadBatch batch = stream.BeginBatch();
        bool accepted = RunStepsBatch(ref batch, steps, 0, steps.Count, run);

        if (vector.Expect == ConformanceExpect.Refused)
        {
            if (accepted)
            {
                batch.End();
                ConformanceFail(vector, $"the read succeeded, the corpus requires refusal as {vector.ExpectedReason}");
                return;
            }
            if (!CheckConformanceRefusal(vector, batch.Error, run))
            {
                batch.End();
                return;
            }
            for (int i = run.StoppedAt + StepSpan(steps, run.StoppedAt); i < steps.Count; i += StepSpan(steps, i))
            {
                if (RunStepsBatch(ref batch, steps, i, StepSpan(steps, i), new StepRun()))
                {
                    batch.End();
                    ConformanceFail(vector,
                        $"step {i + 1} succeeded after step {run.StoppedAt + 1} was refused; failure must be terminal");
                    return;
                }
            }

            uint after = 0xFFFFFFFF;
            long bitsBefore = batch.BitsProcessed;
            bool further = batch.SerializeBits(ref after, 8);
            long bitsAfter = batch.BitsProcessed;
            batch.End();
            if (further || after != 0xFFFFFFFF || bitsAfter != bitsBefore)
            {
                ConformanceFail(vector, "a read after the refusal succeeded, wrote or consumed bits: failure is not terminal");
                return;
            }
            if (stream.Error != batch.Error || stream.BitsProcessed != bitsAfter)
            {
                ConformanceFail(vector, "ending the batch did not store its error and cursor back to the stream");
                return;
            }
            if (SerializeUtil.RefusalName(stream.Error) != vector.ExpectedReason)
            {
                ConformanceFail(vector, $"a later refusal replaced the first reason with {SerializeUtil.RefusalName(stream.Error)}");
            }
            return;
        }

        long consumed = batch.BitsProcessed;
        batch.End();
        if (!accepted)
        {
            ConformanceFail(vector,
                $"the read was refused as {SerializeUtil.RefusalName(stream.Error)}, the corpus requires it to be accepted");
            return;
        }
        if (stream.BitsProcessed != consumed || !stream.Ok)
        {
            ConformanceFail(vector, "ending the batch did not store its cursor back to the stream");
            return;
        }

        CheckConformanceAccepted(vector, steps, stream.BitsProcessed);
    }

    // Failure is terminal (STANDARD.md, Reader Obligations), and a refused vector is
    // where that rule is testable: the stream is checked by behavior rather than by an
    // accessor, so the same check ports to every implementation in the family. A further
    // read must fail, consume no bits and leave its destination alone.
    private static void FailUnlessStreamIsTerminal(ConformanceVector vector, ReadStream stream)
    {
        uint after = 0xFFFFFFFF;
        long bitsBefore = stream.BitsProcessed;
        if (stream.SerializeBits(ref after, 8))
        {
            ConformanceFail(vector, "the stream accepted a read after the refusal: failure is not terminal");
            return;
        }
        if (after != 0xFFFFFFFF)
        {
            ConformanceFail(vector, "the read after the refusal wrote to its destination");
            return;
        }
        if (stream.BitsProcessed != bitsBefore)
        {
            ConformanceFail(vector, "the read after the refusal consumed bits");
        }
    }

    /*
        The writer input leg. A record carrying `writer_input bits = 0x...` pins the bytes
        a writer emits when handed that float32, which is how the quantization arithmetic
        is pinned for values that do not decode back to themselves. It runs on refused
        records too.
    */
    private static void RunConformanceWriterInput(ConformanceVector vector, List<Step> steps)
    {
        s_conformanceWriterChecks++;

        byte[] scratch = new byte[ConformanceScratchBytes];
        WriteStream stream = new WriteStream(scratch);
        Step step = steps[steps.Count - 1];
        step.Bits = vector.WriterInput;
        if (!RunSteps(stream, steps, 0, steps.Count, new StepRun()))
        {
            ConformanceFail(vector, "the writer refused its writer_input");
            return;
        }
        stream.Flush();
        CheckConformanceWriterBytes(vector, stream, "writer_input");
    }

    private static void CheckConformanceWriterBytes(ConformanceVector vector, WriteStream stream, string what)
    {
        long written = stream.BytesProcessed;
        if (written != vector.Bytes.Length)
        {
            ConformanceFail(vector, $"the {what} writer emitted {written} bytes, the corpus states {vector.Bytes.Length}");
            return;
        }
        ReadOnlySpan<byte> emitted = stream.Data;
        for (int i = 0; i < written; i++)
        {
            if (emitted[i] != vector.Bytes[i])
            {
                ConformanceFail(vector,
                    $"the {what} writer emitted {BytesToHex(emitted)}, the corpus states {BytesToHex(vector.Bytes)}");
                return;
            }
        }
    }

    /*
        The writer leg. A vector marked `writer = canonical` states the bytes a conforming
        writer emits for its value, so the runner writes the decoded steps back and
        compares. The comparison covers the whole stream, which is what pins the trailing
        bits obligation: the unused bits of the final byte must be zero, and a writer
        leaking anything into them produces a byte the vector does not carry.
    */
    private static void RunConformanceWriter(ConformanceVector vector, List<Step> steps)
    {
        s_conformanceWriterChecks++;

        byte[] scratch = new byte[ConformanceScratchBytes];
        for (int i = 0; i < scratch.Length; i++)
        {
            scratch[i] = ConformanceSlackFill;
        }

        WriteStream stream = new WriteStream(scratch);
        if (!RunSteps(stream, steps, 0, steps.Count, new StepRun()))
        {
            ConformanceFail(vector, "the writer refused a canonical vector");
            return;
        }
        stream.Flush();
        CheckConformanceWriterBytes(vector, stream, "canonical");
    }

    /*
        The measure leg. STANDARD.md makes a measure a BOUND and not the packet size — "it
        need not be exact, and cannot be" — so the corpus states a floor and the check is
        an inequality. A measure that computes alignment from a running bit index starting
        at zero under-counts every unaligned start and falls below the floor, which is the
        non-conforming accounting the document names.
    */
    private static void RunConformanceMeasure(ConformanceVector vector, List<Step> steps)
    {
        s_conformanceMeasureChecks++;

        MeasureStream stream = new MeasureStream();
        if (!RunSteps(stream, steps, 0, steps.Count, new StepRun()))
        {
            ConformanceFail(vector, "the measure refused a step; a measure refuses nothing at runtime");
            return;
        }
        if (stream.BitsProcessed < vector.MeasureAtLeast)
        {
            ConformanceFail(vector,
                $"measured {stream.BitsProcessed} bits, the corpus requires at least {vector.MeasureAtLeast}");
        }
    }

    // ---------------------------------------------------------------------------------
    // the step machine

    /// <summary>Where a run stopped, and on which step, for the refusal checks.</summary>
    private sealed class StepRun
    {
        public Step? FailedStep;
        public int StoppedAt;
    }

    // advances past the steps a nested object owns, so a top level walk sees one step per
    // object
    private static int StepSpan(List<Step> steps, int index)
    {
        return steps[index].Kind == StepKind.Object ? 1 + steps[index].Width : 1;
    }

    /*
        STANDARD.md, "object": serialize_object invokes the object's own serialize function
        inline and contributes NO BYTES OF ITS OWN — it is composition, not an encoding,
        with no framing, length prefix or alignment inserted around it. A step spelled
        `object <n>` wraps the next n steps in a nested object, so a vector can state the
        same operations twice, once nested and once flat, and require identical bytes.

        The nested object is driven through the public SerializeObject surface rather than
        by calling the steps directly, so what the vectors exercise is the composition the
        stream performs.
    */
    private sealed class NestedObject : ISerializer
    {
        public List<Step> Steps = new List<Step>();
        public int Start;
        public int Count;
        public StepRun Run = new StepRun();

        public bool Serialize(IBitStream stream)
        {
            return RunSteps(stream, Steps, Start, Count, Run);
        }
    }

    private static bool RunSteps(IBitStream stream, List<Step> steps, int start, int count, StepRun run)
    {
        for (int i = start; i < start + count; i += StepSpan(steps, i))
        {
            if (steps[i].Kind == StepKind.Object)
            {
                NestedObject nested = new NestedObject
                {
                    Steps = steps,
                    Start = i + 1,
                    Count = steps[i].Width,
                    Run = run,
                };
                if (!stream.SerializeObject(nested))
                {
                    run.StoppedAt = i;
                    return false;
                }
                continue;
            }
            if (!RunStep(stream, steps[i]))
            {
                run.FailedStep = steps[i];
                run.StoppedAt = i;
                return false;
            }
        }
        return true;
    }

    /*
        Runs one step against any stream. The destination sentinel rule lives at the call
        site: for the scalar operations the caller seeds the destination and checks it
        afterwards, and for the caller owned buffers it does not, because STANDARD.md
        leaves those unspecified after a refusal.
    */
    private static bool RunStep(IBitStream stream, Step step)
    {
        switch (step.Kind)
        {
            case StepKind.Bits:
            {
                ulong value = (ulong)step.Bits;
                bool ok = stream.SerializeBits64(ref value, step.Width);
                step.Bits = value;
                return ok;
            }

            case StepKind.Bool:
                return stream.SerializeBool(ref step.Boolean);

            case StepKind.UInt128:
            {
                UInt128Value value = step.Bits;
                bool ok = stream.SerializeUInt128(ref value);
                step.Bits = value;
                return ok;
            }

            case StepKind.Align:
                return stream.SerializeAlign();

            case StepKind.Int:
            {
                int value = (int)step.Number;
                bool ok = stream.SerializeInt(ref value, (int)step.Min, (int)step.Max);
                step.Number = value;
                return ok;
            }

            case StepKind.Int64:
            {
                long value = (long)step.Number;
                bool ok = stream.SerializeInt64(ref value, (long)step.Min, (long)step.Max);
                step.Number = value;
                return ok;
            }

            case StepKind.Int128:
            {
                Int128Value value = step.Number;
                bool ok = stream.SerializeInt128(ref value, step.Min, step.Max);
                step.Number = value;
                return ok;
            }

            case StepKind.IntRelative:
            {
                int value = (int)step.Number;
                bool ok = stream.SerializeIntRelative(step.Previous, ref value);
                step.Number = value;
                return ok;
            }

            case StepKind.Float:
            {
                float value = BitConverter.UInt32BitsToSingle((uint)step.Bits);
                bool ok = stream.SerializeFloat(ref value);
                step.Bits = BitConverter.SingleToUInt32Bits(value);
                return ok;
            }

            case StepKind.Double:
            {
                double value = BitConverter.UInt64BitsToDouble((ulong)step.Bits);
                bool ok = stream.SerializeDouble(ref value);
                step.Bits = BitConverter.DoubleToUInt64Bits(value);
                return ok;
            }

            case StepKind.CompressedFloat:
            {
                float value = BitConverter.UInt32BitsToSingle((uint)step.Bits);
                bool ok = stream.SerializeCompressedFloat(ref value, step.FloatMin, step.FloatMax, step.FloatResolution);
                step.Bits = BitConverter.SingleToUInt32Bits(value);
                return ok;
            }

            case StepKind.Bytes:
                return stream.SerializeBytes(step.Buffer);

            case StepKind.String:
                return stream.SerializeString(ref step.Text, step.Width);

            case StepKind.Fixed:
                return RunFixedStep(stream, step);

            case StepKind.End:
                return stream.SerializeEnd();

            default:
                // nesting is driven by RunSteps, which owns the step range an object
                // wraps; a bare object step reaching here is a runner bug
                return false;
        }
    }

    // The step machine again, over a ReadBatch: the batch is a ref struct, so it cannot
    // stand behind IBitStream, and every operation is called on it directly. A nested
    // object runs through the batch's SerializeObject, whose function is handed the
    // underlying stream, exactly as a serialize function nested in a batch would be.
    private static bool RunStepsBatch(ref ReadBatch batch, List<Step> steps, int start, int count, StepRun run)
    {
        for (int i = start; i < start + count; i += StepSpan(steps, i))
        {
            if (steps[i].Kind == StepKind.Object)
            {
                NestedObject nested = new NestedObject
                {
                    Steps = steps,
                    Start = i + 1,
                    Count = steps[i].Width,
                    Run = run,
                };
                if (!batch.SerializeObject(nested))
                {
                    run.StoppedAt = i;
                    return false;
                }
                continue;
            }
            if (!RunStepBatch(ref batch, steps[i]))
            {
                run.FailedStep = steps[i];
                run.StoppedAt = i;
                return false;
            }
        }
        return true;
    }

    private static bool RunStepBatch(ref ReadBatch batch, Step step)
    {
        switch (step.Kind)
        {
            case StepKind.Bits:
            {
                ulong value = (ulong)step.Bits;
                bool ok = batch.SerializeBits64(ref value, step.Width);
                step.Bits = value;
                return ok;
            }

            case StepKind.Bool:
                return batch.SerializeBool(ref step.Boolean);

            case StepKind.UInt128:
            {
                UInt128Value value = step.Bits;
                bool ok = batch.SerializeUInt128(ref value);
                step.Bits = value;
                return ok;
            }

            case StepKind.Align:
                return batch.SerializeAlign();

            case StepKind.Int:
            {
                int value = (int)step.Number;
                bool ok = batch.SerializeInt(ref value, (int)step.Min, (int)step.Max);
                step.Number = value;
                return ok;
            }

            case StepKind.Int64:
            {
                long value = (long)step.Number;
                bool ok = batch.SerializeInt64(ref value, (long)step.Min, (long)step.Max);
                step.Number = value;
                return ok;
            }

            case StepKind.Int128:
            {
                Int128Value value = step.Number;
                bool ok = batch.SerializeInt128(ref value, step.Min, step.Max);
                step.Number = value;
                return ok;
            }

            case StepKind.IntRelative:
            {
                int value = (int)step.Number;
                bool ok = batch.SerializeIntRelative(step.Previous, ref value);
                step.Number = value;
                return ok;
            }

            case StepKind.Float:
            {
                float value = BitConverter.UInt32BitsToSingle((uint)step.Bits);
                bool ok = batch.SerializeFloat(ref value);
                step.Bits = BitConverter.SingleToUInt32Bits(value);
                return ok;
            }

            case StepKind.Double:
            {
                double value = BitConverter.UInt64BitsToDouble((ulong)step.Bits);
                bool ok = batch.SerializeDouble(ref value);
                step.Bits = BitConverter.DoubleToUInt64Bits(value);
                return ok;
            }

            case StepKind.CompressedFloat:
            {
                float value = BitConverter.UInt32BitsToSingle((uint)step.Bits);
                bool ok = batch.SerializeCompressedFloat(ref value, step.FloatMin, step.FloatMax, step.FloatResolution);
                step.Bits = BitConverter.SingleToUInt32Bits(value);
                return ok;
            }

            case StepKind.Bytes:
                return batch.SerializeBytes(step.Buffer);

            case StepKind.String:
                return batch.SerializeString(ref step.Text, step.Width);

            case StepKind.Fixed:
                return RunFixedStepBatch(ref batch, step);

            case StepKind.End:
                return batch.SerializeEnd();

            default:
                return false;
        }
    }

    private static bool RunFixedStepBatch(ref ReadBatch batch, Step step)
    {
        long min = (long)step.Min;
        long max = (long)step.Max;
        switch (step.IntegerBits + step.FractionBits)
        {
            case 16:
            {
                short value = (short)step.Number;
                bool ok = batch.SerializeFixed(ref value, step.IntegerBits, step.FractionBits, min, max);
                step.Number = value;
                return ok;
            }
            case 32:
            {
                int value = (int)step.Number;
                bool ok = batch.SerializeFixed(ref value, step.IntegerBits, step.FractionBits, min, max);
                step.Number = value;
                return ok;
            }
            case 64:
            {
                long value = (long)step.Number;
                bool ok = batch.SerializeFixed(ref value, step.IntegerBits, step.FractionBits, min, max);
                step.Number = value;
                return ok;
            }
            default:
            {
                Int128Value value = step.Number;
                bool ok = batch.SerializeFixed(ref value, step.IntegerBits, step.FractionBits, min, max);
                step.Number = value;
                return ok;
            }
        }
    }

    /*
        Fixed point. Every parameter is a runtime argument of this port's API, so the
        runner needs no table of declarations: the storage width is integer_bits +
        fraction_bits and it selects the overload. A width this port has no overload for
        FAILS rather than passes, and so does a bound outside the long the API takes.

        The raw value travels through the runner as a 128 bit integer whatever the
        declaration's storage width, and is written back whatever the verdict, so a
        refused read that wrote its destination is seen: the refusal check compares it
        against the sentinel narrowed to the storage width (FixedSentinel).
    */
    private static bool RunFixedStep(IBitStream stream, Step step)
    {
        long min = (long)step.Min;
        long max = (long)step.Max;
        switch (step.IntegerBits + step.FractionBits)
        {
            case 16:
            {
                short value = (short)step.Number;
                bool ok = stream.SerializeFixed(ref value, step.IntegerBits, step.FractionBits, min, max);
                step.Number = value;
                return ok;
            }
            case 32:
            {
                int value = (int)step.Number;
                bool ok = stream.SerializeFixed(ref value, step.IntegerBits, step.FractionBits, min, max);
                step.Number = value;
                return ok;
            }
            case 64:
            {
                long value = (long)step.Number;
                bool ok = stream.SerializeFixed(ref value, step.IntegerBits, step.FractionBits, min, max);
                step.Number = value;
                return ok;
            }
            default:
            {
                Int128Value value = step.Number;
                bool ok = stream.SerializeFixed(ref value, step.IntegerBits, step.FractionBits, min, max);
                step.Number = value;
                return ok;
            }
        }
    }

    // the field of a step that holds the value, which is the destination
    // "a refused primitive read must leave its destination unwritten" reaches

    private static bool StepValueIsABitPattern(StepKind kind)
    {
        return kind == StepKind.Bits || kind == StepKind.UInt128 || kind == StepKind.Float
            || kind == StepKind.Double || kind == StepKind.CompressedFloat;
    }

    private static bool StepValueIsANumber(StepKind kind)
    {
        return kind == StepKind.Int || kind == StepKind.Int64 || kind == StepKind.Int128
            || kind == StepKind.IntRelative || kind == StepKind.Fixed;
    }

    // ---------------------------------------------------------------------------------
    // building steps

    private static Step? StepFromWords(ConformanceVector vector, string text)
    {
        string[] words = text.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        if (words.Length == 0)
        {
            return null;
        }

        Step step = new Step();
        switch (words[0])
        {
            case "bits":
                if (words.Length != 2 || !TryParseStepInt(words[1], out step.Width)) return null;
                step.Kind = StepKind.Bits;
                return step;
            case "bool":
                if (words.Length != 1) return null;
                step.Kind = StepKind.Bool;
                return step;
            case "object":
                if (words.Length != 2 || !TryParseStepInt(words[1], out step.Width)) return null;
                step.Kind = StepKind.Object;
                return step;
            case "align":
                if (words.Length != 1) return null;
                step.Kind = StepKind.Align;
                return step;
            case "float":
                if (words.Length != 1) return null;
                step.Kind = StepKind.Float;
                return step;
            case "double":
                if (words.Length != 1) return null;
                step.Kind = StepKind.Double;
                return step;
            case "uint128":
                if (words.Length != 1) return null;
                step.Kind = StepKind.UInt128;
                return step;
            case "int_relative":
                if (words.Length != 2 || !TryParseStepInt(words[1], out step.Previous)) return null;
                step.Kind = StepKind.IntRelative;
                return step;
            case "compressed_float":
                if (words.Length != 4 ||
                    !TryParseStepFloat(words[1], out step.FloatMin) ||
                    !TryParseStepFloat(words[2], out step.FloatMax) ||
                    !TryParseStepFloat(words[3], out step.FloatResolution)) return null;
                step.Kind = StepKind.CompressedFloat;
                return step;
            case "bytes":
                if (words.Length != 2 || !TryParseStepInt(words[1], out step.Width)) return null;
                step.Kind = StepKind.Bytes;
                return step;
            case "string":
                if (words.Length != 2 || !TryParseStepInt(words[1], out step.Width)) return null;
                step.Kind = StepKind.String;
                return step;
            case "end":
                if (words.Length != 1) return null;
                step.Kind = StepKind.End;
                return step;
            case "int":
            case "int64":
            case "int128":
                if (words.Length != 3 ||
                    !TryParseConformanceNumber(words[1], out step.Min) ||
                    !TryParseConformanceNumber(words[2], out step.Max)) return null;
                step.Kind = words[0] == "int" ? StepKind.Int
                    : words[0] == "int64" ? StepKind.Int64 : StepKind.Int128;
                return step;
            case "fixed":
                if (words.Length != 5 ||
                    !TryParseStepInt(words[1], out step.IntegerBits) ||
                    !TryParseStepInt(words[2], out step.FractionBits) ||
                    !TryParseConformanceNumber(words[3], out step.Min) ||
                    !TryParseConformanceNumber(words[4], out step.Max)) return null;
                step.Kind = StepKind.Fixed;
                return CheckFixedDeclaration(vector, step);
            default:
                return null;
        }
    }

    // this port takes the Q format as runtime arguments, so the only declarations it
    // cannot drive are a storage width it has no overload for and a bound wider than the
    // long the API takes. Either FAILS rather than passes.
    private static Step? CheckFixedDeclaration(ConformanceVector vector, Step step)
    {
        int storageBits = step.IntegerBits + step.FractionBits;
        if (storageBits != 16 && storageBits != 32 && storageBits != 64 && storageBits != 128)
        {
            ConformanceFail(vector,
                $"no runner for a fixed point storage width of {storageBits} bits");
            return null;
        }
        if (step.Min != (Int128Value)(long)step.Min || step.Max != (Int128Value)(long)step.Max)
        {
            ConformanceFail(vector, "no runner for a fixed point bound outside the signed 64 bit domain");
            return null;
        }
        return step;
    }

    /*
        Builds the step list for a vector. A single operation vector becomes a one or two
        step sequence: the operations whose interesting behavior only exists at a non-zero
        bit index take a `preceding_bits` parameter, which becomes a leading bits step.
    */
    private static List<Step>? BuildSteps(ConformanceVector vector)
    {
        List<Step> steps = new List<Step>();

        if (vector.Operation == "sequence")
        {
            foreach (string text in vector.StepText)
            {
                Step? parsed = StepFromWords(vector, text);
                if (parsed == null)
                {
                    return null;
                }
                steps.Add(parsed);
            }
            return steps.Count > 0 ? steps : null;
        }

        if (TryConformanceParamInt(vector, "preceding_bits", out int precedingBits) && precedingBits > 0)
        {
            steps.Add(new Step { Kind = StepKind.Bits, Width = precedingBits });
        }

        Step step = new Step();
        switch (vector.Operation)
        {
            case "bits":
                if (!TryConformanceParamInt(vector, "bits", out step.Width)) return null;
                step.Kind = StepKind.Bits;
                break;
            case "bool":
                step.Kind = StepKind.Bool;
                break;
            case "uint128":
                step.Kind = StepKind.UInt128;
                break;
            case "align":
                step.Kind = StepKind.Align;
                break;
            case "int":
                if (!TryConformanceParamNumber(vector, "min", out step.Min) ||
                    !TryConformanceParamNumber(vector, "max", out step.Max)) return null;
                step.Kind = StepKind.Int;
                break;
            case "int64":
                if (!TryConformanceParamNumber(vector, "min", out step.Min) ||
                    !TryConformanceParamNumber(vector, "max", out step.Max)) return null;
                step.Kind = StepKind.Int64;
                break;
            case "int128":
                if (!TryConformanceParamNumber(vector, "min", out step.Min) ||
                    !TryConformanceParamNumber(vector, "max", out step.Max)) return null;
                step.Kind = StepKind.Int128;
                break;
            case "int_relative":
                if (!TryConformanceParamInt(vector, "previous", out step.Previous)) return null;
                step.Kind = StepKind.IntRelative;
                break;
            case "float":
                step.Kind = StepKind.Float;
                break;
            case "double":
                step.Kind = StepKind.Double;
                break;
            case "compressed_float":
                if (!TryConformanceParamFloat(vector, "min", out step.FloatMin) ||
                    !TryConformanceParamFloat(vector, "max", out step.FloatMax) ||
                    !TryConformanceParamFloat(vector, "res", out step.FloatResolution)) return null;
                step.Kind = StepKind.CompressedFloat;
                break;
            case "bytes":
                if (!TryConformanceParamInt(vector, "count", out step.Width)) return null;
                step.Kind = StepKind.Bytes;
                break;
            case "string":
                if (!TryConformanceParamInt(vector, "buffer_size", out step.Width)) return null;
                step.Kind = StepKind.String;
                break;
            case "end":
                step.Kind = StepKind.End;
                break;
            case "fixed":
                if (!TryConformanceParamInt(vector, "integer_bits", out step.IntegerBits) ||
                    !TryConformanceParamInt(vector, "fraction_bits", out step.FractionBits) ||
                    !TryConformanceParamNumber(vector, "min", out step.Min) ||
                    !TryConformanceParamNumber(vector, "max", out step.Max)) return null;
                step.Kind = StepKind.Fixed;
                if (CheckFixedDeclaration(vector, step) == null) return null;
                break;
            default:
                return null;
        }

        steps.Add(step);
        return steps;
    }

    /*
        A parameter this runner does not understand is a FAILURE and not a silent default:
        a vector whose declaration is not the one being exercised proves nothing, and a
        corpus that grows a parameter must grow a runner to read it. Each operation states
        the parameters it consumes.
    */
    private static bool OperationTakesParam(string operation, string name)
    {
        switch (name)
        {
            case "step": return operation == "sequence";
            case "preceding_bits": return operation == "align" || operation == "bytes";
            case "bits": return operation == "bits";
            case "count": return operation == "bytes";
            case "buffer_size": return operation == "string";
            case "previous": return operation == "int_relative";
            case "res": return operation == "compressed_float";
            case "integer_bits":
            case "fraction_bits": return operation == "fixed";
            case "min":
            case "max":
                return operation == "int" || operation == "int64" || operation == "int128"
                    || operation == "fixed" || operation == "compressed_float";
            default: return false;
        }
    }

    // ---------------------------------------------------------------------------------
    // expectations

    /*
        Renders a step's decoded value for a failure message, and decides whether it
        matches the corpus.

        Numeric values — every integer width, and the float, double and compressed_float
        bit patterns — are compared as 128 bit PATTERNS: the step's value is taken as its
        two's complement 128 bit form and the corpus expectation is parsed to the same
        form, so a hexadecimal expectation and its decimal twin are one expectation, and
        NOTHING here goes through a float. That last part is the document's requirement,
        not a convenience: STANDARD.md says conformance vectors for float and double
        "must compare BIT PATTERNS, NOT VALUES: NaN compares unequal to itself,
        -0.0 == 0.0, and a tolerance comparison cannot see a quieted signaling bit, so a
        value-space comparison here proves nothing."

        The remaining kinds have textual spellings the corpus states directly: `true` or
        `false`, and hexadecimal byte pairs for bytes and string payloads.
    */
    private static bool TryStepPattern(Step step, out UInt128Value pattern)
    {
        if (StepValueIsABitPattern(step.Kind))
        {
            pattern = step.Bits;
            return true;
        }
        if (StepValueIsANumber(step.Kind))
        {
            pattern = (UInt128Value)step.Number;
            return true;
        }
        pattern = UInt128Value.Zero;
        return false;
    }

    private static bool ExpectationMatches(Step step, string expected)
    {
        if (TryStepPattern(step, out UInt128Value pattern))
        {
            if (!TryParseConformanceNumber(expected, out Int128Value wanted))
            {
                return false;
            }
            return pattern == (UInt128Value)wanted;
        }
        return RenderStepValue(step) == expected;
    }

    private static string RenderStepValue(Step step)
    {
        if (TryStepPattern(step, out UInt128Value pattern))
        {
            return $"0x{pattern.Hi:X16}{pattern.Lo:X16}";
        }

        switch (step.Kind)
        {
            case StepKind.Object:
            case StepKind.Align:
            case StepKind.End:
                // none has a value of its own; for align and end the corpus states the
                // padding consumed, which a conforming read always finds zero
                return "0";

            case StepKind.Bool:
                return step.Boolean ? "true" : "false";

            case StepKind.Bytes:
                return BytesToHex(step.Buffer);

            case StepKind.String:
                return BytesToHex(Encoding.UTF8.GetBytes(step.Text));

            default:
                return "?";
        }
    }

    private static string BytesToHex(ReadOnlySpan<byte> data)
    {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < data.Length; i++)
        {
            if (i > 0)
            {
                builder.Append(' ');
            }
            builder.Append(data[i].ToString("X2", CultureInfo.InvariantCulture));
        }
        return builder.ToString();
    }

    // splits an expect list into per step entries, on "|"
    private static string[] SplitExpect(string text)
    {
        string[] entries = text.Split('|');
        for (int i = 0; i < entries.Length; i++)
        {
            entries[i] = entries[i].Trim();
        }
        return entries;
    }

    // ---------------------------------------------------------------------------------
    // parameters and numbers

    private static string? ConformanceParam(ConformanceVector vector, string name)
    {
        foreach (KeyValuePair<string, string> param in vector.Params)
        {
            if (param.Key == name)
            {
                return param.Value;
            }
        }
        return null;
    }

    private static bool TryConformanceParamNumber(ConformanceVector vector, string name, out Int128Value value)
    {
        string? text = ConformanceParam(vector, name);
        if (text == null)
        {
            value = Int128Value.Zero;
            return false;
        }
        return TryParseConformanceNumber(text, out value);
    }

    private static bool TryConformanceParamInt(ConformanceVector vector, string name, out int value)
    {
        value = 0;
        if (!TryConformanceParamNumber(vector, name, out Int128Value wide))
        {
            return false;
        }
        // a number that does not fit the int the API takes is not this parameter
        if (wide < (Int128Value)int.MinValue || wide > (Int128Value)int.MaxValue)
        {
            return false;
        }
        value = (int)wide;
        return true;
    }

    private static bool TryConformanceParamFloat(ConformanceVector vector, string name, out float value)
    {
        value = 0.0f;
        string? text = ConformanceParam(vector, name);
        if (text == null)
        {
            return false;
        }
        return float.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out value);
    }

    private static bool TryParseStepFloat(string text, out float value)
    {
        return float.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out value);
    }

    private static bool TryParseStepInt(string text, out int value)
    {
        value = 0;
        if (!TryParseConformanceNumber(text, out Int128Value wide))
        {
            return false;
        }
        // a number that does not fit the int the API takes is not this parameter
        if (wide < (Int128Value)int.MinValue || wide > (Int128Value)int.MaxValue)
        {
            return false;
        }
        value = (int)wide;
        return true;
    }

    /*
        Numbers in a vector are signed decimal or 0x hexadecimal, parsed to 128 bits,
        because a vector's value can be wider than any built in parse and the corpus states
        wide bounds as hexadecimal where the decimal would be unreadable.

        The accumulation runs in the UNSIGNED domain and the sign is applied there too. The
        corpus states 128 bit bounds at both extremes — the full signed range's minimum,
        and the unsigned maximum as a decimal — and the two's complement reading happens
        once, at the end.
    */
    private static bool TryParseConformanceNumber(string text, out Int128Value result)
    {
        result = Int128Value.Zero;
        if (text.Length == 0)
        {
            return false;
        }

        int index = 0;
        bool negative = false;
        if (text[0] == '-')
        {
            negative = true;
            index = 1;
        }
        else if (text[0] == '+')
        {
            index = 1;
        }
        if (index >= text.Length)
        {
            return false;
        }

        UInt128Value value = UInt128Value.Zero;
        if (index + 1 < text.Length && text[index] == '0' && (text[index + 1] == 'x' || text[index + 1] == 'X'))
        {
            index += 2;
            if (index >= text.Length)
            {
                return false;
            }
            for (; index < text.Length; index++)
            {
                int digit = HexDigit(text[index]);
                if (digit < 0)
                {
                    return false;
                }
                value = value * 16 + (uint)digit;
            }
        }
        else
        {
            for (; index < text.Length; index++)
            {
                if (text[index] < '0' || text[index] > '9')
                {
                    return false;
                }
                value = value * 10 + (uint)(text[index] - '0');
            }
        }

        if (negative)
        {
            value = UInt128Value.Zero - value;
        }
        result = (Int128Value)value;
        return true;
    }

    private static int HexDigit(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    }

    // ---------------------------------------------------------------------------------
    // the corpus files

    private const string ConformanceResourcePrefix = "conformance/";
    private const string ControlResourcePrefix = "conformance-controls/";

    // Every .txt resource embedded from conformance/ (see Tests.csproj and
    // TestsNs21.csproj), which is a glob MSBuild re-evaluates, so a vector added upstream
    // and copied across runs without a code change. A runner holding a list of file names
    // in its source is non conforming.
    private static List<ConformanceVector> LoadConformanceVectors()
    {
        List<ConformanceVector> vectors = new List<ConformanceVector>();
        foreach (string resource in typeof(Program).Assembly.GetManifestResourceNames())
        {
            if (resource.StartsWith(ConformanceResourcePrefix, StringComparison.Ordinal)
                && resource.EndsWith(".txt", StringComparison.Ordinal))
            {
                ParseConformanceFile(resource, ReadConformanceResource(resource), vectors);
            }
        }
        return vectors;
    }

    private static string ReadConformanceResource(string resource)
    {
        using (Stream? stream = typeof(Program).Assembly.GetManifestResourceStream(resource))
        {
            Check(stream != null, $"conformance resource {resource} would not open");
            using (StreamReader reader = new StreamReader(stream!))
            {
                return reader.ReadToEnd();
            }
        }
    }

    // STANDARD.md, "Refusal reasons": the closed list, as SerializeUtil.RefusalName
    // spells it. A refused record must name one of these.
    private static bool IsRefusalName(string reason)
    {
        foreach (SerializeError error in Enum.GetValues(typeof(SerializeError)))
        {
            if (error != SerializeError.None && SerializeUtil.RefusalName(error) == reason)
            {
                return true;
            }
        }
        return false;
    }

    // STANDARD.md, "The vector format": `#` begins a comment at the START of a line and
    // nowhere else, records are separated by blank lines, and each line is a key and a
    // value, with `param` repeated once per parameter.
    private static void ParseConformanceFile(string source, string text, List<ConformanceVector> vectors)
    {
        ConformanceVector? vector = null;
        foreach (string rawLine in text.Split('\n'))
        {
            if (rawLine.Length > 0 && rawLine[0] == '#')
            {
                continue;
            }
            string line = rawLine.Trim();
            if (line.Length == 0)
            {
                vector = null;
                continue;
            }

            int space = line.IndexOf(' ');
            string key = space < 0 ? line : line.Substring(0, space);
            string value = space < 0 ? "" : line.Substring(space + 1).Trim();

            if (vector == null)
            {
                vector = new ConformanceVector { Source = source };
                vectors.Add(vector);
            }

            switch (key)
            {
                case "operation":
                    vector.Operation = value;
                    break;
                case "name":
                    vector.Name = value;
                    break;
                case "param":
                {
                    KeyValuePair<string, string> param = ParseConformanceParam(source, value);
                    if (param.Key == "step")
                    {
                        vector.StepText.Add(param.Value);
                    }
                    else
                    {
                        vector.Params.Add(param);
                    }
                    break;
                }
                case "bytes":
                    vector.Bytes = ParseConformanceBytes(source, value);
                    break;
                case "expect":
                    if (value == "refused" || value.StartsWith("refused ", StringComparison.Ordinal))
                    {
                        // `expect refused <reason>`: a missing or unknown reason makes the
                        // record malformed, which fails the vector rather than skipping it
                        vector.Expect = ConformanceExpect.Refused;
                        string reason = value.Substring("refused".Length).Trim();
                        if (reason.Length == 0)
                        {
                            vector.Malformed = "`expect refused` states no reason";
                        }
                        else if (!IsRefusalName(reason))
                        {
                            vector.Malformed = $"`expect refused` states \"{reason}\", which is not a refusal reason";
                        }
                        else
                        {
                            vector.ExpectedReason = reason;
                        }
                    }
                    else
                    {
                        KeyValuePair<string, string> expect = ParseConformanceParam(source, value);
                        Check(expect.Key == "value" || expect.Key == "bits",
                            $"{source}: unknown expect kind \"{expect.Key}\"");
                        vector.Expect = expect.Key == "bits" ? ConformanceExpect.Bits : ConformanceExpect.Value;
                        vector.ExpectedValue = expect.Value;
                    }
                    break;
                case "consumed":
                    vector.Consumed = long.Parse(value, CultureInfo.InvariantCulture);
                    vector.HasConsumed = true;
                    break;
                case "measure_at_least":
                    vector.MeasureAtLeast = long.Parse(value, CultureInfo.InvariantCulture);
                    vector.HasMeasure = true;
                    break;
                case "writer":
                    Check(value == "canonical", $"{source}: unknown writer mode \"{value}\"");
                    vector.WriterCanonical = true;
                    break;
                case "writer_input":
                {
                    // `writer_input bits = 0x...`, a float32 pattern handed to the writer
                    KeyValuePair<string, string> input = ParseConformanceParam(source, value);
                    if (input.Key != "bits"
                        || !TryParseConformanceNumber(input.Value, out Int128Value pattern)
                        || pattern < Int128Value.Zero || pattern > (Int128Value)uint.MaxValue)
                    {
                        vector.Malformed = $"writer_input \"{value}\" is not bits = a float32 pattern";
                    }
                    else
                    {
                        vector.HasWriterInput = true;
                        vector.WriterInput = (uint)pattern;
                    }
                    break;
                }
                default:
                    Check(false, $"{source}: unknown vector key \"{key}\"");
                    break;
            }
        }
    }

    // `name = value`, the shape of a `param` line and of an accepted `expect` line
    private static KeyValuePair<string, string> ParseConformanceParam(string source, string text)
    {
        int equals = text.IndexOf('=');
        Check(equals > 0, $"{source}: \"{text}\" is not name = value");
        return new KeyValuePair<string, string>(
            text.Substring(0, equals).Trim(), text.Substring(equals + 1).Trim());
    }

    // hexadecimal byte pairs, empty for a zero-bit read
    private static byte[] ParseConformanceBytes(string source, string text)
    {
        string[] fields = text.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        byte[] bytes = new byte[fields.Length];
        for (int i = 0; i < fields.Length; i++)
        {
            Check(byte.TryParse(fields[i], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out bytes[i]),
                $"{source}: \"{text}\" is not a run of hexadecimal byte pairs");
        }
        return bytes;
    }
}
