/*
    Conformance.cs

    The shared conformance corpus, run through this port's reader.

    conformance/ is vendored verbatim from mas-bandwidth/serialize beside STANDARD.md,
    and CI fails when either drifts. The corpus is the normative instrument: it holds
    the accepted and refused vectors the standard's rules require, written once for
    every implementation, so no port checks its codec against its own regenerated
    expectations (STANDARD.md, "The shared corpus is the conformance instrument").

    Every vector file embedded in the test assembly runs here. An operation this file
    does not know is a FAILURE, never a skip: an operation the corpus covers and this
    port does not implement is a gap, and a silent skip is how it would stay one.

    Accepted vectors must yield the stated value and consume the stated bit count.
    Refused vectors must be refused, and must leave the destination exactly as the
    caller left it — the non-mutation rule under Reader Obligations. After a refusal
    the stream position is not part of the contract, so nothing here checks it.
*/

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;

namespace Serialize.Tests;

internal static partial class Program
{
    // a destination value no accepted vector can produce: negative, so it is outside
    // the int_relative domain, and far from any 128 bit bound the corpus declares.
    // A refused read that leaves this in place has written nothing.
    private const int ConformanceSentinel = unchecked((int)0xDEADBEEF);

    private sealed class ConformanceVector
    {
        public string Source = "";
        public string Operation = "";
        public string Name = "";
        public List<KeyValuePair<string, string>> Params = new List<KeyValuePair<string, string>>();
        public byte[] Bytes = Array.Empty<byte>();
        public bool Refused;
        public string ExpectedValue = "";
        public int Consumed = -1;

        public string Label => $"{Source}:{Name}";
    }

    private static void TestConformanceVectors()
    {
        List<ConformanceVector> vectors = LoadConformanceVectors();
        Check(vectors.Count > 0,
            "no conformance vectors were embedded: conformance/ is missing from the test assembly");

        int failures = 0;
        foreach (ConformanceVector vector in vectors)
        {
            if (!RunConformanceVector(vector))
            {
                failures++;
            }
        }

        Check(failures == 0, $"{failures} of {vectors.Count} conformance vectors failed");

        if (Verbose.Enabled)
        {
            Console.WriteLine($"    {vectors.Count} conformance vectors passed");
        }
    }

    // returns false and prints why on failure, so one run reports every red vector
    // instead of stopping at the first
    private static bool RunConformanceVector(ConformanceVector vector)
    {
        switch (vector.Operation)
        {
            case "int_relative": return RunIntRelativeVector(vector);
            case "int128": return RunInt128Vector(vector);
            default:
                Console.Error.WriteLine(
                    $"    {vector.Label}: operation \"{vector.Operation}\" is in the corpus and not implemented here");
                return false;
        }
    }

    private static bool RunIntRelativeVector(ConformanceVector vector)
    {
        int previous = int.Parse(ConformanceParam(vector, "previous"), CultureInfo.InvariantCulture);
        ReadStream stream = new ReadStream(vector.Bytes);
        int current = ConformanceSentinel;
        bool ok = stream.SerializeIntRelative(previous, ref current);

        if (vector.Refused)
        {
            return CheckRefused(vector, ok, current == ConformanceSentinel, current.ToString(CultureInfo.InvariantCulture), stream);
        }

        int expected = int.Parse(vector.ExpectedValue, CultureInfo.InvariantCulture);
        return CheckAccepted(vector, ok, current == expected, current.ToString(CultureInfo.InvariantCulture), stream);
    }

    private static bool RunInt128Vector(ConformanceVector vector)
    {
        Int128Value min = ParseInt128(ConformanceParam(vector, "min"));
        Int128Value max = ParseInt128(ConformanceParam(vector, "max"));
        ReadStream stream = new ReadStream(vector.Bytes);
        Int128Value sentinel = ConformanceSentinel;
        Int128Value value = sentinel;
        bool ok = stream.SerializeInt128(ref value, min, max);

        if (vector.Refused)
        {
            return CheckRefused(vector, ok, value == sentinel, value.ToString(), stream);
        }

        Int128Value expected = ParseInt128(vector.ExpectedValue);
        return CheckAccepted(vector, ok, value == expected, value.ToString(), stream);
    }

    private static bool CheckAccepted(ConformanceVector vector, bool ok, bool valueMatches, string got, ReadStream stream)
    {
        if (!ok)
        {
            Console.Error.WriteLine($"    {vector.Label}: expected the read to be accepted, it was refused with {stream.Error}");
            return false;
        }
        if (!valueMatches)
        {
            Console.Error.WriteLine($"    {vector.Label}: expected value {vector.ExpectedValue}, got {got}");
            return false;
        }
        if (stream.BitsProcessed != vector.Consumed)
        {
            Console.Error.WriteLine($"    {vector.Label}: expected {vector.Consumed} bits consumed, got {stream.BitsProcessed}");
            return false;
        }
        return true;
    }

    private static bool CheckRefused(ConformanceVector vector, bool ok, bool destinationUnwritten, string got, ReadStream stream)
    {
        if (ok)
        {
            Console.Error.WriteLine($"    {vector.Label}: expected the read to be refused, it was accepted with {got}");
            return false;
        }
        if (stream.Error == SerializeError.None)
        {
            Console.Error.WriteLine($"    {vector.Label}: the read was refused without latching an error");
            return false;
        }
        if (!destinationUnwritten)
        {
            Console.Error.WriteLine($"    {vector.Label}: a refused read wrote {got} to the destination");
            return false;
        }
        return true;
    }

    private static string ConformanceParam(ConformanceVector vector, string name)
    {
        foreach (KeyValuePair<string, string> param in vector.Params)
        {
            if (param.Key == name)
            {
                return param.Value;
            }
        }
        Check(false, $"{vector.Label}: the vector has no \"{name}\" parameter");
        return "";
    }

    // decimal text to the emulated 128 bit pair. The corpus states 128 bit bounds in
    // decimal and nothing in the library parses them: the pair carries wire arithmetic
    // only, deliberately.
    private static Int128Value ParseInt128(string text)
    {
        bool negative = text.Length > 0 && text[0] == '-';
        string digits = negative ? text.Substring(1) : text;
        Check(digits.Length > 0, $"\"{text}\" is not a 128 bit decimal integer");

        UInt128Value magnitude = UInt128Value.Zero;
        foreach (char c in digits)
        {
            Check(c >= '0' && c <= '9', $"\"{text}\" is not a 128 bit decimal integer");
            magnitude = magnitude * 10 + (uint)(c - '0');
        }

        Int128Value value = (Int128Value)magnitude;
        return negative ? -value : value;
    }

    // Every .txt resource embedded from conformance/ (see Tests.csproj), parsed per
    // STANDARD.md, "The vector format": # comments, blank lines between records, one
    // key and value per line, `param` repeated once per parameter.
    private static List<ConformanceVector> LoadConformanceVectors()
    {
        List<ConformanceVector> vectors = new List<ConformanceVector>();
        Assembly assembly = typeof(Program).Assembly;
        foreach (string resource in assembly.GetManifestResourceNames())
        {
            if (!resource.EndsWith(".txt", StringComparison.Ordinal))
            {
                continue;
            }
            using (Stream? stream = assembly.GetManifestResourceStream(resource))
            {
                Check(stream != null, $"conformance resource {resource} would not open");
                using (StreamReader reader = new StreamReader(stream!))
                {
                    ParseConformanceFile(resource, reader.ReadToEnd(), vectors);
                }
            }
        }
        return vectors;
    }

    private static void ParseConformanceFile(string source, string text, List<ConformanceVector> vectors)
    {
        ConformanceVector? vector = null;
        foreach (string rawLine in text.Split('\n'))
        {
            string line = rawLine.Trim();
            if (line.Length == 0)
            {
                vector = null;
                continue;
            }
            if (line[0] == '#')
            {
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
                    vector.Params.Add(ParseConformanceParam(source, value));
                    break;
                case "bytes":
                    vector.Bytes = ParseConformanceBytes(value);
                    break;
                case "expect":
                    if (value == "refused")
                    {
                        vector.Refused = true;
                    }
                    else
                    {
                        vector.ExpectedValue = ParseConformanceParam(source, value).Value;
                    }
                    break;
                case "consumed":
                    vector.Consumed = int.Parse(value, CultureInfo.InvariantCulture);
                    break;
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

    // hexadecimal byte pairs, empty for a zero-bit read. The array is sized exactly to
    // the vector, with no slack past the data, so the vectors exercise the reader's
    // no-slack window path as well as its arithmetic.
    private static byte[] ParseConformanceBytes(string text)
    {
        string[] fields = text.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        byte[] bytes = new byte[fields.Length];
        for (int i = 0; i < fields.Length; i++)
        {
            bytes[i] = byte.Parse(fields[i], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }
        return bytes;
    }
}
