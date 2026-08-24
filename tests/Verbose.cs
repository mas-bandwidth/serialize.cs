/*
    Verbose.cs

    Is informational narration wanted?

    Under a passing test the suite prints each test's name and nothing else. The
    informational narration -- check counts, negative-control statistics, skip
    reasons, which arithmetic discipline this runtime exercised -- is opt-in: set
    SERIALIZE_TEST_VERBOSE=1 in the environment to restore it. Failures print
    everything relevant regardless, and no check runs or does not run because of
    this switch: it gates narration only.

    Same variable name and same semantics as the C and C++ serialize suites,
    deliberately, so one environment variable covers the whole family.

    It matters more here than it looks. This runner is a plain console
    executable with no test framework capturing output, so every line written
    goes straight to the terminal, and tests-ns21 compiles these same sources
    again, so CI printed all of it twice.
*/

using System;

namespace Serialize.Tests;

internal static class Verbose
{
    private static readonly bool s_wanted = Wanted();

    internal static bool Enabled => s_wanted;

    private static bool Wanted()
    {
        string? value = Environment.GetEnvironmentVariable("SERIALIZE_TEST_VERBOSE");
        return !string.IsNullOrEmpty(value) && value != "0";
    }
}
