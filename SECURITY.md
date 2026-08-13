# Security Policy

serialize.cs is a bitpacking serialization library. Its read path consumes buffers that
in practice arrive from the network, so a malformed or hostile stream must not be able to
read out of bounds, allocate without bound, or throw where the caller expected a clean
failure.

## Reporting a vulnerability

**Please do not report security issues in public GitHub issues or pull requests.**

Report privately through either channel:

- **GitHub private vulnerability reporting** (preferred): on this repository, go to the
  **Security** tab → **Report a vulnerability**. This opens a private advisory visible
  only to the maintainers.
- **Email**: glenn@mas-bandwidth.com.

Please include enough detail to reproduce: the affected version or commit, a description
of the flaw, and — where possible — a proof-of-concept buffer or a small patch. Fuzzing
crash artifacts are ideal.

We will acknowledge your report, keep you updated on our assessment, and coordinate
disclosure timing with you. We prefer coordinated disclosure and will credit reporters
who wish to be named.

## Scope

In scope — bugs in the library itself (the sources under `src/`).

Especially of interest, in the read path reachable from a hostile buffer:

- **Out-of-bounds reads** past the end of a stream.
- **Integer overflow** in bit or byte counts, particularly where a count derived from
  wire data feeds an index or a length calculation.
- **Unbounded allocation** — any way for a serialized length or array count to drive an
  allocation without first being bounds-checked against what remains in the buffer. In a
  managed runtime this is the likeliest way a hostile packet does damage: not memory
  corruption, but a length prefix that turns into a multi-gigabyte array.
- **An exception escaping the read path.** The library's contract is that malicious
  packet data never throws — a bad stream fails cleanly through the sticky latched
  error, and exceptions are reserved for API misuse by the caller. A hostile buffer that
  produces an exception breaks that contract and is a bug worth reporting even though a
  managed exception is not memory-unsafe, because callers are entitled to write their
  packet loop without a catch block.
- **Divergence from the C++, Go or Rust ports** on the same input. The four are meant to
  be bit-identical; if this one accepts a stream another refuses, that is a security bug
  in a deployment that mixes languages across client and server, which is the normal
  case.

## Out of scope

- **Transport-level concerns.** This is a wire-format library, not a transport. Replay,
  spoofing, amplification, rate limiting and authentication belong to the layer above.
- **Confidentiality.** The library performs no encryption and no authentication. It is
  normally used underneath a layer that authenticates. That does not put the items above
  out of scope — a stream is only trustworthy if the layer above actually verified it,
  and we would rather serialize.cs be safe on its own.
- **Write-side misuse.** Writing a value outside its declared range is a caller bug.

## Supported versions

The latest tagged release is supported. There are no long-term support branches; a fix
lands on `main` and in the next tag.
