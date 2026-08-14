/*
    The C++ half of the cross language wire compatibility harness. Its C# twin is
    ../Compat.cs; the interop gate runs both against each other: each side writes its
    stream to a file, the two files must be byte identical, and each side must read the
    other's file back to the exact values.

    Build against the real C++ serialize.h (the single source of truth for the wire
    format), e.g. against a sibling clone of github.com/mas-bandwidth/serialize:

        clang++ -O2 -std=c++17 -ffp-contract=off -Wall -I ../../../serialize -o compat compat.cpp
        ./compat write cpp.bin && ./compat read cpp.bin

    -ffp-contract=off is REQUIRED: strict IEEE evaluation is the normative wire.
    Default clang/gcc on ARM64 contract the compressed float quantization
    (normalized * maxInteger + 0.5f) into a fused multiply-add, which rounds
    differently within 1 ULP of a .5 boundary and shifts the written integer by one
    wire quantum. C# (and the Rust port) always evaluate strictly; the fmaBoundaryFloat
    value below sits exactly on such a boundary so a contracted build fails the gate
    instead of passing it silently.

    Build with asserts ON (no -DNDEBUG): they are the C++ end of the family rule that
    API misuse is loud (exceptions in C#, serialize_assert here), and the degenerate
    range below must pass with them enabled rather than around them. That
    is also why the interop gate needs a serialize.h of v1.6.2 or newer: up to and
    including v1.4.3 the library asserted min < max, so an assert-enabled build aborts
    on the degenerate field. See ../../scripts/interop.sh.

    This file is adapted from the Go port's compat/cpp/compat.cpp (the extended golden
    sequence: golden wire values plus the 64 bit paths). Any change to the value
    sequence must be mirrored in ../Compat.cs, and never changes the wire format.
*/

#include "serialize.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

struct CompatData
{
    uint32_t bits4;
    uint32_t bits11;
    uint32_t bits24;
    uint32_t bits32;
    int32_t intSmall;
    int32_t intFull;
    int32_t degenerate;
    bool flag;
    float floatValue;
    float compressedFloatValue;
    double doubleValue;
    uint8_t uint8Value;
    uint16_t uint16Value;
    uint32_t uint32Value;
    uint64_t uint64Value;
    int32_t relativeNear;
    int32_t relativeFar;
    uint8_t bytes[7];
    char str[16];
    wchar_t wstr[8];
    uint64_t bits33;
    int64_t int64Full;
    int64_t int64Range;
    float fmaBoundaryFloat;

    void Init()
    {
        memset( this, 0, sizeof( *this ) );
        bits4 = 13;
        bits11 = 1445;
        bits24 = 11259375;
        bits32 = 0xDEADBEEF;
        intSmall = -37;
        intFull = -123456789;
        degenerate = 42;                        // min == max: known from the range alone, zero bits on the wire
        flag = true;
        floatValue = 3.1415926f;
        compressedFloatValue = 5.0f;            // 5.0 in [0,10] normalizes to exactly 0.5: quantizes identically everywhere
        doubleValue = 1.0 / 3.0;
        uint8Value = 0x7F;
        uint16Value = 0x1234;
        uint32Value = 0x12345678;
        uint64Value = 0x123456789ABCDEF0ULL;
        relativeNear = 101;                     // difference of 1 from the base: exercises the one bit branch
        relativeFar = 2100;                     // difference of 2000 from the base: exercises the twelve bit bucket
        const uint8_t bytesInit[7] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x01 };
        memcpy( bytes, bytesInit, sizeof( bytes ) );
        strcpy( str, "golden" );
        wstr[0] = (wchar_t) 0x043C;             // "мир": cyrillic, BMP only, explicit code points
        wstr[1] = (wchar_t) 0x0438;
        wstr[2] = (wchar_t) 0x0440;
        wstr[3] = 0;
        bits33 = 0x1DEADBEEFULL;
        int64Full = -123456789012345LL;
        int64Range = 4123456789LL;
        fmaBoundaryFloat = 0.005f;              // t = 1.0f quantization boundary: strict evaluation writes 1, a fused build writes 0
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        const int32_t relativeBase = 100;
        serialize_bits( stream, bits4, 4 );
        serialize_bits( stream, bits11, 11 );
        serialize_bits( stream, bits24, 24 );
        serialize_bits( stream, bits32, 32 );
        serialize_int( stream, intSmall, -100, +100 );
        serialize_int( stream, intFull, INT32_MIN, INT32_MAX );
        serialize_int( stream, degenerate, 42, 42 );    // the degenerate range: zero bits, and every field below must stay put
        serialize_bool( stream, flag );
        serialize_float( stream, floatValue );
        serialize_compressed_float( stream, compressedFloatValue, 0.0f, 10.0f, 0.01f );
        serialize_double( stream, doubleValue );
        serialize_uint8( stream, uint8Value );
        serialize_uint16( stream, uint16Value );
        serialize_uint32( stream, uint32Value );
        serialize_uint64( stream, uint64Value );
        serialize_int_relative( stream, relativeBase, relativeNear );
        serialize_int_relative( stream, relativeBase, relativeFar );
        serialize_align( stream );
        serialize_bytes( stream, bytes, sizeof( bytes ) );
        serialize_string( stream, str, sizeof( str ) );
        serialize_wstring( stream, wstr, sizeof( wstr ) / sizeof( wstr[0] ) );
        serialize_bits( stream, bits33, 33 );
        serialize_int64( stream, int64Full, INT64_MIN, INT64_MAX );
        serialize_int64( stream, int64Range, -5000000000LL, +5000000000LL );
        serialize_compressed_float( stream, fmaBoundaryFloat, 0.0f, 10.0f, 0.01f );
        return true;
    }

    bool Equals( const CompatData & other ) const
    {
        return bits4 == other.bits4
            && bits11 == other.bits11
            && bits24 == other.bits24
            && bits32 == other.bits32
            && intSmall == other.intSmall
            && intFull == other.intFull
            && degenerate == other.degenerate
            && flag == other.flag
            && floatValue == other.floatValue
            && compressedFloatValue == other.compressedFloatValue
            && doubleValue == other.doubleValue
            && uint8Value == other.uint8Value
            && uint16Value == other.uint16Value
            && uint32Value == other.uint32Value
            && uint64Value == other.uint64Value
            && relativeNear == other.relativeNear
            && relativeFar == other.relativeFar
            && memcmp( bytes, other.bytes, sizeof( bytes ) ) == 0
            && strcmp( str, other.str ) == 0
            && wcscmp( wstr, other.wstr ) == 0
            && bits33 == other.bits33
            && int64Full == other.int64Full
            && int64Range == other.int64Range
            && fabsf( fmaBoundaryFloat - other.fmaBoundaryFloat ) <= 0.01f;   // within the resolution: 0.005 decodes to 0.01
    }
};

static uint8_t g_buffer[256 + 8];               // + 8: the C++ bit reader window loads may extend past the data

static int Write( const char * path )
{
    CompatData data;
    data.Init();

    serialize::WriteStream stream( g_buffer, 256 );
    if ( !data.Serialize( stream ) )
    {
        fprintf( stderr, "compat cpp write: serialize failed\n" );
        return 1;
    }
    stream.Flush();

    FILE * file = fopen( path, "wb" );
    if ( !file )
    {
        fprintf( stderr, "compat cpp write: could not open %s\n", path );
        return 1;
    }
    const size_t bytes = (size_t) stream.GetBytesProcessed();
    if ( fwrite( g_buffer, 1, bytes, file ) != bytes )
    {
        fprintf( stderr, "compat cpp write: short write to %s\n", path );
        fclose( file );
        return 1;
    }
    fclose( file );

    printf( "compat cpp write ok\n" );
    return 0;
}

static int Read( const char * path )
{
    FILE * file = fopen( path, "rb" );
    if ( !file )
    {
        fprintf( stderr, "compat cpp read: could not open %s\n", path );
        return 1;
    }
    const size_t bytes = fread( g_buffer, 1, 256, file );
    fclose( file );
    if ( bytes == 0 || bytes >= 256 )
    {
        fprintf( stderr, "compat cpp read: unexpected packet size %zu\n", bytes );
        return 1;
    }

    serialize::ReadStream stream( g_buffer, (int) bytes );
    CompatData data;
    memset( &data, 0, sizeof( data ) );
    if ( !data.Serialize( stream ) )
    {
        fprintf( stderr, "compat cpp read: serialize failed\n" );
        return 1;
    }

    CompatData expected;
    expected.Init();
    if ( !data.Equals( expected ) )
    {
        fprintf( stderr, "compat cpp read: decoded values do not match\n" );
        return 1;
    }

    printf( "compat cpp read ok\n" );
    return 0;
}

int main( int argc, char ** argv )
{
    if ( argc != 3 )
    {
        fprintf( stderr, "usage: compat-cpp write|read <file>\n" );
        return 2;
    }
    if ( strcmp( argv[1], "write" ) == 0 )
        return Write( argv[2] );
    if ( strcmp( argv[1], "read" ) == 0 )
        return Read( argv[2] );
    fprintf( stderr, "usage: compat-cpp write|read <file>\n" );
    return 2;
}
