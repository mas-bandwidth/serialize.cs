#define SERIALIZE_IMPLEMENTATION
#include "/Users/glenn/rowan-working/serialize-cs-port/serialize/serialize.h"
#include <cstdio>
int main()
{
    uint8_t buffer[64];
    memset(buffer, 0, sizeof(buffer));
    const float lo = -3.4e38f, hi = 3.4e38f, res = 1e-30f;
    printf("delta = %g\n", hi - lo);
    // write a legitimate value, then read it back: what does the C++ library do?
    {
        serialize::WriteStream w(buffer, sizeof(buffer));
        float v = 1.0f;
        bool ok = serialize::serialize_compressed_float_internal(w, v, lo, hi, res);
        w.Flush();
        printf("cpp write ok=%d\n", (int)ok);
    }
    {
        serialize::ReadStream r(buffer, sizeof(buffer));
        float v = -1.0f;
        bool ok = serialize::serialize_compressed_float_internal(r, v, lo, hi, res);
        printf("cpp read  ok=%d value=%g isnan=%d\n", (int)ok, v, (int)(v != v));
    }
    // raw zero on the wire
    {
        memset(buffer, 0, sizeof(buffer));
        serialize::ReadStream r(buffer, sizeof(buffer));
        float v = -1.0f;
        bool ok = serialize::serialize_compressed_float_internal(r, v, lo, hi, res);
        printf("cpp raw0  ok=%d value=%g isnan=%d\n", (int)ok, v, (int)(v != v));
    }
    return 0;
}
