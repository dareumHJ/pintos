#define f (1 << 14)
#include <stdint.h>

int int_to_fp (int n) { return (n * f); } // return fixed point
int fp_to_int_rtz (int x) { return (x / f); } // return integer, round to zero
int fp_to_int_rtn (int x) // return integer, round to nearest
{
    if (x >= 0) return (x + f / 2) / f;
    else return (x - f / 2) / f;
}
int add_fp_int (int x, int n) { return (x + n * f); } // return fixed point
int sub_fp_int (int x, int n) { return (x - n * f); } // return fixed point
int mul_fp_fp (int x, int y) { return (((int64_t) x) * y / f); } // return fixed point
int div_fp_fp (int x, int y) { return (((int64_t) x) * f / y); } // return fixed point