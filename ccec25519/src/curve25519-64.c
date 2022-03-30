/* Copyright (c) (2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/* Copyright 2008, Google Inc.
 * All rights reserved.
 *
 * Code released into the public domain.
 *
 * curve25519-donna: Curve25519 elliptic curve, public key function
 *
 * http://code.google.com/p/curve25519-donna/
 *
 * Adam Langley <agl@imperialviolet.org>
 *
 * Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
 *
 * More information about curve25519 can be found here
 *   http://cr.yp.to/ecdh.html
 *
 * djb's sample implementation of curve25519 is written in a special assembly
 * language called qhasm and uses the floating point registers.
 *
 * This is, almost, a clean room reimplementation from the curve25519 paper. It
 * uses many of the tricks described therein. Only the crecip function is taken
 * from the sample implementation.
 */

#include <corecrypto/cc.h>
#include <corecrypto/ccec25519_priv.h>
#include <corecrypto/cc_priv.h>
#include "curve25519_priv.h"

#if CCEC25519_CURVE25519_64BIT

/* Sum two numbers: output = a + b */
void fsum(limb *output, const limb *a, const limb *b)
{
    output[0] = a[0] + b[0];
    output[1] = a[1] + b[1];
    output[2] = a[2] + b[2];
    output[3] = a[3] + b[3];
    output[4] = a[4] + b[4];
}

/* Find the difference of two numbers: output = a - b
 * (note the order of the arguments!)
 *
 * Assumes that a[i] < 2**52 and likewise for b.
 * On return, out[i] < 2**55
 */
void fdiff(limb *out, const limb *a, const limb *b)
{
    /* 152 is 19 << 3 */
    static const limb two54m152 = (((limb)1) << 54) - 152;
    static const limb two54m8 = (((limb)1) << 54) - 8;

    out[0] = a[0] + two54m152 - b[0];
    out[1] = a[1] + two54m8 - b[1];
    out[2] = a[2] + two54m8 - b[2];
    out[3] = a[3] + two54m8 - b[3];
    out[4] = a[4] + two54m8 - b[4];
}

/* Multiply a number by 121666. */
void fmul_121666(limb *output, const limb *in)
{
    uint128_t a;

    a = ((uint128_t)in[0]) * 121666;
    output[0] = ((limb)a) & 0x7ffffffffffff;

    a = ((uint128_t)in[1]) * 121666 + ((limb)(a >> 51));
    output[1] = ((limb)a) & 0x7ffffffffffff;

    a = ((uint128_t)in[2]) * 121666 + ((limb)(a >> 51));
    output[2] = ((limb)a) & 0x7ffffffffffff;

    a = ((uint128_t)in[3]) * 121666 + ((limb)(a >> 51));
    output[3] = ((limb)a) & 0x7ffffffffffff;

    a = ((uint128_t)in[4]) * 121666 + ((limb)(a >> 51));
    output[4] = ((limb)a) & 0x7ffffffffffff;

    output[0] += (a >> 51) * 19;
}

/* Multiply two numbers: output = in2 * in
 *
 * output must be distinct to both inputs. The inputs are reduced coefficient
 * form, the output is not.
 *
 * Assumes that in[i] < 2**55 and likewise for in2.
 * On return, output[i] < 2**52
 */
void fmul(limb *output, const limb *in2, const limb *in)
{
    uint128_t t[5];
    limb r0, r1, r2, r3, r4, s0, s1, s2, s3, s4, c;

    r0 = in[0];
    r1 = in[1];
    r2 = in[2];
    r3 = in[3];
    r4 = in[4];

    s0 = in2[0];
    s1 = in2[1];
    s2 = in2[2];
    s3 = in2[3];
    s4 = in2[4];

    t[0] = ((uint128_t)r0) * s0;
    t[1] = ((uint128_t)r0) * s1 + ((uint128_t)r1) * s0;
    t[2] = ((uint128_t)r0) * s2 + ((uint128_t)r2) * s0 + ((uint128_t)r1) * s1;
    t[3] = ((uint128_t)r0) * s3 + ((uint128_t)r3) * s0 + ((uint128_t)r1) * s2 + ((uint128_t)r2) * s1;
    t[4] = ((uint128_t)r0) * s4 + ((uint128_t)r4) * s0 + ((uint128_t)r3) * s1 + ((uint128_t)r1) * s3 + ((uint128_t)r2) * s2;

    r4 *= 19;
    r1 *= 19;
    r2 *= 19;
    r3 *= 19;

    t[0] += ((uint128_t)r4) * s1 + ((uint128_t)r1) * s4 + ((uint128_t)r2) * s3 + ((uint128_t)r3) * s2;
    t[1] += ((uint128_t)r4) * s2 + ((uint128_t)r2) * s4 + ((uint128_t)r3) * s3;
    t[2] += ((uint128_t)r4) * s3 + ((uint128_t)r3) * s4;
    t[3] += ((uint128_t)r4) * s4;

    /* clang-format off */
    r0 = (limb)t[0] & 0x7ffffffffffff; c = (limb)(t[0] >> 51);
    t[1] += c;      r1 = (limb)t[1] & 0x7ffffffffffff; c = (limb)(t[1] >> 51);
    t[2] += c;      r2 = (limb)t[2] & 0x7ffffffffffff; c = (limb)(t[2] >> 51);
    t[3] += c;      r3 = (limb)t[3] & 0x7ffffffffffff; c = (limb)(t[3] >> 51);
    t[4] += c;      r4 = (limb)t[4] & 0x7ffffffffffff; c = (limb)(t[4] >> 51);
    r0 +=   c * 19; c = r0 >> 51; r0 = r0 & 0x7ffffffffffff;
    r1 +=   c;      c = r1 >> 51; r1 = r1 & 0x7ffffffffffff;
    r2 +=   c;
    /* clang-format on */

    output[0] = r0;
    output[1] = r1;
    output[2] = r2;
    output[3] = r3;
    output[4] = r4;
}

void fsquare_times(limb *output, const limb *in, limb count)
{
    uint128_t t[5];
    limb r0, r1, r2, r3, r4, c;
    limb d0, d1, d2, d4, d419;

    r0 = in[0];
    r1 = in[1];
    r2 = in[2];
    r3 = in[3];
    r4 = in[4];

    for (limb i = 0; i < count; i++) {
        d0 = r0 << 1;
        d1 = r1 << 1;
        d2 = (r2 * 19) << 1;
        d419 = r4 * 19;
        d4 = d419 << 1;

        t[0] = ((uint128_t)r0) * r0 + ((uint128_t)d4) * r1 + (((uint128_t)d2) * (r3));
        t[1] = ((uint128_t)d0) * r1 + ((uint128_t)d4) * r2 + (((uint128_t)r3) * (r3 * 19));
        t[2] = ((uint128_t)d0) * r2 + ((uint128_t)r1) * r1 + (((uint128_t)d4) * (r3));
        t[3] = ((uint128_t)d0) * r3 + ((uint128_t)d1) * r2 + (((uint128_t)r4) * (d419));
        t[4] = ((uint128_t)d0) * r4 + ((uint128_t)d1) * r3 + (((uint128_t)r2) * (r2));

        /* clang-format off */
        r0 = (limb)t[0] & 0x7ffffffffffff; c = (limb)(t[0] >> 51);
        t[1] += c;      r1 = (limb)t[1] & 0x7ffffffffffff; c = (limb)(t[1] >> 51);
        t[2] += c;      r2 = (limb)t[2] & 0x7ffffffffffff; c = (limb)(t[2] >> 51);
        t[3] += c;      r3 = (limb)t[3] & 0x7ffffffffffff; c = (limb)(t[3] >> 51);
        t[4] += c;      r4 = (limb)t[4] & 0x7ffffffffffff; c = (limb)(t[4] >> 51);
        r0 +=   c * 19; c = r0 >> 51; r0 = r0 & 0x7ffffffffffff;
        r1 +=   c;      c = r1 >> 51; r1 = r1 & 0x7ffffffffffff;
        r2 +=   c;
        /* clang-format on */
    }

    output[0] = r0;
    output[1] = r1;
    output[2] = r2;
    output[3] = r3;
    output[4] = r4;
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
void fexpand(limb *output, const uint8_t *in)
{
    uint64_t x;

    CC_LOAD64_LE(x, in);
    output[0] = x & 0x7ffffffffffff;

    CC_LOAD64_LE(x, in + 6);
    output[1] = (x >> 3) & 0x7ffffffffffff;

    CC_LOAD64_LE(x, in + 12);
    output[2] = (x >> 6) & 0x7ffffffffffff;

    CC_LOAD64_LE(x, in + 19);
    output[3] = (x >> 1) & 0x7ffffffffffff;

    CC_LOAD64_LE(x, in + 24);
    output[4] = (x >> 12) & 0x7ffffffffffff;
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
void fcontract(uint8_t *output, const limb *input)
{
    uint128_t t[5];

    t[0] = input[0];
    t[1] = input[1];
    t[2] = input[2];
    t[3] = input[3];
    t[4] = input[4];

    /* clang-format off */
    t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
    t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
    t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
    t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
    t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffff;

    t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
    t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
    t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
    t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
    t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffff;

    /* now t is between 0 and 2^255-1, properly carried. */
    /* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */

    t[0] += 19;

    t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
    t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
    t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
    t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
    t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffff;

    /* now between 19 and 2^255-1 in both cases, and offset by 19. */

    t[0] += 0x8000000000000 - 19;
    t[1] += 0x8000000000000 - 1;
    t[2] += 0x8000000000000 - 1;
    t[3] += 0x8000000000000 - 1;
    t[4] += 0x8000000000000 - 1;

    /* now between 2^255 and 2^256-20, and offset by 2^255. */

    t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
    t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
    t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
    t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
    t[4] &= 0x7ffffffffffff;

    CC_STORE64_LE(t[0] | (t[1] << 51), output);
    CC_STORE64_LE((t[1] >> 13) | (t[2] << 38), output + 8);
    CC_STORE64_LE((t[2] >> 26) | (t[3] << 25), output + 16);
    CC_STORE64_LE((t[3] >> 39) | (t[4] << 12), output + 24);
    /* clang-format on */
}

#endif /* CCEC25519_CURVE25519_64BIT */
