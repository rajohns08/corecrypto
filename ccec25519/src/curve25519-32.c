/* Copyright (c) (2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
 * from the sample implementation. */

#include <corecrypto/cc.h>
#include <corecrypto/ccec25519_priv.h>
#include <corecrypto/cc_priv.h>
#include "curve25519_priv.h"

#if !CCEC25519_CURVE25519_64BIT

typedef int32_t s32;

cc_static_assert(-1 == ~0, "This code only works on a two's complement system.");

/* Field element representation:
 *
 * Field elements are written as an array of signed, 64-bit limbs, least
 * significant first. The value of the field element is:
 *   x[0] + 2^26·x[1] + x^51·x[2] + 2^102·x[3] + ...
 *
 * i.e. the limbs are 26, 25, 26, 25, ... bits wide. */

/* Sum two numbers: output += in */
void fsum(limb *output, const limb *a, const limb *b)
{
    for (int i = 0; i < 10; i += 2) {
        output[0 + i] = a[0 + i] + b[0 + i];
        output[1 + i] = a[1 + i] + b[1 + i];
    }
}

/* Find the difference of two numbers: output = a - b */
void fdiff(limb *output, const limb *a, const limb *b)
{
    for (int i = 0; i < 10; ++i) {
        output[i] = a[i] - b[i];
    }
}

/* Multiply two numbers: output = in2 * in
 *
 * output must be distinct to both inputs. The inputs are reduced coefficient
 * form, the output is not.
 *
 * output[x] <= 14 * the largest product of the input limbs. */
/* clang-format off */
static void fproduct(limb *output, const limb *in2, const limb *in)
{
    output[0] =       ((limb) ((s32) in2[0])) * ((s32) in[0]);
    output[1] =       ((limb) ((s32) in2[0])) * ((s32) in[1]) +
    ((limb) ((s32) in2[1])) * ((s32) in[0]);
    output[2] =  2 *  ((limb) ((s32) in2[1])) * ((s32) in[1]) +
    ((limb) ((s32) in2[0])) * ((s32) in[2]) +
    ((limb) ((s32) in2[2])) * ((s32) in[0]);
    output[3] =       ((limb) ((s32) in2[1])) * ((s32) in[2]) +
    ((limb) ((s32) in2[2])) * ((s32) in[1]) +
    ((limb) ((s32) in2[0])) * ((s32) in[3]) +
    ((limb) ((s32) in2[3])) * ((s32) in[0]);
    output[4] =       ((limb) ((s32) in2[2])) * ((s32) in[2]) +
    2 * (((limb) ((s32) in2[1])) * ((s32) in[3]) +
         ((limb) ((s32) in2[3])) * ((s32) in[1])) +
    ((limb) ((s32) in2[0])) * ((s32) in[4]) +
    ((limb) ((s32) in2[4])) * ((s32) in[0]);
    output[5] =       ((limb) ((s32) in2[2])) * ((s32) in[3]) +
    ((limb) ((s32) in2[3])) * ((s32) in[2]) +
    ((limb) ((s32) in2[1])) * ((s32) in[4]) +
    ((limb) ((s32) in2[4])) * ((s32) in[1]) +
    ((limb) ((s32) in2[0])) * ((s32) in[5]) +
    ((limb) ((s32) in2[5])) * ((s32) in[0]);
    output[6] =  2 * (((limb) ((s32) in2[3])) * ((s32) in[3]) +
                      ((limb) ((s32) in2[1])) * ((s32) in[5]) +
                      ((limb) ((s32) in2[5])) * ((s32) in[1])) +
    ((limb) ((s32) in2[2])) * ((s32) in[4]) +
    ((limb) ((s32) in2[4])) * ((s32) in[2]) +
    ((limb) ((s32) in2[0])) * ((s32) in[6]) +
    ((limb) ((s32) in2[6])) * ((s32) in[0]);
    output[7] =       ((limb) ((s32) in2[3])) * ((s32) in[4]) +
    ((limb) ((s32) in2[4])) * ((s32) in[3]) +
    ((limb) ((s32) in2[2])) * ((s32) in[5]) +
    ((limb) ((s32) in2[5])) * ((s32) in[2]) +
    ((limb) ((s32) in2[1])) * ((s32) in[6]) +
    ((limb) ((s32) in2[6])) * ((s32) in[1]) +
    ((limb) ((s32) in2[0])) * ((s32) in[7]) +
    ((limb) ((s32) in2[7])) * ((s32) in[0]);
    output[8] =       ((limb) ((s32) in2[4])) * ((s32) in[4]) +
    2 * (((limb) ((s32) in2[3])) * ((s32) in[5]) +
         ((limb) ((s32) in2[5])) * ((s32) in[3]) +
         ((limb) ((s32) in2[1])) * ((s32) in[7]) +
         ((limb) ((s32) in2[7])) * ((s32) in[1])) +
    ((limb) ((s32) in2[2])) * ((s32) in[6]) +
    ((limb) ((s32) in2[6])) * ((s32) in[2]) +
    ((limb) ((s32) in2[0])) * ((s32) in[8]) +
    ((limb) ((s32) in2[8])) * ((s32) in[0]);
    output[9] =       ((limb) ((s32) in2[4])) * ((s32) in[5]) +
    ((limb) ((s32) in2[5])) * ((s32) in[4]) +
    ((limb) ((s32) in2[3])) * ((s32) in[6]) +
    ((limb) ((s32) in2[6])) * ((s32) in[3]) +
    ((limb) ((s32) in2[2])) * ((s32) in[7]) +
    ((limb) ((s32) in2[7])) * ((s32) in[2]) +
    ((limb) ((s32) in2[1])) * ((s32) in[8]) +
    ((limb) ((s32) in2[8])) * ((s32) in[1]) +
    ((limb) ((s32) in2[0])) * ((s32) in[9]) +
    ((limb) ((s32) in2[9])) * ((s32) in[0]);
    output[10] = 2 * (((limb) ((s32) in2[5])) * ((s32) in[5]) +
                      ((limb) ((s32) in2[3])) * ((s32) in[7]) +
                      ((limb) ((s32) in2[7])) * ((s32) in[3]) +
                      ((limb) ((s32) in2[1])) * ((s32) in[9]) +
                      ((limb) ((s32) in2[9])) * ((s32) in[1])) +
    ((limb) ((s32) in2[4])) * ((s32) in[6]) +
    ((limb) ((s32) in2[6])) * ((s32) in[4]) +
    ((limb) ((s32) in2[2])) * ((s32) in[8]) +
    ((limb) ((s32) in2[8])) * ((s32) in[2]);
    output[11] =      ((limb) ((s32) in2[5])) * ((s32) in[6]) +
    ((limb) ((s32) in2[6])) * ((s32) in[5]) +
    ((limb) ((s32) in2[4])) * ((s32) in[7]) +
    ((limb) ((s32) in2[7])) * ((s32) in[4]) +
    ((limb) ((s32) in2[3])) * ((s32) in[8]) +
    ((limb) ((s32) in2[8])) * ((s32) in[3]) +
    ((limb) ((s32) in2[2])) * ((s32) in[9]) +
    ((limb) ((s32) in2[9])) * ((s32) in[2]);
    output[12] =      ((limb) ((s32) in2[6])) * ((s32) in[6]) +
    2 * (((limb) ((s32) in2[5])) * ((s32) in[7]) +
         ((limb) ((s32) in2[7])) * ((s32) in[5]) +
         ((limb) ((s32) in2[3])) * ((s32) in[9]) +
         ((limb) ((s32) in2[9])) * ((s32) in[3])) +
    ((limb) ((s32) in2[4])) * ((s32) in[8]) +
    ((limb) ((s32) in2[8])) * ((s32) in[4]);
    output[13] =      ((limb) ((s32) in2[6])) * ((s32) in[7]) +
    ((limb) ((s32) in2[7])) * ((s32) in[6]) +
    ((limb) ((s32) in2[5])) * ((s32) in[8]) +
    ((limb) ((s32) in2[8])) * ((s32) in[5]) +
    ((limb) ((s32) in2[4])) * ((s32) in[9]) +
    ((limb) ((s32) in2[9])) * ((s32) in[4]);
    output[14] = 2 * (((limb) ((s32) in2[7])) * ((s32) in[7]) +
                      ((limb) ((s32) in2[5])) * ((s32) in[9]) +
                      ((limb) ((s32) in2[9])) * ((s32) in[5])) +
    ((limb) ((s32) in2[6])) * ((s32) in[8]) +
    ((limb) ((s32) in2[8])) * ((s32) in[6]);
    output[15] =      ((limb) ((s32) in2[7])) * ((s32) in[8]) +
    ((limb) ((s32) in2[8])) * ((s32) in[7]) +
    ((limb) ((s32) in2[6])) * ((s32) in[9]) +
    ((limb) ((s32) in2[9])) * ((s32) in[6]);
    output[16] =      ((limb) ((s32) in2[8])) * ((s32) in[8]) +
    2 * (((limb) ((s32) in2[7])) * ((s32) in[9]) +
         ((limb) ((s32) in2[9])) * ((s32) in[7]));
    output[17] =      ((limb) ((s32) in2[8])) * ((s32) in[9]) +
    ((limb) ((s32) in2[9])) * ((s32) in[8]);
    output[18] = 2 *  ((limb) ((s32) in2[9])) * ((s32) in[9]);
}
/* clang-format on */

/* Reduce a long form to a short form by taking the input mod 2^255 - 19.
 *
 * On entry: |output[i]| < 14*2^54
 * On exit: |output[0..8]| < 280*2^54 */
static void freduce_degree(limb *output)
{
    /* Each of these shifts and adds ends up multiplying the value by 19.
     *
     * For output[0..8], the absolute entry value is < 14*2^54 and we add, at
     * most, 19*14*2^54 thus, on exit, |output[0..8]| < 280*2^54. */
    output[8] += output[18] << 4;
    output[8] += output[18] << 1;
    output[8] += output[18];
    output[7] += output[17] << 4;
    output[7] += output[17] << 1;
    output[7] += output[17];
    output[6] += output[16] << 4;
    output[6] += output[16] << 1;
    output[6] += output[16];
    output[5] += output[15] << 4;
    output[5] += output[15] << 1;
    output[5] += output[15];
    output[4] += output[14] << 4;
    output[4] += output[14] << 1;
    output[4] += output[14];
    output[3] += output[13] << 4;
    output[3] += output[13] << 1;
    output[3] += output[13];
    output[2] += output[12] << 4;
    output[2] += output[12] << 1;
    output[2] += output[12];
    output[1] += output[11] << 4;
    output[1] += output[11] << 1;
    output[1] += output[11];
    output[0] += output[10] << 4;
    output[0] += output[10] << 1;
    output[0] += output[10];
}

/* return v / 2^26, using only shifts and adds.
 *
 * On entry: v can take any value. */
static inline limb div_by_2_26(const limb v)
{
    /* High word of v; no shift needed. */
    const uint32_t highword = (uint32_t)(((uint64_t)v) >> 32);
    /* Set to all 1s if v was negative; else set to 0s. */
    const int32_t sign = ((int32_t)highword) >> 31;
    /* Set to 0x3ffffff if v was negative; else set to 0. */
    const int32_t roundoff = ((uint32_t)sign) >> 6;
    /* Should return v / (1<<26) */
    return (v + roundoff) >> 26;
}

/* return v / (2^25), using only shifts and adds.
 *
 * On entry: v can take any value. */
static inline limb div_by_2_25(const limb v)
{
    /* High word of v; no shift needed*/
    const uint32_t highword = (uint32_t)(((uint64_t)v) >> 32);
    /* Set to all 1s if v was negative; else set to 0s. */
    const int32_t sign = ((int32_t)highword) >> 31;
    /* Set to 0x1ffffff if v was negative; else set to 0. */
    const int32_t roundoff = ((uint32_t)sign) >> 7;
    /* Should return v / (1<<25) */
    return (v + roundoff) >> 25;
}

/* Reduce all coefficients of the short form input so that |x| < 2^26.
 *
 * On entry: |output[i]| < 280*2^54 */
static void freduce_coefficients(limb *output)
{
    unsigned i;

    output[10] = 0;

    for (i = 0; i < 10; i += 2) {
        limb over = div_by_2_26(output[i]);
        /* The entry condition (that |output[i]| < 280*2^54) means that over is, at
         * most, 280*2^28 in the first iteration of this loop. This is added to the
         * next limb and we can approximate the resulting bound of that limb by
         * 281*2^54. */
        output[i] -= over << 26;
        output[i + 1] += over;

        /* For the first iteration, |output[i+1]| < 281*2^54, thus |over| <
         * 281*2^29. When this is added to the next limb, the resulting bound can
         * be approximated as 281*2^54.
         *
         * For subsequent iterations of the loop, 281*2^54 remains a conservative
         * bound and no overflow occurs. */
        over = div_by_2_25(output[i + 1]);
        output[i + 1] -= over << 25;
        output[i + 2] += over;
    }
    /* Now |output[10]| < 281*2^29 and all other coefficients are reduced. */
    output[0] += output[10] << 4;
    output[0] += output[10] << 1;
    output[0] += output[10];

    output[10] = 0;

    /* Now output[1..9] are reduced, and |output[0]| < 2^26 + 19*281*2^29
     * So |over| will be no more than 2^16. */
    {
        limb over = div_by_2_26(output[0]);
        output[0] -= over << 26;
        output[1] += over;
    }

    /* Now output[0,2..9] are reduced, and |output[1]| < 2^25 + 2^16 < 2^26. The
     * bound on |output[1]| is sufficient to meet our needs. */
}

/* Multiply a number by 121666. |in[i]| < 2^26 */
void fmul_121666(limb *output, const limb *in)
{
    for (int i = 0; i < 10; ++i) {
#if defined(_WIN32)
        uint32_t i0 = (uint32_t)in[i];
        uint64_t r0 = (uint64_t)i0 * 121666;
        uint64_t r1 = (uint64_t)in[i] & 0xfffe24be00000000;
        output[i] = (limb)(r0 + r1);
#else
        output[i] = in[i] * 121666;
#endif
    }

    freduce_coefficients(output);
    /* |output[i]| < 2^26 */
}

/* A helpful wrapper around fproduct: output = in * in2.
 *
 * On entry: |in[i]| < 2^27 and |in2[i]| < 2^27.
 *
 * output must be distinct to both inputs. The output is reduced degree
 * (indeed, one need only provide storage for 10 limbs) and |output[i]| < 2^26. */
void fmul(limb *output, const limb *in, const limb *in2)
{
    limb t[19];
    fproduct(t, in, in2);
    /* |t[i]| < 14*2^54 */
    freduce_degree(t);
    freduce_coefficients(t);
    /* |t[i]| < 2^26 */
    cc_memcpy(output, t, sizeof(limb) * 10);
}

/* Square a number: output = in**2
 *
 * output must be distinct from the input. The inputs are reduced coefficient
 * form, the output is not.
 *
 * output[x] <= 14 * the largest product of the input limbs. */
/* clang-format off */
static void fsquare_inner(limb *output, const limb *in)
{
    output[0] =       ((limb) ((s32) in[0])) * ((s32) in[0]);
    output[1] =  2 *  ((limb) ((s32) in[0])) * ((s32) in[1]);
    output[2] =  2 * (((limb) ((s32) in[1])) * ((s32) in[1]) +
                      ((limb) ((s32) in[0])) * ((s32) in[2]));
    output[3] =  2 * (((limb) ((s32) in[1])) * ((s32) in[2]) +
                      ((limb) ((s32) in[0])) * ((s32) in[3]));
    output[4] =       ((limb) ((s32) in[2])) * ((s32) in[2]) +
    4 *  ((limb) ((s32) in[1])) * ((s32) in[3]) +
    2 *  ((limb) ((s32) in[0])) * ((s32) in[4]);
    output[5] =  2 * (((limb) ((s32) in[2])) * ((s32) in[3]) +
                      ((limb) ((s32) in[1])) * ((s32) in[4]) +
                      ((limb) ((s32) in[0])) * ((s32) in[5]));
    output[6] =  2 * (((limb) ((s32) in[3])) * ((s32) in[3]) +
                      ((limb) ((s32) in[2])) * ((s32) in[4]) +
                      ((limb) ((s32) in[0])) * ((s32) in[6]) +
                      2 *  ((limb) ((s32) in[1])) * ((s32) in[5]));
    output[7] =  2 * (((limb) ((s32) in[3])) * ((s32) in[4]) +
                      ((limb) ((s32) in[2])) * ((s32) in[5]) +
                      ((limb) ((s32) in[1])) * ((s32) in[6]) +
                      ((limb) ((s32) in[0])) * ((s32) in[7]));
    output[8] =       ((limb) ((s32) in[4])) * ((s32) in[4]) +
    2 * (((limb) ((s32) in[2])) * ((s32) in[6]) +
         ((limb) ((s32) in[0])) * ((s32) in[8]) +
         2 * (((limb) ((s32) in[1])) * ((s32) in[7]) +
              ((limb) ((s32) in[3])) * ((s32) in[5])));
    output[9] =  2 * (((limb) ((s32) in[4])) * ((s32) in[5]) +
                      ((limb) ((s32) in[3])) * ((s32) in[6]) +
                      ((limb) ((s32) in[2])) * ((s32) in[7]) +
                      ((limb) ((s32) in[1])) * ((s32) in[8]) +
                      ((limb) ((s32) in[0])) * ((s32) in[9]));
    output[10] = 2 * (((limb) ((s32) in[5])) * ((s32) in[5]) +
                      ((limb) ((s32) in[4])) * ((s32) in[6]) +
                      ((limb) ((s32) in[2])) * ((s32) in[8]) +
                      2 * (((limb) ((s32) in[3])) * ((s32) in[7]) +
                           ((limb) ((s32) in[1])) * ((s32) in[9])));
    output[11] = 2 * (((limb) ((s32) in[5])) * ((s32) in[6]) +
                      ((limb) ((s32) in[4])) * ((s32) in[7]) +
                      ((limb) ((s32) in[3])) * ((s32) in[8]) +
                      ((limb) ((s32) in[2])) * ((s32) in[9]));
    output[12] =      ((limb) ((s32) in[6])) * ((s32) in[6]) +
    2 * (((limb) ((s32) in[4])) * ((s32) in[8]) +
         2 * (((limb) ((s32) in[5])) * ((s32) in[7]) +
              ((limb) ((s32) in[3])) * ((s32) in[9])));
    output[13] = 2 * (((limb) ((s32) in[6])) * ((s32) in[7]) +
                      ((limb) ((s32) in[5])) * ((s32) in[8]) +
                      ((limb) ((s32) in[4])) * ((s32) in[9]));
    output[14] = 2 * (((limb) ((s32) in[7])) * ((s32) in[7]) +
                      ((limb) ((s32) in[6])) * ((s32) in[8]) +
                      2 *  ((limb) ((s32) in[5])) * ((s32) in[9]));
    output[15] = 2 * (((limb) ((s32) in[7])) * ((s32) in[8]) +
                      ((limb) ((s32) in[6])) * ((s32) in[9]));
    output[16] =      ((limb) ((s32) in[8])) * ((s32) in[8]) +
    4 *  ((limb) ((s32) in[7])) * ((s32) in[9]);
    output[17] = 2 *  ((limb) ((s32) in[8])) * ((s32) in[9]);
    output[18] = 2 *  ((limb) ((s32) in[9])) * ((s32) in[9]);
}
/* clang-format on */

/* fsquare_times sets output = in^(2^count).
 *
 * On entry: The |in| argument is in reduced coefficients form and |in[i]| <
 * 2^27.
 *
 * On exit: The |output| argument is in reduced coefficients form (indeed, one
 * need only provide storage for 10 limbs) and |out[i]| < 2^26. */
void fsquare_times(limb *output, const limb *in, limb count)
{
    limb _t0[19], _t1[19];
    limb *t0 = _t0;
    limb *t1 = _t1;

    memcpy(t0, in, sizeof(limb) * 10);

    for (limb i = 0; i < count; i++) {
        fsquare_inner(t1, t0);
        /* |t[i]| < 14*2^54 because the largest product of two limbs will be <
         * 2^(27+27) and fsquare_inner adds together, at most, 14 of those
         * products. */
        freduce_degree(t1);
        freduce_coefficients(t1);
        CC_SWAP(t0, t1);
    }

    /* |t[i]| < 2^26 */
    cc_memcpy(output, t0, sizeof(limb) * 10);
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
/* clang-format off */
void fexpand(limb *output, const uint8_t *input)
{
#define F(n,start,shift,mask) \
output[n] = ((((limb) input[start + 0]) | \
((limb) input[start + 1]) << 8 | \
((limb) input[start + 2]) << 16 | \
((limb) input[start + 3]) << 24) >> shift) & mask;
    F(0, 0, 0, 0x3ffffff);
    F(1, 3, 2, 0x1ffffff);
    F(2, 6, 3, 0x3ffffff);
    F(3, 9, 5, 0x1ffffff);
    F(4, 12, 6, 0x3ffffff);
    F(5, 16, 0, 0x1ffffff);
    F(6, 19, 1, 0x3ffffff);
    F(7, 22, 3, 0x1ffffff);
    F(8, 25, 4, 0x3ffffff);
    F(9, 28, 6, 0x1ffffff);
#undef F
}
/* clang-format on */

#if (-32 >> 1) != -16
#error "This code only works when >> does sign-extension on negative numbers"
#endif

/* s32_eq returns 0xffffffff iff a == b and zero otherwise. */
static s32 s32_eq(s32 a, s32 b)
{
    a = ~(a ^ b);
    a &= a << 16;
    a &= a << 8;
    a &= a << 4;
    a &= a << 2;
    a &= a << 1;
    return a >> 31;
}

/* s32_gte returns 0xffffffff if a >= b and zero otherwise, where a and b are
 * both non-negative. */
static s32 s32_gte(s32 a, s32 b)
{
    a -= b;
    /* a >= 0 iff a >= b. */
    return ~(a >> 31);
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array.
 *
 * On entry: |input_limbs[i]| < 2^26 */
void fcontract(uint8_t *output, const limb *input_limbs)
{
    int i;
    int j;
    s32 input[10];

    /* |input_limbs[i]| < 2^26, so it's valid to convert to an s32. */
    for (i = 0; i < 10; i++) {
        input[i] = (s32)input_limbs[i];
    }

    for (j = 0; j < 2; ++j) {
        for (i = 0; i < 9; ++i) {
            if ((i & 1) == 1) {
                /* This calculation is a time-invariant way to make input[i]
                 * non-negative by borrowing from the next-larger limb. */
                const s32 mask = input[i] >> 31;
                const s32 carry = -((input[i] & mask) >> 25);
                input[i] = input[i] + (carry << 25);
                input[i + 1] = input[i + 1] - carry;
            } else {
                const s32 mask = input[i] >> 31;
                const s32 carry = -((input[i] & mask) >> 26);
                input[i] = input[i] + (carry << 26);
                input[i + 1] = input[i + 1] - carry;
            }
        }

        /* There's no greater limb for input[9] to borrow from, but we can multiply
         * by 19 and borrow from input[0], which is valid mod 2^255-19. */
        {
            const s32 mask = input[9] >> 31;
            const s32 carry = -((input[9] & mask) >> 25);
            input[9] = input[9] + (carry << 25);
            input[0] = input[0] - (carry * 19);
        }

        /* After the first iteration, input[1..9] are non-negative and fit within
         * 25 or 26 bits, depending on position. However, input[0] may be
         * negative. */
    }

    /* The first borrow-propagation pass above ended with every limb
     except (possibly) input[0] non-negative.

     If input[0] was negative after the first pass, then it was because of a
     carry from input[9]. On entry, input[9] < 2^26 so the carry was, at most,
     one, since (2**26-1) >> 25 = 1. Thus input[0] >= -19.

     In the second pass, each limb is decreased by at most one. Thus the second
     borrow-propagation pass could only have wrapped around to decrease
     input[0] again if the first pass left input[0] negative *and* input[1]
     through input[9] were all zero.  In that case, input[1] is now 2^25 - 1,
     and this last borrow-propagation step will leave input[1] non-negative. */
    {
        const s32 mask = input[0] >> 31;
        const s32 carry = -((input[0] & mask) >> 26);
        input[0] = input[0] + (carry << 26);
        input[1] = input[1] - carry;
    }

    /* All input[i] are now non-negative. However, there might be values between
     * 2^25 and 2^26 in a limb which is, nominally, 25 bits wide. */
    for (j = 0; j < 2; j++) {
        for (i = 0; i < 9; i++) {
            if ((i & 1) == 1) {
                const s32 carry = input[i] >> 25;
                input[i] &= 0x1ffffff;
                input[i + 1] += carry;
            } else {
                const s32 carry = input[i] >> 26;
                input[i] &= 0x3ffffff;
                input[i + 1] += carry;
            }
        }

        {
            const s32 carry = input[9] >> 25;
            input[9] &= 0x1ffffff;
            input[0] += 19 * carry;
        }
    }

    /* If the first carry-chain pass, just above, ended up with a carry from
     * input[9], and that caused input[0] to be out-of-bounds, then input[0] was
     * < 2^26 + 2*19, because the carry was, at most, two.
     *
     * If the second pass carried from input[9] again then input[0] is < 2*19 and
     * the input[9] -> input[0] carry didn't push input[0] out of bounds. */

    /* It still remains the case that input might be between 2^255-19 and 2^255.
     * In this case, input[1..9] must take their maximum value and input[0] must
     * be >= (2^255-19) & 0x3ffffff, which is 0x3ffffed. */
    s32 mask = s32_gte(input[0], 0x3ffffed);
    for (i = 1; i < 10; i++) {
        if ((i & 1) == 1) {
            mask &= s32_eq(input[i], 0x1ffffff);
        } else {
            mask &= s32_eq(input[i], 0x3ffffff);
        }
    }

    /* mask is either 0xffffffff (if input >= 2^255-19) and zero otherwise. Thus
     * this conditionally subtracts 2^255-19. */
    input[0] -= mask & 0x3ffffed;

    for (i = 1; i < 10; i++) {
        if ((i & 1) == 1) {
            input[i] -= mask & 0x1ffffff;
        } else {
            input[i] -= mask & 0x3ffffff;
        }
    }

    input[1] <<= 2;
    input[2] <<= 3;
    input[3] <<= 5;
    input[4] <<= 6;
    input[6] <<= 1;
    input[7] <<= 3;
    input[8] <<= 4;
    input[9] <<= 6;
#define F(i, s)                              \
    output[s + 0] |= input[i] & 0xff;        \
    output[s + 1] = (input[i] >> 8) & 0xff;  \
    output[s + 2] = (input[i] >> 16) & 0xff; \
    output[s + 3] = (input[i] >> 24) & 0xff;
    output[0] = 0;
    output[16] = 0;
    F(0, 0);
    F(1, 3);
    F(2, 6);
    F(3, 9);
    F(4, 12);
    F(5, 16);
    F(6, 19);
    F(7, 22);
    F(8, 25);
    F(9, 28);
#undef F
}

#endif /* !CCEC25519_CURVE25519_64BIT */
