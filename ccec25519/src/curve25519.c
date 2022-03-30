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
#include <stdbool.h>
#include <corecrypto/ccec25519_priv.h>
#include "curve25519_priv.h"
#include "shared25519.h"
#include "cc_priv.h"

#define e_bit(_e_, _i_) ((_e_[(_i_) >> 3] >> ((_i_) & 7)) & 1)

/* Curve25519's base point: x=9. */
static const uint8_t kCurve25519BasePoint[32] = { 9 };

/*!
    @function   cswap
    @abstract   Conditionally swaps (a,b), iff s == 1.

    @discussion This is basically the same as `ccn_cond_swap` (with slightly
                simplified mask computation) but works with type `rlimb`
                instead of `cc_unit`.

    @param      s  Swap bit.
    @param      a  First field element.
    @param      b  Second field element.
 */
CC_NONNULL_ALL
static void cswap(uint8_t s, limb *a, limb *b)
{
    cc_assert(s < 2);

    rlimb lo = (rlimb)0x5555555555555555;
    rlimb hi = (rlimb)0xaaaaaaaaaaaaaaaa;

    rlimb m0 = lo << s;
    rlimb m1 = ~m0;

    for (int i = 0; i < NLIMBS; i++) {
        rlimb u0 = (rlimb)a[i];
        rlimb u1 = (rlimb)b[i];
        a[i] = (limb)((((u0 & lo) | (u1 & hi)) & m0) | (((u0 & hi) | (u1 & lo)) & m1));
        b[i] = (limb)((((u0 & lo) | (u1 & hi)) & m1) | (((u0 & hi) | (u1 & lo)) & m0));
    }
}

/*!
    @function   cmult
    @abstract   Scalar multiplication using a Montgomery Ladder and
                differential addition formulas that allow for Z ≠ 1.

    @param      resultx   Output for X-coordinate of the result.
    @param      resultz   Output for Z-coordinate of the result.
    @param      e         The "scalar" or "exponent".
    @param      lambda0   Random field element.
    @param      xlambda0  Randomized X-coordinate of the base point.
    @param      lambda1   Second random field element.
 */
CC_NONNULL_ALL
static void cmult(limb *resultx,
                  limb *resultz,
                  const uint8_t *e,
                  const limb *lambda0,
                  const limb *xlambda0,
                  const limb *lambda1)
{
    limb x1[NLIMBS_BIG], z1[NLIMBS_BIG], x2[NLIMBS_BIG];
    limb t0[NLIMBS], t1[NLIMBS];
    limb z2[NLIMBS_BIG] = { 0 };

    memcpy(z1, lambda0, sizeof(limb) * NLIMBS);
    memcpy(x1, xlambda0, sizeof(limb) * NLIMBS);
    memcpy(x2, lambda1, sizeof(limb) * NLIMBS);

    for (int i = 254; i >= 0; i--) {
        cswap(e_bit(e, i) ^ e_bit(e, i + 1), x1, x2);
        cswap(e_bit(e, i) ^ e_bit(e, i + 1), z1, z2);

        fdiff(t0, x1, z1);
        fdiff(t1, x2, z2);
        fsum(x2, x2, z2);
        fsum(z2, x1, z1);
        fmul(z1, t0, x2);
        fmul(z2, z2, t1);
        fsquare_times(t0, t1, 1);
        fsquare_times(t1, x2, 1);
        fsum(x1, z1, z2);
        fdiff(z2, z1, z2);
        fmul(x2, t1, t0);
        fdiff(t1, t1, t0);
        fsquare_times(z2, z2, 1);
        fmul_121666(z1, t1);
        fsquare_times(x1, x1, 1);
        fmul(x1, x1, lambda0);
        fsum(t0, t0, z1);
        fmul(z1, z2, xlambda0);
        fmul(z2, t1, t0);
    }

    cswap(e_bit(e, 0), x1, x2);
    cswap(e_bit(e, 0), z1, z2);

    memcpy(resultx, x2, sizeof(limb) * NLIMBS);
    memcpy(resultz, z2, sizeof(limb) * NLIMBS);
}

/*!
    @function   crecip
    @abstract   Computes 1/z mod (2^255-19).

    @param      out  Output for modular inverse of `z`.
    @param      z    Field element to invert.
 */
CC_NONNULL_ALL
static void crecip(limb *out, const limb *z)
{
    limb a[NLIMBS], t0[NLIMBS], b[NLIMBS], c[NLIMBS];

    /* 2 */ fsquare_times(a, z, 1); // a = 2
    /* 8 */ fsquare_times(t0, a, 2);
    /* 9 */ fmul(b, t0, z); // b = 9
    /* 11 */ fmul(a, b, a); // a = 11
    /* 22 */ fsquare_times(t0, a, 1);
    /* 2^5 - 2^0 = 31 */ fmul(b, t0, b);
    /* 2^10 - 2^5 */ fsquare_times(t0, b, 5);
    /* 2^10 - 2^0 */ fmul(b, t0, b);
    /* 2^20 - 2^10 */ fsquare_times(t0, b, 10);
    /* 2^20 - 2^0 */ fmul(c, t0, b);
    /* 2^40 - 2^20 */ fsquare_times(t0, c, 20);
    /* 2^40 - 2^0 */ fmul(t0, t0, c);
    /* 2^50 - 2^10 */ fsquare_times(t0, t0, 10);
    /* 2^50 - 2^0 */ fmul(b, t0, b);
    /* 2^100 - 2^50 */ fsquare_times(t0, b, 50);
    /* 2^100 - 2^0 */ fmul(c, t0, b);
    /* 2^200 - 2^100 */ fsquare_times(t0, c, 100);
    /* 2^200 - 2^0 */ fmul(t0, t0, c);
    /* 2^250 - 2^50 */ fsquare_times(t0, t0, 50);
    /* 2^250 - 2^0 */ fmul(t0, t0, b);
    /* 2^255 - 2^5 */ fsquare_times(t0, t0, 5);
    /* 2^255 - 21 */ fmul(out, t0, a);
}

int cccurve25519_internal(ccec25519key out,
                          const ccec25519secretkey sk,
                          const ccec25519base base,
                          struct ccrng_state *rng)
{
    limb bp[NLIMBS], x[NLIMBS], z[NLIMBS + 1], zmone[NLIMBS];

    int rv = 0;
    uint8_t lambda0[32], lambda1[32];
    rv |= frandom(lambda0, rng);
    rv |= frandom(lambda1, rng);
    if (rv) {
        return rv;
    }

    limb l0[NLIMBS], l1[NLIMBS];
    fexpand(l0, lambda0);
    fexpand(l1, lambda1);

    uint8_t e[32];
    memcpy(e, sk, 32);
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    if (base == NULL) {
        base = kCurve25519BasePoint;
    }

    fexpand(bp, base);
    fmul(bp, bp, l0);
    cmult(x, z, e, l0, bp, l1);
    crecip(zmone, z);
    fmul(z, x, zmone);
    fcontract(out, z);
    cc_clear(sizeof(e), e);

    return CCERR_OK;
}

void cccurve25519(ccec25519key out, const ccec25519secretkey sk, const ccec25519base base)
{
    (void)cccurve25519_internal(out, sk, base, ccrng(NULL));
}
