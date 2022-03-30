/* Copyright (c) (2010,2011,2012,2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include "ccn_internal.h"

// 2^384 mod Q.
static const cc_unit RR_MOD_Q[CCN192_N] = {
    CCN192_C(28,be,56,77,ea,05,81,a2,46,96,ea,5b,bb,3a,6b,ee,ce,66,ba,cc,de,b3,59,61)
};

// 2^192 mod Q.
static const cc_unit R1_MOD_Q[CCN192_N] = {
    CCN192_C(00,00,00,00,00,00,00,00,00,00,00,00,66,21,07,c9,eb,94,36,4e,4b,2d,d7,cf)
};

// -((q % 2^w)^-1 % 2^w)
static const cc_unit Q0_INV = (cc_unit)0x882672070ddbcf2f;

// q - 2 (mod 2^96)
static const cc_unit Q_EXP[CCN192_N] = {
    CCN192_C(00,00,00,00,00,00,00,00,00,00,00,00,99,de,f8,36,14,6b,c9,b1,b4,d2,28,2f)
};

#define A(i) ccn64_64_parse(a,i)
#define Anil ccn64_64_null
#define Cnil ccn32_32_null

static void ccn_mod_192(CC_UNUSED cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *a)
{
    cc_assert(cczp_n(zp) == CCN192_N);
    cc_unit s1[CCN192_N] = { ccn192_64(Anil,  A(3),  A(3)) };
    cc_unit s2[CCN192_N] = { ccn192_64(A(4),  A(4),  Anil) };
    cc_unit s3[CCN192_N] = { ccn192_64(A(5),  A(5),  A(5)) };

    cc_unit carry;
    carry =  ccn_add(CCN192_N, r, a, s1);
    carry += ccn_add(CCN192_N, r, r, s2);
    carry += ccn_add(CCN192_N, r, r, s3);

    // Prepare to reduce once more.
    cc_unit t[CCN192_N] = { ccn192_32(Cnil, Cnil, Cnil, carry, Cnil, carry) };

    // Reduce r mod p192.
    carry = ccn_add(CCN192_N, t, r, t);

    // One extra reduction (subtract p).
    cc_unit k = ccn_sub(CCN192_N, r, t, cczp_prime(zp));

    // Keep the extra reduction if carry=1 or k=0.
    ccn_mux(CCN192_N, carry | (k ^ 1), r, r, t);

    /* Sanity for debug */
    cc_assert(ccn_cmp(CCN192_N, r, cczp_prime(zp)) < 0);
}

/*
 * p192 - 2 = 0xfffffffffffffffffffffffffffffffefffffffffffffffd
 *
 * A straightforward square-multiply implementation will need 192S+190M.
 * cczp_power_fast() with a fixed 2-bit window needs roughly 192S+95M.
 *
 * By dividing the exponent into the windows
 *   0xffffffffffffffff, 0xfffffffffffffffe, 0xfffffffffffffffd
 * we can get away with only 191S+14M.
 */
static int ccn_inv_192(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);
    cc_unit *t0 = CC_ALLOC_WS(ws, CCN192_N);
    cc_unit *t1 = CC_ALLOC_WS(ws, CCN192_N);
    cc_unit *t2 = CC_ALLOC_WS(ws, CCN192_N);
    int result = CCZP_INV_NO_INVERSE;

    // t2 := x^2
    cczp_sqr_ws(ws, zp, t2, x);

    // t1 := x^3
    cczp_mul_ws(ws, zp, t1, t2, x);

    // t0 := x^0xd
    cczp_sqr_times_ws(ws, zp, t1, t1, 2);
    cczp_mul_ws(ws, zp, t0, t1, x);

    // t1 := x^0xf
    cczp_mul_ws(ws, zp, t1, t0, t2);

    // t0 := x^0xfd
    cczp_sqr_times_ws(ws, zp, t1, t1, 4);
    cczp_mul_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xff
    cczp_mul_ws(ws, zp, t1, t0, t2);

    // t0 := x^0xfffd
    cczp_sqr_times_ws(ws, zp, t1, t1, 8);
    cczp_mul_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xffff
    cczp_mul_ws(ws, zp, t1, t0, t2);

    // t0 := x^0xfffffffd
    cczp_sqr_times_ws(ws, zp, t1, t1, 16);
    cczp_mul_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xffffffff
    cczp_mul_ws(ws, zp, t1, t0, t2);

    // t0 := x^0xfffffffffffffffd
    cczp_sqr_times_ws(ws, zp, t1, t1, 32);
    cczp_mul_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xfffffffffffffffe
    cczp_mul_ws(ws, zp, t1, t0, x);

    // t2 := x^0xffffffffffffffff
    cczp_mul_ws(ws, zp, t2, t1, x);

    // t2 := x^0xfffffffffffffffffffffffffffffffe
    cczp_sqr_times_ws(ws, zp, t2, t2, 64);
    cczp_mul_ws(ws, zp, t2, t2, t1);

    // t1 := x^0xfffffffffffffffffffffffffffffffefffffffffffffffd
    cczp_sqr_times_ws(ws, zp, t2, t2, 64);
    cczp_mul_ws(ws, zp, t1, t2, t0);

    // r*x = 1 (mod p)?
    cczp_mul_ws(ws, zp, t0, t1, x);
    if (!cczp_is_one_ws(ws, zp, t0)) {
        goto errOut;
    }

    ccn_set(CCN192_N, r, t1);
    result = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

static cczp_funcs_decl_mod_inv(cczp_p192_funcs, ccn_mod_192, ccn_inv_192);

CC_NONNULL_ALL
static int ccn_q192_inv(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);
    cc_unit *t0 = CC_ALLOC_WS(ws, CCN192_N);
    cc_unit *t1 = CC_ALLOC_WS(ws, CCN192_N);
    cc_unit *t2 = CC_ALLOC_WS(ws, CCN192_N);
    int result = CCZP_INV_NO_INVERSE;

    cczp_t zpmm = (cczp_t)CC_ALLOC_WS(ws, cczp_mm_nof_n(CCN192_N));
    cczp_mm_init_precomp(zpmm, CCN192_N, cczp_prime(zp), Q0_INV, R1_MOD_Q, RR_MOD_Q);
    cczp_to_ws(ws, zpmm, t2, x);

    // t0 := x^2
    cczp_sqr_ws(ws, zpmm, t0, t2);

    // t0 := x^3
    cczp_mul_ws(ws, zpmm, t0, t0, t2);

    // t0 := x^0xf
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 2);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 4);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xffff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 8);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xffffffff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 16);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t1 := x^0xffffffffffffffff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 32);
    cczp_mul_ws(ws, zpmm, t1, t1, t0);

    // t0 := x^0xffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zpmm, t1, t1, 32);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xffffffffffffffffffffffff99def836146bc9b1b4d2282f
    for (size_t bit = 95; bit < 96; --bit) {
        cczp_sqr_ws(ws, zpmm, t0, t0);

        if (ccn_bit(Q_EXP, bit)) {
            cczp_mul_ws(ws, zpmm, t0, t0, t2);
        }
    }

    // r*x = 1 (mod q)?
    cczp_mul_ws(ws, zpmm, t1, t0, t2);
    if (!cczp_is_one_ws(ws, zpmm, t1)) {
        goto errOut;
    }

    cczp_from_ws(ws, zpmm, r, t0);
    result = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

static cczp_funcs_decl_inv(cczp_q192_funcs, ccn_q192_inv);

static const ccec_cp_decl(192) ccec_cp192 =
{
    .hp = {
        .n = CCN192_N,
        .bitlen = 192,
        .funcs = &cczp_p192_funcs
    },
    .p = {
        CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,fe,ff,ff,ff,ff,ff,ff,ff,ff)
    },
    .pr = {
        CCN192_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01,00,00,00,00,00,00,00,01),1
    },
    .b = {
        CCN192_C(64,21,05,19,e5,9c,80,e7,0f,a7,e9,ab,72,24,30,49,fe,b8,de,ec,c1,46,b9,b1)
    },
    .gx = {
        CCN192_C(18,8d,a8,0e,b0,30,90,f6,7c,bf,20,eb,43,a1,88,00,f4,ff,0a,fd,82,ff,10,12)
    },
    .gy = {
        CCN192_C(07,19,2b,95,ff,c8,da,78,63,10,11,ed,6b,24,cd,d5,73,f9,77,a1,1e,79,48,11)
    },
    .hq = {
        .n = CCN192_N,
        .bitlen = 192,
        .funcs = &cczp_q192_funcs
    },
    .q = {
        CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,99,de,f8,36,14,6b,c9,b1,b4,d2,28,31)
    },
    .qr = {
        CCN192_C(00,00,00,00,00,00,00,00,00,00,00,00,66,21,07,c9,eb,94,36,4e,4b,2d,d7,cf),1
    }
};

ccec_const_cp_t ccec_cp_192(void)
{
    return (ccec_const_cp_t) &ccec_cp192;
}
