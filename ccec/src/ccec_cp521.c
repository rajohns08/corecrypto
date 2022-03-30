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

#if CCN_UNIT_SIZE == 8

// 2^1152 mod Q.
static const cc_unit RR_MOD_Q[CCN521_N] = {
    CCN528_C(00,3d,2d,8e,03,d1,49,2d,0d,45,5b,cc,6d,61,a8,e5,67,bc,cf,f3,d1,42,b7,75,6e,3e,dd,6e,23,d8,2e,49,c7,db,d3,72,1e,f5,57,f7,5e,06,12,a7,8d,38,79,45,73,ff,f7,07,ba,dc,e5,54,7e,a3,13,7c,d0,4d,cf,15,dd,04)
};

// 2^576 mod Q.
static const cc_unit R1_MOD_Q[CCN521_N] = {
    CCN528_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,02,d7,3c,bc,3e,20,68,34,ca,40,19,ff,5b,84,7b,2d,17,e2,25,1b,23,bb,31,dc,28,a2,48,24,70,b7,63,cd,fb,80,00,00,00,00,00,00)
};

#else

// 2^1088 mod Q.
static const cc_unit RR_MOD_Q[CCN521_N] = {
    CCN528_C(01,9a,5b,5a,3a,fe,8c,44,38,3d,2d,8e,03,d1,49,2d,0d,45,5b,cc,6d,61,a8,e5,67,bc,cf,f3,d1,42,b7,75,6e,3a,4f,b3,5b,72,d3,40,27,05,5d,4d,d6,d3,07,91,d9,dc,18,35,4a,56,43,74,a6,42,11,63,11,5a,61,c6,4c,a7)
};

// 2^544 mod Q.
static const cc_unit R1_MOD_Q[CCN521_N] = {
    CCN528_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,02,d7,3c,bc,3e,20,68,34,ca,40,19,ff,5b,84,7b,2d,17,e2,25,1b,23,bb,31,dc,28,a2,48,24,70,b7,63,cd,fb,80,00,00)
};

#endif

// -((q % 2^w)^-1 % 2^w)
static const cc_unit Q0_INV = (cc_unit)0x1d2f5ccd79a995c7;

// q - 2 (mod 2^261)
static const cc_unit Q_EXP[CCN521_N] = {
    CCN528_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,1a,51,86,87,83,bf,2f,96,6b,7f,cc,01,48,f7,09,a5,d0,3b,b5,c9,b8,89,9c,47,ae,bb,6f,b7,1e,91,38,64,07)
};

static void ccn_mod_521(CC_UNUSED cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *a)
{
    cc_assert(cczp_n(zp) == CCN521_N);
    cc_unit t[CCN521_N];
    cc_unit t2[CCN521_N];
    cc_unit borrow;

#if CCN_UNIT_SIZE == 1
    ccn_shift_right(CCN521_N - 1, t2, &a[CCN521_N - 1], 1); // r = a521,...,a1041
    t2[CCN521_N - 1] += a[CCN521_N - 1] & CC_UNIT_C(1);
    t2[CCN521_N - 1] += ccn_add(CCN521_N - 1,t2,t2,a);
#else
    ccn_shift_right(CCN521_N, t2, &a[CCN512_N], 9);  // r = a521,...,a1041
    t2[CCN512_N] += a[CCN512_N] & CC_UNIT_C(0x1ff);  // r += (a512,...,a520)*2^512
    t2[CCN512_N] += ccn_add(CCN512_N,t2,t2,a);         // r += a0,...,a511
#endif
    borrow=ccn_sub(CCN521_N, t, t2, cczp_prime(zp));
    ccn_mux(CCN521_N, borrow, r, t2, t);

    /* Sanity for debug */
    cc_assert(ccn_cmp(CCN521_N, r, cczp_prime(zp)) < 0);
}

/*
 * p521 - 2 = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd
 *
 * A straightforward square-multiply implementation will need 521S+520M.
 * cczp_power_fast() with a fixed 2-bit window needs roughly 521S+260M.
 *
 * By dividing the exponent into windows we can get away with only 520S+13M.
 */
static int ccn_inv_521(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);
    cc_unit *t0 = CC_ALLOC_WS(ws, CCN521_N);
    cc_unit *t1 = CC_ALLOC_WS(ws, CCN521_N);
    cc_unit *t2 = CC_ALLOC_WS(ws, CCN521_N);
    int result = CCZP_INV_NO_INVERSE;

    // t1 := x^2
    cczp_sqr_ws(ws, zp, t1, x);

    // t1 := x^3
    cczp_mul_ws(ws, zp, t1, t1, x);

    // t0 := x^0xf
    cczp_sqr_times_ws(ws, zp, t0, t1, 2);
    cczp_mul_ws(ws, zp, t0, t0, t1);

    // t0 := x^0x3f
    cczp_sqr_times_ws(ws, zp, t0, t0, 2);
    cczp_mul_ws(ws, zp, t0, t0, t1);

    // t0,t2 := x^0x7f
    cczp_sqr_ws(ws, zp, t0, t0);
    cczp_mul_ws(ws, zp, t0, t0, x);
    ccn_set(CCN521_N, t2, t0);

    // t0 := x^0xff
    cczp_sqr_ws(ws, zp, t0, t0);
    cczp_mul_ws(ws, zp, t0, t0, x);

    // t1 := x^0xffff
    cczp_sqr_times_ws(ws, zp, t1, t0, 8);
    cczp_mul_ws(ws, zp, t1, t1, t0);

    // t0 := x^0xffffffff
    cczp_sqr_times_ws(ws, zp, t0, t1, 16);
    cczp_mul_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xffffffffffffffff
    cczp_sqr_times_ws(ws, zp, t1, t0, 32);
    cczp_mul_ws(ws, zp, t1, t1, t0);

    // t0 := x^0xffffffffffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zp, t0, t1, 64);
    cczp_mul_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zp, t1, t0, 128);
    cczp_mul_ws(ws, zp, t1, t1, t0);

    // t0 := x^0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zp, t0, t1, 256);
    cczp_mul_ws(ws, zp, t0, t0, t1);

    // t0 := x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zp, t0, t0, 7);
    cczp_mul_ws(ws, zp, t0, t0, t2);

    // t1 := x^0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd
    cczp_sqr_times_ws(ws, zp, t0, t0, 2);
    cczp_mul_ws(ws, zp, t1, t0, x);

    // r*x = 1 (mod p)?
    cczp_mul_ws(ws, zp, t0, t1, x);
    if (!cczp_is_one_ws(ws, zp, t0)) {
        goto errOut;
    }

    ccn_set(CCN521_N, r, t1);
    result = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

static cczp_funcs_decl_mod_inv(cczp_p521_funcs, ccn_mod_521, ccn_inv_521);

CC_NONNULL_ALL
static int ccn_q521_inv(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);
    cc_unit *t0 = CC_ALLOC_WS(ws, CCN521_N);
    cc_unit *t1 = CC_ALLOC_WS(ws, CCN521_N);
    cc_unit *t2 = CC_ALLOC_WS(ws, CCN521_N);
    cc_unit *t3 = CC_ALLOC_WS(ws, CCN521_N);
    int result = CCZP_INV_NO_INVERSE;

    cczp_t zpmm = (cczp_t)CC_ALLOC_WS(ws, cczp_mm_nof_n(CCN521_N));
    cczp_mm_init_precomp(zpmm, CCN521_N, cczp_prime(zp), Q0_INV, R1_MOD_Q, RR_MOD_Q);
    cczp_to_ws(ws, zpmm, t3, x);

    // t0 := x^2
    cczp_sqr_ws(ws, zpmm, t0, t3);

    // t0 := x^3
    cczp_mul_ws(ws, zpmm, t0, t0, t3);

    // t2 := x^0xf
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 2);
    cczp_mul_ws(ws, zpmm, t2, t0, t1);

    // t0 := x^0xff
    cczp_sqr_times_ws(ws, zpmm, t1, t2, 4);
    cczp_mul_ws(ws, zpmm, t0, t1, t2);

    // t0 := x^0xffff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 8);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xffffffff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 16);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xffffffffffffffff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 32);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xffffffffffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 64);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 128);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zpmm, t0, t0, 4);
    cczp_mul_ws(ws, zpmm, t0, t0, t2);

    // t0 := x^0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386407
    for (size_t bit = 260; bit < 261; --bit) {
        cczp_sqr_ws(ws, zpmm, t0, t0);

        if (ccn_bit(Q_EXP, bit)) {
            cczp_mul_ws(ws, zpmm, t0, t0, t3);
        }
    }

    // r*x = 1 (mod q)?
    cczp_mul_ws(ws, zpmm, t1, t0, t3);
    if (!cczp_is_one_ws(ws, zpmm, t1)) {
        goto errOut;
    }

    cczp_from_ws(ws, zpmm, r, t0);
    result = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

static cczp_funcs_decl_inv(cczp_q521_funcs, ccn_q521_inv);

static const ccec_cp_decl(521) ccec_cp521 =
{
    .hp = {
        .n = CCN521_N,
        .bitlen = 521,
        .funcs = &cczp_p521_funcs
    },
    .p = {
        CCN528_C(01,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)
    },
    .pr = {
        CCN528_C(02,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01)
    },
    .b = {

        CCN528_C(00,51,95,3e,b9,61,8e,1c,9a,1f,92,9a,21,a0,b6,85,40,ee,a2,da,72,5b,99,b3,15,f3,b8,b4,89,91,8e,f1,09,e1,56,19,39,51,ec,7e,93,7b,16,52,c0,bd,3b,b1,bf,07,35,73,df,88,3d,2c,34,f1,ef,45,1f,d4,6b,50,3f,00)
    },
    .gx = {

        CCN528_C(00,c6,85,8e,06,b7,04,04,e9,cd,9e,3e,cb,66,23,95,b4,42,9c,64,81,39,05,3f,b5,21,f8,28,af,60,6b,4d,3d,ba,a1,4b,5e,77,ef,e7,59,28,fe,1d,c1,27,a2,ff,a8,de,33,48,b3,c1,85,6a,42,9b,f9,7e,7e,31,c2,e5,bd,66)
    },
    .gy = {
        CCN528_C(01,18,39,29,6a,78,9a,3b,c0,04,5c,8a,5f,b4,2c,7d,1b,d9,98,f5,44,49,57,9b,44,68,17,af,bd,17,27,3e,66,2c,97,ee,72,99,5e,f4,26,40,c5,50,b9,01,3f,ad,07,61,35,3c,70,86,a2,72,c2,40,88,be,94,76,9f,d1,66,50)
    },
    .hq = {
        .n = CCN521_N,
        .bitlen = 521,
        .funcs = &cczp_q521_funcs
    },
    .q = {
        CCN528_C(01,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,fa,51,86,87,83,bf,2f,96,6b,7f,cc,01,48,f7,09,a5,d0,3b,b5,c9,b8,89,9c,47,ae,bb,6f,b7,1e,91,38,64,09)
    },
    .qr = {
        CCN528_C(02,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,05,ae,79,78,7c,40,d0,69,94,80,33,fe,b7,08,f6,5a,2f,c4,4a,36,47,76,63,b8,51,44,90,48,e1,6e,c7,9b,f7)
    }
};

ccec_const_cp_t ccec_cp_521(void)
{
    return (ccec_const_cp_t)(const struct cczp *)(const cc_unit*)&ccec_cp521;
}
