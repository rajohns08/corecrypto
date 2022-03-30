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

#include <corecrypto/cc_config.h>
#include "ccec_internal.h"
#include "ccn_internal.h"

#if CCN_UNIT_SIZE == 8

// 2^512 mod P.
static const cc_unit RR_MOD_P[CCN224_N] = {
    CCN224_C(ff,ff,ff,ff,ff,ff,ff,fe,00,00,00,00,ff,ff,ff,ff,00,00,00,00,ff,ff,ff,ff,00,00,00,01)
};

// 2^256 mod P.
static const cc_unit R1_MOD_P[CCN224_N] = {
    CCN224_C(00,00,00,00,00,00,00,00,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,00)
};

// 2^512 mod Q.
static const cc_unit RR_MOD_Q[CCN224_N] = {
    CCN224_C(b1,e9,79,61,6a,d1,5f,7c,d9,71,48,56,ab,c8,ff,59,31,d6,3f,4b,29,94,7a,69,5f,51,7d,15)
};

// 2^256 mod Q.
static const cc_unit R1_MOD_Q[CCN224_N] = {
    CCN224_C(00,00,00,00,00,00,00,00,00,00,e9,5d,1f,47,0f,c1,ec,22,d6,ba,a3,a3,d5,c3,00,00,00,00)
};

#else

// 2^448 mod P.
static const cc_unit RR_MOD_P[CCN224_N] = {
    CCN224_C(00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,fe,00,00,00,00,00,00,00,00,00,00,00,01)
};

// 2^224 mod P.
static const cc_unit R1_MOD_P[CCN224_N] = {
    CCN224_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)
};

// 2^448 mod Q.
static const cc_unit RR_MOD_Q[CCN224_N] = {
    CCN224_C(d4,ba,a4,cf,18,22,bc,47,b1,e9,79,61,6a,d0,9d,91,97,a5,45,52,6b,da,ae,6c,3a,d0,12,89)
};

// 2^224 mod Q.
static const cc_unit R1_MOD_Q[CCN224_N] = {
    CCN224_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,e9,5d,1f,47,0f,c1,ec,22,d6,ba,a3,a3,d5,c3)
};

#endif

// -((q % 2^w)^-1 % 2^w)
static const cc_unit Q0_INV = (cc_unit)0xd6e242706a1fc2eb;

// q - 2 (mod 2^112)
static const cc_unit Q_EXP[CCN224_N] = {
    CCN224_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,16,a2,e0,b8,f0,3e,13,dd,29,45,5c,5c,2a,3b)
};

// c1, the largest integer such that 2^c1 divides p - 1.
static const size_t SQRT_C1 = 96;

// c2 = (p - 1) / (2^c1)
// c3 = (c2 - 1) / 2
static const cc_unit SQRT_C3[CCN224_N] = {
    CCN224_C(00,00,00,00,00,00,00,00,00,00,00,00,7f,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)
};

// c2 = (p - 1) / (2^c1)
// c4 = 0xb (a non-square value in F)
// c5 = c4^c2 in F.
static const cc_unit SQRT_C5[CCN224_N] = {
#if CCN_UNIT_SIZE == 8
    CCN224_C(dc,58,4a,70,48,83,1b,2a,b4,0e,42,70,e8,ff,4d,ec,bd,bc,c8,60,04,ab,76,ab,3d,fe,35,12)
#else
    CCN224_C(dd,4f,6d,00,14,bb,49,f6,fc,ae,2c,30,99,6f,56,28,14,df,d3,a4,6a,c7,64,62,0a,f2,e8,1a)
#endif
};

#if !CCN_MULMOD_224_ASM
/*! @function ccn_addmul1_p224
 @abstract Computes r += p224 * v.

 @param r  Result
 @param v  Limb to add

 @return Any carry bits.
 */
CC_NONNULL_ALL
#if (CCN_UNIT_SIZE == 8) && CCN_UINT128_SUPPORT_FOR_64BIT_ARCH
static cc_unit ccn_addmul1_p224(cc_unit *r, cc_unit v)
{
    cc_dunit tmp;

    // v * 0xffffffff
    cc_dunit v1 = ((cc_dunit)v << 32) - v;

    // * 0x0000000000000001
    tmp = (cc_dunit)r[0] + v;
    r[0] = (cc_unit)tmp;

    // * 0xffffffff00000000
    tmp = (cc_dunit)r[1] + (v1 << 32) + (tmp >> 64);
    r[1] = (cc_unit)tmp;

    // * 0xffffffffffffffff
    tmp = (cc_dunit)r[2] + (((cc_dunit)v << 64) - v) + (tmp >> 64);
    r[2] = (cc_unit)tmp;

    // * 0x00000000ffffffff
    tmp = (cc_dunit)r[3] + v1 + (tmp >> 64);
    r[3] = (cc_unit)tmp;

    return (tmp >> 64);
}
#elif (CCN_UNIT_SIZE == 4)
static cc_unit ccn_addmul1_p224(cc_unit *r, cc_unit v)
{
    cc_dunit tmp;

    // v * 0xffffffff
    cc_dunit v1 = ((cc_dunit)v << 32) - v;

    // * 0x00000001
    tmp = (cc_dunit)r[0] + v;
    r[0] = (cc_unit)tmp;

    // * 0x00000000
    tmp = (cc_dunit)r[1] + (tmp >> 32);
    r[1] = (cc_unit)tmp;

    // * 0x00000000
    tmp = (cc_dunit)r[2] + (tmp >> 32);
    r[2] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[3] + v1 + (tmp >> 32);
    r[3] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[4] + v1 + (tmp >> 32);
    r[4] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[5] + v1 + (tmp >> 32);
    r[5] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[6] + v1 + (tmp >> 32);
    r[6] = (cc_unit)tmp;

    return (tmp >> 32);
}
#else
static cc_unit ccn_addmul1_p224(cc_unit *r, cc_unit v)
{
    return ccn_addmul1(CCN224_N, r, ccec_cp_p(ccec_cp_224()), v);
}
#endif

/*! @function ccn_p224_redc
 @abstract Computes r := a / R (mod p224) via Montgomery's REDC algorithm.

 @param zp  Multiplicative group Z/(p)
 @param r   Result of the reduction
 @param t   Number to reduce
 */
CC_NONNULL_ALL
static void ccn_p224_redc(cczp_const_t zp, cc_unit *r, cc_unit *t)
{
    // t += (t * N' (mod R)) * N
    for (cc_size i = 0; i < CCN224_N; i++) {
        // Write carries to t[i] directly as each iteration of the partial
        // REDC algorithm zeroes the current word t[i]. When finished, the
        // lower half of t contains the carries that are then added to the
        // intermediate result in t's upper half.
        t[i] = ccn_addmul1_p224(&t[i], -t[i]);
    }

    // Optional final reduction.
    cc_unit s = ccn_add(CCN224_N, &t[CCN224_N], &t[CCN224_N], t);
    s ^= ccn_sub(CCN224_N, t, &t[CCN224_N], cczp_prime(zp));
    ccn_mux(CCN224_N, s, r, &t[CCN224_N], t);

    // Sanity check.
    cc_assert(ccn_cmp(CCN224_N, r, cczp_prime(zp)) < 0);
}
#endif // !CCN_MULMOD_224_ASM

/*! @function ccn_p224_mul
 @abstract Multiplies two 224-bit numbers x and y.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Multiplier
 @param y   Multiplicand
 */
CC_NONNULL_ALL
static void ccn_p224_mul(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
#if CCN_MULMOD_224_ASM
    ccn_mul_224_montgomery(r, x, y);
#else
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * CCN224_N);
    ccn_mul_ws(ws, CCN224_N, rbig, x, y);
    ccn_p224_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
#endif
}

/*! @function ccn_p224_sqr
 @abstract Squares a 224-bit number x.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Number to square
 */
CC_NONNULL_ALL
static void ccn_p224_sqr(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
#if CCN_MULMOD_224_ASM
    ccn_sqr_224_montgomery(r, x);
#else
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * CCN224_N);
    ccn_sqr_ws(ws, CCN224_N, rbig, x);
    ccn_p224_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
#endif
}

/*! @function ccn_p224_is_one
 @abstract Returns whether x = R (mod p224), i.e. whether x = 1 in Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param x   Number

 @return True, if x = R (mod p224). False otherwise.
 */
CC_NONNULL_ALL
static bool ccn_p224_is_one(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, const cc_unit *x)
{
    return ccn_cmp(CCN224_N, x, R1_MOD_P) == 0;
}

#define ccn_p224_sqr_times(_ws_, _zp_, _x_, _n_) \
    for (unsigned i = 0; i < _n_; i++) {         \
        ccn_p224_sqr(_ws_, _zp_, _x_, _x_);      \
    }

/*
 * p224 - 2 = 0xfffffffffffffffffffffffffffffffeffffffffffffffffffffffff
 *
 * A straightforward square-multiply implementation will need 224S+223M.
 * cczp_power_fast() with a fixed 2-bit window needs roughly 224S+112M.
 *
 * By dividing the exponent into the windows
 *   0xffffffffffffffffffffffff, 0xfffffffe, 0xffffffffffffffffffffffff
 * we can get away with only 223S+14M.
 */
static int ccn_p224_inv(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);
    cc_unit *t0 = CC_ALLOC_WS(ws, CCN224_N);
    cc_unit *t1 = CC_ALLOC_WS(ws, CCN224_N);
    cc_unit *t2 = CC_ALLOC_WS(ws, CCN224_N);
    int result = CCZP_INV_NO_INVERSE;

    // t0 := x^2
    ccn_p224_sqr(ws, zp, t0, x);

    // t1 := x^3
    ccn_p224_mul(ws, zp, t1, t0, x);

    // t0 := x^0xe
    ccn_p224_sqr_times(ws, zp, t1, 2);
    ccn_p224_mul(ws, zp, t0, t0, t1);

    // t1 := x^0xf
    ccn_p224_mul(ws, zp, t1, t0, x);
    ccn_set(CCN224_N, t2, t1);

    // t0 := x^0xfe
    ccn_p224_sqr_times(ws, zp, t1, 4);
    ccn_p224_mul(ws, zp, t0, t0, t1);

    // t1 := x^0xff
    ccn_p224_mul(ws, zp, t1, t0, x);

    // t0 := x^0xfffe
    ccn_p224_sqr_times(ws, zp, t1, 8);
    ccn_p224_mul(ws, zp, t0, t0, t1);

    // t1 := x^0xffff
    ccn_p224_mul(ws, zp, t1, t0, x);

    // t0 := x^0xfffffffe
    ccn_p224_sqr_times(ws, zp, t1, 16);
    ccn_p224_mul(ws, zp, t0, t0, t1);

    // t1 := x^0xffffffff
    ccn_p224_mul(ws, zp, t1, t0, x);
    ccn_set(CCN224_N, t2, t1);

    // t2 := x^0xffffffffffffffff
    ccn_p224_sqr_times(ws, zp, t2, 32);
    ccn_p224_mul(ws, zp, t2, t2, t1);

    // t2 := x^0xffffffffffffffffffffffff
    ccn_p224_sqr_times(ws, zp, t2, 32);
    ccn_p224_mul(ws, zp, t2, t2, t1);
    ccn_set(CCN224_N, t1, t2);

    // t2 := x^0xfffffffffffffffffffffffffffffffe
    ccn_p224_sqr_times(ws, zp, t2, 32);
    ccn_p224_mul(ws, zp, t2, t2, t0);

    // t1 := x^0xfffffffffffffffffffffffffffffffeffffffffffffffffffffffff
    ccn_p224_sqr_times(ws, zp, t2, 32 * 3);
    ccn_p224_mul(ws, zp, t1, t1, t2);

    // r*x = 1 (mod p)?
    ccn_p224_mul(ws, zp, t0, t1, x);
    if (!ccn_p224_is_one(ws, zp, t0)) {
        goto errOut;
    }

    ccn_set(CCN224_N, r, t1);
    result = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

/*! @function ccn_p224_sqrt
 @abstract Computes r := x^(1/2) (mod p224) via constant-time Tonelli-Shanks.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Square root of x
 @param x   Quadratic residue
 */
static int ccn_p224_sqrt(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    return cczp_sqrt_tonelli_shanks_precomp_ws(ws, zp, r, x, SQRT_C1, SQRT_C3, SQRT_C5);
}

/*! @function ccn_p224_to
 @abstract Computes r := x * R (mod p224) to convert x to Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result in Montgomery space
 @param x   Number to convert
 */
CC_NONNULL_ALL
static void ccn_p224_to(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
#if CCN_MULMOD_224_ASM
    ccn_mul_224_montgomery(r, x, RR_MOD_P);
#else
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * CCN224_N);
    ccn_mul_ws(ws, CCN224_N, rbig, x, RR_MOD_P);
    ccn_p224_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
#endif
}

/*! @function ccn_p224_from
 @abstract Computes r := x / R (mod p224) to convert x out of Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result not in Montgomery space
 @param x   Number to convert
 */
CC_NONNULL_ALL
static void ccn_p224_from(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
#if CCN_MULMOD_224_ASM
    ccn_mod_224_montgomery(r, x);
#else
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * CCN224_N);
    ccn_setn(2 * CCN224_N, rbig, CCN224_N, x);
    ccn_p224_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
#endif
}

static cczp_funcs_decl(cczp_p224_funcs,
    ccn_p224_mul, ccn_p224_sqr, cczp_mod_default_ws, ccn_p224_inv, ccn_p224_sqrt, ccn_p224_to, ccn_p224_from, ccn_p224_is_one);

CC_NONNULL_ALL
static int ccn_q224_inv(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);
    cc_unit *t0 = CC_ALLOC_WS(ws, CCN224_N);
    cc_unit *t1 = CC_ALLOC_WS(ws, CCN224_N);
    cc_unit *t2 = CC_ALLOC_WS(ws, CCN224_N);
    cc_unit *t3 = CC_ALLOC_WS(ws, CCN224_N);
    int result = CCZP_INV_NO_INVERSE;

    cczp_t zpmm = (cczp_t)CC_ALLOC_WS(ws, cczp_mm_nof_n(CCN224_N));
    cczp_mm_init_precomp(zpmm, CCN224_N, cczp_prime(zp), Q0_INV, R1_MOD_Q, RR_MOD_Q);
    cczp_to_ws(ws, zpmm, t3, x);

    // t0 := x^2
    cczp_sqr_ws(ws, zpmm, t0, t3);

    // t0 := x^3
    cczp_mul_ws(ws, zpmm, t0, t0, t3);

    // t0 := x^0xf
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 2);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t1 := x^0xff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 4);
    cczp_mul_ws(ws, zpmm, t1, t1, t0);

    // t1 := x^0xfff
    cczp_sqr_times_ws(ws, zpmm, t1, t1, 4);
    cczp_mul_ws(ws, zpmm, t1, t1, t0);

    // t1 := x^0xffffff
    cczp_sqr_times_ws(ws, zpmm, t2, t1, 12);
    cczp_mul_ws(ws, zpmm, t1, t1, t2);

    // t0 := x^0xfffffff
    cczp_sqr_times_ws(ws, zpmm, t1, t1, 4);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xffffffffffffff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 28);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xffffffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 56);
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3b
    for (size_t bit = 111; bit < 112; --bit) {
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

static cczp_funcs_decl_inv(cczp_q224_funcs, ccn_q224_inv);

static const ccec_cp_decl(224) ccec_cp224 =
{
    .hp = {
        .n = CCN224_N,
        .bitlen = 224,
        .funcs = &cczp_p224_funcs
    },
    .p = {
        CCN224_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,00,00,00,00,00,00,00,00,01)
    },
    .pr = {
        CCN232_C(01,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)
    },
    .b = {
#if CCN_UNIT_SIZE == 8
        CCN224_C(7f,c0,2f,93,3d,ce,ba,98,c8,52,81,51,10,7a,c2,f3,cc,f0,13,10,e7,68,cd,f6,63,c0,59,cd)
#else
        CCN224_C(9c,3f,a6,33,7f,c0,2f,93,3d,ce,ba,98,c8,52,81,50,74,3b,1c,c0,cc,f0,13,10,e7,68,cd,f7)
#endif
    },
    .gx = {
        CCN224_C(b7,0e,0c,bd,6b,b4,bf,7f,32,13,90,b9,4a,03,c1,d3,56,c2,11,22,34,32,80,d6,11,5c,1d,21)
    },
    .gy = {
        CCN224_C(bd,37,63,88,b5,f7,23,fb,4c,22,df,e6,cd,43,75,a0,5a,07,47,64,44,d5,81,99,85,00,7e,34)
    },
    .hq = {
        .n = CCN224_N,
        .bitlen = 224,
        .funcs = &cczp_q224_funcs
    },
    .q = {
        CCN224_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,16,a2,e0,b8,f0,3e,13,dd,29,45,5c,5c,2a,3d)
    },
    .qr = {
        CCN232_C(01,00,00,00,00,00,00,00,00,00,00,00,00,00,00,e9,5d,1f,47,0f,c1,ec,22,d6,ba,a3,a3,d5,c3)
    }
};

ccec_const_cp_t ccec_cp_224(void)
{
    return (ccec_const_cp_t)(const struct cczp *)(const cc_unit *)&ccec_cp224;
}
