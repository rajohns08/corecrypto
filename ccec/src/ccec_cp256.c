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

#include <corecrypto/cc_runtime_config.h>
#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include "ccn_internal.h"

// 2^512 mod P.
static const cc_unit RR_MOD_P[CCN256_N] = {
    CCN256_C(00,00,00,04,ff,ff,ff,fd,ff,ff,ff,ff,ff,ff,ff,fe,ff,ff,ff,fb,ff,ff,ff,ff,00,00,00,00,00,00,00,03)
};

// 2^256 mod P.
static const cc_unit R1_MOD_P[CCN256_N] = {
    CCN256_C(00,00,00,00,ff,ff,ff,fe,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,00,00,00,00,00,00,00,00,01)
};

// 2^512 mod Q.
static const cc_unit RR_MOD_Q[CCN256_N] = {
    CCN256_C(66,e1,2d,94,f3,d9,56,20,28,45,b2,39,2b,6b,ec,59,46,99,79,9c,49,bd,6f,a6,83,24,4c,95,be,79,ee,a2)
};

// 2^256 mod Q.
static const cc_unit R1_MOD_Q[CCN256_N] = {
    CCN256_C(00,00,00,00,ff,ff,ff,ff,00,00,00,00,00,00,00,00,43,19,05,52,58,e8,61,7b,0c,46,35,3d,03,9c,da,af)
};

// -((q % 2^w)^-1 % 2^w)
static const cc_unit Q0_INV = (cc_unit)0xccd1c8aaee00bc4f;

// q - 2 (mod 2^128)
static const cc_unit Q_EXP[CCN256_N] = {
    CCN256_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,bc,e6,fa,ad,a7,17,9e,84,f3,b9,ca,c2,fc,63,25,4f)
};

#if CCN_MULMOD_256_ASM
CC_INLINE bool ccec_use_p256_assembly()
{
#if defined(__x86_64__)
  return CC_HAS_BMI2() && CC_HAS_ADX();
#else
  return true;
#endif
}
#endif

/*! @function ccn_addmul1_p256
 @abstract Computes r += p256 * v.

 @param r  Result
 @param v  Limb to add

 @return Any carry bits.
 */
CC_NONNULL_ALL
#if (CCN_UNIT_SIZE == 8) && CCN_UINT128_SUPPORT_FOR_64BIT_ARCH
static cc_unit ccn_addmul1_p256(cc_unit *r, cc_unit v)
{
    cc_dunit tmp;

    // v * 0xffffffff
    cc_dunit v1 = ((cc_dunit)v << 32) - v;

    // * 0xffffffffffffffff
    tmp = (cc_dunit)r[0] + (((cc_dunit)v << 64) - v);
    r[0] = (cc_unit)tmp;

    // * 0x00000000ffffffff
    tmp = (cc_dunit)r[1] + v1 + (tmp >> 64);
    r[1] = (cc_unit)tmp;

    // * 0x0000000000000000
    tmp = (cc_dunit)r[2] + (tmp >> 64);
    r[2] = (cc_unit)tmp;

    // * 0xffffffff00000001
    tmp = (cc_dunit)r[3] + ((v1 << 32) + v) + (tmp >> 64);
    r[3] = (cc_unit)tmp;

    return (tmp >> 64);
}
#elif (CCN_UNIT_SIZE == 4)
static cc_unit ccn_addmul1_p256(cc_unit *r, cc_unit v)
{
    cc_dunit tmp;

    // v * 0xffffffff
    cc_dunit v1 = ((cc_dunit)v << 32) - v;

    // * 0xffffffff
    tmp = (cc_dunit)r[0] + v1;
    r[0] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[1] + v1 + (tmp >> 32);
    r[1] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[2] + v1 + (tmp >> 32);
    r[2] = (cc_unit)tmp;

    // * 0x00000000
    tmp = (cc_dunit)r[3] + (tmp >> 32);
    r[3] = (cc_unit)tmp;

    // * 0x00000000
    tmp = (cc_dunit)r[4] + (tmp >> 32);
    r[4] = (cc_unit)tmp;

    // * 0x00000000
    tmp = (cc_dunit)r[5] + (tmp >> 32);
    r[5] = (cc_unit)tmp;

    // * 0x00000001
    tmp = (cc_dunit)r[6] + v + (tmp >> 32);
    r[6] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[7] + v1 + (tmp >> 32);
    r[7] = (cc_unit)tmp;

    return (tmp >> 32);
}
#else
static cc_unit ccn_addmul1_p256(cc_unit *r, cc_unit v)
{
    return ccn_addmul1(CCN256_N, r, ccec_cp_p(ccec_cp_256()), v);
}
#endif

/*! @function ccn_p256_redc
 @abstract Computes r := a / R (mod p256) via Montgomery's REDC algorithm.

 @param zp  Multiplicative group Z/(p)
 @param r   Result of the reduction
 @param t   Number to reduce
 */
CC_NONNULL_ALL
static void ccn_p256_redc(cczp_const_t zp, cc_unit *r, cc_unit *t)
{
    // t += (t * N' (mod R)) * N
    for (cc_size i = 0; i < CCN256_N; i++) {
        // Write carries to t[i] directly as each iteration of the partial
        // REDC algorithm zeroes the current word t[i]. When finished, the
        // lower half of t contains the carries that are then added to the
        // intermediate result in t's upper half.
        t[i] = ccn_addmul1_p256(&t[i], t[i]);
    }

    // Optional final reduction.
    cc_unit s = ccn_add(CCN256_N, &t[CCN256_N], &t[CCN256_N], t);
    s ^= ccn_sub(CCN256_N, t, &t[CCN256_N], cczp_prime(zp));
    ccn_mux(CCN256_N, s, r, &t[CCN256_N], t);

    /* Sanity check. */
    cc_assert(ccn_cmp(CCN256_N, r, cczp_prime(zp)) < 0);
}

/*! @function ccn_p256_mul
 @abstract Multiplies two 256-bit numbers x and y.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Multiplier
 @param y   Multiplicand
 */
CC_NONNULL_ALL
static void ccn_p256_mul(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
#if CCN_MULMOD_256_ASM
    if (ccec_use_p256_assembly()) {
        ccn_mul_256_montgomery(r, x, y);
        return;
    }
#endif

    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * CCN256_N);
    ccn_mul_ws(ws, CCN256_N, rbig, x, y);
    ccn_p256_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function ccn_p256_sqr
 @abstract Squares a 256-bit number x.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Number to square
 */
CC_NONNULL_ALL
static void ccn_p256_sqr(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
#if CCN_MULMOD_256_ASM
    if (ccec_use_p256_assembly()) {
        ccn_sqr_256_montgomery(r, x);
        return;
    }
#endif

    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * CCN256_N);
    ccn_sqr_ws(ws, CCN256_N, rbig, x);
    ccn_p256_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function ccn_p256_is_one
 @abstract Returns whether x = R (mod p256), i.e. whether x = 1 in Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param x   Number

 @return True, if x = R (mod p256). False otherwise.
 */
CC_NONNULL_ALL
static bool ccn_p256_is_one(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, const cc_unit *x)
{
    return ccn_cmp(CCN256_N, x, R1_MOD_P) == 0;
}

#define ccn_p256_sqr_times(_ws_, _zp_, _x_, _n_) \
    for (unsigned i = 0; i < _n_; i++) {         \
        ccn_p256_sqr(_ws_, _zp_, _x_, _x_);      \
    }

/*
 * p256 - 2 = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffd
 *
 * A straightforward square-multiply implementation will need 256S+128M.
 * cczp_power_fast() with a fixed 2-bit window needs roughly 256S+128M as well.
 *
 * By dividing the exponent into the windows
 *   0xffffffff, 0x00000001, 0x000000000000000000000000ffffffff, 0xfffffffd
 * we can get away with only 255S+14M.
 */
CC_NONNULL_ALL
static int ccn_p256_inv(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);
    cc_unit *t0 = CC_ALLOC_WS(ws, CCN256_N);
    cc_unit *t1 = CC_ALLOC_WS(ws, CCN256_N);
    cc_unit *t2 = CC_ALLOC_WS(ws, CCN256_N);
    int result = CCZP_INV_NO_INVERSE;

    // t2 := x^2
    ccn_p256_sqr(ws, zp, t2, x);

    // t1 := x^3
    ccn_p256_mul(ws, zp, t1, t2, x);

    // t0 := x^0xd
    ccn_p256_sqr_times(ws, zp, t1, 2);
    ccn_p256_mul(ws, zp, t0, t1, x);

    // t1 := x^0xf
    ccn_p256_mul(ws, zp, t1, t0, t2);

    // t0 := x^0xfd
    ccn_p256_sqr_times(ws, zp, t1, 4);
    ccn_p256_mul(ws, zp, t0, t0, t1);

    // t1 := x^0xff
    ccn_p256_mul(ws, zp, t1, t0, t2);

    // t0 := x^0xfffd
    ccn_p256_sqr_times(ws, zp, t1, 8);
    ccn_p256_mul(ws, zp, t0, t0, t1);

    // t1 := x^0xffff
    ccn_p256_mul(ws, zp, t1, t0, t2);

    // t0 := x^0xfffffffd
    ccn_p256_sqr_times(ws, zp, t1, 16);
    ccn_p256_mul(ws, zp, t0, t0, t1);

    // t1 := x^0xffffffff
    ccn_p256_mul(ws, zp, t1, t0, t2);
    ccn_set(CCN256_N, t2, t1);

    // t2 = x^0xffffffff00000001
    ccn_p256_sqr_times(ws, zp, t2, 32);
    ccn_p256_mul(ws, zp, t2, t2, x);

    // t2 = x^0xffffffff00000001000000000000000000000000ffffffff
    ccn_p256_sqr_times(ws, zp, t2, 32 * 4);
    ccn_p256_mul(ws, zp, t2, t2, t1);

    // t2 = x^0xffffffff00000001000000000000000000000000ffffffffffffffff
    ccn_p256_sqr_times(ws, zp, t2, 32);
    ccn_p256_mul(ws, zp, t2, t2, t1);

    // t1 = x^0xffffffff00000001000000000000000000000000fffffffffffffffffffffffd
    ccn_p256_sqr_times(ws, zp, t2, 32);
    ccn_p256_mul(ws, zp, t1, t2, t0);

    // r*x = 1 (mod p)?
    ccn_p256_mul(ws, zp, t0, t1, x);
    if (!ccn_p256_is_one(ws, zp, t0)) {
        goto errOut;
    }

    ccn_set(CCN256_N, r, t1);
    result = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

/*! @function ccn_p256_to
 @abstract Computes r := x * R (mod p256) to convert x to Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result in Montgomery space
 @param x   Number to convert
 */
CC_NONNULL_ALL
static void ccn_p256_to(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
#if CCN_MULMOD_256_ASM
    if (ccec_use_p256_assembly()) {
        ccn_mul_256_montgomery(r, x, RR_MOD_P);
        return;
    }
#endif

    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * CCN256_N);
    ccn_mul_ws(ws, CCN256_N, rbig, x, RR_MOD_P);
    ccn_p256_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function ccn_p256_from
 @abstract Computes r := x / R (mod p256) to convert x out of Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result not in Montgomery space
 @param x   Number to convert
 */
CC_NONNULL_ALL
static void ccn_p256_from(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
#if CCN_MULMOD_256_ASM
    if (ccec_use_p256_assembly()) {
        ccn_mod_256_montgomery(r, x);
        return;
    }
#endif

    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * CCN256_N);
    ccn_setn(2 * CCN256_N, rbig, CCN256_N, x);
    ccn_p256_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

static cczp_funcs_decl(cczp_p256_funcs,
    ccn_p256_mul, ccn_p256_sqr, cczp_mod_default_ws, ccn_p256_inv, cczp_sqrt_default_ws, ccn_p256_to, ccn_p256_from, ccn_p256_is_one);

CC_NONNULL_ALL
static int ccn_q256_inv(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);
    cc_unit *t0 = CC_ALLOC_WS(ws, CCN256_N);
    cc_unit *t1 = CC_ALLOC_WS(ws, CCN256_N);
    cc_unit *t2 = CC_ALLOC_WS(ws, CCN256_N);
    int result = CCZP_INV_NO_INVERSE;

    cczp_t zpmm = (cczp_t)CC_ALLOC_WS(ws, cczp_mm_nof_n(CCN256_N));
    cczp_mm_init_precomp(zpmm, CCN256_N, cczp_prime(zp), Q0_INV, R1_MOD_Q, RR_MOD_Q);
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

    // t1 := x^0xffffffff00000000
    cczp_sqr_times_ws(ws, zpmm, t1, t0, 32);

    // t0 := x^0xffffffffffffffff
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t1 := x^0xffffffff000000000000000000000000
    cczp_sqr_times_ws(ws, zpmm, t1, t1, 64);

    // t0 := x^0xffffffff00000000ffffffffffffffff
    cczp_mul_ws(ws, zpmm, t0, t0, t1);

    // t0 := x^0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f
    for (size_t bit = 127; bit < 128; --bit) {
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

static cczp_funcs_decl_inv(cczp_q256_funcs, ccn_q256_inv);

static const ccec_cp_decl(256) ccec_cp256 =
{
    .hp = {
        .n = CCN256_N,
        .bitlen = 256,
        .funcs = &cczp_p256_funcs
    },
    .p = {
        CCN256_C(ff,ff,ff,ff,00,00,00,01,00,00,00,00,00,00,00,00,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)
    },
    .pr = {
        CCN256_C(00,00,00,00,ff,ff,ff,ff,ff,ff,ff,fe,ff,ff,ff,fe,ff,ff,ff,fe,ff,ff,ff,ff,00,00,00,00,00,00,00,03),1
    },
    .b = {
        CCN256_C(dc,30,06,1d,04,87,48,34,e5,a2,20,ab,f7,21,2e,d6,ac,f0,05,cd,78,84,30,90,d8,9c,df,62,29,c4,bd,df)
    },
    .gx = {
        CCN256_C(6b,17,d1,f2,e1,2c,42,47,f8,bc,e6,e5,63,a4,40,f2,77,03,7d,81,2d,eb,33,a0,f4,a1,39,45,d8,98,c2,96)
    },
    .gy = {
        CCN256_C(4f,e3,42,e2,fe,1a,7f,9b,8e,e7,eb,4a,7c,0f,9e,16,2b,ce,33,57,6b,31,5e,ce,cb,b6,40,68,37,bf,51,f5)
    },
    .hq = {
        .n = CCN256_N,
        .bitlen = 256,
        .funcs = &cczp_q256_funcs
    },
    .q = {
        CCN256_C(ff,ff,ff,ff,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,bc,e6,fa,ad,a7,17,9e,84,f3,b9,ca,c2,fc,63,25,51)
    },
    .qr = {
        CCN256_C(00,00,00,00,ff,ff,ff,ff,ff,ff,ff,fe,ff,ff,ff,ff,43,19,05,52,df,1a,6c,21,01,2f,fd,85,ee,df,9b,fe),1
    }
};

ccec_const_cp_t ccec_cp_256(void)
{
    return (ccec_const_cp_t)(const struct cczp *)(const cc_unit*)&ccec_cp256;
}
